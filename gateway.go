package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	requestTimeout = 30 * time.Second
	maxBodySize    = 10 * 1024 * 1024 // 10 MB
)

// activeShortCookieName is the cookie that remembers which Shore the user last
// navigated to by path prefix. It is read by resolveShore to route un-prefixed
// SPA sub-requests (assets, API calls) back to the same Shore.
const activeShortCookieName = "hermit_active_shore"

// routeToShore is the main handler for authenticated user requests.
// It resolves which Shore to use, wraps the HTTP request as JSON, sends it
// over the Shore's WebSocket, waits for the response, and writes it back.
func (app *App) routeToShore(w http.ResponseWriter, r *http.Request) {
	shore, stripPrefix := app.resolveShore(r)
	// resolveShore returns nil when no Shore matches the path and no valid
	// hermit_active_shore cookie is set; the landing page is served for "/".
	if shore == nil {
		if len(app.registry.List()) == 0 {
			http.Error(w, "No Shores connected", http.StatusBadGateway)
		} else {
			http.Error(w, "No Shore available for this path", http.StatusBadGateway)
		}
		return
	}

	// When we matched by path prefix, pin the active Shore in a cookie so that
	// subsequent un-prefixed SPA sub-requests (assets, API calls) are routed to
	// the same Shore instead of falling through to an arbitrary one.
	if stripPrefix != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     activeShortCookieName,
			Value:    stripPrefix,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	// Build the forwarded path (strip the shore-name prefix if present).
	forwardPath := r.URL.Path
	if stripPrefix != "" {
		forwardPath = strings.TrimPrefix(r.URL.Path, "/"+stripPrefix)
		if forwardPath == "" || forwardPath[0] != '/' {
			forwardPath = "/" + forwardPath
		}
	}
	if r.URL.RawQuery != "" {
		forwardPath += "?" + r.URL.RawQuery
	}

	// Flatten headers into a string map.
	headers := flattenHeaders(r)
	headers["X-Real-IP"] = extractClientIP(r.RemoteAddr)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		headers["X-Forwarded-For"] = fwd
	}

	// Strip any client-supplied identity headers to prevent spoofing.
	// flattenHeaders preserves Go's canonical casing, but iterate defensively.
	for k := range headers {
		switch strings.ToLower(k) {
		case "x-dock-user", "x-dock-email", "x-dock-provider":
			delete(headers, k)
		}
	}
	// Inject the Dock-authenticated user identity into the forwarded frame.
	// Plaintext is safe here — the mTLS tunnel is the cryptographic trust boundary.
	if user := getUser(r); user != "" {
		headers["X-Dock-User"] = user
		log.Printf("FORWARD | shore=%s | user=%s", shore.Name, user)
	}

	reqID := generateID()

	// SSE passthrough: if the client wants an event stream, use stream_start.
	if r.Header.Get("Accept") == "text/event-stream" {
		app.handleSSERequest(w, r, shore, reqID, r.Method, forwardPath, headers)
		return
	}

	// ── Regular HTTP-over-WebSocket ───────────────────────────────────────────
	var bodyStr *string
	if r.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if err == nil && len(raw) > 0 {
			encoded := base64.StdEncoding.EncodeToString(raw)
			bodyStr = &encoded
		}
	}

	msg := HTTPRequestMessage{
		Type:    MsgTypeHTTPRequest,
		ID:      reqID,
		Method:  r.Method,
		Path:    forwardPath,
		Headers: headers,
		Body:    bodyStr,
	}

	respCh, err := shore.SendHTTPRequest(msg)
	if err != nil {
		http.Error(w, "Failed to send request to Shore", http.StatusBadGateway)
		return
	}

	select {
	case resp, ok := <-respCh:
		if !ok {
			http.Error(w, "Shore disconnected", http.StatusBadGateway)
			return
		}
		writeHTTPResponse(w, resp)

	case <-time.After(requestTimeout):
		shore.CancelPendingRequest(reqID)
		http.Error(w, "Request timeout", http.StatusGatewayTimeout)

	case <-shore.done:
		http.Error(w, "Shore disconnected", http.StatusBadGateway)
	}
}

// handleSSERequest opens a stream_start channel to Shore and forwards
// stream_frame messages to the browser as a live SSE stream.
func (app *App) handleSSERequest(w http.ResponseWriter, r *http.Request,
	shore *ShoreConnection, streamID, method, path string, headers map[string]string,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported by this server", http.StatusInternalServerError)
		return
	}

	msg := StreamStartMessage{
		Type:    MsgTypeStreamStart,
		ID:      streamID,
		Method:  method,
		Path:    path,
		Headers: headers,
	}
	frameCh, err := shore.OpenStream(msg)
	if err != nil {
		http.Error(w, "Failed to open stream to Shore", http.StatusBadGateway)
		return
	}

	// Set SSE response headers before writing any data.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case frame, ok := <-frameCh:
			if !ok {
				// stream_end received — Shore closed the stream normally.
				return
			}
			fmt.Fprint(w, frame.Data)
			flusher.Flush()

		case <-ctx.Done():
			// Client disconnected — clean up the stream channel.
			shore.CloseStream(streamID)
			return

		case <-shore.done:
			// Shore disconnected mid-stream.
			return
		}
	}
}

// resolveShore maps a request URL path to a Shore connection owned by the
// authenticated user (extracted from request context via getUser).
//
// Routing rules:
//   - /master/...  → shore-master owned by user  (stripPrefix = "master")
//   - /tower/...   → shore-tower owned by user   (stripPrefix = "tower")
//   - un-prefixed  → Shore named in hermit_active_shore cookie (if owned+connected)
//   - no match     → nil, "" (caller serves an error; landing page handles bare "/")
//
// Only Shores owned by the authenticated user are considered.
func (app *App) resolveShore(r *http.Request) (*ShoreConnection, string) {
	user := getUser(r)

	trimmed := strings.TrimPrefix(r.URL.Path, "/")
	if trimmed != "" {
		parts := strings.SplitN(trimmed, "/", 2)
		candidate := "shore-" + parts[0]
		if shore, ok := app.registry.GetByOwner(user, candidate); ok {
			return shore, parts[0]
		}
	}

	// No path-prefix match. Consult the hermit_active_shore cookie to route
	// un-prefixed SPA sub-requests (assets, API calls) back to the correct Shore.
	// The lexicographic fallback has been intentionally removed — silent crossover
	// between Shores was the root cause of SPA asset bleed between shore-master and
	// shore-tower. The bare-root landing page ("/") is handled upstream by main.go
	// and serves the dynamic shore picker, so returning nil here is correct.
	if cookie, err := r.Cookie(activeShortCookieName); err == nil && cookie.Value != "" {
		candidate := "shore-" + cookie.Value
		if shore, ok := app.registry.GetByOwner(user, candidate); ok {
			return shore, "" // un-prefixed request; nothing to strip
		}
	}
	return nil, ""
}

// writeHTTPResponse copies an HTTPResponseMessage back to the browser.
// The body is base64-decoded before writing.
func writeHTTPResponse(w http.ResponseWriter, resp *HTTPResponseMessage) {
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(resp.Status)

	if resp.Body != "" {
		decoded, err := base64.StdEncoding.DecodeString(resp.Body)
		if err != nil {
			// Body wasn't base64 — write it raw (defensive fallback).
			w.Write([]byte(resp.Body))
			return
		}
		w.Write(decoded)
	}
}

// flattenHeaders collapses an http.Header multi-map into a single-value map.
// Multiple values for the same header are joined with ", ".
func flattenHeaders(r *http.Request) map[string]string {
	out := make(map[string]string, len(r.Header))
	for k, vals := range r.Header {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}
