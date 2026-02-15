package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

//go:embed static
var staticFiles embed.FS

// statusResponseWriter wraps http.ResponseWriter to capture the status code
type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (w *statusResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// extractClientIP extracts the client IP from RemoteAddr (strips port)
func extractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// loggingMiddleware logs every request with audit-relevant fields
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(sw, r)

		clientIP := extractClientIP(r.RemoteAddr)
		xff := r.Header.Get("X-Forwarded-For")
		ua := r.Header.Get("User-Agent")

		log.Printf("AUDIT | %s | %s %s | src=%s | xff=%s | ua=%s | status=%d | dur=%s",
			time.Now().UTC().Format(time.RFC3339),
			r.Method, r.URL.Path,
			clientIP,
			xff,
			ua,
			sw.statusCode,
			time.Since(start),
		)
	})
}

// generateSessionSecret creates a random 32-byte secret for HMAC signing
func generateSessionSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("Failed to generate session secret: %v", err)
	}
	return secret
}

// createSessionToken creates an HMAC-signed session token
// Format: timestamp_hex.hmac_hex
func createSessionToken(secret []byte) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	sig := hex.EncodeToString(mac.Sum(nil))
	return ts + "." + sig
}

// validateSessionToken checks that the token is validly signed and not expired
func validateSessionToken(token string, secret []byte, maxAge time.Duration) bool {
	// Split into timestamp.signature
	var ts, sig string
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			ts = token[:i]
			sig = token[i+1:]
			break
		}
	}
	if ts == "" || sig == "" {
		return false
	}

	// Verify HMAC
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return false
	}

	// Check expiry
	var tsInt int64
	fmt.Sscanf(ts, "%d", &tsInt)
	issued := time.Unix(tsInt, 0)
	if time.Since(issued) > maxAge {
		return false
	}

	return true
}

func main() {
	upstreamURL := os.Getenv("UPSTREAM_URL")
	if upstreamURL == "" {
		log.Fatal("UPSTREAM_URL environment variable is required")
	}

	password := os.Getenv("BASIC_AUTH_PASSWORD")
	if password == "" {
		log.Fatal("BASIC_AUTH_PASSWORD environment variable is required")
	}

	username := "micah"
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Session config
	sessionSecret := generateSessionSecret()
	sessionMaxAge := 24 * time.Hour * 7 // 7-day sessions
	cookieName := "hermit_session"

	target, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("Invalid UPSTREAM_URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the director to rewrite Host and set forwarding headers.
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		clientIP := extractClientIP(req.RemoteAddr)
		originalDirector(req)
		req.Host = target.Host
		req.Header.Set("X-Real-IP", clientIP)
	}

	// Custom error handler for upstream failures
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		clientIP := extractClientIP(r.RemoteAddr)
		log.Printf("AUDIT | %s | PROXY_ERROR | src=%s | xff=%s | err=%v",
			time.Now().UTC().Format(time.RFC3339),
			clientIP,
			r.Header.Get("X-Forwarded-For"),
			err,
		)
		http.Error(w, "Upstream unreachable", http.StatusBadGateway)
	}

	// Read the login page from embedded static files
	loginPage, err := staticFiles.ReadFile("static/login.html")
	if err != nil {
		log.Fatalf("Failed to read embedded login page: %v", err)
	}

	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Serve static assets (logo, etc.) without auth — needed for login page
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// POST /login — validate credentials and set session cookie
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.ParseForm()
		user := r.FormValue("username")
		pass := r.FormValue("password")

		if subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "invalid")
			return
		}

		// Credentials valid — set session cookie
		token := createSessionToken(sessionSecret)
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   int(sessionMaxAge.Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// GET /logout — clear session cookie
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Everything else goes through session check + proxy
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check session cookie first
		cookie, err := r.Cookie(cookieName)
		if err == nil && validateSessionToken(cookie.Value, sessionSecret, sessionMaxAge) {
			// Valid session — proxy the request
			proxy.ServeHTTP(w, r)
			return
		}

		// Also accept Basic auth (for API clients, curl, etc.)
		user, pass, ok := r.BasicAuth()
		if ok &&
			subtle.ConstantTimeCompare([]byte(user), []byte(username)) == 1 &&
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1 {
			proxy.ServeHTTP(w, r)
			return
		}

		// Not authenticated — serve login page for browsers, 401 for API
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			w.Write(loginPage)
			return
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="hermit-dock"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})

	// Wrap the entire mux with the logging middleware
	handler := loggingMiddleware(mux)

	addr := ":" + port
	log.Printf("hermit-dock proxy listening on %s, forwarding to %s", addr, upstreamURL)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
