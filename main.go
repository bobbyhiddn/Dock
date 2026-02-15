package main

import (
	"crypto/subtle"
	"embed"
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

	target, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("Invalid UPSTREAM_URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the director to rewrite Host and set forwarding headers.
	// NOTE: httputil.NewSingleHostReverseProxy's default Director already
	// appends the client IP to X-Forwarded-For. We call it first, then
	// set X-Real-IP with the original client IP for downstream consumers.
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// Save client IP before originalDirector potentially modifies things
		clientIP := extractClientIP(req.RemoteAddr)

		// Default director sets scheme, host, path, and appends X-Forwarded-For
		originalDirector(req)
		req.Host = target.Host

		// Set X-Real-IP with the direct client IP (Fly edge → this proxy)
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

	// Health check endpoint (no auth required)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Read the login page from embedded static files
	loginPage, err := staticFiles.ReadFile("static/login.html")
	if err != nil {
		log.Fatalf("Failed to read embedded login page: %v", err)
	}

	// Serve static assets (logo, etc.) without auth — needed for login page
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Everything else goes through basic auth + proxy
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Basic auth check
		user, pass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {

			// If this is a login check from the JS form, return 401 (no redirect)
			if r.Header.Get("X-Login-Check") == "1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// For browser GET requests without auth, serve the login page
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusOK)
				w.Write(loginPage)
				return
			}

			// For API/non-browser requests, return 401
			w.Header().Set("WWW-Authenticate", `Basic realm="hermit-dock"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	// Wrap the entire mux with the logging middleware
	handler := loggingMiddleware(mux)

	addr := ":" + port
	log.Printf("hermit-dock proxy listening on %s, forwarding to %s", addr, upstreamURL)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
