package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"time"
)

//go:embed static
var staticFiles embed.FS

// App holds all shared state for the Dock gateway.
type App struct {
	registry      *ShoreRegistry
	caCertPool    *x509.CertPool // nil if mTLS is not configured
	sessionSecret []byte
	sessionMaxAge time.Duration
	cookieName    string
	username      string
	password      string
}

// ── Utility ──────────────────────────────────────────────────────────────────

// generateID creates a random hex string suitable for request/stream IDs.
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generateID: rand.Read failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// statusResponseWriter wraps http.ResponseWriter to capture the status code.
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

// extractClientIP strips the port from a RemoteAddr string.
func extractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// ── Logging middleware ────────────────────────────────────────────────────────

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("AUDIT | %s | %s %s | src=%s | xff=%s | ua=%s | status=%d | dur=%s",
			time.Now().UTC().Format(time.RFC3339),
			r.Method, r.URL.Path,
			extractClientIP(r.RemoteAddr),
			r.Header.Get("X-Forwarded-For"),
			r.Header.Get("User-Agent"),
			sw.statusCode,
			time.Since(start),
		)
	})
}

// ── Session / auth ────────────────────────────────────────────────────────────

func generateSessionSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("Failed to generate session secret: %v", err)
	}
	return secret
}

// createSessionToken creates an HMAC-signed session token (timestamp.hmac).
func createSessionToken(secret []byte) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	return ts + "." + hex.EncodeToString(mac.Sum(nil))
}

// validateSessionToken checks the HMAC signature and expiry of a session token.
func validateSessionToken(token string, secret []byte, maxAge time.Duration) bool {
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
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) != 1 {
		return false
	}
	var tsInt int64
	fmt.Sscanf(ts, "%d", &tsInt)
	return time.Since(time.Unix(tsInt, 0)) <= maxAge
}

// requireSession is a middleware that gates routes behind the session/basic-auth check.
func (app *App) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(app.cookieName); err == nil {
			if validateSessionToken(cookie.Value, app.sessionSecret, app.sessionMaxAge) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if user, pass, ok := r.BasicAuth(); ok {
			if subtle.ConstantTimeCompare([]byte(user), []byte(app.username)) == 1 &&
				subtle.ConstantTimeCompare([]byte(pass), []byte(app.password)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Unauthenticated — serve login page for browsers, 401 for API clients.
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			loginPage, _ := staticFiles.ReadFile("static/login.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			w.Write(loginPage)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="hermit-dock"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// ── Status endpoint ───────────────────────────────────────────────────────────

type shoreStatus struct {
	Name       string    `json:"name"`
	Services   []string  `json:"services"`
	Connected  time.Time `json:"connected"`
	LastPing   time.Time `json:"last_ping"`
	RemoteAddr string    `json:"remote_addr"`
}

func (app *App) statusHandler(w http.ResponseWriter, r *http.Request) {
	shores := app.registry.List()
	sort.Slice(shores, func(i, j int) bool {
		return shores[i].Name < shores[j].Name
	})
	out := make([]shoreStatus, 0, len(shores))
	for _, s := range shores {
		out = append(out, shoreStatus{
			Name:       s.Name,
			Services:   s.Services,
			Connected:  s.Connected,
			LastPing:   s.LastPing,
			RemoteAddr: s.RemoteAddr,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"shores": out,
		"count":  len(out),
	})
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	// ── Config from environment ───────────────────────────────────────────────
	password := os.Getenv("BASIC_AUTH_PASSWORD")
	if password == "" {
		log.Fatal("BASIC_AUTH_PASSWORD environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// UPSTREAM_URL is no longer required — Shores connect via WebSocket.
	// Log a notice if it is set (it's ignored in v2).
	if u := os.Getenv("UPSTREAM_URL"); u != "" {
		log.Printf("NOTE: UPSTREAM_URL=%q is ignored in v2 (Shores connect via WebSocket)", u)
	}

	// Optional mTLS CA certificate.
	var caCertPool *x509.CertPool
	if caPath := os.Getenv("DOCK_CA_CERT"); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			log.Fatalf("Failed to read DOCK_CA_CERT=%q: %v", caPath, err)
		}
		pool, err := parseCACert(pem)
		if err != nil {
			log.Fatalf("Failed to parse CA cert: %v", err)
		}
		caCertPool = pool
		log.Printf("mTLS enabled — CA cert loaded from %s", caPath)
	} else {
		log.Printf("WARN: DOCK_CA_CERT not set — mTLS validation disabled for /shore/connect")
	}

	// Optional TLS for direct HTTPS (needed for mTLS in local dev).
	tlsCert := os.Getenv("DOCK_TLS_CERT")
	tlsKey := os.Getenv("DOCK_TLS_KEY")

	app := &App{
		registry:      NewShoreRegistry(),
		caCertPool:    caCertPool,
		sessionSecret: generateSessionSecret(),
		sessionMaxAge: 7 * 24 * time.Hour,
		cookieName:    "hermit_session",
		username:      "micah",
		password:      password,
	}

	// ── Read login page once ──────────────────────────────────────────────────
	loginPage, err := staticFiles.ReadFile("static/login.html")
	if err != nil {
		log.Fatalf("Failed to read embedded login page: %v", err)
	}

	// ── HTTP mux ──────────────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// Public endpoints (no auth).
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		shores := app.registry.List()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","shores":%d}`, len(shores))
	})

	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Shore WebSocket endpoint — no user auth, but mTLS if configured.
	mux.HandleFunc("/shore/connect", app.shoreConnectHandler)

	// Auth endpoints.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		user := r.FormValue("username")
		pass := r.FormValue("password")
		if subtle.ConstantTimeCompare([]byte(user), []byte(app.username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(app.password)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "invalid")
			return
		}
		token := createSessionToken(app.sessionSecret)
		http.SetCookie(w, &http.Cookie{
			Name:     app.cookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   int(app.sessionMaxAge.Seconds()),
			HttpOnly: true,
			Secure:   tlsCert != "",
			SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     app.cookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   tlsCert != "",
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Protected: Shore registry status.
	mux.Handle("/status", app.requireSession(http.HandlerFunc(app.statusHandler)))

	// Protected: everything else is proxied to a Shore.
	mux.Handle("/", app.requireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the login page for the root path when no Shores are connected.
		if r.URL.Path == "/" && len(app.registry.List()) == 0 {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			w.Write(loginPage)
			return
		}
		app.routeToShore(w, r)
	})))

	handler := loggingMiddleware(mux)

	// ── Start server ──────────────────────────────────────────────────────────
	addr := ":" + port
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	if tlsCert != "" && tlsKey != "" {
		srv.TLSConfig = buildTLSConfig(caCertPool)
		log.Printf("hermit-dock v2 listening on %s (TLS, mTLS=%v)", addr, caCertPool != nil)
		if err := srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		log.Printf("hermit-dock v2 listening on %s (plain HTTP — use TLS in production)", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}

// parseCACert parses a PEM-encoded CA certificate into an x509.CertPool.
func parseCACert(pemData []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	var found bool
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			pool.AddCert(cert)
			found = true
		}
		pemData = rest
	}
	if !found {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return pool, nil
}
