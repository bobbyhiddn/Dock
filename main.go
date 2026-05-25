package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
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
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	gothgithub "github.com/markbates/goth/providers/github"
	"golang.org/x/crypto/bcrypt"
)

//go:embed static
var staticFiles embed.FS

// ── Context keys ──────────────────────────────────────────────────────────────

type contextKey string

const userContextKey contextKey = "user"

// getUser extracts the authenticated username from the request context.
// Returns "" if not authenticated.
func getUser(r *http.Request) string {
	if v := r.Context().Value(userContextKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// App holds all shared state for the Dock gateway.
type App struct {
	registry      *ShoreRegistry
	caCertPool    *x509.CertPool // nil if mTLS is not configured
	users         *UserStore
	sessionSecret []byte
	sessionMaxAge time.Duration
	cookieName    string
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

// createSessionToken creates an HMAC-signed session token encoding the username.
// Format: username:timestamp.HMAC(username:timestamp)
func createSessionToken(username string, secret []byte) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	payload := username + ":" + ts
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

// extractSessionUser validates a session token and extracts the username.
// Returns (username, true) on success, ("", false) on failure.
func extractSessionUser(token string, secret []byte, maxAge time.Duration) (string, bool) {
	// Find last '.' to split payload from HMAC.
	dotIdx := strings.LastIndex(token, ".")
	if dotIdx < 0 {
		return "", false
	}
	payload := token[:dotIdx]
	sig := token[dotIdx+1:]

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return "", false
	}

	// payload = "username:timestamp"
	colonIdx := strings.LastIndex(payload, ":")
	if colonIdx < 0 {
		return "", false
	}
	username := payload[:colonIdx]
	ts := payload[colonIdx+1:]

	var tsInt int64
	fmt.Sscanf(ts, "%d", &tsInt)
	if time.Since(time.Unix(tsInt, 0)) > maxAge {
		return "", false
	}
	if username == "" {
		return "", false
	}
	return username, true
}

// requireSession is a middleware that gates routes behind session auth.
// On success it injects the username into the request context.
func (app *App) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(app.cookieName); err == nil {
			if username, ok := extractSessionUser(cookie.Value, app.sessionSecret, app.sessionMaxAge); ok {
				ctx := context.WithValue(r.Context(), userContextKey, username)
				next.ServeHTTP(w, r.WithContext(ctx))
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

// setSessionCookie writes the session cookie for the given user.
func (app *App) setSessionCookie(w http.ResponseWriter, username string, secure bool) {
	token := createSessionToken(username, app.sessionSecret)
	http.SetCookie(w, &http.Cookie{
		Name:     app.cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(app.sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ── Status / API endpoints ────────────────────────────────────────────────────

type shoreStatus struct {
	Name       string    `json:"name"`
	Owner      string    `json:"owner"`
	Services   []string  `json:"services"`
	Connected  time.Time `json:"connected"`
	LastPing   time.Time `json:"last_ping"`
	RemoteAddr string    `json:"remote_addr"`
}

// statusHandler returns Shores owned by the authenticated user.
func (app *App) statusHandler(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	shores := app.registry.ListByOwner(user)
	sort.Slice(shores, func(i, j int) bool {
		return shores[i].Name < shores[j].Name
	})
	out := make([]shoreStatus, 0, len(shores))
	for _, s := range shores {
		out = append(out, shoreStatus{
			Name:       s.Name,
			Owner:      s.Owner,
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
		"user":   user,
	})
}

// apiShoresHandler is the landing-page data endpoint — same as /status but at /api/shores.
func (app *App) apiShoresHandler(w http.ResponseWriter, r *http.Request) {
	app.statusHandler(w, r)
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	// ── Config from environment ───────────────────────────────────────────────
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// UPSTREAM_URL is no longer required — Shores connect via WebSocket.
	if u := os.Getenv("UPSTREAM_URL"); u != "" {
		log.Printf("NOTE: UPSTREAM_URL=%q is ignored in v2 (Shores connect via WebSocket)", u)
	}

	// Optional mTLS CA certificate.
	var caCertPool *x509.CertPool
	if caPath := os.Getenv("DOCK_CA_CERT"); caPath != "" {
		pemData, err := os.ReadFile(caPath)
		if err != nil {
			log.Fatalf("Failed to read DOCK_CA_CERT=%q: %v", caPath, err)
		}
		pool, err := parseCACert(pemData)
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
	secureCookies := tlsCert != ""

	// ── User store (SQLite) ───────────────────────────────────────────────────
	users, err := NewUserStore(userStoreDBPath())
	if err != nil {
		log.Fatalf("Failed to open user store: %v", err)
	}
	log.Printf("User store opened at %s", userStoreDBPath())

	app := &App{
		registry:      NewShoreRegistry(),
		caCertPool:    caCertPool,
		users:         users,
		sessionSecret: generateSessionSecret(),
		sessionMaxAge: 7 * 24 * time.Hour,
		cookieName:    "hermit_session",
	}

	// ── Goth / OAuth setup ────────────────────────────────────────────────────
	store := sessions.NewCookieStore(app.sessionSecret)
	gothic.Store = store

	githubKey := os.Getenv("GOTH_GITHUB_KEY")
	githubSecret := os.Getenv("GOTH_GITHUB_SECRET")
	if githubKey != "" && githubSecret != "" {
		scheme := "http"
		if secureCookies {
			scheme = "https"
		}
		host := os.Getenv("DOCK_HOST")
		if host == "" {
			host = "localhost:" + port
		}
		callbackURL := fmt.Sprintf("%s://%s/auth/github/callback", scheme, host)
		goth.UseProviders(gothgithub.New(githubKey, githubSecret, callbackURL))
		log.Printf("GitHub OAuth configured — callback: %s", callbackURL)
	} else {
		log.Printf("WARN: GOTH_GITHUB_KEY/SECRET not set — GitHub OAuth disabled")
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

	// ── Auth endpoints (public) ───────────────────────────────────────────────

	// POST /login — username+password login.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		username := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")

		user, err := app.users.GetByUsername(username)
		if err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, "invalid")
				return
			}
			log.Printf("LOGIN | db error | username=%q | err=%v", username, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if user.PasswordHash == "" {
			// OIDC-only account — must use OAuth.
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "use_oauth")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(pass)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "invalid")
			return
		}
		app.setSessionCookie(w, user.Username, secureCookies)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// POST /register — create a new local account.
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		username := strings.TrimSpace(r.FormValue("username"))
		email := strings.TrimSpace(r.FormValue("email"))
		pass := r.FormValue("password")

		if username == "" || pass == "" {
			http.Error(w, "username and password required", http.StatusBadRequest)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		if err := app.users.CreateUser(username, email, string(hash), "", ""); err != nil {
			// Likely a unique constraint violation.
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintln(w, "username_taken")
			return
		}

		// First registered user gets admin, or the configured DOCK_ADMIN_USER.
		adminUser := os.Getenv("DOCK_ADMIN_USER")
		count, _ := app.users.CountUsers()
		if count == 1 || (adminUser != "" && username == adminUser) {
			app.users.SetAdmin(username)
		}

		app.setSessionCookie(w, username, secureCookies)
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
			Secure:   secureCookies,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// ── Goth OAuth routes ─────────────────────────────────────────────────────

	// GET /auth/{provider} — redirect to OAuth provider.
	mux.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /auth/{provider} or /auth/{provider}/callback
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/auth/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}

		if len(parts) >= 2 && parts[1] == "callback" {
			// Completion callback from OAuth provider.
			gothUser, err := gothic.CompleteUserAuth(w, r)
			if err != nil {
				log.Printf("OAUTH | CompleteUserAuth error: %v", err)
				http.Error(w, "OAuth error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			// Find or create user.
			dbUser, err := app.users.GetByProvider(gothUser.Provider, gothUser.UserID)
			if err != nil && err != sql.ErrNoRows {
				log.Printf("OAUTH | db lookup error: %v", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
			if err == sql.ErrNoRows {
				// New user — create account.
				username := gothUser.NickName
				if username == "" {
					username = gothUser.Name
				}
				if username == "" {
					username = "user-" + gothUser.UserID
				}
				// Ensure uniqueness.
				base := username
				for i := 2; ; i++ {
					if _, lookupErr := app.users.GetByUsername(username); lookupErr == sql.ErrNoRows {
						break
					}
					username = fmt.Sprintf("%s%d", base, i)
				}
				if createErr := app.users.CreateUser(username, gothUser.Email, "", gothUser.Provider, gothUser.UserID); createErr != nil {
					log.Printf("OAUTH | create user error: %v", createErr)
					http.Error(w, "Failed to create account", http.StatusInternalServerError)
					return
				}
				count, _ := app.users.CountUsers()
				adminUser := os.Getenv("DOCK_ADMIN_USER")
				if count == 1 || (adminUser != "" && username == adminUser) {
					app.users.SetAdmin(username)
				}
				dbUser, err = app.users.GetByUsername(username)
				if err != nil {
					http.Error(w, "Internal error", http.StatusInternalServerError)
					return
				}
			}
			app.setSessionCookie(w, dbUser.Username, secureCookies)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Begin auth flow.
		gothic.BeginAuthHandler(w, r)
	})

	// ── Protected endpoints ───────────────────────────────────────────────────

	// Shore registry status (user-scoped).
	mux.Handle("/status", app.requireSession(http.HandlerFunc(app.statusHandler)))

	// API endpoint for landing page.
	mux.Handle("/api/shores", app.requireSession(http.HandlerFunc(app.apiShoresHandler)))

	// Everything else → proxy to a Shore (identity-scoped).
	mux.Handle("/", app.requireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root path — serve landing page for authenticated users.
		if r.URL.Path == "/" {
			landingPage, err := staticFiles.ReadFile("static/landing.html")
			if err != nil {
				// Fallback: if landing page not found, route to Shore or error.
				http.Error(w, "Landing page not found", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			w.Write(landingPage)
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
