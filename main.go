package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

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

	// Customize the director to rewrite the Host header
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	// Custom error handler for upstream failures
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Upstream unreachable", http.StatusBadGateway)
	}

	// Health check endpoint (no auth required)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Everything else goes through basic auth + proxy
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Basic auth check
		user, pass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="hermit-dock"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	addr := ":" + port
	log.Printf("hermit-dock proxy listening on %s, forwarding to %s", addr, upstreamURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
