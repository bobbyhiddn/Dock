package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var shoreUpgrader = websocket.Upgrader{
	// Shore instances connect from trusted infrastructure — no CORS check needed.
	CheckOrigin: func(r *http.Request) bool { return true },
	// Generous buffer sizes for HTTP-over-WS messages (request bodies can be large).
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
}

// shoreConnectHandler handles POST /shore/connect.
// Shore instances connect here, present their mTLS client certificate, register,
// and then maintain a long-lived WebSocket for HTTP-over-WS tunnelling.
func (app *App) shoreConnectHandler(w http.ResponseWriter, r *http.Request) {
	// ── mTLS validation ───────────────────────────────────────────────────────
	var certName string
	if app.caCertPool != nil {
		// Server was started with TLS + client cert request.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			log.Printf("SHORE | no client cert | addr=%s", r.RemoteAddr)
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		opts := x509.VerifyOptions{
			Roots:     app.caCertPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			log.Printf("SHORE | invalid client cert | addr=%s | err=%v", r.RemoteAddr, err)
			http.Error(w, "Invalid client certificate", http.StatusUnauthorized)
			return
		}
		certName = cert.Subject.CommonName
		log.Printf("SHORE | mTLS OK | CN=%s | addr=%s", certName, r.RemoteAddr)
	} else {
		log.Printf("SHORE | mTLS disabled (no DOCK_CA_CERT) | addr=%s", r.RemoteAddr)
	}

	// ── WebSocket upgrade ─────────────────────────────────────────────────────
	conn, err := shoreUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("SHORE | WS upgrade failed | addr=%s | err=%v", r.RemoteAddr, err)
		return
	}

	// ── Registration handshake ────────────────────────────────────────────────
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		log.Printf("SHORE | register read error | addr=%s | err=%v", r.RemoteAddr, err)
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{}) // clear deadline for long-lived connection

	var reg RegisterMessage
	if err := json.Unmarshal(data, &reg); err != nil || reg.Type != MsgTypeRegister {
		log.Printf("SHORE | bad register message | addr=%s | raw=%s", r.RemoteAddr, string(data))
		conn.Close()
		return
	}

	// Resolve Shore identity: mTLS CN takes precedence over the register message name.
	shoreName := reg.Name
	if certName != "" {
		if certName != reg.Name {
			log.Printf("SHORE | cert CN=%q overrides register name=%q", certName, reg.Name)
		}
		shoreName = certName
	}
	if shoreName == "" {
		log.Printf("SHORE | empty name after registration | addr=%s", r.RemoteAddr)
		conn.Close()
		return
	}

	// ── Build and register the connection ─────────────────────────────────────
	shore := &ShoreConnection{
		Name:       shoreName,
		Conn:       conn,
		Services:   reg.Services,
		LastPing:   time.Now(),
		Connected:  time.Now(),
		RemoteAddr: r.RemoteAddr,
		pending:    make(map[string]chan *HTTPResponseMessage),
		streams:    make(map[string]chan *StreamFrameMessage),
		done:       make(chan struct{}),
	}
	app.registry.Register(shore)

	// ── Read loop (runs until connection closes) ───────────────────────────────
	app.runShoreReadLoop(shore)
}

// runShoreReadLoop processes incoming messages from a registered Shore until
// the WebSocket closes or an unrecoverable error occurs.
func (app *App) runShoreReadLoop(shore *ShoreConnection) {
	defer func() {
		app.registry.Unregister(shore.Name)
		shore.Close()
		log.Printf("SHORE | disconnected | name=%s", shore.Name)
	}()

	for {
		_, data, err := shore.Conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err,
				websocket.CloseNormalClosure,
				websocket.CloseGoingAway,
				websocket.CloseNoStatusReceived,
			) {
				log.Printf("SHORE | read error | name=%s | err=%v", shore.Name, err)
			}
			return
		}

		msgType, err := peekType(data)
		if err != nil {
			log.Printf("SHORE | parse error | name=%s | err=%v", shore.Name, err)
			continue
		}

		switch msgType {

		case MsgTypePing:
			shore.LastPing = time.Now()
			// Respond with pong.
			pong := PongMessage{Type: MsgTypePong, Ts: time.Now().Unix()}
			if err := shore.WriteJSON(pong); err != nil {
				log.Printf("SHORE | pong write error | name=%s | err=%v", shore.Name, err)
				return
			}

		case MsgTypeHTTPResponse:
			var resp HTTPResponseMessage
			if err := json.Unmarshal(data, &resp); err != nil {
				log.Printf("SHORE | bad http_response | name=%s | err=%v", shore.Name, err)
				continue
			}
			shore.DeliverResponse(&resp)

		case MsgTypeStreamFrame:
			var frame StreamFrameMessage
			if err := json.Unmarshal(data, &frame); err != nil {
				log.Printf("SHORE | bad stream_frame | name=%s | err=%v", shore.Name, err)
				continue
			}
			shore.DeliverFrame(&frame)

		case MsgTypeStreamEnd:
			var end StreamEndMessage
			if err := json.Unmarshal(data, &end); err != nil {
				log.Printf("SHORE | bad stream_end | name=%s | err=%v", shore.Name, err)
				continue
			}
			shore.CloseStream(end.ID)

		default:
			log.Printf("SHORE | unknown message type=%q | name=%s", msgType, shore.Name)
		}
	}
}

// buildTLSConfig constructs a tls.Config that requests (but does not require) a
// client certificate, using the provided CA pool for validation.
// The /shore/connect handler performs the actual require+verify step so that
// other endpoints (user browser traffic) are not affected.
func buildTLSConfig(caCertPool *x509.CertPool) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if caCertPool != nil {
		// RequestClientCert asks for the cert but does not reject connections that
		// don't have one — browsers will still work.  The /shore/connect handler
		// performs strict validation when a CA pool is configured.
		cfg.ClientAuth = tls.RequestClientCert
		cfg.ClientCAs = caCertPool
	}
	return cfg
}
