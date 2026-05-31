# Dock Architecture — Multi-Shore Proxy

## Overview

Dock is the **UAG (Unified Access Gateway)** for the Hermit platform. It sits in a DMZ
(Fly.io, Dallas region) and routes authenticated requests to the correct Shore instance.
Shores connect **outbound** to Dock via WebSocket, so no inbound ports are needed on any host.

```
Internet → hermit-dock.com → Dock (Fly.io)
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
              Shore-master  Shore-tower  Shore-N
              (masternode)  (the-tower)  (future)
```

## Current State (v1)

- Single Go binary on Fly.io (`shared-cpu-1x`, 256MB)
- Single `UPSTREAM_URL` → Cloudflare tunnel → Shore → Rhode
- Basic auth (username/password) + HMAC session cookies
- No WebSocket proxying, no multi-backend, no mTLS

## Target State (v2 — Multi-Shore MVP)

### Core Components

#### 1. Shore Registry
In-memory registry of connected Shore instances. Each Shore is identified by its
mTLS certificate Common Name (e.g., `shore-master`, `shore-tower`).

```go
type ShoreConnection struct {
    Name       string        // CN from client cert
    Conn       *websocket.Conn
    Upstream   string        // What this Shore proxies to (e.g., "rhode", "shell")
    Services   []string      // Available services on this Shore
    LastPing   time.Time
    Connected  time.Time
    RemoteAddr string
}
```

#### 2. Shore WebSocket Endpoint
`/shore/connect` — Shore instances connect here with their client certificate.
Protocol:
1. Shore opens WSS to `wss://hermit-dock.com/shore/connect`
2. Dock validates client cert against private CA
3. Shore sends registration message: `{"name": "shore-master", "services": ["rhode", "shell", "ordinal"]}`
4. Dock adds to registry
5. Bidirectional: Dock forwards HTTP requests over WS, Shore responds over WS
6. Heartbeat: Shore sends ping every 15s, Dock reaps after 45s silence

#### 3. Request Routing
When an authenticated user hits Dock:
1. Dock checks the URL path prefix: `/master/...`, `/tower/...` (explicit routing)
2. Or uses the user's default Shore binding (set during OAuth login)
3. Looks up the Shore in the registry
4. Forwards the request over the Shore's WebSocket tunnel
5. Returns the response to the user

#### 4. Authentication (Two Layers)

**User → Dock** (GitHub OAuth):
- Users authenticate via GitHub OAuth (replacing basic auth)
- GitHub identity maps to allowed Shores (ACL)
- Session cookie after OAuth flow

**Shore → Dock** (mTLS):
- Private CA (age-encrypted key in SOPS)
- Each Shore gets a client cert signed by the CA
- Dock validates against CA root on WebSocket connect
- Cert CN = Shore identity (no spoofing)

#### 5. MCP OAuth Relay
For MCP tools that need OAuth (e.g., Legate, Atlassian):
1. Instance initiates OAuth flow → redirect goes to `hermit-dock.com/oauth/callback`
2. Dock routes callback to the originating Shore (tracked by state parameter)
3. Shore completes the OAuth flow and stores tokens locally

### Protocol: HTTP-over-WebSocket

Dock wraps HTTP requests into WebSocket messages to tunnel them to Shore.

```json
// Dock → Shore (request)
{
    "type": "http_request",
    "id": "req-abc123",
    "method": "GET",
    "path": "/rhode/tasks",
    "headers": {"Cookie": "...", "X-Forwarded-For": "..."},
    "body": null
}

// Shore → Dock (response)
{
    "type": "http_response",
    "id": "req-abc123",
    "status": 200,
    "headers": {"Content-Type": "application/json"},
    "body": "{...}"
}

// Shore → Dock (registration)
{
    "type": "register",
    "name": "shore-master",
    "services": ["rhode", "shell", "ordinal", "circle"],
    "version": "0.2.0"
}

// Bidirectional heartbeat
{
    "type": "ping",
    "ts": 1716600000
}
```

### SSE / WebSocket Passthrough

For SSE streams (task events) and WebSocket connections (terminal, logs):
- Dock holds the client connection open
- Forwards frames bidirectionally over the Shore tunnel
- Shore's ReverseProxy already handles SSE and WS — Dock just tunnels

```json
// Client wants SSE stream
{
    "type": "stream_start",
    "id": "stream-xyz",
    "method": "GET",
    "path": "/rhode/tasks/123/stream",
    "headers": {...}
}

// Shore sends frames back
{
    "type": "stream_frame",
    "id": "stream-xyz",
    "data": "data: {\"type\": \"message\", ...}\n\n"
}
```

## Security Model

1. **No inbound ports on hosts** — Shore connects outbound only
2. **mTLS for Shore identity** — cryptographic, not network-based
3. **Private CA in SOPS** — CA key encrypted with age, stored in Rhode repo
4. **Cert revocation** — Dock checks a revocation list (simple file) on each connect
5. **GitHub OAuth for users** — no more basic auth password
6. **Audit logging** — all requests logged with user identity + Shore routing

## Deployment

- Fly.io (`hermit-dock` app, DFW region)
- Single binary, no external dependencies
- CA cert bundle baked into the image (or fetched from Fly secrets)
- Shore registry is in-memory (stateless — Shores reconnect automatically)

## Shore Client Module (added to Shore codebase)

```python
# src/shore/dock_client.py
class DockClient:
    """Outbound WebSocket connector to Dock."""
    
    def __init__(self, config: DockConfig):
        self.url = config.url          # wss://hermit-dock.com/shore/connect
        self.cert = config.cert_path   # /etc/hermetic/certs/shore.crt
        self.key = config.key_path     # /etc/hermetic/certs/shore.key
        self.ca = config.ca_path       # /etc/hermetic/certs/hermit-ca.crt
        self.name = config.name        # shore-master
        self.services = config.services
    
    async def connect(self):
        """Connect to Dock with mTLS, register, maintain heartbeat."""
        ssl_ctx = ssl.create_default_context(cafile=self.ca)
        ssl_ctx.load_cert_chain(self.cert, self.key)
        
        async with websockets.connect(self.url, ssl=ssl_ctx) as ws:
            await self._register(ws)
            await self._run(ws)  # heartbeat + request handling loop
    
    async def _handle_request(self, ws, msg):
        """Receive HTTP request from Dock, proxy locally, return response."""
        # Forward to local service via Shore's existing proxy infrastructure
        ...
```

## CLI Tooling

```bash
# Generate private CA (one-time, store key in SOPS)
dock ca init

# Issue a cert for a new Shore
dock ca issue --name shore-tower --output /etc/hermetic/certs/

# Revoke a Shore cert
dock ca revoke --name shore-tower

# List connected Shores (queries Dock API)
dock status

# Shore-side: initialize connection to Dock
shore dock init --url wss://hermit-dock.com/shore/connect --name shore-master
```

## Migration Path (v1 → v2)

1. Deploy v2 Dock alongside v1 (same Fly app, new routes)
2. Shore-master connects to Dock via WebSocket
3. Verify routing works through WS tunnel
4. Remove Cloudflare tunnel from the chain (Dock talks directly to Shores)
5. Shore-tower connects
6. Switch DNS / Cloudflare Access to point at new routes
7. Remove v1 basic auth code
