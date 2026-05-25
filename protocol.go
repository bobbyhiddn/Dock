package main

import "encoding/json"

// Message type constants — both Dock and Shore must agree on these strings.
const (
	MsgTypeHTTPRequest  = "http_request"
	MsgTypeHTTPResponse = "http_response"
	MsgTypeRegister     = "register"
	MsgTypePing         = "ping"
	MsgTypePong         = "pong"
	MsgTypeStreamStart  = "stream_start"
	MsgTypeStreamFrame  = "stream_frame"
	MsgTypeStreamEnd    = "stream_end"
)

// TypedMessage is used to peek at the type field before full decoding.
type TypedMessage struct {
	Type string `json:"type"`
}

// RegisterMessage is sent by Shore immediately after the WebSocket handshake.
// Shore → Dock
type RegisterMessage struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Services []string `json:"services"`
	Version  string   `json:"version,omitempty"`
}

// PingMessage is sent by Shore every ~15s.  Dock responds with a PongMessage.
// Shore → Dock
type PingMessage struct {
	Type string `json:"type"`
	Ts   int64  `json:"ts"`
}

// PongMessage is sent by Dock in response to a PingMessage.
// Dock → Shore
type PongMessage struct {
	Type string `json:"type"`
	Ts   int64  `json:"ts"`
}

// HTTPRequestMessage is sent by Dock to Shore to forward a user HTTP request.
// Body is base64-encoded (or null for requests with no body).
// Dock → Shore
type HTTPRequestMessage struct {
	Type    string            `json:"type"`
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"` // base64-encoded, null if empty
}

// HTTPResponseMessage is sent by Shore back to Dock after handling a request.
// Body is base64-encoded (empty string if no body).
// Shore → Dock
type HTTPResponseMessage struct {
	Type    string            `json:"type"`
	ID      string            `json:"id"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"` // base64-encoded
}

// StreamStartMessage is sent by Dock to Shore to open an SSE / streaming response.
// Dock → Shore
type StreamStartMessage struct {
	Type    string            `json:"type"`
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// StreamFrameMessage carries a single SSE data frame from Shore to Dock.
// Data contains the raw SSE text (e.g. "data: {...}\n\n").
// Shore → Dock
type StreamFrameMessage struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Data string `json:"data"`
}

// StreamEndMessage signals that the Shore-side stream has closed.
// Shore → Dock
type StreamEndMessage struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// peekType unmarshals only the "type" field from a raw JSON message.
func peekType(data []byte) (string, error) {
	var m TypedMessage
	err := json.Unmarshal(data, &m)
	return m.Type, err
}
