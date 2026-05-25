package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const staleThreshold = 45 * time.Second

// ShoreConnection represents one connected Shore instance.
type ShoreConnection struct {
	Name       string
	Conn       *websocket.Conn
	Services   []string
	LastPing   time.Time
	Connected  time.Time
	RemoteAddr string

	// pending maps request ID → response channel for in-flight HTTP-over-WS requests.
	mu      sync.Mutex
	pending map[string]chan *HTTPResponseMessage
	// streams maps stream ID → frame channel for active SSE passthroughs.
	streams map[string]chan *StreamFrameMessage

	// writeMu guards all WebSocket writes (gorilla allows one writer at a time).
	writeMu sync.Mutex

	// done is closed when the connection is being torn down.
	done      chan struct{}
	closeOnce sync.Once
}

// WriteJSON marshals v and sends it as a text WebSocket frame.
func (s *ShoreConnection) WriteJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.Conn.WriteMessage(websocket.TextMessage, data)
}

// SendHTTPRequest registers a pending request and sends the message to Shore.
// Returns a channel that will receive the response (buffered 1).
func (s *ShoreConnection) SendHTTPRequest(msg HTTPRequestMessage) (chan *HTTPResponseMessage, error) {
	ch := make(chan *HTTPResponseMessage, 1)
	s.mu.Lock()
	s.pending[msg.ID] = ch
	s.mu.Unlock()

	if err := s.WriteJSON(msg); err != nil {
		s.mu.Lock()
		delete(s.pending, msg.ID)
		s.mu.Unlock()
		return nil, err
	}
	return ch, nil
}

// DeliverResponse routes an incoming http_response to the waiting caller.
func (s *ShoreConnection) DeliverResponse(resp *HTTPResponseMessage) {
	s.mu.Lock()
	ch, ok := s.pending[resp.ID]
	if ok {
		delete(s.pending, resp.ID)
	}
	s.mu.Unlock()
	if ok {
		select {
		case ch <- resp:
		default:
		}
	}
}

// OpenStream registers a streaming channel and sends a stream_start to Shore.
// Returns the frame channel that will receive StreamFrameMessages.
func (s *ShoreConnection) OpenStream(msg StreamStartMessage) (chan *StreamFrameMessage, error) {
	ch := make(chan *StreamFrameMessage, 32)
	s.mu.Lock()
	s.streams[msg.ID] = ch
	s.mu.Unlock()

	if err := s.WriteJSON(msg); err != nil {
		s.mu.Lock()
		delete(s.streams, msg.ID)
		s.mu.Unlock()
		return nil, err
	}
	return ch, nil
}

// DeliverFrame routes an incoming stream_frame to the SSE handler.
func (s *ShoreConnection) DeliverFrame(frame *StreamFrameMessage) {
	s.mu.Lock()
	ch, ok := s.streams[frame.ID]
	s.mu.Unlock()
	if ok {
		select {
		case ch <- frame:
		default: // drop if channel is full (slow consumer)
		}
	}
}

// CloseStream closes and removes the frame channel for a given stream ID.
func (s *ShoreConnection) CloseStream(id string) {
	s.mu.Lock()
	ch, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	s.mu.Unlock()
	if ok {
		close(ch)
	}
}

// CancelPendingRequest removes a pending request without delivering a response.
func (s *ShoreConnection) CancelPendingRequest(id string) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

// Close tears down the connection exactly once.
func (s *ShoreConnection) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.Conn.Close()
	})
}

// ShoreRegistry is the in-memory registry of connected Shore instances.
type ShoreRegistry struct {
	mu     sync.RWMutex
	shores map[string]*ShoreConnection
}

// NewShoreRegistry creates an empty registry and starts the stale-connection reaper.
func NewShoreRegistry() *ShoreRegistry {
	r := &ShoreRegistry{
		shores: make(map[string]*ShoreConnection),
	}
	go r.runReaper()
	return r
}

// Register adds (or replaces) a Shore connection. If a previous connection with the
// same name exists it is cleanly closed.
func (r *ShoreRegistry) Register(shore *ShoreConnection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.shores[shore.Name]; ok {
		log.Printf("REGISTRY | replacing existing shore | name=%s", shore.Name)
		existing.Close()
	}
	r.shores[shore.Name] = shore
	log.Printf("REGISTRY | registered | name=%s | services=%v | addr=%s",
		shore.Name, shore.Services, shore.RemoteAddr)
}

// Unregister removes a Shore connection by name.
func (r *ShoreRegistry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.shores, name)
	log.Printf("REGISTRY | unregistered | name=%s", name)
}

// Get returns the named Shore if it is connected.
func (r *ShoreRegistry) Get(name string) (*ShoreConnection, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.shores[name]
	return s, ok
}

// Default returns any connected Shore (used when no path prefix is present).
// Returns the lexicographically first Shore for determinism.
func (r *ShoreRegistry) Default() (*ShoreConnection, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var first *ShoreConnection
	for _, s := range r.shores {
		if first == nil || s.Name < first.Name {
			first = s
		}
	}
	if first != nil {
		return first, true
	}
	return nil, false
}

// List returns a snapshot of all connected Shores.
func (r *ShoreRegistry) List() []*ShoreConnection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ShoreConnection, 0, len(r.shores))
	for _, s := range r.shores {
		out = append(out, s)
	}
	return out
}

// runReaper periodically removes Shores whose heartbeat has gone stale.
func (r *ShoreRegistry) runReaper() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		r.reap()
	}
}

func (r *ShoreRegistry) reap() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for name, shore := range r.shores {
		age := now.Sub(shore.LastPing)
		if age > staleThreshold {
			log.Printf("REAPER | stale shore | name=%s | last_ping=%s ago", name, age.Round(time.Second))
			shore.Close()
			delete(r.shores, name)
		}
	}
}
