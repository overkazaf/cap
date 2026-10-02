package types

import "time"

// WSFrame is a single captured WebSocket frame (RFC 6455), associated with
// the HTTP flow whose Upgrade handshake established the connection it rode
// on.
type WSFrame struct {
	ID        string    `json:"id"`
	FlowID    string    `json:"flow_id"` // parent HTTP upgrade flow
	Timestamp time.Time `json:"ts"`
	Direction string    `json:"direction"` // "client" or "server"
	Opcode    int       `json:"opcode"`    // 1=text, 2=binary, 8=close, 9=ping, 10=pong
	Data      []byte    `json:"data,omitempty"`
	Len       int       `json:"len"`
	IsFinal   bool      `json:"is_final"`
}

// SSEEvent is a single captured Server-Sent Event, associated with the HTTP
// flow whose request produced the text/event-stream response it was parsed
// from.
type SSEEvent struct {
	ID        string    `json:"id"`
	FlowID    string    `json:"flow_id"` // parent HTTP request flow
	Timestamp time.Time `json:"ts"`
	EventType string    `json:"event_type"` // SSE event type
	Data      string    `json:"data"`
	EventID   string    `json:"event_id,omitempty"` // SSE id field
	Retry     int       `json:"retry,omitempty"`
}
