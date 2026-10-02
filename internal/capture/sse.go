package capture

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

// NewSSECapture creates an SSECapture that invokes onEvent for every
// Server-Sent Event parsed by ParseSSEStream. onEvent may be nil, in which
// case ParseSSEStream still parses the stream (and reports any read error)
// but discards every event.
func NewSSECapture(onEvent func(*types.SSEEvent)) *SSECapture {
	return &SSECapture{onEvent: onEvent}
}

// SSECapture parses a text/event-stream (SSE) HTTP response body into
// discrete events, following the line-based field parsing rules of the
// WHATWG "Server-Sent Events" spec.
type SSECapture struct {
	onEvent func(*types.SSEEvent)
}

// ParseSSEStream reads body line by line until EOF (or a read error),
// accumulating fields into an event and dispatching it via onEvent, in
// order, each time a blank line is seen.
//
// Recognized fields:
//   - "data:"  appended to the event's Data, newline-joined across repeated
//     data lines within the same event.
//   - "event:" sets EventType.
//   - "id:"    sets EventID.
//   - "retry:" sets Retry, parsed as an integer (ignored, leaving Retry
//     unset, if the value isn't one).
//
// Lines starting with ":" are comments and ignored, as is any other
// unrecognized line. A single leading space immediately after a field's
// colon is stripped, per the SSE spec; further leading whitespace is kept.
//
// ParseSSEStream returns nil on a clean EOF. A stream that ends without a
// final blank line still has its last, otherwise-undispatched event
// delivered to onEvent before returning.
func (c *SSECapture) ParseSSEStream(body io.Reader, flowID string) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		dataLines []string
		eventType string
		eventID   string
		retry     int
	)

	hasContent := func() bool {
		return len(dataLines) > 0 || eventType != "" || eventID != "" || retry != 0
	}

	dispatch := func() {
		if !hasContent() {
			return
		}
		if c.onEvent != nil {
			c.onEvent(&types.SSEEvent{
				ID:        nextSSEEventID(),
				FlowID:    flowID,
				Timestamp: time.Now(),
				EventType: eventType,
				Data:      strings.Join(dataLines, "\n"),
				EventID:   eventID,
				Retry:     retry,
			})
		}
		dataLines = nil
		eventType = ""
		eventID = ""
		retry = 0
	}

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case line == "":
			dispatch()
		case strings.HasPrefix(line, ":"):
			// Comment line; ignored.
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, trimOneLeadingSpace(strings.TrimPrefix(line, "data:")))
		case strings.HasPrefix(line, "event:"):
			eventType = trimOneLeadingSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "id:"):
			eventID = trimOneLeadingSpace(strings.TrimPrefix(line, "id:"))
		case strings.HasPrefix(line, "retry:"):
			if n, err := strconv.Atoi(trimOneLeadingSpace(strings.TrimPrefix(line, "retry:"))); err == nil {
				retry = n
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("capture: read SSE stream: %w", err)
	}

	dispatch()

	return nil
}

// trimOneLeadingSpace removes a single leading space from s, if present —
// the SSE spec strips at most one space immediately following a field's
// colon, preserving the rest (including any further leading whitespace) as
// part of the value.
func trimOneLeadingSpace(s string) string {
	if strings.HasPrefix(s, " ") {
		return s[1:]
	}
	return s
}

var sseEventIDSeq atomic.Int64

// nextSSEEventID returns a unique, process-local ID for a captured
// types.SSEEvent (e.g. "sse1", "sse2", ...).
func nextSSEEventID() string {
	return fmt.Sprintf("sse%d", sseEventIDSeq.Add(1))
}
