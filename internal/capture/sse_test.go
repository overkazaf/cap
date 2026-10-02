package capture_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/overkazaf/cap/internal/capture"
	"github.com/overkazaf/cap/internal/types"
)

func TestParseSSEBasic(t *testing.T) {
	var got *types.SSEEvent
	c := capture.NewSSECapture(func(e *types.SSEEvent) { got = e })

	if err := c.ParseSSEStream(strings.NewReader("data: hello\n\n"), "flow-sse-1"); err != nil {
		t.Fatalf("ParseSSEStream: %v", err)
	}

	if got == nil {
		t.Fatal("no event captured")
	}
	if got.Data != "hello" {
		t.Errorf("Data = %q, want %q", got.Data, "hello")
	}
	if got.FlowID != "flow-sse-1" {
		t.Errorf("FlowID = %q, want %q", got.FlowID, "flow-sse-1")
	}
}

func TestParseSSEMultiLine(t *testing.T) {
	var got *types.SSEEvent
	c := capture.NewSSECapture(func(e *types.SSEEvent) { got = e })

	stream := "data: line1\ndata: line2\n\n"
	if err := c.ParseSSEStream(strings.NewReader(stream), "flow1"); err != nil {
		t.Fatalf("ParseSSEStream: %v", err)
	}

	if got == nil {
		t.Fatal("no event captured")
	}
	want := "line1\nline2"
	if got.Data != want {
		t.Errorf("Data = %q, want %q", got.Data, want)
	}
}

func TestParseSSEEventType(t *testing.T) {
	var got *types.SSEEvent
	c := capture.NewSSECapture(func(e *types.SSEEvent) { got = e })

	stream := "event: update\ndata: {}\n\n"
	if err := c.ParseSSEStream(strings.NewReader(stream), "flow1"); err != nil {
		t.Fatalf("ParseSSEStream: %v", err)
	}

	if got == nil {
		t.Fatal("no event captured")
	}
	if got.EventType != "update" {
		t.Errorf("EventType = %q, want %q", got.EventType, "update")
	}
	if got.Data != "{}" {
		t.Errorf("Data = %q, want %q", got.Data, "{}")
	}
}

func TestParseSSEMultipleEvents(t *testing.T) {
	var got []*types.SSEEvent
	c := capture.NewSSECapture(func(e *types.SSEEvent) { got = append(got, e) })

	stream := "data: one\n\ndata: two\n\ndata: three\n\n"
	if err := c.ParseSSEStream(strings.NewReader(stream), "flow1"); err != nil {
		t.Fatalf("ParseSSEStream: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	want := []string{"one", "two", "three"}
	for i, e := range got {
		if e.Data != want[i] {
			t.Errorf("event %d Data = %q, want %q", i, e.Data, want[i])
		}
		if e.FlowID != "flow1" {
			t.Errorf("event %d FlowID = %q, want %q", i, e.FlowID, "flow1")
		}
	}
}

func TestParseSSEIDAndRetry(t *testing.T) {
	var got *types.SSEEvent
	c := capture.NewSSECapture(func(e *types.SSEEvent) { got = e })

	stream := "id: 42\nretry: 5000\ndata: ping\n\n"
	if err := c.ParseSSEStream(strings.NewReader(stream), "flow1"); err != nil {
		t.Fatalf("ParseSSEStream: %v", err)
	}

	if got == nil {
		t.Fatal("no event captured")
	}
	if got.EventID != "42" {
		t.Errorf("EventID = %q, want %q", got.EventID, "42")
	}
	if got.Retry != 5000 {
		t.Errorf("Retry = %d, want 5000", got.Retry)
	}
}

func TestParseSSECommentsIgnored(t *testing.T) {
	var got []*types.SSEEvent
	c := capture.NewSSECapture(func(e *types.SSEEvent) { got = append(got, e) })

	stream := ": this is a comment\ndata: real\n: another comment\n\n"
	if err := c.ParseSSEStream(strings.NewReader(stream), "flow1"); err != nil {
		t.Fatalf("ParseSSEStream: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Data != "real" {
		t.Errorf("Data = %q, want %q", got[0].Data, "real")
	}
}

func TestParseSSENoTrailingBlankLineStillDispatches(t *testing.T) {
	var got *types.SSEEvent
	c := capture.NewSSECapture(func(e *types.SSEEvent) { got = e })

	// No trailing blank line: the stream (and the underlying connection)
	// simply ends right after the last data line.
	if err := c.ParseSSEStream(strings.NewReader("data: trailing"), "flow1"); err != nil {
		t.Fatalf("ParseSSEStream: %v", err)
	}

	if got == nil {
		t.Fatal("expected the trailing event to still be dispatched on EOF")
	}
	if got.Data != "trailing" {
		t.Errorf("Data = %q, want %q", got.Data, "trailing")
	}
}

func TestParseSSENilOnEventIsSafe(t *testing.T) {
	c := capture.NewSSECapture(nil)
	if err := c.ParseSSEStream(strings.NewReader("data: hello\n\n"), "flow1"); err != nil {
		t.Fatalf("ParseSSEStream with nil onEvent: %v", err)
	}
}

// errReader is an io.Reader that always fails with err, used to exercise
// ParseSSEStream's read-error path.
type errReader struct{ err error }

func (r *errReader) Read(p []byte) (int, error) { return 0, r.err }

func TestParseSSEReadError(t *testing.T) {
	c := capture.NewSSECapture(nil)
	wantErr := errors.New("boom")

	err := c.ParseSSEStream(&errReader{err: wantErr}, "flow1")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
}
