package agent_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nongjiawu/cap/internal/export/agent"
	"github.com/nongjiawu/cap/internal/types"
)

// jsonLines splits JSONL output into its individual lines, trimming any
// trailing newline, and fails the test if any line is not valid JSON.
func jsonLines(t *testing.T, out []byte) []string {
	t.Helper()
	s := strings.TrimRight(string(out), "\n")
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\nline: %s", i, err, line)
		}
	}
	return lines
}

func TestFormatCompact(t *testing.T) {
	flows := []*types.Flow{
		{
			ID:        "f1",
			Method:    "POST",
			URL:       "https://api.com/login",
			Host:      "api.com",
			Path:      "/login",
			Status:    200,
			Timestamp: time.Now(),
			ReqHeaders: map[string]string{
				"Content-Type":    "application/json",
				"Accept-Encoding": "gzip",
				"Connection":      "keep-alive",
				"X-Forwarded-For": "1.2.3.4",
			},
			ReqBody:   []byte(`{"user":"a"}`),
			RespBody:  []byte(`{"token":"x"}`),
			LatencyMs: 100,
		},
	}

	out, err := agent.Format(flows, agent.FormatOptions{})
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}

	lines := jsonLines(t, out)
	if len(lines) != 1 {
		t.Fatalf("expected 1 JSONL line, got %d: %q", len(lines), string(out))
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("line is not valid JSON: %v", err)
	}
	if m["method"] != "POST" {
		t.Errorf("method = %v, want POST", m["method"])
	}
	if status, ok := m["status"].(float64); !ok || status != 200 {
		t.Errorf("status = %v, want 200", m["status"])
	}

	s := string(out)
	for _, noisy := range []string{"Accept-Encoding", "Connection", "X-Forwarded-For"} {
		if strings.Contains(s, noisy) {
			t.Errorf("noise header %q leaked into output: %s", noisy, s)
		}
	}
	if !strings.Contains(s, "Content-Type") {
		t.Error("non-noise header Content-Type should be preserved in output")
	}
}

func TestFormatTruncatesLargeBody(t *testing.T) {
	bigBody := bytes.Repeat([]byte("x"), 50000)
	flows := []*types.Flow{
		{
			ID:        "f1",
			Method:    "GET",
			URL:       "https://a.com/data",
			Status:    200,
			Timestamp: time.Now(),
			RespBody:  bigBody,
		},
	}

	out, err := agent.Format(flows, agent.FormatOptions{MaxBodySize: 1024})
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}
	if len(out) > 5000 {
		t.Errorf("output too large (%d bytes); large body should have been truncated", len(out))
	}
	if !strings.Contains(string(out), "truncated") {
		t.Error("expected a truncation marker in output")
	}
	jsonLines(t, out)
}

func TestDetectSignParams(t *testing.T) {
	flow := &types.Flow{
		URL:     "https://api.com/data?sign=abc123&timestamp=1696200000&nonce=xyz&user=test",
		ReqBody: []byte(`{"sign":"abc","ts":1696200000}`),
	}

	params := agent.DetectSignParams(flow)
	if len(params) == 0 {
		t.Fatal("expected sign params to be detected")
	}

	found := make(map[string]bool, len(params))
	for _, p := range params {
		found[strings.ToLower(p)] = true
	}

	if !found["sign"] {
		t.Error("missing 'sign' param")
	}
	if !found["timestamp"] && !found["ts"] {
		t.Error("missing a timestamp-like param")
	}
	if !found["nonce"] {
		t.Error("missing 'nonce' param")
	}
	if found["user"] {
		t.Error("'user' should not be flagged as a sign param")
	}
}

func TestDetectNoSignParams(t *testing.T) {
	flow := &types.Flow{
		URL:     "https://api.com/products?page=2&category=shoes&sort=price",
		ReqBody: []byte(`{"page":2,"category":"shoes"}`),
	}

	params := agent.DetectSignParams(flow)
	if len(params) != 0 {
		t.Errorf("expected no sign params, got %v", params)
	}
}

func TestFormatMultipleFlows(t *testing.T) {
	flows := []*types.Flow{
		{ID: "f1", Method: "GET", URL: "https://a.com/1", Status: 200, Timestamp: time.Now()},
		{ID: "f2", Method: "POST", URL: "https://a.com/2", Status: 201, Timestamp: time.Now()},
		{ID: "f3", Method: "DELETE", URL: "https://a.com/3", Status: 204, Timestamp: time.Now()},
	}

	out, err := agent.Format(flows, agent.FormatOptions{})
	if err != nil {
		t.Fatalf("Format returned error: %v", err)
	}

	lines := jsonLines(t, out)
	if len(lines) != 3 {
		t.Fatalf("expected 3 JSONL lines, got %d: %q", len(lines), string(out))
	}
}
