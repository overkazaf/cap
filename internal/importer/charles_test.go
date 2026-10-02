package importer_test

import (
	"strings"
	"testing"

	"github.com/overkazaf/cap/internal/importer"
)

const sampleCharles = `<?xml version="1.0" encoding="UTF-8"?>
<charles-session>
  <transaction>
    <request method="GET" url="https://example.com/api">
      <header name="Host" value="example.com"/>
      <body></body>
    </request>
    <response status="200">
      <header name="Content-Type" value="application/json"/>
      <body>{"ok":true}</body>
    </response>
    <duration>150</duration>
  </transaction>
  <transaction>
    <request method="POST" url="https://example.com/api/login">
      <header name="Content-Type" value="application/json"/>
      <body>{"user":"alice"}</body>
    </request>
    <response status="201">
    </response>
    <duration>42</duration>
  </transaction>
</charles-session>`

// TestImportCharles parses a two-transaction Charles session export and
// checks that both flows come back with the expected method, URL, host,
// path, status, headers, bodies, latency and generated ID.
func TestImportCharles(t *testing.T) {
	flows, err := importer.ImportCharles(strings.NewReader(sampleCharles))
	if err != nil {
		t.Fatalf("ImportCharles returned error: %v", err)
	}
	if len(flows) != 2 {
		t.Fatalf("len(flows) = %d, want 2", len(flows))
	}

	f1 := flows[0]
	if f1.ID != "imp-1" {
		t.Errorf("flows[0].ID = %q, want %q", f1.ID, "imp-1")
	}
	if f1.Method != "GET" {
		t.Errorf("flows[0].Method = %q, want GET", f1.Method)
	}
	if f1.URL != "https://example.com/api" {
		t.Errorf("flows[0].URL = %q, want https://example.com/api", f1.URL)
	}
	if f1.Host != "example.com" {
		t.Errorf("flows[0].Host = %q, want example.com", f1.Host)
	}
	if f1.Path != "/api" {
		t.Errorf("flows[0].Path = %q, want /api", f1.Path)
	}
	if f1.Status != 200 {
		t.Errorf("flows[0].Status = %d, want 200", f1.Status)
	}
	if f1.LatencyMs != 150 {
		t.Errorf("flows[0].LatencyMs = %d, want 150", f1.LatencyMs)
	}
	if string(f1.RespBody) != `{"ok":true}` {
		t.Errorf("flows[0].RespBody = %q, want %q", f1.RespBody, `{"ok":true}`)
	}
	if f1.RespHeaders["Content-Type"] != "application/json" {
		t.Errorf("flows[0].RespHeaders[Content-Type] = %q, want application/json", f1.RespHeaders["Content-Type"])
	}
	if f1.ReqHeaders["Host"] != "example.com" {
		t.Errorf("flows[0].ReqHeaders[Host] = %q, want example.com", f1.ReqHeaders["Host"])
	}
	if f1.ReqBody != nil {
		t.Errorf("flows[0].ReqBody = %q, want nil for an empty <body>", f1.ReqBody)
	}

	f2 := flows[1]
	if f2.ID != "imp-2" {
		t.Errorf("flows[1].ID = %q, want %q", f2.ID, "imp-2")
	}
	if f2.Method != "POST" {
		t.Errorf("flows[1].Method = %q, want POST", f2.Method)
	}
	if f2.Path != "/api/login" {
		t.Errorf("flows[1].Path = %q, want /api/login", f2.Path)
	}
	if string(f2.ReqBody) != `{"user":"alice"}` {
		t.Errorf("flows[1].ReqBody = %q, want %q", f2.ReqBody, `{"user":"alice"}`)
	}
	if f2.Status != 201 {
		t.Errorf("flows[1].Status = %d, want 201", f2.Status)
	}
	if f2.LatencyMs != 42 {
		t.Errorf("flows[1].LatencyMs = %d, want 42", f2.LatencyMs)
	}
}

// TestImportCharlesEmpty checks that a session with no transactions
// produces an empty, non-nil flow slice and no error.
func TestImportCharlesEmpty(t *testing.T) {
	const empty = `<charles-session></charles-session>`

	flows, err := importer.ImportCharles(strings.NewReader(empty))
	if err != nil {
		t.Fatalf("ImportCharles returned error: %v", err)
	}
	if flows == nil {
		t.Fatal("ImportCharles returned nil slice, want non-nil empty slice")
	}
	if len(flows) != 0 {
		t.Fatalf("len(flows) = %d, want 0", len(flows))
	}
}

// TestImportCharlesInvalidXML checks that malformed or wrong-root input
// produces an error instead of a silently empty or partial result.
func TestImportCharlesInvalidXML(t *testing.T) {
	_, err := importer.ImportCharles(strings.NewReader(`<not-a-charles-session>`))
	if err == nil {
		t.Fatal("ImportCharles returned nil error for malformed XML, want an error")
	}
}
