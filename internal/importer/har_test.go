package importer_test

import (
	"strings"
	"testing"

	"github.com/overkazaf/cap/internal/importer"
)

const sampleHAR = `{
  "log": {
    "entries": [
      {
        "startedDateTime": "2024-01-02T03:04:05Z",
        "request": {
          "method": "GET",
          "url": "https://example.com/api",
          "headers": [{"name": "Host", "value": "example.com"}]
        },
        "response": {
          "status": 200,
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "content": {"text": "{\"ok\":true}", "mimeType": "application/json"}
        },
        "time": 150
      },
      {
        "request": {
          "method": "POST",
          "url": "https://example.com/api/login",
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "postData": {"text": "{\"user\":\"alice\"}", "mimeType": "application/json"}
        },
        "response": {
          "status": 201,
          "headers": []
        },
        "time": 42.7
      }
    ]
  }
}`

// TestImportHAR parses a two-entry HAR document and checks that both flows
// come back with the expected method, URL, host, path, status, headers,
// bodies, latency and generated ID.
func TestImportHAR(t *testing.T) {
	flows, err := importer.ImportHAR(strings.NewReader(sampleHAR))
	if err != nil {
		t.Fatalf("ImportHAR returned error: %v", err)
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
	if f1.RespBodyType != "application/json" {
		t.Errorf("flows[0].RespBodyType = %q, want application/json", f1.RespBodyType)
	}
	if f1.RespHeaders["Content-Type"] != "application/json" {
		t.Errorf("flows[0].RespHeaders[Content-Type] = %q, want application/json", f1.RespHeaders["Content-Type"])
	}
	if f1.ReqHeaders["Host"] != "example.com" {
		t.Errorf("flows[0].ReqHeaders[Host] = %q, want example.com", f1.ReqHeaders["Host"])
	}
	if f1.Timestamp.IsZero() {
		t.Error("flows[0].Timestamp should be parsed from startedDateTime, got zero value")
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
	if f2.ReqBodyType != "application/json" {
		t.Errorf("flows[1].ReqBodyType = %q, want application/json", f2.ReqBodyType)
	}
	if f2.Status != 201 {
		t.Errorf("flows[1].Status = %d, want 201", f2.Status)
	}
	if f2.LatencyMs != 43 { // 42.7ms rounds to 43
		t.Errorf("flows[1].LatencyMs = %d, want 43 (42.7 rounded)", f2.LatencyMs)
	}
	if !f2.Timestamp.IsZero() {
		t.Errorf("flows[1].Timestamp = %v, want zero value (no startedDateTime in input)", f2.Timestamp)
	}
}

// TestImportHAREmpty checks that a HAR document with no entries produces an
// empty, non-nil flow slice and no error.
func TestImportHAREmpty(t *testing.T) {
	const empty = `{"log": {"entries": []}}`

	flows, err := importer.ImportHAR(strings.NewReader(empty))
	if err != nil {
		t.Fatalf("ImportHAR returned error: %v", err)
	}
	if flows == nil {
		t.Fatal("ImportHAR returned nil slice, want non-nil empty slice")
	}
	if len(flows) != 0 {
		t.Fatalf("len(flows) = %d, want 0", len(flows))
	}
}

// TestImportHARInvalidJSON checks that malformed input produces an error
// instead of a partial or panicking result.
func TestImportHARInvalidJSON(t *testing.T) {
	_, err := importer.ImportHAR(strings.NewReader(`{not valid json`))
	if err == nil {
		t.Fatal("ImportHAR returned nil error for malformed JSON, want an error")
	}
}
