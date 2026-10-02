package sequence_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/sequence"
)

// TestVariableSubstitution checks that "{{name}}" placeholders are
// substituted from Sequence.Variables into a step's URL (path and query),
// headers, and body before the request is sent.
func TestVariableSubstitution(t *testing.T) {
	var gotAuth, gotPath, gotQuery string
	var gotBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "substitution-test",
		Steps: []sequence.Step{
			{
				Method: "POST",
				URL:    server.URL + "/users/{{user_id}}?session={{token}}",
				Headers: map[string]string{
					"Authorization": "Bearer {{token}}",
				},
				Body: []byte(`{"id":"{{user_id}}"}`),
			},
		},
		Variables: []sequence.Variable{
			{Name: "token", Value: "secret-abc"},
			{Name: "user_id", Value: "42"},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}

	if gotAuth != "Bearer secret-abc" {
		t.Errorf("server saw Authorization %q, want %q", gotAuth, "Bearer secret-abc")
	}
	if gotPath != "/users/42" {
		t.Errorf("server saw path %q, want %q", gotPath, "/users/42")
	}
	if gotQuery != "session=secret-abc" {
		t.Errorf("server saw query %q, want %q", gotQuery, "session=secret-abc")
	}
	if string(gotBody) != `{"id":"42"}` {
		t.Errorf("server saw body %q, want %q", gotBody, `{"id":"42"}`)
	}
}

// TestReplay runs a two-step sequence (login, then an authenticated fetch)
// against a local test server, and checks that both the per-step results
// and the overall result accurately reflect what the server returned —
// including a body_json extraction feeding the second step's header.
func TestReplay(t *testing.T) {
	var gotAuth string

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"token":"tok-123"}}`))
	})
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"items":[1,2,3]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "login-then-fetch",
		Steps: []sequence.Step{
			{
				Method: "POST",
				URL:    server.URL + "/login",
				Extract: []sequence.Extraction{
					{Name: "token", Source: "body_json", Path: "data.token"},
				},
			},
			{
				Method: "GET",
				URL:    server.URL + "/data",
				Headers: map[string]string{
					"Authorization": "Bearer {{token}}",
				},
			},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("len(result.Steps) = %d, want 2", len(result.Steps))
	}

	s0 := result.Steps[0]
	if s0.StepIndex != 0 {
		t.Errorf("Steps[0].StepIndex = %d, want 0", s0.StepIndex)
	}
	if s0.Status != http.StatusOK {
		t.Errorf("Steps[0].Status = %d, want %d", s0.Status, http.StatusOK)
	}
	if s0.Body != `{"data":{"token":"tok-123"}}` {
		t.Errorf("Steps[0].Body = %q, want %q", s0.Body, `{"data":{"token":"tok-123"}}`)
	}
	if s0.Headers["Content-Type"] != "application/json" {
		t.Errorf("Steps[0].Headers[Content-Type] = %q, want application/json", s0.Headers["Content-Type"])
	}
	if s0.Error != "" {
		t.Errorf("Steps[0].Error = %q, want empty", s0.Error)
	}
	if s0.LatencyMs < 0 {
		t.Errorf("Steps[0].LatencyMs = %d, want >= 0", s0.LatencyMs)
	}

	s1 := result.Steps[1]
	if s1.StepIndex != 1 {
		t.Errorf("Steps[1].StepIndex = %d, want 1", s1.StepIndex)
	}
	if s1.Status != http.StatusCreated {
		t.Errorf("Steps[1].Status = %d, want %d", s1.Status, http.StatusCreated)
	}

	if gotAuth != "Bearer tok-123" {
		t.Errorf("server saw Authorization %q on step 2, want %q", gotAuth, "Bearer tok-123")
	}

	foundToken := false
	for _, v := range result.Variables {
		if v.Name == "token" {
			foundToken = true
			if v.Value != "tok-123" {
				t.Errorf("Variables[token] = %q, want %q", v.Value, "tok-123")
			}
		}
	}
	if !foundToken {
		t.Errorf("result.Variables missing %q, got %+v", "token", result.Variables)
	}
}

// TestCookiePropagation checks that a cookie set by step 1's response is
// automatically sent as the Cookie header on step 2's request.
func TestCookiePropagation(t *testing.T) {
	var gotCookie string

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "cookie-flow",
		Steps: []sequence.Step{
			{
				Method: "POST",
				URL:    server.URL + "/login",
				Extract: []sequence.Extraction{
					{Name: "cookie", Source: "cookie"},
				},
			},
			{
				Method: "GET",
				URL:    server.URL + "/data",
			},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}

	if gotCookie != "session=abc123" {
		t.Errorf("server saw Cookie %q on step 2, want %q", gotCookie, "session=abc123")
	}
}

// TestReplayJSONExtractionScalarTypes checks that body_json extraction
// renders non-string JSON leaves (numbers, booleans) as plain text, not as
// their original JSON encoding (e.g. "true", not quoted, and "3" rather
// than "3.0").
func TestReplayJSONExtractionScalarTypes(t *testing.T) {
	var gotLimit, gotActive string

	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"limit":3,"active":true}`))
	})
	mux.HandleFunc("/follow-up", func(w http.ResponseWriter, r *http.Request) {
		gotLimit = r.Header.Get("X-Limit")
		gotActive = r.Header.Get("X-Active")
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "scalar-extraction",
		Steps: []sequence.Step{
			{
				Method: "GET",
				URL:    server.URL + "/start",
				Extract: []sequence.Extraction{
					{Name: "limit", Source: "body_json", Path: "limit"},
					{Name: "active", Source: "body_json", Path: "active"},
				},
			},
			{
				Method: "GET",
				URL:    server.URL + "/follow-up",
				Headers: map[string]string{
					"X-Limit":  "{{limit}}",
					"X-Active": "{{active}}",
				},
			},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}

	if gotLimit != "3" {
		t.Errorf("server saw X-Limit %q, want %q", gotLimit, "3")
	}
	if gotActive != "true" {
		t.Errorf("server saw X-Active %q, want %q", gotActive, "true")
	}
}

// TestReplayExtractionPathNotFound checks that a body_json Extraction whose
// Path doesn't match anything in the response is a graceful no-op — the
// variable is simply never set — rather than aborting the sequence.
func TestReplayExtractionPathNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"token":"tok-123"}}`))
	}))
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "missing-path",
		Steps: []sequence.Step{
			{
				Method: "GET",
				URL:    server.URL,
				Extract: []sequence.Extraction{
					{Name: "missing", Source: "body_json", Path: "data.nonexistent"},
				},
			},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}

	for _, v := range result.Variables {
		if v.Name == "missing" {
			t.Errorf("Variables contains %q = %q, want it absent since the path didn't match", v.Name, v.Value)
		}
	}
}

// TestReplayExtractionNullField checks that a body_json Extraction whose
// Path resolves to a JSON null (a field that exists but has no value yet —
// e.g. a token before login completes) sets the variable to an empty
// string, distinct from a Path that doesn't match at all.
func TestReplayExtractionNullField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":null}`))
	}))
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "null-field",
		Steps: []sequence.Step{
			{
				Method: "GET",
				URL:    server.URL,
				Extract: []sequence.Extraction{
					{Name: "token", Source: "body_json", Path: "token"},
				},
			},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}

	found := false
	for _, v := range result.Variables {
		if v.Name == "token" {
			found = true
			if v.Value != "" {
				t.Errorf("Variables[token] = %q, want empty string for a JSON null", v.Value)
			}
		}
	}
	if !found {
		t.Error("result.Variables is missing \"token\" — a present-but-null field should still set the variable")
	}
}

// TestReplayCookieExtractionByName checks that setting Extraction.Path to a
// specific cookie name extracts just that cookie — out of several the
// response sets — and that the value propagated into the next step's
// Cookie header is still a well-formed "name=value" pair, not the bare
// cookie value.
func TestReplayCookieExtractionByName(t *testing.T) {
	var gotCookie string

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
		http.SetCookie(w, &http.Cookie{Name: "tracking", Value: "xyz999"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "cookie-by-name",
		Steps: []sequence.Step{
			{
				Method: "POST",
				URL:    server.URL + "/login",
				Extract: []sequence.Extraction{
					{Name: "session_cookie", Source: "cookie", Path: "session"},
				},
			},
			{
				Method: "GET",
				URL:    server.URL + "/data",
			},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}

	if gotCookie != "session=abc123" {
		t.Errorf("server saw Cookie %q on step 2, want %q", gotCookie, "session=abc123")
	}

	for _, v := range result.Variables {
		if v.Name == "session_cookie" && v.Value != "abc123" {
			t.Errorf("Variables[session_cookie] = %q, want bare value %q", v.Value, "abc123")
		}
	}
}

// TestReplayHeaderExtraction checks that a "header" Extraction pulls a
// named response header into a variable that a later step can then
// reference via "{{name}}".
func TestReplayHeaderExtraction(t *testing.T) {
	var gotRequestID string

	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req-789")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/follow-up", func(w http.ResponseWriter, r *http.Request) {
		gotRequestID = r.Header.Get("X-Request-Id")
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "header-extraction",
		Steps: []sequence.Step{
			{
				Method: "GET",
				URL:    server.URL + "/start",
				Extract: []sequence.Extraction{
					{Name: "request_id", Source: "header", Path: "X-Request-Id"},
				},
			},
			{
				Method: "GET",
				URL:    server.URL + "/follow-up",
				Headers: map[string]string{
					"X-Request-Id": "{{request_id}}",
				},
			},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}
	if gotRequestID != "req-789" {
		t.Errorf("server saw X-Request-Id %q on step 2, want %q", gotRequestID, "req-789")
	}
}

// TestReplayBaseURLOverride checks that ReplayOptions.BaseURL replaces the
// scheme and host of every step's URL while preserving its path, letting a
// captured sequence be replayed against a different environment.
func TestReplayBaseURLOverride(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	seq := &sequence.Sequence{
		Name: "base-url-test",
		Steps: []sequence.Step{
			{Method: "GET", URL: "https://original-host.invalid/ping"},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("result.Success = false, want true (Error = %q)", result.Error)
	}
	if gotPath != "/ping" {
		t.Errorf("server saw path %q, want %q", gotPath, "/ping")
	}
}

// TestReplayStepFailure checks that a step which cannot be completed (here,
// a connection to a server that is no longer listening) is reported through
// both the returned error and the result's Success/Error/StepResult.Error
// fields, rather than panicking or silently continuing.
func TestReplayStepFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	badURL := server.URL
	server.Close() // nothing is listening here anymore

	seq := &sequence.Sequence{
		Name: "will-fail",
		Steps: []sequence.Step{
			{Method: "GET", URL: badURL},
		},
	}

	result, err := sequence.Replay(seq, sequence.ReplayOptions{Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("Replay returned nil error, want an error from the unreachable step")
	}
	if result == nil {
		t.Fatal("Replay returned nil result, want a non-nil result carrying the error")
	}
	if result.Success {
		t.Error("result.Success = true, want false")
	}
	if result.Error == "" {
		t.Error("result.Error is empty, want a message describing the failure")
	}
	if len(result.Steps) != 1 {
		t.Fatalf("len(result.Steps) = %d, want 1", len(result.Steps))
	}
	if result.Steps[0].Error == "" {
		t.Error("Steps[0].Error is empty, want the connection error")
	}
}
