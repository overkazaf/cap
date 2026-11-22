package redaction

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHeaders(t *testing.T) {
	input := map[string]string{
		"Authorization": "Bearer secret",
		"Content-Type":  "application/json",
		"X-API-KEY":     "secret",
		"Cookie":        "session=secret",
	}
	got := Headers(input)
	if got["Authorization"] != Placeholder || got["X-API-KEY"] != Placeholder || got["Cookie"] != Placeholder {
		t.Fatalf("got %#v", got)
	}
	if got["Content-Type"] != "application/json" {
		t.Fatalf("ordinary header changed: %#v", got)
	}
	if input["Authorization"] != "Bearer secret" {
		t.Fatal("input map mutated")
	}
}

func TestURL(t *testing.T) {
	got := URL("https://example.com/login?user=abc&token=secret&page=2")
	if strings.Contains(got, "secret") || !strings.Contains(got, "user=abc") || !strings.Contains(got, "page=2") {
		t.Fatalf("got %q", got)
	}
}

func TestURLInvalid(t *testing.T) {
	input := "://invalid"
	if got := URL(input); got != input {
		t.Fatalf("got %q", got)
	}
}

func TestBody(t *testing.T) {
	input := []byte(`{"user":"abc","password":"secret","nested":{"api_key":"secret"},"tokens":["one","two"],"safe":true}`)
	got, ok := Body(input)
	if !ok {
		t.Fatal("expected valid JSON")
	}
	var payload map[string]any
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["password"] != Placeholder {
		t.Fatalf("password = %#v", payload["password"])
	}
	nested := payload["nested"].(map[string]any)
	if nested["api_key"] != Placeholder {
		t.Fatalf("api_key = %#v", nested["api_key"])
	}
	if payload["user"] != "abc" || payload["safe"] != true {
		t.Fatalf("safe fields changed: %#v", payload)
	}
}

func TestBodyInvalid(t *testing.T) {
	input := []byte(`{"password":`)
	got, ok := Body(input)
	if ok || string(got) != string(input) {
		t.Fatalf("got %q, %v", got, ok)
	}
}
