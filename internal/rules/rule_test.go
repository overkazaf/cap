package rules_test

import (
	"testing"

	"github.com/overkazaf/cap/internal/rules"
)

func TestMatcherBasic(t *testing.T) {
	tests := []struct {
		name                    string
		matcher                 rules.Matcher
		method, host, path, url string
		want                    bool
	}{
		{
			name:    "empty matcher matches anything",
			matcher: rules.Matcher{},
			method:  "GET", host: "example.com", path: "/foo", url: "http://example.com/foo",
			want: true,
		},
		{
			name:    "method exact match",
			matcher: rules.Matcher{Method: "POST"},
			method:  "POST", host: "example.com", path: "/foo", url: "http://example.com/foo",
			want: true,
		},
		{
			name:    "method mismatch",
			matcher: rules.Matcher{Method: "POST"},
			method:  "GET", host: "example.com", path: "/foo", url: "http://example.com/foo",
			want: false,
		},
		{
			name:    "method match is case-insensitive",
			matcher: rules.Matcher{Method: "post"},
			method:  "POST", host: "example.com", path: "/foo", url: "http://example.com/foo",
			want: true,
		},
		{
			name:    "host contains match",
			matcher: rules.Matcher{Host: "api.example.com"},
			method:  "GET", host: "api.example.com:443", path: "/foo", url: "https://api.example.com/foo",
			want: true,
		},
		{
			name:    "host mismatch",
			matcher: rules.Matcher{Host: "api.example.com"},
			method:  "GET", host: "other.com", path: "/foo", url: "https://other.com/foo",
			want: false,
		},
		{
			name:    "path contains match",
			matcher: rules.Matcher{Path: "/v1/users"},
			method:  "GET", host: "example.com", path: "/v1/users/42", url: "http://example.com/v1/users/42",
			want: true,
		},
		{
			name:    "path regex match",
			matcher: rules.Matcher{Path: `^/v1/users/\d+$`},
			method:  "GET", host: "example.com", path: "/v1/users/42", url: "http://example.com/v1/users/42",
			want: true,
		},
		{
			name:    "path regex mismatch",
			matcher: rules.Matcher{Path: `^/v1/users/\d+$`},
			method:  "GET", host: "example.com", path: "/v1/users/abc", url: "http://example.com/v1/users/abc",
			want: false,
		},
		{
			name:    "url contains match",
			matcher: rules.Matcher{URL: "token=secret"},
			method:  "GET", host: "example.com", path: "/foo", url: "http://example.com/foo?token=secret",
			want: true,
		},
		{
			name:    "url mismatch",
			matcher: rules.Matcher{URL: "token=secret"},
			method:  "GET", host: "example.com", path: "/foo", url: "http://example.com/foo?token=other",
			want: false,
		},
		{
			name:    "every non-empty field must match (AND semantics)",
			matcher: rules.Matcher{Method: "GET", Host: "example.com", Path: "/foo"},
			method:  "GET", host: "example.com", path: "/bar", url: "http://example.com/bar",
			want: false,
		},
		{
			name:    "path pattern that fails to compile as regex falls back to substring match",
			matcher: rules.Matcher{Path: "/api(v1"},
			method:  "GET", host: "example.com", path: "/api(v1/data", url: "http://example.com/api(v1/data",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.matcher.Matches(tt.method, tt.host, tt.path, tt.url, nil, nil)
			if got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherHeaders(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		headers map[string]string
		want    bool
	}{
		{
			name:    "exact key and contained value",
			header:  "X-Api-Key: secret",
			headers: map[string]string{"X-Api-Key": "secret-123"},
			want:    true,
		},
		{
			name:    "value mismatch",
			header:  "X-Api-Key: secret",
			headers: map[string]string{"X-Api-Key": "other"},
			want:    false,
		},
		{
			name:    "key missing",
			header:  "X-Api-Key: secret",
			headers: map[string]string{"X-Other": "secret"},
			want:    false,
		},
		{
			name:    "key match is case-insensitive",
			header:  "content-type: json",
			headers: map[string]string{"Content-Type": "application/json"},
			want:    true,
		},
		{
			name:    "bare key presence check (no colon)",
			header:  "X-Debug",
			headers: map[string]string{"X-Debug": "anything"},
			want:    true,
		},
		{
			name:    "bare key absent",
			header:  "X-Debug",
			headers: map[string]string{"X-Other": "anything"},
			want:    false,
		},
		{
			name:    "nil headers never match",
			header:  "X-Api-Key: secret",
			headers: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := rules.Matcher{Header: tt.header}
			got := m.Matches("GET", "example.com", "/", "http://example.com/", tt.headers, nil)
			if got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherBodyContains(t *testing.T) {
	m := rules.Matcher{BodyContains: "username"}

	if !m.Matches("POST", "example.com", "/login", "http://example.com/login", nil, []byte(`{"username":"neo"}`)) {
		t.Error("expected match: body contains substring")
	}
	if m.Matches("POST", "example.com", "/login", "http://example.com/login", nil, []byte(`{"email":"neo@x.com"}`)) {
		t.Error("expected no match: body does not contain substring")
	}
	if m.Matches("POST", "example.com", "/login", "http://example.com/login", nil, nil) {
		t.Error("expected no match: nil body")
	}
}
