// Package rules implements cap's real-time traffic interception and rules
// engine: user-defined rules are matched against live HTTP requests flowing
// through the MITM proxy (see internal/proxy) and can mock, modify, drop, or
// pause ("breakpoint") a request or its response before it reaches its
// destination.
package rules

import (
	"bytes"
	"regexp"
	"strings"
)

// Rule is a single traffic-interception rule: when a request matches Match,
// Action describes what the engine should do with it (see
// Engine.FindMatch).
type Rule struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Enabled  bool    `json:"enabled"`
	Priority int     `json:"priority"` // lower = higher priority
	Match    Matcher `json:"match"`
	Action   Action  `json:"action"`
}

// Matcher describes the criteria a request must satisfy for a Rule to
// apply. Every non-empty field must match (AND semantics); a Matcher with
// every field left at its zero value matches any request.
type Matcher struct {
	// Method is matched case-insensitively against the request method
	// ("GET", "POST", ...). Empty matches any method.
	Method string `json:"method,omitempty"`
	// Host is matched as a substring of the request's host[:port]. Empty
	// matches any host.
	Host string `json:"host,omitempty"`
	// Path is matched against the request's URL path. It is tried first as
	// a regular expression (so e.g. `^/v1/users/\d+$` works) and, only if
	// it fails to compile, falls back to a plain substring match. Note
	// that a literal path is itself a valid (if boring) regular
	// expression, so characters like "." act as wildcards unless escaped
	// ("\."). Empty matches any path.
	Path string `json:"path,omitempty"`
	// URL is matched as a substring of the full request URL (including
	// any query string). Empty matches any URL.
	URL string `json:"url,omitempty"`
	// Header matches a single request header, written as "Key: Value".
	// The key is matched case-insensitively; the value is matched as a
	// substring of the header's actual value. A value-less "Key" (no
	// colon) matches when the header is present with any value. Empty
	// matches any request.
	Header string `json:"header,omitempty"`
	// BodyContains is matched as a substring of the raw request body.
	// Empty matches any body.
	BodyContains string `json:"body_contains,omitempty"`
}

// ActionType names the effect a Rule has on a matched request/response.
type ActionType string

const (
	// ActionPassthrough forwards the request/response unmodified. This is
	// also the effective behavior when Action.Type is left as the zero
	// value.
	ActionPassthrough ActionType = "passthrough"
	// ActionMock short-circuits the request, returning a canned response
	// without contacting the upstream server.
	ActionMock ActionType = "mock"
	// ActionModifyReq edits the request (headers and/or body) before it is
	// forwarded upstream.
	ActionModifyReq ActionType = "modify_request"
	// ActionModifyResp edits the response (headers, body and/or status)
	// before it is returned to the client.
	ActionModifyResp ActionType = "modify_response"
	// ActionBreakpoint pauses the request and/or response for manual
	// inspection/editing; see Action.BreakOnReq, Action.BreakOnResp and
	// Engine.CreateBreakpoint.
	ActionBreakpoint ActionType = "breakpoint"
	// ActionDrop blocks the request, returning a 403 to the client without
	// contacting the upstream server.
	ActionDrop ActionType = "drop"
)

// Action describes what Engine's handlers do with a request/response that
// matched a Rule's Matcher. Only the fields relevant to Type are used.
type Action struct {
	Type ActionType `json:"type"`

	// For ActionMock: the canned response returned instead of forwarding.
	MockStatus  int               `json:"mock_status,omitempty"`
	MockHeaders map[string]string `json:"mock_headers,omitempty"`
	MockBody    string            `json:"mock_body,omitempty"`

	// For ActionModifyReq: edits applied to the request before
	// forwarding. SetHeaders adds/overwrites the named headers;
	// DelHeaders removes them (applied after SetHeaders); a non-empty
	// ReplaceBody replaces the entire request body — there is no way to
	// explicitly replace it with an empty body via this field, so leave
	// it empty to keep the original body untouched.
	SetHeaders  map[string]string `json:"set_headers,omitempty"`
	DelHeaders  []string          `json:"del_headers,omitempty"`
	ReplaceBody string            `json:"replace_body,omitempty"`

	// For ActionModifyResp: edits applied to the response before it
	// reaches the client. Same conventions as the request fields above.
	SetRespHeaders  map[string]string `json:"set_resp_headers,omitempty"`
	ReplaceRespBody string            `json:"replace_resp_body,omitempty"`
	SetStatus       int               `json:"set_status,omitempty"`

	// For ActionBreakpoint: which phase(s) pause for manual resolution.
	BreakOnReq  bool `json:"break_on_req,omitempty"`
	BreakOnResp bool `json:"break_on_resp,omitempty"`
}

// Matches reports whether a request/response described by the given fields
// satisfies every non-empty criterion in m. headers and body may be nil.
func (m *Matcher) Matches(method, host, path, url string, headers map[string]string, body []byte) bool {
	if m.Method != "" && !strings.EqualFold(m.Method, method) {
		return false
	}
	if m.Host != "" && !strings.Contains(host, m.Host) {
		return false
	}
	if m.Path != "" && !matchPath(m.Path, path) {
		return false
	}
	if m.URL != "" && !strings.Contains(url, m.URL) {
		return false
	}
	if m.Header != "" && !matchHeader(m.Header, headers) {
		return false
	}
	if m.BodyContains != "" && !bytes.Contains(body, []byte(m.BodyContains)) {
		return false
	}
	return true
}

// matchPath matches pattern against path, trying pattern as a regular
// expression first and falling back to a plain substring check if it
// doesn't compile as one.
func matchPath(pattern, path string) bool {
	if re, err := regexp.Compile(pattern); err == nil {
		return re.MatchString(path)
	}
	return strings.Contains(path, pattern)
}

// matchHeader implements Matcher.Header's "Key: Value" (or bare "Key")
// matching against a flattened header map, with a case-insensitive key
// lookup and substring value match.
func matchHeader(spec string, headers map[string]string) bool {
	key, val, hasColon := strings.Cut(spec, ":")
	key = strings.TrimSpace(key)
	val = strings.TrimSpace(val)

	for hk, hv := range headers {
		if !strings.EqualFold(hk, key) {
			continue
		}
		if !hasColon || val == "" {
			return true
		}
		return strings.Contains(hv, val)
	}
	return false
}
