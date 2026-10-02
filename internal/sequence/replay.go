package sequence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultTimeout bounds each step's round trip when ReplayOptions.Timeout
// is left at its zero value — a literal zero Duration would make every
// step fail instantly rather than use a sensible default.
const defaultTimeout = 30 * time.Second

// ReplayOptions configures how a Sequence is replayed.
type ReplayOptions struct {
	// Timeout bounds each step's round trip (connect, write, read). The
	// zero value is treated as the documented default of 30s.
	Timeout time.Duration

	// BaseURL, if set, replaces the scheme and host of every step's URL
	// (its path, query and fragment are kept), letting a sequence captured
	// against one environment be replayed against another.
	BaseURL string
}

// ReplayResult is the outcome of replaying every step of a Sequence.
type ReplayResult struct {
	Steps     []StepResult `json:"steps"`
	Variables []Variable   `json:"variables"`
	Success   bool         `json:"success"`
	Error     string       `json:"error,omitempty"`
}

// StepResult is the outcome of replaying a single Step.
type StepResult struct {
	StepIndex int               `json:"step_index"`
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	LatencyMs int64             `json:"latency_ms"`
	Error     string            `json:"error,omitempty"`
}

// varPattern matches a "{{name}}" placeholder, tolerating extra whitespace
// inside the braces (e.g. "{{ name }}").
var varPattern = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)

// Replay executes every step of seq in order against the real network,
// substituting "{{variable_name}}" placeholders from the current variable
// set into each step's URL, headers and body before sending it, then
// running that step's Extract rules against the response to update the
// variable set for subsequent steps. A cookie extraction additionally
// arms automatic propagation: once any step yields one, its value is sent
// as the Cookie header on every later step, independent of templating.
//
// Replay stops at the first step whose request cannot be completed (the
// request can't be built, the network call fails, or the response body
// can't be read) and reports that failure via both the returned error and
// result.Success/result.Error — an HTTP error status from a step that DID
// complete (e.g. a 404 or 500) is not treated as a failure and does not
// stop the sequence. In every case the returned result is non-nil, with
// Steps holding every step executed so far, so a caller only interested in
// the display-friendly result can check result.Error instead of the second
// return value.
func Replay(seq *Sequence, opts ReplayOptions) (*ReplayResult, error) {
	if seq == nil {
		return nil, fmt.Errorf("sequence: seq is nil")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}

	vars := make(map[string]string, len(seq.Variables))
	for _, v := range seq.Variables {
		vars[v.Name] = v.Value
	}

	client := &http.Client{Timeout: opts.Timeout}
	result := &ReplayResult{
		Steps:   make([]StepResult, 0, len(seq.Steps)),
		Success: true,
	}

	var cookieHeader string

	for i, step := range seq.Steps {
		sr, respForExtraction, failErr := runStep(client, opts, i, step, vars, cookieHeader)
		result.Steps = append(result.Steps, sr)
		if failErr != nil {
			result.Success = false
			result.Error = failErr.Error()
			result.Variables = varsToSlice(vars)
			return result, failErr
		}

		for _, ext := range step.Extract {
			switch ext.Source {
			case "header":
				if v, ok := getHeaderCI(sr.Headers, ext.Path); ok {
					vars[ext.Name] = v
				}
			case "cookie":
				if varValue, headerValue, ok := extractCookie(respForExtraction, ext.Path); ok {
					vars[ext.Name] = varValue
					cookieHeader = headerValue
				}
			case "body_json":
				if v, ok := extractJSONPath([]byte(sr.Body), ext.Path); ok {
					vars[ext.Name] = v
				}
			}
		}
	}

	result.Variables = varsToSlice(vars)
	return result, nil
}

// runStep sends a single step's request and returns its StepResult. On
// success, it also returns the *http.Response (still only header/cookie
// data is used from it — the body has already been drained into
// StepResult.Body) so the cookie extraction can see Set-Cookie headers; on
// failure, failErr is non-nil and resp is nil.
func runStep(client *http.Client, opts ReplayOptions, index int, step Step, vars map[string]string, cookieHeader string) (StepResult, *http.Response, error) {
	stepURL, err := buildStepURL(step.URL, opts.BaseURL, vars)
	if err != nil {
		failErr := fmt.Errorf("sequence: step %d: %w", index, err)
		return StepResult{StepIndex: index, Error: failErr.Error()}, nil, failErr
	}

	var bodyReader io.Reader
	if len(step.Body) > 0 {
		bodyReader = bytes.NewReader([]byte(substitute(string(step.Body), vars)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, step.Method, stepURL, bodyReader)
	if err != nil {
		failErr := fmt.Errorf("sequence: step %d: build request: %w", index, err)
		return StepResult{StepIndex: index, Error: failErr.Error()}, nil, failErr
	}
	for k, v := range step.Headers {
		httpReq.Header.Set(k, substitute(v, vars))
	}
	if cookieHeader != "" {
		httpReq.Header.Set("Cookie", cookieHeader)
	}

	start := time.Now()
	httpResp, err := client.Do(httpReq)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		failErr := fmt.Errorf("sequence: step %d: send request: %w", index, err)
		return StepResult{StepIndex: index, LatencyMs: latency, Error: failErr.Error()}, nil, failErr
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		failErr := fmt.Errorf("sequence: step %d: read response: %w", index, err)
		return StepResult{StepIndex: index, Status: httpResp.StatusCode, LatencyMs: latency, Error: failErr.Error()}, nil, failErr
	}

	sr := StepResult{
		StepIndex: index,
		Status:    httpResp.StatusCode,
		Headers:   flattenHeaders(httpResp.Header),
		Body:      string(respBody),
		LatencyMs: latency,
	}
	return sr, httpResp, nil
}

// buildStepURL substitutes variables into rawURL, then, if baseURL is set,
// overrides its scheme and host with baseURL's (keeping path/query/
// fragment) — see ReplayOptions.BaseURL.
func buildStepURL(rawURL, baseURL string, vars map[string]string) (string, error) {
	substituted := substitute(rawURL, vars)
	if baseURL == "" {
		return substituted, nil
	}

	u, err := url.Parse(substituted)
	if err != nil {
		return "", fmt.Errorf("parse step URL %q: %w", substituted, err)
	}
	b, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL %q: %w", baseURL, err)
	}
	u.Scheme = b.Scheme
	u.Host = b.Host
	return u.String(), nil
}

// substitute replaces every "{{name}}" placeholder in s with vars[name].
// A placeholder naming an unknown variable is left untouched, so a typo or
// a not-yet-extracted variable is easy to spot rather than silently
// becoming an empty string.
func substitute(s string, vars map[string]string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return varPattern.ReplaceAllStringFunc(s, func(match string) string {
		name := varPattern.FindStringSubmatch(match)[1]
		if v, ok := vars[name]; ok {
			return v
		}
		return match
	})
}

// extractCookie reads cookies from resp and returns two representations of
// what was found: varValue is what gets stored as the Extraction's named
// Variable, and headerValue is what gets auto-propagated as the literal
// Cookie header on later steps (see Replay) — always a well-formed
// "name=value" pair (or several, "; "-joined), never a bare value, since
// that's what a server expects a Cookie header to contain.
//
// If name is empty, both values are every cookie in the response joined as
// "a=1; b=2" (there's no single bare "value" for a whole jar). If name
// names one cookie, varValue is just that cookie's bare value (handy for
// referencing via "{{name}}" outside of a Cookie header) while headerValue
// is still "name=value".
func extractCookie(resp *http.Response, name string) (varValue, headerValue string, ok bool) {
	if resp == nil {
		return "", "", false
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return "", "", false
	}
	if name != "" {
		for _, c := range cookies {
			if c.Name == name {
				return c.Value, c.Name + "=" + c.Value, true
			}
		}
		return "", "", false
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	joined := strings.Join(parts, "; ")
	return joined, joined, true
}

// extractJSONPath parses body as JSON and walks path's dot-separated
// segments (e.g. "data.token") through nested objects, returning the
// leaf value formatted as a string.
func extractJSONPath(body []byte, path string) (string, bool) {
	if len(body) == 0 || path == "" {
		return "", false
	}
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", false
	}

	cur := data
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		v, ok := m[seg]
		if !ok {
			return "", false
		}
		cur = v
	}
	return jsonScalarToString(cur), true
}

// jsonScalarToString renders a decoded JSON value as plain text for use as
// a Variable's value: strings pass through unquoted, numbers avoid
// unnecessary trailing zeros or scientific notation, and anything
// non-scalar (object/array) falls back to its compact JSON form.
func jsonScalarToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		if b, err := json.Marshal(t); err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", t)
	}
}

// flattenHeaders collapses an http.Header (map[string][]string) down to the
// map[string]string shape StepResult uses, joining repeated values.
func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vals := range h {
		m[k] = strings.Join(vals, "; ")
	}
	return m
}

// varsToSlice renders the current variable set as a sorted []Variable, so
// ReplayResult.Variables is in deterministic (alphabetical) order.
func varsToSlice(vars map[string]string) []Variable {
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Variable, 0, len(names))
	for _, name := range names {
		out = append(out, Variable{Name: name, Value: vars[name]})
	}
	return out
}
