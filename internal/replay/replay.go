// Package replay rebuilds a captured HTTP flow into a real request, resends
// it — optionally with modifications — using net/http, and reports how the
// new response differs from the one that was originally captured. It backs
// cap's "replay / modify and replay" feature for probing how a
// reverse-engineered API behaves when a request is repeated or tweaked.
package replay

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

// defaultTimeout is used whenever Options.Timeout is left at its zero value.
// A literal zero-duration timeout would make every replay fail instantly, so
// (unlike http.Client, which treats a zero Timeout as "wait forever") zero
// here means "use the default" instead.
const defaultTimeout = 30 * time.Second

// Options configures how a flow is replayed.
type Options struct {
	// Timeout bounds the whole round trip (connect, write request, read
	// response). The zero value is treated as the documented default of
	// 30s rather than an instant timeout.
	Timeout time.Duration

	// FollowRedirects controls whether 3xx responses are followed
	// automatically. Documented default: true. Note that since Go has no
	// "unset bool", the zero value of Options{} is false (don't follow) —
	// callers that want the documented default must set this explicitly.
	FollowRedirects bool

	// InsecureSkipVerify disables TLS certificate verification on the
	// outgoing request, for targets presenting self-signed certificates.
	InsecureSkipVerify bool
}

// Modifications describes changes to apply to a flow before replaying it.
// Zero-value fields mean "keep the original": an empty URL/Method keeps the
// original URL/method, and a nil Body keeps the original body. DelHeaders is
// applied before SetHeaders, so a key listed in both ends up set.
type Modifications struct {
	URL        string            // override URL (empty = keep original)
	Method     string            // override method (empty = keep original)
	SetHeaders map[string]string // headers to add or replace
	DelHeaders []string          // header keys to remove before sending
	Body       []byte            // override body (nil = keep original)
}

// HeaderDiff describes a single response header that differs between the
// original and replayed flow.
type HeaderDiff struct {
	Key      string
	Original string
	Replayed string
	Type     string // "added", "removed", or "changed"
}

// Diff summarizes how a replayed response differs from the originally
// captured one. See ComputeDiff.
type Diff struct {
	StatusChanged bool
	StatusDiff    string // e.g. "200 → 403"; set only when StatusChanged
	HeadersDiff   []HeaderDiff
	BodyDiff      string // human-readable summary of body differences
	LatencyDiff   int64  // absolute ms difference between the two latencies
}

// Result is the outcome of replaying a flow.
type Result struct {
	// Original is the flow that was replayed, unmodified.
	Original *types.Flow
	// Replayed is the newly captured flow, or nil if the request could not
	// be completed — see Error.
	Replayed *types.Flow
	// Diff compares Original and Replayed, or nil if Replayed is nil.
	Diff *Diff
	// Error is set if building or sending the replayed request failed.
	Error error
}

// Replay resends flow exactly as captured — same method, URL, headers and
// body — and reports how the response compares to the original.
func Replay(flow *types.Flow, opts Options) (*Result, error) {
	return ReplayModified(flow, Modifications{}, opts)
}

// ReplayModified resends flow after applying mods (URL/method override,
// header additions/removals, body override), and reports how the response
// compares to the original flow.
//
// A non-nil error is returned whenever the replayed request could not be
// completed — including flow being nil. In every case but a nil flow, the
// returned Result is still non-nil and carries the same error in its Error
// field, so callers that only care about the display-friendly Result can
// check result.Error instead of the second return value.
func ReplayModified(flow *types.Flow, mods Modifications, opts Options) (*Result, error) {
	if flow == nil {
		return nil, errors.New("replay: flow is nil")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}

	reqURL := flow.URL
	if mods.URL != "" {
		reqURL = mods.URL
	}
	method := flow.Method
	if mods.Method != "" {
		method = mods.Method
	}
	body := flow.ReqBody
	if mods.Body != nil {
		body = mods.Body
	}
	headers := mergeHeaders(flow.ReqHeaders, mods.SetHeaders, mods.DelHeaders)

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		err = fmt.Errorf("replay: build request: %w", err)
		return &Result{Original: flow, Error: err}, err
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			//nolint:gosec // explicit opt-in via Options.InsecureSkipVerify, documented above.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
		},
	}
	if !opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	start := time.Now()
	httpResp, err := client.Do(httpReq)
	if err != nil {
		err = fmt.Errorf("replay: send request: %w", err)
		return &Result{Original: flow, Error: err}, err
	}
	defer httpResp.Body.Close()
	latency := time.Since(start).Milliseconds()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		err = fmt.Errorf("replay: read response body: %w", err)
		return &Result{Original: flow, Error: err}, err
	}

	replayed := &types.Flow{
		ID:           flow.ID + "-replay",
		Timestamp:    start,
		Method:       method,
		URL:          reqURL,
		Host:         httpReq.URL.Host,
		Path:         httpReq.URL.Path,
		ReqHeaders:   headers,
		ReqBody:      body,
		ReqBodyType:  httpReq.Header.Get("Content-Type"),
		Status:       httpResp.StatusCode,
		RespHeaders:  flattenHeaders(httpResp.Header),
		RespBody:     respBody,
		RespBodyType: httpResp.Header.Get("Content-Type"),
		LatencyMs:    latency,
	}

	return &Result{
		Original: flow,
		Replayed: replayed,
		Diff:     ComputeDiff(flow, replayed),
	}, nil
}

// mergeHeaders combines a flow's original request headers with
// Modifications, canonicalizing keys (via http.CanonicalHeaderKey) so that,
// e.g., "x-custom" and "X-Custom" refer to the same header regardless of
// casing. del is applied before set, so a key listed in both ends up set.
func mergeHeaders(original, set map[string]string, del []string) map[string]string {
	merged := make(map[string]string, len(original)+len(set))
	for k, v := range original {
		merged[http.CanonicalHeaderKey(k)] = v
	}
	for _, k := range del {
		delete(merged, http.CanonicalHeaderKey(k))
	}
	for k, v := range set {
		merged[http.CanonicalHeaderKey(k)] = v
	}
	return merged
}

// flattenHeaders collapses an http.Header (map[string][]string) down to the
// map[string]string shape types.Flow stores, joining repeated values —
// mirroring internal/proxy's capture behavior so a replayed flow looks the
// same as one captured live by the proxy.
func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vals := range h {
		m[k] = strings.Join(vals, "; ")
	}
	return m
}
