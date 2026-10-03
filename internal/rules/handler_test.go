package rules_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/overkazaf/cap/internal/rules"
)

// waitForPendingBreakpoint polls e until exactly one breakpoint is pending,
// returning its ID. It fails the test if none appears in time.
func waitForPendingBreakpoint(t *testing.T, e *rules.Engine) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pending := e.ListPendingBreakpoints(); len(pending) == 1 {
			return pending[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a pending breakpoint to appear")
	return ""
}

func TestMockAction(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "mock1",
		Enabled: true,
		Match:   rules.Matcher{Path: "/api/mock"},
		Action: rules.Action{
			Type:        rules.ActionMock,
			MockStatus:  201,
			MockHeaders: map[string]string{"X-Mocked": "yes"},
			MockBody:    `{"mocked":true}`,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/mock", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	gotReq, gotResp := e.RequestHandler()(req, ctx)
	if gotReq == nil {
		t.Fatal("expected the request to still be returned, got nil")
	}
	if gotResp == nil {
		t.Fatal("expected a mock response, got nil")
	}
	if gotResp.StatusCode != 201 {
		t.Errorf("StatusCode = %d, want 201", gotResp.StatusCode)
	}
	if gotResp.Header.Get("X-Mocked") != "yes" {
		t.Errorf("X-Mocked header = %q, want yes", gotResp.Header.Get("X-Mocked"))
	}
	body, _ := io.ReadAll(gotResp.Body)
	if string(body) != `{"mocked":true}` {
		t.Errorf("body = %q, want %q", body, `{"mocked":true}`)
	}
}

func TestMockActionDefaultStatus(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "mock2",
		Enabled: true,
		Match:   rules.Matcher{Path: "/api/mock2"},
		Action:  rules.Action{Type: rules.ActionMock, MockBody: "ok"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/mock2", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	_, gotResp := e.RequestHandler()(req, ctx)
	if gotResp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200 (default)", gotResp.StatusCode)
	}
}

func TestModifyRequest(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "mod1",
		Enabled: true,
		Match:   rules.Matcher{Path: "/api/modify"},
		Action: rules.Action{
			Type:       rules.ActionModifyReq,
			SetHeaders: map[string]string{"X-Injected": "hello"},
			DelHeaders: []string{"X-Remove-Me"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/modify", nil)
	req.Header.Set("X-Remove-Me", "bye")
	ctx := &goproxy.ProxyCtx{Req: req}

	gotReq, gotResp := e.RequestHandler()(req, ctx)
	if gotResp != nil {
		t.Fatalf("expected no response (continue to upstream), got status %d", gotResp.StatusCode)
	}
	if gotReq.Header.Get("X-Injected") != "hello" {
		t.Errorf("X-Injected header = %q, want hello", gotReq.Header.Get("X-Injected"))
	}
	if gotReq.Header.Get("X-Remove-Me") != "" {
		t.Errorf("X-Remove-Me header should have been removed, got %q", gotReq.Header.Get("X-Remove-Me"))
	}
}

func TestModifyRequestReplacesBody(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "mod2",
		Enabled: true,
		Match:   rules.Matcher{Path: "/api/body"},
		Action:  rules.Action{Type: rules.ActionModifyReq, ReplaceBody: `{"patched":true}`},
	})

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/body", strings.NewReader(`{"orig":true}`))
	ctx := &goproxy.ProxyCtx{Req: req}

	gotReq, _ := e.RequestHandler()(req, ctx)
	body, _ := io.ReadAll(gotReq.Body)
	if string(body) != `{"patched":true}` {
		t.Errorf("body = %q, want %q", body, `{"patched":true}`)
	}
}

func TestModifyRequestPreservesBodyWhenNotReplaced(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "mod3",
		Enabled: true,
		Match:   rules.Matcher{Path: "/api/keep-body"},
		Action:  rules.Action{Type: rules.ActionModifyReq, SetHeaders: map[string]string{"X-A": "B"}},
	})

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/keep-body", strings.NewReader(`{"orig":true}`))
	ctx := &goproxy.ProxyCtx{Req: req}

	gotReq, _ := e.RequestHandler()(req, ctx)
	body, _ := io.ReadAll(gotReq.Body)
	if string(body) != `{"orig":true}` {
		t.Errorf("body = %q, want original body preserved: %q", body, `{"orig":true}`)
	}
}

func TestDropAction(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "drop1",
		Enabled: true,
		Match:   rules.Matcher{Path: "/forbidden"},
		Action:  rules.Action{Type: rules.ActionDrop},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/forbidden", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	_, gotResp := e.RequestHandler()(req, ctx)
	if gotResp == nil {
		t.Fatal("expected a blocking response, got nil")
	}
	if gotResp.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", gotResp.StatusCode)
	}
}

func TestPassthroughNoMatch(t *testing.T) {
	e := rules.NewEngine() // no rules at all

	req := httptest.NewRequest(http.MethodGet, "http://example.com/anything", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	gotReq, gotResp := e.RequestHandler()(req, ctx)
	if gotResp != nil {
		t.Errorf("expected nil response for passthrough, got status %d", gotResp.StatusCode)
	}
	if gotReq != req {
		t.Error("expected the same request to be returned unchanged")
	}
}

func TestResponseHandlerNoOpWithoutMatchedRule(t *testing.T) {
	e := rules.NewEngine() // no rules; RequestHandler never ran either

	req := httptest.NewRequest(http.MethodGet, "http://example.com/anything", nil)
	ctx := &goproxy.ProxyCtx{Req: req}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("hi"))}

	got := e.ResponseHandler()(resp, ctx)
	if got != resp {
		t.Error("expected the same response to be returned unchanged")
	}
}

func TestResponseHandlerNilResponsePassesThrough(t *testing.T) {
	e := rules.NewEngine()
	ctx := &goproxy.ProxyCtx{}

	if got := e.ResponseHandler()(nil, ctx); got != nil {
		t.Errorf("expected nil response to stay nil, got %v", got)
	}
}

func TestResponseHandlerIgnoresNonResponseActions(t *testing.T) {
	// A mock rule only has request-phase effects; ResponseHandler should
	// leave the (already-mocked) response alone when it sees one.
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "mock-passthrough",
		Enabled: true,
		Match:   rules.Matcher{Path: "/api/mock"},
		Action:  rules.Action{Type: rules.ActionMock, MockBody: "hi"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/mock", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	_, mockResp := e.RequestHandler()(req, ctx)
	if mockResp == nil {
		t.Fatal("expected a mock response from the request phase")
	}

	got := e.ResponseHandler()(mockResp, ctx)
	if got != mockResp {
		t.Error("expected ResponseHandler to pass a non-response-action rule's response through unchanged")
	}
}

func TestModifyResponse(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "modresp1",
		Enabled: true,
		Match:   rules.Matcher{Path: "/api/resp"},
		Action: rules.Action{
			Type:            rules.ActionModifyResp,
			SetRespHeaders:  map[string]string{"X-Patched": "yes"},
			ReplaceRespBody: `{"patched":true}`,
			SetStatus:       202,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/resp", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	// Run the request phase first so the engine records which rule governs
	// this flow — ResponseHandler relies on ctx.UserData set by
	// RequestHandler rather than re-matching from scratch.
	_, shortCircuit := e.RequestHandler()(req, ctx)
	if shortCircuit != nil {
		t.Fatalf("modify_response rule should not short-circuit the request, got status %d", shortCircuit.StatusCode)
	}

	origResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"original":true}`)),
		Request:    req,
	}

	gotResp := e.ResponseHandler()(origResp, ctx)
	if gotResp.StatusCode != 202 {
		t.Errorf("StatusCode = %d, want 202", gotResp.StatusCode)
	}
	if gotResp.Header.Get("X-Patched") != "yes" {
		t.Errorf("X-Patched header = %q, want yes", gotResp.Header.Get("X-Patched"))
	}
	body, _ := io.ReadAll(gotResp.Body)
	if string(body) != `{"patched":true}` {
		t.Errorf("body = %q, want %q", body, `{"patched":true}`)
	}
}

func TestBreakpoint(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "bp1",
		Name:    "pause-on-login",
		Enabled: true,
		Match:   rules.Matcher{Path: "/login"},
		Action:  rules.Action{Type: rules.ActionBreakpoint, BreakOnReq: true},
	})

	req := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(`{"user":"neo"}`))
	ctx := &goproxy.ProxyCtx{Req: req}

	type result struct {
		req  *http.Request
		resp *http.Response
	}
	resultCh := make(chan result, 1)
	go func() {
		gotReq, gotResp := e.RequestHandler()(req, ctx)
		resultCh <- result{gotReq, gotResp}
	}()

	bpID := waitForPendingBreakpoint(t, e)

	// Simulate a user editing the paused request in a UI and approving it.
	if err := e.ResolveBreakpoint(bpID, &rules.BreakpointResolution{
		Action:  "forward",
		Headers: map[string]string{"X-Approved": "true"},
	}); err != nil {
		t.Fatalf("ResolveBreakpoint: %v", err)
	}

	select {
	case r := <-resultCh:
		if r.resp != nil {
			t.Fatalf("expected the request to forward (no response), got status %d", r.resp.StatusCode)
		}
		if r.req.Header.Get("X-Approved") != "true" {
			t.Errorf("X-Approved header = %q, want true", r.req.Header.Get("X-Approved"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RequestHandler to complete after resolving the breakpoint")
	}
}

func TestBreakpointResolvedWithMethodAndURLChange(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "bp-edit",
		Enabled: true,
		Match:   rules.Matcher{Path: "/login"},
		Action:  rules.Action{Type: rules.ActionBreakpoint, BreakOnReq: true},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/login", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	type result struct {
		req  *http.Request
		resp *http.Response
	}
	resultCh := make(chan result, 1)
	go func() {
		gotReq, gotResp := e.RequestHandler()(req, ctx)
		resultCh <- result{gotReq, gotResp}
	}()

	bpID := waitForPendingBreakpoint(t, e)
	if err := e.ResolveBreakpoint(bpID, &rules.BreakpointResolution{
		Action: "forward",
		Method: http.MethodPost,
		URL:    "http://other.example.com/v2/login",
	}); err != nil {
		t.Fatalf("ResolveBreakpoint: %v", err)
	}

	select {
	case r := <-resultCh:
		if r.req.Method != http.MethodPost {
			t.Errorf("Method = %q, want POST", r.req.Method)
		}
		if r.req.URL.String() != "http://other.example.com/v2/login" {
			t.Errorf("URL = %q, want %q", r.req.URL.String(), "http://other.example.com/v2/login")
		}
		if r.req.Host != "other.example.com" {
			t.Errorf("Host = %q, want other.example.com", r.req.Host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RequestHandler to complete after resolving the breakpoint")
	}
}

func TestBreakpointResolvedAsDrop(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "bp2",
		Enabled: true,
		Match:   rules.Matcher{Path: "/secret"},
		Action:  rules.Action{Type: rules.ActionBreakpoint, BreakOnReq: true},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/secret", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	resultCh := make(chan *http.Response, 1)
	go func() {
		_, gotResp := e.RequestHandler()(req, ctx)
		resultCh <- gotResp
	}()

	bpID := waitForPendingBreakpoint(t, e)
	if err := e.ResolveBreakpoint(bpID, &rules.BreakpointResolution{Action: "drop"}); err != nil {
		t.Fatalf("ResolveBreakpoint: %v", err)
	}

	select {
	case resp := <-resultCh:
		if resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected a 403 response from the drop resolution, got %v", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RequestHandler to complete after resolving the breakpoint")
	}
}

func TestBreakpointResolvedAsMock(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "bp3",
		Enabled: true,
		Match:   rules.Matcher{Path: "/mockme"},
		Action:  rules.Action{Type: rules.ActionBreakpoint, BreakOnReq: true},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/mockme", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	resultCh := make(chan *http.Response, 1)
	go func() {
		_, gotResp := e.RequestHandler()(req, ctx)
		resultCh <- gotResp
	}()

	bpID := waitForPendingBreakpoint(t, e)
	if err := e.ResolveBreakpoint(bpID, &rules.BreakpointResolution{
		Action:      "mock",
		Status:      418,
		RespHeaders: map[string]string{"X-Teapot": "yes"},
		RespBody:    []byte("I'm a teapot"),
	}); err != nil {
		t.Fatalf("ResolveBreakpoint: %v", err)
	}

	select {
	case resp := <-resultCh:
		if resp == nil {
			t.Fatal("expected a mock response, got nil")
		}
		if resp.StatusCode != 418 {
			t.Errorf("StatusCode = %d, want 418", resp.StatusCode)
		}
		if resp.Header.Get("X-Teapot") != "yes" {
			t.Errorf("X-Teapot header = %q, want yes", resp.Header.Get("X-Teapot"))
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "I'm a teapot" {
			t.Errorf("body = %q, want %q", body, "I'm a teapot")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RequestHandler to complete after resolving the breakpoint")
	}
}

func TestBreakpointResolvedAsMockDefaultStatus(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "bp-mock-default",
		Enabled: true,
		Match:   rules.Matcher{Path: "/mockdefault"},
		Action:  rules.Action{Type: rules.ActionBreakpoint, BreakOnReq: true},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/mockdefault", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	resultCh := make(chan *http.Response, 1)
	go func() {
		_, gotResp := e.RequestHandler()(req, ctx)
		resultCh <- gotResp
	}()

	bpID := waitForPendingBreakpoint(t, e)
	if err := e.ResolveBreakpoint(bpID, &rules.BreakpointResolution{Action: "mock", RespBody: []byte("ok")}); err != nil {
		t.Fatalf("ResolveBreakpoint: %v", err)
	}

	select {
	case resp := <-resultCh:
		if resp.StatusCode != http.StatusOK {
			t.Errorf("StatusCode = %d, want 200 (default)", resp.StatusCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RequestHandler to complete after resolving the breakpoint")
	}
}

func TestBreakpointOnResponse(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{
		ID:      "bp4",
		Enabled: true,
		Match:   rules.Matcher{Path: "/api/resp-pause"},
		Action:  rules.Action{Type: rules.ActionBreakpoint, BreakOnResp: true},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/resp-pause", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	// Request phase: BreakOnReq is false, so it should just record the rule
	// and pass through without pausing.
	gotReq, shortCircuit := e.RequestHandler()(req, ctx)
	if shortCircuit != nil {
		t.Fatalf("expected no short-circuit on the request phase, got status %d", shortCircuit.StatusCode)
	}
	if gotReq != req {
		t.Error("expected the same request back from the request phase")
	}

	origResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("original")),
		Request:    req,
	}

	resultCh := make(chan *http.Response, 1)
	go func() {
		resultCh <- e.ResponseHandler()(origResp, ctx)
	}()

	bpID := waitForPendingBreakpoint(t, e)
	pending := e.ListPendingBreakpoints()
	if len(pending) != 1 || pending[0].Body != "original" {
		t.Fatalf("pending breakpoint should carry the response body, got %+v", pending)
	}

	if err := e.ResolveBreakpoint(bpID, &rules.BreakpointResolution{
		Action:      "forward",
		Status:      201,
		RespHeaders: map[string]string{"X-Edited": "yes"},
		RespBody:    []byte("edited"),
	}); err != nil {
		t.Fatalf("ResolveBreakpoint: %v", err)
	}

	select {
	case resp := <-resultCh:
		if resp.StatusCode != 201 {
			t.Errorf("StatusCode = %d, want 201", resp.StatusCode)
		}
		if resp.Header.Get("X-Edited") != "yes" {
			t.Errorf("X-Edited header = %q, want yes", resp.Header.Get("X-Edited"))
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "edited" {
			t.Errorf("body = %q, want %q", body, "edited")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ResponseHandler to complete after resolving the breakpoint")
	}
}
