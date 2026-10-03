package rules

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"
)

// RequestHandler returns a goproxy request handler (for
// gp.OnRequest().DoFunc(...)) that matches each request against e's rules
// and applies the matched rule's action:
//
//   - no match, or ActionPassthrough: the request is forwarded unmodified.
//   - ActionMock: a canned response is returned without contacting
//     upstream.
//   - ActionModifyReq: headers/body are edited, then the request forwards.
//   - ActionBreakpoint with BreakOnReq: the request pauses until resolved,
//     or DefaultBreakpointTimeout elapses — in which case it fails open and
//     forwards unmodified.
//   - ActionDrop: a 403 response is returned without contacting upstream.
//
// Whichever rule matched (or nil) is stashed in ctx.UserData so the
// ResponseHandler call for the same round trip can apply
// ActionModifyResp/BreakOnResp behavior for that *same* rule, rather than
// re-matching from scratch against response data and potentially landing on
// a different rule.
func (e *Engine) RequestHandler() func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	return func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		method := req.Method
		host := req.URL.Host
		if host == "" {
			host = req.Host
		}
		path := req.URL.Path
		fullURL := req.URL.String()
		headers := headerMap(req.Header)
		body := readAndRestoreRequestBody(req)

		rule := e.FindMatch(method, host, path, fullURL, headers, body)
		ctx.UserData = rule
		if rule == nil {
			return req, nil
		}

		switch rule.Action.Type {
		case ActionMock:
			return req, buildMockResponse(req, &rule.Action)

		case ActionDrop:
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by rule")

		case ActionModifyReq:
			applyRequestEdits(req, &rule.Action)
			return req, nil

		case ActionBreakpoint:
			if !rule.Action.BreakOnReq {
				return req, nil
			}
			bpID, _ := e.CreateBreakpoint(rule, method, fullURL, headers, body)
			res, err := e.WaitForBreakpoint(bpID, DefaultBreakpointTimeout)
			if err != nil {
				// Timed out (or otherwise failed to resolve): fail open
				// rather than hang the client indefinitely.
				return req, nil
			}
			switch res.Action {
			case "drop":
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by breakpoint")
			case "mock":
				return req, buildMockResponseFromResolution(req, res)
			default: // "forward"
				applyRequestResolution(req, res)
				return req, nil
			}

		default: // ActionPassthrough, ActionModifyResp, or unrecognized
			return req, nil
		}
	}
}

// ResponseHandler returns a goproxy response handler (for
// gp.OnResponse().DoFunc(...)) that applies ActionModifyResp/BreakOnResp
// behavior for whichever rule RequestHandler recorded in ctx.UserData for
// this round trip (see RequestHandler). It's a no-op if no rule matched, or
// if the matched rule's action isn't response-related.
func (e *Engine) ResponseHandler() func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	return func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}
		rule, _ := ctx.UserData.(*Rule)
		if rule == nil {
			return resp
		}

		switch rule.Action.Type {
		case ActionModifyResp:
			applyResponseEdits(resp, &rule.Action)
			return resp

		case ActionBreakpoint:
			req := ctx.Req
			if !rule.Action.BreakOnResp || req == nil {
				return resp
			}
			bpID, _ := e.CreateBreakpoint(rule, req.Method, req.URL.String(), headerMap(resp.Header), readAndRestoreResponseBody(resp))
			res, err := e.WaitForBreakpoint(bpID, DefaultBreakpointTimeout)
			if err != nil {
				// Timed out: fail open, returning the original response.
				return resp
			}
			if res.Action == "drop" {
				return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by breakpoint")
			}
			applyResponseResolution(resp, res)
			return resp

		default:
			return resp
		}
	}
}

// headerMap flattens an http.Header into the map[string]string shape rules
// are matched/reported against, joining repeated values with "; ".
func headerMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vals := range h {
		m[k] = strings.Join(vals, "; ")
	}
	return m
}

// readAndRestoreRequestBody reads req.Body (if any) and immediately
// replaces it with a fresh reader over the same bytes, so the real request
// proceeds unaffected regardless of what the matched rule (if any) does
// with the returned bytes.
func readAndRestoreRequestBody(req *http.Request) []byte {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	req.Body = io.NopCloser(bytes.NewReader(b))
	return b
}

// readAndRestoreResponseBody is readAndRestoreRequestBody's response-side
// counterpart, used when a response breakpoint needs to show the body
// without consuming it for the real client.
func readAndRestoreResponseBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return b
}

// buildMockResponse builds the canned response for an ActionMock rule.
func buildMockResponse(req *http.Request, a *Action) *http.Response {
	status := a.MockStatus
	if status == 0 {
		status = http.StatusOK
	}
	resp := goproxy.NewResponse(req, goproxy.ContentTypeText, status, a.MockBody)
	for k, v := range a.MockHeaders {
		resp.Header.Set(k, v)
	}
	return resp
}

// buildMockResponseFromResolution builds the canned response for a request
// breakpoint resolved with Action == "mock".
func buildMockResponseFromResolution(req *http.Request, res *BreakpointResolution) *http.Response {
	status := res.Status
	if status == 0 {
		status = http.StatusOK
	}
	resp := goproxy.NewResponse(req, goproxy.ContentTypeText, status, string(res.RespBody))
	for k, v := range res.RespHeaders {
		resp.Header.Set(k, v)
	}
	return resp
}

// applyRequestEdits applies an ActionModifyReq action's edits to req.
func applyRequestEdits(req *http.Request, a *Action) {
	for k, v := range a.SetHeaders {
		req.Header.Set(k, v)
	}
	for _, k := range a.DelHeaders {
		req.Header.Del(k)
	}
	if a.ReplaceBody != "" {
		setRequestBody(req, []byte(a.ReplaceBody))
	}
}

// applyRequestResolution applies a "forward" breakpoint resolution to req.
// Zero-value fields leave the corresponding part of the request unchanged;
// Headers are merged (set/overwritten) rather than replacing the whole
// header set.
func applyRequestResolution(req *http.Request, res *BreakpointResolution) {
	if res.Method != "" {
		req.Method = res.Method
	}
	if res.URL != "" {
		if u, err := url.Parse(res.URL); err == nil {
			req.URL = u
			req.Host = u.Host
		}
	}
	for k, v := range res.Headers {
		req.Header.Set(k, v)
	}
	if res.Body != nil {
		setRequestBody(req, res.Body)
	}
}

// applyResponseEdits applies an ActionModifyResp action's edits to resp.
func applyResponseEdits(resp *http.Response, a *Action) {
	for k, v := range a.SetRespHeaders {
		resp.Header.Set(k, v)
	}
	if a.ReplaceRespBody != "" {
		setResponseBody(resp, []byte(a.ReplaceRespBody))
	}
	if a.SetStatus != 0 {
		resp.StatusCode = a.SetStatus
		resp.Status = http.StatusText(a.SetStatus)
	}
}

// applyResponseResolution applies a non-"drop" response-breakpoint
// resolution to resp, reusing the same Status/RespHeaders/RespBody fields a
// request breakpoint's "mock" resolution uses.
func applyResponseResolution(resp *http.Response, res *BreakpointResolution) {
	for k, v := range res.RespHeaders {
		resp.Header.Set(k, v)
	}
	if res.RespBody != nil {
		setResponseBody(resp, res.RespBody)
	}
	if res.Status != 0 {
		resp.StatusCode = res.Status
		resp.Status = http.StatusText(res.Status)
	}
}

func setRequestBody(req *http.Request, body []byte) {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
}

func setResponseBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
}
