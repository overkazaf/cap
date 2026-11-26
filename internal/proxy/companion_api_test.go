package proxy_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/overkazaf/cap/internal/proxy"
)

type apiStatsResp struct {
	OK            bool    `json:"ok"`
	ProxyAddr     string  `json:"proxy_addr"`
	TotalFlows    int64   `json:"total_flows"`
	BufferedFlows int     `json:"buffered_flows"`
	LatestSeq     int64   `json:"latest_seq"`
	TotalBytes    int64   `json:"total_bytes"`
	ReqPerSec     float64 `json:"req_per_sec"`
	UptimeSec     int64   `json:"uptime_sec"`
}

type apiFlowsResp struct {
	OK            bool                         `json:"ok"`
	LatestSeq     int64                        `json:"latest_seq"`
	TotalFlows    int64                        `json:"total_flows"`
	BufferedFlows int                          `json:"buffered_flows"`
	TotalBytes    int64                        `json:"total_bytes"`
	ReqPerSec     float64                      `json:"req_per_sec"`
	Flows         []proxy.CompanionFlowSummary `json:"flows"`
}

type apiFlowDetailResp struct {
	OK   bool                      `json:"ok"`
	Flow proxy.CompanionFlowDetail `json:"flow"`
}

type apiClearResp struct {
	OK        bool  `json:"ok"`
	LatestSeq int64 `json:"latest_seq"`
}

type apiErrResp struct {
	Error string `json:"error"`
}

func directCompanionClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
		Timeout: 5 * time.Second,
	}
}

func doCompanionRequest(t *testing.T, client *http.Client, method, addr, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, nil)
	if err != nil {
		t.Fatalf("build companion request %s %s: %v", method, path, err)
	}
	if token != "" {
		req.Header.Set("X-Cap-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("companion request %s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read companion response %s %s: %v", method, path, err)
	}
	return resp, body
}

func TestEnsureCompanionTokenCreatesReusesAndValidates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested-cap")

	tok1, err := proxy.EnsureCompanionToken(dir)
	if err != nil {
		t.Fatalf("EnsureCompanionToken (create): %v", err)
	}
	if len(tok1) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars (%q)", len(tok1), tok1)
	}
	for i := 0; i < len(tok1); i++ {
		c := tok1[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("token contains non-lowercase-hex char %q in %q", c, tok1)
		}
	}

	tokenPath := filepath.Join(dir, "companion.token")
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat companion.token: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("companion.token perm = %04o, want 0600", perm)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat certDir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("certDir perm = %04o, want 0700", perm)
	}

	// Second call must reuse the exact same token.
	tok2, err := proxy.EnsureCompanionToken(dir)
	if err != nil {
		t.Fatalf("EnsureCompanionToken (reuse): %v", err)
	}
	if tok2 != tok1 {
		t.Fatalf("token changed on reuse: %q != %q", tok2, tok1)
	}

	// Custom valid 32-hex-char token must be respected.
	custom32 := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(tokenPath, []byte("  "+custom32+"\n"), 0o600); err != nil {
		t.Fatalf("write custom token: %v", err)
	}
	tok3, err := proxy.EnsureCompanionToken(dir)
	if err != nil {
		t.Fatalf("EnsureCompanionToken (custom32): %v", err)
	}
	if tok3 != custom32 {
		t.Fatalf("got %q, want %q", tok3, custom32)
	}

	// Invalid (short / non-hex) token file must be replaced with a fresh 64-char token.
	for _, bad := range []string{"short", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", ""} {
		if err := os.WriteFile(tokenPath, []byte(bad), 0o600); err != nil {
			t.Fatalf("write bad token %q: %v", bad, err)
		}
		tokRegen, err := proxy.EnsureCompanionToken(dir)
		if err != nil {
			t.Fatalf("EnsureCompanionToken (regen from %q): %v", bad, err)
		}
		if len(tokRegen) != 64 {
			t.Fatalf("regenerated token len = %d, want 64", len(tokRegen))
		}
	}

	// Default certDir ("") should write to $HOME/.cap/companion.token.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	defaultTok, err := proxy.EnsureCompanionToken("")
	if err != nil {
		t.Fatalf("EnsureCompanionToken default dir: %v", err)
	}
	if len(defaultTok) != 64 {
		t.Fatalf("default token len = %d, want 64", len(defaultTok))
	}
	raw, err := os.ReadFile(filepath.Join(fakeHome, ".cap", "companion.token"))
	if err != nil {
		t.Fatalf("read default companion.token: %v", err)
	}
	if strings.TrimSpace(string(raw)) != defaultTok {
		t.Fatalf("disk token %q != returned token %q", strings.TrimSpace(string(raw)), defaultTok)
	}
}

func TestCompanionAPIAuthHeadersAndNotRecordedAsFlow(t *testing.T) {
	const testToken = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	p, flows, _ := startProxy(t, proxy.Options{
		CompanionToken: testToken,
	})
	if p.CompanionToken() != testToken {
		t.Fatalf("CompanionToken() = %q, want %q", p.CompanionToken(), testToken)
	}

	direct := directCompanionClient()
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/_cap/companion/stats"},
		{http.MethodGet, "/_cap/companion/flows"},
		{http.MethodGet, "/_cap/companion/flows/f1"},
		{http.MethodPost, "/_cap/companion/clear"},
		{http.MethodGet, "/_cap/companion/unknown"},
	}

	// Missing, short, and same-length wrong tokens must all get 401.
	badTokens := []string{
		"",
		"short",
		"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778890", // 1 char diff, same length
	}
	for _, ep := range endpoints {
		for _, tok := range badTokens {
			resp, body := doCompanionRequest(t, direct, ep.method, p.Addr(), ep.path, tok)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s (tok=%q): status=%d, want 401 (body=%s)", ep.method, ep.path, tok, resp.StatusCode, body)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Errorf("%s %s: Content-Type=%q, want application/json; charset=utf-8", ep.method, ep.path, ct)
			}
			if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("%s %s: Cache-Control=%q, want no-store", ep.method, ep.path, cc)
			}
			var er apiErrResp
			if err := json.Unmarshal(body, &er); err != nil || er.Error != "unauthorized" {
				t.Errorf("%s %s: body=%s, want {\"error\":\"unauthorized\"}", ep.method, ep.path, body)
			}
		}
	}

	// Authorized calls succeed and check headers + method enforcement.
	resp, body := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/stats", testToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /stats status=%d body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type=%q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control=%q", cc)
	}
	var st apiStatsResp
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}
	if !st.OK || st.ProxyAddr != p.Addr() || st.TotalFlows != 0 || st.BufferedFlows != 0 || st.LatestSeq != 0 {
		t.Fatalf("unexpected initial stats: %+v", st)
	}

	// Method-not-allowed checks
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/_cap/companion/stats"},
		{http.MethodPost, "/_cap/companion/flows"},
		{http.MethodDelete, "/_cap/companion/flows/f1"},
		{http.MethodGet, "/_cap/companion/clear"},
	} {
		r, _ := doCompanionRequest(t, direct, tc.method, p.Addr(), tc.path, testToken)
		if r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status=%d, want 405", tc.method, tc.path, r.StatusCode)
		}
	}

	// Unknown route with valid auth -> 404
	r404, _ := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/does-not-exist", testToken)
	if r404.StatusCode != http.StatusNotFound {
		t.Errorf("unknown route status=%d, want 404", r404.StatusCode)
	}

	// Verify NONE of the direct /_cap/companion/* calls triggered OnFlow or populated /flows.
	select {
	case f := <-flows:
		t.Fatalf("direct companion API request was unexpectedly captured as a flow: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
	_, flowsBody := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows", testToken)
	var fl apiFlowsResp
	if err := json.Unmarshal(flowsBody, &fl); err != nil {
		t.Fatalf("unmarshal flows: %v", err)
	}
	if !fl.OK || fl.TotalFlows != 0 || fl.BufferedFlows != 0 || len(fl.Flows) != 0 {
		t.Fatalf("expected 0 flows after companion API calls, got %+v", fl)
	}
	// Ensure empty flows serializes as [] rather than null.
	if !strings.Contains(string(flowsBody), `"flows":[]`) {
		t.Errorf("expected empty flows JSON array [], got %s", flowsBody)
	}
}

func TestCompanionAPIDisabledOption(t *testing.T) {
	p, _, _ := startProxy(t, proxy.Options{
		DisableCompanionAPI: true,
	})
	if p.CompanionToken() != "" {
		t.Fatalf("expected empty CompanionToken when disabled, got %q", p.CompanionToken())
	}
	direct := directCompanionClient()
	resp, _ := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/stats", "anything")
	// When disabled, goproxy handles the non-proxy request directly and returns 500
	// ("This is a proxy server. Does not respond to non-proxy requests.") rather than 200/401 JSON.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("expected disabled companion API not to respond with 200/401, got %d", resp.StatusCode)
	}
}

func TestCompanionAPILiveFlowsFilteringPaginationDetailAndClear(t *testing.T) {
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Add("X-Multi", "alpha")
			w.Header().Add("X-Multi", "beta")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"users":["alice","bob"]}`))
		case "/api/orders":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"created":true}`))
		case "/api/missing":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		case "/api/boom":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("server error"))
		case "/_cap/companion/stats":
			// Proxied request to an upstream path that happens to start with /_cap/companion/
			// MUST be proxied normally, NOT intercepted by local companion API!
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("upstream-not-local"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer httpBackend.Close()

	httpsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tls":"ok"}`))
	}))
	defer httpsBackend.Close()

	p, flows, _ := startProxy(t, proxy.Options{
		InsecureSkipUpstreamVerify: true,
	})
	token := p.CompanionToken()
	if len(token) != 64 {
		t.Fatalf("expected auto-generated 64-char token, got len=%d", len(token))
	}

	pClient := proxyClient(t, p)
	pClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	// 1. GET /api/users (HTTP 200)
	req1, _ := http.NewRequest(http.MethodGet, httpBackend.URL+"/api/users?page=1", nil)
	req1.Header.Add("X-Req-Multi", "one")
	req1.Header.Add("X-Req-Multi", "two")
	r1, err := pClient.Do(req1)
	if err != nil {
		t.Fatalf("GET /api/users: %v", err)
	}
	_, _ = io.Copy(io.Discard, r1.Body)
	r1.Body.Close()
	f1 := awaitFlow(t, flows)

	// 2. POST /api/orders (HTTP 201)
	req2, _ := http.NewRequest(http.MethodPost, httpBackend.URL+"/api/orders", bytes.NewBufferString(`{"item":"coffee"}`))
	req2.Header.Set("Content-Type", "application/json")
	r2, err := pClient.Do(req2)
	if err != nil {
		t.Fatalf("POST /api/orders: %v", err)
	}
	_, _ = io.Copy(io.Discard, r2.Body)
	r2.Body.Close()
	_ = awaitFlow(t, flows)

	// 3. GET /api/missing (HTTP 404)
	r3, err := pClient.Get(httpBackend.URL + "/api/missing")
	if err != nil {
		t.Fatalf("GET /api/missing: %v", err)
	}
	_, _ = io.Copy(io.Discard, r3.Body)
	r3.Body.Close()
	_ = awaitFlow(t, flows)

	// 4. GET /api/boom (HTTP 500)
	r4, err := pClient.Get(httpBackend.URL + "/api/boom")
	if err != nil {
		t.Fatalf("GET /api/boom: %v", err)
	}
	_, _ = io.Copy(io.Discard, r4.Body)
	r4.Body.Close()
	_ = awaitFlow(t, flows)

	// 5. HTTPS GET /secure/profile (HTTPS 200)
	r5, err := pClient.Get(httpsBackend.URL + "/secure/profile")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, r5.Body)
	r5.Body.Close()
	_ = awaitFlow(t, flows)

	// 6. Proxied request whose path starts with /_cap/companion/ MUST go to upstream!
	r6, err := pClient.Get(httpBackend.URL + "/_cap/companion/stats")
	if err != nil {
		t.Fatalf("proxied /_cap/companion/stats: %v", err)
	}
	b6, _ := io.ReadAll(r6.Body)
	r6.Body.Close()
	if string(b6) != "upstream-not-local" {
		t.Fatalf("proxied /_cap/companion/stats returned %q, want upstream-not-local", b6)
	}
	_ = awaitFlow(t, flows)

	direct := directCompanionClient()

	// Check /stats
	_, statsRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/stats", token)
	var st apiStatsResp
	if err := json.Unmarshal(statsRaw, &st); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}
	if !st.OK || st.TotalFlows != 6 || st.BufferedFlows != 6 || st.LatestSeq != 6 || st.TotalBytes <= 0 || st.ReqPerSec <= 0 {
		t.Fatalf("unexpected stats: %+v", st)
	}

	// Check /flows newest-first ordering
	_, allRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows", token)
	var all apiFlowsResp
	if err := json.Unmarshal(allRaw, &all); err != nil {
		t.Fatalf("unmarshal all flows: %v", err)
	}
	if !all.OK || len(all.Flows) != 6 || all.LatestSeq != 6 {
		t.Fatalf("unexpected all flows: %+v", all)
	}
	for i := 1; i < len(all.Flows); i++ {
		if all.Flows[i-1].Seq <= all.Flows[i].Seq {
			t.Fatalf("flows not ordered newest-first: seq[%d]=%d, seq[%d]=%d", i-1, all.Flows[i-1].Seq, i, all.Flows[i].Seq)
		}
	}

	// Check pagination: after=3 & limit=2 -> returns seq 6, 5
	_, pageRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows?after=3&limit=2", token)
	var page apiFlowsResp
	_ = json.Unmarshal(pageRaw, &page)
	if len(page.Flows) != 2 || page.Flows[0].Seq != 6 || page.Flows[1].Seq != 5 {
		t.Fatalf("after=3&limit=2 returned %+v, want seq 6,5", page.Flows)
	}

	// Check method=POST filter
	_, postRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows?method=post", token)
	var postResp apiFlowsResp
	_ = json.Unmarshal(postRaw, &postResp)
	if len(postResp.Flows) != 1 || postResp.Flows[0].Path != "/api/orders" || postResp.Flows[0].Status != 201 {
		t.Fatalf("method=POST returned %+v", postResp.Flows)
	}

	// Check scheme=https filter
	_, httpsRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows?scheme=https", token)
	var httpsResp apiFlowsResp
	_ = json.Unmarshal(httpsRaw, &httpsResp)
	if len(httpsResp.Flows) != 1 || httpsResp.Flows[0].Scheme != "https" || httpsResp.Flows[0].Path != "/secure/profile" {
		t.Fatalf("scheme=https returned %+v", httpsResp.Flows)
	}

	// Check status_group filters: 2xx, 4xx, 5xx, err
	for _, tc := range []struct {
		group string
		want  int
	}{
		{"2xx", 4},
		{"4xx", 1},
		{"5xx", 1},
		{"err", 2},
	} {
		_, gRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows?status_group="+tc.group, token)
		var gResp apiFlowsResp
		_ = json.Unmarshal(gRaw, &gResp)
		if len(gResp.Flows) != tc.want {
			t.Errorf("status_group=%s returned %d flows, want %d", tc.group, len(gResp.Flows), tc.want)
		}
	}

	// Check search (case-insensitive substring in path/url/content_type)
	_, searchRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows?search=PROFILE", token)
	var searchResp apiFlowsResp
	_ = json.Unmarshal(searchRaw, &searchResp)
	if len(searchResp.Flows) != 1 || searchResp.Flows[0].Path != "/secure/profile" {
		t.Fatalf("search=PROFILE returned %+v", searchResp.Flows)
	}
	_, searchQueryRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows?search="+url.QueryEscape("page=1"), token)
	var searchQueryResp apiFlowsResp
	_ = json.Unmarshal(searchQueryRaw, &searchQueryResp)
	if len(searchQueryResp.Flows) != 1 || searchQueryResp.Flows[0].ID != f1.ID {
		t.Fatalf("search=page=1 returned %+v", searchQueryResp.Flows)
	}

	// Check detail endpoint + header flattening with ", "
	detailHTTPResp, detailRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows/"+f1.ID, token)
	if detailHTTPResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /flows/%s status=%d body=%s", f1.ID, detailHTTPResp.StatusCode, detailRaw)
	}
	var detail apiFlowDetailResp
	if err := json.Unmarshal(detailRaw, &detail); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if !detail.OK || detail.Flow.ID != f1.ID || detail.Flow.Status != 200 {
		t.Fatalf("unexpected flow detail: %+v", detail)
	}
	if detail.Flow.ReqHeaders["X-Req-Multi"] != "one, two" {
		t.Errorf("ReqHeaders[X-Req-Multi] = %q, want %q", detail.Flow.ReqHeaders["X-Req-Multi"], "one, two")
	}
	if detail.Flow.RespHeaders["X-Multi"] != "alpha, beta" {
		t.Errorf("RespHeaders[X-Multi] = %q, want %q", detail.Flow.RespHeaders["X-Multi"], "alpha, beta")
	}
	if detail.Flow.RespBody != `{"users":["alice","bob"]}` || detail.Flow.RespBodyBinary || detail.Flow.RespBodyTruncated {
		t.Errorf("unexpected RespBody detail: body=%q bin=%v trunc=%v", detail.Flow.RespBody, detail.Flow.RespBodyBinary, detail.Flow.RespBodyTruncated)
	}

	// Missing flow ID -> 404 {"error":"flow not found"}
	missResp, missBody := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows/f99999", token)
	if missResp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing flow status=%d, want 404", missResp.StatusCode)
	}
	var missErr apiErrResp
	if err := json.Unmarshal(missBody, &missErr); err != nil || missErr.Error != "flow not found" {
		t.Fatalf("missing flow body=%s, want {\"error\":\"flow not found\"}", missBody)
	}

	// Clear endpoint clears buffer but keeps latest_seq monotonic.
	clearResp, clearRaw := doCompanionRequest(t, direct, http.MethodPost, p.Addr(), "/_cap/companion/clear", token)
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /clear status=%d body=%s", clearResp.StatusCode, clearRaw)
	}
	var cl apiClearResp
	if err := json.Unmarshal(clearRaw, &cl); err != nil || !cl.OK || cl.LatestSeq != 6 {
		t.Fatalf("unexpected clear response: %+v (raw=%s)", cl, clearRaw)
	}

	_, afterClearRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows", token)
	var afterClear apiFlowsResp
	_ = json.Unmarshal(afterClearRaw, &afterClear)
	if afterClear.BufferedFlows != 0 || len(afterClear.Flows) != 0 || afterClear.LatestSeq != 6 {
		t.Fatalf("expected empty buffer & latest_seq=6 after clear, got %+v", afterClear)
	}

	// Next proxied request gets seq=7.
	r7, err := pClient.Get(httpBackend.URL + "/api/users")
	if err != nil {
		t.Fatalf("post-clear GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, r7.Body)
	r7.Body.Close()
	_ = awaitFlow(t, flows)

	_, postClearFlowsRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows", token)
	var postClearFlows apiFlowsResp
	_ = json.Unmarshal(postClearFlowsRaw, &postClearFlows)
	if len(postClearFlows.Flows) != 1 || postClearFlows.Flows[0].Seq != 7 || postClearFlows.LatestSeq != 7 {
		t.Fatalf("expected seq=7 after clear, got %+v", postClearFlows)
	}

	// Upstream dial failure should appear under status_group=err with non-empty error string.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dead port: %v", err)
	}
	deadAddr := deadLn.Addr().String()
	deadLn.Close()
	if rDead, err := pClient.Get("http://" + deadAddr + "/unreachable"); err == nil {
		_, _ = io.Copy(io.Discard, rDead.Body)
		rDead.Body.Close()
	}
	_, errFlowsRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows?status_group=err", token)
	var errFlows apiFlowsResp
	_ = json.Unmarshal(errFlowsRaw, &errFlows)
	if len(errFlows.Flows) == 0 || errFlows.Flows[0].Status != 0 || errFlows.Flows[0].Error == "" {
		t.Fatalf("expected upstream dial failure in status_group=err, got %+v", errFlows.Flows)
	}
}

func TestCompanionAPIBodyTruncationAndBinaryPreview(t *testing.T) {
	// 40 KiB of valid multi-byte UTF-8 Chinese text (3 bytes per rune) to verify
	// 32 KiB truncation preserves valid UTF-8 and does NOT falsely mark as binary.
	largeUTF8 := strings.Repeat("中", 14000) // 42000 bytes > 32 KiB

	// Raw PNG-like binary payload with NUL & invalid UTF-8 bytes
	binaryPayload := append([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0xfe, 0x80}, bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 200)...)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/large-utf8":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(largeUTF8))
		case "/binary":
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(binaryPayload)
		case "/invalid-utf8":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{0xff, 0xfe, 0xfd, 0x00, 0x01, 0x02})
		}
	}))
	defer backend.Close()

	p, flows, _ := startTestProxy(t)
	token := p.CompanionToken()
	pClient := proxyClient(t, p)
	direct := directCompanionClient()

	// 1. Large UTF-8 text
	r1, err := pClient.Get(backend.URL + "/large-utf8")
	if err != nil {
		t.Fatalf("GET /large-utf8: %v", err)
	}
	_, _ = io.Copy(io.Discard, r1.Body)
	r1.Body.Close()
	f1 := awaitFlow(t, flows)

	_, d1Raw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows/"+f1.ID, token)
	var d1 apiFlowDetailResp
	if err := json.Unmarshal(d1Raw, &d1); err != nil {
		t.Fatalf("unmarshal large-utf8 detail: %v", err)
	}
	if !d1.Flow.RespBodyTruncated || d1.Flow.RespBodyBinary {
		t.Errorf("large-utf8 flags: truncated=%v binary=%v, want truncated=true binary=false", d1.Flow.RespBodyTruncated, d1.Flow.RespBodyBinary)
	}
	if !utf8.ValidString(d1.Flow.RespBody) || len(d1.Flow.RespBody) > 32*1024 || len(d1.Flow.RespBody) < 32*1024-3 {
		t.Errorf("large-utf8 preview invalid or unexpected length: len=%d valid=%v", len(d1.Flow.RespBody), utf8.ValidString(d1.Flow.RespBody))
	}
	if d1.Flow.RespBytes != int64(len(largeUTF8)) {
		t.Errorf("large-utf8 RespBytes=%d, want %d", d1.Flow.RespBytes, len(largeUTF8))
	}

	// 2. Binary image/png payload (>512 bytes)
	r2, err := pClient.Get(backend.URL + "/binary")
	if err != nil {
		t.Fatalf("GET /binary: %v", err)
	}
	_, _ = io.Copy(io.Discard, r2.Body)
	r2.Body.Close()
	f2 := awaitFlow(t, flows)

	_, d2Raw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows/"+f2.ID, token)
	var d2 apiFlowDetailResp
	if err := json.Unmarshal(d2Raw, &d2); err != nil {
		t.Fatalf("unmarshal binary detail: %v", err)
	}
	if !d2.Flow.RespBodyBinary || !d2.Flow.RespBodyTruncated {
		t.Errorf("binary flags: binary=%v truncated=%v, want true/true", d2.Flow.RespBodyBinary, d2.Flow.RespBodyTruncated)
	}
	if !utf8.ValidString(d2.Flow.RespBody) || !strings.Contains(d2.Flow.RespBody, "[binary body:") || !strings.Contains(d2.Flow.RespBody, "89 50 4e 47") {
		t.Errorf("unexpected binary preview: %q", d2.Flow.RespBody)
	}

	// 3. Invalid UTF-8 disguised as text/plain (small binary payload)
	r3, err := pClient.Get(backend.URL + "/invalid-utf8")
	if err != nil {
		t.Fatalf("GET /invalid-utf8: %v", err)
	}
	_, _ = io.Copy(io.Discard, r3.Body)
	r3.Body.Close()
	f3 := awaitFlow(t, flows)

	_, d3Raw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows/"+f3.ID, token)
	var d3 apiFlowDetailResp
	if err := json.Unmarshal(d3Raw, &d3); err != nil {
		t.Fatalf("unmarshal invalid-utf8 detail: %v", err)
	}
	if !d3.Flow.RespBodyBinary || d3.Flow.RespBodyTruncated {
		t.Errorf("small invalid-utf8 flags: binary=%v truncated=%v, want true/false", d3.Flow.RespBodyBinary, d3.Flow.RespBodyTruncated)
	}
	if !utf8.ValidString(d3.Flow.RespBody) || !strings.Contains(d3.Flow.RespBody, "ff fe fd") {
		t.Errorf("unexpected invalid-utf8 preview: %q", d3.Flow.RespBody)
	}
}

func TestCompanionAPIRingBufferEvictionAndConcurrentRace(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	defer backend.Close()

	// BufferSize=3 must be clamped to minCompanionBufferSize (10).
	p, err := proxy.New(proxy.Options{
		Addr:                "127.0.0.1:0",
		CertDir:             t.TempDir(),
		CompanionBufferSize: 3,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := p.Start(); err != nil {
			t.Errorf("proxy.Start: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = p.Stop()
		<-done
	})

	token := p.CompanionToken()
	pClient := proxyClient(t, p)
	direct := directCompanionClient()

	// 1. Sequential burst of 18 requests to verify exact ring clamping (10) & eviction.
	for i := 0; i < 18; i++ {
		resp, err := pClient.Get(fmt.Sprintf("%s/item/%d", backend.URL, i))
		if err != nil {
			t.Fatalf("GET /item/%d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	_, listRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows?limit=200", token)
	var listResp apiFlowsResp
	if err := json.Unmarshal(listRaw, &listResp); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if listResp.TotalFlows != 18 || listResp.BufferedFlows != 10 || len(listResp.Flows) != 10 || listResp.LatestSeq != 18 {
		t.Fatalf("expected total=18 buffered=10 latest_seq=18, got %+v", listResp)
	}
	if listResp.Flows[0].Seq != 18 || listResp.Flows[len(listResp.Flows)-1].Seq != 9 {
		t.Fatalf("expected buffered seq 18..9, got %d..%d", listResp.Flows[0].Seq, listResp.Flows[len(listResp.Flows)-1].Seq)
	}
	// Evicted oldest flow f1 must return 404.
	evictedResp, _ := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/flows/f1", token)
	if evictedResp.StatusCode != http.StatusNotFound {
		t.Errorf("evicted flow f1 status=%d, want 404", evictedResp.StatusCode)
	}

	// 2. Concurrent traffic + concurrent readers + clear under -race.
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			cli := proxyClient(t, p)
			for j := 0; j < 6; j++ {
				resp, err := cli.Get(fmt.Sprintf("%s/race/%d/%d", backend.URL, worker, j))
				if err != nil {
					t.Errorf("concurrent GET: %v", err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}(g)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(reader int) {
			defer wg.Done()
			cli := directCompanionClient()
			for k := 0; k < 10; k++ {
				stResp, _ := doCompanionRequest(t, cli, http.MethodGet, p.Addr(), "/_cap/companion/stats", token)
				if stResp.StatusCode != http.StatusOK {
					t.Errorf("concurrent /stats status=%d", stResp.StatusCode)
				}
				flResp, flBody := doCompanionRequest(t, cli, http.MethodGet, p.Addr(), "/_cap/companion/flows?limit=20&search=race", token)
				if flResp.StatusCode != http.StatusOK {
					t.Errorf("concurrent /flows status=%d", flResp.StatusCode)
				}
				var parsed apiFlowsResp
				if err := json.Unmarshal(flBody, &parsed); err == nil && len(parsed.Flows) > 0 {
					dResp, _ := doCompanionRequest(t, cli, http.MethodGet, p.Addr(), "/_cap/companion/flows/"+parsed.Flows[0].ID, token)
					if dResp.StatusCode != http.StatusOK && dResp.StatusCode != http.StatusNotFound {
						t.Errorf("concurrent /flows/{id} unexpected status=%d", dResp.StatusCode)
					}
				}
				if reader == 0 && k == 5 {
					cResp, _ := doCompanionRequest(t, cli, http.MethodPost, p.Addr(), "/_cap/companion/clear", token)
					if cResp.StatusCode != http.StatusOK {
						t.Errorf("concurrent /clear status=%d", cResp.StatusCode)
					}
				}
			}
		}(r)
	}
	wg.Wait()

	_, finalRaw := doCompanionRequest(t, direct, http.MethodGet, p.Addr(), "/_cap/companion/stats", token)
	var finalStats apiStatsResp
	if err := json.Unmarshal(finalRaw, &finalStats); err != nil {
		t.Fatalf("unmarshal final stats: %v", err)
	}
	if finalStats.TotalFlows != 18+36 || finalStats.LatestSeq != 18+36 || finalStats.BufferedFlows > 10 {
		t.Fatalf("unexpected final stats after concurrent race test: %+v", finalStats)
	}
}
