package proxy_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/types"
)

// startProxy starts a Proxy built from opts, filling in a loopback
// OS-assigned port and a hermetic CertDir (so tests never touch the real
// user's ~/.cap) when left unset. It returns the running proxy along with a
// channel fed by OnFlow, and registers t.Cleanup to stop it.
func startProxy(t *testing.T, opts proxy.Options) (*proxy.Proxy, <-chan *types.Flow) {
	t.Helper()

	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:0"
	}
	if opts.CertDir == "" {
		opts.CertDir = t.TempDir()
	}

	flows := make(chan *types.Flow, 16)
	userOnFlow := opts.OnFlow
	opts.OnFlow = func(f *types.Flow) {
		flows <- f
		if userOnFlow != nil {
			userOnFlow(f)
		}
	}

	p, err := proxy.New(opts)
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
		p.Stop()
		<-done
	})

	return p, flows
}

// startTestProxy is startProxy with default options — the common case of
// plain HTTP capture tests that don't need any special proxy configuration.
func startTestProxy(t *testing.T) (*proxy.Proxy, <-chan *types.Flow) {
	t.Helper()
	return startProxy(t, proxy.Options{})
}

// proxyClient returns an *http.Client configured to route all requests
// through p.
func proxyClient(t *testing.T, p *proxy.Proxy) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + p.Addr())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
}

// awaitFlow waits for a single captured flow, failing the test if none
// arrives within a reasonable timeout.
func awaitFlow(t *testing.T, flows <-chan *types.Flow) *types.Flow {
	t.Helper()
	select {
	case f := <-flows:
		return f
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for captured flow")
		return nil
	}
}

func TestProxyCapturesGetRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	p, flows := startTestProxy(t)
	client := proxyClient(t, p)

	resp, err := client.Get(backend.URL + "/api/test")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("client saw body = %q, want %q", body, `{"ok":true}`)
	}

	f := awaitFlow(t, flows)

	if f.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", f.Method)
	}
	wantURL := backend.URL + "/api/test"
	if f.URL != wantURL {
		t.Errorf("URL = %q, want %q", f.URL, wantURL)
	}
	if f.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", f.Status)
	}
	if string(f.RespBody) != `{"ok":true}` {
		t.Errorf("RespBody = %q, want %q", f.RespBody, `{"ok":true}`)
	}
	if f.LatencyMs < 0 {
		t.Errorf("LatencyMs = %d, want >= 0", f.LatencyMs)
	}
	if f.ID == "" {
		t.Error("ID should not be empty")
	}
	if f.RespHeaders["Content-Type"] != "application/json" {
		t.Errorf("RespHeaders[Content-Type] = %q, want application/json", f.RespHeaders["Content-Type"])
	}
}

func TestProxyCapturesRequestHeadersAndBody(t *testing.T) {
	var gotBody []byte
	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Test-Header")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer backend.Close()

	p, flows := startTestProxy(t)
	client := proxyClient(t, p)

	const reqBody = `{"username":"neo"}`
	req, err := http.NewRequest(http.MethodPost, backend.URL+"/v1/login", bytes.NewBufferString(reqBody))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Header", "matrix")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Sanity: the backend must still receive an intact request — proving the
	// proxy's body-buffering-for-capture doesn't break the actual proxied
	// request.
	if gotHeader != "matrix" {
		t.Fatalf("backend saw X-Test-Header = %q, want %q", gotHeader, "matrix")
	}
	if string(gotBody) != reqBody {
		t.Fatalf("backend saw body = %q, want %q", gotBody, reqBody)
	}

	f := awaitFlow(t, flows)

	if f.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", f.Method)
	}
	if f.Host == "" {
		t.Error("Host should not be empty")
	}
	if f.Path != "/v1/login" {
		t.Errorf("Path = %q, want /v1/login", f.Path)
	}
	if string(f.ReqBody) != reqBody {
		t.Errorf("ReqBody = %q, want %q", f.ReqBody, reqBody)
	}
	if f.ReqHeaders["X-Test-Header"] != "matrix" {
		t.Errorf("ReqHeaders[X-Test-Header] = %q, want matrix; got %v", f.ReqHeaders["X-Test-Header"], f.ReqHeaders)
	}
	if f.ReqBodyType != "application/json" {
		t.Errorf("ReqBodyType = %q, want application/json", f.ReqBodyType)
	}
	if f.Status != http.StatusCreated {
		t.Errorf("Status = %d, want 201", f.Status)
	}
}

func TestProxyCapturesHTTPSRequest(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure-ok"))
	}))
	defer backend.Close()

	// backend uses httptest's self-signed cert; tell the proxy not to reject
	// it when connecting upstream (see the Options.InsecureSkipUpstreamVerify
	// doc).
	p, flows := startProxy(t, proxy.Options{InsecureSkipUpstreamVerify: true})

	client := proxyClient(t, p)
	// The MITM leaf certificate is signed by cap's own CA, which this test
	// client doesn't have in its trust store — skip verification so we're
	// testing that MITM decryption and flow capture work, not chain trust.
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	resp, err := client.Get(backend.URL + "/secure")
	if err != nil {
		t.Fatalf("GET through proxy (https): %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "secure-ok" {
		t.Fatalf("client saw body = %q, want %q", body, "secure-ok")
	}

	f := awaitFlow(t, flows)

	if f.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", f.Method)
	}
	if !strings.HasPrefix(f.URL, "https://") {
		t.Errorf("URL = %q, want https:// scheme (MITM should decrypt and report the real scheme)", f.URL)
	}
	if f.Path != "/secure" {
		t.Errorf("Path = %q, want /secure", f.Path)
	}
	if f.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", f.Status)
	}
	if string(f.RespBody) != "secure-ok" {
		t.Errorf("RespBody = %q, want %q", f.RespBody, "secure-ok")
	}
}

func TestProxyAssignsSequentialFlowIDs(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p, flows := startTestProxy(t)
	client := proxyClient(t, p)

	for i := 0; i < 2; i++ {
		resp, err := client.Get(backend.URL + "/ping")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	f1 := awaitFlow(t, flows)
	f2 := awaitFlow(t, flows)

	if f1.ID != "f1" {
		t.Errorf("first flow ID = %q, want f1", f1.ID)
	}
	if f2.ID != "f2" {
		t.Errorf("second flow ID = %q, want f2", f2.ID)
	}
}

func TestProxyStopStopsServing(t *testing.T) {
	p, err := proxy.New(proxy.Options{
		Addr:    "127.0.0.1:0",
		CertDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- p.Start() }()

	addr := p.Addr()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial before stop: %v", err)
	}
	conn.Close()

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start() returned error after Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}

	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("expected dial to fail after Stop, but it succeeded")
	}
}

func TestStripNoiseHeaders(t *testing.T) {
	in := map[string]string{
		"Accept-Encoding":     "gzip",
		"Connection":          "keep-alive",
		"Proxy-Connection":    "keep-alive",
		"Proxy-Authorization": "Basic xxx",
		"TE":                  "trailers",
		"Trailer":             "X-Foo",
		"Transfer-Encoding":   "chunked",
		"Upgrade":             "websocket",
		"Keep-Alive":          "timeout=5",
		"X-Forwarded-For":     "1.2.3.4",
		"X-Forwarded-Proto":   "https",
		"Content-Type":        "application/json",
		"Authorization":       "Bearer tok123",
		"X-Custom-Header":     "value",
	}

	got := proxy.StripNoiseHeaders(in)

	noise := []string{
		"Accept-Encoding", "Connection", "Proxy-Connection", "Proxy-Authorization",
		"TE", "Trailer", "Transfer-Encoding", "Upgrade", "Keep-Alive",
		"X-Forwarded-For", "X-Forwarded-Proto",
	}
	for _, h := range noise {
		if _, ok := got[h]; ok {
			t.Errorf("noise header %q was not stripped", h)
		}
	}

	keep := map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer tok123",
		"X-Custom-Header": "value",
	}
	for k, want := range keep {
		if got[k] != want {
			t.Errorf("header %q = %q, want %q (should be preserved)", k, got[k], want)
		}
	}

	if len(got) != len(keep) {
		t.Errorf("got %d headers, want %d: %v", len(got), len(keep), got)
	}
}

func TestStripNoiseHeadersCaseInsensitive(t *testing.T) {
	in := map[string]string{
		"accept-encoding": "gzip",
		"CONNECTION":      "close",
		"x-Forwarded-For": "1.2.3.4",
		"content-type":    "text/plain",
	}

	got := proxy.StripNoiseHeaders(in)

	if len(got) != 1 {
		t.Fatalf("got %d headers, want 1: %v", len(got), got)
	}
	if got["content-type"] != "text/plain" {
		t.Errorf("content-type = %q, want text/plain", got["content-type"])
	}
}

func TestStripNoiseHeadersEmptyAndNilInput(t *testing.T) {
	if got := proxy.StripNoiseHeaders(map[string]string{}); len(got) != 0 {
		t.Errorf("got %d headers for empty input, want 0", len(got))
	}
	if got := proxy.StripNoiseHeaders(nil); len(got) != 0 {
		t.Errorf("got %d headers for nil input, want 0", len(got))
	}
}

func TestEnsureCACreatesFiles(t *testing.T) {
	dir := t.TempDir()

	certFile, keyFile, err := proxy.EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("cert file is not a valid PEM certificate block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if cert.Subject.CommonName != "Cap MITM CA" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Cap MITM CA")
	}
	if !cert.IsCA {
		t.Error("certificate should be a CA")
	}
	wantNotAfter := time.Now().AddDate(10, 0, 0)
	if cert.NotAfter.Before(wantNotAfter.Add(-24 * time.Hour)) {
		t.Errorf("NotAfter = %v, want ~10 years from now (%v)", cert.NotAfter, wantNotAfter)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatalf("key file is not valid PEM")
	}
	if _, err := x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("parse EC private key: %v", err)
	}
}

func TestEnsureCAIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	certFile1, keyFile1, err := proxy.EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA (first call): %v", err)
	}
	certBytes1, err := os.ReadFile(certFile1)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyBytes1, err := os.ReadFile(keyFile1)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	certFile2, keyFile2, err := proxy.EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA (second call): %v", err)
	}
	if certFile1 != certFile2 || keyFile1 != keyFile2 {
		t.Fatalf("paths changed between calls: (%s,%s) vs (%s,%s)", certFile1, keyFile1, certFile2, keyFile2)
	}

	certBytes2, err := os.ReadFile(certFile2)
	if err != nil {
		t.Fatalf("read cert (second): %v", err)
	}
	keyBytes2, err := os.ReadFile(keyFile2)
	if err != nil {
		t.Fatalf("read key (second): %v", err)
	}

	if !bytes.Equal(certBytes1, certBytes2) {
		t.Error("cert file content changed on second EnsureCA call; expected idempotent reuse")
	}
	if !bytes.Equal(keyBytes1, keyBytes2) {
		t.Error("key file content changed on second EnsureCA call; expected idempotent reuse")
	}
}
