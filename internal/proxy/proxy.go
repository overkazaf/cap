// Package proxy implements cap's MITM (man-in-the-middle) HTTP/HTTPS proxy
// core. It wraps github.com/elazarl/goproxy to intercept both plain HTTP and
// TLS-protected HTTPS traffic, reconstructing each completed request/response
// pair as a types.Flow and handing it to a user-supplied callback.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/types"
)

// Options configures a Proxy.
type Options struct {
	// Addr is the TCP address the proxy listens on, e.g. "127.0.0.1:8080".
	// Pass "127.0.0.1:0" (or a ":0" port) to let the OS pick a free port —
	// read the actual bound address back via Proxy.Addr().
	Addr string

	// OnFlow is invoked once for every completed request/response pair.
	OnFlow func(*types.Flow)

	// OnStreamEvent is invoked while WebSocket or SSE traffic is relayed.
	// Events are emitted as soon as a frame or a complete SSE event parses;
	// callbacks must return promptly because they delay forwarding.
	OnStreamEvent func(StreamEvent)

	// RequestInterceptor is called before forwarding each request. It can
	// modify the request or return a response to short-circuit (mock).
	// Return (req, nil) to forward, (req, resp) to mock.
	RequestInterceptor func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)

	// ResponseInterceptor is called before returning each response to the client.
	// It can modify the response.
	ResponseInterceptor func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response

	// CertDir is the directory holding the MITM CA certificate/key pair
	// used to sign on-the-fly leaf certificates for intercepted HTTPS
	// connections (see EnsureCA). It is created on first use if missing.
	//
	// This is optional: when empty, it defaults to "~/.cap" so that the
	// same CA generated here is the one `cap android connect`-style tooling
	// installs as a trust anchor on devices.
	CertDir string

	// InsecureSkipUpstreamVerify, when true, disables TLS certificate
	// verification on the proxy's own connections to real upstream servers
	// (as opposed to the certificates it presents to clients, which are
	// always signed by the proxy's MITM CA regardless of this setting).
	//
	// This is off by default: the proxy verifies upstream certificates
	// normally, so it can't itself be MITM'd between it and the real
	// server. Reverse-engineering targets often talk to internal/staging
	// backends with self-signed or private-CA certificates, so this exists
	// as an explicit opt-in for that case rather than a silent default.
	InsecureSkipUpstreamVerify bool

	// MaxBodyBytes bounds body data held in memory for each captured Flow.
	// Larger bodies continue forwarding, but only this prefix is captured.
	// It defaults to 1 MiB.
	MaxBodyBytes int64

	// MaxStreamPayloadBytes bounds a captured WebSocket frame or SSE event.
	// Larger payloads forward intact and are reported with Truncated=true.
	// It defaults to 256 KiB.
	MaxStreamPayloadBytes int64
}

// Proxy is a MITM HTTP(S) proxy that captures every completed request/
// response pair as a types.Flow.
type Proxy struct {
	opts     Options
	gp       *goproxy.ProxyHttpServer
	listener net.Listener
	server   *http.Server

	idSeq atomic.Int64

	// pending tracks in-flight requests between the OnRequest and
	// OnResponse hooks, keyed by the *http.Request pointer goproxy carries
	// through both phases of a single round trip. Access is guarded by mu
	// since goproxy serves concurrent requests from multiple goroutines.
	mu      sync.Mutex
	pending map[*http.Request]*pendingFlow
}

// pendingFlow holds the request-side state captured in OnRequest that's
// needed once the matching response arrives in OnResponse.
type pendingFlow struct {
	start   time.Time
	reqBody []byte
}

// New creates a Proxy bound to opts.Addr. The TCP listener is bound
// immediately (so Addr() is valid as soon as New returns, and port-in-use
// errors surface here rather than from Start), and the MITM CA under
// opts.CertDir is generated or loaded. Call Start to begin serving.
func New(opts Options) (*Proxy, error) {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:0"
	}
	normalizeLimits(&opts)

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen on %s: %w", opts.Addr, err)
	}

	certDir := opts.CertDir
	if certDir == "" {
		certDir = defaultCertDir()
	}
	caCert, err := loadOrCreateCA(certDir)
	if err != nil {
		ln.Close()
		return nil, err
	}

	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false
	if opts.InsecureSkipUpstreamVerify {
		if gp.Tr == nil {
			gp.Tr = &http.Transport{}
		}
		gp.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in, documented on Options.
	}

	p := &Proxy{
		opts:     opts,
		gp:       gp,
		listener: ln,
		server:   &http.Server{Handler: gp},
		pending:  make(map[*http.Request]*pendingFlow),
	}

	// Perform MITM on every CONNECT (i.e. every HTTPS request), signing
	// cached modern X.509v3 leaf certs with our own CA rather than goproxy's
	// baked-in default — this ensures Android 12–15 Conscrypt / Chrome / Apple
	// trust compliance (<=366d validity, DNS/IP SANs, EKU ServerAuth, AKI, full chain).
	mitm := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: NewTLSConfigFromCA(caCert),
	}
	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return mitm, host
	})

	gp.OnRequest().DoFunc(p.onRequest)
	gp.OnResponse().DoFunc(p.onResponse)

	return p, nil
}

// Start begins accepting and serving connections. It blocks until Stop is
// called (or the listener fails for another reason), returning nil on a
// clean shutdown.
func (p *Proxy) Start() error {
	err := p.server.Serve(p.listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Stop shuts the proxy down, closing its listener and any active
// connections. It is safe to call even if Start has not returned yet.
func (p *Proxy) Stop() error {
	return p.server.Close()
}

// Addr returns the proxy's bound listen address (e.g. "127.0.0.1:54321"),
// including the actual OS-assigned port when Options.Addr used ":0".
func (p *Proxy) Addr() string {
	return p.listener.Addr().String()
}

// onRequest is the goproxy request hook: it stashes the request start time
// and a copy of the request body (restoring a fresh reader so the real
// request proceeds unaffected), keyed for later retrieval in onResponse.
func (p *Proxy) onRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	meta := &pendingFlow{start: time.Now()}

	if req.Body != nil && req.Body != http.NoBody {
		if body, replay, err := captureBody(req.Body, p.opts.MaxBodyBytes); err == nil {
			meta.reqBody = body
			req.Body = replay
		}
	}

	p.mu.Lock()
	p.pending[req] = meta
	p.mu.Unlock()

	// Apply request interceptor if set
	if p.opts.RequestInterceptor != nil {
		return p.opts.RequestInterceptor(req, ctx)
	}

	return req, nil
}

// onResponse is the goproxy response hook: it pairs the response with the
// pending request state, builds the captured types.Flow, invokes OnFlow, and
// restores the response body so the real client still receives it.
func (p *Proxy) onResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	req := ctx.Req
	if req == nil {
		return resp
	}

	p.mu.Lock()
	meta, ok := p.pending[req]
	if ok {
		delete(p.pending, req)
	}
	p.mu.Unlock()
	if !ok {
		// No matching OnRequest state (shouldn't normally happen); fall
		// back to a zero-latency entry rather than dropping the flow.
		meta = &pendingFlow{start: time.Now()}
	}

	if resp == nil {
		// The round trip to the upstream server failed outright (dial
		// error, timeout, ...) — there's no status/body to report.
		return resp
	}

	flow := &types.Flow{
		ID:           fmt.Sprintf("f%d", p.idSeq.Add(1)),
		Timestamp:    meta.start,
		Method:       req.Method,
		URL:          req.URL.String(),
		Host:         req.URL.Host,
		Path:         req.URL.Path,
		ReqHeaders:   flattenHeaders(req.Header),
		ReqBody:      meta.reqBody,
		ReqBodyType:  req.Header.Get("Content-Type"),
		Status:       resp.StatusCode,
		RespHeaders:  flattenHeaders(resp.Header),
		RespBody:     nil,
		RespBodyType: resp.Header.Get("Content-Type"),
		LatencyMs:    time.Since(meta.start).Milliseconds(),
	}

	// Apply the interceptor before wrapping the relay body so capture sees
	// the response actually handed back to goproxy.
	if p.opts.ResponseInterceptor != nil {
		resp = p.opts.ResponseInterceptor(resp, ctx)
	}

	if isWebSocketUpgrade(resp) {
		resp.Body = p.websocketBody(resp.Body, flow)
		p.emitFlow(flow)
		return resp
	}

	if isServerSentEvent(resp) && resp.Body != nil {
		resp.Body = p.sseBody(resp.Body, flow)
		p.emitFlow(flow)
		return resp
	}

	if resp.Body != nil {
		if body, replay, err := captureBody(resp.Body, p.opts.MaxBodyBytes); err == nil {
			flow.RespBody = body
			resp.Body = replay
		}
	}

	p.emitFlow(flow)

	return resp
}

func (p *Proxy) emitFlow(flow *types.Flow) {
	if p.opts.OnFlow != nil {
		p.opts.OnFlow(flow)
	}
}

// flattenHeaders collapses an http.Header (map[string][]string) down to the
// map[string]string shape types.Flow stores, joining repeated values.
func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vals := range h {
		m[k] = strings.Join(vals, "; ")
	}
	return m
}

func defaultCertDir() string {
	return config.DefaultDir()
}

// loadOrCreateCA ensures a CA exists under dir and loads it as a
// tls.Certificate suitable for goproxy.TLSConfigFromCA.
func loadOrCreateCA(dir string) (tls.Certificate, error) {
	certFile, keyFile, err := EnsureCA(dir)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("proxy: load CA key pair: %w", err)
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("proxy: parse CA certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return cert, nil
}
