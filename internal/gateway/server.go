package gateway

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxGatewayReqBodyBytes  = 4 * 1024 * 1024
	maxUpstreamRespBytes    = 10 * 1024 * 1024
	gatewayShutdownTimeout  = 5 * time.Second
)

// routeRateLimiter implements a lightweight thread-safe token bucket per route.
type routeRateLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newRouteRateLimiter(rps float64) *routeRateLimiter {
	burst := math.Max(1, math.Ceil(rps))
	return &routeRateLimiter{
		rate:   rps,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
	}
}

func (l *routeRateLimiter) allow(rps float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.rate != rps {
		l.rate = rps
		l.burst = math.Max(1, math.Ceil(rps))
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	elapsed := now.Sub(l.last).Seconds()
	if elapsed > 0 {
		l.tokens = math.Min(l.burst, l.tokens+elapsed*l.rate)
		l.last = now
	}
	if l.tokens < 1.0 {
		return false
	}
	l.tokens -= 1.0
	return true
}

func (m *Manager) allowRouteRequest(route *ServiceRoute) bool {
	if route == nil || route.RateLimitRPS <= 0 {
		return true
	}
	m.rlMu.Lock()
	lim, ok := m.limiters[route.ID]
	if !ok {
		lim = newRouteRateLimiter(route.RateLimitRPS)
		m.limiters[route.ID] = lim
	}
	m.rlMu.Unlock()
	return lim.allow(route.RateLimitRPS)
}

// Start launches the embedded Open API Gateway HTTP server on addr (defaulting
// to GatewayConfig.ListenAddr when addr is empty).
func (m *Manager) Start(addr string) error {
	targetAddr := strings.TrimSpace(addr)
	if targetAddr == "" {
		targetAddr = m.GetConfig().ListenAddr
	}
	if targetAddr == "" {
		targetAddr = DefaultListenAddr
	}

	m.srvMu.Lock()
	if m.running {
		cur := m.boundAddr
		m.srvMu.Unlock()
		return fmt.Errorf("gateway server is already running on %s", cur)
	}

	ln, err := net.Listen("tcp", targetAddr)
	if err != nil {
		m.srvMu.Unlock()
		m.emitStatus(GatewayStatus{
			Running:    false,
			ListenAddr: targetAddr,
			Error:      err.Error(),
		})
		return fmt.Errorf("listen %s: %w", targetAddr, err)
	}

	srv := &http.Server{
		Handler:           m.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	actualAddr := ln.Addr().String()
	startedAt := nowRFC3339()

	m.httpSrv = srv
	m.running = true
	m.boundAddr = actualAddr
	m.startedAt = startedAt
	m.srvMu.Unlock()

	m.emitStatus(GatewayStatus{
		Running:    true,
		ListenAddr: actualAddr,
		StartedAt:  startedAt,
	})

	go func() {
		serveErr := srv.Serve(ln)
		m.srvMu.Lock()
		// Only clear state if this server is still the active instance.
		if m.httpSrv == srv {
			m.httpSrv = nil
			m.running = false
		}
		m.srvMu.Unlock()

		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			m.emitStatus(GatewayStatus{
				Running:    false,
				ListenAddr: actualAddr,
				Error:      serveErr.Error(),
			})
		}
	}()

	return nil
}

// Stop gracefully shuts down the embedded Open API Gateway HTTP server.
func (m *Manager) Stop() error {
	m.srvMu.Lock()
	srv := m.httpSrv
	wasRunning := m.running
	addr := m.boundAddr
	m.httpSrv = nil
	m.running = false
	m.srvMu.Unlock()

	if srv == nil || !wasRunning {
		return nil
	}

	srv.SetKeepAlivesEnabled(false)

	timeout := gatewayShutdownTimeout
	noActive := m.inFlight.Load() == 0
	if noActive {
		timeout = 250 * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := srv.Shutdown(ctx)
	if err != nil && errors.Is(err, context.DeadlineExceeded) {
		closeErr := srv.Close()
		// If no HTTP requests were actively being served (e.g. only an idle/StateNew
		// client socket remained open), closing forcefully is a clean shutdown.
		if m.inFlight.Load() == 0 {
			err = closeErr
		}
	}

	st := GatewayStatus{
		Running:    false,
		ListenAddr: addr,
	}
	if err != nil {
		st.Error = err.Error()
	}
	m.emitStatus(st)
	return err
}

// IsRunning reports whether the embedded Open API Gateway HTTP server is active.
func (m *Manager) IsRunning() bool {
	m.srvMu.Lock()
	defer m.srvMu.Unlock()
	return m.running
}

// ListenAddr returns the bound address when running, or the configured listen
// address when stopped.
func (m *Manager) ListenAddr() string {
	m.srvMu.Lock()
	running := m.running
	bound := m.boundAddr
	m.srvMu.Unlock()
	if running && bound != "" {
		return bound
	}
	return m.GetConfig().ListenAddr
}

// Handler builds the HTTP handler serving `/health`, `/metrics`,
// `/openapi.json`, and `/gw/{slug}` with CORS support.
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", m.handleHealth)
	mux.HandleFunc("/metrics", m.handleMetrics)
	mux.HandleFunc("/openapi.json", m.handleOpenAPI)
	mux.HandleFunc("/gw/", m.handleGatewayRoute)
	return m.withCORS(mux)
}

func (m *Manager) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.inFlight.Add(1)
		defer m.inFlight.Add(-1)

		cfg := m.GetConfig()
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		allowOrigin := resolveAllowedCORSOrigin(origin, cfg.CORSOrigins)
		if allowOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			if allowOrigin != "*" {
				w.Header().Add("Vary", "Origin")
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Cap-Device-ID, X-Cap-Proxy-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func resolveAllowedCORSOrigin(reqOrigin string, allowed []string) string {
	if len(allowed) == 0 {
		return "*"
	}
	for _, a := range allowed {
		if a == "*" {
			return "*"
		}
		if reqOrigin != "" && strings.EqualFold(a, reqOrigin) {
			return reqOrigin
		}
	}
	return ""
}

func (m *Manager) authenticateRequest(r *http.Request) bool {
	cfg := m.GetConfig()
	if !cfg.RequireAuth {
		return true
	}
	if len(cfg.APIKeys) == 0 {
		return false
	}

	token := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if token == "" {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if rest, ok := cutPrefixFold(auth, "Bearer "); ok {
			token = strings.TrimSpace(rest)
		}
	}
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("api_key"))
	}
	if token == "" {
		return false
	}

	for _, key := range cfg.APIKeys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(key)) == 1 {
			return true
		}
	}
	return false
}

func (m *Manager) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	st := m.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"status":          "healthy",
		"running":         st.Running,
		"listen_addr":     st.ListenAddr,
		"routes_enabled":  st.RouteEnabled,
		"proxies_healthy": st.ProxyHealthy,
		"devices_enabled": st.DeviceEnabled,
		"timestamp":       nowRFC3339(),
	})
}

func (m *Manager) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !m.authenticateRequest(r) {
		m.authFailures.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "unauthorized: invalid or missing API key")
		return
	}
	writeJSON(w, http.StatusOK, m.Stats())
}

func (m *Manager) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	spec := m.OpenAPISpec()
	writeJSON(w, http.StatusOK, spec)
}

func (m *Manager) handleGatewayRoute(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/gw/")
	slug = strings.Trim(slug, "/")
	if idx := strings.IndexByte(slug, '/'); idx >= 0 {
		slug = slug[:idx]
	}
	if slug == "" {
		writeJSONError(w, http.StatusNotFound, "missing route slug")
		return
	}

	// 1. Auth
	if !m.authenticateRequest(r) {
		m.authFailures.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "unauthorized: invalid or missing API key")
		return
	}

	// 2. Route lookup
	route, ok := m.GetRouteBySlug(slug)
	if !ok {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("service route %q not found", slug))
		return
	}
	if !route.Enabled {
		writeJSONError(w, http.StatusServiceUnavailable, fmt.Sprintf("service route %q is disabled", slug))
		return
	}

	// 3. Per-route rate limiting
	if !m.allowRouteRequest(route) {
		m.rateLimited.Add(1)
		w.Header().Set("Retry-After", "1")
		writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	// 4. Parse incoming gateway request into TestInvokeRequest
	rawQuery := r.URL.Query()
	rawMode := rawQuery.Get("raw") == "1" || strings.EqualFold(rawQuery.Get("raw"), "true")

	var bodyStr string
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxGatewayReqBodyBytes))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("read request body: %v", err))
			return
		}
		bodyStr = string(b)
	}

	inputMap := make(map[string]string)
	extraQuery := make(map[string]string)

	// Extract top-level scalar JSON fields into inputMap for convenient POST /gw/{slug} calls.
	if trimmed := strings.TrimSpace(bodyStr); strings.HasPrefix(trimmed, "{") {
		var bodyObj map[string]any
		if json.Unmarshal([]byte(trimmed), &bodyObj) == nil {
			for k, v := range bodyObj {
				switch v.(type) {
				case string, float64, bool:
					inputMap[k] = stringifyScalar(v)
				}
			}
		}
	}

	// Query params override JSON body input keys and also pass through as extraQuery unless consumed by templates.
	templateInputs := make(map[string]struct{})
	for _, k := range routeTemplateInputKeys(route) {
		templateInputs[k] = struct{}{}
	}
	for k, vals := range rawQuery {
		if k == "raw" || k == "api_key" || k == "_device_id" || k == "_proxy_id" {
			continue
		}
		val := ""
		if len(vals) > 0 {
			val = vals[0]
		}
		inputMap[k] = val
		if _, consumed := templateInputs[k]; !consumed {
			extraQuery[k] = val
		}
	}

	// Forward non-gateway custom request headers (skipping automatic client headers
	// like User-Agent so device fingerprint / route headers are not clobbered, and
	// never leaking the gateway's Bearer API key upstream).
	cfg := m.GetConfig()
	fwdHeaders := make(map[string]string)
	for k, vals := range r.Header {
		if len(vals) == 0 || isGatewayInternalHeader(k) || isHopByHopOrAutoHeader(k) || isClientAutoHeader(k) {
			continue
		}
		if cfg.RequireAuth && strings.EqualFold(k, "Authorization") {
			if _, isBearer := cutPrefixFold(strings.TrimSpace(vals[0]), "Bearer "); isBearer {
				continue
			}
		}
		fwdHeaders[k] = vals[0]
	}

	devicePin := strings.TrimSpace(r.Header.Get("X-Cap-Device-ID"))
	if devicePin == "" {
		devicePin = strings.TrimSpace(rawQuery.Get("_device_id"))
	}
	proxyPin := strings.TrimSpace(r.Header.Get("X-Cap-Proxy-ID"))
	if proxyPin == "" {
		proxyPin = strings.TrimSpace(rawQuery.Get("_proxy_id"))
	}

	invokeReq := TestInvokeRequest{
		RouteSlug: route.Slug,
		Input:     inputMap,
		Query:     extraQuery,
		Headers:   fwdHeaders,
		Body:      bodyStr,
		DeviceID:  devicePin,
		ProxyID:   proxyPin,
		Raw:       rawMode,
	}

	res, httpStatus := m.executeRoutePipeline(r.Context(), route, invokeReq, clientIPFromRequest(r))

	if rawMode && res.Error == "" {
		for k, v := range res.Headers {
			if isHopByHopOrAutoHeader(k) {
				continue
			}
			w.Header().Set(k, v)
		}
		status := res.Status
		if status <= 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(res.Body))
		return
	}

	writeJSON(w, httpStatus, res)
}

// InvokeRoute executes a published ServiceRoute directly in-process (for GUI
// testing and CLI invocation without requiring an external HTTP client).
func (m *Manager) InvokeRoute(ctx context.Context, slug string, req TestInvokeRequest) (*TestInvokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(slug) == "" {
		slug = req.RouteSlug
	}
	route, ok := m.GetRouteBySlug(slug)
	if !ok {
		return nil, fmt.Errorf("service route %q not found", slug)
	}
	res, _ := m.executeRoutePipeline(ctx, route, req, "local")
	if res.Error != "" {
		return res, errors.New(res.Error)
	}
	return res, nil
}

// executeRoutePipeline implements the full gateway execution chain:
// Acquire Device -> Acquire Proxy IP (honoring device sticky proxy) -> Render
// URL/Headers/Body -> Call Signer & inject signature -> Forward to Upstream
// (with failover retries across healthy proxies) -> Record InvocationRecord &
// emit live callback.
func (m *Manager) executeRoutePipeline(ctx context.Context, route *ServiceRoute, req TestInvokeRequest, clientIP string) (*TestInvokeResult, int) {
	start := time.Now()
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = route.UpstreamMethod
	}
	if method == "" {
		method = http.MethodGet
	}

	rec := InvocationRecord{
		RouteID:   route.ID,
		RouteSlug: route.Slug,
		Method:    method,
		SignerID:  route.SignerID,
		ClientIP:  clientIP,
	}

	var secrets []string
	trackSecret := func(s string) {
		if s != "" {
			secrets = append(secrets, s)
		}
	}

	finishErr := func(httpCode int, errMsg string) (*TestInvokeResult, int) {
		safeErr := redactSecrets(errMsg, secrets...)
		elapsed := time.Since(start).Milliseconds()
		rec.LatencyMs = elapsed
		rec.StatusCode = httpCode
		rec.OK = false
		rec.Error = safeErr
		m.recordInvocation(rec)
		return &TestInvokeResult{
			OK:          false,
			Status:      httpCode,
			LatencyMs:   elapsed,
			SignerMs:    rec.SignerMs,
			UpstreamURL: rec.UpstreamURL,
			Proxy:       rec.ProxyName,
			ProxyID:     rec.ProxyID,
			Device:      rec.DeviceName,
			DeviceID:    rec.DeviceID,
			Retries:     rec.Retries,
			Error:       safeErr,
		}, httpCode
	}

	// Step 1: Acquire Device (if required, tagged, explicitly pinned, or referenced in templates)
	var device *DeviceProfile
	needDevice := route.RequireDevice ||
		strings.TrimSpace(req.DeviceID) != "" ||
		len(route.DeviceTags) > 0 ||
		routeUsesDeviceTemplates(route)

	if needDevice {
		dev, err := m.devices.Acquire(route.DeviceTags, req.DeviceID)
		if err != nil {
			if route.RequireDevice || strings.TrimSpace(req.DeviceID) != "" {
				return finishErr(http.StatusServiceUnavailable, fmt.Sprintf("acquire device: %v", err))
			}
		} else {
			device = dev
			rec.DeviceID = dev.ID
			rec.DeviceName = dev.Name
		}
	}

	// Step 2: Acquire initial Proxy IP (honoring explicit pin or device sticky proxy / region)
	stickyProxyID, stickyRegion := m.devices.StickyProxyFor(device)
	if strings.TrimSpace(req.ProxyID) != "" {
		stickyProxyID = strings.TrimSpace(req.ProxyID)
	}
	wantProxy := route.RequireProxy ||
		stickyProxyID != "" ||
		stickyRegion != "" ||
		len(route.ProxyTags) > 0

	// If proxies exist in pool and none were explicitly constrained, use pool automatically.
	if !wantProxy {
		if total, _ := m.proxies.Counts(); total > 0 {
			wantProxy = true
		}
	}

	var initialProxy *ProxyNode
	if wantProxy {
		proxyOpts := ProxySelectOptions{
			Tags:          route.ProxyTags,
			Region:        stickyRegion,
			StickyProxyID: stickyProxyID,
		}
		pn, err := m.proxies.Select(proxyOpts)
		if err != nil {
			if route.RequireProxy || strings.TrimSpace(req.ProxyID) != "" {
				return finishErr(http.StatusBadGateway, fmt.Sprintf("acquire proxy: %v", err))
			}
			// Pool has no eligible proxies and proxy is optional -> fall back to direct.
			wantProxy = false
		} else {
			initialProxy = pn
			trackSecret(pn.Password)
			rec.ProxyID = pn.ID
			rec.ProxyName = pn.Name
		}
	}

	// Step 3: Render URL / Headers / Body with TemplateContext
	now := time.Now()
	tplCtx := TemplateContext{
		Input:       req.Input,
		Device:      device,
		Timestamp:   now.Unix(),
		TimestampMs: now.UnixMilli(),
		Nonce:       randomHex(8),
	}

	parsedURL, err := RenderURLTemplate(route.UpstreamURL, tplCtx)
	if err != nil {
		return finishErr(http.StatusBadRequest, fmt.Sprintf("invalid rendered upstream URL: %v", err))
	}
	if parsedURL.User != nil {
		if pw, ok := parsedURL.User.Password(); ok {
			trackSecret(pw)
		}
	}

	q := parsedURL.Query()
	for k, v := range route.StaticQuery {
		q.Set(k, RenderTemplate(v, tplCtx))
	}
	for k, v := range req.Query {
		q.Set(k, v)
	}
	parsedURL.RawQuery = q.Encode()

	headers := make(map[string]string)
	// Base headers from acquired device fingerprint & session.
	if device != nil {
		if device.Fingerprint.UserAgent != "" {
			setHeaderFold(headers, "User-Agent", device.Fingerprint.UserAgent)
		}
		if device.Fingerprint.Locale != "" {
			setHeaderFold(headers, "Accept-Language", strings.ReplaceAll(device.Fingerprint.Locale, "_", "-"))
		}
		for k, v := range device.Fingerprint.ExtraHeaders {
			setHeaderFold(headers, k, v)
		}
		for k, v := range device.AuthHeaders {
			setHeaderFold(headers, k, v)
		}
		if len(device.Cookies) > 0 {
			setHeaderFold(headers, "Cookie", formatCookieHeader(device.Cookies))
		}
	}
	// Overlay route static headers (rendered).
	for k, v := range route.StaticHeaders {
		if isHopByHopOrAutoHeader(k) {
			continue
		}
		setHeaderFold(headers, k, RenderTemplate(v, tplCtx))
	}
	// Overlay caller request headers.
	for k, v := range req.Headers {
		if isHopByHopOrAutoHeader(k) || isGatewayInternalHeader(k) {
			continue
		}
		setHeaderFold(headers, k, v)
	}

	var renderedBody string
	if strings.TrimSpace(route.BodyTemplate) != "" {
		trimmedTpl := strings.TrimSpace(route.BodyTemplate)
		ct := strings.ToLower(lookupMapFold(headers, "Content-Type"))
		if strings.HasPrefix(trimmedTpl, "{") || strings.HasPrefix(trimmedTpl, "[") || strings.Contains(ct, "json") {
			renderedBody = RenderJSONTemplate(route.BodyTemplate, tplCtx)
		} else {
			renderedBody = RenderTemplate(route.BodyTemplate, tplCtx)
		}
	} else {
		renderedBody = req.Body
	}

	// Step 4: Call Signer & inject signature
	var signedParams map[string]string
	var signedHeaders map[string]string
	if strings.TrimSpace(route.SignerID) != "" {
		signer, ok := m.GetSigner(route.SignerID)
		if !ok {
			return finishErr(http.StatusBadGateway, fmt.Sprintf("signer %q not found", route.SignerID))
		}
		if !signer.Enabled {
			return finishErr(http.StatusBadGateway, fmt.Sprintf("signer %q is disabled", signer.Name))
		}
		trackSecret(signer.HMACSecret)

		flatQuery := make(map[string]string)
		for k, vals := range parsedURL.Query() {
			if len(vals) > 0 {
				flatQuery[k] = vals[0]
			}
		}
		signerIn := SignerInput{
			Method:    method,
			URL:       parsedURL.String(),
			Path:      parsedURL.Path,
			Query:     flatQuery,
			Headers:   cloneStringMap(headers),
			Body:      renderedBody,
			Timestamp: tplCtx.Timestamp,
			Nonce:     tplCtx.Nonce,
			Device:    device,
			Input:     cloneStringMap(req.Input),
		}

		sigOut, sigErr := ExecuteSigner(ctx, signer, signerIn)
		if sigErr != nil {
			return finishErr(http.StatusBadGateway, fmt.Sprintf("signer %q failed: %v", signer.Name, sigErr))
		}
		rec.SignerMs = sigOut.LatencyMs

		beforeQuery := parsedURL.Query()
		beforeHeaders := cloneStringMap(headers)
		parsedURL, headers, renderedBody, err = ApplySignature(signer, sigOut, parsedURL, headers, renderedBody)
		if err != nil {
			return finishErr(http.StatusBadGateway, fmt.Sprintf("apply signature: %v", err))
		}
		signedParams = diffQueryParams(beforeQuery, parsedURL.Query())
		signedHeaders = diffStringMaps(beforeHeaders, headers)
	}

	finalURL := parsedURL.String()
	redactedFinalURL := parsedURL.Redacted()
	rec.UpstreamURL = redactedFinalURL

	// Step 5: Forward to Upstream (with failover retries across healthy proxies)
	timeoutSec := route.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = DefaultTimeoutSec
	}
	timeout := time.Duration(timeoutSec) * time.Second

	maxRetries := 0
	if wantProxy && strings.TrimSpace(req.ProxyID) == "" {
		maxRetries = m.proxies.Config().FailoverRetries
		if maxRetries < 0 {
			maxRetries = 0
		}
	}

	triedProxies := make(map[string]bool)
	currentProxy := initialProxy

	var (
		upstreamResp *http.Response
		upstreamBody []byte
		lastErr      error
		retriesUsed  int
	)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Select next healthy proxy excluding previously failed ones.
			nextProxy, selErr := m.proxies.Select(ProxySelectOptions{
				Tags:       route.ProxyTags,
				Region:     stickyRegion,
				ExcludeIDs: triedProxies,
			})
			if selErr != nil {
				// Retry without region restriction if region-specific proxies exhausted.
				if stickyRegion != "" {
					nextProxy, selErr = m.proxies.Select(ProxySelectOptions{
						Tags:       route.ProxyTags,
						ExcludeIDs: triedProxies,
					})
				}
			}
			if selErr != nil {
				break
			}
			currentProxy = nextProxy
			retriesUsed++
		}

		var transport http.RoundTripper = m.directTransport
		if wantProxy && currentProxy != nil {
			trackSecret(currentProxy.Password)
			rec.ProxyID = currentProxy.ID
			rec.ProxyName = currentProxy.Name
			tr, trErr := m.proxies.TransportFor(currentProxy)
			if trErr != nil {
				lastErr = trErr
				triedProxies[currentProxy.ID] = true
				m.proxies.RecordResult(currentProxy.ID, false, 0, trErr)
				continue
			}
			transport = tr
		}

		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		var bodyReader io.Reader
		if renderedBody != "" {
			bodyReader = bytes.NewBufferString(renderedBody)
		}
		upReq, reqErr := http.NewRequestWithContext(attemptCtx, method, finalURL, bodyReader)
		if reqErr != nil {
			cancel()
			return finishErr(http.StatusBadRequest, fmt.Sprintf("build upstream request: %v", reqErr))
		}
		for k, v := range headers {
			upReq.Header.Set(k, v)
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}

		hopStart := time.Now()
		resp, doErr := client.Do(upReq)
		hopMs := time.Since(hopStart).Milliseconds()
		if hopMs <= 0 {
			hopMs = 1
		}

		if doErr != nil {
			cancel()
			lastErr = doErr
			if wantProxy && currentProxy != nil {
				triedProxies[currentProxy.ID] = true
				m.proxies.RecordResult(currentProxy.ID, false, hopMs, doErr)
				continue
			}
			break
		}

		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamRespBytes))
		resp.Body.Close()
		cancel()

		if readErr != nil {
			lastErr = readErr
			if wantProxy && currentProxy != nil {
				triedProxies[currentProxy.ID] = true
				m.proxies.RecordResult(currentProxy.ID, false, hopMs, readErr)
				continue
			}
			break
		}

		if wantProxy && currentProxy != nil {
			m.proxies.RecordResult(currentProxy.ID, true, hopMs, nil)
		}
		upstreamResp = resp
		upstreamBody = bodyBytes
		lastErr = nil
		break
	}

	rec.Retries = retriesUsed

	if lastErr != nil || upstreamResp == nil {
		errMsg := "upstream request failed"
		if lastErr != nil {
			errMsg = fmt.Sprintf("upstream request failed: %v", lastErr)
		}
		return finishErr(http.StatusBadGateway, errMsg)
	}

	// Step 6: Build response envelope & record telemetry
	respHeaders := make(map[string]string, len(upstreamResp.Header))
	for k, vals := range upstreamResp.Header {
		if len(vals) > 0 {
			respHeaders[k] = strings.Join(vals, ", ")
		}
	}

	var parsedData any
	if trimmed := bytes.TrimSpace(upstreamBody); len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var tmp any
		if json.Unmarshal(trimmed, &tmp) == nil {
			parsedData = tmp
		}
	}

	elapsed := time.Since(start).Milliseconds()
	ok := upstreamResp.StatusCode >= 200 && upstreamResp.StatusCode < 500
	rec.StatusCode = upstreamResp.StatusCode
	rec.LatencyMs = elapsed
	rec.OK = ok
	m.recordInvocation(rec)

	res := &TestInvokeResult{
		OK:            ok,
		Status:        upstreamResp.StatusCode,
		LatencyMs:     elapsed,
		SignerMs:      rec.SignerMs,
		UpstreamURL:   redactedFinalURL,
		Proxy:         rec.ProxyName,
		ProxyID:       rec.ProxyID,
		Device:        rec.DeviceName,
		DeviceID:      rec.DeviceID,
		Headers:       respHeaders,
		Body:          string(upstreamBody),
		Data:          parsedData,
		Retries:       retriesUsed,
		SignedParams:  signedParams,
		SignedHeaders: signedHeaders,
	}
	return res, http.StatusOK
}

// OpenAPISpec generates a valid OpenAPI 3.0.3 specification map describing all
// currently enabled ServiceRoutes.
func (m *Manager) OpenAPISpec() map[string]any {
	cfg := m.GetConfig()
	addr := m.ListenAddr()
	if addr == "" {
		addr = DefaultListenAddr
	}
	serverURL := normalizeOpenAPIServerURL(addr)

	paths := make(map[string]any)
	for _, r := range m.ListRoutes() {
		if !r.Enabled {
			continue
		}
		pathKey := "/gw/" + r.Slug
		opMethod := strings.ToLower(r.UpstreamMethod)
		switch opMethod {
		case "get", "post", "put", "patch", "delete", "head", "options":
		default:
			opMethod = "get"
		}

		inputKeys := routeTemplateInputKeys(&r)
		params := make([]map[string]any, 0, len(inputKeys)+1)
		for _, k := range inputKeys {
			if strings.EqualFold(k, "raw") {
				continue
			}
			params = append(params, map[string]any{
				"name":        k,
				"in":          "query",
				"required":    false,
				"description": fmt.Sprintf("Template input variable {{input.%s}}", k),
				"schema":      map[string]any{"type": "string"},
			})
		}
		params = append(params, map[string]any{
			"name":        "raw",
			"in":          "query",
			"required":    false,
			"description": "Set to 1 to return the raw upstream response instead of the JSON envelope",
			"schema":      map[string]any{"type": "string", "enum": []string{"0", "1"}},
		})

		op := map[string]any{
			"operationId": sanitizeID("gw-"+r.Slug, "invoke"),
			"summary":     r.Name,
			"description": r.Description,
			"tags":        []string{"gateway"},
			"parameters":  params,
			"responses": map[string]any{
				"200": map[string]any{
					"description": "Successful gateway invocation envelope",
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{
								"$ref": "#/components/schemas/GatewayEnvelope",
							},
						},
					},
				},
				"401": map[string]any{"description": "Unauthorized (invalid or missing API key)"},
				"429": map[string]any{"description": "Rate limit exceeded"},
				"502": map[string]any{"description": "Upstream, proxy, or signer error"},
			},
		}

		if opMethod == "post" || opMethod == "put" || opMethod == "patch" || (opMethod == "delete" && strings.TrimSpace(r.BodyTemplate) != "") {
			props := make(map[string]any, len(inputKeys))
			for _, k := range inputKeys {
				props[k] = map[string]any{"type": "string"}
			}
			op["requestBody"] = map[string]any{
				"required": false,
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{
							"type":       "object",
							"properties": props,
						},
					},
				},
			}
		}

		paths[pathKey] = map[string]any{
			opMethod: op,
		}
	}

	spec := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "cap Open API Gateway",
			"version":     "1.0.0",
			"description": "Published reverse-engineered mobile API endpoints served by cap's full-chain integration gateway (Device Pool + Proxy IP Pool + Pluggable Signers).",
		},
		"servers": []map[string]any{
			{"url": serverURL},
		},
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"ApiKeyAuth": map[string]any{
					"type": "apiKey",
					"in":   "header",
					"name": "X-API-Key",
				},
				"BearerAuth": map[string]any{
					"type":   "http",
					"scheme": "bearer",
				},
			},
			"schemas": map[string]any{
				"GatewayEnvelope": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"ok":         map[string]any{"type": "boolean"},
						"status":     map[string]any{"type": "integer"},
						"latency_ms": map[string]any{"type": "integer"},
						"proxy":      map[string]any{"type": "string"},
						"device":     map[string]any{"type": "string"},
						"headers":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
						"body":       map[string]any{"type": "string"},
						"data":       map[string]any{},
						"error":      map[string]any{"type": "string"},
					},
				},
			},
		},
	}

	if cfg.RequireAuth {
		spec["security"] = []map[string]any{
			{"ApiKeyAuth": []string{}},
			{"BearerAuth": []string{}},
		}
	}

	return spec
}

// OpenAPISpecJSON marshals OpenAPISpec() as pretty-printed JSON.
func (m *Manager) OpenAPISpecJSON() ([]byte, error) {
	return json.MarshalIndent(m.OpenAPISpec(), "", "  ")
}

// ---- Helpers ----

func routeTemplateInputKeys(route *ServiceRoute) []string {
	if route == nil {
		return nil
	}
	sources := make([]string, 0, 2+len(route.StaticHeaders)+len(route.StaticQuery))
	sources = append(sources, route.UpstreamURL, route.BodyTemplate)
	for _, v := range route.StaticHeaders {
		sources = append(sources, v)
	}
	for _, v := range route.StaticQuery {
		sources = append(sources, v)
	}
	return ExtractTemplateInputKeys(sources...)
}

func routeUsesDeviceTemplates(route *ServiceRoute) bool {
	if route == nil {
		return false
	}
	sources := make([]string, 0, 2+len(route.StaticHeaders)+len(route.StaticQuery))
	sources = append(sources, route.UpstreamURL, route.BodyTemplate)
	for _, v := range route.StaticHeaders {
		sources = append(sources, v)
	}
	for _, v := range route.StaticQuery {
		sources = append(sources, v)
	}
	return TemplateUsesDevice(sources...)
}

func isGatewayInternalHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "x-api-key", "x-cap-device-id", "x-cap-proxy-id":
		return true
	default:
		return false
	}
}

func isClientAutoHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "user-agent", "accept", "origin", "referer":
		return true
	default:
		return false
	}
}

func normalizeOpenAPIServerURL(addr string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		s = DefaultListenAddr
	}
	scheme := "http"
	if strings.HasPrefix(s, "https://") {
		scheme = "https"
		s = strings.TrimPrefix(s, "https://")
	} else if strings.HasPrefix(s, "http://") {
		s = strings.TrimPrefix(s, "http://")
	}
	host, port, err := net.SplitHostPort(s)
	if err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		s = net.JoinHostPort(host, port)
	}
	return scheme + "://" + s
}

func formatCookieHeader(cookies map[string]string) string {
	keys := make([]string, 0, len(cookies))
	for k := range cookies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, cookies[k]))
	}
	return strings.Join(parts, "; ")
}

func diffQueryParams(before, after url.Values) map[string]string {
	var diff map[string]string
	for k, vals := range after {
		afterVal := ""
		if len(vals) > 0 {
			afterVal = vals[0]
		}
		if before.Get(k) != afterVal || !before.Has(k) {
			if diff == nil {
				diff = make(map[string]string)
			}
			diff[k] = afterVal
		}
	}
	return diff
}

func diffStringMaps(before, after map[string]string) map[string]string {
	var diff map[string]string
	for k, v := range after {
		bv := lookupMapFold(before, k)
		if bv != v || !hasKeyFold(before, k) {
			if diff == nil {
				diff = make(map[string]string)
			}
			diff[k] = v
		}
	}
	return diff
}

func hasKeyFold(m map[string]string, key string) bool {
	for k := range m {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

func clientIPFromRequest(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"ok":     false,
		"status": status,
		"error":  msg,
	})
}
