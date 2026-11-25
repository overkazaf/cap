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
// `/metrics/prometheus`, `/openapi.json`, and `/gw/{slug}` with CORS support.
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", m.handleHealth)
	mux.HandleFunc("/metrics", m.handleMetrics)
	mux.HandleFunc("/metrics/prometheus", m.handlePrometheusMetrics)
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Cap-Device-ID, X-Cap-Proxy-ID, X-Cap-Account-ID, Cache-Control")

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
		"accounts_active": st.ActiveAccounts,
		"workers_healthy": st.HealthyWorkers,
		"open_circuits":   st.OpenCircuits,
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

func (m *Manager) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !m.authenticateRequest(r) {
		m.authFailures.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "unauthorized: invalid or missing API key")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(m.PrometheusMetrics()))
	}
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
		if k == "raw" || k == "api_key" || k == "_device_id" || k == "_proxy_id" || k == "_account_id" {
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
	accountPin := strings.TrimSpace(r.Header.Get("X-Cap-Account-ID"))
	if accountPin == "" {
		accountPin = strings.TrimSpace(rawQuery.Get("_account_id"))
	}

	ccHeader := strings.ToLower(r.Header.Get("Cache-Control"))
	bypassCache := strings.Contains(ccHeader, "no-cache") || strings.Contains(ccHeader, "no-store")

	invokeReq := TestInvokeRequest{
		RouteSlug:   route.Slug,
		Input:       inputMap,
		Query:       extraQuery,
		Headers:     fwdHeaders,
		Body:        bodyStr,
		DeviceID:    devicePin,
		ProxyID:     proxyPin,
		AccountID:   accountPin,
		BypassCache: bypassCache,
		Raw:         rawMode,
	}

	res, httpStatus := m.executeRoutePipeline(r.Context(), route, invokeReq, clientIPFromRequest(r))

	if cacheHdr := lookupMapFold(res.Headers, "X-Cap-Cache"); cacheHdr != "" {
		w.Header().Set("X-Cap-Cache", cacheHdr)
	}
	if res.CircuitTripped {
		w.Header().Set("X-Cap-Circuit", "open")
	}

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

type refreshCtxKey struct{}

type refreshCtxState struct {
	depth              int
	visited            map[string]bool
	refreshingAccounts map[string]bool
}

func getRefreshCtxState(ctx context.Context) *refreshCtxState {
	if ctx == nil {
		return nil
	}
	st, _ := ctx.Value(refreshCtxKey{}).(*refreshCtxState)
	return st
}

func isRefreshCall(ctx context.Context) bool {
	st := getRefreshCtxState(ctx)
	return st != nil && st.depth > 0
}

func isRefreshingAccountInCtx(ctx context.Context, accountID string) bool {
	st := getRefreshCtxState(ctx)
	if st == nil || strings.TrimSpace(accountID) == "" {
		return false
	}
	return st.refreshingAccounts[strings.TrimSpace(accountID)]
}

func canTriggerRefresh(ctx context.Context, currentSlug, targetRefreshSlug, accountID string, maxAttempts int) bool {
	target := normalizeSlug(targetRefreshSlug)
	cur := normalizeSlug(currentSlug)
	if target == "" || strings.EqualFold(cur, target) {
		return false
	}
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxRefreshAttempts
	}
	st := getRefreshCtxState(ctx)
	if st == nil {
		return true
	}
	if accountID != "" && st.refreshingAccounts[strings.TrimSpace(accountID)] {
		return false
	}
	if st.depth >= maxAttempts {
		return false
	}
	if st.visited[strings.ToLower(target)] {
		return false
	}
	return true
}

func withRefreshContext(ctx context.Context, currentSlug, targetRefreshSlug, accountID string) context.Context {
	prev := getRefreshCtxState(ctx)
	visited := make(map[string]bool)
	refreshing := make(map[string]bool)
	depth := 1
	if prev != nil {
		depth = prev.depth + 1
		for k, v := range prev.visited {
			visited[k] = v
		}
		for k, v := range prev.refreshingAccounts {
			refreshing[k] = v
		}
	}
	if c := normalizeSlug(currentSlug); c != "" {
		visited[strings.ToLower(c)] = true
	}
	if t := normalizeSlug(targetRefreshSlug); t != "" {
		visited[strings.ToLower(t)] = true
	}
	if aid := strings.TrimSpace(accountID); aid != "" {
		refreshing[aid] = true
	}
	return context.WithValue(ctx, refreshCtxKey{}, &refreshCtxState{
		depth:              depth,
		visited:            visited,
		refreshingAccounts: refreshing,
	})
}

type upstreamAttemptOutcome struct {
	resp             *http.Response
	body             []byte
	redactedFinalURL string
	signedParams     map[string]string
	signedHeaders    map[string]string
	retriesUsed      int
	errCode          int
	errMsg           string
	upstreamFailure  bool
}

// executeRoutePipeline implements the full gateway execution chain:
// Route TTL Cache -> Per-Route Circuit Breaker -> Acquire Device -> Acquire
// Account -> Acquire Proxy IP (honoring sticky bindings) -> Render URL/Headers/
// Body (precedence: static -> device -> account -> request -> signer) -> Call
// SignerExecutor (supporting Managed Worker Pools) -> Forward to Upstream over
// TLS/mTLS profile transport (with proxy failover) -> Singleflight Auto-Refresh
// + Retry ONCE on 401/403/body match -> Async Challenge Webhook -> Circuit
// state update -> Cache store -> Record InvocationRecord & emit live callback.
func (m *Manager) executeRoutePipeline(ctx context.Context, route *ServiceRoute, req TestInvokeRequest, clientIP string) (*TestInvokeResult, int) {
	start := time.Now()
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = route.UpstreamMethod
	}
	if method == "" {
		method = http.MethodGet
	}

	tlsProfile, err := NormalizeTLSProfile(route.TLSProfile)
	if err != nil {
		tlsProfile = TLSProfileGoDefault
	}

	rec := InvocationRecord{
		RouteID:    route.ID,
		RouteSlug:  route.Slug,
		Method:     method,
		SignerID:   route.SignerID,
		TLSProfile: tlsProfile,
		ClientIP:   clientIP,
	}

	var secrets []string
	trackSecret := func(s string) {
		if s != "" {
			secrets = append(secrets, s)
		}
	}

	finishErr := func(httpCode int, errMsg string, extraHeaders map[string]string) (*TestInvokeResult, int) {
		safeErr := redactSecrets(errMsg, secrets...)
		elapsed := time.Since(start).Milliseconds()
		rec.LatencyMs = elapsed
		rec.StatusCode = httpCode
		rec.OK = false
		rec.Error = safeErr
		m.recordInvocation(rec)
		return &TestInvokeResult{
			OK:               false,
			Status:           httpCode,
			LatencyMs:        elapsed,
			SignerMs:         rec.SignerMs,
			UpstreamURL:      rec.UpstreamURL,
			Proxy:            rec.ProxyName,
			ProxyID:          rec.ProxyID,
			Device:           rec.DeviceName,
			DeviceID:         rec.DeviceID,
			Account:          rec.AccountName,
			AccountID:        rec.AccountID,
			CacheHit:         rec.CacheHit,
			CircuitTripped:   rec.CircuitTripped,
			RefreshTriggered: rec.RefreshTriggered,
			TLSProfile:       rec.TLSProfile,
			Headers:          extraHeaders,
			Retries:          rec.Retries,
			Error:            safeErr,
		}, httpCode
	}

	// Step 0a: Route TTL Response Cache lookup (when CacheTTLSec > 0 and not inside a refresh call)
	cacheEnabled := route.CacheTTLSec > 0 && !isRefreshCall(ctx)
	var cacheKey string
	bypassCache := req.BypassCache ||
		cacheControlHasDirective(req.Headers, "no-cache") ||
		cacheControlHasDirective(req.Headers, "no-store")
	noStore := cacheControlHasDirective(req.Headers, "no-store")

	if cacheEnabled {
		cacheKey = BuildCacheKey(route, method, req)
		if !bypassCache {
			if cached, hit := m.cache.Get(route.Slug, cacheKey); hit {
				m.cacheHits.Add(1)
				elapsed := time.Since(start).Milliseconds()
				rec.CacheHit = true
				rec.StatusCode = cached.status
				rec.UpstreamURL = cached.upstreamURL
				rec.LatencyMs = elapsed
				rec.OK = true
				m.recordInvocation(rec)

				hdrs := cloneStringMap(cached.headers)
				if hdrs == nil {
					hdrs = make(map[string]string)
				}
				setHeaderFold(hdrs, "X-Cap-Cache", "HIT")
				return &TestInvokeResult{
					OK:          true,
					Status:      cached.status,
					LatencyMs:   elapsed,
					UpstreamURL: cached.upstreamURL,
					CacheHit:    true,
					TLSProfile:  rec.TLSProfile,
					Headers:     hdrs,
					Body:        cached.body,
					Data:        cached.data,
				}, http.StatusOK
			}
		}
		m.cacheMisses.Add(1)
	}

	// Step 0b: Per-Route Circuit Breaker check
	circuitAdmittedHalfOpen := false
	circuitResolved := false
	if route.CircuitFailThreshold > 0 {
		allowed, state := m.circuits.Allow(route.Slug, route.CircuitFailThreshold, route.CircuitCooldownSec)
		if !allowed {
			rec.CircuitTripped = true
			return finishErr(
				http.StatusServiceUnavailable,
				fmt.Sprintf("circuit breaker open for route %q", route.Slug),
				map[string]string{"X-Cap-Circuit": "open"},
			)
		}
		if state == CircuitStateHalfOpen {
			circuitAdmittedHalfOpen = true
			defer func() {
				if circuitAdmittedHalfOpen && !circuitResolved {
					m.circuits.ReleaseHalfOpen(route.Slug)
				}
			}()
		}
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
				return finishErr(http.StatusServiceUnavailable, fmt.Sprintf("acquire device: %v", err), nil)
			}
		} else {
			device = dev
			rec.DeviceID = dev.ID
			rec.DeviceName = dev.Name
		}
	}

	// Step 2: Acquire Account (if required, tagged, explicitly pinned, or referenced in templates)
	poolRefreshCfg := m.accounts.Config().Refresh
	refreshSlug := route.RefreshRouteSlug
	if refreshSlug == "" {
		refreshSlug = poolRefreshCfg.RefreshRouteSlug
	}
	webhookURL := route.ChallengeWebhookURL
	if webhookURL == "" {
		webhookURL = poolRefreshCfg.ChallengeWebhookURL
	}

	var account *AccountProfile
	needAccount := route.RequireAccount ||
		strings.TrimSpace(req.AccountID) != "" ||
		len(route.AccountTags) > 0 ||
		routeUsesAccountTemplates(route)

	if needAccount {
		deviceID := ""
		if device != nil {
			deviceID = device.ID
		}
		acc, err := m.accounts.Acquire(AccountSelectOptions{
			Tags:           route.AccountTags,
			ExplicitID:     req.AccountID,
			DeviceID:       deviceID,
			IncludeExpired: (route.AutoRefresh && refreshSlug != "") || isRefreshCall(ctx),
		})
		if err != nil {
			if route.RequireAccount || strings.TrimSpace(req.AccountID) != "" {
				return finishErr(http.StatusServiceUnavailable, fmt.Sprintf("acquire account: %v", err), nil)
			}
		} else {
			account = acc
			rec.AccountID = acc.ID
			rec.AccountName = acc.Name
			for _, sec := range accountSecrets(acc) {
				trackSecret(sec)
			}
			// If account specifies a sticky device and none was acquired yet, try to bind it.
			if device == nil && strings.TrimSpace(acc.StickyDeviceID) != "" {
				if dev, devErr := m.devices.Acquire(nil, acc.StickyDeviceID); devErr == nil {
					device = dev
					rec.DeviceID = dev.ID
					rec.DeviceName = dev.Name
				}
			}
		}
	}

	// Step 3: Acquire initial Proxy IP (honoring explicit pin, device sticky proxy, or account sticky proxy)
	stickyProxyID, stickyRegion := m.devices.StickyProxyFor(device)
	if stickyProxyID == "" && account != nil && strings.TrimSpace(account.StickyProxyID) != "" {
		stickyProxyID = strings.TrimSpace(account.StickyProxyID)
	}
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
				return finishErr(http.StatusBadGateway, fmt.Sprintf("acquire proxy: %v", err), nil)
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

	// Step 4 & 5 encapsulated so singleflight auto-refresh can cleanly re-render,
	// re-sign, and replay the upstream request ONCE with refreshed credentials.
	attemptUpstream := func(activeAcc *AccountProfile) upstreamAttemptOutcome {
		now := time.Now()
		tplCtx := TemplateContext{
			Input:       req.Input,
			Device:      device,
			Account:     activeAcc,
			Timestamp:   now.Unix(),
			TimestampMs: now.UnixMilli(),
			Nonce:       randomHex(8),
		}

		parsedURL, err := RenderURLTemplate(route.UpstreamURL, tplCtx)
		if err != nil {
			return upstreamAttemptOutcome{
				errCode: http.StatusBadRequest,
				errMsg:  fmt.Sprintf("invalid rendered upstream URL: %v", err),
			}
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

		// Header precedence (case-insensitive):
		// 1. static route headers -> 2. device headers -> 3. account headers -> 4. dynamic request headers -> 5. signer headers
		headers := make(map[string]string)

		// 1. Static route headers (rendered)
		for k, v := range route.StaticHeaders {
			if isHopByHopOrAutoHeader(k) {
				continue
			}
			setHeaderFold(headers, k, RenderTemplate(v, tplCtx))
		}

		// 2. Device headers
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

		// 3. Account headers (AuthHeaders, Cookie, and Bearer Token when not custom-templated)
		if activeAcc != nil {
			for k, v := range activeAcc.AuthHeaders {
				if isHopByHopOrAutoHeader(k) {
					continue
				}
				setHeaderFold(headers, k, v)
			}
			if cookieVal := activeAcc.EffectiveCookie(); cookieVal != "" && !staticHeaderUsesAccountTemplate(route, "Cookie") {
				setHeaderFold(headers, "Cookie", cookieVal)
			}
			if tok := activeAcc.EffectiveToken(); tok != "" &&
				!hasKeyFold(activeAcc.AuthHeaders, "Authorization") &&
				!staticHeaderUsesAccountTemplate(route, "Authorization") {
				authVal := tok
				if !strings.Contains(tok, " ") {
					authVal = "Bearer " + tok
				}
				setHeaderFold(headers, "Authorization", authVal)
			}
		}

		// 4. Caller dynamic request headers
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

		// 5. Call SignerExecutor & inject signature
		var signedParams map[string]string
		var signedHeaders map[string]string
		if strings.TrimSpace(route.SignerID) != "" {
			signer, ok := m.GetSigner(route.SignerID)
			if !ok {
				return upstreamAttemptOutcome{
					errCode: http.StatusBadGateway,
					errMsg:  fmt.Sprintf("signer %q not found", route.SignerID),
				}
			}
			if !signer.Enabled {
				return upstreamAttemptOutcome{
					errCode: http.StatusBadGateway,
					errMsg:  fmt.Sprintf("signer %q is disabled", signer.Name),
				}
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
				Account:   activeAcc,
				Input:     cloneStringMap(req.Input),
			}

			sigOut, sigErr := m.signerExec.Execute(ctx, signer, signerIn)
			if sigErr != nil {
				return upstreamAttemptOutcome{
					errCode: http.StatusBadGateway,
					errMsg:  fmt.Sprintf("signer %q failed: %v", signer.Name, sigErr),
				}
			}
			rec.SignerMs = sigOut.LatencyMs

			beforeQuery := parsedURL.Query()
			beforeHeaders := cloneStringMap(headers)
			parsedURL, headers, renderedBody, err = ApplySignature(signer, sigOut, parsedURL, headers, renderedBody)
			if err != nil {
				return upstreamAttemptOutcome{
					errCode: http.StatusBadGateway,
					errMsg:  fmt.Sprintf("apply signature: %v", err),
				}
			}
			signedParams = diffQueryParams(beforeQuery, parsedURL.Query())
			signedHeaders = diffStringMaps(beforeHeaders, headers)
		}

		finalURL := parsedURL.String()
		redactedFinalURL := redactSecrets(parsedURL.Redacted(), secrets...)
		rec.UpstreamURL = redactedFinalURL

		// Forward to Upstream (with failover retries across healthy proxies & TLS/mTLS profile)
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
				nextProxy, selErr := m.proxies.Select(ProxySelectOptions{
					Tags:       route.ProxyTags,
					Region:     stickyRegion,
					ExcludeIDs: triedProxies,
				})
				if selErr != nil && stickyRegion != "" {
					nextProxy, selErr = m.proxies.Select(ProxySelectOptions{
						Tags:       route.ProxyTags,
						ExcludeIDs: triedProxies,
					})
				}
				if selErr != nil {
					break
				}
				currentProxy = nextProxy
				retriesUsed++
			}

			var activeProxy *ProxyNode
			if wantProxy && currentProxy != nil {
				activeProxy = currentProxy
				trackSecret(currentProxy.Password)
				rec.ProxyID = currentProxy.ID
				rec.ProxyName = currentProxy.Name
			}

			transport, trErr := m.transportForRoute(activeProxy, route)
			if trErr != nil {
				lastErr = trErr
				if activeProxy != nil {
					triedProxies[activeProxy.ID] = true
					m.proxies.RecordResult(activeProxy.ID, false, 0, trErr)
					continue
				}
				break
			}

			attemptCtx, cancel := context.WithTimeout(ctx, timeout)
			var bodyReader io.Reader
			if renderedBody != "" {
				bodyReader = bytes.NewBufferString(renderedBody)
			}
			upReq, reqErr := http.NewRequestWithContext(attemptCtx, method, finalURL, bodyReader)
			if reqErr != nil {
				cancel()
				return upstreamAttemptOutcome{
					errCode: http.StatusBadRequest,
					errMsg:  fmt.Sprintf("build upstream request: %v", reqErr),
				}
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
				if activeProxy != nil {
					triedProxies[activeProxy.ID] = true
					m.proxies.RecordResult(activeProxy.ID, false, hopMs, doErr)
					continue
				}
				break
			}

			bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamRespBytes))
			resp.Body.Close()
			cancel()

			if readErr != nil {
				lastErr = readErr
				if activeProxy != nil {
					triedProxies[activeProxy.ID] = true
					m.proxies.RecordResult(activeProxy.ID, false, hopMs, readErr)
					continue
				}
				break
			}

			if activeProxy != nil {
				m.proxies.RecordResult(activeProxy.ID, true, hopMs, nil)
			}
			upstreamResp = resp
			upstreamBody = bodyBytes
			lastErr = nil
			break
		}

		if lastErr != nil || upstreamResp == nil {
			errMsg := "upstream request failed"
			if lastErr != nil {
				errMsg = fmt.Sprintf("upstream request failed: %v", lastErr)
			}
			return upstreamAttemptOutcome{
				redactedFinalURL: redactedFinalURL,
				retriesUsed:      retriesUsed,
				errCode:          http.StatusBadGateway,
				errMsg:           errMsg,
				upstreamFailure:  true,
			}
		}

		return upstreamAttemptOutcome{
			resp:             upstreamResp,
			body:             upstreamBody,
			redactedFinalURL: redactedFinalURL,
			signedParams:     signedParams,
			signedHeaders:    signedHeaders,
			retriesUsed:      retriesUsed,
		}
	}

	outcome := attemptUpstream(account)
	rec.Retries = outcome.retriesUsed

	if outcome.errMsg != "" || outcome.resp == nil {
		if outcome.upstreamFailure && route.CircuitFailThreshold > 0 {
			circuitResolved = true
			m.circuits.RecordFailure(route.Slug, route.CircuitFailThreshold, route.CircuitCooldownSec, redactSecrets(outcome.errMsg, secrets...))
		}
		code := outcome.errCode
		if code <= 0 {
			code = http.StatusBadGateway
		}
		return finishErr(code, outcome.errMsg, nil)
	}

	// Step 5b: Singleflight Auto-Refresh on 401/403 (or body match) and Retry ONCE
	maxRefreshAttempts := poolRefreshCfg.MaxRefreshAttempts
	if maxRefreshAttempts <= 0 {
		maxRefreshAttempts = DefaultMaxRefreshAttempts
	}
	matchedRefresh := shouldTriggerRefresh(route, poolRefreshCfg, outcome.resp.StatusCode, outcome.body)
	var refreshErr error
	if route.AutoRefresh && account != nil && matchedRefresh && canTriggerRefresh(ctx, route.Slug, refreshSlug, account.ID, maxRefreshAttempts) {
		seenRefreshCount := account.RefreshCount
		seenToken := account.EffectiveToken()
		seenCookie := account.EffectiveCookie()
		devID := ""
		if device != nil {
			devID = device.ID
		}

		refreshedAcc, rErr := m.accounts.RefreshSingleflight(
			ctx,
			account.ID,
			seenRefreshCount,
			seenToken,
			seenCookie,
			func(rCtx context.Context) (AccountCredentialUpdate, error) {
				guardedCtx := withRefreshContext(rCtx, route.Slug, refreshSlug, account.ID)
				refreshReq := TestInvokeRequest{
					RouteSlug: refreshSlug,
					AccountID: account.ID,
					DeviceID:  devID,
					Input: map[string]string{
						"account_id":    account.ID,
						"username":      account.Username,
						"refresh_token": account.RefreshToken,
					},
				}
				rRes, invErr := m.InvokeRoute(guardedCtx, refreshSlug, refreshReq)
				if invErr != nil {
					return AccountCredentialUpdate{}, fmt.Errorf("refresh route %q failed: %w", refreshSlug, invErr)
				}
				return extractCredentialsFromRefreshResult(rRes, time.Now())
			},
		)
		if rErr != nil {
			refreshErr = rErr
		} else if refreshedAcc != nil {
			rec.RefreshTriggered = true
			account = refreshedAcc
			for _, sec := range accountSecrets(refreshedAcc) {
				trackSecret(sec)
			}
			retryOutcome := attemptUpstream(refreshedAcc)
			rec.Retries += retryOutcome.retriesUsed
			if retryOutcome.errMsg != "" || retryOutcome.resp == nil {
				if retryOutcome.upstreamFailure && route.CircuitFailThreshold > 0 {
					circuitResolved = true
					m.circuits.RecordFailure(route.Slug, route.CircuitFailThreshold, route.CircuitCooldownSec, redactSecrets(retryOutcome.errMsg, secrets...))
				}
				code := retryOutcome.errCode
				if code <= 0 {
					code = http.StatusBadGateway
				}
				return finishErr(code, retryOutcome.errMsg, nil)
			}
			outcome = retryOutcome
		}
	}

	// Step 5c: Non-refreshable challenge / risk-control webhook alerting (never bypasses CAPTCHAs)
	if challengeReason, challenged := classifyChallengeOutcome(outcome.resp.StatusCode, outcome.body, refreshErr, rec.RefreshTriggered); challenged {
		if account != nil && (challengeReason != "" && (outcome.resp.StatusCode == http.StatusForbidden || outcome.resp.StatusCode == http.StatusTooManyRequests || outcome.resp.StatusCode == http.StatusUnavailableForLegalReasons || strings.Contains(challengeReason, "challenge"))) {
			_ = m.accounts.MarkChallenged(account.ID, challengeReason)
		}
		if webhookURL != "" {
			m.dispatchChallengeWebhookAsync(webhookURL, challengeWebhookPayload{
				Event:       "gateway.challenge_detected",
				Timestamp:   nowRFC3339(),
				RouteID:     route.ID,
				RouteSlug:   route.Slug,
				AccountID:   rec.AccountID,
				AccountName: rec.AccountName,
				DeviceID:    rec.DeviceID,
				ProxyID:     rec.ProxyID,
				StatusCode:  outcome.resp.StatusCode,
				UpstreamURL: outcome.redactedFinalURL,
				Reason:      challengeReason,
				BodyPreview: string(outcome.body),
			}, secrets)
		}
	}

	// Step 5d: Update Circuit Breaker from upstream response status
	if route.CircuitFailThreshold > 0 {
		circuitResolved = true
		if outcome.resp.StatusCode >= 500 {
			m.circuits.RecordFailure(route.Slug, route.CircuitFailThreshold, route.CircuitCooldownSec, fmt.Sprintf("upstream HTTP %d", outcome.resp.StatusCode))
		} else {
			m.circuits.RecordSuccess(route.Slug)
		}
	}

	// Step 6: Build response envelope, update cache & record telemetry
	respHeaders := make(map[string]string, len(outcome.resp.Header)+1)
	for k, vals := range outcome.resp.Header {
		if len(vals) > 0 {
			respHeaders[k] = strings.Join(vals, ", ")
		}
	}

	var parsedData any
	if trimmed := bytes.TrimSpace(outcome.body); len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var tmp any
		if json.Unmarshal(trimmed, &tmp) == nil {
			parsedData = tmp
		}
	}

	if cacheEnabled {
		if outcome.resp.StatusCode >= 200 && outcome.resp.StatusCode < 300 && !noStore {
			m.cache.Set(route.Slug, cacheKey, cachedRouteEntry{
				status:      outcome.resp.StatusCode,
				headers:     respHeaders,
				body:        string(outcome.body),
				data:        parsedData,
				upstreamURL: outcome.redactedFinalURL,
			}, time.Duration(route.CacheTTLSec)*time.Second, route.CacheMaxEntries)
		}
		setHeaderFold(respHeaders, "X-Cap-Cache", "MISS")
	}

	elapsed := time.Since(start).Milliseconds()
	ok := outcome.resp.StatusCode >= 200 && outcome.resp.StatusCode < 500
	rec.StatusCode = outcome.resp.StatusCode
	rec.LatencyMs = elapsed
	rec.OK = ok
	m.recordInvocation(rec)

	res := &TestInvokeResult{
		OK:               ok,
		Status:           outcome.resp.StatusCode,
		LatencyMs:        elapsed,
		SignerMs:         rec.SignerMs,
		UpstreamURL:      outcome.redactedFinalURL,
		Proxy:            rec.ProxyName,
		ProxyID:          rec.ProxyID,
		Device:           rec.DeviceName,
		DeviceID:         rec.DeviceID,
		Account:          rec.AccountName,
		AccountID:        rec.AccountID,
		CacheHit:         false,
		CircuitTripped:   false,
		RefreshTriggered: rec.RefreshTriggered,
		TLSProfile:       rec.TLSProfile,
		Headers:          respHeaders,
		Body:             string(outcome.body),
		Data:             parsedData,
		Retries:          rec.Retries,
		SignedParams:     outcome.signedParams,
		SignedHeaders:    outcome.signedHeaders,
	}
	return res, http.StatusOK
}

func (m *Manager) transportForRoute(proxy *ProxyNode, route *ServiceRoute) (*http.Transport, error) {
	needCustomTLS := strings.TrimSpace(route.TLSProfile) != "" &&
		!strings.EqualFold(strings.TrimSpace(route.TLSProfile), TLSProfileGoDefault)
	needMTLS := strings.TrimSpace(route.MTLSCertPath) != "" || strings.TrimSpace(route.MTLSKeyPath) != ""
	hasCustomRoot := m.transports != nil && m.transports.HasCustomRootCAs()

	if !needCustomTLS && !needMTLS && !hasCustomRoot {
		if proxy != nil {
			return m.proxies.TransportFor(proxy)
		}
		return m.directTransport, nil
	}
	return m.transports.TransportFor(proxy, route.TLSProfile, route.MTLSCertPath, route.MTLSKeyPath)
}

func shouldTriggerRefresh(route *ServiceRoute, poolCfg AccountRefreshConfig, statusCode int, body []byte) bool {
	statuses := route.RefreshOnStatuses
	if len(statuses) == 0 {
		statuses = poolCfg.RefreshOnStatuses
	}
	if len(statuses) == 0 {
		statuses = []int{http.StatusUnauthorized}
	}
	for _, s := range statuses {
		if statusCode == s {
			return true
		}
	}
	substr := strings.TrimSpace(route.RefreshOnBodySubstr)
	if substr == "" {
		substr = strings.TrimSpace(poolCfg.RefreshOnBodySubstr)
	}
	if substr != "" && bytes.Contains(body, []byte(substr)) {
		return true
	}
	return false
}

func classifyChallengeOutcome(statusCode int, body []byte, refreshErr error, refreshTriggered bool) (string, bool) {
	if reason, ok := detectChallengeBody(body); ok {
		return reason, true
	}
	if statusCode == http.StatusUnavailableForLegalReasons {
		return fmt.Sprintf("upstream returned HTTP %d (restricted/challenge)", statusCode), true
	}
	if statusCode == http.StatusForbidden && (refreshTriggered || refreshErr != nil) {
		return "upstream returned HTTP 403 after refresh attempt", true
	}
	if refreshErr != nil && (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) {
		return fmt.Sprintf("session refresh failed on HTTP %d: %v", statusCode, refreshErr), true
	}
	return "", false
}

func staticHeaderUsesAccountTemplate(route *ServiceRoute, headerName string) bool {
	if route == nil {
		return false
	}
	val := lookupMapFold(route.StaticHeaders, headerName)
	if val == "" {
		return false
	}
	return TemplateUsesAccount(val)
}

func (m *Manager) dispatchChallengeWebhookAsync(webhookURL string, payload challengeWebhookPayload, secrets []string) {
	if m.lifecycleCtx != nil && m.lifecycleCtx.Err() != nil {
		return
	}
	secCopy := cloneStringSlice(secrets)
	select {
	case m.webhookSem <- struct{}{}:
	default:
		// Bound concurrent webhook dispatches under traffic spikes.
		return
	}
	m.webhookWG.Add(1)
	go func() {
		defer m.webhookWG.Done()
		defer func() { <-m.webhookSem }()
		baseCtx := m.lifecycleCtx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		_ = sendChallengeWebhook(baseCtx, m.webhookClient, webhookURL, payload, secCopy)
	}()
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

func routeUsesAccountTemplates(route *ServiceRoute) bool {
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
	return TemplateUsesAccount(sources...)
}

func isGatewayInternalHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "x-api-key", "x-cap-device-id", "x-cap-proxy-id", "x-cap-account-id":
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
