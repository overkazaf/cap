package gateway

import (
	"container/list"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ==================== TTL + LRU Route Response Cache ====================

type cachedRouteEntry struct {
	key         string
	slug        string
	status      int
	headers     map[string]string
	body        string
	data        any
	upstreamURL string
	expiresAt   time.Time
}

type routeCacheBucket struct {
	maxEntries int
	lru        *list.List
	items      map[string]*list.Element
}

// RouteCache is a thread-safe per-route bounded LRU + TTL response cache.
type RouteCache struct {
	mu      sync.Mutex
	buckets map[string]*routeCacheBucket
	now     func() time.Time
}

// NewRouteCache creates a new bounded LRU+TTL RouteCache.
func NewRouteCache() *RouteCache {
	return &RouteCache{
		buckets: make(map[string]*routeCacheBucket),
		now:     time.Now,
	}
}

// Get retrieves a non-expired cached response and refreshes its LRU position.
func (c *RouteCache) Get(slug, key string) (*cachedRouteEntry, bool) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, ok := c.buckets[slug]
	if !ok {
		return nil, false
	}
	elem, exists := bucket.items[key]
	if !exists {
		return nil, false
	}
	entry := elem.Value.(*cachedRouteEntry)
	if !now.Before(entry.expiresAt) {
		bucket.lru.Remove(elem)
		delete(bucket.items, key)
		return nil, false
	}
	bucket.lru.MoveToFront(elem)
	cp := *entry
	cp.headers = cloneStringMap(entry.headers)
	return &cp, true
}

// Set stores a response entry in slug's LRU bucket with the given TTL and cap.
func (c *RouteCache) Set(slug, key string, entry cachedRouteEntry, ttl time.Duration, maxEntries int) {
	if ttl <= 0 {
		return
	}
	if maxEntries <= 0 {
		maxEntries = DefaultCacheMaxEntries
	}
	now := c.now()
	entry.key = key
	entry.slug = slug
	entry.headers = cloneStringMap(entry.headers)
	entry.expiresAt = now.Add(ttl)

	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, ok := c.buckets[slug]
	if !ok {
		bucket = &routeCacheBucket{
			maxEntries: maxEntries,
			lru:        list.New(),
			items:      make(map[string]*list.Element),
		}
		c.buckets[slug] = bucket
	}
	bucket.maxEntries = maxEntries

	if elem, exists := bucket.items[key]; exists {
		elem.Value = &entry
		bucket.lru.MoveToFront(elem)
	} else {
		elem := bucket.lru.PushFront(&entry)
		bucket.items[key] = elem
	}

	for bucket.lru.Len() > bucket.maxEntries {
		back := bucket.lru.Back()
		if back == nil {
			break
		}
		evicted := back.Value.(*cachedRouteEntry)
		delete(bucket.items, evicted.key)
		bucket.lru.Remove(back)
	}
}

// Clear removes cached entries for slug (or all routes when slug is empty).
func (c *RouteCache) Clear(slug string) {
	slug = normalizeSlug(slug)
	c.mu.Lock()
	defer c.mu.Unlock()
	if slug == "" {
		c.buckets = make(map[string]*routeCacheBucket)
		return
	}
	delete(c.buckets, slug)
}

// BuildCacheKey computes a deterministic SHA-256 key from route.Slug, HTTP
// method, and either route.CacheKeyFields or the full input/query/body payload.
func BuildCacheKey(route *ServiceRoute, method string, req TestInvokeRequest) string {
	h := sha256.New()
	_, _ = h.Write([]byte(route.Slug))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.ToUpper(strings.TrimSpace(method))))
	_, _ = h.Write([]byte{0})

	if len(route.CacheKeyFields) > 0 {
		var bodyObj map[string]any
		if trimmed := strings.TrimSpace(req.Body); strings.HasPrefix(trimmed, "{") {
			_ = json.Unmarshal([]byte(trimmed), &bodyObj)
		}
		fields := cloneStringSlice(route.CacheKeyFields)
		sort.Strings(fields)
		for _, field := range fields {
			f := strings.TrimSpace(field)
			if f == "" {
				continue
			}
			val := ""
			if v, ok := req.Input[f]; ok {
				val = v
			} else if v, ok := req.Query[f]; ok {
				val = v
			} else if bodyObj != nil {
				if rawVal, ok := bodyObj[f]; ok {
					val = stringifyScalar(rawVal)
				}
			} else if hv := lookupMapFold(req.Headers, f); hv != "" {
				val = hv
			}
			_, _ = h.Write([]byte(f))
			_, _ = h.Write([]byte{'='})
			_, _ = h.Write([]byte(val))
			_, _ = h.Write([]byte{0})
		}
		return hex.EncodeToString(h.Sum(nil))
	}

	writeSortedMapHash(h, "in", req.Input)
	writeSortedMapHash(h, "q", req.Query)
	_, _ = h.Write([]byte("body="))
	_, _ = h.Write([]byte(req.Body))
	return hex.EncodeToString(h.Sum(nil))
}

func writeSortedMapHash(h interface{ Write([]byte) (int, error) }, prefix string, m map[string]string) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = h.Write([]byte(prefix))
		_, _ = h.Write([]byte{':'})
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{'='})
		_, _ = h.Write([]byte(m[k]))
		_, _ = h.Write([]byte{0})
	}
}

func cacheControlHasDirective(headers map[string]string, directive string) bool {
	cc := strings.ToLower(lookupMapFold(headers, "Cache-Control"))
	if cc == "" {
		return false
	}
	for _, part := range strings.Split(cc, ",") {
		if strings.TrimSpace(part) == directive {
			return true
		}
	}
	return false
}

// ==================== Per-Route Circuit Breaker ====================

type routeCircuitEntry struct {
	slug                string
	state               string
	consecutiveFailures int
	threshold           int
	cooldown            time.Duration
	openedAt            time.Time
	lastFailure         string
	tripCount           int64
	halfOpenInFlight    bool
}

// CircuitBreaker tracks per-route failure streaks and trips open circuits
// with cooldown recovery via a half-open probe.
type CircuitBreaker struct {
	mu       sync.Mutex
	circuits map[string]*routeCircuitEntry
	now      func() time.Time
}

// NewCircuitBreaker constructs a thread-safe per-route CircuitBreaker.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		circuits: make(map[string]*routeCircuitEntry),
		now:      time.Now,
	}
}

func circuitCooldownDuration(sec int) time.Duration {
	if sec <= 0 {
		sec = DefaultCircuitCooldownSec
	}
	return time.Duration(sec) * time.Second
}

// Allow decides whether a request to slug may proceed. When an open circuit's
// cooldown has elapsed, one request is admitted as a half_open probe.
func (cb *CircuitBreaker) Allow(slug string, threshold int, cooldownSec int) (allowed bool, state string) {
	if threshold <= 0 {
		return true, CircuitStateClosed
	}
	slug = normalizeSlug(slug)
	cooldown := circuitCooldownDuration(cooldownSec)
	now := cb.now()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	entry, ok := cb.circuits[slug]
	if !ok {
		cb.circuits[slug] = &routeCircuitEntry{
			slug:      slug,
			state:     CircuitStateClosed,
			threshold: threshold,
			cooldown:  cooldown,
		}
		return true, CircuitStateClosed
	}
	entry.threshold = threshold
	entry.cooldown = cooldown

	switch entry.state {
	case CircuitStateClosed:
		return true, CircuitStateClosed
	case CircuitStateOpen:
		if !now.Before(entry.openedAt.Add(entry.cooldown)) {
			entry.state = CircuitStateHalfOpen
			entry.halfOpenInFlight = true
			return true, CircuitStateHalfOpen
		}
		return false, CircuitStateOpen
	case CircuitStateHalfOpen:
		if entry.halfOpenInFlight {
			return false, CircuitStateOpen
		}
		entry.halfOpenInFlight = true
		return true, CircuitStateHalfOpen
	default:
		entry.state = CircuitStateClosed
		return true, CircuitStateClosed
	}
}

// RecordSuccess transitions a closed or half_open circuit cleanly to closed.
func (cb *CircuitBreaker) RecordSuccess(slug string) {
	slug = normalizeSlug(slug)
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if entry, ok := cb.circuits[slug]; ok {
		entry.state = CircuitStateClosed
		entry.consecutiveFailures = 0
		entry.halfOpenInFlight = false
		entry.lastFailure = ""
		entry.openedAt = time.Time{}
	}
}

// RecordFailure increments consecutive failures and opens the circuit when the
// threshold is reached (or immediately on a failed half_open probe).
func (cb *CircuitBreaker) RecordFailure(slug string, threshold int, cooldownSec int, reason string) {
	if threshold <= 0 {
		return
	}
	slug = normalizeSlug(slug)
	cooldown := circuitCooldownDuration(cooldownSec)
	now := cb.now()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	entry, ok := cb.circuits[slug]
	if !ok {
		entry = &routeCircuitEntry{
			slug:      slug,
			state:     CircuitStateClosed,
			threshold: threshold,
			cooldown:  cooldown,
		}
		cb.circuits[slug] = entry
	}
	entry.threshold = threshold
	entry.cooldown = cooldown
	entry.lastFailure = reason
	entry.consecutiveFailures++

	if entry.state == CircuitStateHalfOpen || entry.consecutiveFailures >= threshold {
		entry.state = CircuitStateOpen
		entry.openedAt = now
		entry.halfOpenInFlight = false
		entry.tripCount++
	}
}

// Reset manually closes and clears circuit breaker state for slug (or all routes
// when slug is empty).
func (cb *CircuitBreaker) Reset(slug string) {
	slug = normalizeSlug(slug)
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if slug == "" {
		for _, entry := range cb.circuits {
			entry.state = CircuitStateClosed
			entry.consecutiveFailures = 0
			entry.halfOpenInFlight = false
			entry.lastFailure = ""
			entry.openedAt = time.Time{}
		}
		return
	}
	if entry, ok := cb.circuits[slug]; ok {
		entry.state = CircuitStateClosed
		entry.consecutiveFailures = 0
		entry.halfOpenInFlight = false
		entry.lastFailure = ""
		entry.openedAt = time.Time{}
	}
}

// Snapshots returns a copy of all tracked per-route circuit breaker states.
func (cb *CircuitBreaker) Snapshots() map[string]CircuitSnapshot {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	out := make(map[string]CircuitSnapshot, len(cb.circuits))
	for slug, e := range cb.circuits {
		snap := CircuitSnapshot{
			RouteSlug:           e.slug,
			State:               e.state,
			ConsecutiveFailures: e.consecutiveFailures,
			Threshold:           e.threshold,
			CooldownSec:         int(e.cooldown.Seconds()),
			LastFailure:         e.lastFailure,
			TripCount:           e.tripCount,
		}
		if !e.openedAt.IsZero() {
			snap.OpenedAt = e.openedAt.UTC().Format(time.RFC3339)
			snap.NextProbeAt = e.openedAt.Add(e.cooldown).UTC().Format(time.RFC3339)
		}
		out[slug] = snap
	}
	return out
}

// OpenCount returns the number of routes currently in the open state.
func (cb *CircuitBreaker) OpenCount() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	count := 0
	for _, e := range cb.circuits {
		if e.state == CircuitStateOpen {
			count++
		}
	}
	return count
}

// ==================== TLS Fingerprint & mTLS Upstream Transports ====================

// NormalizeTLSProfile validates and canonicalizes a TLSProfile identifier.
func NormalizeTLSProfile(profile string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(profile))
	switch p {
	case "", TLSProfileGoDefault:
		return TLSProfileGoDefault, nil
	case TLSProfileChrome131, TLSProfileSafari17, TLSProfileFirefox132, TLSProfileOkHttpAndroid, TLSProfileIOSCFNetwork:
		return p, nil
	default:
		return "", fmt.Errorf("unsupported tls_profile %q", profile)
	}
}

// BuildTLSConfig constructs a tailored *tls.Config for profile plus optional
// mTLS client cert/key files and optional custom RootCAs.
func BuildTLSConfig(profile, mtlsCertPath, mtlsKeyPath string, rootCAs *x509.CertPool) (*tls.Config, error) {
	norm, err := NormalizeTLSProfile(profile)
	if err != nil {
		return nil, err
	}
	certPath := strings.TrimSpace(mtlsCertPath)
	keyPath := strings.TrimSpace(mtlsKeyPath)
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("both mtls_cert_path and mtls_key_path must be specified together")
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    rootCAs,
	}

	switch norm {
	case TLSProfileChrome131:
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		}
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}
		cfg.NextProtos = []string{"h2", "http/1.1"}
	case TLSProfileSafari17:
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
		cfg.NextProtos = []string{"h2", "http/1.1"}
	case TLSProfileFirefox132:
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
		cfg.NextProtos = []string{"h2", "http/1.1"}
	case TLSProfileOkHttpAndroid:
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}
		cfg.NextProtos = []string{"h2", "http/1.1"}
	case TLSProfileIOSCFNetwork:
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
		cfg.NextProtos = []string{"h2", "http/1.1"}
	case TLSProfileGoDefault:
		// Keep Go default cipher suites and curve preferences.
	}

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load mTLS client keypair (%s, %s): %w", certPath, keyPath, err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

type upstreamTransportCacheKey struct {
	proxyKey   string
	tlsProfile string
	mtlsCert   string
	mtlsKey    string
}

// UpstreamTransportPool caches configured *http.Transports keyed by
// (proxyKey, tlsProfile, mtlsCert, mtlsKey).
type UpstreamTransportPool struct {
	mu         sync.RWMutex
	transports map[upstreamTransportCacheKey]*http.Transport
	rootCAs    *x509.CertPool
}

// NewUpstreamTransportPool creates an empty UpstreamTransportPool.
func NewUpstreamTransportPool() *UpstreamTransportPool {
	return &UpstreamTransportPool{
		transports: make(map[upstreamTransportCacheKey]*http.Transport),
	}
}

// SetRootCAs configures an optional trusted CA pool (e.g. for private CAs or
// mTLS unit tests) and resets cached transports.
func (p *UpstreamTransportPool) SetRootCAs(pool *x509.CertPool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
	p.rootCAs = pool
}

// HasCustomRootCAs reports whether a custom RootCA pool is configured.
func (p *UpstreamTransportPool) HasCustomRootCAs() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rootCAs != nil
}

// TransportFor returns a pooled *http.Transport tailored for proxy + TLS profile
// + mTLS client cert/key.
func (p *UpstreamTransportPool) TransportFor(proxy *ProxyNode, tlsProfile, mtlsCert, mtlsKey string) (*http.Transport, error) {
	normProfile, err := NormalizeTLSProfile(tlsProfile)
	if err != nil {
		return nil, err
	}
	mtlsCert = strings.TrimSpace(mtlsCert)
	mtlsKey = strings.TrimSpace(mtlsKey)

	proxyKey := "direct"
	if proxy != nil {
		proxyKey = canonicalProxyKey(*proxy)
	}
	key := upstreamTransportCacheKey{
		proxyKey:   proxyKey,
		tlsProfile: normProfile,
		mtlsCert:   mtlsCert,
		mtlsKey:    mtlsKey,
	}

	p.mu.RLock()
	if tr, ok := p.transports[key]; ok {
		p.mu.RUnlock()
		return tr, nil
	}
	rootCAs := p.rootCAs
	p.mu.RUnlock()

	tlsCfg, err := BuildTLSConfig(normProfile, mtlsCert, mtlsKey, rootCAs)
	if err != nil {
		return nil, err
	}

	var tr *http.Transport
	if proxy != nil {
		tr, err = BuildProxyTransport(proxy)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = tlsCfg
	} else {
		tr = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsCfg,
		}
	}

	if hasALPNProtocol(tlsCfg.NextProtos, "h2") {
		tr.ForceAttemptHTTP2 = true
	}

	p.mu.Lock()
	if existing, ok := p.transports[key]; ok {
		p.mu.Unlock()
		tr.CloseIdleConnections()
		return existing, nil
	}
	p.transports[key] = tr
	p.mu.Unlock()
	return tr, nil
}

// CloseIdleConnections releases idle sockets across all cached transports.
func (p *UpstreamTransportPool) CloseIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
}

func (p *UpstreamTransportPool) closeLocked() {
	for k, tr := range p.transports {
		tr.CloseIdleConnections()
		delete(p.transports, k)
	}
}

func hasALPNProtocol(protos []string, target string) bool {
	for _, p := range protos {
		if p == target {
			return true
		}
	}
	return false
}

// ==================== Prometheus Metrics Exposition ====================

// FormatPrometheusMetrics renders gateway telemetry in Prometheus text
// exposition format (`text/plain; version=0.0.4`).
func FormatPrometheusMetrics(stats GatewayStats, circuits map[string]CircuitSnapshot) string {
	var b strings.Builder

	writeMetric := func(name, help, typ, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", name, typ)
		fmt.Fprintf(&b, "%s %s\n", name, value)
	}

	writeMetric("cap_gateway_requests_total", "Total number of gateway route invocations.", "counter", fmt.Sprintf("%d", stats.TotalRequests))
	writeMetric("cap_gateway_errors_total", "Total number of failed gateway route invocations.", "counter", fmt.Sprintf("%d", stats.ErrorRequests))
	writeMetric("cap_gateway_cache_hits_total", "Total number of route response cache hits.", "counter", fmt.Sprintf("%d", stats.CacheHits))
	writeMetric("cap_gateway_cache_misses_total", "Total number of route response cache misses.", "counter", fmt.Sprintf("%d", stats.CacheMisses))
	writeMetric("cap_gateway_latency_ms_avg", "Average gateway request latency in milliseconds.", "gauge", fmt.Sprintf("%.2f", stats.AvgLatencyMs))
	writeMetric("cap_gateway_proxies_healthy", "Current number of enabled and healthy proxy nodes.", "gauge", fmt.Sprintf("%d", stats.ProxyHealthy))
	writeMetric("cap_gateway_devices_active", "Current number of enabled device profiles.", "gauge", fmt.Sprintf("%d", stats.DeviceEnabled))
	writeMetric("cap_gateway_accounts_active", "Current number of active non-expired account profiles.", "gauge", fmt.Sprintf("%d", stats.ActiveAccounts))
	writeMetric("cap_gateway_workers_healthy", "Current number of healthy managed signer worker instances.", "gauge", fmt.Sprintf("%d", stats.HealthyWorkers))

	b.WriteString("# HELP cap_gateway_route_circuit_state Current per-route circuit breaker state (0=closed, 1=open, 2=half_open).\n")
	b.WriteString("# TYPE cap_gateway_route_circuit_state gauge\n")
	if len(circuits) > 0 {
		slugs := make([]string, 0, len(circuits))
		for slug := range circuits {
			slugs = append(slugs, slug)
		}
		sort.Strings(slugs)
		for _, slug := range slugs {
			snap := circuits[slug]
			val := 0
			switch snap.State {
			case CircuitStateOpen:
				val = 1
			case CircuitStateHalfOpen:
				val = 2
			}
			fmt.Fprintf(&b, "cap_gateway_route_circuit_state{route=\"%s\"} %d\n", escapePromLabelValue(slug), val)
		}
	}

	return b.String()
}

func escapePromLabelValue(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// ==================== Headless Docker Deployment Export ====================

func extractListenPort(listenAddr string) string {
	addr := strings.TrimSpace(listenAddr)
	if addr == "" {
		addr = DefaultListenAddr
	}
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	if strings.HasPrefix(addr, ":") && len(addr) > 1 {
		return addr[1:]
	}
	return "9090"
}

// GenerateDockerfile returns a production multi-stage Dockerfile for running
// `cap gateway serve` headlessly in a container.
func GenerateDockerfile(listenAddr string) string {
	port := extractListenPort(listenAddr)
	return fmt.Sprintf(`# syntax=docker/dockerfile:1
FROM golang:1.27-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cap ./cmd/cap

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN useradd --system --create-home --home-dir /home/cap --shell /usr/sbin/nologin cap \
    && mkdir -p /data/cap && chown -R cap:cap /data/cap
COPY --from=builder /out/cap /usr/local/bin/cap
USER cap
ENV HOME=/data/cap
WORKDIR /data/cap
VOLUME ["/data/cap"]
EXPOSE %s
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:%s/health || exit 1
ENTRYPOINT ["cap"]
CMD ["gateway", "serve", "--addr", "0.0.0.0:%s"]
`, port, port, port)
}

// GenerateDockerCompose returns a docker-compose.yml for deploying the headless
// cap Open API Gateway with persistent state and healthchecks.
func GenerateDockerCompose(listenAddr string) string {
	port := extractListenPort(listenAddr)
	return fmt.Sprintf(`services:
  cap-gateway:
    build:
      context: .
      dockerfile: Dockerfile
    image: cap-gateway:latest
    container_name: cap-gateway
    restart: unless-stopped
    ports:
      - "%s:%s"
    environment:
      - HOME=/data/cap
      - CAP_GW_LISTEN_ADDR=0.0.0.0:%s
    volumes:
      - ./cap-data:/data/cap
    command: ["gateway", "serve", "--addr", "0.0.0.0:%s"]
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:%s/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 5s
`, port, port, port, port, port)
}
