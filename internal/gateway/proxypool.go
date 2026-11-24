package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	maxProxyProviderBodyBytes = 4 * 1024 * 1024
	healthCheckConcurrency    = 8
	defaultHealthCheckTimeout = 8 * time.Second
)

type transportCacheKey struct {
	url      string
	username string
	password string
}

// ProxyPool manages a thread-safe pool of HTTP/HTTPS/SOCKS5 proxies with
// health probing, dynamic IP provider ingestion, rotation strategies, tag and
// region filtering, sticky device binding, and failover selection.
type ProxyPool struct {
	mu         sync.RWMutex
	cfg        ProxyPoolConfig
	nodes      map[string]ProxyNode
	transports map[transportCacheKey]*http.Transport
	rrCounter  atomic.Uint64

	refreshMu     sync.Mutex
	refreshCancel context.CancelFunc
	refreshDone   chan struct{}

	// providerClient may be overridden in tests if needed; defaults to a standard client.
	providerClient *http.Client
}

// NewProxyPool constructs a ProxyPool with normalized default settings.
func NewProxyPool(cfg ProxyPoolConfig) *ProxyPool {
	cfg = normalizeProxyPoolConfig(cfg)
	return &ProxyPool{
		cfg:            cfg,
		nodes:          make(map[string]ProxyNode),
		transports:     make(map[transportCacheKey]*http.Transport),
		providerClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func normalizeProxyPoolConfig(cfg ProxyPoolConfig) ProxyPoolConfig {
	switch strings.ToLower(strings.TrimSpace(cfg.Strategy)) {
	case StrategyRoundRobin, StrategyRandom, StrategyLeastLatency, StrategyStickyDevice:
		cfg.Strategy = strings.ToLower(strings.TrimSpace(cfg.Strategy))
	default:
		cfg.Strategy = StrategyRoundRobin
	}
	if cfg.ProviderFormat != "" {
		f := strings.ToLower(strings.TrimSpace(cfg.ProviderFormat))
		if f == ProviderFormatLines || f == ProviderFormatJSON {
			cfg.ProviderFormat = f
		}
	}
	if cfg.FailoverRetries < 0 {
		cfg.FailoverRetries = 0
	}
	return cfg
}

// Config returns a copy of the current ProxyPoolConfig.
func (p *ProxyPool) Config() ProxyPoolConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

// SetConfig updates the ProxyPoolConfig.
func (p *ProxyPool) SetConfig(cfg ProxyPoolConfig) {
	cfg = normalizeProxyPoolConfig(cfg)
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
}

// LoadNodes replaces the in-memory proxy nodes (used during persistence load).
func (p *ProxyPool) LoadNodes(nodes []ProxyNode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeTransportsLocked()
	p.nodes = make(map[string]ProxyNode, len(nodes))
	for _, n := range nodes {
		if normURL, err := NormalizeProxyURL(n.URL); err == nil {
			n.URL = normURL
		}
		if strings.TrimSpace(n.ID) == "" {
			n.ID = "proxy-" + randomHex(4)
		}
		n.Tags = normalizeTags(n.Tags)
		p.nodes[n.ID] = cloneProxyNode(n)
	}
}

// List returns all proxy nodes sorted deterministically by name then ID.
func (p *ProxyPool) List() []ProxyNode {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]ProxyNode, 0, len(p.nodes))
	for _, n := range p.nodes {
		out = append(out, cloneProxyNode(n))
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if ni != nj {
			return ni < nj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get retrieves a proxy node by ID.
func (p *ProxyPool) Get(id string) (*ProxyNode, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n, ok := p.nodes[strings.TrimSpace(id)]
	if !ok {
		return nil, false
	}
	cp := cloneProxyNode(n)
	return &cp, true
}

// Add inserts or updates a proxy node. Alias for Upsert.
func (p *ProxyPool) Add(node ProxyNode) (*ProxyNode, error) {
	return p.Upsert(node)
}

// Upsert validates, normalizes, and stores a proxy node.
func (p *ProxyPool) Upsert(node ProxyNode) (*ProxyNode, error) {
	normURL, err := NormalizeProxyURL(node.URL)
	if err != nil {
		return nil, err
	}
	node.URL = normURL
	node.ID = strings.TrimSpace(node.ID)
	if node.ID == "" {
		base := sanitizeID(node.Name, "proxy")
		node.ID = fmt.Sprintf("%s-%s", base, randomHex(4))
	}
	node.Name = strings.TrimSpace(node.Name)
	if node.Name == "" {
		if u, err := url.Parse(node.URL); err == nil && u.Host != "" {
			node.Name = u.Host
		} else {
			node.Name = node.ID
		}
	}
	node.Region = strings.TrimSpace(node.Region)
	node.Tags = normalizeTags(node.Tags)

	p.mu.Lock()
	if prev, exists := p.nodes[node.ID]; exists {
		// Invalidate cached transport if endpoint or credentials changed.
		if prev.URL != node.URL || prev.Username != node.Username || prev.Password != node.Password {
			key := transportCacheKey{url: prev.URL, username: prev.Username, password: prev.Password}
			if tr, ok := p.transports[key]; ok {
				tr.CloseIdleConnections()
				delete(p.transports, key)
			}
		}
	}
	p.nodes[node.ID] = cloneProxyNode(node)
	p.mu.Unlock()

	cp := cloneProxyNode(node)
	return &cp, nil
}

// Delete removes a proxy node by ID and closes any idle transport for it.
func (p *ProxyPool) Delete(id string) error {
	id = strings.TrimSpace(id)
	p.mu.Lock()
	defer p.mu.Unlock()
	prev, ok := p.nodes[id]
	if !ok {
		return fmt.Errorf("proxy %q not found", id)
	}
	delete(p.nodes, id)
	key := transportCacheKey{url: prev.URL, username: prev.Username, password: prev.Password}
	if tr, exists := p.transports[key]; exists {
		tr.CloseIdleConnections()
		delete(p.transports, key)
	}
	return nil
}

// Counts returns (total, healthyEnabled) proxy node counts.
func (p *ProxyPool) Counts() (total int, healthy int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total = len(p.nodes)
	for _, n := range p.nodes {
		if n.Enabled && n.Healthy {
			healthy++
		}
	}
	return total, healthy
}

// Select chooses an eligible proxy node according to opts and the configured
// rotation strategy.
//
// Eligibility rules:
//   - Only Enabled nodes not present in opts.ExcludeIDs are considered.
//   - Nodes must match opts.Tags (all required tags) and opts.Region (if set).
//   - If opts.StickyProxyID is set and that node is enabled, not excluded, and
//     healthy (or unchecked), it is returned immediately.
//   - Healthy nodes (Healthy == true) are always preferred; if none are marked
//     Healthy yet, unchecked nodes (LastChecked == "" && FailCount == 0 &&
//     LastError == "") are eligible as a fallback so freshly added proxies work
//     immediately before a health probe runs. Nodes that have explicitly failed
//     are never selected until they recover.
func (p *ProxyPool) Select(opts ProxySelectOptions) (*ProxyNode, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	strategy := strings.ToLower(strings.TrimSpace(opts.Strategy))
	if strategy == "" {
		strategy = p.cfg.Strategy
	}
	if strategy == "" {
		strategy = StrategyRoundRobin
	}

	isEligibleNode := func(n ProxyNode) bool {
		if !n.Enabled {
			return false
		}
		if opts.ExcludeIDs != nil && opts.ExcludeIDs[n.ID] {
			return false
		}
		return true
	}

	isUnchecked := func(n ProxyNode) bool {
		return !n.Healthy && n.LastChecked == "" && n.FailCount == 0 && n.LastError == ""
	}

	// Honor explicit sticky proxy affinity first if available and healthy/unchecked.
	if stickyID := strings.TrimSpace(opts.StickyProxyID); stickyID != "" {
		if n, ok := p.nodes[stickyID]; ok && isEligibleNode(n) && (n.Healthy || isUnchecked(n)) {
			cp := cloneProxyNode(n)
			return &cp, nil
		}
	}

	var healthy []ProxyNode
	var unchecked []ProxyNode
	for _, n := range p.nodes {
		if !isEligibleNode(n) {
			continue
		}
		if !hasAllTags(n.Tags, opts.Tags) {
			continue
		}
		if opts.Region != "" && !strings.EqualFold(strings.TrimSpace(n.Region), strings.TrimSpace(opts.Region)) {
			continue
		}
		if n.Healthy {
			healthy = append(healthy, n)
		} else if isUnchecked(n) {
			unchecked = append(unchecked, n)
		}
	}

	candidates := healthy
	if len(candidates) == 0 {
		candidates = unchecked
	}
	if len(candidates) == 0 {
		return nil, errors.New("no healthy proxy available matching criteria")
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ID < candidates[j].ID
	})

	var chosen ProxyNode
	switch strategy {
	case StrategyRandom:
		chosen = candidates[rand.IntN(len(candidates))]
	case StrategyLeastLatency:
		bestIdx := -1
		bestLat := int64(math.MaxInt64)
		for i, c := range candidates {
			lat := c.LatencyMs
			if lat <= 0 {
				lat = math.MaxInt64
			}
			if lat < bestLat {
				bestLat = lat
				bestIdx = i
			}
		}
		if bestIdx < 0 || bestLat == math.MaxInt64 {
			idx := p.rrCounter.Add(1) - 1
			chosen = candidates[idx%uint64(len(candidates))]
		} else {
			chosen = candidates[bestIdx]
		}
	case StrategyStickyDevice, StrategyRoundRobin:
		idx := p.rrCounter.Add(1) - 1
		chosen = candidates[idx%uint64(len(candidates))]
	default:
		idx := p.rrCounter.Add(1) - 1
		chosen = candidates[idx%uint64(len(candidates))]
	}

	cp := cloneProxyNode(chosen)
	return &cp, nil
}

// RecordResult updates success/failure counters, latency, and health state for a proxy node.
func (p *ProxyPool) RecordResult(id string, ok bool, latencyMs int64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, exists := p.nodes[id]
	if !exists {
		return
	}
	n.LastChecked = nowRFC3339()
	if ok {
		n.Healthy = true
		n.SuccessCount++
		n.LastError = ""
		if latencyMs > 0 {
			if n.LatencyMs <= 0 {
				n.LatencyMs = latencyMs
			} else {
				// Smooth latency with 50/50 EWMA so recent probes dominate while damping spikes.
				n.LatencyMs = (n.LatencyMs + latencyMs) / 2
			}
		}
	} else {
		n.Healthy = false
		n.FailCount++
		if err != nil {
			n.LastError = err.Error()
		} else {
			n.LastError = "proxy request failed"
		}
	}
	p.nodes[id] = n
}

// TransportFor returns a pooled *http.Transport configured for node (caching by
// URL and credentials to reuse connections safely).
func (p *ProxyPool) TransportFor(node *ProxyNode) (*http.Transport, error) {
	if node == nil {
		return nil, errors.New("proxy node is nil")
	}
	key := transportCacheKey{
		url:      node.URL,
		username: node.Username,
		password: node.Password,
	}
	p.mu.RLock()
	tr, ok := p.transports[key]
	p.mu.RUnlock()
	if ok {
		return tr, nil
	}

	built, err := BuildProxyTransport(node)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if existing, ok := p.transports[key]; ok {
		p.mu.Unlock()
		built.CloseIdleConnections()
		return existing, nil
	}
	p.transports[key] = built
	p.mu.Unlock()
	return built, nil
}

// CloseIdleConnections releases idle sockets across all cached proxy transports.
func (p *ProxyPool) CloseIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeTransportsLocked()
}

func (p *ProxyPool) closeTransportsLocked() {
	for k, tr := range p.transports {
		tr.CloseIdleConnections()
		delete(p.transports, k)
	}
}

// CheckNode probes a single proxy node against checkURL (or pool HealthCheckURL),
// measuring latency and updating its health metadata.
func (p *ProxyPool) CheckNode(ctx context.Context, id string, checkURL string) (*ProxyNode, error) {
	node, ok := p.Get(id)
	if !ok {
		return nil, fmt.Errorf("proxy %q not found", id)
	}
	target := strings.TrimSpace(checkURL)
	if target == "" {
		target = strings.TrimSpace(p.Config().HealthCheckURL)
	}
	if target == "" {
		target = DefaultHealthCheckURL
	}

	tr, err := BuildProxyTransport(node)
	if err != nil {
		p.RecordResult(node.ID, false, 0, err)
		updated, _ := p.Get(node.ID)
		return updated, err
	}
	defer tr.CloseIdleConnections()

	probeCtx, cancel := context.WithTimeout(ctx, defaultHealthCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target, nil)
	if err != nil {
		p.RecordResult(node.ID, false, 0, err)
		updated, _ := p.Get(node.ID)
		return updated, err
	}
	req.Header.Set("User-Agent", "cap-gateway-healthcheck/1.0")

	client := &http.Client{
		Transport: tr,
		Timeout:   defaultHealthCheckTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if latency <= 0 {
		latency = 1
	}
	if err != nil {
		p.RecordResult(node.ID, false, latency, err)
		updated, _ := p.Get(node.ID)
		return updated, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		statusErr := fmt.Errorf("health check HTTP %d", resp.StatusCode)
		p.RecordResult(node.ID, false, latency, statusErr)
		updated, _ := p.Get(node.ID)
		return updated, statusErr
	}

	// Set exact measured latency on explicit health check.
	p.mu.Lock()
	if cur, exists := p.nodes[node.ID]; exists {
		cur.Healthy = true
		cur.LatencyMs = latency
		cur.SuccessCount++
		cur.LastChecked = nowRFC3339()
		cur.LastError = ""
		p.nodes[node.ID] = cur
	}
	p.mu.Unlock()

	updated, _ := p.Get(node.ID)
	return updated, nil
}

// CheckAll concurrently probes all enabled proxy nodes with bounded workers.
func (p *ProxyPool) CheckAll(ctx context.Context, checkURL string) []ProxyNode {
	nodes := p.List()
	var enabled []ProxyNode
	for _, n := range nodes {
		if n.Enabled {
			enabled = append(enabled, n)
		}
	}
	if len(enabled) == 0 {
		return nodes
	}

	sem := make(chan struct{}, healthCheckConcurrency)
	var wg sync.WaitGroup
	for _, n := range enabled {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			_, _ = p.CheckNode(ctx, id, checkURL)
		}(n.ID)
	}
	wg.Wait()
	return p.List()
}

// FetchFromProvider fetches proxy nodes from the configured ProviderURL and merges
// them into the pool.
func (p *ProxyPool) FetchFromProvider(ctx context.Context) (added int, total int, err error) {
	cfg := p.Config()
	return p.FetchFromProviderURL(ctx, cfg.ProviderURL, cfg.ProviderFormat, cfg.ProviderJSONPath)
}

// FetchFromProviderURL fetches dynamic proxies from an HTTP endpoint returning
// either line-delimited proxies or a JSON list.
func (p *ProxyPool) FetchFromProviderURL(ctx context.Context, providerURL, format, jsonPath string) (added int, total int, err error) {
	providerURL = strings.TrimSpace(providerURL)
	if providerURL == "" {
		return 0, len(p.List()), errors.New("proxy provider URL is empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, providerURL, nil)
	if err != nil {
		return 0, len(p.List()), fmt.Errorf("build provider request: %w", err)
	}
	req.Header.Set("User-Agent", "cap-gateway/1.0")

	client := p.providerClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, len(p.List()), fmt.Errorf("fetch proxy provider: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, len(p.List()), fmt.Errorf("proxy provider returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyProviderBodyBytes))
	if err != nil {
		return 0, len(p.List()), fmt.Errorf("read proxy provider response: %w", err)
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return 0, len(p.List()), nil
	}

	fmtMode := strings.ToLower(strings.TrimSpace(format))
	if fmtMode == "" {
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			fmtMode = ProviderFormatJSON
		} else {
			fmtMode = ProviderFormatLines
		}
	}

	var parsed []ProxyNode
	switch fmtMode {
	case ProviderFormatJSON:
		parsed, err = ParseProxyJSON(body, jsonPath)
		if err != nil {
			return 0, len(p.List()), err
		}
	case ProviderFormatLines:
		parsed = ParseProxyLines(trimmed)
	default:
		return 0, len(p.List()), fmt.Errorf("unsupported provider format %q", format)
	}

	p.mu.Lock()
	existingByURL := make(map[string]string, len(p.nodes))
	for id, n := range p.nodes {
		existingByURL[canonicalProxyKey(n)] = id
	}
	for _, n := range parsed {
		normURL, err := NormalizeProxyURL(n.URL)
		if err != nil {
			continue
		}
		n.URL = normURL
		n.Enabled = true
		n.Healthy = true
		n.Tags = normalizeTags(append(n.Tags, "provider"))
		key := canonicalProxyKey(n)
		if existingID, exists := existingByURL[key]; exists {
			cur := p.nodes[existingID]
			cur.Enabled = true
			if n.Region != "" {
				cur.Region = n.Region
			}
			cur.Tags = normalizeTags(append(cur.Tags, n.Tags...))
			p.nodes[existingID] = cur
			continue
		}
		if n.ID == "" {
			n.ID = fmt.Sprintf("provider-%s", randomHex(4))
		}
		if n.Name == "" {
			if u, err := url.Parse(n.URL); err == nil && u.Host != "" {
				n.Name = u.Host
			} else {
				n.Name = n.ID
			}
		}
		p.nodes[n.ID] = cloneProxyNode(n)
		existingByURL[key] = n.ID
		added++
	}
	total = len(p.nodes)
	p.mu.Unlock()
	return added, total, nil
}

// StartAutoRefresh launches a background refresh loop if ProviderURL and
// RefreshIntervalSec > 0 are configured. Calling it restarts any previous loop.
func (p *ProxyPool) StartAutoRefresh(ctx context.Context) {
	p.StopAutoRefresh()
	cfg := p.Config()
	if strings.TrimSpace(cfg.ProviderURL) == "" || cfg.RefreshIntervalSec <= 0 {
		return
	}
	interval := time.Duration(cfg.RefreshIntervalSec) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	p.refreshMu.Lock()
	p.refreshCancel = cancel
	p.refreshDone = done
	p.refreshMu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				_, _, _ = p.FetchFromProvider(runCtx)
			}
		}
	}()
}

// StopAutoRefresh cancels any active background provider refresh loop.
func (p *ProxyPool) StopAutoRefresh() {
	p.refreshMu.Lock()
	cancel := p.refreshCancel
	done := p.refreshDone
	p.refreshCancel = nil
	p.refreshDone = nil
	p.refreshMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func canonicalProxyKey(n ProxyNode) string {
	return strings.ToLower(strings.TrimSpace(n.URL)) + "|" + n.Username + "|" + n.Password
}

// NormalizeProxyURL validates and normalizes a proxy endpoint string.
// Supported forms:
//   - "1.2.3.4:8080" -> "http://1.2.3.4:8080"
//   - "user:pass@1.2.3.4:8080" -> "http://user:pass@1.2.3.4:8080"
//   - "http://...", "https://...", "socks5://...", "socks5h://..."
func NormalizeProxyURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("proxy URL is required")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("unsupported proxy scheme %q (supported: http, https, socks5, socks5h)", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("proxy URL %q is missing host", raw)
	}
	u.Scheme = scheme
	return u.String(), nil
}

// BuildProxyTransport constructs an *http.Transport wired to node (supporting
// HTTP, HTTPS, and SOCKS5 proxies with optional authentication).
func BuildProxyTransport(node *ProxyNode) (*http.Transport, error) {
	if node == nil {
		return nil, errors.New("proxy node is nil")
	}
	normURL, err := NormalizeProxyURL(node.URL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(normURL)
	if err != nil {
		return nil, err
	}
	if node.Username != "" && u.User == nil {
		if node.Password != "" {
			u.User = url.UserPassword(node.Username, node.Password)
		} else {
			u.User = url.User(node.Username)
		}
	}

	baseDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}

	switch u.Scheme {
	case "http", "https":
		tr.DialContext = baseDialer.DialContext
		tr.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{
				User:     u.User.Username(),
				Password: pw,
			}
		}
		socksDialer, err := xproxy.SOCKS5("tcp", u.Host, auth, baseDialer)
		if err != nil {
			return nil, fmt.Errorf("build socks5 dialer for %s: %w", u.Host, err)
		}
		if cd, ok := socksDialer.(xproxy.ContextDialer); ok {
			tr.DialContext = cd.DialContext
		} else {
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				type result struct {
					conn net.Conn
					err  error
				}
				ch := make(chan result, 1)
				go func() {
					c, e := socksDialer.Dial(network, addr)
					ch <- result{c, e}
				}()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case res := <-ch:
					return res.conn, res.err
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}

	return tr, nil
}

// ParseProxyLines parses newline/comma-separated proxy endpoints supporting:
//   - ip:port
//   - ip:port:user:pass
//   - user:pass@ip:port
//   - scheme://[user:pass@]ip:port
func ParseProxyLines(raw string) []ProxyNode {
	var out []ProxyNode
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Allow comma or semicolon separated items on a single line if no scheme conflicts.
		entries := []string{line}
		if !strings.Contains(line, "://") && (strings.Contains(line, ",") || strings.Contains(line, ";")) {
			entries = strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' })
		}
		for _, entry := range entries {
			if node, ok := parseProxyLineEntry(entry); ok {
				out = append(out, node)
			}
		}
	}
	return out
}

func parseProxyLineEntry(entry string) (ProxyNode, bool) {
	s := strings.TrimSpace(entry)
	if s == "" {
		return ProxyNode{}, false
	}

	var user, pass string
	// Handle host:port:user:pass format when no scheme or '@' is present.
	if !strings.Contains(s, "://") && !strings.Contains(s, "@") {
		parts := strings.Split(s, ":")
		if len(parts) == 4 && parts[0] != "" && parts[1] != "" {
			if _, err := strconv.Atoi(parts[1]); err == nil {
				s = fmt.Sprintf("http://%s:%s", parts[0], parts[1])
				user = parts[2]
				pass = parts[3]
			}
		}
	}

	normURL, err := NormalizeProxyURL(s)
	if err != nil {
		return ProxyNode{}, false
	}
	u, err := url.Parse(normURL)
	if err != nil {
		return ProxyNode{}, false
	}
	if u.User != nil && user == "" {
		user = u.User.Username()
		pass, _ = u.User.Password()
		u.User = nil
		normURL = u.String()
	}

	return ProxyNode{
		Name:     u.Host,
		URL:      normURL,
		Username: user,
		Password: pass,
		Enabled:  true,
		Healthy:  true,
	}, true
}

// ParseProxyJSON extracts proxy nodes from a JSON response body, navigating an
// optional dot-separated jsonPath (e.g., "data.list" or "proxies").
func ParseProxyJSON(raw []byte, jsonPath string) ([]ProxyNode, error) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse proxy provider JSON: %w", err)
	}

	target := root
	if strings.TrimSpace(jsonPath) != "" {
		for _, seg := range strings.Split(jsonPath, ".") {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			obj, ok := target.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("json path %q segment %q: expected object", jsonPath, seg)
			}
			next, exists := obj[seg]
			if !exists {
				return nil, fmt.Errorf("json path %q segment %q not found", jsonPath, seg)
			}
			target = next
		}
	} else if obj, ok := target.(map[string]any); ok {
		// Auto-discover common wrapper fields if no explicit jsonPath was provided.
		for _, key := range []string{"data", "proxies", "list", "items", "ips", "result"} {
			if v, exists := obj[key]; exists {
				switch inner := v.(type) {
				case []any:
					target = inner
				case map[string]any:
					for _, sub := range []string{"list", "proxies", "items", "ips"} {
						if arr, ok := inner[sub].([]any); ok {
							target = arr
							break
						}
					}
				}
				if _, isArr := target.([]any); isArr {
					break
				}
			}
		}
	}

	arr, ok := target.([]any)
	if !ok {
		return nil, fmt.Errorf("proxy provider JSON did not resolve to an array")
	}

	var out []ProxyNode
	for _, item := range arr {
		switch v := item.(type) {
		case string:
			if node, ok := parseProxyLineEntry(v); ok {
				out = append(out, node)
			}
		case map[string]any:
			if node, ok := parseProxyJSONObject(v); ok {
				out = append(out, node)
			}
		}
	}
	return out, nil
}

func parseProxyJSONObject(m map[string]any) (ProxyNode, bool) {
	getString := func(keys ...string) string {
		for _, k := range keys {
			if val, ok := m[k]; ok && val != nil {
				switch tv := val.(type) {
				case string:
					if s := strings.TrimSpace(tv); s != "" {
						return s
					}
				case float64:
					if tv == math.Trunc(tv) {
						return strconv.FormatInt(int64(tv), 10)
					}
					return strconv.FormatFloat(tv, 'f', -1, 64)
				}
			}
		}
		return ""
	}

	rawURL := getString("url", "proxy", "endpoint", "addr", "address")
	if rawURL == "" {
		host := getString("ip", "host", "server")
		port := getString("port")
		if host == "" {
			return ProxyNode{}, false
		}
		scheme := strings.ToLower(getString("scheme", "protocol", "type"))
		if scheme == "" {
			scheme = "http"
		}
		if port != "" {
			rawURL = fmt.Sprintf("%s://%s:%s", scheme, host, port)
		} else {
			rawURL = fmt.Sprintf("%s://%s", scheme, host)
		}
	}

	node, ok := parseProxyLineEntry(rawURL)
	if !ok {
		return ProxyNode{}, false
	}
	if u := getString("username", "user"); u != "" {
		node.Username = u
	}
	if pw := getString("password", "pass", "pwd"); pw != "" {
		node.Password = pw
	}
	if name := getString("name", "label"); name != "" {
		node.Name = name
	}
	if region := getString("region", "country", "location", "city"); region != "" {
		node.Region = region
	}
	if rawTags, exists := m["tags"]; exists {
		if tagList, ok := rawTags.([]any); ok {
			for _, t := range tagList {
				if ts, ok := t.(string); ok && strings.TrimSpace(ts) != "" {
					node.Tags = append(node.Tags, strings.TrimSpace(ts))
				}
			}
		}
	}
	return node, true
}
