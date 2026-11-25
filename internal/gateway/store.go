package gateway

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/fsutil"
	"github.com/overkazaf/cap/internal/types"
)

const (
	fileGatewayConfig       = "config.json"
	fileProxyPool           = "proxies.json"
	fileDevices             = "devices.json"
	fileSigners             = "signers.json"
	fileRoutes              = "routes.json"
	maxConcurrentWebhooks   = 8
)

type persistedProxyPool struct {
	Config ProxyPoolConfig `json:"config"`
	Nodes  []ProxyNode     `json:"nodes"`
}

// Manager coordinates cap's Open API Gateway: configuration, Proxy IP Pool,
// Device Pool, Account Pool, Managed Signer Worker Pool, Signer Providers,
// published ServiceRoutes, TTL Response Cache, Per-Route Circuit Breaker,
// TLS/mTLS Upstream Transport Pool, invocation ring-buffer logs, JSON
// persistence under ~/.cap/gateway/, live callbacks, and the embedded HTTP
// gateway server.
type Manager struct {
	dir        string
	proxies    *ProxyPool
	devices    *DevicePool
	accounts   *AccountPool
	workers    *WorkerPool
	signerExec *SignerExecutor
	cache      *RouteCache
	circuits   *CircuitBreaker
	transports *UpstreamTransportPool

	mu      sync.RWMutex
	cfg     GatewayConfig
	signers map[string]SignerProvider
	routes  map[string]ServiceRoute

	logMu sync.RWMutex
	logs  []InvocationRecord

	cbMu     sync.RWMutex
	onInvoke func(InvocationRecord)
	onStatus func(GatewayStatus)

	srvMu     sync.Mutex
	httpSrv   *http.Server
	running   bool
	boundAddr string
	startedAt string

	rlMu     sync.Mutex
	limiters map[string]*routeRateLimiter

	directTransport *http.Transport

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	webhookSem      chan struct{}
	webhookWG       sync.WaitGroup

	totalRequests   atomic.Int64
	successRequests atomic.Int64
	errorRequests   atomic.Int64
	rateLimited     atomic.Int64
	authFailures    atomic.Int64
	cacheHits       atomic.Int64
	cacheMisses     atomic.Int64
	totalLatencyMs  atomic.Int64
	invSeq          atomic.Int64
	inFlight        atomic.Int64
}

// NewManager initializes a Gateway Manager backed by `<capDir>/gateway/`.
// If capDir is empty, config.DefaultDir() (`~/.cap`) is used.
// Initialization degrades gracefully on read-only filesystems so in-memory
// operations remain available even when persistence cannot create directories.
func NewManager(capDir string) (*Manager, error) {
	if strings.TrimSpace(capDir) == "" {
		capDir = config.DefaultDir()
	}
	gwDir := filepath.Join(capDir, "gateway")
	_ = os.MkdirAll(gwDir, 0o755)

	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	workers := NewWorkerPool(filepath.Join(gwDir, fileWorkers))

	m := &Manager{
		dir: gwDir,
		cfg: GatewayConfig{
			ListenAddr: DefaultListenAddr,
			MaxLogs:    DefaultMaxLogs,
		},
		proxies: NewProxyPool(ProxyPoolConfig{
			Strategy:        StrategyRoundRobin,
			FailoverRetries: DefaultFailoverRetries,
		}),
		devices:    NewDevicePool(),
		accounts:   NewAccountPool(filepath.Join(gwDir, fileAccounts), AccountPoolConfig{Strategy: StrategyRoundRobin}),
		workers:    workers,
		signerExec: NewSignerExecutor(workers),
		cache:      NewRouteCache(),
		circuits:   NewCircuitBreaker(),
		transports: NewUpstreamTransportPool(),
		signers:    make(map[string]SignerProvider),
		routes:     make(map[string]ServiceRoute),
		logs:       make([]InvocationRecord, 0, 64),
		limiters:   make(map[string]*routeRateLimiter),
		directTransport: &http.Transport{
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		webhookSem:      make(chan struct{}, maxConcurrentWebhooks),
	}

	m.loadFromDisk()
	return m, nil
}

// Dir returns the gateway persistence directory path.
func (m *Manager) Dir() string {
	return m.dir
}

// ProxyPool returns the underlying ProxyPool instance.
func (m *Manager) ProxyPool() *ProxyPool {
	return m.proxies
}

// DevicePool returns the underlying DevicePool instance.
func (m *Manager) DevicePool() *DevicePool {
	return m.devices
}

// AccountPool returns the underlying AccountPool instance.
func (m *Manager) AccountPool() *AccountPool {
	return m.accounts
}

// WorkerPool returns the underlying Managed WorkerPool instance.
func (m *Manager) WorkerPool() *WorkerPool {
	return m.workers
}

// SignerExecutor returns the SignerExecutor wired to this Manager's WorkerPool.
func (m *Manager) SignerExecutor() *SignerExecutor {
	return m.signerExec
}

// SetUpstreamRootCAs configures an optional custom RootCA pool for upstream
// TLS/mTLS transports (e.g. private internal CAs or test servers).
func (m *Manager) SetUpstreamRootCAs(pool *x509.CertPool) {
	m.transports.SetRootCAs(pool)
}

// ClearRouteCache evicts cached responses for slug (or all routes if slug is empty).
func (m *Manager) ClearRouteCache(slug string) {
	m.cache.Clear(slug)
}

// ResetCircuit resets the circuit breaker state for slug (or all routes if empty).
func (m *Manager) ResetCircuit(slug string) {
	m.circuits.Reset(slug)
}

// CircuitStates returns live snapshots of all tracked route circuit breakers,
// including configured circuit-protected routes currently in the closed state.
func (m *Manager) CircuitStates() map[string]CircuitSnapshot {
	snaps := m.circuits.Snapshots()
	m.mu.RLock()
	for _, r := range m.routes {
		if r.CircuitFailThreshold > 0 {
			if _, exists := snaps[r.Slug]; !exists {
				cd := r.CircuitCooldownSec
				if cd <= 0 {
					cd = DefaultCircuitCooldownSec
				}
				snaps[r.Slug] = CircuitSnapshot{
					RouteSlug:   r.Slug,
					State:       CircuitStateClosed,
					Threshold:   r.CircuitFailThreshold,
					CooldownSec: cd,
				}
			}
		}
	}
	m.mu.RUnlock()
	return snaps
}

// PrometheusMetrics returns current gateway metrics in Prometheus text
// exposition format (`text/plain; version=0.0.4`).
func (m *Manager) PrometheusMetrics() string {
	return FormatPrometheusMetrics(m.Stats(), m.CircuitStates())
}

// ExportDockerBundle generates Dockerfile and docker-compose.yml artifacts for
// deploying headless `cap gateway serve`.
func (m *Manager) ExportDockerBundle(listenAddr string) DockerDeployBundle {
	addr := strings.TrimSpace(listenAddr)
	if addr == "" {
		addr = m.GetConfig().ListenAddr
	}
	if addr == "" {
		addr = DefaultListenAddr
	}
	return DockerDeployBundle{
		ListenAddr:    addr,
		Dockerfile:    GenerateDockerfile(addr),
		DockerCompose: GenerateDockerCompose(addr),
	}
}

// SetCallbacks registers optional real-time callbacks invoked on each route
// invocation and on gateway server start/stop transitions.
func (m *Manager) SetCallbacks(onInvoke func(InvocationRecord), onStatus func(GatewayStatus)) {
	m.cbMu.Lock()
	m.onInvoke = onInvoke
	m.onStatus = onStatus
	m.cbMu.Unlock()
}

func (m *Manager) emitInvoke(rec InvocationRecord) {
	m.cbMu.RLock()
	fn := m.onInvoke
	m.cbMu.RUnlock()
	if fn != nil {
		fn(rec)
	}
}

func (m *Manager) emitStatus(st GatewayStatus) {
	m.cbMu.RLock()
	fn := m.onStatus
	m.cbMu.RUnlock()
	if fn != nil {
		fn(st)
	}
}

// Shutdown stops the HTTP server, shuts down all managed signer worker
// processes, cancels background auto-refresh and async webhook dispatchers,
// and closes idle connections across all upstream transports.
func (m *Manager) Shutdown() error {
	if m.lifecycleCancel != nil {
		m.lifecycleCancel()
	}
	m.proxies.StopAutoRefresh()
	if m.workers != nil {
		m.workers.Shutdown()
	}
	err := m.Stop()
	m.webhookWG.Wait()
	m.proxies.CloseIdleConnections()
	if m.transports != nil {
		m.transports.CloseIdleConnections()
	}
	if m.directTransport != nil {
		m.directTransport.CloseIdleConnections()
	}
	return err
}

// ---- Gateway Config ----

// GetConfig returns a copy of the current GatewayConfig.
func (m *Manager) GetConfig() GatewayConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneGatewayConfig(m.cfg)
}

// UpdateConfig hot-updates GatewayConfig and persists it to disk.
func (m *Manager) UpdateConfig(cfg GatewayConfig) error {
	cfg = normalizeGatewayConfig(cfg)
	m.mu.Lock()
	m.cfg = cloneGatewayConfig(cfg)
	m.mu.Unlock()
	m.trimLogs(cfg.MaxLogs)
	return m.persistConfig()
}

func normalizeGatewayConfig(cfg GatewayConfig) GatewayConfig {
	cfg.ListenAddr = strings.TrimSpace(cfg.ListenAddr)
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if cfg.MaxLogs <= 0 {
		cfg.MaxLogs = DefaultMaxLogs
	}
	if cfg.MaxLogs > 10000 {
		cfg.MaxLogs = 10000
	}
	cleanKeys := make([]string, 0, len(cfg.APIKeys))
	for _, k := range cfg.APIKeys {
		if trimmed := strings.TrimSpace(k); trimmed != "" {
			cleanKeys = append(cleanKeys, trimmed)
		}
	}
	cfg.APIKeys = cleanKeys

	cleanCORS := make([]string, 0, len(cfg.CORSOrigins))
	for _, o := range cfg.CORSOrigins {
		if trimmed := strings.TrimSpace(o); trimmed != "" {
			cleanCORS = append(cleanCORS, trimmed)
		}
	}
	cfg.CORSOrigins = cleanCORS
	return cfg
}

// ---- Proxy Pool Management (with persistence) ----

func (m *Manager) GetProxyConfig() ProxyPoolConfig {
	return m.proxies.Config()
}

func (m *Manager) UpdateProxyConfig(cfg ProxyPoolConfig) error {
	m.proxies.SetConfig(cfg)
	return m.persistProxies()
}

func (m *Manager) ListProxies() []ProxyNode {
	return m.proxies.List()
}

func (m *Manager) GetProxy(id string) (*ProxyNode, bool) {
	return m.proxies.Get(id)
}

func (m *Manager) SaveProxy(node ProxyNode) (*ProxyNode, error) {
	saved, err := m.proxies.Upsert(node)
	if err != nil {
		return nil, err
	}
	if err := m.persistProxies(); err != nil {
		return saved, err
	}
	return saved, nil
}

func (m *Manager) DeleteProxy(id string) error {
	if err := m.proxies.Delete(id); err != nil {
		return err
	}
	return m.persistProxies()
}

func (m *Manager) CheckProxy(ctx context.Context, id, checkURL string) (*ProxyNode, error) {
	node, err := m.proxies.CheckNode(ctx, id, checkURL)
	_ = m.persistProxies()
	return node, err
}

func (m *Manager) CheckAllProxies(ctx context.Context, checkURL string) []ProxyNode {
	nodes := m.proxies.CheckAll(ctx, checkURL)
	_ = m.persistProxies()
	return nodes
}

func (m *Manager) FetchProxiesFromProvider(ctx context.Context) (added int, total int, err error) {
	added, total, err = m.proxies.FetchFromProvider(ctx)
	if err == nil {
		_ = m.persistProxies()
	}
	return added, total, err
}

// ---- Device Pool Management (with persistence) ----

func (m *Manager) ListDevices() []DeviceProfile {
	return m.devices.List()
}

func (m *Manager) GetDevice(id string) (*DeviceProfile, bool) {
	return m.devices.Get(id)
}

func (m *Manager) SaveDevice(profile DeviceProfile) (*DeviceProfile, error) {
	saved, err := m.devices.Upsert(profile)
	if err != nil {
		return nil, err
	}
	if err := m.persistDevices(); err != nil {
		return saved, err
	}
	return saved, nil
}

func (m *Manager) DeleteDevice(id string) error {
	if err := m.devices.Delete(id); err != nil {
		return err
	}
	return m.persistDevices()
}

func (m *Manager) CreateDeviceFromPreset(presetID, name string, tags []string) (*DeviceProfile, error) {
	saved, err := m.devices.CreateFromPreset(presetID, name, tags)
	if err != nil {
		return nil, err
	}
	if err := m.persistDevices(); err != nil {
		return saved, err
	}
	return saved, nil
}

func (m *Manager) SyncADBDevices(ctx context.Context) ([]DeviceProfile, error) {
	synced, err := m.devices.SyncADBDevices(ctx)
	if len(synced) > 0 {
		_ = m.persistDevices()
	}
	return synced, err
}

// ---- Account Pool Management (with persistence) ----

func (m *Manager) GetAccountConfig() AccountPoolConfig {
	return m.accounts.Config()
}

func (m *Manager) UpdateAccountConfig(cfg AccountPoolConfig) error {
	return m.accounts.SetConfig(cfg)
}

func (m *Manager) ListAccounts() []AccountProfile {
	return m.accounts.List()
}

func (m *Manager) GetAccount(id string) (*AccountProfile, bool) {
	return m.accounts.Get(id)
}

func (m *Manager) SaveAccount(acc AccountProfile) (*AccountProfile, error) {
	return m.accounts.Upsert(acc)
}

func (m *Manager) DeleteAccount(id string) error {
	return m.accounts.Delete(id)
}

// ---- Managed Signer Worker Pool Management (with persistence) ----

func (m *Manager) ListWorkers() []ManagedWorkerSpec {
	return m.workers.ListSpecs()
}

func (m *Manager) GetWorker(id string) (*ManagedWorkerSpec, bool) {
	return m.workers.GetSpec(id)
}

func (m *Manager) SaveWorker(spec ManagedWorkerSpec) (*ManagedWorkerSpec, error) {
	return m.workers.SaveSpec(spec)
}

func (m *Manager) DeleteWorker(id string) error {
	return m.workers.DeleteSpec(id)
}

func (m *Manager) StartWorker(id string) error {
	return m.workers.StartWorker(id)
}

func (m *Manager) StopWorker(id string) error {
	return m.workers.StopWorker(id)
}

func (m *Manager) RestartWorker(id string) error {
	return m.workers.RestartWorker(id)
}

func (m *Manager) ListWorkerStatuses() []ManagedWorkerStatus {
	return m.workers.ListWorkerStatuses()
}

// ---- Signer Provider CRUD ----

func (m *Manager) ListSigners() []SignerProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SignerProvider, 0, len(m.signers))
	for _, s := range m.signers {
		out = append(out, cloneSignerProvider(s))
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

func (m *Manager) GetSigner(id string) (*SignerProvider, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.signers[strings.TrimSpace(id)]
	if !ok {
		return nil, false
	}
	cp := cloneSignerProvider(s)
	return &cp, true
}

func (m *Manager) SaveSigner(s SignerProvider) (*SignerProvider, error) {
	s.Name = strings.TrimSpace(s.Name)
	s.Kind = strings.ToLower(strings.TrimSpace(s.Kind))
	if err := ValidateSigner(&s); err != nil {
		return nil, err
	}
	s.ID = strings.TrimSpace(s.ID)
	if s.ID == "" {
		s.ID = fmt.Sprintf("signer-%s-%s", sanitizeID(s.Name, "custom"), randomHex(4))
	}
	if s.TimeoutSec <= 0 {
		s.TimeoutSec = DefaultSignerTimeoutSec
	}
	if s.InjectTarget == "" {
		s.InjectTarget = InjectTargetQuery
	}

	m.mu.Lock()
	m.signers[s.ID] = cloneSignerProvider(s)
	m.mu.Unlock()

	cp := cloneSignerProvider(s)
	if err := m.persistSigners(); err != nil {
		return &cp, err
	}
	return &cp, nil
}

func (m *Manager) DeleteSigner(id string) error {
	id = strings.TrimSpace(id)
	m.mu.Lock()
	if _, ok := m.signers[id]; !ok {
		m.mu.Unlock()
		return fmt.Errorf("signer %q not found", id)
	}
	delete(m.signers, id)
	m.mu.Unlock()
	return m.persistSigners()
}

// TestSigner executes a saved SignerProvider by ID against sample input.
func (m *Manager) TestSigner(ctx context.Context, id string, input SignerInput) (*SignerOutput, error) {
	signer, ok := m.GetSigner(id)
	if !ok {
		return nil, fmt.Errorf("signer %q not found", id)
	}
	// Allow testing even if temporarily disabled by cloning with Enabled=true.
	signer.Enabled = true
	return m.signerExec.Execute(ctx, signer, input)
}

// ---- ServiceRoute CRUD & Flow Publishing ----

func (m *Manager) ListRoutes() []ServiceRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ServiceRoute, 0, len(m.routes))
	for _, r := range m.routes {
		out = append(out, cloneServiceRoute(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slug != out[j].Slug {
			return out[i].Slug < out[j].Slug
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (m *Manager) GetRoute(id string) (*ServiceRoute, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.routes[strings.TrimSpace(id)]
	if !ok {
		return nil, false
	}
	cp := cloneServiceRoute(r)
	return &cp, true
}

func (m *Manager) GetRouteBySlug(slug string) (*ServiceRoute, bool) {
	clean := normalizeSlug(slug)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.routes {
		if strings.EqualFold(r.Slug, clean) {
			cp := cloneServiceRoute(r)
			return &cp, true
		}
	}
	return nil, false
}

func (m *Manager) SaveRoute(r ServiceRoute) (*ServiceRoute, error) {
	r.UpstreamURL = strings.TrimSpace(r.UpstreamURL)
	if err := ValidateRouteURLTemplate(r.UpstreamURL); err != nil {
		return nil, err
	}
	r.UpstreamMethod = strings.ToUpper(strings.TrimSpace(r.UpstreamMethod))
	if r.UpstreamMethod == "" {
		r.UpstreamMethod = http.MethodGet
	}
	r.Slug = normalizeSlug(r.Slug)
	if r.Slug == "" {
		r.Slug = normalizeSlug(r.Name)
	}
	if r.Slug == "" {
		return nil, errors.New("route slug is required")
	}
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		r.Name = r.Slug
	}
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		r.ID = fmt.Sprintf("route-%s-%s", sanitizeID(r.Slug, "api"), randomHex(4))
	}
	if r.TimeoutSec <= 0 {
		r.TimeoutSec = DefaultTimeoutSec
	}
	r.DeviceTags = normalizeTags(r.DeviceTags)
	r.ProxyTags = normalizeTags(r.ProxyTags)
	r.AccountTags = normalizeTags(r.AccountTags)
	r.RefreshRouteSlug = normalizeSlug(r.RefreshRouteSlug)
	r.RefreshOnStatuses = normalizeStatusCodes(r.RefreshOnStatuses)
	r.RefreshOnBodySubstr = strings.TrimSpace(r.RefreshOnBodySubstr)
	r.ChallengeWebhookURL = strings.TrimSpace(r.ChallengeWebhookURL)
	if r.ChallengeWebhookURL != "" {
		if _, err := validateWebhookURL(r.ChallengeWebhookURL); err != nil {
			return nil, fmt.Errorf("invalid challenge_webhook_url: %w", err)
		}
	}
	if strings.TrimSpace(r.TLSProfile) != "" {
		normTLS, err := NormalizeTLSProfile(r.TLSProfile)
		if err != nil {
			return nil, err
		}
		r.TLSProfile = normTLS
	}
	r.MTLSCertPath = strings.TrimSpace(r.MTLSCertPath)
	r.MTLSKeyPath = strings.TrimSpace(r.MTLSKeyPath)
	if (r.MTLSCertPath == "") != (r.MTLSKeyPath == "") {
		return nil, errors.New("both mtls_cert_path and mtls_key_path must be specified together")
	}
	r.CacheKeyFields = normalizePreserveCaseList(r.CacheKeyFields)

	now := nowRFC3339()
	var prevSlug string
	m.mu.Lock()
	for id, existing := range m.routes {
		if id != r.ID && strings.EqualFold(existing.Slug, r.Slug) {
			m.mu.Unlock()
			return nil, fmt.Errorf("route slug %q already exists (route %s)", r.Slug, id)
		}
	}
	if prev, exists := m.routes[r.ID]; exists {
		prevSlug = prev.Slug
		if r.CreatedAt == "" {
			r.CreatedAt = prev.CreatedAt
		}
	}
	if r.CreatedAt == "" {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	m.routes[r.ID] = cloneServiceRoute(r)
	m.mu.Unlock()

	if m.cache != nil {
		m.cache.Clear(r.Slug)
		if prevSlug != "" && prevSlug != r.Slug {
			m.cache.Clear(prevSlug)
		}
	}

	cp := cloneServiceRoute(r)
	if err := m.persistRoutes(); err != nil {
		return &cp, err
	}
	return &cp, nil
}

func normalizePreserveCaseList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		clean := strings.TrimSpace(it)
		if clean == "" {
			continue
		}
		if _, dup := seen[clean]; dup {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (m *Manager) DeleteRoute(id string) error {
	id = strings.TrimSpace(id)
	m.mu.Lock()
	route, ok := m.routes[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("route %q not found", id)
	}
	delete(m.routes, id)
	m.mu.Unlock()

	m.rlMu.Lock()
	delete(m.limiters, route.ID)
	m.rlMu.Unlock()

	if m.cache != nil {
		m.cache.Clear(route.Slug)
	}
	if m.circuits != nil {
		m.circuits.Reset(route.Slug)
	}

	return m.persistRoutes()
}

// PublishFlowAsRoute converts a captured cap Flow into an immediately callable
// gateway ServiceRoute, extracting query parameters, clean request headers,
// body template, and source flow lineage.
func (m *Manager) PublishFlowAsRoute(flow *types.Flow, slug, name string) (*ServiceRoute, error) {
	if flow == nil {
		return nil, errors.New("flow is nil")
	}
	rawURL := strings.TrimSpace(flow.URL)
	if rawURL == "" && flow.Host != "" {
		path := flow.Path
		if path != "" && !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		rawURL = "https://" + flow.Host + path
	}
	if rawURL == "" {
		return nil, errors.New("flow has no URL or Host")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse flow URL: %w", err)
	}

	staticQuery := make(map[string]string)
	for k, vals := range parsed.Query() {
		if len(vals) > 0 {
			staticQuery[k] = vals[0]
		} else {
			staticQuery[k] = ""
		}
	}
	parsed.RawQuery = ""
	cleanURL := parsed.String()

	method := strings.ToUpper(strings.TrimSpace(flow.Method))
	if method == "" {
		method = http.MethodGet
	}

	staticHeaders := make(map[string]string)
	for k, v := range flow.ReqHeaders {
		if isHopByHopOrAutoHeader(k) {
			continue
		}
		staticHeaders[k] = v
	}

	derivedSlug := normalizeSlug(slug)
	if derivedSlug == "" {
		pathClean := strings.Trim(parsed.Path, "/")
		if pathClean != "" {
			derivedSlug = normalizeSlug(strings.ReplaceAll(pathClean, "/", "-"))
		} else {
			derivedSlug = normalizeSlug(parsed.Hostname())
		}
		if derivedSlug == "" {
			derivedSlug = "api-" + randomHex(3)
		}
		// Ensure uniqueness if auto-derived slug collides.
		if _, exists := m.GetRouteBySlug(derivedSlug); exists {
			derivedSlug = derivedSlug + "-" + randomHex(2)
		}
	}

	routeName := strings.TrimSpace(name)
	if routeName == "" {
		p := parsed.Path
		if p == "" {
			p = "/"
		}
		routeName = fmt.Sprintf("%s %s", method, p)
	}

	route := ServiceRoute{
		Slug:           derivedSlug,
		Name:           routeName,
		Description:    fmt.Sprintf("Published from captured flow %s (%s %s)", flow.ID, method, parsed.Host+parsed.Path),
		Enabled:        true,
		UpstreamMethod: method,
		UpstreamURL:    cleanURL,
		StaticHeaders:  staticHeaders,
		StaticQuery:    staticQuery,
		BodyTemplate:   string(flow.ReqBody),
		TimeoutSec:     DefaultTimeoutSec,
		SourceFlowID:   flow.ID,
	}
	if len(route.StaticQuery) == 0 {
		route.StaticQuery = nil
	}
	if len(route.StaticHeaders) == 0 {
		route.StaticHeaders = nil
	}
	return m.SaveRoute(route)
}

func normalizeSlug(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "/")
	if s == "" {
		return ""
	}
	return sanitizeID(s, "")
}

func isHopByHopOrAutoHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "host", "content-length", "connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade",
		"accept-encoding":
		return true
	default:
		return false
	}
}

// ---- Invocation Logs & Stats ----

func (m *Manager) recordInvocation(rec InvocationRecord) {
	if rec.ID == "" {
		rec.ID = fmt.Sprintf("inv-%d", m.invSeq.Add(1))
	}
	if rec.Timestamp == "" {
		rec.Timestamp = nowRFC3339()
	}

	m.totalRequests.Add(1)
	m.totalLatencyMs.Add(rec.LatencyMs)
	if rec.OK {
		m.successRequests.Add(1)
	} else {
		m.errorRequests.Add(1)
	}

	maxLogs := m.GetConfig().MaxLogs
	if maxLogs <= 0 {
		maxLogs = DefaultMaxLogs
	}

	m.logMu.Lock()
	m.logs = append(m.logs, rec)
	if len(m.logs) > maxLogs {
		excess := len(m.logs) - maxLogs
		copy(m.logs, m.logs[excess:])
		m.logs = m.logs[:maxLogs]
	}
	m.logMu.Unlock()

	m.emitInvoke(rec)
}

func (m *Manager) trimLogs(maxLogs int) {
	if maxLogs <= 0 {
		maxLogs = DefaultMaxLogs
	}
	m.logMu.Lock()
	if len(m.logs) > maxLogs {
		excess := len(m.logs) - maxLogs
		copy(m.logs, m.logs[excess:])
		m.logs = m.logs[:maxLogs]
	}
	m.logMu.Unlock()
}

// ListLogs returns recorded invocations newest-first. If limit <= 0, all stored
// records are returned.
func (m *Manager) ListLogs(limit int) []InvocationRecord {
	m.logMu.RLock()
	defer m.logMu.RUnlock()
	n := len(m.logs)
	if n == 0 {
		return []InvocationRecord{}
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]InvocationRecord, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, m.logs[i])
	}
	return out
}

// ClearLogs empties the in-memory invocation ring buffer.
func (m *Manager) ClearLogs() {
	m.logMu.Lock()
	m.logs = m.logs[:0]
	m.logMu.Unlock()
}

// Stats returns a live snapshot of gateway traffic and pool counts.
func (m *Manager) Stats() GatewayStats {
	m.srvMu.Lock()
	running := m.running
	addr := m.boundAddr
	startedAt := m.startedAt
	m.srvMu.Unlock()
	if addr == "" {
		addr = m.GetConfig().ListenAddr
	}

	proxyTotal, proxyHealthy := m.proxies.Counts()
	deviceTotal, deviceEnabled := m.devices.Counts()
	totalAccounts, activeAccounts := m.accounts.Counts()
	totalWorkers, healthyWorkers := m.workers.Counts()

	m.mu.RLock()
	signerTotal := len(m.signers)
	routeTotal := len(m.routes)
	routeEnabled := 0
	for _, r := range m.routes {
		if r.Enabled {
			routeEnabled++
		}
	}
	m.mu.RUnlock()

	totalReq := m.totalRequests.Load()
	avgLat := 0.0
	if totalReq > 0 {
		avgLat = float64(m.totalLatencyMs.Load()) / float64(totalReq)
	}

	return GatewayStats{
		Running:         running,
		ListenAddr:      addr,
		StartedAt:       startedAt,
		TotalRequests:   totalReq,
		SuccessRequests: m.successRequests.Load(),
		ErrorRequests:   m.errorRequests.Load(),
		RateLimited:     m.rateLimited.Load(),
		AuthFailures:    m.authFailures.Load(),
		AvgLatencyMs:    avgLat,
		ProxyTotal:      proxyTotal,
		ProxyHealthy:    proxyHealthy,
		DeviceTotal:     deviceTotal,
		DeviceEnabled:   deviceEnabled,
		SignerTotal:     signerTotal,
		RouteTotal:      routeTotal,
		RouteEnabled:    routeEnabled,
		TotalAccounts:   totalAccounts,
		ActiveAccounts:  activeAccounts,
		TotalWorkers:    totalWorkers,
		HealthyWorkers:  healthyWorkers,
		CacheHits:       m.cacheHits.Load(),
		CacheMisses:     m.cacheMisses.Load(),
		OpenCircuits:    m.circuits.OpenCount(),
	}
}

// ---- JSON Persistence ----

func (m *Manager) loadFromDisk() {
	if raw, err := os.ReadFile(filepath.Join(m.dir, fileGatewayConfig)); err == nil {
		var cfg GatewayConfig
		if json.Unmarshal(raw, &cfg) == nil {
			m.cfg = normalizeGatewayConfig(cfg)
		}
	}

	if raw, err := os.ReadFile(filepath.Join(m.dir, fileProxyPool)); err == nil {
		var pp persistedProxyPool
		if json.Unmarshal(raw, &pp) == nil {
			m.proxies.SetConfig(pp.Config)
			m.proxies.LoadNodes(pp.Nodes)
		}
	}

	if raw, err := os.ReadFile(filepath.Join(m.dir, fileDevices)); err == nil {
		var devs []DeviceProfile
		if json.Unmarshal(raw, &devs) == nil {
			m.devices.Load(devs)
		}
	}

	_ = m.accounts.LoadFromDisk()
	_ = m.workers.LoadFromDisk()

	if raw, err := os.ReadFile(filepath.Join(m.dir, fileSigners)); err == nil {
		var list []SignerProvider
		if json.Unmarshal(raw, &list) == nil {
			for _, s := range list {
				if strings.TrimSpace(s.ID) != "" {
					m.signers[s.ID] = cloneSignerProvider(s)
				}
			}
		}
	}

	if raw, err := os.ReadFile(filepath.Join(m.dir, fileRoutes)); err == nil {
		var list []ServiceRoute
		if json.Unmarshal(raw, &list) == nil {
			for _, r := range list {
				if strings.TrimSpace(r.ID) != "" {
					m.routes[r.ID] = cloneServiceRoute(r)
				}
			}
		}
	}
}

func (m *Manager) writeJSONFile(filename string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(m.dir, filename), data, 0o644)
}

func (m *Manager) persistConfig() error {
	return m.writeJSONFile(fileGatewayConfig, m.GetConfig())
}

func (m *Manager) persistProxies() error {
	return m.writeJSONFile(fileProxyPool, persistedProxyPool{
		Config: m.proxies.Config(),
		Nodes:  m.proxies.List(),
	})
}

func (m *Manager) persistDevices() error {
	return m.writeJSONFile(fileDevices, m.devices.List())
}

func (m *Manager) persistSigners() error {
	return m.writeJSONFile(fileSigners, m.ListSigners())
}

func (m *Manager) persistRoutes() error {
	return m.writeJSONFile(fileRoutes, m.ListRoutes())
}
