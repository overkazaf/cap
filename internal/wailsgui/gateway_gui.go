package wailsgui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/overkazaf/cap/internal/gateway"
)

// ==================== Open API Gateway ====================

func (a *App) ensureGatewayManager() (*gateway.Manager, error) {
	a.mu.Lock()
	mgr := a.gatewayMgr
	capDir := a.certDir
	a.mu.Unlock()

	if mgr != nil {
		return mgr, nil
	}
	created, err := gateway.NewManager(capDir)
	if err != nil {
		return nil, err
	}
	if a.events != nil {
		created.SetCallbacks(
			func(rec gateway.InvocationRecord) {
				a.events.Emit(EventGatewayInvoke, rec)
			},
			func(st gateway.GatewayStatus) {
				a.events.Emit(EventGatewayStatus, st)
			},
		)
	}
	a.mu.Lock()
	if a.gatewayMgr == nil {
		a.gatewayMgr = created
	}
	mgr = a.gatewayMgr
	a.mu.Unlock()
	return mgr, nil
}

// GetGatewayStatus returns live gateway server state, traffic telemetry, and pool counts.
func (a *App) GetGatewayStatus() gateway.GatewayStats {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return gateway.GatewayStats{}
	}
	return mgr.Stats()
}

// GetGatewayConfig returns the current Open API Gateway runtime configuration.
func (a *App) GetGatewayConfig() gateway.GatewayConfig {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return gateway.GatewayConfig{ListenAddr: gateway.DefaultListenAddr}
	}
	return mgr.GetConfig()
}

// UpdateGatewayConfig persists updated Open API Gateway settings.
func (a *App) UpdateGatewayConfig(cfg gateway.GatewayConfig) (gateway.GatewayConfig, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return gateway.GatewayConfig{}, err
	}
	if err := mgr.UpdateConfig(cfg); err != nil {
		return mgr.GetConfig(), err
	}
	updated := mgr.GetConfig()
	if updated.ListenAddr != "" {
		a.mu.Lock()
		if a.settings == nil {
			a.settings = make(map[string]string)
		}
		a.settings["gateway_addr"] = updated.ListenAddr
		certDir := a.certDir
		snapshot := make(map[string]string, len(a.settings))
		for k, v := range a.settings {
			snapshot[k] = v
		}
		a.mu.Unlock()
		if certDir != "" {
			_ = saveSettings(filepath.Join(certDir, "settings.json"), snapshot)
		}
	}
	return updated, nil
}

// StartGateway starts the embedded Open API Gateway HTTP server on listenAddr
// (defaulting to configured listen address if empty).
func (a *App) StartGateway(listenAddr string) (gateway.GatewayStats, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return gateway.GatewayStats{}, err
	}
	addr := strings.TrimSpace(listenAddr)
	if addr == "" {
		addr = strings.TrimSpace(mgr.GetConfig().ListenAddr)
	}
	if addr == "" {
		addr = strings.TrimSpace(a.GetSetting("gateway_addr"))
	}
	if err := mgr.Start(addr); err != nil {
		return mgr.Stats(), err
	}
	return mgr.Stats(), nil
}

// StopGateway gracefully stops the embedded Open API Gateway HTTP server.
func (a *App) StopGateway() (gateway.GatewayStats, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return gateway.GatewayStats{}, err
	}
	stopErr := mgr.Stop()
	return mgr.Stats(), stopErr
}

// GetGatewayOpenAPI returns the pretty-printed OpenAPI 3.0.3 JSON spec for enabled routes.
func (a *App) GetGatewayOpenAPI() (string, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return "", err
	}
	raw, err := mgr.OpenAPISpecJSON()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ==================== Proxy IP Pool ====================

// ListGatewayProxies returns all configured proxy pool nodes.
func (a *App) ListGatewayProxies() []gateway.ProxyNode {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.ProxyNode{}
	}
	return mgr.ListProxies()
}

// GetProxyPoolConfig returns the current proxy pool rotation and provider config.
func (a *App) GetProxyPoolConfig() gateway.ProxyPoolConfig {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return gateway.ProxyPoolConfig{Strategy: gateway.StrategyRoundRobin}
	}
	return mgr.GetProxyConfig()
}

// UpdateProxyPoolConfig updates and persists proxy pool configuration.
func (a *App) UpdateProxyPoolConfig(cfg gateway.ProxyPoolConfig) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.UpdateProxyConfig(cfg)
}

// SaveGatewayProxy creates or updates a proxy node in the pool.
func (a *App) SaveGatewayProxy(node gateway.ProxyNode) (*gateway.ProxyNode, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.SaveProxy(node)
}

// BulkImportGatewayProxies parses newline/comma/semicolon-separated proxy lines,
// applies optional defaultScheme, region, and tags, and saves them into the proxy pool.
func (a *App) BulkImportGatewayProxies(rawLines, defaultScheme, region string, tags []string) (int, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return 0, err
	}
	scheme := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(defaultScheme), "://"))
	if scheme != "" {
		switch scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return 0, fmt.Errorf("unsupported default proxy scheme %q (expected http, https, socks5, or socks5h)", defaultScheme)
		}
	}
	region = strings.TrimSpace(region)

	// Parse token-by-token so we know whether each entry explicitly specified a scheme.
	lines := strings.FieldsFunc(rawLines, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	imported := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		var entries []string
		if strings.Contains(line, "://") {
			entries = []string{line}
		} else {
			entries = strings.FieldsFunc(line, func(r rune) bool {
				return r == ',' || r == ';'
			})
		}
		for _, entry := range entries {
			tok := strings.TrimSpace(entry)
			if tok == "" {
				continue
			}
			parsed := gateway.ParseProxyLines(tok)
			for _, node := range parsed {
				if scheme != "" && !strings.Contains(tok, "://") && strings.HasPrefix(node.URL, "http://") {
					node.URL = scheme + "://" + strings.TrimPrefix(node.URL, "http://")
				}
				if region != "" && node.Region == "" {
					node.Region = region
				}
				if len(tags) > 0 {
					node.Tags = append(node.Tags, tags...)
				}
				node.Enabled = true
				if _, saveErr := mgr.SaveProxy(node); saveErr != nil {
					return imported, saveErr
				}
				imported++
			}
		}
	}
	return imported, nil
}

// DeleteGatewayProxy deletes a proxy node from the pool by ID.
func (a *App) DeleteGatewayProxy(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.DeleteProxy(id)
}

// CheckGatewayProxies probes all enabled proxies concurrently and returns updated node states.
func (a *App) CheckGatewayProxies() []gateway.ProxyNode {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.ProxyNode{}
	}
	return mgr.CheckAllProxies(context.Background(), "")
}

// FetchGatewayProxiesFromProvider fetches proxy nodes from an external HTTP provider API
// and persists them into the pool, returning the number of newly added proxies.
func (a *App) FetchGatewayProxiesFromProvider(providerURL, format, jsonPath string) (int, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return 0, err
	}
	providerURL = strings.TrimSpace(providerURL)
	format = strings.TrimSpace(format)
	jsonPath = strings.TrimSpace(jsonPath)
	if providerURL != "" {
		added, _, err := mgr.ProxyPool().FetchFromProviderURL(context.Background(), providerURL, format, jsonPath)
		if err != nil {
			return 0, err
		}
		cfg := mgr.GetProxyConfig()
		cfg.ProviderURL = providerURL
		cfg.ProviderFormat = format
		cfg.ProviderJSONPath = jsonPath
		_ = mgr.UpdateProxyConfig(cfg)
		return added, nil
	}
	added, _, err := mgr.FetchProxiesFromProvider(context.Background())
	return added, err
}

// ==================== Device Pool ====================

// ListGatewayDevices returns all virtual and physical device profiles.
func (a *App) ListGatewayDevices() []gateway.DeviceProfile {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.DeviceProfile{}
	}
	return mgr.ListDevices()
}

// ListGatewayDevicePresets returns curated virtual Android device presets.
func (a *App) ListGatewayDevicePresets() []gateway.DevicePreset {
	return gateway.BuiltinDevicePresets()
}

// CreateGatewayDeviceFromPreset instantiates and persists a virtual device from presetID.
func (a *App) CreateGatewayDeviceFromPreset(presetID, customName string) (*gateway.DeviceProfile, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.CreateDeviceFromPreset(presetID, customName, nil)
}

// SyncGatewayADBDevices discovers connected physical ADB devices and upserts them into the pool.
func (a *App) SyncGatewayADBDevices() ([]gateway.DeviceProfile, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.SyncADBDevices(context.Background())
}

// SaveGatewayDevice creates or updates a device profile.
func (a *App) SaveGatewayDevice(dev gateway.DeviceProfile) (*gateway.DeviceProfile, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.SaveDevice(dev)
}

// DeleteGatewayDevice removes a device profile by ID.
func (a *App) DeleteGatewayDevice(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.DeleteDevice(id)
}

// ==================== Signer Providers ====================

// ListGatewaySigners returns all configured signer providers.
func (a *App) ListGatewaySigners() []gateway.SignerProvider {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.SignerProvider{}
	}
	return mgr.ListSigners()
}

// SaveGatewaySigner validates and persists a signer provider.
func (a *App) SaveGatewaySigner(s gateway.SignerProvider) (*gateway.SignerProvider, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.SaveSigner(s)
}

// DeleteGatewaySigner removes a signer provider by ID.
func (a *App) DeleteGatewaySigner(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.DeleteSigner(id)
}

// TestGatewaySigner validates and executes a signer provider (including unsaved/disabled drafts)
// against sampleInput.
func (a *App) TestGatewaySigner(s gateway.SignerProvider, sampleInput gateway.SignerInput) (*gateway.SignerOutput, error) {
	if err := gateway.ValidateSigner(&s); err != nil {
		return nil, err
	}
	s.Enabled = true
	if mgr, err := a.ensureGatewayManager(); err == nil && mgr.SignerExecutor() != nil {
		return mgr.SignerExecutor().Execute(context.Background(), &s, sampleInput)
	}
	return gateway.ExecuteSigner(context.Background(), &s, sampleInput)
}

// ==================== Service Routes & Telemetry ====================

// ListGatewayRoutes returns all configured service routes.
func (a *App) ListGatewayRoutes() []gateway.ServiceRoute {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.ServiceRoute{}
	}
	return mgr.ListRoutes()
}

// SaveGatewayRoute validates and persists a service route.
func (a *App) SaveGatewayRoute(r gateway.ServiceRoute) (*gateway.ServiceRoute, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.SaveRoute(r)
}

// DeleteGatewayRoute removes a service route by ID.
func (a *App) DeleteGatewayRoute(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.DeleteRoute(id)
}

// PublishFlowToGateway loads a captured flow from the store and publishes it as a ServiceRoute.
func (a *App) PublishFlowToGateway(flowID, slug, name string) (*gateway.ServiceRoute, error) {
	if a.store == nil {
		return nil, fmt.Errorf("flow store unavailable")
	}
	flowID = strings.TrimSpace(flowID)
	if flowID == "" {
		return nil, fmt.Errorf("flow ID is required")
	}
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.PublishFlowAsRoute(f, slug, name)
}

// TestGatewayRoute invokes a published route directly in-process and returns its envelope.
func (a *App) TestGatewayRoute(slug string, req gateway.TestInvokeRequest) (*gateway.TestInvokeResult, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.InvokeRoute(context.Background(), slug, req)
}

// ListGatewayLogs returns recent gateway invocation records newest-first.
func (a *App) ListGatewayLogs(limit int) []gateway.InvocationRecord {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.InvocationRecord{}
	}
	return mgr.ListLogs(limit)
}

// ClearGatewayLogs clears the in-memory gateway invocation log buffer.
func (a *App) ClearGatewayLogs() {
	if mgr, err := a.ensureGatewayManager(); err == nil {
		mgr.ClearLogs()
	}
}

// ==================== Account / Session Pool ====================

// ListGatewayAccounts returns all configured account profiles in the gateway Account Pool.
func (a *App) ListGatewayAccounts() []gateway.AccountProfile {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.AccountProfile{}
	}
	return mgr.ListAccounts()
}

// SaveGatewayAccount validates, normalizes, and persists an AccountProfile.
func (a *App) SaveGatewayAccount(acc gateway.AccountProfile) (*gateway.AccountProfile, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.SaveAccount(acc)
}

// DeleteGatewayAccount removes an AccountProfile by ID.
func (a *App) DeleteGatewayAccount(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.DeleteAccount(id)
}

// GetAccountPoolConfig returns the current AccountPoolConfig.
func (a *App) GetAccountPoolConfig() gateway.AccountPoolConfig {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return gateway.AccountPoolConfig{Strategy: gateway.StrategyRoundRobin}
	}
	return mgr.GetAccountConfig()
}

// UpdateAccountPoolConfig updates and persists AccountPoolConfig.
func (a *App) UpdateAccountPoolConfig(cfg gateway.AccountPoolConfig) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.UpdateAccountConfig(cfg)
}

// MarkGatewayAccountHealthy marks an account profile active and clears prior errors/expiry.
func (a *App) MarkGatewayAccountHealthy(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.AccountPool().MarkHealthy(id)
}

// ==================== Managed Signer Worker Pool ====================

// ListGatewayWorkers returns all configured ManagedWorkerSpecs.
func (a *App) ListGatewayWorkers() []gateway.ManagedWorkerSpec {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.ManagedWorkerSpec{}
	}
	return mgr.ListWorkers()
}

// ListGatewayWorkerStatuses returns live runtime health snapshots for all worker pools.
func (a *App) ListGatewayWorkerStatuses() []gateway.ManagedWorkerStatus {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return []gateway.ManagedWorkerStatus{}
	}
	return mgr.ListWorkerStatuses()
}

// SaveGatewayWorker validates and persists a ManagedWorkerSpec.
func (a *App) SaveGatewayWorker(spec gateway.ManagedWorkerSpec) (*gateway.ManagedWorkerSpec, error) {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return nil, err
	}
	return mgr.SaveWorker(spec)
}

// DeleteGatewayWorker stops and deletes a ManagedWorkerSpec by ID.
func (a *App) DeleteGatewayWorker(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.DeleteWorker(id)
}

// StartGatewayWorker spawns all configured instances for worker ID.
func (a *App) StartGatewayWorker(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.StartWorker(id)
}

// StopGatewayWorker cleanly stops all running instances for worker ID.
func (a *App) StopGatewayWorker(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.StopWorker(id)
}

// RestartGatewayWorker stops and restarts worker ID with its latest spec.
func (a *App) RestartGatewayWorker(id string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	return mgr.RestartWorker(id)
}

// ==================== Resilience, Prometheus & Docker Export ====================

// GetGatewayCircuitStates returns live per-route circuit breaker snapshots.
func (a *App) GetGatewayCircuitStates() map[string]gateway.CircuitSnapshot {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return map[string]gateway.CircuitSnapshot{}
	}
	return mgr.CircuitStates()
}

// ResetGatewayCircuit resets circuit breaker state for slug (or all routes if empty).
func (a *App) ResetGatewayCircuit(slug string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	mgr.ResetCircuit(slug)
	return nil
}

// ClearGatewayRouteCache evicts cached responses for slug (or all routes if empty).
func (a *App) ClearGatewayRouteCache(slug string) error {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return err
	}
	mgr.ClearRouteCache(slug)
	return nil
}

// GetGatewayPrometheusMetrics renders gateway telemetry in Prometheus text exposition format.
func (a *App) GetGatewayPrometheusMetrics() string {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		return ""
	}
	return mgr.PrometheusMetrics()
}

// ExportGatewayDockerBundle generates Dockerfile and docker-compose.yml artifacts for
// headless `cap gateway serve` deployment.
func (a *App) ExportGatewayDockerBundle(listenAddr string) gateway.DockerDeployBundle {
	mgr, err := a.ensureGatewayManager()
	if err != nil {
		addr := strings.TrimSpace(listenAddr)
		if addr == "" {
			addr = gateway.DefaultListenAddr
		}
		return gateway.DockerDeployBundle{
			ListenAddr:    addr,
			Dockerfile:    gateway.GenerateDockerfile(addr),
			DockerCompose: gateway.GenerateDockerCompose(addr),
		}
	}
	return mgr.ExportDockerBundle(listenAddr)
}
