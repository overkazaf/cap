package wailsgui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/recon"
)

// ==================== Site Recon, Domain/TLS/Subdomain/Port Scanner ====================

func reconToolchainFromSettings(settings map[string]string) recon.ToolchainConfig {
	if settings == nil {
		return recon.ToolchainConfig{}
	}
	return recon.ToolchainConfig{
		NmapPath:      strings.TrimSpace(settings["recon_nmap_path"]),
		SubfinderPath: strings.TrimSpace(settings["recon_subfinder_path"]),
		WhoisPath:     strings.TrimSpace(settings["recon_whois_path"]),
		DigPath:       strings.TrimSpace(settings["recon_dig_path"]),
	}
}

func isReconToolchainSettingKey(key string) bool {
	return strings.HasPrefix(key, "recon_")
}

func (a *App) appBaseContext() context.Context {
	if a.ctx != nil {
		return a.ctx
	}
	return context.Background()
}

func (a *App) ensureReconManager() (*recon.Manager, error) {
	a.mu.Lock()
	mgr := a.reconMgr
	capDir := a.certDir
	tcCfg := reconToolchainFromSettings(a.settings)
	a.mu.Unlock()

	if mgr != nil {
		return mgr, nil
	}
	created, err := recon.NewManager(capDir)
	if err != nil {
		return nil, err
	}
	created.SetToolchainConfig(tcCfg)
	if a.events != nil {
		created.SetCallbacks(
			func(ev recon.ReconJobEvent) {
				a.events.Emit(EventReconLog, ev)
			},
			func(st *recon.ReconJobState) {
				a.events.Emit(EventReconStatus, st)
			},
		)
	}
	a.mu.Lock()
	if a.reconMgr == nil {
		a.reconMgr = created
	}
	mgr = a.reconMgr
	a.mu.Unlock()
	return mgr, nil
}

// GetReconToolchain inspects host nmap, subfinder, whois, and dig availability.
func (a *App) GetReconToolchain(forceRefresh bool) recon.ToolchainInfo {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return recon.ToolchainInfo{
			Issues: []string{err.Error()},
		}
	}
	return mgr.GetToolchain(forceRefresh)
}

// UpdateReconToolchainConfig persists custom recon binary paths and re-probes immediately.
func (a *App) UpdateReconToolchainConfig(cfg recon.ToolchainConfig) (recon.ToolchainInfo, error) {
	trimmed := recon.ToolchainConfig{
		NmapPath:      strings.TrimSpace(cfg.NmapPath),
		SubfinderPath: strings.TrimSpace(cfg.SubfinderPath),
		WhoisPath:     strings.TrimSpace(cfg.WhoisPath),
		DigPath:       strings.TrimSpace(cfg.DigPath),
	}
	updates := map[string]string{
		"recon_nmap_path":      trimmed.NmapPath,
		"recon_subfinder_path": trimmed.SubfinderPath,
		"recon_whois_path":     trimmed.WhoisPath,
		"recon_dig_path":       trimmed.DigPath,
	}
	for k, v := range updates {
		if err := a.SetSetting(k, v); err != nil {
			return recon.ToolchainInfo{}, err
		}
	}
	mgr, err := a.ensureReconManager()
	if err != nil {
		return recon.ToolchainInfo{}, err
	}
	mgr.SetToolchainConfig(trimmed)
	return mgr.GetToolchain(true), nil
}

// AnalyzeReconDomain runs synchronous domain intelligence (DNS, WHOIS, CDN/WAF, TLS) with a 60s timeout.
func (a *App) AnalyzeReconDomain(target string) (*recon.DomainReport, error) {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(a.appBaseContext(), 60*time.Second)
	defer cancel()
	return mgr.AnalyzeDomain(ctx, target)
}

// ProbeReconSite runs HTTP fingerprinting, security header audit, and site discovery with a 45s timeout.
func (a *App) ProbeReconSite(rawURL string, opts recon.SiteProbeOptions) (*recon.SiteProfile, error) {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(a.appBaseContext(), 45*time.Second)
	defer cancel()
	return mgr.ProbeSite(ctx, rawURL, opts)
}

// InspectReconTLS inspects live TLS handshake negotiation and peer certificates with a 20s timeout.
func (a *App) InspectReconTLS(host string, port int) (*recon.TLSInspectReport, error) {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(a.appBaseContext(), 20*time.Second)
	defer cancel()
	return mgr.InspectTLS(ctx, host, port)
}

// EnumerateReconSubdomains runs multi-source subdomain enumeration with a 90s timeout.
func (a *App) EnumerateReconSubdomains(req recon.SubdomainRequest) (*recon.SubdomainReport, error) {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(a.appBaseContext(), 90*time.Second)
	defer cancel()
	return mgr.EnumerateSubdomains(ctx, req)
}

// StartReconJob launches an asynchronous cancellable recon job.
func (a *App) StartReconJob(req recon.ReconJobRequest) (*recon.ReconJobState, error) {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return nil, err
	}
	return mgr.StartScanJob(req)
}

// CancelReconJob terminates any currently running asynchronous recon job.
func (a *App) CancelReconJob() error {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return err
	}
	return mgr.CancelJob()
}

// GetReconJobState returns a snapshot of the active or most recent recon job.
func (a *App) GetReconJobState() *recon.ReconJobState {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return &recon.ReconJobState{
			Status: recon.StatusIdle,
			Events: []recon.ReconJobEvent{},
		}
	}
	return mgr.GetJobState()
}

// ClearReconJobLogs clears logged events on the current recon job snapshot.
func (a *App) ClearReconJobLogs() {
	if mgr, err := a.ensureReconManager(); err == nil {
		mgr.ClearJobLogs()
	}
}

// ListReconHistory returns persisted recon history entries sorted newest-first.
func (a *App) ListReconHistory() []recon.ReconHistoryEntry {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return []recon.ReconHistoryEntry{}
	}
	return mgr.ListHistory()
}

// GetReconHistory fetches a single persisted recon history entry by ID.
func (a *App) GetReconHistory(id string) (*recon.ReconHistoryEntry, error) {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return nil, err
	}
	entry, ok := mgr.GetHistory(id)
	if !ok {
		return nil, fmt.Errorf("recon history entry %q not found", id)
	}
	return entry, nil
}

// DeleteReconHistory removes a single persisted recon history entry by ID.
func (a *App) DeleteReconHistory(id string) error {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return err
	}
	return mgr.DeleteHistory(id)
}

// ClearReconHistory removes all persisted recon history entries.
func (a *App) ClearReconHistory() error {
	mgr, err := a.ensureReconManager()
	if err != nil {
		return err
	}
	return mgr.ClearHistory()
}
