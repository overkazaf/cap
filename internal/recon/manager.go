package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/fsutil"
)

var historyIDSafeRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

type activeReconJob struct {
	id        string
	kind      string
	ctx       context.Context
	cancel    context.CancelFunc
	cancelled atomic.Bool
	doneCh    chan struct{}
}

// Manager coordinates host recon toolchain caching, synchronous recon APIs,
// async cancellable scan jobs with live progress callbacks, and persistent
// scan history stored under ~/.cap/recon-history/*.json.
type Manager struct {
	capDir     string
	historyDir string

	tcMu   sync.RWMutex
	tcCfg  ToolchainConfig
	tcInfo *ToolchainInfo
	tcGen  uint64

	histMu sync.Mutex

	jobOpMu  sync.Mutex
	mu       sync.Mutex
	active   *activeReconJob
	state    *ReconJobState
	seq      atomic.Int64
	onLog    func(ReconJobEvent)
	onStatus func(*ReconJobState)
}

// NewManager creates a recon Manager backed by capDir (defaulting to ~/.cap).
func NewManager(capDir string) (*Manager, error) {
	if strings.TrimSpace(capDir) == "" {
		capDir = config.DefaultDir()
	}
	histDir := filepath.Join(capDir, "recon-history")
	_ = os.MkdirAll(histDir, 0755)
	return &Manager{
		capDir:     capDir,
		historyDir: histDir,
		state: &ReconJobState{
			Status: StatusIdle,
			Events: []ReconJobEvent{},
		},
	}, nil
}

// HistoryDir returns the directory used to persist recon history JSON files.
func (m *Manager) HistoryDir() string {
	return m.historyDir
}

// SetCallbacks installs optional live log and status listeners (used by Wails GUI / CLI).
func (m *Manager) SetCallbacks(onLog func(ReconJobEvent), onStatus func(*ReconJobState)) {
	m.mu.Lock()
	m.onLog = onLog
	m.onStatus = onStatus
	m.mu.Unlock()
}

// SetToolchainConfig updates custom binary paths and invalidates the cached probe.
func (m *Manager) SetToolchainConfig(cfg ToolchainConfig) {
	m.tcMu.Lock()
	m.tcCfg = cfg
	m.tcInfo = nil
	m.tcGen++
	m.tcMu.Unlock()
}

// GetToolchainConfig returns the currently configured custom toolchain paths.
func (m *Manager) GetToolchainConfig() ToolchainConfig {
	m.tcMu.RLock()
	defer m.tcMu.RUnlock()
	return m.tcCfg
}

// GetToolchain returns host toolchain readiness, re-probing when forceRefresh is true.
func (m *Manager) GetToolchain(forceRefresh bool) ToolchainInfo {
	m.tcMu.RLock()
	cached := m.tcInfo
	cfg := m.tcCfg
	gen := m.tcGen
	m.tcMu.RUnlock()
	if cached != nil && !forceRefresh {
		return *cached
	}
	info := DetectToolchain(cfg)
	m.tcMu.Lock()
	if m.tcGen == gen {
		m.tcInfo = &info
	}
	m.tcMu.Unlock()
	return info
}

// --- Synchronous Convenience Entrypoints -----------------------------------

// AnalyzeDomain runs domain analysis using the manager's toolchain configuration.
func (m *Manager) AnalyzeDomain(ctx context.Context, target string) (*DomainReport, error) {
	return AnalyzeDomain(ctx, target, m.GetToolchainConfig())
}

// InspectTLS inspects live TLS handshake & certificate chain for host:port.
func (m *Manager) InspectTLS(ctx context.Context, host string, port int) (*TLSInspectReport, error) {
	return InspectTLS(ctx, host, port)
}

// ProbeSite runs HTTP fingerprinting, security header audit, and site discovery.
func (m *Manager) ProbeSite(ctx context.Context, rawURL string, opts SiteProbeOptions) (*SiteProfile, error) {
	return ProbeSite(ctx, rawURL, opts)
}

// EnumerateSubdomains runs subdomain discovery using the manager's toolchain configuration.
func (m *Manager) EnumerateSubdomains(ctx context.Context, req SubdomainRequest) (*SubdomainReport, error) {
	return EnumerateSubdomains(ctx, req, m.GetToolchainConfig())
}

// RunPortScan runs a port scan using the manager's toolchain configuration.
func (m *Manager) RunPortScan(ctx context.Context, req PortScanRequest, onProgress func(string)) (*PortScanResult, error) {
	return RunPortScan(ctx, req, m.GetToolchainConfig(), onProgress)
}

// --- Async Cancellable Job Execution ---------------------------------------

// GetJobState returns a thread-safe deep snapshot of the current or most recent recon job.
func (m *Manager) GetJobState() *ReconJobState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneJobState(m.state)
}

// ClearJobLogs clears recorded log events on the current job snapshot.
func (m *Manager) ClearJobLogs() {
	m.mu.Lock()
	if m.state != nil {
		m.state.Events = []ReconJobEvent{}
		m.state.EventCount = 0
	}
	snap := cloneJobState(m.state)
	onStatus := m.onStatus
	m.mu.Unlock()
	if onStatus != nil {
		onStatus(snap)
	}
}

// StartScanJob launches an asynchronous, cancellable recon job (domain, site,
// subdomain, or portscan). Any currently running job is cleanly cancelled first.
func (m *Manager) StartScanJob(req ReconJobRequest) (*ReconJobState, error) {
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	target, err := validateJobRequest(kind, &req)
	if err != nil {
		return nil, err
	}
	req.Kind = kind
	req.Target = target

	m.jobOpMu.Lock()
	defer m.jobOpMu.Unlock()

	m.cancelJobLocked()

	var ctx context.Context
	var cancel context.CancelFunc
	if req.TimeoutSec > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(req.TimeoutSec)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	jobID := fmt.Sprintf("recon-%d-%d", time.Now().UnixNano(), m.seq.Add(1))
	startedAt := time.Now().UnixMilli()
	job := &activeReconJob{
		id:     jobID,
		kind:   kind,
		ctx:    ctx,
		cancel: cancel,
		doneCh: make(chan struct{}),
	}

	m.mu.Lock()
	m.active = job
	m.state = &ReconJobState{
		ID:          jobID,
		Kind:        kind,
		Target:      target,
		Status:      StatusRunning,
		Running:     true,
		StartedAtMs: startedAt,
		Events:      make([]ReconJobEvent, 0, 32),
	}
	snap := cloneJobState(m.state)
	onStatus := m.onStatus
	m.mu.Unlock()

	if onStatus != nil {
		onStatus(snap)
	}
	m.appendLog(jobID, kind, "system", fmt.Sprintf("Starting %s recon job for %s", kind, target))

	go m.runScanJob(job, req)
	return snap, nil
}

func validateJobRequest(kind string, req *ReconJobRequest) (string, error) {
	switch kind {
	case JobKindDomain:
		host, _, err := NormalizeDomainTarget(req.Target)
		if err != nil {
			return "", err
		}
		return host, nil
	case JobKindSite:
		u, _, err := NormalizeSiteURL(req.Target)
		if err != nil {
			return "", err
		}
		return u, nil
	case JobKindSubdomain:
		subReq := SubdomainRequest{Domain: req.Target}
		if req.Subdomain != nil {
			subReq = *req.Subdomain
			if strings.TrimSpace(subReq.Domain) == "" {
				subReq.Domain = req.Target
			}
		}
		dom, _, err := NormalizeDomainTarget(subReq.Domain)
		if err != nil {
			return "", err
		}
		if net.ParseIP(dom) != nil {
			return "", fmt.Errorf("recon: subdomain job requires a domain name, got IP %q", dom)
		}
		if !strings.Contains(dom, ".") {
			return "", fmt.Errorf("recon: subdomain job requires a domain name, got %q", dom)
		}
		subReq.Domain = dom
		req.Subdomain = &subReq
		return dom, nil
	case JobKindPortScan:
		psReq := PortScanRequest{Target: req.Target}
		if req.PortScan != nil {
			psReq = *req.PortScan
			if strings.TrimSpace(psReq.Target) == "" {
				psReq.Target = req.Target
			}
		}
		t, err := ValidateScanTarget(psReq.Target)
		if err != nil {
			return "", err
		}
		if strings.EqualFold(strings.TrimSpace(psReq.Preset), PresetCustom) || (strings.TrimSpace(psReq.Preset) == "" && strings.TrimSpace(psReq.PortsSpec) != "") {
			if _, pErr := ParsePortSpec(psReq.PortsSpec); pErr != nil {
				return "", pErr
			}
		}
		psReq.Target = t
		req.PortScan = &psReq
		return t, nil
	default:
		return "", fmt.Errorf("recon: unsupported scan job kind %q (expected domain, site, subdomain, or portscan)", kind)
	}
}

func (m *Manager) runScanJob(job *activeReconJob, req ReconJobRequest) {
	defer func() {
		job.cancel()
		close(job.doneCh)
	}()

	cfg := m.GetToolchainConfig()
	started := time.Now()
	onProgress := func(msg string) {
		m.appendLog(job.id, req.Kind, "progress", msg)
	}

	var (
		domRep  *DomainReport
		sitePro *SiteProfile
		subRep  *SubdomainReport
		psRes   *PortScanResult
		cmdStr  string
		summary string
		runErr  error
	)

	switch req.Kind {
	case JobKindDomain:
		onProgress("Resolving DNS, WHOIS, CDN/WAF, and TLS for " + req.Target)
		domRep, runErr = AnalyzeDomain(job.ctx, req.Target, cfg)
		if domRep != nil {
			summary = fmt.Sprintf("IPv4:%d IPv6:%d CDN:%d", len(domRep.IPv4), len(domRep.IPv6), len(domRep.CDNProviders))
		}
	case JobKindSite:
		opts := SiteProbeOptions{}
		if req.SiteOptions != nil {
			opts = *req.SiteOptions
		}
		onProgress("Probing site headers, technologies, and discovery endpoints for " + req.Target)
		sitePro, runErr = ProbeSite(job.ctx, req.Target, opts)
		if sitePro != nil {
			summary = fmt.Sprintf("HTTP %d · %d tech · score %d/100", sitePro.StatusCode, len(sitePro.Technologies), sitePro.SecurityScore)
		}
	case JobKindSubdomain:
		subReq := *req.Subdomain
		subRep, runErr = EnumerateSubdomainsWithProgress(job.ctx, subReq, cfg, onProgress)
		if subRep != nil {
			summary = fmt.Sprintf("%d subdomain(s) via %s", subRep.TotalCount, strings.Join(subRep.SourcesUsed, ","))
		}
	case JobKindPortScan:
		psReq := *req.PortScan
		psRes, runErr = RunPortScan(job.ctx, psReq, cfg, onProgress)
		if psRes != nil {
			cmdStr = psRes.Command
			summary = fmt.Sprintf("%s · %d open / %d scanned", psRes.Engine, psRes.OpenCount, psRes.TotalScanned)
		}
	}

	elapsedMs := time.Since(started).Milliseconds()
	finishedAt := time.Now().UnixMilli()

	status := StatusDone
	errStr := ""
	if job.cancelled.Load() || errors.Is(job.ctx.Err(), context.Canceled) {
		status = StatusCancelled
		errStr = "scan cancelled"
	} else if runErr != nil {
		status = StatusError
		errStr = runErr.Error()
	}

	// Persist completed job history unless explicitly disabled.
	saveHist := req.SaveHistory == nil || *req.SaveHistory
	historyID := ""
	if saveHist && status == StatusDone {
		entry := ReconHistoryEntry{
			ID:              job.id,
			Kind:            req.Kind,
			Target:          req.Target,
			Summary:         summary,
			Status:          status,
			ElapsedMs:       elapsedMs,
			CreatedAt:       nowHistoryTimestamp(),
			DomainReport:    domRep,
			SiteProfile:     sitePro,
			SubdomainReport: subRep,
			PortScanResult:  psRes,
		}
		if saved, sErr := m.SaveHistory(entry); sErr == nil && saved != nil {
			historyID = saved.ID
		}
	}

	switch status {
	case StatusDone:
		m.appendLog(job.id, req.Kind, "result", fmt.Sprintf("Completed %s recon (%s) in %dms", req.Kind, summary, elapsedMs))
	case StatusCancelled:
		m.appendLog(job.id, req.Kind, "warn", "Recon job cancelled")
	case StatusError:
		m.appendLog(job.id, req.Kind, "error", "Recon job failed: "+errStr)
	}

	m.mu.Lock()
	if m.state != nil && m.state.ID == job.id {
		m.state.Status = status
		m.state.Running = false
		m.state.Command = cmdStr
		m.state.FinishedAtMs = finishedAt
		m.state.ElapsedMs = elapsedMs
		m.state.Error = errStr
		m.state.HistoryID = historyID
		m.state.DomainReport = domRep
		m.state.SiteProfile = sitePro
		m.state.SubdomainReport = subRep
		m.state.PortScanResult = psRes
	}
	if m.active == job {
		m.active = nil
	}
	snap := cloneJobState(m.state)
	onStatus := m.onStatus
	m.mu.Unlock()

	if onStatus != nil {
		onStatus(snap)
	}
}

// CancelJob terminates any active recon job and its child process group.
func (m *Manager) CancelJob() error {
	m.jobOpMu.Lock()
	defer m.jobOpMu.Unlock()
	m.cancelJobLocked()
	return nil
}

func (m *Manager) cancelJobLocked() {
	m.mu.Lock()
	job := m.active
	m.mu.Unlock()
	if job == nil {
		return
	}
	job.cancelled.Store(true)
	job.cancel()
	select {
	case <-job.doneCh:
	case <-time.After(3 * time.Second):
	}
}

// WaitJob blocks until the active recon job finishes (or ctx is cancelled) and
// returns the latest ReconJobState snapshot.
func (m *Manager) WaitJob(ctx context.Context) (*ReconJobState, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	job := m.active
	m.mu.Unlock()
	if job == nil {
		return m.GetJobState(), nil
	}
	select {
	case <-job.doneCh:
		return m.GetJobState(), nil
	case <-ctx.Done():
		return m.GetJobState(), ctx.Err()
	}
}

// Shutdown cancels any active recon job during application exit.
func (m *Manager) Shutdown() {
	_ = m.CancelJob()
}

func (m *Manager) appendLog(jobID, kind, level, msg string) {
	ev := ReconJobEvent{
		Seq:         m.seq.Add(1),
		JobID:       jobID,
		TimestampMs: time.Now().UnixMilli(),
		Kind:        kind,
		Level:       level,
		Message:     msg,
	}
	m.mu.Lock()
	if m.state != nil && m.state.ID == jobID {
		m.state.EventCount++
		if len(m.state.Events) >= MaxJobEvents {
			copy(m.state.Events, m.state.Events[1:])
			m.state.Events[len(m.state.Events)-1] = ev
		} else {
			m.state.Events = append(m.state.Events, ev)
		}
	}
	onLog := m.onLog
	m.mu.Unlock()

	if onLog != nil {
		onLog(ev)
	}
}

func cloneJobState(st *ReconJobState) *ReconJobState {
	if st == nil {
		return &ReconJobState{Status: StatusIdle, Events: []ReconJobEvent{}}
	}
	cp := *st
	cp.Events = make([]ReconJobEvent, len(st.Events))
	copy(cp.Events, st.Events)
	return &cp
}

// --- Persistent Scan History (~/.cap/recon-history/*.json, max 50) ---------

// SaveHistory persists a ReconHistoryEntry atomically and prunes old entries beyond MaxHistoryEntries.
func (m *Manager) SaveHistory(entry ReconHistoryEntry) (*ReconHistoryEntry, error) {
	m.histMu.Lock()
	defer m.histMu.Unlock()

	entry.ID = sanitizeHistoryID(entry.ID)
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("recon-%d-%d", time.Now().UnixNano(), m.seq.Add(1))
	}
	if entry.CreatedAt == "" {
		entry.CreatedAt = nowHistoryTimestamp()
	}
	if entry.Status == "" {
		entry.Status = StatusDone
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal recon history: %w", err)
	}
	filePath := filepath.Join(m.historyDir, entry.ID+".json")
	if err := fsutil.WriteFileAtomic(filePath, data, 0644); err != nil {
		return nil, fmt.Errorf("write recon history: %w", err)
	}

	m.pruneHistoryLocked()
	cp := entry
	return &cp, nil
}

// ListHistory loads all persisted recon history entries sorted newest-first.
func (m *Manager) ListHistory() []ReconHistoryEntry {
	m.histMu.Lock()
	defer m.histMu.Unlock()
	return m.loadAllHistoryLocked()
}

// GetHistory fetches a single persisted recon history entry by ID.
func (m *Manager) GetHistory(id string) (*ReconHistoryEntry, bool) {
	id = strings.TrimSpace(id)
	if !isValidHistoryID(id) {
		return nil, false
	}
	m.histMu.Lock()
	defer m.histMu.Unlock()

	raw, err := os.ReadFile(filepath.Join(m.historyDir, id+".json"))
	if err != nil {
		return nil, false
	}
	var entry ReconHistoryEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, false
	}
	if entry.ID == "" {
		entry.ID = id
	}
	return &entry, true
}

// DeleteHistory removes one persisted recon history entry by ID.
func (m *Manager) DeleteHistory(id string) error {
	id = strings.TrimSpace(id)
	if !isValidHistoryID(id) {
		return fmt.Errorf("recon: invalid history id %q", id)
	}
	m.histMu.Lock()
	defer m.histMu.Unlock()

	err := os.Remove(filepath.Join(m.historyDir, id+".json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ClearHistory removes all persisted recon history JSON files.
func (m *Manager) ClearHistory() error {
	m.histMu.Lock()
	defer m.histMu.Unlock()

	entries, err := os.ReadDir(m.historyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		_ = os.Remove(filepath.Join(m.historyDir, e.Name()))
	}
	return nil
}

func (m *Manager) loadAllHistoryLocked() []ReconHistoryEntry {
	dirEntries, err := os.ReadDir(m.historyDir)
	if err != nil {
		return []ReconHistoryEntry{}
	}
	type loadedItem struct {
		entry ReconHistoryEntry
		mtime time.Time
	}
	items := make([]loadedItem, 0, len(dirEntries))
	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		raw, rErr := os.ReadFile(filepath.Join(m.historyDir, de.Name()))
		if rErr != nil {
			continue
		}
		var entry ReconHistoryEntry
		if json.Unmarshal(raw, &entry) != nil {
			continue
		}
		if entry.ID == "" {
			entry.ID = strings.TrimSuffix(de.Name(), ".json")
		}
		var mt time.Time
		if fi, fiErr := de.Info(); fiErr == nil {
			mt = fi.ModTime()
		}
		items = append(items, loadedItem{entry: entry, mtime: mt})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].entry.CreatedAt != items[j].entry.CreatedAt {
			return items[i].entry.CreatedAt > items[j].entry.CreatedAt
		}
		if !items[i].mtime.Equal(items[j].mtime) {
			return items[i].mtime.After(items[j].mtime)
		}
		return items[i].entry.ID > items[j].entry.ID
	})
	out := make([]ReconHistoryEntry, 0, len(items))
	for _, it := range items {
		out = append(out, it.entry)
	}
	return out
}

func (m *Manager) pruneHistoryLocked() {
	all := m.loadAllHistoryLocked()
	if len(all) <= MaxHistoryEntries {
		return
	}
	for _, old := range all[MaxHistoryEntries:] {
		if isValidHistoryID(old.ID) {
			_ = os.Remove(filepath.Join(m.historyDir, old.ID+".json"))
		}
	}
}

func nowHistoryTimestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
}

func isValidHistoryID(id string) bool {
	if id == "" || len(id) > 128 || strings.HasPrefix(id, ".") || strings.Contains(id, "..") {
		return false
	}
	return historyIDSafeRe.MatchString(id)
}

func sanitizeHistoryID(raw string) string {
	s := strings.TrimSpace(raw)
	if isValidHistoryID(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), ".-_")
	if !isValidHistoryID(out) {
		return ""
	}
	return out
}
