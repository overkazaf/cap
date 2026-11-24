package wailsgui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/overkazaf/cap/internal/deobf"
	"github.com/overkazaf/cap/internal/exectrace"
	"github.com/overkazaf/cap/internal/retools"
	captrace "github.com/overkazaf/cap/internal/trace"
)

// ==================== Native RE Toolchain & Emulation ====================

func retoolsToolchainFromSettings(settings map[string]string) retools.ToolchainConfig {
	if settings == nil {
		return retools.ToolchainConfig{}
	}
	return retools.ToolchainConfig{
		R2Path:       strings.TrimSpace(settings["re_r2_path"]),
		JavaPath:     strings.TrimSpace(settings["re_java_path"]),
		MvnPath:      strings.TrimSpace(settings["re_mvn_path"]),
		UnidbgDir:    strings.TrimSpace(settings["re_unidbg_dir"]),
		PythonPath:   strings.TrimSpace(settings["re_python_path"]),
		QilingRootFS: strings.TrimSpace(settings["re_qiling_rootfs"]),
	}
}

func isREToolchainSettingKey(key string) bool {
	switch key {
	case "re_r2_path", "re_java_path", "re_mvn_path", "re_unidbg_dir", "re_python_path", "re_qiling_rootfs":
		return true
	default:
		return false
	}
}

func (a *App) ensureRetoolsManager() (*retools.Manager, error) {
	a.mu.Lock()
	mgr := a.retoolsMgr
	capDir := a.certDir
	tcCfg := retoolsToolchainFromSettings(a.settings)
	a.mu.Unlock()

	if mgr != nil {
		return mgr, nil
	}
	created, err := retools.NewManager(capDir)
	if err != nil {
		return nil, err
	}
	created.SetToolchainConfig(tcCfg)
	if a.events != nil {
		created.SetCallbacks(
			func(ev retools.JobLogEvent) {
				a.events.Emit(EventRELog, ev)
			},
			func(st *retools.JobState) {
				a.events.Emit(EventREStatus, st)
			},
		)
	}
	a.mu.Lock()
	if a.retoolsMgr == nil {
		a.retoolsMgr = created
	}
	mgr = a.retoolsMgr
	a.mu.Unlock()
	return mgr, nil
}

func (a *App) ensureExecTraceManager() (*exectrace.Manager, error) {
	a.mu.Lock()
	mgr := a.execTraceMgr
	capDir := a.certDir
	a.mu.Unlock()

	if mgr != nil {
		return mgr, nil
	}
	traceDir := ""
	if strings.TrimSpace(capDir) != "" {
		traceDir = filepath.Join(capDir, "exec-traces")
	}
	created, err := exectrace.NewManager(traceDir)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.execTraceMgr == nil {
		a.execTraceMgr = created
	}
	mgr = a.execTraceMgr
	a.mu.Unlock()
	return mgr, nil
}

func parseHexUint64(raw string) (uint64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, nil
	}
	clean := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if clean == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(clean, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid hex address %q: %w", raw, err)
	}
	return v, nil
}

// GetREToolchain inspects host radare2, Java/Maven/Unidbg, and Python/Qiling/angr readiness.
func (a *App) GetREToolchain(forceRefresh bool) retools.ToolchainInfo {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return retools.ToolchainInfo{
			Issues: []string{err.Error()},
		}
	}
	return mgr.GetToolchain(forceRefresh)
}

// UpdateREToolchainConfig persists custom RE toolchain paths and re-probes immediately.
func (a *App) UpdateREToolchainConfig(cfg retools.ToolchainConfig) (retools.ToolchainInfo, error) {
	trimmed := retools.ToolchainConfig{
		R2Path:       strings.TrimSpace(cfg.R2Path),
		JavaPath:     strings.TrimSpace(cfg.JavaPath),
		MvnPath:      strings.TrimSpace(cfg.MvnPath),
		UnidbgDir:    strings.TrimSpace(cfg.UnidbgDir),
		PythonPath:   strings.TrimSpace(cfg.PythonPath),
		QilingRootFS: strings.TrimSpace(cfg.QilingRootFS),
	}
	updates := map[string]string{
		"re_r2_path":       trimmed.R2Path,
		"re_java_path":     trimmed.JavaPath,
		"re_mvn_path":      trimmed.MvnPath,
		"re_unidbg_dir":    trimmed.UnidbgDir,
		"re_python_path":   trimmed.PythonPath,
		"re_qiling_rootfs": trimmed.QilingRootFS,
	}
	for k, v := range updates {
		if err := a.SetSetting(k, v); err != nil {
			return retools.ToolchainInfo{}, err
		}
	}
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return retools.ToolchainInfo{}, err
	}
	mgr.SetToolchainConfig(trimmed)
	return mgr.GetToolchain(true), nil
}

// AnalyzeBinary runs static analysis on an ELF/Mach-O binary using radare2 or pure-Go fallback.
func (a *App) AnalyzeBinary(binaryPath string) (*retools.BinaryAnalysis, error) {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return nil, err
	}
	return mgr.AnalyzeBinary(context.Background(), binaryPath)
}

// InspectBinaryFunction returns disassembly, pseudo-C, and cross-references for one function.
func (a *App) InspectBinaryFunction(binaryPath, funcNameOrAddr string) (*retools.FunctionDetail, error) {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return nil, err
	}
	return mgr.InspectFunction(context.Background(), binaryPath, funcNameOrAddr)
}

// RunR2Command executes a sanitized read-only radare2 command on binaryPath.
func (a *App) RunR2Command(binaryPath, r2Cmd string) (*retools.R2CommandResult, error) {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return nil, err
	}
	return mgr.RunR2Command(context.Background(), binaryPath, r2Cmd)
}

// ListREProjects returns built-in templates and user-saved RE projects, optionally filtered by engine.
func (a *App) ListREProjects(engine string) []retools.REProject {
	mgr, err := a.ensureRetoolsManager()
	if err != nil || mgr.Projects() == nil {
		return []retools.REProject{}
	}
	return mgr.Projects().ListByEngine(engine)
}

// SaveREProject persists a custom RE project to disk.
func (a *App) SaveREProject(proj retools.REProject) (*retools.REProject, error) {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return nil, err
	}
	return mgr.SaveProject(proj)
}

// DeleteREProject deletes a user-saved RE project by ID.
func (a *App) DeleteREProject(id string) error {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return err
	}
	return mgr.DeleteProject(id)
}

// GenerateREHarnessFromTrace synthesizes a Unidbg, Qiling, angr, or radare2 harness
// using the current DeepTrace result (if available) merged with opts.
func (a *App) GenerateREHarnessFromTrace(engine string, opts retools.GenerateOptions) (*retools.GeneratedHarness, error) {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return nil, err
	}
	a.traceMu.Lock()
	var traceRes *captrace.TraceResult
	if a.traceState != nil {
		traceRes = a.traceState.Result
	}
	a.traceMu.Unlock()

	return mgr.GenerateFromTrace(traceRes, engine, opts)
}

// StartREJob launches an asynchronous cancellable RE execution job.
func (a *App) StartREJob(req retools.RunJobRequest) (*retools.JobState, error) {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return nil, err
	}
	return mgr.StartJob(req)
}

// CancelREJob terminates the currently running RE job.
func (a *App) CancelREJob() error {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return err
	}
	return mgr.CancelJob()
}

// GetREJobState returns a snapshot of the active or most recent RE job.
func (a *App) GetREJobState() *retools.JobState {
	mgr, err := a.ensureRetoolsManager()
	if err != nil {
		return &retools.JobState{
			Status:  retools.StatusIdle,
			Events:  []retools.JobLogEvent{},
			Results: []retools.JobResult{},
		}
	}
	return mgr.GetJobState()
}

// ClearREJobLogs clears logged events and structured results for the current RE job.
func (a *App) ClearREJobLogs() {
	if mgr, err := a.ensureRetoolsManager(); err == nil {
		mgr.ClearJobLogs()
	}
}

// ==================== Deobfuscation, Stealth & VMP ====================

// ScanProtection audits an APK archive (if targetPath ends in .apk) or an ELF binary.
func (a *App) ScanProtection(targetPath string) (*deobf.ProtectionReport, error) {
	p := strings.TrimSpace(targetPath)
	if p == "" {
		return nil, fmt.Errorf("target path is required")
	}
	if strings.HasSuffix(strings.ToLower(p), ".apk") {
		return deobf.ScanAPK(p)
	}
	return deobf.ScanELF(p)
}

// GenerateStealthScript synthesizes a composable Frida Anti-Debug / Anti-Frida stealth script.
func (a *App) GenerateStealthScript(opts deobf.StealthOptions, report *deobf.ProtectionReport) *deobf.GeneratedScript {
	return deobf.GenerateStealthScript(opts, report)
}

// GenerateDexUnpackerScript synthesizes an in-memory DEX unpacker Frida script.
func (a *App) GenerateDexUnpackerScript(pkg string) *deobf.GeneratedScript {
	return deobf.GenerateDexUnpackerScript(pkg)
}

// GenerateOLLVMDeflattenScript generates an angr OLLVM CFF de-flattening & patching Python script.
func (a *App) GenerateOLLVMDeflattenScript(soPath, funcAddr, arch string) *deobf.GeneratedScript {
	return deobf.GenerateOLLVMDeflattenScript(soPath, funcAddr, arch)
}

// GenerateStringDecryptScript generates a dynamic string-decryption script for the given engine.
func (a *App) GenerateStringDecryptScript(engine, soPath, apkPath string) *deobf.GeneratedScript {
	return deobf.GenerateStringDecryptScript(engine, soPath, apkPath)
}

// GenerateJavaDeobfScript generates a Frida runtime Java reflection/classloader deobfuscation script.
func (a *App) GenerateJavaDeobfScript(targetPkg string) *deobf.GeneratedScript {
	return deobf.GenerateJavaDeobfScript(targetPkg)
}

// GenerateVMPStalkerScript synthesizes a module-scoped Frida Stalker tracer for native VMP analysis.
func (a *App) GenerateVMPStalkerScript(soName, entrySymbolOrOffset string, maxEvents int) *deobf.GeneratedScript {
	return deobf.GenerateVMPStalkerScript(soName, entrySymbolOrOffset, maxEvents)
}

// GenerateVMPRegisterNativesScript synthesizes a Frida RegisterNatives / JNI dynamic binding tracer.
func (a *App) GenerateVMPRegisterNativesScript(filterPkg string) *deobf.GeneratedScript {
	return deobf.GenerateVMPRegisterNativesScript(filterPkg)
}

// GenerateUnidbgVMPTraceScript generates an Unidbg Java harness configured for VMP instruction tracing.
func (a *App) GenerateUnidbgVMPTraceScript(apkPath, soName, className, methodName string) *deobf.GeneratedScript {
	return deobf.GenerateUnidbgVMPTraceScript(apkPath, soName, className, methodName)
}

// AnalyzeVMPTrace analyzes a raw Frida Stalker, Unidbg, or Tenet trace to identify VMP dispatchers and handlers.
func (a *App) AnalyzeVMPTrace(rawTrace string, moduleBaseHex string) *deobf.VMPTraceAnalysis {
	base, _ := parseHexUint64(moduleBaseHex)
	return deobf.AnalyzeVMPTrace(rawTrace, base)
}

// ==================== Execution Trace Engine ====================

// ImportExecTrace parses, analyzes, and stores a dynamic execution trace from raw text.
func (a *App) ImportExecTrace(name, format, rawContent, moduleBaseHex string) (*exectrace.ExecTraceSession, error) {
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return nil, err
	}
	base, err := parseHexUint64(moduleBaseHex)
	if err != nil {
		return nil, err
	}
	return mgr.ImportTrace(name, format, rawContent, base)
}

// ImportExecTraceFile reads a trace file from disk, parses, analyzes, and stores it.
func (a *App) ImportExecTraceFile(filePath, format, moduleBaseHex string) (*exectrace.ExecTraceSession, error) {
	p := strings.TrimSpace(filePath)
	if p == "" {
		return nil, fmt.Errorf("trace file path is required")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read trace file %s: %w", p, err)
	}
	base, err := parseHexUint64(moduleBaseHex)
	if err != nil {
		return nil, err
	}
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
	if name == "" {
		name = filepath.Base(p)
	}
	return mgr.ImportTrace(name, format, string(raw), base)
}

// ListExecTraces returns metadata and summaries for all stored execution trace sessions.
func (a *App) ListExecTraces() []*exectrace.ExecTraceSession {
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return []*exectrace.ExecTraceSession{}
	}
	sessions := mgr.ListSessions()
	out := make([]*exectrace.ExecTraceSession, len(sessions))
	for i := range sessions {
		cp := sessions[i]
		out[i] = &cp
	}
	return out
}

// GetExecTrace fetches a full execution trace session (including events) by ID.
func (a *App) GetExecTrace(id string) (*exectrace.ExecTraceSession, error) {
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return nil, err
	}
	sess, ok := mgr.GetSession(id)
	if !ok {
		return nil, fmt.Errorf("execution trace session %q not found", id)
	}
	return sess, nil
}

// DeleteExecTrace removes a stored execution trace session by ID.
func (a *App) DeleteExecTrace(id string) error {
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return err
	}
	return mgr.DeleteSession(id)
}

// QueryExecTraceEvents returns a filtered, paginated window of trace events for sessionID.
func (a *App) QueryExecTraceEvents(sessionID string, filter exectrace.EventFilter) (*exectrace.EventPage, error) {
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return nil, err
	}
	return mgr.QueryEvents(sessionID, filter)
}

// RunExecTraceTaint performs forward or backward register/memory taint analysis on a stored trace session.
func (a *App) RunExecTraceTaint(req exectrace.TaintRequest) (*exectrace.TaintResult, error) {
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return nil, err
	}
	return mgr.RunTaint(req)
}

// DiffExecTraces computes an ASLR-normalized differential comparison between two trace sessions.
func (a *App) DiffExecTraces(sessionA, sessionB string, maxDivergences int) (*exectrace.TraceDiffResult, error) {
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return nil, err
	}
	return mgr.DiffSessions(sessionA, sessionB, maxDivergences)
}

// GenerateExecTraceCollector synthesizes a ready-to-run trace collector script.
func (a *App) GenerateExecTraceCollector(kind string, cfg exectrace.CollectorConfig) *exectrace.GeneratedCollector {
	return exectrace.GenerateCollector(kind, cfg)
}

// ExportExecTrace exports a stored execution trace session in tenet, jsonl, or markdown format.
func (a *App) ExportExecTrace(sessionID, format string) (string, error) {
	mgr, err := a.ensureExecTraceManager()
	if err != nil {
		return "", err
	}
	return mgr.ExportTrace(sessionID, format)
}
