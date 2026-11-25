package wailsgui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/overkazaf/cap/internal/ai"
	"github.com/overkazaf/cap/internal/buildinfo"
	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/exectrace"
	"github.com/overkazaf/cap/internal/frida"
	"github.com/overkazaf/cap/internal/gateway"
	"github.com/overkazaf/cap/internal/plugin"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/recon"
	"github.com/overkazaf/cap/internal/retools"
	"github.com/overkazaf/cap/internal/rules"
	"github.com/overkazaf/cap/internal/screen"
	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails application binding, providing methods callable from
// the frontend. Domain-specific methods are split across sibling files:
//   - proxy_gui.go: proxy control, capture, domain filtering
//   - flows_gui.go: flows, export, replay, analysis, sequences
//   - device_gui.go: Android device, screen, RE tools, deep trace
//   - frida_gui.go: Frida server management, script library, live sessions
//   - retools_gui.go: Native RE (r2/Unidbg/Qiling/angr), Deobf/VMP, ExecTrace
//   - gateway_gui.go: Open API Gateway, Proxy Pool, Device Pool, Signers
//   - recon_gui.go: Site Recon, Domain/TLS/Subdomain/Port scanning, history
//   - ai_gui.go: Multi-model AI provider config, diagnosis, self-healing loop
type App struct {
	ctx         context.Context
	store       store.Store
	proxy       *proxy.Proxy
	plugins     *plugin.Engine
	rulesEngine *rules.Engine
	events      *EventBus
	mu          sync.Mutex
	settings    map[string]string

	flows      []*types.Flow
	isRunning  bool
	isPaused   bool
	certDir    string
	reqCount   int64
	byteCount  int64
	rateReqPS  float64
	rateBytPS  float64
	lastRateTS time.Time
	lastReqN   int64
	lastByteN  int64

	domainWhitelist []string
	domainBlacklist []string
	tlsErrors       map[string]int
	tlsErrorsMu     sync.Mutex

	deviceMu         sync.Mutex
	connectedDevices map[string]*connectedDeviceSession
	staleDevices     map[string]bool
	monitorStop      chan struct{}
	monitorRunning   bool

	screenMu     sync.Mutex
	screenStream *screen.MJPEGServer

	traceMu     sync.Mutex
	traceCancel context.CancelFunc
	traceState  *DeepTraceState

	pluginSem    chan struct{}
	pluginCtx    context.Context
	pluginCancel context.CancelFunc

	fridaMgr     *frida.Manager
	retoolsMgr   *retools.Manager
	execTraceMgr *exectrace.Manager
	gatewayMgr   *gateway.Manager
	reconMgr     *recon.Manager
	aiMgr        *ai.Manager

	aiHealMu     sync.Mutex
	aiHealCancel context.CancelFunc
	aiHealSeq    uint64
}

const maxConcurrentAutoPlugins = 4

func NewApp(st store.Store) *App {
	capDir := config.DefaultDir()
	pluginEngine, _ := plugin.NewEngine(filepath.Join(capDir, "plugins"))
	fridaMgr, _ := frida.NewManager(capDir)
	retoolsMgr, _ := retools.NewManager(capDir)
	execTraceMgr, _ := exectrace.NewManager(filepath.Join(capDir, "exec-traces"))
	gatewayMgr, _ := gateway.NewManager(capDir)
	reconMgr, _ := recon.NewManager(capDir)
	aiMgr, _ := ai.NewManager(capDir)
	settingsFile := filepath.Join(capDir, "settings.json")
	settings := loadSettings(settingsFile)
	pCtx, pCancel := context.WithCancel(context.Background())
	events := NewEventBus()
	if fridaMgr != nil {
		fridaMgr.SetToolchainConfig(frida.ToolchainConfig{
			PythonPath: settings["frida_python_path"],
			FridaPath:  settings["frida_cli_path"],
		})
		fridaMgr.SetCallbacks(
			func(ev frida.LogEvent) {
				events.Emit(EventFridaLog, ev)
			},
			func(st *frida.SessionState) {
				events.Emit(EventFridaStatus, st)
			},
		)
	}
	if retoolsMgr != nil {
		retoolsMgr.SetToolchainConfig(retoolsToolchainFromSettings(settings))
		retoolsMgr.SetCallbacks(
			func(ev retools.JobLogEvent) {
				events.Emit(EventRELog, ev)
			},
			func(st *retools.JobState) {
				events.Emit(EventREStatus, st)
			},
		)
	}
	if gatewayMgr != nil {
		gatewayMgr.SetCallbacks(
			func(rec gateway.InvocationRecord) {
				events.Emit(EventGatewayInvoke, rec)
			},
			func(st gateway.GatewayStatus) {
				events.Emit(EventGatewayStatus, st)
			},
		)
	}
	if reconMgr != nil {
		reconMgr.SetToolchainConfig(reconToolchainFromSettings(settings))
		reconMgr.SetCallbacks(
			func(ev recon.ReconJobEvent) {
				events.Emit(EventReconLog, ev)
			},
			func(st *recon.ReconJobState) {
				events.Emit(EventReconStatus, st)
			},
		)
	}
	return &App{
		store:            st,
		certDir:          capDir,
		plugins:          pluginEngine,
		rulesEngine:      rules.NewEngine(),
		events:           events,
		settings:         settings,
		tlsErrors:        make(map[string]int),
		connectedDevices: make(map[string]*connectedDeviceSession),
		staleDevices:     make(map[string]bool),
		pluginSem:        make(chan struct{}, maxConcurrentAutoPlugins),
		pluginCtx:        pCtx,
		pluginCancel:     pCancel,
		fridaMgr:         fridaMgr,
		retoolsMgr:       retoolsMgr,
		execTraceMgr:     execTraceMgr,
		gatewayMgr:       gatewayMgr,
		reconMgr:         reconMgr,
		aiMgr:            aiMgr,
	}
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	a.events.SetEmitter(func(event string, data ...interface{}) {
		runtime.EventsEmit(ctx, event, data...)
	})
	proxy.EnsureCA(a.certDir)
}

func (a *App) Shutdown(ctx context.Context) {
	// Cancel any active DeepTrace run, AI Auto-Heal loop, Frida session,
	// RE jobs, Recon jobs, Gateway server, and auto-run plugin scripts cleanly.
	_ = a.CancelDeepTrace()
	_ = a.CancelAIAutoHeal()

	a.mu.Lock()
	fridaMgr := a.fridaMgr
	retoolsMgr := a.retoolsMgr
	gatewayMgr := a.gatewayMgr
	reconMgr := a.reconMgr
	a.mu.Unlock()

	if fridaMgr != nil {
		fridaMgr.Shutdown()
	}
	if retoolsMgr != nil {
		retoolsMgr.Shutdown()
	}
	if reconMgr != nil {
		reconMgr.Shutdown()
	}
	if gatewayMgr != nil {
		_ = gatewayMgr.Shutdown()
	}
	if a.pluginCancel != nil {
		a.pluginCancel()
	}

	// Stop any active screen mirror stream immediately so ffmpeg/scrcpy/adb
	// subprocesses and loopback listeners never leak on exit.
	_ = a.StopScreenStream()

	// Stop device monitor and clean up connected Android devices BEFORE
	// stopping the proxy so Companion Guard receives a clean stop signal
	// and phones are never left with stale proxy settings.
	a.stopDeviceMonitor()
	a.teardownAllDevices("app_shutdown")

	a.mu.Lock()
	p := a.proxy
	running := a.isRunning
	a.isRunning = false
	a.proxy = nil
	a.mu.Unlock()

	if running && p != nil {
		_ = p.Stop()
	}
}

// ==================== Plugins ====================

func (a *App) ListPlugins() []*plugin.Plugin {
	return a.plugins.List()
}

func (a *App) GetPlugin(name string) (*plugin.Plugin, error) {
	return a.plugins.Get(name)
}

func (a *App) SavePlugin(p plugin.Plugin) error {
	return a.plugins.Save(&p)
}

func (a *App) DeletePlugin(name string) error {
	return a.plugins.Delete(name)
}

func (a *App) TogglePlugin(name string) error {
	return a.plugins.Toggle(name)
}

func (a *App) GetExamplePlugins() []plugin.Plugin {
	return plugin.ExamplePlugins
}

func (a *App) RunPlugin(name, flowID string) (*plugin.ExecResult, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}
	res := a.plugins.RunAnalyzer(name, f)
	if logs := a.plugins.Logs(1); len(logs) > 0 && logs[0].ID != "" && logs[0].PluginName == name && logs[0].FlowID == flowID {
		a.events.Emit(EventPluginExecuted, logs[0])
	} else {
		runtimeName := plugin.RuntimeBuiltin
		if p, getErr := a.plugins.Get(name); getErr == nil && p != nil && p.Runtime != "" {
			runtimeName = p.Runtime
		}
		rec := plugin.ExecutionRecord{
			ID:         fmt.Sprintf("manual-%d", time.Now().UnixNano()),
			PluginName: name,
			Runtime:    runtimeName,
			FlowID:     f.ID,
			Method:     f.Method,
			URL:        f.URL,
			Status:     f.Status,
			Output:     res.Output,
			Error:      res.Error,
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Trigger:    "manual",
		}
		a.plugins.RecordExecution(rec)
		if logs := a.plugins.Logs(1); len(logs) > 0 && logs[0].ID != "" {
			rec = logs[0]
		}
		a.events.Emit(EventPluginExecuted, rec)
	}
	return res, nil
}

func (a *App) TestPluginMatch(p plugin.Plugin, flowID string) (bool, error) {
	if a.store == nil {
		return false, fmt.Errorf("flow store unavailable")
	}
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return false, err
	}
	return plugin.MatchesFlow(&p, f), nil
}

// RunPluginDraft executes an unsaved/in-memory plugin draft against flowID
// (even when p.Enabled is false), records a manual ExecutionRecord, emits
// EventPluginExecuted, and returns the execution output.
func (a *App) RunPluginDraft(p plugin.Plugin, flowID string) (*plugin.ExecResult, error) {
	if a.store == nil {
		return nil, fmt.Errorf("flow store unavailable")
	}
	if a.plugins == nil {
		return nil, fmt.Errorf("plugin engine unavailable")
	}
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}
	ctx := a.pluginCtx
	if ctx == nil {
		ctx = context.Background()
	}
	res, rec := a.plugins.RunDraftContext(ctx, &p, f)
	if rec.ID == "" {
		rec.ID = fmt.Sprintf("draft-%d", time.Now().UnixNano())
	}
	a.events.Emit(EventPluginExecuted, rec)
	return res, nil
}

// GetPluginFlowPayload returns the exact indented JSON payload passed to
// plugin scripts on stdin for flowID (including query and query_params).
func (a *App) GetPluginFlowPayload(flowID string) (string, error) {
	if a.store == nil {
		return "", fmt.Errorf("flow store unavailable")
	}
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return "", err
	}
	data, err := plugin.BuildFlowPayloadJSON(f)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (a *App) GetPluginDir() string {
	if a.plugins == nil {
		return ""
	}
	return a.plugins.Dir()
}

func (a *App) ReloadPlugins() ([]*plugin.Plugin, error) {
	if a.plugins == nil {
		return []*plugin.Plugin{}, nil
	}
	if err := a.plugins.Reload(); err != nil {
		return nil, err
	}
	return a.plugins.List(), nil
}

func (a *App) GetPluginLogs(limit int) []plugin.ExecutionRecord {
	if a.plugins == nil {
		return []plugin.ExecutionRecord{}
	}
	return a.plugins.Logs(limit)
}

func (a *App) ClearPluginLogs() {
	if a.plugins == nil {
		return
	}
	a.plugins.ClearLogs()
}

func (a *App) runAutoPlugins(f *types.Flow) {
	if a.plugins == nil || f == nil {
		return
	}
	ctx := a.pluginCtx
	if ctx == nil {
		ctx = context.Background()
	}

	sem := a.pluginSem
	if sem != nil {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			return
		}
	}

	records := a.plugins.RunMatching(ctx, f)
	for _, rec := range records {
		a.events.Emit(EventPluginExecuted, rec)
	}
}

// ==================== Intercept Rules ====================

func (a *App) AddRule(rule rules.Rule) error {
	a.rulesEngine.AddRule(&rule)
	return nil
}

func (a *App) RemoveRule(id string) {
	a.rulesEngine.RemoveRule(id)
}

func (a *App) ListRules() []*rules.Rule {
	return a.rulesEngine.ListRules()
}

func (a *App) SetRules(ruleList []rules.Rule) {
	ptrs := make([]*rules.Rule, len(ruleList))
	for i := range ruleList {
		ptrs[i] = &ruleList[i]
	}
	a.rulesEngine.SetRules(ptrs)
}

func (a *App) GetPendingBreakpoints() []*rules.PendingBreakpoint {
	return a.rulesEngine.ListPendingBreakpoints()
}

func (a *App) ResolveBreakpoint(bpID, action string, url, method, body string, headers map[string]string, status int, respHeaders map[string]string, respBody string) error {
	res := &rules.BreakpointResolution{
		Action:      action,
		URL:         url,
		Method:      method,
		Headers:     headers,
		Body:        []byte(body),
		Status:      status,
		RespHeaders: respHeaders,
		RespBody:    []byte(respBody),
	}
	return a.rulesEngine.ResolveBreakpoint(bpID, res)
}

// ==================== Terminal ====================

func (a *App) ExecCommand(cmd string) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", nil
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	c := exec.Command(shell, "-c", cmd)
	c.Env = os.Environ()
	out, err := c.CombinedOutput()
	result := string(out)
	if err != nil {
		if result != "" {
			return result, nil
		}
		return err.Error(), nil
	}
	return result, nil
}

// ==================== Settings ====================

func (a *App) GetSettings() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]string, len(a.settings))
	for k, v := range a.settings {
		out[k] = v
	}
	return out
}

func (a *App) SetSetting(key string, value interface{}) error {
	strVal := fmt.Sprintf("%v", value)
	a.mu.Lock()
	if a.settings == nil {
		a.settings = make(map[string]string)
	}
	a.settings[key] = strVal
	pyPath := a.settings["frida_python_path"]
	cliPath := a.settings["frida_cli_path"]
	reCfg := retoolsToolchainFromSettings(a.settings)
	reconCfg := reconToolchainFromSettings(a.settings)
	fridaMgr := a.fridaMgr
	retoolsMgr := a.retoolsMgr
	reconMgr := a.reconMgr
	gatewayMgr := a.gatewayMgr
	certDir := a.certDir
	snapshot := make(map[string]string, len(a.settings))
	for k, v := range a.settings {
		snapshot[k] = v
	}
	a.mu.Unlock()

	if (key == "frida_python_path" || key == "frida_cli_path") && fridaMgr != nil {
		fridaMgr.SetToolchainConfig(frida.ToolchainConfig{
			PythonPath: pyPath,
			FridaPath:  cliPath,
		})
	}
	if isREToolchainSettingKey(key) && retoolsMgr != nil {
		retoolsMgr.SetToolchainConfig(reCfg)
	}
	if isReconToolchainSettingKey(key) && reconMgr != nil {
		reconMgr.SetToolchainConfig(reconCfg)
	}
	if key == "gateway_addr" && gatewayMgr != nil {
		if addr := strings.TrimSpace(strVal); addr != "" {
			cfg := gatewayMgr.GetConfig()
			if cfg.ListenAddr != addr {
				cfg.ListenAddr = addr
				_ = gatewayMgr.UpdateConfig(cfg)
			}
		}
	}
	return saveSettings(filepath.Join(certDir, "settings.json"), snapshot)
}

func (a *App) GetSetting(key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings[key]
}

func loadSettings(path string) map[string]string {
	settings := map[string]string{
		"theme":                 "dark",
		"proxy_addr":            "0.0.0.0:8080",
		"proxy_port":            "8080",
		"auto_detect":           "true",
		"install_cert":          "true",
		"max_body_size":         "4096",
		"font_size":             "13",
		"frida_python_path":     "",
		"frida_cli_path":        "",
		"frida_default_port":    "27042",
		"re_r2_path":            "",
		"re_java_path":          "",
		"re_mvn_path":           "",
		"re_unidbg_dir":         "",
		"re_python_path":        "",
		"re_qiling_python_path": "",
		"re_angr_python_path":   "",
		"re_qiling_rootfs":      "",
		"recon_nmap_path":       "",
		"recon_subfinder_path":  "",
		"recon_whois_path":      "",
		"recon_dig_path":        "",
		"gateway_addr":          "127.0.0.1:9090",
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return settings
	}
	var loaded map[string]string
	if json.Unmarshal(data, &loaded) == nil {
		for k, v := range loaded {
			settings[k] = v
		}
	}
	return settings
}

func saveSettings(path string, settings map[string]string) error {
	data, _ := json.MarshalIndent(settings, "", "  ")
	return os.WriteFile(path, data, 0644)
}

// ==================== Utils ====================

func (a *App) GetHostIP() string {
	addrs := strings.Split(a.ProxyAddr(), ":")
	if len(addrs) > 0 && addrs[0] != "" && addrs[0] != "0.0.0.0" {
		return addrs[0]
	}
	return "auto"
}

func (a *App) GetVersion() string {
	return buildinfo.Version()
}
