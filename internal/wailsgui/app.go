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

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/plugin"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/rules"
	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
)

// App is the Wails application binding, providing methods callable from
// the frontend. Domain-specific methods are split across sibling files:
//   - proxy_gui.go: proxy control, capture, domain filtering
//   - flows_gui.go: flows, export, replay, analysis, sequences
//   - device_gui.go: Android device, screen, RE tools, deep trace
type App struct {
	ctx      context.Context
	store    store.Store
	proxy    *proxy.Proxy
	plugins     *plugin.Engine
	rulesEngine *rules.Engine
	mu          sync.Mutex
	settings map[string]string

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
}

func NewApp(st store.Store) *App {
	capDir := config.DefaultDir()
	pluginEngine, _ := plugin.NewEngine(filepath.Join(capDir, "plugins"))
	settingsFile := filepath.Join(capDir, "settings.json")
	settings := loadSettings(settingsFile)
	return &App{
		store:       st,
		certDir:     capDir,
		plugins:     pluginEngine,
		rulesEngine: rules.NewEngine(),
		settings:    settings,
		tlsErrors:   make(map[string]int),
	}
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	proxy.EnsureCA(a.certDir)
}

func (a *App) Shutdown(ctx context.Context) {
	a.mu.Lock()
	if a.isRunning && a.proxy != nil {
		a.proxy.Stop()
	}
	a.mu.Unlock()

	devices, _ := android.ListDevices()
	for _, d := range devices {
		android.Teardown(d.Serial)
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
	return a.plugins.RunAnalyzer(name, f), nil
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
	return a.settings
}

func (a *App) SetSetting(key string, value interface{}) error {
	a.settings[key] = fmt.Sprintf("%v", value)
	return saveSettings(filepath.Join(a.certDir, "settings.json"), a.settings)
}

func (a *App) GetSetting(key string) string {
	return a.settings[key]
}

func loadSettings(path string) map[string]string {
	settings := map[string]string{
		"theme":         "dark",
		"proxy_addr":    "0.0.0.0:8080",
		"proxy_port":    "8080",
		"auto_detect":   "true",
		"install_cert":  "true",
		"max_body_size": "4096",
		"font_size":     "13",
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
	return "0.2.0"
}
