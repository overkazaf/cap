package wailsgui

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/rules"
	"github.com/overkazaf/cap/internal/screen"
	captrace "github.com/overkazaf/cap/internal/trace"
	"github.com/overkazaf/cap/internal/compare"
	"github.com/overkazaf/cap/internal/grouping"
	"github.com/overkazaf/cap/internal/importer"
	"github.com/overkazaf/cap/internal/proto"
	"github.com/overkazaf/cap/internal/sequence"
	"github.com/overkazaf/cap/internal/stats"
	"github.com/overkazaf/cap/internal/export/agent"
	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/plugin"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/replay"
	"github.com/overkazaf/cap/internal/sign"
	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
)

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
	home, _ := os.UserHomeDir()
	capDir := filepath.Join(home, ".cap")
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
	// Stop proxy
	a.mu.Lock()
	if a.isRunning && a.proxy != nil {
		a.proxy.Stop()
	}
	a.mu.Unlock()

	// Disconnect all devices (restore proxy settings)
	devices, _ := android.ListDevices()
	for _, d := range devices {
		android.Teardown(d.Serial)
	}
}

// ==================== Proxy ====================

type FlowEvent struct {
	ID      string `json:"id"`
	Method  string `json:"method"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Latency int64  `json:"latency_ms"`
}

func (a *App) StartProxy(addr string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.isRunning {
		return fmt.Errorf("proxy already running")
	}
	if addr == "" {
		addr = "0.0.0.0:8080"
	}

	a.reqCount = 0
	a.byteCount = 0
	a.lastRateTS = time.Now()

	p, err := proxy.New(proxy.Options{
		Addr:                addr,
		CertDir:             a.certDir,
		RequestInterceptor:  a.rulesEngine.RequestHandler(),
		ResponseInterceptor: a.rulesEngine.ResponseHandler(),
		OnFlow: func(f *types.Flow) {
			if !a.shouldCapture(f.Host) {
				return
			}
			a.store.SaveFlow(f)
			a.mu.Lock()
			a.flows = append([]*types.Flow{f}, a.flows...)
			a.reqCount++
			a.byteCount += int64(len(f.ReqBody) + len(f.RespBody))
			a.mu.Unlock()
		},
	})
	if err != nil {
		return err
	}

	a.proxy = p
	a.isRunning = true
	a.isPaused = false
	go p.Start()
	return nil
}

func (a *App) StopProxy() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.isRunning || a.proxy == nil {
		return nil
	}
	err := a.proxy.Stop()
	a.isRunning = false
	a.proxy = nil
	return err
}

func (a *App) ProxyAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proxy != nil {
		return a.proxy.Addr()
	}
	return ""
}

func (a *App) IsProxyRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isRunning
}

// ==================== Capture Controls ====================

func (a *App) PauseCapture() {
	a.mu.Lock()
	a.isPaused = true
	a.mu.Unlock()
}

func (a *App) ResumeCapture() {
	a.mu.Lock()
	a.isPaused = false
	a.mu.Unlock()
}

func (a *App) IsPaused() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isPaused
}

type TrafficRate struct {
	ReqPerSec  float64 `json:"req_per_sec"`
	BytePerSec float64 `json:"byte_per_sec"`
	TotalReqs  int64   `json:"total_reqs"`
	TotalBytes int64   `json:"total_bytes"`
}

func (a *App) GetTrafficRate() TrafficRate {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(a.lastRateTS).Seconds()
	if elapsed >= 1.0 {
		a.rateReqPS = float64(a.reqCount-a.lastReqN) / elapsed
		a.rateBytPS = float64(a.byteCount-a.lastByteN) / elapsed
		a.lastReqN = a.reqCount
		a.lastByteN = a.byteCount
		a.lastRateTS = now
	}
	return TrafficRate{
		ReqPerSec:  a.rateReqPS,
		BytePerSec: a.rateBytPS,
		TotalReqs:  a.reqCount,
		TotalBytes: a.byteCount,
	}
}

func (a *App) SetDomainFilter(whitelist, blacklist []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.domainWhitelist = whitelist
	a.domainBlacklist = blacklist
}

func (a *App) GetDomainFilter() map[string][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string][]string{
		"whitelist": a.domainWhitelist,
		"blacklist": a.domainBlacklist,
	}
}

func (a *App) shouldCapture(host string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isPaused {
		return false
	}
	if len(a.domainWhitelist) > 0 {
		for _, d := range a.domainWhitelist {
			if strings.Contains(host, d) {
				return true
			}
		}
		return false
	}
	for _, d := range a.domainBlacklist {
		if strings.Contains(host, d) {
			return false
		}
	}
	return true
}

type TLSError struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

func (a *App) GetTLSErrors() []TLSError {
	a.tlsErrorsMu.Lock()
	defer a.tlsErrorsMu.Unlock()
	result := make([]TLSError, 0, len(a.tlsErrors))
	for host, count := range a.tlsErrors {
		result = append(result, TLSError{Host: host, Count: count})
	}
	return result
}

func (a *App) ClearTLSErrors() {
	a.tlsErrorsMu.Lock()
	a.tlsErrors = make(map[string]int)
	a.tlsErrorsMu.Unlock()
}

func (a *App) ConnectWiFiADB(ipPort string) (string, error) {
	if ipPort == "" {
		return "", fmt.Errorf("IP:PORT required")
	}
	out, err := exec.Command("adb", "connect", ipPort).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (a *App) DisconnectWiFiADB(ipPort string) (string, error) {
	out, err := exec.Command("adb", "disconnect", ipPort).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

type AppInfo struct {
	Package string `json:"package"`
	Name    string `json:"name"`
}

func (a *App) ListApps(serial string) ([]AppInfo, error) {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "pm", "list", "packages", "-3")
	out, err := exec.Command("adb", args...).Output()
	if err != nil {
		return nil, err
	}
	var apps []AppInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			pkg := strings.TrimPrefix(line, "package:")
			apps = append(apps, AppInfo{Package: pkg, Name: pkg})
		}
	}
	return apps, nil
}

func (a *App) LaunchApp(serial, packageName string) error {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "monkey", "-p", packageName, "-c", "android.intent.category.LAUNCHER", "1")
	return exec.Command("adb", args...).Run()
}

// ==================== Flows ====================

type FlowSummary struct {
	ID       string `json:"id"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Latency  int64  `json:"latency_ms"`
	BodyType string `json:"body_type"`
	Time     string `json:"time"`
}

type FlowDetail struct {
	FlowSummary
	ReqHeaders  map[string]string `json:"req_headers"`
	ReqBody     string            `json:"req_body"`
	RespHeaders map[string]string `json:"resp_headers"`
	RespBody    string            `json:"resp_body"`
	Tags        []string          `json:"tags"`
	SignParams  []string          `json:"sign_params"`
	SourceRef   *types.SourceRef  `json:"source_ref"`
}

func (a *App) GetFlows(host, method, search string, limit int) []FlowSummary {
	if limit <= 0 {
		limit = 10000
	}
	flows, _ := a.store.ListFlows(types.FlowFilter{
		Host: host, Method: method, Search: search, Limit: limit,
	})
	result := make([]FlowSummary, len(flows))
	for i, f := range flows {
		result[i] = FlowSummary{
			ID:       f.ID,
			Method:   f.Method,
			URL:      f.URL,
			Host:     f.Host,
			Path:     f.Path,
			Status:   f.Status,
			Latency:  f.LatencyMs,
			BodyType: f.RespBodyType,
			Time:     f.Timestamp.Format("15:04:05.000"),
		}
	}
	return result
}

func (a *App) GetFlowDetail(id string) (*FlowDetail, error) {
	f, err := a.store.GetFlow(id)
	if err != nil {
		return nil, err
	}
	detail := &FlowDetail{
		FlowSummary: FlowSummary{
			ID:       f.ID,
			Method:   f.Method,
			URL:      f.URL,
			Host:     f.Host,
			Path:     f.Path,
			Status:   f.Status,
			Latency:  f.LatencyMs,
			BodyType: f.RespBodyType,
			Time:     f.Timestamp.Format("15:04:05.000"),
		},
		ReqHeaders:  f.ReqHeaders,
		ReqBody:     string(f.ReqBody),
		RespHeaders: f.RespHeaders,
		RespBody:    string(f.RespBody),
		Tags:        f.Tags,
		SignParams:  f.SignParams,
		SourceRef:   f.SourceRef,
	}

	if len(detail.SignParams) == 0 {
		detected := agent.DetectSignParams(f)
		if len(detected) > 0 {
			detail.SignParams = detected
		}
	}

	return detail, nil
}

func (a *App) ClearFlows() error {
	flows, _ := a.store.ListFlows(types.FlowFilter{Limit: 10000})
	for _, f := range flows {
		a.store.DeleteFlow(f.ID)
	}
	a.mu.Lock()
	a.flows = nil
	a.mu.Unlock()
	return nil
}

func (a *App) GetBodyHex(flowID string, isReq bool) (string, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return "", err
	}
	body := f.RespBody
	if isReq {
		body = f.ReqBody
	}
	if len(body) == 0 {
		return "(empty)", nil
	}
	return hex.EncodeToString(body), nil
}

// ==================== Export ====================

func (a *App) ExportCode(flowID, lang string) (string, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return "", err
	}
	return codegen.Generate(f, lang)
}

func (a *App) ExportAgent() (string, error) {
	flows, _ := a.store.ListFlows(types.FlowFilter{Limit: 500})
	out, err := agent.Format(flows, agent.FormatOptions{})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (a *App) GetLanguages() []string {
	return codegen.Languages()
}

// ==================== Android ====================

type DeviceInfo struct {
	Serial string `json:"serial"`
	State  string `json:"state"`
}

func (a *App) ListDevices() ([]DeviceInfo, error) {
	devs, err := android.ListDevices()
	if err != nil {
		return nil, err
	}
	result := make([]DeviceInfo, len(devs))
	for i, d := range devs {
		result[i] = DeviceInfo{Serial: d.Serial, State: d.State}
	}
	return result, nil
}

func (a *App) ConnectDevice(serial, port string, installCert bool) error {
	if port == "" {
		port = "8080"
	}
	var certPath string
	if installCert {
		var err error
		certPath, _, err = proxy.EnsureCA(a.certDir)
		if err != nil {
			return err
		}
	}
	return android.Setup(android.SetupOptions{
		ProxyPort:   port,
		Serial:      serial,
		CACertPath:  certPath,
		InstallCert: installCert,
	})
}

func (a *App) DisconnectDevice(serial string) error {
	return android.Teardown(serial)
}

// ==================== Replay ====================

type ReplayResult struct {
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Latency     int64             `json:"latency_ms"`
	StatusDiff  string            `json:"status_diff"`
	LatencyDiff int64             `json:"latency_diff"`
}

func (a *App) ReplayFlow(flowID string) (*ReplayResult, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}
	result, err := replay.Replay(f, replay.Options{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	rr := &ReplayResult{
		Status:  result.Replayed.Status,
		Headers: result.Replayed.RespHeaders,
		Body:    string(result.Replayed.RespBody),
		Latency: result.Replayed.LatencyMs,
	}
	if result.Diff != nil {
		rr.StatusDiff = result.Diff.StatusDiff
		rr.LatencyDiff = result.Diff.LatencyDiff
	}
	return rr, nil
}

// ==================== Sign Analysis ====================

type SignResult struct {
	ParamName    string   `json:"param_name"`
	Value        string   `json:"value"`
	Encoding     string   `json:"encoding"`
	PossibleAlgs []string `json:"possible_algs"`
	InputGuess   string   `json:"input_guess"`
	Confidence   float64  `json:"confidence"`
}

func (a *App) AnalyzeSign(flowID string) ([]SignResult, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}
	analyses := sign.AnalyzeSingle(f)
	result := make([]SignResult, len(analyses))
	for i, an := range analyses {
		result[i] = SignResult{
			ParamName:    an.ParamName,
			Value:        an.Value,
			Encoding:     an.Encoding,
			PossibleAlgs: an.PossibleAlgs,
			InputGuess:   an.InputGuess,
			Confidence:   an.Confidence,
		}
	}
	return result, nil
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

// ==================== Replay Modified ====================

type ModifyRequest struct {
	FlowID     string            `json:"flow_id"`
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	SetHeaders map[string]string `json:"set_headers"`
	DelHeaders []string          `json:"del_headers"`
	Body       string            `json:"body"`
}

func (a *App) ReplayModified(req ModifyRequest) (*ReplayResult, error) {
	f, err := a.store.GetFlow(req.FlowID)
	if err != nil {
		return nil, err
	}
	mods := replay.Modifications{
		URL:        req.URL,
		Method:     req.Method,
		SetHeaders: req.SetHeaders,
		DelHeaders: req.DelHeaders,
	}
	if req.Body != "" {
		mods.Body = []byte(req.Body)
	}
	result, err := replay.ReplayModified(f, mods, replay.Options{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	rr := &ReplayResult{
		Status:  result.Replayed.Status,
		Headers: result.Replayed.RespHeaders,
		Body:    string(result.Replayed.RespBody),
		Latency: result.Replayed.LatencyMs,
	}
	if result.Diff != nil {
		rr.StatusDiff = result.Diff.StatusDiff
		rr.LatencyDiff = result.Diff.LatencyDiff
	}
	return rr, nil
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

// ==================== Device Environment ====================

type DeviceEnv struct {
	Model       string `json:"model"`
	Brand       string `json:"brand"`
	Android     string `json:"android"`
	SDK         string `json:"sdk"`
	CPU         string `json:"cpu"`
	RAM         string `json:"ram"`
	Screen      string `json:"screen"`
	Kernel      string `json:"kernel"`
	Battery     string `json:"battery"`
	Rooted      bool   `json:"rooted"`
	RootMethod  string `json:"root_method"`
	Magisk      string `json:"magisk"`
	MagiskVer   string `json:"magisk_ver"`
	KernelSU    bool   `json:"kernelsu"`
	KernelSUVer string `json:"kernelsu_ver"`
	Zygisk      bool   `json:"zygisk"`
	LSPosed     bool   `json:"lsposed"`
	LSPosedVer  string `json:"lsposed_ver"`
	SELinux     string `json:"selinux"`
	Integrity   string `json:"integrity"`
	Fingerprint string `json:"fingerprint"`
}

func (a *App) GetDeviceEnv(serial string) (*DeviceEnv, error) {
	prop := func(key string) string {
		args := []string{}
		if serial != "" {
			args = append(args, "-s", serial)
		}
		args = append(args, "shell", "getprop", key)
		out, err := exec.Command("adb", args...).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}

	shell := func(cmd string) string {
		args := []string{}
		if serial != "" {
			args = append(args, "-s", serial)
		}
		args = append(args, "shell", cmd)
		out, _ := exec.Command("adb", args...).CombinedOutput()
		return strings.TrimSpace(string(out))
	}

	suShell := func(cmd string) string {
		args := []string{}
		if serial != "" {
			args = append(args, "-s", serial)
		}
		args = append(args, "shell", fmt.Sprintf("su -c '%s'", cmd))
		out, _ := exec.Command("adb", args...).CombinedOutput()
		return strings.TrimSpace(string(out))
	}

	env := &DeviceEnv{
		Model:       prop("ro.product.model"),
		Brand:       prop("ro.product.brand"),
		Android:     prop("ro.build.version.release"),
		SDK:         prop("ro.build.version.sdk"),
		CPU:         prop("ro.product.cpu.abi"),
		Kernel:      shell("uname -r"),
		Fingerprint: prop("ro.build.fingerprint"),
	}

	// Screen
	env.Screen = shell("wm size")
	if idx := strings.Index(env.Screen, ": "); idx >= 0 {
		env.Screen = env.Screen[idx+2:]
	}

	// RAM
	memInfo := shell("cat /proc/meminfo | head -1")
	if strings.Contains(memInfo, "MemTotal") {
		parts := strings.Fields(memInfo)
		if len(parts) >= 2 {
			kb := 0
			fmt.Sscanf(parts[1], "%d", &kb)
			env.RAM = fmt.Sprintf("%.1f GB", float64(kb)/1048576.0)
		}
	}

	// Battery
	battInfo := shell("dumpsys battery | grep level")
	if strings.Contains(battInfo, "level") {
		parts := strings.Split(battInfo, ":")
		if len(parts) >= 2 {
			env.Battery = strings.TrimSpace(parts[1]) + "%"
		}
	}

	// Root check
	rootCheck := shell("su -c id")
	env.Rooted = strings.Contains(rootCheck, "uid=0")
	if env.Rooted {
		env.RootMethod = "su"
	}

	// Magisk
	magiskVer := suShell("magisk -v")
	if magiskVer != "" && !strings.Contains(magiskVer, "not found") && !strings.Contains(magiskVer, "error") {
		env.Magisk = "installed"
		env.MagiskVer = magiskVer
		env.RootMethod = "Magisk"
	} else {
		magiskDir := suShell("ls /data/adb/magisk/")
		if magiskDir != "" && !strings.Contains(magiskDir, "No such") {
			env.Magisk = "installed"
			env.RootMethod = "Magisk"
		} else {
			env.Magisk = "not found"
		}
	}

	// KernelSU
	ksuVer := shell("ksud --version 2>/dev/null")
	if ksuVer != "" && !strings.Contains(ksuVer, "not found") {
		env.KernelSU = true
		env.KernelSUVer = ksuVer
		if env.RootMethod == "su" {
			env.RootMethod = "KernelSU"
		}
	} else {
		ksuDir := suShell("ls /data/adb/ksu/ 2>/dev/null")
		if ksuDir != "" && !strings.Contains(ksuDir, "No such") {
			env.KernelSU = true
			env.RootMethod = "KernelSU"
		} else {
			ksuModule := shell("ls /data/adb/modules/.kernelsu 2>/dev/null")
			if ksuModule != "" && !strings.Contains(ksuModule, "No such") {
				env.KernelSU = true
			}
		}
	}

	// Zygisk
	zygiskProp := prop("persist.magisk.zygisk")
	if zygiskProp == "1" {
		env.Zygisk = true
	} else {
		zygiskCheck := suShell("ls /data/adb/modules/zygisksu 2>/dev/null || ls /data/adb/modules/zygisk* 2>/dev/null")
		env.Zygisk = zygiskCheck != "" && !strings.Contains(zygiskCheck, "No such")
	}

	// LSPosed
	lsposedCheck := shell("pm list packages 2>/dev/null | grep lspd")
	if strings.Contains(lsposedCheck, "lspd") {
		env.LSPosed = true
	} else {
		lspdDir := suShell("ls /data/adb/lspd/ 2>/dev/null || ls /data/adb/modules/lsposed* 2>/dev/null")
		env.LSPosed = lspdDir != "" && !strings.Contains(lspdDir, "No such")
	}
	if env.LSPosed {
		env.LSPosedVer = suShell("cat /data/adb/lspd/manager/version 2>/dev/null")
	}

	// SELinux
	env.SELinux = shell("getenforce")

	// Google Play Integrity (basic check)
	gmsVer := shell("dumpsys package com.google.android.gms 2>/dev/null | grep versionName | head -1")
	if strings.Contains(gmsVer, "versionName") {
		parts := strings.Split(gmsVer, "=")
		if len(parts) >= 2 {
			env.Integrity = "GMS " + strings.TrimSpace(parts[1])
		}
	}
	// Check if device passes basic integrity
	integrityCheck := prop("ro.boot.verifiedbootstate")
	if integrityCheck != "" {
		env.Integrity += " | boot=" + integrityCheck
	}

	return env, nil
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

// ==================== RE Tools ====================

type AppDetail struct {
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	TargetSDK   string   `json:"target_sdk"`
	MinSDK      string   `json:"min_sdk"`
	Permissions []string `json:"permissions"`
	Activities  []string `json:"activities"`
	Services    []string `json:"services"`
	Receivers   []string `json:"receivers"`
	NativeLibs  []string `json:"native_libs"`
	APKPath     string   `json:"apk_path"`
	DataDir     string   `json:"data_dir"`
	UID         string   `json:"uid"`
	Debuggable  bool     `json:"debuggable"`
}

func (a *App) InspectApp(serial, pkg string) (*AppDetail, error) {
	shell := func(cmd string) string {
		args := []string{}
		if serial != "" {
			args = append(args, "-s", serial)
		}
		args = append(args, "shell", cmd)
		out, _ := exec.Command("adb", args...).CombinedOutput()
		return strings.TrimSpace(string(out))
	}

	dump := shell(fmt.Sprintf("dumpsys package %s", pkg))
	detail := &AppDetail{Package: pkg}

	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "versionName=") {
			detail.Version = strings.TrimPrefix(line, "versionName=")
		} else if strings.HasPrefix(line, "targetSdk=") {
			detail.TargetSDK = strings.TrimPrefix(line, "targetSdk=")
		} else if strings.HasPrefix(line, "minSdk=") {
			detail.MinSDK = strings.TrimPrefix(line, "minSdk=")
		} else if strings.HasPrefix(line, "codePath=") {
			detail.APKPath = strings.TrimPrefix(line, "codePath=")
		} else if strings.HasPrefix(line, "dataDir=") {
			detail.DataDir = strings.TrimPrefix(line, "dataDir=")
		} else if strings.HasPrefix(line, "userId=") {
			detail.UID = strings.TrimPrefix(line, "userId=")
		} else if strings.Contains(line, "android.permission.") {
			perm := line
			if idx := strings.Index(perm, "android.permission."); idx >= 0 {
				perm = perm[idx:]
				if spIdx := strings.IndexAny(perm, " :"); spIdx > 0 {
					perm = perm[:spIdx]
				}
				detail.Permissions = append(detail.Permissions, perm)
			}
		} else if strings.Contains(line, "flags=") && strings.Contains(line, "DEBUGGABLE") {
			detail.Debuggable = true
		}
	}

	// Activities
	actDump := shell(fmt.Sprintf("cmd package query-activities --brief %s 2>/dev/null || dumpsys package %s | grep -A1 'Activity Resolver'", pkg, pkg))
	for _, line := range strings.Split(actDump, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, pkg) && strings.Contains(line, "/") {
			detail.Activities = append(detail.Activities, line)
		}
	}

	// Services
	svcDump := shell(fmt.Sprintf("dumpsys package %s | grep '%s' | grep -i service", pkg, pkg))
	for _, line := range strings.Split(svcDump, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, pkg) && len(line) > 5 {
			detail.Services = append(detail.Services, line)
		}
	}

	// Native libs
	libDump := shell(fmt.Sprintf("ls %s/lib/arm64/ 2>/dev/null || ls %s/lib/arm/ 2>/dev/null", detail.APKPath, detail.APKPath))
	for _, line := range strings.Split(libDump, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, ".so") {
			detail.NativeLibs = append(detail.NativeLibs, line)
		}
	}

	return detail, nil
}

type ProcessInfo struct {
	PID  string `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
}

func (a *App) ListProcesses(serial string) ([]ProcessInfo, error) {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "ps -A -o PID,USER,NAME 2>/dev/null || ps")
	out, err := exec.Command("adb", args...).Output()
	if err != nil {
		return nil, err
	}
	var procs []ProcessInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] != "PID" {
			procs = append(procs, ProcessInfo{PID: fields[0], User: fields[1], Name: fields[2]})
		}
	}
	return procs, nil
}

func (a *App) PullAPK(serial, pkg string) (string, error) {
	shell := func(cmd string) string {
		args := []string{}
		if serial != "" {
			args = append(args, "-s", serial)
		}
		args = append(args, "shell", cmd)
		out, _ := exec.Command("adb", args...).Output()
		return strings.TrimSpace(string(out))
	}

	pathOut := shell(fmt.Sprintf("pm path %s", pkg))
	apkPath := ""
	for _, line := range strings.Split(pathOut, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "package:") {
			apkPath = strings.TrimPrefix(strings.TrimSpace(line), "package:")
			break
		}
	}
	if apkPath == "" {
		return "", fmt.Errorf("package %s not found", pkg)
	}

	localDir := filepath.Join(a.certDir, "apks")
	os.MkdirAll(localDir, 0755)
	localPath := filepath.Join(localDir, pkg+".apk")

	pullArgs := []string{}
	if serial != "" {
		pullArgs = append(pullArgs, "-s", serial)
	}
	pullArgs = append(pullArgs, "pull", apkPath, localPath)
	if err := exec.Command("adb", pullArgs...).Run(); err != nil {
		return "", err
	}
	return localPath, nil
}

func (a *App) CheckFrida(serial string) map[string]string {
	result := map[string]string{"status": "not running"}

	adbShell := func(cmd string) string {
		args := []string{}
		if serial != "" {
			args = append(args, "-s", serial)
		}
		args = append(args, "shell", cmd)
		out, _ := exec.Command("adb", args...).CombinedOutput()
		return strings.TrimSpace(string(out))
	}

	psOut := adbShell("ps -A 2>/dev/null | grep frida || ps | grep frida")
	if strings.Contains(psOut, "frida") {
		result["status"] = "running"
		for _, line := range strings.Split(psOut, "\n") {
			if strings.Contains(line, "frida") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					result["pid"] = fields[1]
				}
				break
			}
		}
	}

	binOut := adbShell("ls /data/local/tmp/frida-server* 2>/dev/null")
	if binOut != "" && !strings.Contains(binOut, "No such") {
		result["binary"] = binOut
	}

	return result
}

func (a *App) StartFrida(serial string) (string, error) {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "su -c 'nohup /data/local/tmp/frida-server -D > /dev/null 2>&1 &'")
	out, err := exec.Command("adb", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (a *App) RunLogcat(serial, filter string, lines int) (string, error) {
	if lines <= 0 {
		lines = 100
	}
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "logcat", "-d", "-t", fmt.Sprintf("%d", lines))
	if filter != "" {
		args = append(args, "-s", filter)
	}
	out, err := exec.Command("adb", args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ==================== Deep Trace ====================

func (a *App) DeepTrace(flowID, packageName string) (*captrace.TraceResult, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}

	devices, _ := android.ListDevices()
	serial := ""
	if len(devices) > 0 {
		serial = devices[0].Serial
	}

	return captrace.Trace(f, captrace.Options{
		Serial:    serial,
		OutputDir: filepath.Join(a.certDir, "trace", packageName),
		Package:   packageName,
	})
}

func (a *App) GetTraceMermaid(flowID, packageName string) (string, error) {
	result, err := a.DeepTrace(flowID, packageName)
	if err != nil {
		return "", err
	}
	return result.Mermaid, nil
}

// ==================== Device Screen ====================

func (a *App) CaptureScreen(serial string) (string, error) {
	return a.CaptureScreenScaled(serial, 50)
}

func (a *App) CaptureScrcpy(serial string) (string, error) {
	data, err := screen.Capture(screen.Options{
		Serial:  serial,
		Engine:  screen.EngineScrcpy,
		MaxSize: 540,
		Quality: 70,
	})
	if err != nil {
		return "", err
	}
	return "data:image/jpeg;base64," + base64Encode(data), nil
}

func (a *App) DeployScrcpy(serial string) (string, error) {
	cacheDir, _ := screen.DefaultCacheDir()
	if err := screen.DeployScrcpyServer(serial, cacheDir); err != nil {
		return "", err
	}
	return "scrcpy-server deployed", nil
}

func (a *App) IsScrcpyReady(serial string) bool {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return false
	}
	return screen.IsScrcpyDeployed(serial)
}

func (a *App) CaptureScreenScaled(serial string, quality int) (string, error) {
	maxSize := 540
	if quality > 80 {
		maxSize = 720
	} else if quality > 60 {
		maxSize = 540
	} else if quality > 40 {
		maxSize = 400
	} else {
		maxSize = 320
	}

	jpegData, err := screen.FastCapture(serial, maxSize, quality)
	if err != nil {
		// Fallback to old screencap -p method
		args := []string{}
		if serial != "" {
			args = append(args, "-s", serial)
		}
		args = append(args, "exec-out", "screencap", "-p")
		out, fallbackErr := exec.Command("adb", args...).Output()
		if fallbackErr != nil {
			return "", fmt.Errorf("screencap: %w (fast: %v)", fallbackErr, err)
		}
		return "data:image/png;base64," + base64Encode(out), nil
	}

	return "data:image/jpeg;base64," + base64Encode(jpegData), nil
}

func (a *App) DeviceTap(serial string, x, y int) error {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "input", "tap", fmt.Sprintf("%d", x), fmt.Sprintf("%d", y))
	return exec.Command("adb", args...).Run()
}

func (a *App) DeviceSwipe(serial string, x1, y1, x2, y2, duration int) error {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "input", "swipe",
		fmt.Sprintf("%d", x1), fmt.Sprintf("%d", y1),
		fmt.Sprintf("%d", x2), fmt.Sprintf("%d", y2),
		fmt.Sprintf("%d", duration))
	return exec.Command("adb", args...).Run()
}

func (a *App) DeviceBack(serial string) error {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "input", "keyevent", "4")
	return exec.Command("adb", args...).Run()
}

func (a *App) DeviceHome(serial string) error {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "input", "keyevent", "3")
	return exec.Command("adb", args...).Run()
}

func (a *App) GetScreenSize(serial string) ([]int, error) {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "shell", "wm", "size")
	out, err := exec.Command("adb", args...).Output()
	if err != nil {
		return nil, err
	}
	// Parse "Physical size: 1080x2400"
	s := strings.TrimSpace(string(out))
	parts := strings.Split(s, ": ")
	if len(parts) < 2 {
		return []int{1080, 2400}, nil
	}
	dims := strings.Split(parts[len(parts)-1], "x")
	if len(dims) < 2 {
		return []int{1080, 2400}, nil
	}
	w := 1080
	h := 2400
	fmt.Sscanf(dims[0], "%d", &w)
	fmt.Sscanf(dims[1], "%d", &h)
	return []int{w, h}, nil
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// ==================== API Grouping ====================

func (a *App) GetAPIGroups() []grouping.APIGroup {
	flows, _ := a.store.ListFlows(types.FlowFilter{Limit: 5000})
	return grouping.GroupFlows(flows)
}

// ==================== Import ====================

func (a *App) ImportHARFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	flows, err := importer.ImportHAR(f)
	if err != nil {
		return 0, err
	}
	for _, fl := range flows {
		a.store.SaveFlow(fl)
	}
	return len(flows), nil
}

// ==================== Compare ====================

func (a *App) CompareFlows(idA, idB string) (*compare.Comparison, error) {
	fA, err := a.store.GetFlow(idA)
	if err != nil {
		return nil, fmt.Errorf("flow %s: %w", idA, err)
	}
	fB, err := a.store.GetFlow(idB)
	if err != nil {
		return nil, fmt.Errorf("flow %s: %w", idB, err)
	}
	return compare.Compare(fA, fB), nil
}

// ==================== Protobuf ====================

func (a *App) DecodeProtobuf(flowID string, isReq bool) (string, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return "", err
	}
	body := f.RespBody
	if isReq {
		body = f.ReqBody
	}
	if len(body) == 0 {
		return "(empty)", nil
	}
	if !proto.IsProtobuf(body) {
		return "(not protobuf data)", nil
	}
	fields, err := proto.Decode(body)
	if err != nil {
		return "", err
	}
	return proto.FormatFields(fields, ""), nil
}

// ==================== Traffic Stats ====================

func (a *App) GetTrafficStats() *stats.Summary {
	flows, _ := a.store.ListFlows(types.FlowFilter{Limit: 10000})
	return stats.Compute(flows)
}

// ==================== Sequences ====================

func (a *App) CreateSequence(name string, flowIDs []string) error {
	var flows []*types.Flow
	for _, id := range flowIDs {
		f, err := a.store.GetFlow(id)
		if err != nil {
			return err
		}
		flows = append(flows, f)
	}
	seq := sequence.FromFlows(name, flows)
	return sequence.Save(seq, filepath.Join(a.certDir, "sequences"))
}

func (a *App) ListSequences() ([]string, error) {
	return sequence.ListSaved(filepath.Join(a.certDir, "sequences"))
}

func (a *App) ReplaySequence(name string) (*sequence.ReplayResult, error) {
	seq, err := sequence.Load(name, filepath.Join(a.certDir, "sequences"))
	if err != nil {
		return nil, err
	}
	return sequence.Replay(seq, sequence.ReplayOptions{Timeout: 30 * time.Second})
}
