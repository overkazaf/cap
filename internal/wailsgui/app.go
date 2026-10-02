package wailsgui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/export/agent"
	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/replay"
	"github.com/overkazaf/cap/internal/sign"
	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
)

type App struct {
	ctx   context.Context
	store store.Store
	proxy *proxy.Proxy
	mu    sync.Mutex

	flows     []*types.Flow
	isRunning bool
	certDir   string
}

func NewApp(st store.Store) *App {
	home, _ := os.UserHomeDir()
	return &App{
		store:   st,
		certDir: filepath.Join(home, ".cap"),
	}
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	proxy.EnsureCA(a.certDir)
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

	p, err := proxy.New(proxy.Options{
		Addr:    addr,
		CertDir: a.certDir,
		OnFlow: func(f *types.Flow) {
			a.store.SaveFlow(f)
			a.mu.Lock()
			a.flows = append([]*types.Flow{f}, a.flows...)
			a.mu.Unlock()
		},
	})
	if err != nil {
		return err
	}

	a.proxy = p
	a.isRunning = true
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
		limit = 200
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
	return &FlowDetail{
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
	}, nil
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
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", nil
	}
	c := exec.Command(parts[0], parts[1:]...)
	c.Env = os.Environ()
	out, err := c.CombinedOutput()
	result := strings.TrimRight(string(out), "\n")
	if err != nil && result == "" {
		return "", err
	}
	return result, nil
}

// ==================== Utils ====================

func (a *App) GetHostIP() string {
	addrs := strings.Split(a.ProxyAddr(), ":")
	if len(addrs) > 0 && addrs[0] != "" && addrs[0] != "0.0.0.0" {
		return addrs[0]
	}
	return "auto"
}
