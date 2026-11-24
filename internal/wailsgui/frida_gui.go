package wailsgui

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/frida"
	"github.com/overkazaf/cap/internal/unpin"
)

// ==================== Frida Workbench ====================

// FridaDeployRequest configures deploying frida-server to an Android device from GUI.
type FridaDeployRequest struct {
	Serial          string `json:"serial"`
	Version         string `json:"version"`
	Arch            string `json:"arch"`
	LocalBinaryPath string `json:"local_binary_path"`
	RemoteName      string `json:"remote_name"`
	Port            int    `json:"port"`
	AutoStart       bool   `json:"auto_start"`
	ForwardPort     bool   `json:"forward_port"`
}

// FridaStartRequest configures starting frida-server on an Android device.
type FridaStartRequest struct {
	Serial      string `json:"serial"`
	BinaryPath  string `json:"binary_path"`
	Port        int    `json:"port"`
	ListenHost  string `json:"listen_host"`
	ForwardPort bool   `json:"forward_port"`
}

func (a *App) ensureFridaManager() (*frida.Manager, error) {
	a.mu.Lock()
	mgr := a.fridaMgr
	capDir := a.certDir
	pyPath := a.settings["frida_python_path"]
	cliPath := a.settings["frida_cli_path"]
	a.mu.Unlock()

	if mgr != nil {
		return mgr, nil
	}
	created, err := frida.NewManager(capDir)
	if err != nil {
		return nil, err
	}
	created.SetToolchainConfig(frida.ToolchainConfig{
		PythonPath: pyPath,
		FridaPath:  cliPath,
	})
	if a.events != nil {
		created.SetCallbacks(
			func(ev frida.LogEvent) {
				a.events.Emit(EventFridaLog, ev)
			},
			func(st *frida.SessionState) {
				a.events.Emit(EventFridaStatus, st)
			},
		)
	}
	a.mu.Lock()
	if a.fridaMgr == nil {
		a.fridaMgr = created
	}
	mgr = a.fridaMgr
	a.mu.Unlock()
	return mgr, nil
}

func (a *App) defaultFridaPort() int {
	a.mu.Lock()
	raw := strings.TrimSpace(a.settings["frida_default_port"])
	a.mu.Unlock()
	if p, err := strconv.Atoi(raw); err == nil && p > 0 && p <= 65535 {
		return p
	}
	return frida.DefaultPort
}

// CheckFrida preserves the legacy Capture-tab signature while returning enriched
// status metadata (pid, binary, version, arch, port, version_match).
func (a *App) CheckFrida(serial string) map[string]string {
	result := map[string]string{"status": "not running"}
	hostVer := ""
	if mgr, err := a.ensureFridaManager(); err == nil {
		tc := mgr.GetToolchain(false)
		hostVer = tc.FridaVersion
		if hostVer == "" {
			hostVer = tc.FridaCLIVersion
		}
	}
	st, err := frida.CheckServer(serial, a.defaultFridaPort(), hostVer)
	if err != nil || st == nil {
		return result
	}
	if st.Running {
		result["status"] = "running"
		if st.PID != "" {
			result["pid"] = st.PID
		}
	}
	if st.BinaryPath != "" {
		result["binary"] = st.BinaryPath
	}
	if st.ServerVersion != "" {
		result["version"] = st.ServerVersion
	}
	if st.FridaArch != "" {
		result["arch"] = st.FridaArch
	}
	if st.VersionMatch != "" {
		result["version_match"] = st.VersionMatch
	}
	if st.Port > 0 {
		result["port"] = strconv.Itoa(st.Port)
	}
	return result
}

// StartFrida preserves the legacy Capture-tab signature and starts frida-server.
func (a *App) StartFrida(serial string) (string, error) {
	st, err := a.StartFridaServer(FridaStartRequest{
		Serial:      serial,
		Port:        a.defaultFridaPort(),
		ForwardPort: true,
	})
	if err != nil {
		return "", err
	}
	if st != nil && st.Running {
		return fmt.Sprintf("frida-server running (PID %s)", st.PID), nil
	}
	return "frida-server start signal sent", nil
}

// GetFridaToolchain inspects host Python/Frida/CLI readiness.
func (a *App) GetFridaToolchain(forceRefresh bool) frida.ToolchainInfo {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return frida.ToolchainInfo{
			Driver: frida.DriverNone,
			Issues: []string{err.Error()},
		}
	}
	return mgr.GetToolchain(forceRefresh)
}

// UpdateFridaToolchainConfig persists custom python3 / frida CLI paths and re-probes immediately.
func (a *App) UpdateFridaToolchainConfig(pythonPath, fridaCLIPath string) (frida.ToolchainInfo, error) {
	if err := a.SetSetting("frida_python_path", strings.TrimSpace(pythonPath)); err != nil {
		return frida.ToolchainInfo{}, err
	}
	if err := a.SetSetting("frida_cli_path", strings.TrimSpace(fridaCLIPath)); err != nil {
		return frida.ToolchainInfo{}, err
	}
	return a.GetFridaToolchain(true), nil
}

// GetFridaServerStatus probes frida-server status, ABI, version match & port on device.
func (a *App) GetFridaServerStatus(serial string, port int) (*frida.ServerStatus, error) {
	if port <= 0 {
		port = a.defaultFridaPort()
	}
	hostVer := ""
	if mgr, err := a.ensureFridaManager(); err == nil {
		tc := mgr.GetToolchain(false)
		hostVer = tc.FridaVersion
		if hostVer == "" {
			hostVer = tc.FridaCLIVersion
		}
	}
	return frida.CheckServer(serial, port, hostVer)
}

// DeployFridaServer downloads (matching host version/ABI) or pushes a local binary to device.
func (a *App) DeployFridaServer(req FridaDeployRequest) (*frida.DeployResult, error) {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return nil, err
	}
	version := strings.TrimSpace(req.Version)
	if version == "" && strings.TrimSpace(req.LocalBinaryPath) == "" {
		tc := mgr.GetToolchain(false)
		if tc.FridaVersion != "" {
			version = tc.FridaVersion
		} else if tc.FridaCLIVersion != "" {
			version = tc.FridaCLIVersion
		}
	}
	port := req.Port
	if port <= 0 {
		port = a.defaultFridaPort()
	}
	return frida.DeployServer(context.Background(), frida.DeployOptions{
		Serial:          req.Serial,
		Version:         version,
		Arch:            req.Arch,
		LocalBinaryPath: req.LocalBinaryPath,
		RemoteName:      req.RemoteName,
		Port:            port,
		AutoStart:       req.AutoStart,
		ForwardPort:     req.ForwardPort,
		CacheDir:        mgr.CacheDir(),
		OnProgress: func(ev frida.DeployProgressEvent) {
			if a.events != nil {
				a.events.Emit(EventFridaDeployProgress, ev)
			}
		},
	})
}

// StartFridaServer starts frida-server on the target Android device.
func (a *App) StartFridaServer(req FridaStartRequest) (*frida.ServerStatus, error) {
	port := req.Port
	if port <= 0 {
		port = a.defaultFridaPort()
	}
	hostVer := ""
	if mgr, err := a.ensureFridaManager(); err == nil {
		tc := mgr.GetToolchain(false)
		hostVer = tc.FridaVersion
		if hostVer == "" {
			hostVer = tc.FridaCLIVersion
		}
	}
	return frida.StartServer(frida.StartServerOptions{
		Serial:      req.Serial,
		BinaryPath:  req.BinaryPath,
		Port:        port,
		ListenHost:  req.ListenHost,
		ForwardPort: req.ForwardPort,
		HostVersion: hostVer,
	})
}

// StopFridaServer stops running frida-server on the target Android device.
func (a *App) StopFridaServer(serial, binaryName string, port int) (*frida.ServerStatus, error) {
	if port <= 0 {
		port = a.defaultFridaPort()
	}
	hostVer := ""
	if mgr, err := a.ensureFridaManager(); err == nil {
		tc := mgr.GetToolchain(false)
		hostVer = tc.FridaVersion
	}
	return frida.StopServer(serial, binaryName, port, hostVer)
}

// ListFridaProcesses enumerates installed apps and running processes on device.
func (a *App) ListFridaProcesses(serial, remoteHost string) ([]frida.ProcessEntry, error) {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return nil, err
	}
	tc := mgr.GetToolchain(false)
	return frida.ListProcesses(context.Background(), serial, remoteHost, tc)
}

// ==================== Frida Script Library ====================

func (a *App) ListFridaScripts() []frida.Script {
	mgr, err := a.ensureFridaManager()
	if err != nil || mgr.Scripts() == nil {
		return frida.BuiltinScripts()
	}
	return mgr.Scripts().List()
}

func (a *App) SaveFridaScript(sc frida.Script) (*frida.Script, error) {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return nil, err
	}
	return mgr.Scripts().Save(sc)
}

func (a *App) DeleteFridaScript(id string) error {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return err
	}
	return mgr.Scripts().Delete(id)
}

func (a *App) ReloadFridaScripts() ([]frida.Script, error) {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return nil, err
	}
	if err := mgr.Scripts().Reload(); err != nil {
		return nil, err
	}
	return mgr.Scripts().List(), nil
}

func (a *App) GetFridaScriptDir() string {
	mgr, err := a.ensureFridaManager()
	if err != nil || mgr.Scripts() == nil {
		return ""
	}
	return mgr.Scripts().Dir()
}

// ==================== Live Hook Sessions ====================

func (a *App) StartFridaSession(cfg frida.SessionConfig) (*frida.SessionState, error) {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return nil, err
	}
	return mgr.StartSession(cfg)
}

func (a *App) StopFridaSession() error {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return err
	}
	return mgr.StopSession()
}

func (a *App) ReloadFridaSessionScript(code string) error {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return err
	}
	return mgr.ReloadScript(code)
}

func (a *App) ResumeFridaSession() error {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return err
	}
	return mgr.ResumeSession()
}

func (a *App) GetFridaSessionState() *frida.SessionState {
	mgr, err := a.ensureFridaManager()
	if err != nil {
		return &frida.SessionState{Status: frida.StatusIdle, Events: []frida.LogEvent{}}
	}
	return mgr.GetSessionState()
}

func (a *App) ClearFridaSessionLogs() {
	if mgr, err := a.ensureFridaManager(); err == nil {
		mgr.ClearLogs()
	}
}

// ==================== CodeShare & App Fingerprinting ====================

func (a *App) SearchFridaCodeShare(query string) ([]unpin.CodeShareEntry, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return a.BrowseFridaCodeShare(1)
	}
	return unpin.NewCodeShareClient().Search(query)
}

func (a *App) BrowseFridaCodeShare(page int) ([]unpin.CodeShareEntry, error) {
	return unpin.NewCodeShareClient().Browse(page)
}

func (a *App) FetchFridaCodeShareScript(slug string) (*unpin.CodeShareScript, error) {
	return unpin.NewCodeShareClient().FetchScript(slug)
}

// FingerprintDeviceApp inspects an installed Android package's native libraries
// and characteristics, returning its AppFingerprint and recommended CodeShare scripts.
type AppFingerprintBundle struct {
	Fingerprint *unpin.AppFingerprint  `json:"fingerprint"`
	Scripts     []unpin.CodeShareEntry `json:"scripts"`
}

func (a *App) FingerprintDeviceApp(serial, pkg string, searchCodeShare bool) (*AppFingerprintBundle, error) {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return nil, fmt.Errorf("package name is required")
	}
	resolved, err := android.GetDeviceSerial(serial)
	if err != nil {
		return nil, err
	}
	pathOut, err := android.AdbShell(resolved, fmt.Sprintf("pm path %s", pkg))
	if err != nil {
		return nil, fmt.Errorf("pm path %s: %w", pkg, err)
	}
	apkPath := ""
	for _, line := range strings.Split(pathOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			apkPath = strings.TrimPrefix(line, "package:")
			break
		}
	}
	var soFiles, classes []string
	if apkPath != "" {
		apkDir := apkPath
		if idx := strings.LastIndex(apkPath, "/"); idx > 0 {
			apkDir = apkPath[:idx]
		}
		libOut, _ := android.AdbShell(resolved, fmt.Sprintf("ls %s/lib/arm64/ %s/lib/arm/ %s/lib/x86_64/ 2>/dev/null || true", apkDir, apkDir, apkDir))
		for _, line := range strings.Split(libOut, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasSuffix(line, ".so") {
				soFiles = append(soFiles, line)
			}
		}
	}
	fp := unpin.BuildFingerprint(pkg, soFiles, classes)
	bundle := &AppFingerprintBundle{
		Fingerprint: fp,
		Scripts:     []unpin.CodeShareEntry{},
	}
	if searchCodeShare {
		if entries, searchErr := unpin.SearchForApp(fp); searchErr == nil {
			bundle.Scripts = entries
		}
	}
	return bundle, nil
}

// ==================== DeepTrace -> Frida Hook Generator ====================

// GenerateFridaHookFromTrace generates a tailored Frida JS hook script from the
// most recent DeepTrace run stored in App.
func (a *App) GenerateFridaHookFromTrace(opts frida.HookGenOptions) (*frida.GeneratedHook, error) {
	a.traceMu.Lock()
	var res = a.traceState
	a.traceMu.Unlock()

	if res == nil || res.Result == nil {
		return nil, fmt.Errorf("no completed DeepTrace result available — run DeepTrace first")
	}
	return frida.GenerateHookFromTrace(res.Result, opts), nil
}

// GenerateFridaHookForTargets generates a focused Frida JS script for explicit
// Java/Native targets (e.g. from clicking "Hook" on a single module or SO export in DeepTrace).
func (a *App) GenerateFridaHookForTargets(pkg, title string, targets []frida.HookTarget, includeBacktrace bool) (*frida.GeneratedHook, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one hook target is required")
	}
	return frida.GenerateHookForTargets(pkg, title, targets, includeBacktrace), nil
}
