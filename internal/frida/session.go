package frida

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Manager owns the Frida script store, toolchain configuration, and active
// instrumentation session lifecycle.
type Manager struct {
	scripts  *ScriptStore
	cacheDir string

	tcMu   sync.RWMutex
	tcCfg  ToolchainConfig
	tcInfo *ToolchainInfo

	mu      sync.Mutex
	active  *activeSession
	state   *SessionState
	seq     atomic.Int64
	onEvent func(LogEvent)
	onState func(*SessionState)
}

type activeSession struct {
	id         string
	driver     string
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	stdin      io.WriteCloser
	stdinMu    sync.Mutex
	tempFiles  []string
	stopping   atomic.Bool
	doneCh     chan struct{}
}

// NewManager creates a Manager backed by capDir (e.g. ~/.cap).
func NewManager(capDir string) (*Manager, error) {
	scriptsDir := filepath.Join(capDir, "frida-scripts")
	store, err := NewScriptStore(scriptsDir)
	if err != nil {
		return nil, err
	}
	cacheDir := filepath.Join(capDir, "frida-cache")
	_ = os.MkdirAll(cacheDir, 0755)
	return &Manager{
		scripts:  store,
		cacheDir: cacheDir,
		state: &SessionState{
			Status: StatusIdle,
			Events: []LogEvent{},
		},
	}, nil
}

// SetCallbacks installs optional real-time event and status listeners (used by Wails GUI).
func (m *Manager) SetCallbacks(onEvent func(LogEvent), onState func(*SessionState)) {
	m.mu.Lock()
	m.onEvent = onEvent
	m.onState = onState
	m.mu.Unlock()
}

// SetToolchainConfig updates custom python3 / frida binary paths and invalidates cached probe.
func (m *Manager) SetToolchainConfig(cfg ToolchainConfig) {
	m.tcMu.Lock()
	m.tcCfg = cfg
	m.tcInfo = nil
	m.tcMu.Unlock()
}

// GetToolchain returns host Frida toolchain readiness (re-probing when forceRefresh is true).
func (m *Manager) GetToolchain(forceRefresh bool) ToolchainInfo {
	m.tcMu.RLock()
	cached := m.tcInfo
	cfg := m.tcCfg
	m.tcMu.RUnlock()
	if cached != nil && !forceRefresh {
		return *cached
	}
	info := DetectToolchain(cfg)
	m.tcMu.Lock()
	m.tcInfo = &info
	m.tcMu.Unlock()
	return info
}

// Scripts returns the persistent script store.
func (m *Manager) Scripts() *ScriptStore {
	return m.scripts
}

// CacheDir returns the frida-server download cache directory.
func (m *Manager) CacheDir() string {
	return m.cacheDir
}

// GetSessionState returns a thread-safe snapshot of the active or most recent session.
func (m *Manager) GetSessionState() *SessionState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneSessionState(m.state)
}

// ClearLogs clears recorded log events on the current session snapshot.
func (m *Manager) ClearLogs() {
	m.mu.Lock()
	if m.state != nil {
		m.state.Events = []LogEvent{}
		m.state.EventCount = 0
		m.state.HookCount = 0
		m.state.ErrorCount = 0
	}
	snap := cloneSessionState(m.state)
	onState := m.onState
	m.mu.Unlock()
	if onState != nil {
		onState(snap)
	}
}

// StartSession launches a live Frida instrumentation session using Python Bridge
// (preferred) or frida-cli fallback. Any previous running session is stopped cleanly first.
func (m *Manager) StartSession(cfg SessionConfig) (*SessionState, error) {
	cfg.Target = strings.TrimSpace(cfg.Target)
	if cfg.Target == "" {
		return nil, fmt.Errorf("target package name or PID is required")
	}
	if strings.TrimSpace(cfg.ScriptCode) == "" {
		return nil, fmt.Errorf("Frida JavaScript code is required")
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode != ModeSpawn && mode != ModeAttach {
		mode = ModeAttach
	}
	cfg.Mode = mode

	if cfg.RemoteHost == "" && cfg.Port > 0 && cfg.Port != DefaultPort {
		cfg.RemoteHost = fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	}

	// Determine toolchain & driver
	tcCfg := m.currentToolchainConfig()
	if cfg.PythonPath != "" {
		tcCfg.PythonPath = cfg.PythonPath
	}
	if cfg.FridaPath != "" {
		tcCfg.FridaPath = cfg.FridaPath
	}
	tc := DetectToolchain(tcCfg)

	driver := strings.ToLower(strings.TrimSpace(cfg.Driver))
	if driver == "" || driver == DriverAuto {
		driver = tc.Driver
	}
	if driver == DriverPythonBridge && !tc.FridaModuleOK {
		if tc.FridaCLIOK {
			driver = DriverFridaCLI
		} else {
			return nil, fmt.Errorf("Python `frida` module not available (%s)", strings.Join(tc.Issues, "; "))
		}
	}
	if driver == DriverFridaCLI && !tc.FridaCLIOK {
		return nil, fmt.Errorf("frida CLI not available (%s)", strings.Join(tc.Issues, "; "))
	}
	if driver == DriverNone {
		msg := "no Frida runtime available on host — install with: pip3 install frida-tools"
		if len(tc.Issues) > 0 {
			msg = strings.Join(tc.Issues, "; ")
		}
		return nil, fmt.Errorf("%s", msg)
	}

	// Stop any existing running session before starting a new one
	_ = m.StopSession()

	sessionID := fmt.Sprintf("frida-%d", time.Now().UnixNano())
	startedAt := time.Now().UnixMilli()
	ctx, cancel := context.WithCancel(context.Background())

	var (
		cmd       *exec.Cmd
		tempFiles []string
		stdin     io.WriteCloser
		err       error
	)

	if driver == DriverPythonBridge {
		cmd, stdin, tempFiles, err = buildPythonBridgeCmd(ctx, tc.PythonPath, cfg)
	} else {
		cmd, tempFiles, err = buildFridaCLICmd(ctx, tc.FridaCLIPath, cfg)
	}
	if err != nil {
		cancel()
		cleanupTempFiles(tempFiles)
		return nil, err
	}

	configureProcGroup(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		cleanupTempFiles(tempFiles)
		return nil, fmt.Errorf("frida stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		cleanupTempFiles(tempFiles)
		return nil, fmt.Errorf("frida stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		cleanupTempFiles(tempFiles)
		return nil, fmt.Errorf("start frida driver (%s): %w", driver, err)
	}

	sess := &activeSession{
		id:        sessionID,
		driver:    driver,
		cmd:       cmd,
		cancel:    cancel,
		stdin:     stdin,
		tempFiles: tempFiles,
		doneCh:    make(chan struct{}),
	}

	scriptName := strings.TrimSpace(cfg.ScriptName)
	if scriptName == "" {
		scriptName = "Untitled Script"
	}

	m.mu.Lock()
	m.active = sess
	m.state = &SessionState{
		ID:           sessionID,
		Serial:       cfg.Serial,
		Target:       cfg.Target,
		Mode:         cfg.Mode,
		ScriptID:     cfg.ScriptID,
		ScriptName:   scriptName,
		Driver:       driver,
		Status:       StatusStarting,
		Running:      true,
		Paused:       cfg.Mode == ModeSpawn && !cfg.NoPause,
		RemoteHost:   cfg.RemoteHost,
		CanHotReload: driver == DriverPythonBridge,
		StartedAtMs:  startedAt,
		Events:       make([]LogEvent, 0, 64),
	}
	snap := cloneSessionState(m.state)
	onState := m.onState
	m.mu.Unlock()

	if onState != nil {
		onState(snap)
	}

	m.appendEvent(sessionID, LogEvent{
		Level:    "system",
		Category: "lifecycle",
		Message:  fmt.Sprintf("Starting Frida session (%s · %s) on %s", driver, cfg.Mode, cfg.Target),
	})

	// Stream stdout, stderr, and wait for process exit
	go m.monitorSession(sess, stdout, stderr)

	return snap, nil
}

// ReloadScript hot-reloads JS code inside a running Python Bridge session without restarting the app.
func (m *Manager) ReloadScript(code string) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("script code cannot be empty")
	}
	m.mu.Lock()
	sess := m.active
	m.mu.Unlock()

	if sess == nil || sess.stdin == nil || sess.driver != DriverPythonBridge {
		return fmt.Errorf("hot-reload requires an active Python Bridge session")
	}
	return sess.sendControl(map[string]any{
		"cmd":  "reload",
		"code": code,
	})
}

// ResumeSession resumes a spawned process that was started paused.
func (m *Manager) ResumeSession() error {
	m.mu.Lock()
	sess := m.active
	m.mu.Unlock()

	if sess == nil || sess.stdin == nil || sess.driver != DriverPythonBridge {
		return fmt.Errorf("resume requires an active Python Bridge session")
	}
	return sess.sendControl(map[string]any{"cmd": "resume"})
}

// StopSession detaches cleanly and terminates the running Frida driver process.
func (m *Manager) StopSession() error {
	m.mu.Lock()
	sess := m.active
	m.mu.Unlock()

	if sess == nil {
		return nil
	}
	sess.stopping.Store(true)

	// Ask Python Bridge to detach gracefully first
	if sess.stdin != nil && sess.driver == DriverPythonBridge {
		_ = sess.sendControl(map[string]any{"cmd": "detach"})
		sess.stdinMu.Lock()
		_ = sess.stdin.Close()
		sess.stdinMu.Unlock()
	}

	// Give process brief grace period to detach cleanly, then force-kill process group
	select {
	case <-sess.doneCh:
		return nil
	case <-time.After(1200 * time.Millisecond):
		sess.cancel()
		_ = killProcGroup(sess.cmd)
		select {
		case <-sess.doneCh:
		case <-time.After(1 * time.Second):
		}
		return nil
	}
}

// Shutdown stops any running Frida session during application exit.
func (m *Manager) Shutdown() {
	_ = m.StopSession()
}

func (s *activeSession) sendControl(payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	s.stdinMu.Lock()
	defer s.stdinMu.Unlock()
	if s.stdin == nil {
		return fmt.Errorf("session control pipe closed")
	}
	_, err = s.stdin.Write(data)
	return err
}

func (m *Manager) monitorSession(sess *activeSession, stdout, stderr io.ReadCloser) {
	defer close(sess.doneCh)
	defer cleanupTempFiles(sess.tempFiles)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if sess.driver == DriverPythonBridge {
				m.handleBridgeLine(sess.id, line)
			} else {
				m.handleCLILine(sess.id, line, false)
			}
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		scanner.Buffer(make([]byte, 0, 16*1024), 512*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			m.handleCLILine(sess.id, line, true)
		}
	}()

	wg.Wait()
	waitErr := sess.cmd.Wait()
	stoppedByUser := sess.stopping.Load()
	nowMs := time.Now().UnixMilli()

	m.mu.Lock()
	if m.active == sess {
		m.active = nil
	}
	var snap *SessionState
	onState := m.onState
	if m.state != nil && m.state.ID == sess.id {
		m.state.Running = false
		m.state.Paused = false
		m.state.CanHotReload = false
		m.state.StoppedAtMs = nowMs
		if m.state.StartedAtMs > 0 {
			m.state.ElapsedMs = nowMs - m.state.StartedAtMs
		}
		if stoppedByUser {
			m.state.Status = StatusStopped
		} else if waitErr != nil {
			m.state.Status = StatusError
			if m.state.Error == "" {
				m.state.Error = waitErr.Error()
			}
		} else if m.state.Status != StatusError {
			m.state.Status = StatusStopped
		}
		snap = cloneSessionState(m.state)
	}
	m.mu.Unlock()

	if stoppedByUser {
		m.appendEvent(sess.id, LogEvent{
			Level:    "system",
			Category: "lifecycle",
			Message:  "Session detached by user",
		})
	} else if waitErr != nil {
		m.appendEvent(sess.id, LogEvent{
			Level:    "error",
			Category: "lifecycle",
			Message:  fmt.Sprintf("Frida session terminated: %v", waitErr),
		})
	}

	if onState != nil && snap != nil {
		onState(snap)
	}
}

func (m *Manager) handleBridgeLine(sessionID, line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}
	var msg map[string]any
	if err := json.Unmarshal([]byte(trimmed), &msg); err != nil {
		m.appendEvent(sessionID, LogEvent{
			Level:    "console",
			Category: "script",
			Message:  trimmed,
			Raw:      trimmed,
		})
		return
	}

	msgType, _ := msg["type"].(string)
	switch msgType {
	case "lifecycle":
		evName, _ := msg["event"].(string)
		m.handleLifecycleEvent(sessionID, evName, msg)
	case "send":
		dataHex, _ := msg["data_hex"].(string)
		ev := buildEventFromSendPayload(msg["payload"], dataHex, trimmed)
		m.appendEvent(sessionID, ev)
	case "console":
		lvl, _ := msg["level"].(string)
		if lvl == "" {
			lvl = "info"
		}
		text, _ := msg["message"].(string)
		m.appendEvent(sessionID, LogEvent{
			Level:    normalizeConsoleLevel(lvl),
			Category: inferCategory(text),
			Message:  text,
			Raw:      trimmed,
		})
	case "error":
		desc, _ := msg["description"].(string)
		stack, _ := msg["stack"].(string)
		fullMsg := desc
		if stack != "" && !strings.Contains(desc, stack) {
			fullMsg = desc + "\n" + stack
		}
		m.mu.Lock()
		if m.state != nil && m.state.ID == sessionID && m.state.Status == StatusStarting {
			m.state.Error = desc
		}
		m.mu.Unlock()
		m.appendEvent(sessionID, LogEvent{
			Level:    "error",
			Category: "script",
			Message:  fullMsg,
			Raw:      trimmed,
		})
	default:
		m.appendEvent(sessionID, LogEvent{
			Level:    "console",
			Category: "script",
			Message:  trimmed,
			Raw:      trimmed,
		})
	}
}

func (m *Manager) handleLifecycleEvent(sessionID, evName string, msg map[string]any) {
	m.mu.Lock()
	var snap *SessionState
	onState := m.onState
	if m.state != nil && m.state.ID == sessionID {
		if pidFloat, ok := msg["pid"].(float64); ok && pidFloat > 0 {
			m.state.PID = int(pidFloat)
		}
		switch evName {
		case "attached":
			m.state.Status = StatusRunning
			if paused, ok := msg["paused"].(bool); ok {
				m.state.Paused = paused
			}
		case "loaded":
			m.state.Status = StatusRunning
		case "resumed":
			m.state.Paused = false
			m.state.Status = StatusRunning
		case "reloaded":
			m.state.ReloadCount++
		case "detached":
			m.state.Running = false
			m.state.Status = StatusStopped
		}
		snap = cloneSessionState(m.state)
	}
	m.mu.Unlock()

	detail := evName
	switch evName {
	case "connecting":
		detail = fmt.Sprintf("Connecting to %v (%v)...", msg["target"], msg["mode"])
	case "attached":
		detail = fmt.Sprintf("Attached to %v (PID %v)", msg["target"], msg["pid"])
	case "loaded":
		detail = "Frida script loaded & hooks active"
	case "resumed":
		detail = fmt.Sprintf("Process resumed (PID %v)", msg["pid"])
	case "reloaded":
		detail = "Script hot-reloaded without restarting target process"
	case "detached":
		detail = fmt.Sprintf("Detached: %v", msg["reason"])
	case "exited":
		return
	}

	m.appendEvent(sessionID, LogEvent{
		Level:    "system",
		Category: "lifecycle",
		Message:  detail,
	})
	if onState != nil && snap != nil {
		onState(snap)
	}
}

func (m *Manager) handleCLILine(sessionID, line string, isStderr bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}

	// Mark CLI session as running once we see Frida banner/output
	m.mu.Lock()
	var snap *SessionState
	onState := m.onState
	if m.state != nil && m.state.ID == sessionID && m.state.Status == StatusStarting && !isStderr {
		m.state.Status = StatusRunning
		snap = cloneSessionState(m.state)
	}
	m.mu.Unlock()
	if onState != nil && snap != nil {
		onState(snap)
	}

	if idx := strings.Index(trimmed, cliStructuredPrefix); idx >= 0 {
		jsonPart := strings.TrimSpace(trimmed[idx+len(cliStructuredPrefix):])
		var parsed any
		if json.Unmarshal([]byte(jsonPart), &parsed) == nil {
			m.appendEvent(sessionID, buildEventFromSendPayload(parsed, "", trimmed))
			return
		}
	}

	lvl := "console"
	if isStderr {
		lvl = "error"
	}
	m.appendEvent(sessionID, LogEvent{
		Level:    lvl,
		Category: inferCategory(trimmed),
		Message:  trimmed,
		Raw:      trimmed,
	})
}

func buildEventFromSendPayload(payload any, dataHex, raw string) LogEvent {
	ev := LogEvent{
		Level:    "send",
		Category: "script",
		DataHex:  dataHex,
		Raw:      raw,
	}
	switch v := payload.(type) {
	case map[string]any:
		ev.Payload = v
		ev.Level = "hook"
		if cat, ok := v["cap_cat"].(string); ok && cat != "" {
			ev.Category = cat
		}
		ev.Message = summarizePayloadMap(v)
	case string:
		ev.Message = v
		ev.Category = inferCategory(v)
	default:
		b, _ := json.Marshal(v)
		ev.Message = string(b)
	}
	return ev
}

func summarizePayloadMap(m map[string]any) string {
	hook, _ := m["hook"].(string)
	if detail, ok := m["detail"].(string); ok && detail != "" {
		if hook != "" {
			return fmt.Sprintf("[%s] %s", hook, detail)
		}
		return detail
	}
	if method, ok := m["method"].(string); ok {
		if urlStr, ok := m["url"].(string); ok {
			return fmt.Sprintf("%s %s", method, urlStr)
		}
		if cls, ok := m["class_name"].(string); ok {
			return fmt.Sprintf("%s.%s", cls, method)
		}
	}
	if urlStr, ok := m["url"].(string); ok && urlStr != "" {
		return fmt.Sprintf("[%s] %s", hook, urlStr)
	}
	if algo, ok := m["algorithm"].(string); ok && algo != "" {
		outHex, _ := m["output_hex"].(string)
		if len(outHex) > 48 {
			outHex = outHex[:48] + "…"
		}
		if outHex != "" {
			return fmt.Sprintf("[%s] %s -> %s", hook, algo, outHex)
		}
		return fmt.Sprintf("[%s] %s", hook, algo)
	}
	if blocked, ok := m["blocked"].(string); ok && blocked != "" {
		return fmt.Sprintf("[%s] bypassed %s", hook, blocked)
	}
	if key, ok := m["key"].(string); ok && key != "" {
		return fmt.Sprintf("[%s] %s = %v", hook, key, m["value"])
	}
	if sym, ok := m["symbol"].(string); ok && sym != "" {
		return fmt.Sprintf("[%s] %s", hook, sym)
	}
	if hook != "" {
		return hook
	}
	b, _ := json.Marshal(m)
	s := string(b)
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

func normalizeConsoleLevel(lvl string) string {
	switch strings.ToLower(lvl) {
	case "error", "err":
		return "error"
	case "warn", "warning":
		return "warn"
	case "info", "log", "debug":
		return "console"
	default:
		return "console"
	}
}

func inferCategory(text string) string {
	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "unpin") || strings.Contains(low, "ssl") || strings.Contains(low, "tls") || strings.Contains(low, "certificate"):
		return "ssl"
	case strings.Contains(low, "hmac") || strings.Contains(low, "md5") || strings.Contains(low, "sha") || strings.Contains(low, "aes") || strings.Contains(low, "cipher"):
		return "crypto"
	case strings.Contains(low, "okhttp") || strings.Contains(low, "http"):
		return "http"
	case strings.Contains(low, "jni") || strings.Contains(low, "registernatives") || strings.Contains(low, ".so"):
		return "jni"
	default:
		return "script"
	}
}

func (m *Manager) appendEvent(sessionID string, ev LogEvent) {
	ev.Seq = m.seq.Add(1)
	ev.SessionID = sessionID
	if ev.TimestampMs == 0 {
		ev.TimestampMs = time.Now().UnixMilli()
	}

	m.mu.Lock()
	if m.state != nil && m.state.ID == sessionID {
		m.state.EventCount++
		if ev.Level == "hook" || ev.Level == "send" {
			m.state.HookCount++
		}
		if ev.Level == "error" {
			m.state.ErrorCount++
		}
		m.state.Events = append(m.state.Events, ev)
		if len(m.state.Events) > MaxSessionEvents {
			m.state.Events = m.state.Events[len(m.state.Events)-MaxSessionEvents:]
		}
	}
	onEvent := m.onEvent
	m.mu.Unlock()

	if onEvent != nil {
		onEvent(ev)
	}
}

func (m *Manager) currentToolchainConfig() ToolchainConfig {
	m.tcMu.RLock()
	defer m.tcMu.RUnlock()
	return m.tcCfg
}

func buildPythonBridgeCmd(ctx context.Context, pythonPath string, cfg SessionConfig) (*exec.Cmd, io.WriteCloser, []string, error) {
	tmpDir := os.TempDir()
	bridgeFile, err := os.CreateTemp(tmpDir, "cap-frida-bridge-*.py")
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := bridgeFile.WriteString(pythonBridgeScript); err != nil {
		bridgeFile.Close()
		_ = os.Remove(bridgeFile.Name())
		return nil, nil, nil, err
	}
	bridgeFile.Close()

	cfgFile, err := os.CreateTemp(tmpDir, "cap-frida-cfg-*.json")
	if err != nil {
		_ = os.Remove(bridgeFile.Name())
		return nil, nil, nil, err
	}
	cfgPayload := map[string]any{
		"serial":      cfg.Serial,
		"remote_host": cfg.RemoteHost,
		"target":      cfg.Target,
		"mode":        cfg.Mode,
		"no_pause":    cfg.NoPause,
		"script_code": cfg.ScriptCode,
	}
	if err := json.NewEncoder(cfgFile).Encode(cfgPayload); err != nil {
		cfgFile.Close()
		_ = os.Remove(bridgeFile.Name())
		_ = os.Remove(cfgFile.Name())
		return nil, nil, nil, err
	}
	cfgFile.Close()

	cmd := exec.CommandContext(ctx, pythonPath, "-u", bridgeFile.Name(), cfgFile.Name())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = os.Remove(bridgeFile.Name())
		_ = os.Remove(cfgFile.Name())
		return nil, nil, nil, err
	}
	return cmd, stdin, []string{bridgeFile.Name(), cfgFile.Name()}, nil
}

func buildFridaCLICmd(ctx context.Context, fridaCLIPath string, cfg SessionConfig) (*exec.Cmd, []string, error) {
	scriptFile, err := os.CreateTemp(os.TempDir(), "cap-frida-script-*.js")
	if err != nil {
		return nil, nil, err
	}
	wrapped := wrapScriptForCLI(cfg.ScriptCode)
	if _, err := scriptFile.WriteString(wrapped); err != nil {
		scriptFile.Close()
		_ = os.Remove(scriptFile.Name())
		return nil, nil, err
	}
	scriptFile.Close()

	args := []string{"-q", "-l", scriptFile.Name()}
	if cfg.RemoteHost != "" {
		args = append(args, "-H", cfg.RemoteHost)
	} else if cfg.Serial != "" {
		args = append(args, "-D", cfg.Serial)
	} else {
		args = append(args, "-U")
	}

	if cfg.Mode == ModeSpawn {
		args = append(args, "-f", cfg.Target)
	} else {
		args = append(args, cfg.Target)
	}

	cmd := exec.CommandContext(ctx, fridaCLIPath, args...)
	return cmd, []string{scriptFile.Name()}, nil
}

func cleanupTempFiles(paths []string) {
	for _, p := range paths {
		if p != "" {
			_ = os.Remove(p)
		}
	}
}

func cloneSessionState(st *SessionState) *SessionState {
	if st == nil {
		return &SessionState{
			Status: StatusIdle,
			Events: []LogEvent{},
		}
	}
	cp := *st
	cp.Events = make([]LogEvent, len(st.Events))
	copy(cp.Events, st.Events)
	if cp.Running && cp.StartedAtMs > 0 {
		cp.ElapsedMs = time.Now().UnixMilli() - cp.StartedAtMs
		if cp.ElapsedMs < 0 {
			cp.ElapsedMs = 0
		}
	}
	return &cp
}
