package wailsgui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/ai"
	"github.com/overkazaf/cap/internal/recon"
	"github.com/overkazaf/cap/internal/retools"
)

func newTestReconAIApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	capDir := filepath.Join(os.Getenv("HOME"), ".cap")
	if err := os.MkdirAll(capDir, 0o755); err != nil {
		t.Fatalf("mkdir capDir: %v", err)
	}
	return &App{
		certDir:          capDir,
		events:           NewEventBus(),
		settings:         loadSettings(filepath.Join(capDir, "settings.json")),
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
	}
}

func TestDefaultSettingsAndEventsIncludeReconAndAI(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if EventReconLog != "recon:log" || EventReconStatus != "recon:status" || EventAIHeal != "ai:heal" {
		t.Fatalf("unexpected event names: %q %q %q", EventReconLog, EventReconStatus, EventAIHeal)
	}

	settings := loadSettings(filepath.Join(t.TempDir(), "missing-settings.json"))
	for _, key := range []string{
		"recon_nmap_path",
		"recon_subfinder_path",
		"recon_whois_path",
		"recon_dig_path",
	} {
		if _, ok := settings[key]; !ok {
			t.Errorf("loadSettings missing default key %q", key)
		}
	}

	app := NewApp(nil)
	if app.reconMgr == nil || app.aiMgr == nil {
		t.Fatalf("NewApp must initialize reconMgr and aiMgr")
	}

	// Changing any recon_* key via SetSetting must sync reconMgr's toolchain config.
	if err := app.SetSetting("recon_nmap_path", "/nonexistent/custom-nmap"); err != nil {
		t.Fatalf("SetSetting recon_nmap_path: %v", err)
	}
	if got := app.reconMgr.GetToolchainConfig().NmapPath; got != "/nonexistent/custom-nmap" {
		t.Fatalf("reconMgr.NmapPath = %q, want /nonexistent/custom-nmap", got)
	}

	app.Shutdown(context.Background())
}

func TestReconGUIBindingsHermetic(t *testing.T) {
	app := newTestReconAIApp(t)
	defer app.Shutdown(context.Background())

	// 1. Toolchain config update + persistence
	tmpDir := t.TempDir()
	fakeNmap := filepath.Join(tmpDir, "fake-nmap")
	if err := os.WriteFile(fakeNmap, []byte("#!/bin/sh\necho 'Nmap version 7.95'\n"), 0o755); err != nil {
		t.Fatalf("write fake-nmap: %v", err)
	}
	tc, err := app.UpdateReconToolchainConfig(recon.ToolchainConfig{
		NmapPath:      fakeNmap,
		SubfinderPath: "/nonexistent/subfinder",
		WhoisPath:     "/nonexistent/whois",
		DigPath:       "/nonexistent/dig",
	})
	if err != nil {
		t.Fatalf("UpdateReconToolchainConfig: %v", err)
	}
	if !tc.Nmap.Ready || tc.Nmap.Version != "7.95" {
		t.Fatalf("expected fake nmap ready (7.95), got %+v", tc.Nmap)
	}
	if tc.Subfinder.Ready {
		t.Fatalf("expected invalid subfinder path not ready")
	}
	if got := app.GetSetting("recon_nmap_path"); got != fakeNmap {
		t.Fatalf("recon_nmap_path = %q, want %q", got, fakeNmap)
	}
	cachedTC := app.GetReconToolchain(false)
	if cachedTC.Nmap.Path != tc.Nmap.Path {
		t.Fatalf("cached toolchain mismatch: %+v vs %+v", cachedTC.Nmap, tc.Nmap)
	}

	// 2. AnalyzeReconDomain (loopback IP)
	domRep, err := app.AnalyzeReconDomain("127.0.0.1")
	if err != nil {
		t.Fatalf("AnalyzeReconDomain(127.0.0.1): %v", err)
	}
	if domRep.Target != "127.0.0.1" {
		t.Fatalf("unexpected domain target: %+v", domRep)
	}

	// 3. ProbeReconSite against local httptest server
	siteSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
		case "/.well-known/security.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Contact: mailto:sec@example.test\n"))
		default:
			w.Header().Set("Server", "nginx/1.25.0")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write([]byte("<!doctype html><html><head><title>Cap Recon Target</title></head><body>ok</body></html>"))
		}
	}))
	defer siteSrv.Close()

	profile, err := app.ProbeReconSite(siteSrv.URL, recon.SiteProbeOptions{})
	if err != nil {
		t.Fatalf("ProbeReconSite: %v", err)
	}
	if profile.StatusCode != 200 || profile.Title != "Cap Recon Target" {
		t.Fatalf("unexpected SiteProfile: status=%d title=%q", profile.StatusCode, profile.Title)
	}
	if profile.RobotsRules == nil || !profile.RobotsRules.Found {
		t.Fatalf("expected robots.txt discovery hit, got %+v", profile.RobotsRules)
	}

	// 4. InspectReconTLS against local httptest TLS server
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()
	parsedTLS, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse tls url: %v", err)
	}
	tlsHost, tlsPortStr, err := net.SplitHostPort(parsedTLS.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	tlsPort, _ := strconv.Atoi(tlsPortStr)

	tlsRep, err := app.InspectReconTLS(tlsHost, tlsPort)
	if err != nil {
		t.Fatalf("InspectReconTLS: %v", err)
	}
	if tlsRep.TLSVersion == "" || tlsRep.Leaf == nil {
		t.Fatalf("unexpected TLSInspectReport: %+v", tlsRep)
	}

	// 5. EnumerateReconSubdomains against local mock CT log endpoint
	ctSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name_value":"api.example.test\nwww.example.test"},{"name_value":"cdn.example.test"}]`))
	}))
	defer ctSrv.Close()

	subRep, err := app.EnumerateReconSubdomains(recon.SubdomainRequest{
		Domain:       "example.test",
		UseCTLog:     true,
		UseSubfinder: false,
		UseCommonDNS: false,
		CTEndpoint:   ctSrv.URL + "/?q=%s",
	})
	if err != nil {
		t.Fatalf("EnumerateReconSubdomains: %v", err)
	}
	if subRep.TotalCount != 3 {
		t.Fatalf("expected 3 CT subdomains, got %d (%+v)", subRep.TotalCount, subRep.Subdomains)
	}

	// 6. Async Recon Job (native loopback TCP port scan) + events + history CRUD
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	var (
		evMu          sync.Mutex
		logEvents     int
		statusEvents  int
	)
	app.events.SetEmitter(func(event string, data ...interface{}) {
		evMu.Lock()
		defer evMu.Unlock()
		switch event {
		case EventReconLog:
			logEvents++
		case EventReconStatus:
			statusEvents++
		}
	})

	startSt, err := app.StartReconJob(recon.ReconJobRequest{
		Kind:   recon.JobKindPortScan,
		Target: "127.0.0.1",
		PortScan: &recon.PortScanRequest{
			Target:         "127.0.0.1",
			Engine:         recon.PortScanEngineNative,
			Preset:         recon.PresetCustom,
			PortsSpec:      strconv.Itoa(openPort),
			ServiceVersion: true,
			TimeoutMs:      500,
		},
	})
	if err != nil {
		t.Fatalf("StartReconJob: %v", err)
	}
	if startSt.ID == "" {
		t.Fatalf("expected non-empty recon job ID")
	}

	deadline := time.Now().Add(10 * time.Second)
	var finalSt *recon.ReconJobState
	for time.Now().Before(deadline) {
		finalSt = app.GetReconJobState()
		if !finalSt.Running && finalSt.Status != recon.StatusIdle {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if finalSt == nil || finalSt.Status != recon.StatusDone || finalSt.PortScanResult == nil {
		t.Fatalf("expected completed portscan job, got %+v", finalSt)
	}
	if finalSt.PortScanResult.OpenCount != 1 {
		t.Fatalf("expected 1 open port, got %d", finalSt.PortScanResult.OpenCount)
	}

	evMu.Lock()
	gotLogEvents, gotStatusEvents := logEvents, statusEvents
	evMu.Unlock()
	if gotLogEvents == 0 || gotStatusEvents == 0 {
		t.Fatalf("expected recon events emitted (log=%d status=%d)", gotLogEvents, gotStatusEvents)
	}

	app.ClearReconJobLogs()
	if stAfterClear := app.GetReconJobState(); len(stAfterClear.Events) != 0 {
		t.Fatalf("expected cleared recon job logs, got %d", len(stAfterClear.Events))
	}
	if err := app.CancelReconJob(); err != nil {
		t.Fatalf("CancelReconJob on idle: %v", err)
	}

	// History CRUD
	hist := app.ListReconHistory()
	if len(hist) != 1 {
		t.Fatalf("expected 1 recon history entry, got %d", len(hist))
	}
	entry, err := app.GetReconHistory(hist[0].ID)
	if err != nil || entry.Target != "127.0.0.1" {
		t.Fatalf("GetReconHistory(%s): err=%v entry=%+v", hist[0].ID, err, entry)
	}
	if _, err := app.GetReconHistory("does-not-exist"); err == nil {
		t.Fatal("expected error for missing recon history ID")
	}
	if err := app.DeleteReconHistory(entry.ID); err != nil {
		t.Fatalf("DeleteReconHistory: %v", err)
	}
	if len(app.ListReconHistory()) != 0 {
		t.Fatalf("expected 0 history entries after delete")
	}
	if err := app.ClearReconHistory(); err != nil {
		t.Fatalf("ClearReconHistory: %v", err)
	}
}

func startMockOpenAIServer(t *testing.T, handler func(reqBody map[string]any) (string, int)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		content, status := handler(body)
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusOK {
			http.Error(w, content, status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id": "chatcmpl-test",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": content,
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     42,
				"completion_tokens": 24,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestAIGUIBindingsAndConfigAllowlist(t *testing.T) {
	app := newTestReconAIApp(t)
	defer app.Shutdown(context.Background())

	presets := app.ListAIProviderPresets()
	if len(presets) < 5 {
		t.Fatalf("expected built-in provider presets, got %d", len(presets))
	}

	var (
		mu             sync.Mutex
		lastSystemMsg  string
		sawAuthHeader  string
	)
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawAuthHeader = r.Header.Get("Authorization")
		mu.Unlock()

		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sysMsg := ""
		userMsg := ""
		for _, m := range body.Messages {
			if m.Role == "system" {
				sysMsg = m.Content
			}
			if m.Role == "user" {
				userMsg = m.Content
			}
		}
		mu.Lock()
		lastSystemMsg = sysMsg
		mu.Unlock()

		content := "OK"
		if strings.Contains(userMsg, "broken_fn") {
			diagJSON := map[string]any{
				"root_cause":     "Undefined function broken_fn",
				"error_category": "runtime",
				"confidence":     0.95,
				"fix_kind":       ai.FixKindCodePatch,
				"explanation":    "Replaced broken_fn with print('ok')",
				"patched_code":   "print('ok')\n",
				"config_changes": map[string]string{"re_python_path": "/usr/bin/python3", "theme": "light"},
				"command_hints":  []string{"python3 -m py_compile script.py"},
				"verify_hint":    "Re-run the script",
			}
			raw, _ := json.Marshal(diagJSON)
			content = string(raw)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": content}},
			},
			"usage": map[string]any{"prompt_tokens": 12, "completion_tokens": 34},
		})
	}))
	defer mockSrv.Close()

	// Upsert + secret masking
	rawKey := "sk-super-secret-value-987654321"
	saved, err := app.UpsertAIProfile(ai.ProviderConfig{
		Name:       "Mock OpenAI",
		Provider:   ai.ProviderOpenAICompat,
		BaseURL:    mockSrv.URL,
		APIKey:     rawKey,
		Model:      "gpt-4.1",
		TimeoutSec: 15,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("UpsertAIProfile: %v", err)
	}
	if !saved.HasAPIKey || strings.Contains(saved.APIKeyPreview, rawKey) {
		t.Fatalf("expected masked API key preview, got %+v", saved)
	}

	pub := app.GetAIConfig()
	if pub.ActiveProfileID != saved.ID || len(pub.Profiles) != 1 {
		t.Fatalf("unexpected PublicAIConfig: %+v", pub)
	}

	// UpdateAISettings
	autoHeal := true
	retries := 4
	pub2, err := app.UpdateAISettings(ai.AISettingsUpdate{
		AutoHealEnabled: &autoHeal,
		MaxAutoRetries:  &retries,
	})
	if err != nil {
		t.Fatalf("UpdateAISettings: %v", err)
	}
	if !pub2.AutoHealEnabled || pub2.MaxAutoRetries != 4 {
		t.Fatalf("settings update not reflected: %+v", pub2)
	}

	// TestAIConnection (passing masked/empty API key with saved ID must reuse stored secret)
	testRes := app.TestAIConnection(ai.ProviderConfig{
		ID:       saved.ID,
		Provider: ai.ProviderOpenAICompat,
		BaseURL:  mockSrv.URL,
		Model:    "gpt-4.1",
	})
	if !testRes.OK {
		t.Fatalf("TestAIConnection failed: %+v", testRes)
	}
	mu.Lock()
	gotAuth := sawAuthHeader
	mu.Unlock()
	if gotAuth != "Bearer "+rawKey {
		t.Fatalf("expected stored API key reused in auth header, got %q", gotAuth)
	}

	// DiagnoseAndFixWithAI defaults Locale from app setting "locale" when empty
	if err := app.SetSetting("locale", "zh-CN"); err != nil {
		t.Fatalf("SetSetting locale: %v", err)
	}
	diag, err := app.DiagnoseAndFixWithAI(ai.DiagnoseRequest{
		Scope:     ai.ScopeQiling,
		Code:      "broken_fn()\n",
		Language:  "python",
		ErrorText: "NameError: name 'broken_fn' is not defined",
	})
	if err != nil {
		t.Fatalf("DiagnoseAndFixWithAI: %v", err)
	}
	if diag.FixKind != ai.FixKindCodePatch || diag.Validation == nil || !diag.Validation.Passed {
		t.Fatalf("unexpected DiagnoseResult: %+v", diag)
	}
	if !strings.Contains(diag.UnifiedDiff, "-broken_fn()") || !strings.Contains(diag.UnifiedDiff, "+print('ok')") {
		t.Fatalf("unexpected unified diff:\n%s", diag.UnifiedDiff)
	}
	mu.Lock()
	sysMsg := lastSystemMsg
	mu.Unlock()
	if !strings.Contains(sysMsg, "Chinese") && !strings.Contains(sysMsg, "中文") && !strings.Contains(sysMsg, "zh-CN") {
		t.Fatalf("expected Chinese locale prompt when app locale=zh-CN, got:\n%s", sysMsg)
	}

	// Ensure retoolsMgr is already initialized before ApplyAIConfigChanges so we verify live propagation.
	reMgr, err := app.ensureRetoolsManager()
	if err != nil {
		t.Fatalf("ensureRetoolsManager: %v", err)
	}

	// ApplyAIConfigChanges strict allowlist enforcement + live propagation into retoolsMgr
	applied, err := app.ApplyAIConfigChanges(map[string]string{
		"re_python_path":     "/opt/venv/bin/python3",
		"gateway_addr":       "127.0.0.1:9191",
		"frida_default_port": "27043",
		"theme":              "light",               // disallowed
		"evil_setting":       "rm -rf /",            // disallowed
		"re_r2_path":         "bad\ninjection",      // control char rejected
	})
	if err != nil {
		t.Fatalf("ApplyAIConfigChanges: %v", err)
	}
	if len(applied) != 3 {
		t.Fatalf("expected exactly 3 allowlisted changes applied, got %+v", applied)
	}
	if _, leaked := applied["theme"]; leaked {
		t.Fatal("disallowed key 'theme' should not be applied")
	}
	if _, leaked := applied["evil_setting"]; leaked {
		t.Fatal("disallowed key 'evil_setting' should not be applied")
	}
	if got := app.GetSetting("re_python_path"); got != "/opt/venv/bin/python3" {
		t.Fatalf("re_python_path = %q", got)
	}
	if got := reMgr.GetToolchainConfig().PythonPath; got != "/opt/venv/bin/python3" {
		t.Fatalf("retoolsMgr live PythonPath = %q, want /opt/venv/bin/python3", got)
	}
	if got := app.GetSetting("theme"); got != "dark" {
		t.Fatalf("disallowed theme setting should remain dark, got %q", got)
	}

	// ComputeTextUnifiedDiff
	diff := app.ComputeTextUnifiedDiff("line1\nold\n", "line1\nnew\n")
	if !strings.Contains(diff, "-old") || !strings.Contains(diff, "+new") {
		t.Fatalf("unexpected diff:\n%s", diff)
	}

	// SetActiveAIProfile + DeleteAIProfile
	if err := app.SetActiveAIProfile(""); err != nil {
		t.Fatalf("SetActiveAIProfile empty: %v", err)
	}
	if err := app.SetActiveAIProfile(saved.ID); err != nil {
		t.Fatalf("SetActiveAIProfile saved: %v", err)
	}
	if err := app.DeleteAIProfile(saved.ID); err != nil {
		t.Fatalf("DeleteAIProfile: %v", err)
	}
	if len(app.GetAIConfig().Profiles) != 0 {
		t.Fatalf("expected 0 profiles after delete")
	}
}

func writeFakeQilingPython(t *testing.T) string {
	t.Helper()
	fakePy := filepath.Join(t.TempDir(), "fake-python3")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Python 3.11.9"
  exit 0
fi
if [ "$1" = "-c" ]; then
  echo "PY=3.11.9"
  echo "QILING=1.4.6"
  echo "ANGR=9.2.0"
  exit 0
fi
if [ "$1" = "-u" ]; then
  SCRIPT="$2"
  if grep -q "SLEEP_LONG" "$SCRIPT"; then
    echo "sleeping..."
    sleep 15
    exit 0
  fi
  if grep -q "FIXED_OK" "$SCRIPT"; then
    echo '[CAP_RE] {"kind":"result","result":"healed-42"}'
    echo "execution succeeded"
    exit 0
  fi
  echo "Traceback (most recent call last):" >&2
  echo "NameError: name 'BROKEN_SYM' is not defined" >&2
  exit 1
fi
exit 0
`
	if err := os.WriteFile(fakePy, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake python: %v", err)
	}
	return fakePy
}

func TestRunREJobWithAutoHealAndCancelHermetic(t *testing.T) {
	app := newTestReconAIApp(t)
	defer app.Shutdown(context.Background())

	fakePy := writeFakeQilingPython(t)
	if _, err := app.UpdateREToolchainConfig(retools.ToolchainConfig{
		PythonPath:       fakePy,
		QilingPythonPath: fakePy,
	}); err != nil {
		t.Fatalf("UpdateREToolchainConfig: %v", err)
	}

	mockSrv := startMockOpenAIServer(t, func(reqBody map[string]any) (string, int) {
		diagJSON := map[string]any{
			"root_cause":     "Undefined symbol BROKEN_SYM",
			"error_category": "runtime",
			"confidence":     0.98,
			"fix_kind":       ai.FixKindCodePatch,
			"explanation":    "Replaced BROKEN_SYM with FIXED_OK print",
			"patched_code":   "print('FIXED_OK')\n",
		}
		raw, _ := json.Marshal(diagJSON)
		return string(raw), http.StatusOK
	})
	defer mockSrv.Close()

	if _, err := app.UpsertAIProfile(ai.ProviderConfig{
		Name:       "AutoHeal Mock",
		Provider:   ai.ProviderOpenAICompat,
		BaseURL:    mockSrv.URL,
		APIKey:     "sk-heal-test-1234567890",
		Model:      "gpt-4.1",
		TimeoutSec: 15,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("UpsertAIProfile: %v", err)
	}

	var (
		evMu       sync.Mutex
		healEvents []ai.AutoHealEvent
	)
	app.events.SetEmitter(func(event string, data ...interface{}) {
		if event == EventAIHeal && len(data) > 0 {
			if ev, ok := data[0].(ai.AutoHealEvent); ok {
				evMu.Lock()
				healEvents = append(healEvents, ev)
				evMu.Unlock()
			}
		}
	})

	// 1. Successful auto-heal loop (attempt 0 fails -> AI patches -> attempt 1 succeeds)
	res, err := app.RunREJobWithAutoHeal(retools.RunJobRequest{
		Engine: retools.EngineQiling,
		Code:   "print(BROKEN_SYM)\n",
	}, 3, "en")
	if err != nil {
		t.Fatalf("RunREJobWithAutoHeal: %v", err)
	}
	if !res.Healed || res.StopReason != ai.StopReasonHealed || res.FinalExitCode != 0 {
		t.Fatalf("expected healed auto-heal result, got %+v", res)
	}
	if !strings.Contains(res.FinalCode, "FIXED_OK") {
		t.Fatalf("expected FinalCode to contain FIXED_OK, got %q", res.FinalCode)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("expected 2 attempts (initial + 1 fix), got %d", len(res.Attempts))
	}

	evMu.Lock()
	phases := make([]string, 0, len(healEvents))
	for _, ev := range healEvents {
		phases = append(phases, ev.Phase)
	}
	evMu.Unlock()
	joinedPhases := strings.Join(phases, ",")
	for _, wantPhase := range []string{ai.PhaseRunning, ai.PhaseDiagnosing, ai.PhaseValidating, ai.PhasePatching, ai.PhaseHealed} {
		if !strings.Contains(joinedPhases, wantPhase) {
			t.Errorf("expected EventAIHeal phase %q in %v", wantPhase, phases)
		}
	}

	// 2. Cancellation via CancelAIAutoHeal stops both the loop and running RE job cleanly.
	doneCh := make(chan struct {
		res *ai.AutoHealRunResult
		err error
	}, 1)
	go func() {
		r, e := app.RunREJobWithAutoHeal(retools.RunJobRequest{
			Engine: retools.EngineQiling,
			Code:   "# SLEEP_LONG\nprint('wait')\n",
		}, 2, "en")
		doneCh <- struct {
			res *ai.AutoHealRunResult
			err error
		}{res: r, err: e}
	}()

	// Wait briefly until the job is running, then cancel.
	waitDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(waitDeadline) {
		if st := app.GetREJobState(); st != nil && st.Running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := app.CancelAIAutoHeal(); err != nil {
		t.Fatalf("CancelAIAutoHeal: %v", err)
	}

	select {
	case out := <-doneCh:
		if out.err != nil {
			t.Fatalf("cancelled auto-heal returned unexpected error: %v", out.err)
		}
		if out.res == nil || out.res.StopReason != ai.StopReasonCancelled {
			t.Fatalf("expected StopReasonCancelled, got %+v", out.res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for CancelAIAutoHeal to terminate auto-heal loop")
	}

	// 3. Concurrent/overlapping RunREJobWithAutoHeal: Call 2 supersedes sleeping Call 1
	// and completes with StopReasonHealed without Call 1 killing Call 2's RE job.
	call1Done := make(chan struct {
		res *ai.AutoHealRunResult
		err error
	}, 1)
	go func() {
		r, e := app.RunREJobWithAutoHeal(retools.RunJobRequest{
			Engine: retools.EngineQiling,
			Code:   "# SLEEP_LONG\nprint('call1')\n",
		}, 2, "en")
		call1Done <- struct {
			res *ai.AutoHealRunResult
			err error
		}{res: r, err: e}
	}()

	waitCall1 := time.Now().Add(3 * time.Second)
	for time.Now().Before(waitCall1) {
		if st := app.GetREJobState(); st != nil && st.Running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	call2Res, err := app.RunREJobWithAutoHeal(retools.RunJobRequest{
		Engine: retools.EngineQiling,
		Code:   "print(BROKEN_SYM)\n",
	}, 3, "en")
	if err != nil {
		t.Fatalf("overlapping Call 2 RunREJobWithAutoHeal: %v", err)
	}
	if !call2Res.Healed || call2Res.StopReason != ai.StopReasonHealed || call2Res.FinalExitCode != 0 {
		t.Fatalf("expected Call 2 to heal cleanly after superseding Call 1, got %+v", call2Res)
	}

	select {
	case c1 := <-call1Done:
		if c1.err != nil {
			t.Fatalf("superseded Call 1 returned unexpected error: %v", c1.err)
		}
		if c1.res == nil || c1.res.StopReason != ai.StopReasonCancelled {
			t.Fatalf("expected superseded Call 1 StopReasonCancelled, got %+v", c1.res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for superseded Call 1 to finish")
	}

	// Ensure aiHealCancel and aiHealDone were cleaned up via defer.
	app.aiHealMu.Lock()
	hasCancel := app.aiHealCancel != nil
	hasDone := app.aiHealDone != nil
	app.aiHealMu.Unlock()
	if hasCancel || hasDone {
		t.Fatalf("expected aiHealCancel/aiHealDone to be nil after RunREJobWithAutoHeal returns (cancel=%v done=%v)", hasCancel, hasDone)
	}
	_ = fmt.Sprintf("verified %d heal events", len(phases))
}
