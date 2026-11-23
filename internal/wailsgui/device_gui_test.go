package wailsgui

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	captrace "github.com/overkazaf/cap/internal/trace"
	"github.com/overkazaf/cap/internal/types"
)

func TestGetCACertInfo(t *testing.T) {
	app := &App{
		certDir:          t.TempDir(),
		events:           NewEventBus(),
		settings:         map[string]string{},
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
	}

	info, err := app.GetCACertInfo()
	if err != nil {
		t.Fatalf("GetCACertInfo failed: %v", err)
	}
	if !info.Exists {
		t.Fatalf("expected CA cert to exist")
	}
	if !strings.HasSuffix(info.Hash, ".0") || len(info.Hash) < 10 {
		t.Errorf("unexpected Android hash filename: %q", info.Hash)
	}
	if len(info.Fingerprint) != 95 || strings.Count(info.Fingerprint, ":") != 31 {
		t.Errorf("unexpected SHA-256 fingerprint: %q", info.Fingerprint)
	}
	if info.Subject != "Cap MITM CA" {
		t.Errorf("unexpected subject: %q, want %q", info.Subject, "Cap MITM CA")
	}
}

func TestDeviceLifecycleSafeWhenIdle(t *testing.T) {
	app := &App{
		certDir:          t.TempDir(),
		events:           NewEventBus(),
		settings:         map[string]string{},
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
	}

	// Stopping idle proxy & shutting down should be race-free and panic-free.
	if err := app.StopProxy(); err != nil {
		t.Fatalf("StopProxy on idle app failed: %v", err)
	}
	if st := app.GetScreenStreamStats(); st.Active {
		t.Fatalf("GetScreenStreamStats().Active = true when idle, want false")
	}
	if err := app.StopScreenStream(); err != nil {
		t.Fatalf("StopScreenStream on idle app failed: %v", err)
	}
	app.stopDeviceMonitor()
	app.Shutdown(context.Background())
}

func TestProxyMatchesCap(t *testing.T) {
	localIPs := []string{"192.168.1.50", "10.0.0.12"}
	tests := []struct {
		name       string
		proxyAddr  string
		port       string
		hasReverse bool
		want       bool
	}{
		{"matching LAN IP and port", "192.168.1.50:8080", "8080", false, true},
		{"foreign loopback proxy 127.0.0.1:8083", "127.0.0.1:8083", "8080", false, false},
		{"loopback matching port without adb reverse", "127.0.0.1:8080", "8080", false, false},
		{"loopback matching port WITH adb reverse", "127.0.0.1:8080", "8080", true, true},
		{"matching LAN IP wrong port", "192.168.1.50:8888", "8080", false, false},
		{"foreign host matching port", "192.168.1.99:8080", "8080", false, false},
		{"unset proxy", ":0", "8080", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxyMatchesCap(tt.proxyAddr, localIPs, tt.port, tt.hasReverse); got != tt.want {
				t.Errorf("proxyMatchesCap(%q, port=%q, rev=%v) = %v, want %v",
					tt.proxyAddr, tt.port, tt.hasReverse, got, tt.want)
			}
		})
	}
}

func TestParseDeviceEnvOutput(t *testing.T) {
	base := `
MODEL=Pixel 7 Pro
BRAND=google
ANDROID=14
SDK=34
CPU=arm64-v8a
KERNEL=5.10.198-android13
FINGERPRINT=google/cheetah/cheetah:14/UQ1A
WM_SIZE=Physical size: 1440x3120
MEMTOTAL=MemTotal:       11534336 kB
BATTERY=  level: 85
ROOT=uid=0(root) gid=0(root)
KSUD=
KSU_MOD=
ZYGISK_PROP=1
LSPD_PKG=package:org.lsposed.manager
SELINUX=Enforcing
GMS=    versionName=24.15.16
VBOOT=orange
`
	root := `
MAGISK_V=27.0:MAGISK
MAGISK_DIR=magisk64
KSU_DIR=
ZYGISK_MOD=
LSPD_DIR=manager
LSPD_VER=1.9.2
`
	env := parseDeviceEnvOutput(base, root)
	if env.Model != "Pixel 7 Pro" || env.Brand != "google" || env.Android != "14" || env.SDK != "34" {
		t.Fatalf("unexpected basic env: %+v", env)
	}
	if env.Screen != "1440x3120" || env.RAM != "11.0 GB" || env.Battery != "85%" {
		t.Errorf("unexpected hardware info: screen=%q ram=%q battery=%q", env.Screen, env.RAM, env.Battery)
	}
	if !env.Rooted || env.Magisk != "installed" || env.MagiskVer != "27.0:MAGISK" || !env.Zygisk || !env.LSPosed || env.LSPosedVer != "1.9.2" {
		t.Errorf("unexpected root/framework info: %+v", env)
	}
	if env.SELinux != "Enforcing" || env.Integrity != "GMS 24.15.16 | boot=orange" {
		t.Errorf("unexpected security info: selinux=%q integrity=%q", env.SELinux, env.Integrity)
	}
}

type memFlowStore struct {
	flows map[string]*types.Flow
}

func (m *memFlowStore) SaveFlow(f *types.Flow) error                      { m.flows[f.ID] = f; return nil }
func (m *memFlowStore) ListFlows(types.FlowFilter) ([]*types.Flow, error) { return nil, nil }
func (m *memFlowStore) DeleteFlow(string) error                           { return nil }
func (m *memFlowStore) UpdateTags(string, []string) error                 { return nil }
func (m *memFlowStore) UpdateSourceRef(string, *types.SourceRef) error    { return nil }
func (m *memFlowStore) Close() error                                      { return nil }
func (m *memFlowStore) GetFlow(id string) (*types.Flow, error) {
	f, ok := m.flows[id]
	if !ok {
		return nil, fmt.Errorf("flow %s not found", id)
	}
	return f, nil
}

func writeSyntheticAPK(t *testing.T, dir string, dexPayload string) string {
	t.Helper()
	apkPath := filepath.Join(dir, "sample.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("dex\n035\x00" + dexPayload + "\x00")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return apkPath
}

func TestDeepTraceLifecycleEventsAndStatePersistence(t *testing.T) {
	certDir := t.TempDir()
	apkPath := writeSyntheticAPK(t, certDir, "https://api.example.com/v2/auth/login\x00sign_token\x00")

	flow := &types.Flow{
		ID:     "flow-1",
		Method: "POST",
		URL:    "https://api.example.com/v2/auth/login?sign_token=abc",
		Host:   "api.example.com",
		Path:   "/v2/auth/login",
	}

	app := &App{
		store:            &memFlowStore{flows: map[string]*types.Flow{flow.ID: flow}},
		certDir:          certDir,
		events:           NewEventBus(),
		settings:         map[string]string{},
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
	}

	// Idle state check
	idle := app.GetDeepTraceState()
	if idle.Running || idle.Status != "idle" || len(idle.Stages) != captrace.TotalPipelineStages {
		t.Fatalf("unexpected initial idle state: %+v", idle)
	}

	// Record emitted Wails events
	var evMu sync.Mutex
	var progressEvents []TraceProgressPayload
	doneCh := make(chan TraceDonePayload, 1)
	errCh := make(chan TraceErrorPayload, 1)
	app.events.SetEmitter(func(event string, data ...interface{}) {
		if len(data) == 0 {
			return
		}
		evMu.Lock()
		defer evMu.Unlock()
		switch event {
		case EventTraceProgress:
			if p, ok := data[0].(TraceProgressPayload); ok {
				progressEvents = append(progressEvents, p)
			}
		case EventTraceDone:
			if d, ok := data[0].(TraceDonePayload); ok {
				select {
				case doneCh <- d:
				default:
				}
			}
		case EventTraceError:
			if e, ok := data[0].(TraceErrorPayload); ok {
				select {
				case errCh <- e:
				default:
				}
			}
		}
	})

	// Start async trace against synthetic local APK
	runID, err := app.StartDeepTrace(flow.ID, "com.example.sample", apkPath, false)
	if err != nil {
		t.Fatalf("StartDeepTrace failed: %v", err)
	}
	if runID == "" {
		t.Fatalf("expected non-empty runID")
	}

	select {
	case done := <-doneCh:
		if done.RunID != runID || done.Result == nil {
			t.Fatalf("unexpected trace:done payload: %+v", done)
		}
		if len(done.Result.DexStrings) == 0 {
			t.Errorf("expected at least 1 DEX match from synthetic APK")
		}
	case errEv := <-errCh:
		t.Fatalf("unexpected trace:error event: %+v", errEv)
	case <-time.After(15 * time.Second):
		_ = app.CancelDeepTrace()
		t.Fatal("timed out waiting for StartDeepTrace completion")
	}

	// Verify progress events were emitted live
	evMu.Lock()
	nProgress := len(progressEvents)
	evMu.Unlock()
	if nProgress < 4 {
		t.Errorf("expected multiple live trace:progress events, got %d", nProgress)
	}

	// Verify state persists cleanly for tab-switch restoration
	finalState := app.GetDeepTraceState()
	if finalState.Running || finalState.Status != "done" || finalState.Percent != 100 || finalState.Result == nil {
		t.Fatalf("unexpected final GetDeepTraceState: running=%v status=%q percent=%d hasResult=%v",
			finalState.Running, finalState.Status, finalState.Percent, finalState.Result != nil)
	}
	if finalState.Counts.DexMatches == 0 {
		t.Errorf("expected persisted DexMatches > 0, got %+v", finalState.Counts)
	}
	if len(finalState.Logs) == 0 {
		t.Errorf("expected persisted log entries")
	}

	// CancelDeepTrace when idle must be safe & idempotent
	if err := app.CancelDeepTrace(); err != nil {
		t.Errorf("CancelDeepTrace when idle failed: %v", err)
	}
	// GetTraceToolsStatus must not panic
	_ = app.GetTraceToolsStatus()
}
