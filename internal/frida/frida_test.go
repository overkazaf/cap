package frida

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	captrace "github.com/overkazaf/cap/internal/trace"
)

func TestMapABIToFridaArch(t *testing.T) {
	cases := map[string]string{
		"arm64-v8a":   "arm64",
		"armeabi-v7a": "arm",
		"armeabi":     "arm",
		"x86_64":      "x86_64",
		"x86":         "x86",
		"mips":        "",
	}
	for abi, want := range cases {
		if got := MapABIToFridaArch(abi); got != want {
			t.Errorf("MapABIToFridaArch(%q) = %q, want %q", abi, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		host, server, want string
	}{
		{"16.5.9", "16.5.9", VersionMatchExact},
		{"16.5.9", "16.4.2", VersionMatchMinor},
		{"16.5.9", "15.2.2", VersionMatchMajor},
		{"16.5.9", "", VersionMatchUnknown},
		{"", "16.5.9", VersionMatchUnknown},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.host, tc.server); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %q, want %q", tc.host, tc.server, got, tc.want)
		}
	}
}

func TestSanitizeRemoteName(t *testing.T) {
	if got, err := SanitizeRemoteName(""); err != nil || got != DefaultRemoteName {
		t.Fatalf("empty remote name = (%q, %v), want (%q, nil)", got, err, DefaultRemoteName)
	}
	if got, err := SanitizeRemoteName("hluda-srv_16.5"); err != nil || got != "hluda-srv_16.5" {
		t.Fatalf("stealth name = (%q, %v)", got, err)
	}
	if _, err := SanitizeRemoteName("bad;rm -rf /"); err == nil {
		t.Fatalf("expected error for shell metacharacters in remote name")
	}
}

func TestParseServerProbeOutput(t *testing.T) {
	raw := `
ABI=arm64-v8a
ROOT=uid=0(root) gid=0(root)
PS_START
12345 frida-server /data/local/tmp/frida-server -l 0.0.0.0:27043 -D
PS_END
BINS_START
/data/local/tmp/frida-server-16.5.9
/data/local/tmp/frida-server
BINS_END
PORT_CHECK=
`
	st := parseServerProbeOutput("emulator-5554", raw, DefaultPort, "16.5.9")
	if !st.Connected || !st.Rooted {
		t.Fatalf("expected connected & rooted, got %+v", st)
	}
	if st.DeviceABI != "arm64-v8a" || st.FridaArch != "arm64" {
		t.Errorf("unexpected ABI/arch: %q / %q", st.DeviceABI, st.FridaArch)
	}
	if !st.Running || st.PID != "12345" || st.Port != 27043 || st.ListenAddr != "0.0.0.0:27043" {
		t.Errorf("unexpected running state: %+v", st)
	}
	if st.BinaryPath != "/data/local/tmp/frida-server" || len(st.AllBinaries) != 2 {
		t.Errorf("unexpected binaries: %q (%v)", st.BinaryPath, st.AllBinaries)
	}
}

func TestParseFridaPSOutput(t *testing.T) {
	raw := `
  PID  Name             Identifier
-----  ---------------  -------------------------
 4211  KuGou Music      com.kugou.android
    -  Settings         com.android.settings
`
	entries := parseFridaPSOutput(raw)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}
	if !entries[0].Running || entries[0].PID != 4211 || entries[0].Identifier != "com.kugou.android" || entries[0].Name != "KuGou Music" {
		t.Errorf("unexpected entry[0]: %+v", entries[0])
	}
	if entries[1].Running || entries[1].PID != 0 || entries[1].Identifier != "com.android.settings" {
		t.Errorf("unexpected entry[1]: %+v", entries[1])
	}
}

func TestScriptStoreCRUDAndHotReload(t *testing.T) {
	dir := t.TempDir()
	store, err := NewScriptStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	initial := store.List()
	if len(initial) < 6 {
		t.Fatalf("expected >= 6 built-in scripts, got %d", len(initial))
	}

	// Save a custom script
	saved, err := store.Save(Script{
		Name:        "My Sign Hook",
		Description: "Hooks sign generator",
		Category:    "crypto",
		Code:        "Java.perform(function(){ send({cap_cat:'crypto', hook:'sign'}); });",
		Tags:        []string{"sign", "custom"},
	})
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if saved.Builtin || !strings.HasPrefix(saved.ID, "user:") {
		t.Fatalf("unexpected saved metadata: %+v", saved)
	}

	got, ok := store.Get(saved.ID)
	if !ok || got.Name != "My Sign Hook" {
		t.Fatalf("Get(%q) = (%+v, %v)", saved.ID, got, ok)
	}

	// Simulate external file added on disk -> List should hot-reload automatically
	extPath := filepath.Join(dir, "external-hook.json")
	if err := os.WriteFile(extPath, []byte(`{"id":"user:external-hook","name":"External Hook","category":"custom","code":"console.log('ext')"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("user:external-hook"); !ok {
		t.Fatalf("expected hot-reload to pick up externally written script")
	}

	// Built-in cannot be deleted
	if err := store.Delete("builtin:ssl-unpin-universal"); err == nil {
		t.Fatalf("expected error deleting built-in template")
	}
	// Custom can be deleted
	if err := store.Delete(saved.ID); err != nil {
		t.Fatalf("Delete custom script failed: %v", err)
	}
	if _, ok := store.Get(saved.ID); ok {
		t.Fatalf("deleted script should no longer exist")
	}
}

func TestSessionManagerMockBridgeAndHotReload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell mock python requires unix")
	}

	dir := t.TempDir()
	// Create a fake "python3" executable that implements both toolchain probe and our NDJSON bridge protocol
	mockPy := filepath.Join(dir, "mock-python3")
	mockScript := `#!/bin/sh
if [ "$1" = "-c" ]; then
  echo "PY=3.11.8"
  echo "FRIDA=16.5.9"
  exit 0
fi
# Bridge run: args are -u <bridge.py> <cfg.json>
echo '{"type":"lifecycle","event":"connecting","target":"com.demo.app","mode":"attach"}'
echo '{"type":"lifecycle","event":"attached","pid":4321,"target":"com.demo.app","paused":false}'
echo '{"type":"lifecycle","event":"loaded","pid":4321}'
echo '{"type":"send","payload":{"cap_cat":"crypto","hook":"MessageDigest.digest","algorithm":"MD5","output_hex":"deadbeef"}}'
echo '{"type":"console","level":"info","message":"hello from frida"}'
while IFS= read -r line; do
  case "$line" in
    *'"reload"'*)
      echo '{"type":"lifecycle","event":"reloaded"}'
      echo '{"type":"send","payload":{"cap_cat":"trace","hook":"reloadedHook","detail":"hot reload works"}}'
      ;;
    *'"detach"'*)
      echo '{"type":"lifecycle","event":"detached","reason":"application-requested"}'
      exit 0
      ;;
  esac
done
`
	if err := os.WriteFile(mockPy, []byte(mockScript), 0755); err != nil {
		t.Fatal(err)
	}

	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetToolchainConfig(ToolchainConfig{PythonPath: mockPy})

	tc := mgr.GetToolchain(true)
	if !tc.Ready || tc.Driver != DriverPythonBridge || tc.FridaVersion != "16.5.9" {
		t.Fatalf("unexpected mock toolchain: %+v", tc)
	}

	var evMu sync.Mutex
	var events []LogEvent
	reloadedCh := make(chan struct{}, 1)
	mgr.SetCallbacks(func(ev LogEvent) {
		evMu.Lock()
		events = append(events, ev)
		evMu.Unlock()
		if strings.Contains(ev.Message, "hot reload works") {
			select {
			case reloadedCh <- struct{}{}:
			default:
			}
		}
	}, nil)

	st, err := mgr.StartSession(SessionConfig{
		Serial:     "test-dev",
		Target:     "com.demo.app",
		Mode:       ModeAttach,
		ScriptCode: "console.log('v1');",
		ScriptName: "Mock Test",
		NoPause:    true,
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	if !st.Running || !st.CanHotReload || st.Driver != DriverPythonBridge {
		t.Fatalf("unexpected initial session state: %+v", st)
	}

	// Wait for attached + initial send event
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		snap := mgr.GetSessionState()
		if snap.PID == 4321 && snap.HookCount >= 1 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	snap := mgr.GetSessionState()
	if snap.PID != 4321 || snap.HookCount < 1 {
		t.Fatalf("expected PID=4321 and HookCount>=1, got pid=%d hooks=%d events=%d", snap.PID, snap.HookCount, len(snap.Events))
	}

	// Trigger live Hot Reload
	if err := mgr.ReloadScript("console.log('v2');"); err != nil {
		t.Fatalf("ReloadScript failed: %v", err)
	}
	select {
	case <-reloadedCh:
	case <-time.After(4 * time.Second):
		t.Fatalf("timed out waiting for hot-reload event")
	}

	snap2 := mgr.GetSessionState()
	if snap2.ReloadCount != 1 {
		t.Errorf("expected ReloadCount=1, got %d", snap2.ReloadCount)
	}

	// Clean detach
	if err := mgr.StopSession(); err != nil {
		t.Fatalf("StopSession failed: %v", err)
	}
	finalSnap := mgr.GetSessionState()
	if finalSnap.Running || finalSnap.Status != StatusStopped {
		t.Fatalf("expected stopped session, got running=%v status=%q", finalSnap.Running, finalSnap.Status)
	}
}

func TestGenerateHookFromTrace(t *testing.T) {
	tr := &captrace.TraceResult{
		FlowID:  "flow-42",
		Method:  "POST",
		URL:     "https://api.example.com/v2/login?sign=abc",
		Package: "com.example.shop",
		JavaTrace: []captrace.JavaRef{
			{
				Class:         "com.example.shop.net.AuthClient",
				Method:        "buildSignedRequest",
				MatchedTerm:   "/v2/login",
				CallsNative:   true,
				NativeMethods: []string{"nativeSign"},
			},
		},
		DexXRefs: []captrace.DexMethodRef{
			{
				ClassName:    "com.example.shop.crypto.Signer",
				MethodName:   "computeHmac",
				Category:     "crypto",
				MatchedTerms: []string{"sign"},
			},
		},
		NativeTrace: []captrace.NativeRef{
			{
				SOFile:   "lib/arm64-v8a/libsigner.so",
				Function: "Java_com_example_shop_net_AuthClient_nativeSign",
				Address:  "0x14a8",
			},
		},
		Report: &captrace.TraceReport{
			ParamProvenance: []captrace.ParamTrace{
				{Name: "sign", Role: "sign"},
				{Name: "x-token", Role: "auth"},
			},
		},
	}

	opts := DefaultHookGenOptions()
	opts.IncludeSSLUnpin = true
	gen := GenerateHookFromTrace(tr, opts)

	if gen.TargetPackage != "com.example.shop" {
		t.Errorf("TargetPackage = %q, want com.example.shop", gen.TargetPackage)
	}
	if len(gen.JavaTargets) < 3 {
		t.Errorf("expected >= 3 Java targets (buildSignedRequest, nativeSign, computeHmac), got %d: %+v", len(gen.JavaTargets), gen.JavaTargets)
	}
	if len(gen.NativeTargets) != 1 || gen.NativeTargets[0].SOFile != "libsigner.so" {
		t.Errorf("unexpected NativeTargets: %+v", gen.NativeTargets)
	}
	for _, needle := range []string{
		`"com.example.shop.net.AuthClient"`,
		`"buildSignedRequest"`,
		`"nativeSign"`,
		`"com.example.shop.crypto.Signer"`,
		`"computeHmac"`,
		`"libsigner.so"`,
		`"Java_com_example_shop_net_AuthClient_nativeSign"`,
		`MessageDigest`,
		`TrustManagerImpl`,
	} {
		if !strings.Contains(gen.Code, needle) {
			t.Errorf("generated JS missing expected snippet %s", needle)
		}
	}
	if len(gen.SignParams) != 2 {
		t.Errorf("expected 2 sign/auth params, got %v", gen.SignParams)
	}
}

func TestSummarizePayloadMap(t *testing.T) {
	if s := summarizePayloadMap(map[string]any{"hook": "okhttp3", "method": "POST", "url": "https://a.com/x"}); s != "POST https://a.com/x" {
		t.Errorf("got %q", s)
	}
	if s := summarizePayloadMap(map[string]any{"hook": "MD", "algorithm": "SHA-256", "output_hex": "aabb"}); s != "[MD] SHA-256 -> aabb" {
		t.Errorf("got %q", s)
	}
	if s := summarizePayloadMap(map[string]any{"hook": "File.exists", "blocked": "/su"}); s != "[File.exists] bypassed /su" {
		t.Errorf("got %q", s)
	}
	_ = fmt.Sprintf("ok")
}
