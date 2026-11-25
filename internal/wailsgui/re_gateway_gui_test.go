package wailsgui

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/overkazaf/cap/internal/deobf"
	"github.com/overkazaf/cap/internal/exectrace"
	"github.com/overkazaf/cap/internal/gateway"
	"github.com/overkazaf/cap/internal/retools"
	captrace "github.com/overkazaf/cap/internal/trace"
	"github.com/overkazaf/cap/internal/types"
)

// buildMinimalELF64 creates a tiny valid 64-bit little-endian ARM64 ELF shared object
// suitable for testing pure-Go ELF static analysis and deobf protection scanning.
func buildMinimalELF64(t *testing.T, extraPayload []byte) []byte {
	t.Helper()
	const (
		ehdrSize = 64
		shdrSize = 64
	)
	shstrtab := []byte("\x00.shstrtab\x00.text\x00.rodata\x00")
	textData := []byte{0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6} // mov x0, #0; ret
	rodata := append([]byte("TracerPid:\x00/proc/self/maps\x00Java_com_acme_Sign_compute\x00"), extraPayload...)

	shstrOff := uint64(ehdrSize)
	textOff := shstrOff + uint64(len(shstrtab))
	rodataOff := textOff + uint64(len(textData))
	// Align section header table to 8 bytes
	shoff := (rodataOff + uint64(len(rodata)) + 7) &^ 7

	var buf bytes.Buffer
	// ELF64 header
	hdr := make([]byte, ehdrSize)
	copy(hdr[0:4], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = 2 // ELFCLASS64
	hdr[5] = 1 // ELFDATA2LSB
	hdr[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(hdr[16:18], 3)    // ET_DYN
	binary.LittleEndian.PutUint16(hdr[18:20], 183)  // EM_AARCH64
	binary.LittleEndian.PutUint32(hdr[20:24], 1)    // EV_CURRENT
	binary.LittleEndian.PutUint64(hdr[40:48], shoff)
	binary.LittleEndian.PutUint16(hdr[52:54], ehdrSize)
	binary.LittleEndian.PutUint16(hdr[58:60], shdrSize)
	binary.LittleEndian.PutUint16(hdr[60:62], 4) // 4 sections: null, .shstrtab, .text, .rodata
	binary.LittleEndian.PutUint16(hdr[62:64], 1) // shstrndx = 1
	buf.Write(hdr)
	buf.Write(shstrtab)
	buf.Write(textData)
	buf.Write(rodata)
	for uint64(buf.Len()) < shoff {
		buf.WriteByte(0)
	}

	writeShdr := func(nameOff, shType uint32, flags, addr, off, size uint64) {
		s := make([]byte, shdrSize)
		binary.LittleEndian.PutUint32(s[0:4], nameOff)
		binary.LittleEndian.PutUint32(s[4:8], shType)
		binary.LittleEndian.PutUint64(s[8:16], flags)
		binary.LittleEndian.PutUint64(s[16:24], addr)
		binary.LittleEndian.PutUint64(s[24:32], off)
		binary.LittleEndian.PutUint64(s[32:40], size)
		buf.Write(s)
	}
	// 0: SHT_NULL
	writeShdr(0, 0, 0, 0, 0, 0)
	// 1: .shstrtab (offset 1 in shstrtab)
	writeShdr(1, 3, 0, 0, shstrOff, uint64(len(shstrtab)))
	// 2: .text (offset 11 in shstrtab)
	writeShdr(11, 1, 0x6, 0x1000, textOff, uint64(len(textData)))
	// 3: .rodata (offset 17 in shstrtab)
	writeShdr(17, 1, 0x2, 0x2000, rodataOff, uint64(len(rodata)))

	return buf.Bytes()
}

func buildMinimalAPK(t *testing.T, elfBytes []byte) string {
	t.Helper()
	apkPath := filepath.Join(t.TempDir(), "protected.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create apk: %v", err)
	}
	zw := zip.NewWriter(f)
	entries := map[string][]byte{
		"AndroidManifest.xml":        []byte("manifest com.acme.protected"),
		"classes.dex":                []byte("dex\n035\x00stub"),
		"assets/libjiagu.so":         elfBytes,
		"lib/arm64-v8a/libjiagu.so":  elfBytes,
	}
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}
	return apkPath
}

func newTestREGatewayApp(t *testing.T, flows map[string]*types.Flow) *App {
	t.Helper()
	tmpDir := t.TempDir()
	return &App{
		store:            &memFlowStore{flows: flows},
		certDir:          tmpDir,
		events:           NewEventBus(),
		settings:         loadSettings(filepath.Join(tmpDir, "settings.json")),
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
	}
}

func TestDefaultSettingsIncludeREAndGatewayKeys(t *testing.T) {
	settings := loadSettings(filepath.Join(t.TempDir(), "missing-settings.json"))
	for _, key := range []string{
		"re_r2_path", "re_java_path", "re_mvn_path",
		"re_unidbg_dir", "re_python_path",
		"re_qiling_python_path", "re_angr_python_path",
		"re_qiling_rootfs",
	} {
		if _, ok := settings[key]; !ok {
			t.Errorf("loadSettings missing default key %q", key)
		}
	}
	if got := settings["gateway_addr"]; got != "127.0.0.1:9090" {
		t.Fatalf("gateway_addr default = %q, want 127.0.0.1:9090", got)
	}
}

func TestREToolsGUIBindingsAndTraceHarness(t *testing.T) {
	app := newTestREGatewayApp(t, nil)

	// Toolchain probe & config persistence
	tc, err := app.UpdateREToolchainConfig(retools.ToolchainConfig{
		R2Path:           "/nonexistent/r2",
		QilingPythonPath: "/nonexistent/qiling-py",
		AngrPythonPath:   "/nonexistent/angr-py",
		QilingRootFS:     "/tmp/ql-rootfs",
	})
	if err != nil {
		t.Fatalf("UpdateREToolchainConfig: %v", err)
	}
	if tc.R2.Ready {
		t.Fatalf("expected invalid r2 path not ready")
	}
	if got := app.GetSetting("re_qiling_rootfs"); got != "/tmp/ql-rootfs" {
		t.Fatalf("re_qiling_rootfs setting = %q, want /tmp/ql-rootfs", got)
	}
	if got := app.GetSetting("re_qiling_python_path"); got != "/nonexistent/qiling-py" {
		t.Fatalf("re_qiling_python_path setting = %q, want /nonexistent/qiling-py", got)
	}
	if got := app.GetSetting("re_angr_python_path"); got != "/nonexistent/angr-py" {
		t.Fatalf("re_angr_python_path setting = %q, want /nonexistent/angr-py", got)
	}
	_ = app.GetREToolchain(false)

	// Binary analysis via pure-Go ELF fallback (since r2 path is non-existent)
	elfPath := filepath.Join(t.TempDir(), "libsign.so")
	if err := os.WriteFile(elfPath, buildMinimalELF64(t, nil), 0o644); err != nil {
		t.Fatalf("write elf: %v", err)
	}
	analysis, err := app.AnalyzeBinary(elfPath)
	if err != nil {
		t.Fatalf("AnalyzeBinary: %v", err)
	}
	if !strings.Contains(strings.ToLower(analysis.Format), "elf") ||
		(analysis.Arch != "arm64" && analysis.Arch != "aarch64") {
		t.Fatalf("unexpected binary analysis: format=%s arch=%s", analysis.Format, analysis.Arch)
	}

	// Projects CRUD
	allProjects := app.ListREProjects("")
	if len(allProjects) == 0 {
		t.Fatal("expected built-in RE projects")
	}
	unidbgProjects := app.ListREProjects(retools.EngineUnidbg)
	for _, p := range unidbgProjects {
		if p.Engine != retools.EngineUnidbg {
			t.Fatalf("ListREProjects(unidbg) returned engine=%s", p.Engine)
		}
	}
	saved, err := app.SaveREProject(retools.REProject{
		Name:   "Test Unidbg Signer",
		Engine: retools.EngineUnidbg,
		Code:   "public class TestSigner {}",
	})
	if err != nil {
		t.Fatalf("SaveREProject: %v", err)
	}
	if err := app.DeleteREProject(saved.ID); err != nil {
		t.Fatalf("DeleteREProject: %v", err)
	}

	// Idle job state & log clear & cancel
	js := app.GetREJobState()
	if js == nil || js.Running || js.Status != retools.StatusIdle {
		t.Fatalf("unexpected initial job state: %+v", js)
	}
	app.ClearREJobLogs()
	if err := app.CancelREJob(); err != nil {
		t.Fatalf("CancelREJob on idle: %v", err)
	}

	// GenerateREHarnessFromTrace using current DeepTrace result
	app.traceState = &DeepTraceState{
		Status: "done",
		Result: &captrace.TraceResult{
			FlowID:  "flow-re-1",
			Package: "com.acme.pay",
			APKPath: "/tmp/pay.apk",
			Method:  "POST",
			URL:     "https://api.acme.test/v1/checkout",
			NativeTrace: []captrace.NativeRef{
				{SOFile: "lib/arm64-v8a/libsign.so", Function: "Java_com_acme_pay_Signer_calcSign"},
			},
		},
	}
	harness, err := app.GenerateREHarnessFromTrace(retools.EngineUnidbg, retools.GenerateOptions{
		HTTPServerMode: true,
		HTTPPort:       8899,
	})
	if err != nil {
		t.Fatalf("GenerateREHarnessFromTrace: %v", err)
	}
	if harness.Engine != retools.EngineUnidbg || !strings.Contains(harness.Code, "com/acme/pay/Signer") {
		t.Fatalf("unexpected generated harness: engine=%s targetClass=%s", harness.Engine, harness.TargetClass)
	}
}

func TestDeobfGUIBindingsAndScanProtection(t *testing.T) {
	app := newTestREGatewayApp(t, nil)
	elfBytes := buildMinimalELF64(t, nil)

	// Scan ELF
	soPath := filepath.Join(t.TempDir(), "libsec.so")
	if err := os.WriteFile(soPath, elfBytes, 0o644); err != nil {
		t.Fatalf("write so: %v", err)
	}
	elfReport, err := app.ScanProtection(soPath)
	if err != nil {
		t.Fatalf("ScanProtection(ELF): %v", err)
	}
	if elfReport.TargetKind != deobf.TargetKindELF {
		t.Fatalf("elfReport.TargetKind = %q, want elf", elfReport.TargetKind)
	}

	// Scan APK (routed by .apk suffix)
	apkPath := buildMinimalAPK(t, elfBytes)
	apkReport, err := app.ScanProtection(apkPath)
	if err != nil {
		t.Fatalf("ScanProtection(APK): %v", err)
	}
	if apkReport.TargetKind != deobf.TargetKindAPK || len(apkReport.Packers) == 0 {
		t.Fatalf("expected APK packer finding, got kind=%s packers=%d", apkReport.TargetKind, len(apkReport.Packers))
	}

	// All script generators & VMP trace analyzer
	if sc := app.GenerateStealthScript(deobf.DefaultStealthOptions(), apkReport); sc == nil || sc.Code == "" {
		t.Fatal("GenerateStealthScript returned empty script")
	}
	if sc := app.GenerateDexUnpackerScript("com.acme.app"); sc == nil || sc.Code == "" {
		t.Fatal("GenerateDexUnpackerScript returned empty script")
	}
	if sc := app.GenerateOLLVMDeflattenScript(soPath, "0x1000", "arm64"); sc == nil || sc.Code == "" {
		t.Fatal("GenerateOLLVMDeflattenScript returned empty script")
	}
	if sc := app.GenerateStringDecryptScript("frida", soPath, apkPath); sc == nil || sc.Code == "" {
		t.Fatal("GenerateStringDecryptScript returned empty script")
	}
	if sc := app.GenerateJavaDeobfScript("com.acme.app"); sc == nil || sc.Code == "" {
		t.Fatal("GenerateJavaDeobfScript returned empty script")
	}
	if sc := app.GenerateVMPStalkerScript("libvmp.so", "0x1200", 1000); sc == nil || sc.Code == "" {
		t.Fatal("GenerateVMPStalkerScript returned empty script")
	}
	if sc := app.GenerateVMPRegisterNativesScript("com.acme.app"); sc == nil || sc.Code == "" {
		t.Fatal("GenerateVMPRegisterNativesScript returned empty script")
	}
	if sc := app.GenerateUnidbgVMPTraceScript(apkPath, "libvmp.so", "com/acme/VMP", "run"); sc == nil || sc.Code == "" {
		t.Fatal("GenerateUnidbgVMPTraceScript returned empty script")
	}

	rawVMP := strings.Join([]string{
		`[CAP_VMP] {"pc":"0x7000001000","insn":"br x8","target":"0x7000002000"}`,
		`[CAP_VMP] {"pc":"0x7000002000","insn":"add x0, x0, #1"}`,
		`[CAP_VMP] {"pc":"0x7000001000","insn":"br x8","target":"0x7000003000"}`,
	}, "\n")
	vmpRes := app.AnalyzeVMPTrace(rawVMP, "0x7000000000")
	if vmpRes == nil || vmpRes.TotalInstructions == 0 {
		t.Fatalf("unexpected VMPTraceAnalysis: %+v", vmpRes)
	}
}

func TestExecTraceGUIBindingsImportTaintDiffExport(t *testing.T) {
	app := newTestREGatewayApp(t, nil)

	traceA := strings.Join([]string{
		`[12:00:00 001][libsign.so 0x1000] [e0 03 01 aa] 0x40001000: "mov x0, x1" x1=0x1122 => x0=0x1122`,
		`[12:00:00 002][libsign.so 0x1004] [02 00 03 ca] 0x40001004: "eor x2, x0, x3" x0=0x1122 x3=0xff => x2=0x11dd`,
		`[12:00:00 003][libsign.so 0x1008] [44 00 00 91] 0x40001008: "add x4, x2, #1" x2=0x11dd => x4=0x11de`,
	}, "\n")
	traceB := strings.Join([]string{
		`[12:00:00 001][libsign.so 0x1000] [e0 03 01 aa] 0x50001000: "mov x0, x1" x1=0x1122 => x0=0x1122`,
		`[12:00:00 002][libsign.so 0x1004] [02 00 03 ca] 0x50001004: "eor x2, x0, x3" x0=0x1122 x3=0xaa => x2=0x1188`,
		`[12:00:00 003][libsign.so 0x100c] [44 00 00 91] 0x5000100c: "sub x4, x2, #1" x2=0x1188 => x4=0x1187`,
	}, "\n")

	sessA, err := app.ImportExecTrace("run-a", "unidbg", traceA, "0x40000000")
	if err != nil {
		t.Fatalf("ImportExecTrace A: %v", err)
	}
	traceFile := filepath.Join(t.TempDir(), "run-b.log")
	if err := os.WriteFile(traceFile, []byte(traceB), 0o644); err != nil {
		t.Fatalf("write traceB: %v", err)
	}
	sessB, err := app.ImportExecTraceFile(traceFile, "unidbg", "0x50000000")
	if err != nil {
		t.Fatalf("ImportExecTraceFile B: %v", err)
	}

	listed := app.ListExecTraces()
	if len(listed) != 2 {
		t.Fatalf("ListExecTraces len = %d, want 2", len(listed))
	}

	gotA, err := app.GetExecTrace(sessA.ID)
	if err != nil || len(gotA.Events) != 3 {
		t.Fatalf("GetExecTrace(A) err=%v events=%d", err, len(gotA.Events))
	}

	page, err := app.QueryExecTraceEvents(sessA.ID, exectrace.EventFilter{Search: "eor", Limit: 10})
	if err != nil || page.Total != 1 {
		t.Fatalf("QueryExecTraceEvents err=%v total=%d", err, page.Total)
	}

	taintRes, err := app.RunExecTraceTaint(exectrace.TaintRequest{
		SessionID: sessA.ID,
		Direction: exectrace.TaintForward,
		StartSeq:  1,
		SeedReg:   "x0",
	})
	if err != nil {
		t.Fatalf("RunExecTraceTaint: %v", err)
	}
	if len(taintRes.TaintedSteps) < 2 {
		t.Fatalf("expected tainted propagation steps >= 2, got %d", len(taintRes.TaintedSteps))
	}

	diffRes, err := app.DiffExecTraces(sessA.ID, sessB.ID, 10)
	if err != nil {
		t.Fatalf("DiffExecTraces: %v", err)
	}
	if diffRes.FirstDivergence == nil {
		t.Fatalf("expected divergence between traceA and traceB: %+v", diffRes)
	}

	coll := app.GenerateExecTraceCollector("stalker", exectrace.DefaultCollectorConfig())
	if coll == nil || coll.Code == "" {
		t.Fatal("GenerateExecTraceCollector returned empty collector")
	}

	tenetOut, err := app.ExportExecTrace(sessA.ID, exectrace.ExportTenet)
	if err != nil || !strings.Contains(tenetOut, "pc=0x40001000") {
		t.Fatalf("ExportExecTrace(tenet) err=%v out=%q", err, tenetOut)
	}

	if err := app.DeleteExecTrace(sessB.ID); err != nil {
		t.Fatalf("DeleteExecTrace: %v", err)
	}
	if len(app.ListExecTraces()) != 1 {
		t.Fatalf("expected 1 trace after delete")
	}
}

func TestGatewayGUIBindingsFullLifecycleAndPublishFlow(t *testing.T) {
	// Upstream mock server echoing request query & headers.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"path":   r.URL.Path,
			"sign":   r.URL.Query().Get("sign"),
			"q":      r.URL.Query().Get("q"),
			"ua":     r.Header.Get("User-Agent"),
			"method": r.Method,
		})
	}))
	defer upstream.Close()

	// Proxy provider mock server.
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("127.0.0.1:18081\nsocks5://127.0.0.1:18082\n"))
	}))
	defer providerSrv.Close()

	flow := &types.Flow{
		ID:         "flow-gw-1",
		Method:     "GET",
		URL:        upstream.URL + "/v1/search?q=coffee",
		Host:       strings.TrimPrefix(upstream.URL, "http://"),
		Path:       "/v1/search",
		ReqHeaders: map[string]string{"X-Client": "cap-test"},
	}

	app := newTestREGatewayApp(t, map[string]*types.Flow{flow.ID: flow})

	var evMu sync.Mutex
	var eventsSeen []string
	app.events.SetEmitter(func(event string, data ...interface{}) {
		evMu.Lock()
		eventsSeen = append(eventsSeen, event)
		evMu.Unlock()
	})

	// Config & status
	cfg, err := app.UpdateGatewayConfig(gateway.GatewayConfig{
		ListenAddr:  "127.0.0.1:0",
		RequireAuth: false,
		MaxLogs:     100,
	})
	if err != nil {
		t.Fatalf("UpdateGatewayConfig: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:0" {
		t.Fatalf("ListenAddr = %q, want 127.0.0.1:0", cfg.ListenAddr)
	}
	// Verify UpdateGatewayConfig persisted gateway_addr to settings.json
	reloadedSettings := loadSettings(filepath.Join(app.certDir, "settings.json"))
	if reloadedSettings["gateway_addr"] != "127.0.0.1:0" {
		t.Fatalf("persisted gateway_addr = %q, want 127.0.0.1:0", reloadedSettings["gateway_addr"])
	}

	// Publish flow as gateway route
	route, err := app.PublishFlowToGateway(flow.ID, "search-api", "Search API")
	if err != nil {
		t.Fatalf("PublishFlowToGateway: %v", err)
	}
	if route.Slug != "search-api" || route.SourceFlowID != flow.ID {
		t.Fatalf("unexpected published route: %+v", route)
	}

	// Device presets & creation
	presets := app.ListGatewayDevicePresets()
	if len(presets) == 0 {
		t.Fatal("expected built-in device presets")
	}
	dev, err := app.CreateGatewayDeviceFromPreset(presets[0].ID, "QA Pixel")
	if err != nil {
		t.Fatalf("CreateGatewayDeviceFromPreset: %v", err)
	}
	if len(app.ListGatewayDevices()) != 1 {
		t.Fatalf("expected 1 device in pool")
	}

	// Signer CRUD & direct test
	signer, err := app.SaveGatewaySigner(gateway.SignerProvider{
		Name:          "HMAC Signer",
		Kind:          gateway.SignerKindBuiltinHMAC,
		Enabled:       true,
		HMACAlgorithm: "hmac-sha256",
		HMACSecret:    "top-secret",
		InjectTarget:  gateway.InjectTargetQuery,
		InjectField:   "sign",
	})
	if err != nil {
		t.Fatalf("SaveGatewaySigner: %v", err)
	}
	sigOut, err := app.TestGatewaySigner(*signer, gateway.SignerInput{
		Method: "GET",
		URL:    upstream.URL + "/v1/search?q=coffee",
		Query:  map[string]string{"q": "coffee"},
	})
	if err != nil || sigOut.Sign == "" {
		t.Fatalf("TestGatewaySigner failed: err=%v out=%+v", err, sigOut)
	}

	// Attach signer & device to route and test in-process invocation
	route.SignerID = signer.ID
	route.RequireDevice = true
	route, err = app.SaveGatewayRoute(*route)
	if err != nil {
		t.Fatalf("SaveGatewayRoute: %v", err)
	}

	invokeRes, err := app.TestGatewayRoute(route.Slug, gateway.TestInvokeRequest{
		Query: map[string]string{"q": "espresso"},
	})
	if err != nil || !invokeRes.OK || invokeRes.Status != http.StatusOK {
		t.Fatalf("TestGatewayRoute failed: err=%v res=%+v", err, invokeRes)
	}
	if invokeRes.SignedParams["sign"] == "" || invokeRes.DeviceID != dev.ID {
		t.Fatalf("expected signed param and device ID, got %+v", invokeRes)
	}

	// OpenAPI spec contains /gw/search-api
	openAPI, err := app.GetGatewayOpenAPI()
	if err != nil || !strings.Contains(openAPI, "/gw/search-api") {
		t.Fatalf("GetGatewayOpenAPI err=%v spec=%s", err, openAPI)
	}

	// StartGateway & StopGateway on 127.0.0.1:0
	started, err := app.StartGateway("127.0.0.1:0")
	if err != nil || !started.Running || started.ListenAddr == "" {
		t.Fatalf("StartGateway failed: err=%v stats=%+v", err, started)
	}

	resp, err := http.Get("http://" + started.ListenAddr + "/health")
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/health status = %d, want 200", resp.StatusCode)
	}

	// Logs & ClearLogs
	if logs := app.ListGatewayLogs(10); len(logs) == 0 {
		t.Fatal("expected at least 1 gateway invocation log")
	}
	app.ClearGatewayLogs()
	if logs := app.ListGatewayLogs(10); len(logs) != 0 {
		t.Fatalf("expected 0 logs after ClearGatewayLogs, got %d", len(logs))
	}

	// Bulk import proxies (including password containing ',' and ';') + provider fetch + delete
	imported, err := app.BulkImportGatewayProxies("127.0.0.1:19001\n127.0.0.1:19002:user:pass\nsocks5://alice:p,a;ss@127.0.0.1:19003\n", "socks5", "US", []string{"residential"})
	if err != nil || imported != 3 {
		t.Fatalf("BulkImportGatewayProxies err=%v imported=%d", err, imported)
	}
	proxies := app.ListGatewayProxies()
	if len(proxies) != 3 || !strings.HasPrefix(proxies[0].URL, "socks5://") || proxies[0].Region != "US" {
		t.Fatalf("unexpected imported proxies: %+v", proxies)
	}
	foundSpecialPass := false
	for _, p := range proxies {
		if p.URL == "socks5://127.0.0.1:19003" && p.Username == "alice" && p.Password == "p,a;ss" {
			foundSpecialPass = true
		}
	}
	if !foundSpecialPass {
		t.Fatalf("expected URL with ',' and ';' in password to stay intact, got: %+v", proxies)
	}

	fetched, err := app.FetchGatewayProxiesFromProvider(providerSrv.URL, gateway.ProviderFormatLines, "")
	if err != nil || fetched != 2 {
		t.Fatalf("FetchGatewayProxiesFromProvider err=%v fetched=%d", err, fetched)
	}
	// Regression: invalid provider URL must return error and NOT clobber saved valid ProviderURL
	if _, err := app.FetchGatewayProxiesFromProvider("ftp://invalid.provider/list", gateway.ProviderFormatLines, ""); err == nil {
		t.Fatal("expected error for unsupported provider URL scheme")
	}
	if got := app.GetProxyPoolConfig().ProviderURL; got != providerSrv.URL {
		t.Fatalf("invalid provider fetch clobbered saved ProviderURL: got %q, want %q", got, providerSrv.URL)
	}
	if err := app.UpdateProxyPoolConfig(gateway.ProxyPoolConfig{Strategy: gateway.StrategyRandom, FailoverRetries: 1}); err != nil {
		t.Fatalf("UpdateProxyPoolConfig: %v", err)
	}
	if app.GetProxyPoolConfig().Strategy != gateway.StrategyRandom {
		t.Fatalf("expected random strategy")
	}
	if err := app.DeleteGatewayProxy(proxies[0].ID); err != nil {
		t.Fatalf("DeleteGatewayProxy: %v", err)
	}

	// StopGateway and verify App.Shutdown is also safe
	stopped, err := app.StopGateway()
	if err != nil || stopped.Running {
		t.Fatalf("StopGateway err=%v running=%v", err, stopped.Running)
	}
	app.Shutdown(context.Background())

	// Verify event bus received gateway:status and gateway:invoke
	evMu.Lock()
	joined := strings.Join(eventsSeen, ",")
	evMu.Unlock()
	if !strings.Contains(joined, EventGatewayStatus) || !strings.Contains(joined, EventGatewayInvoke) {
		t.Fatalf("expected %s and %s events, got: %s", EventGatewayStatus, EventGatewayInvoke, joined)
	}

	// Clean up remaining resources
	if err := app.DeleteGatewayRoute(route.ID); err != nil {
		t.Fatalf("DeleteGatewayRoute: %v", err)
	}
	if err := app.DeleteGatewaySigner(signer.ID); err != nil {
		t.Fatalf("DeleteGatewaySigner: %v", err)
	}
	if err := app.DeleteGatewayDevice(dev.ID); err != nil {
		t.Fatalf("DeleteGatewayDevice: %v", err)
	}
}
