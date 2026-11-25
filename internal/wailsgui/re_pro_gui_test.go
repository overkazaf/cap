package wailsgui

import (
	"archive/zip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/macho"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/cryptolab"
	"github.com/overkazaf/cap/internal/gateway"
	"github.com/overkazaf/cap/internal/repro"
	"github.com/overkazaf/cap/internal/tlskit"
)

func buildMinimalMachO64ForTest(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint32(buf[0:4], macho.Magic64)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(macho.CpuArm64))
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(macho.TypeExec))
	binary.LittleEndian.PutUint32(buf[16:20], 0) // ncmds
	binary.LittleEndian.PutUint32(buf[20:24], 0) // sizeofcmds
	binary.LittleEndian.PutUint32(buf[24:28], uint32(macho.FlagPIE|macho.FlagNoHeapExecution))
	binary.LittleEndian.PutUint32(buf[28:32], 0) // reserved
	return buf
}

func generateTestClientKeyPair(t *testing.T, dir string) (certPath, keyPath, certPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName:   "cap-test-client",
			Organization: []string{"Cap QA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	kPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, cPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, kPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath, string(cPEM)
}

func writeZipForTest(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip %s: %v", path, err)
	}
	zw := zip.NewWriter(f)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}
}

func TestReproGUIBindings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	app := newTestREGatewayApp(t, nil)

	// 1. AnalyzeUnidbgLog
	rawLog := strings.Join([]string{
		"java.lang.UnsupportedOperationException: callObjectMethodV: android/content/Context->getPackageName()Ljava/lang/String;",
		"WARN [ARM64SyscallHandler] - openat dirfd=-100, pathname=/proc/self/cmdline, oflags=0x0 => -2",
		`WARN [SystemPropertyHook] - __system_property_get("ro.build.fingerprint")`,
		"WARN [DalvikModule] - Library not found: libcrypto.so",
	}, "\n")
	diag := app.AnalyzeUnidbgLog(rawLog)
	if diag == nil || len(diag.MissingJNI) != 1 || len(diag.MissingFiles) != 1 || len(diag.MissingSysProps) != 1 || len(diag.MissingLibraries) != 1 {
		t.Fatalf("unexpected UnidbgStubDiagnosis: %+v", diag)
	}

	// 2. GenerateFridaEnvSnapshotScript
	snap := app.GenerateFridaEnvSnapshotScript("com.acme.pro")
	if snap == nil || !strings.Contains(snap.Code, "com.acme.pro") {
		t.Fatalf("unexpected Frida env snapshot script: %+v", snap)
	}

	// 3-8. DetectJadx, DecompileAPKWithJadx, ListJadxClasses, ReadJadxClassSource, SearchJadxSource, LinkJavaToNative
	tmp := t.TempDir()
	mockJadx := filepath.Join(tmp, "mock-jadx")
	mockScript := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "1.5.1-mock"
  exit 0
fi
OUT=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-d" ]; then
    OUT="$2"
    shift 2
    continue
  fi
  shift
done
mkdir -p "$OUT/sources/com/acme"
cat > "$OUT/sources/com/acme/Sign.java" <<'EOF'
package com.acme;

public class Sign {
    public static native String compute(String payload);
    public native int verify(int code);
}
EOF
exit 0
`
	if err := os.WriteFile(mockJadx, []byte(mockScript), 0o755); err != nil {
		t.Fatalf("write mock jadx: %v", err)
	}
	if err := app.SetSetting("re_jadx_path", mockJadx); err != nil {
		t.Fatalf("SetSetting re_jadx_path: %v", err)
	}
	jInfo := app.DetectJadx("")
	if !jInfo.Available || jInfo.Version != "1.5.1-mock" {
		t.Fatalf("DetectJadx failed: %+v", jInfo)
	}

	apkPath := filepath.Join(tmp, "sample.apk")
	writeZipForTest(t, apkPath, map[string][]byte{
		"AndroidManifest.xml": []byte("manifest"),
		"classes.dex":         []byte("dex\n035\x00"),
	})
	ws, err := app.DecompileAPKWithJadx(apkPath, 100)
	if err != nil {
		t.Fatalf("DecompileAPKWithJadx: %v", err)
	}
	if !strings.HasPrefix(ws.WorkspaceDir, filepath.Join(app.certDir, "jadx-cache")) {
		t.Fatalf("WorkspaceDir = %q, expected under %q", ws.WorkspaceDir, filepath.Join(app.certDir, "jadx-cache"))
	}
	if ws.ClassCount != 1 || ws.NativeClassCount != 1 {
		t.Fatalf("unexpected workspace: %+v", ws)
	}

	classes, err := app.ListJadxClasses(ws.WorkspaceDir, "Sign", 20)
	if err != nil || len(classes) != 1 || !classes[0].HasNative {
		t.Fatalf("ListJadxClasses err=%v classes=%+v", err, classes)
	}

	src, err := app.ReadJadxClassSource(ws.WorkspaceDir, "com.acme.Sign")
	if err != nil || !strings.Contains(src.Source, "compute") {
		t.Fatalf("ReadJadxClassSource err=%v src=%+v", err, src)
	}

	hits, err := app.SearchJadxSource(ws.WorkspaceDir, "compute", 10)
	if err != nil || len(hits) != 1 {
		t.Fatalf("SearchJadxSource err=%v hits=%+v", err, hits)
	}

	regJSON := `[{"class":"com/acme/Sign","name":"verify","signature":"(I)I","fnPtr":"0x401200","module":"libsign.so"}]`
	soPath := filepath.Join(tmp, "libsign.so")
	if err := os.WriteFile(soPath, buildMinimalELF64(t, nil), 0o644); err != nil {
		t.Fatalf("write so: %v", err)
	}
	linkRep, err := app.LinkJavaToNative(ws.WorkspaceDir, soPath, regJSON)
	if err != nil || linkRep.TotalNativeMethods != 2 || linkRep.DynamicCount != 1 {
		t.Fatalf("LinkJavaToNative err=%v rep=%+v", err, linkRep)
	}

	// 9-10. ExportSymbolScript & ImportSymbolBundleJSON
	bundle := repro.SymbolBundle{
		BinaryName: "libsign.so",
		Arch:       "arm64",
		ImageBase:  "0x1000",
		Functions: []repro.SymbolItem{
			{Name: "sign_entry", Address: "0x1234", Comment: "main signer"},
		},
		Comments: []repro.CommentItem{
			{Address: "0x1240", Text: "HMAC key schedule"},
		},
	}
	idaScript, err := app.ExportSymbolScript(bundle, "ida")
	if err != nil || !strings.Contains(idaScript, "import idaapi") || !strings.Contains(idaScript, "sign_entry") {
		t.Fatalf("ExportSymbolScript(ida) err=%v out=%s", err, idaScript)
	}
	ghidraScript, err := app.ExportSymbolScript(bundle, "ghidra")
	if err != nil || !strings.Contains(ghidraScript, "createLabel") {
		t.Fatalf("ExportSymbolScript(ghidra) err=%v out=%s", err, ghidraScript)
	}
	jsonOut, err := app.ExportSymbolScript(bundle, "json")
	if err != nil || !strings.Contains(jsonOut, "libsign.so") {
		t.Fatalf("ExportSymbolScript(json) err=%v out=%s", err, jsonOut)
	}
	if _, err := app.ExportSymbolScript(bundle, "unknown-format"); err == nil {
		t.Fatal("expected error for unknown ExportSymbolScript format")
	}

	imported, err := app.ImportSymbolBundleJSON(jsonOut)
	if err != nil || imported.BinaryName != "libsign.so" || len(imported.Functions) != 1 {
		t.Fatalf("ImportSymbolBundleJSON err=%v bundle=%+v", err, imported)
	}

	// 11-13. AnalyzeIOSBinary, GenerateUnidbgIOSHarness, GenerateIOSStealthScript
	machoPath := filepath.Join(tmp, "DemoApp")
	if err := os.WriteFile(machoPath, buildMinimalMachO64ForTest(t), 0o755); err != nil {
		t.Fatalf("write macho: %v", err)
	}
	iosRep, err := app.AnalyzeIOSBinary(machoPath)
	if err != nil || iosRep.FileKind != repro.IOSKindMachO || !iosRep.PIE {
		t.Fatalf("AnalyzeIOSBinary err=%v rep=%+v", err, iosRep)
	}

	iosHarness := app.GenerateUnidbgIOSHarness(repro.UnidbgIOSOptions{
		BundleID:     "com.acme.ios",
		BinaryPath:   machoPath,
		ObjCClass:    "Signer",
		ObjCSelector: "sign:",
	})
	if iosHarness == nil || !strings.Contains(iosHarness.Code, "DarwinEmulatorBuilder") {
		t.Fatalf("GenerateUnidbgIOSHarness failed: %+v", iosHarness)
	}

	iosStealth := app.GenerateIOSStealthScript(repro.IOSStealthOptions{
		BundleID:              "com.acme.ios",
		BypassPtrace:          true,
		BypassJailbreakChecks: true,
	})
	if iosStealth == nil || !strings.Contains(iosStealth.Code, "PT_DENY_ATTACH") {
		t.Fatalf("GenerateIOSStealthScript failed: %+v", iosStealth)
	}
}

func TestCryptoLabGUIBindings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	app := newTestREGatewayApp(t, nil)

	// 14. ListCryptoOperations
	ops := app.ListCryptoOperations()
	if len(ops) < 10 {
		t.Fatalf("expected >= 10 crypto operations, got %d", len(ops))
	}

	// 15. RunCryptoPipeline
	pipeRes := app.RunCryptoPipeline(cryptolab.PipelineRequest{
		Input: "cap-pro-crypto",
		Steps: []cryptolab.PipelineStep{
			{Op: "base64_encode"},
			{Op: "base64_decode"},
		},
	})
	if pipeRes == nil || !pipeRes.Success || pipeRes.OutputUTF8 != "cap-pro-crypto" {
		t.Fatalf("RunCryptoPipeline failed: %+v", pipeRes)
	}

	// 16. IdentifyCryptoPayload
	idRes := app.IdentifyCryptoPayload(base64.StdEncoding.EncodeToString([]byte(`{"user":"alice","role":"admin"}`)))
	if idRes == nil || len(idRes.Candidates) == 0 {
		t.Fatalf("IdentifyCryptoPayload returned empty candidates: %+v", idRes)
	}

	// 17-18. DecodeProtobufRawHex (hex with spaces/0x + standard/raw Base64) & EncodeProtobufRawHex
	// Wire bytes: field 1 varint 150 (08 96 01), field 2 string "hello" (12 05 68 65 6c 6c 6f)
	wireBytes, _ := hex.DecodeString("089601120568656c6c6f")
	nodeHex, err := app.DecodeProtobufRawHex("0x08 0x96 0x01 12 05 68 65 6c 6c 6f")
	if err != nil || len(nodeHex.Fields) != 2 || nodeHex.Fields[1].StringVal != "hello" {
		t.Fatalf("DecodeProtobufRawHex(hex) err=%v node=%+v", err, nodeHex)
	}
	nodeB64, err := app.DecodeProtobufRawHex(base64.StdEncoding.EncodeToString(wireBytes))
	if err != nil || len(nodeB64.Fields) != 2 || nodeB64.Fields[1].StringVal != "hello" {
		t.Fatalf("DecodeProtobufRawHex(std b64) err=%v node=%+v", err, nodeB64)
	}
	nodeRawB64, err := app.DecodeProtobufRawHex(base64.RawStdEncoding.EncodeToString(wireBytes))
	if err != nil || len(nodeRawB64.Fields) != 2 {
		t.Fatalf("DecodeProtobufRawHex(raw b64) err=%v node=%+v", err, nodeRawB64)
	}
	if _, err := app.DecodeProtobufRawHex("   "); err == nil {
		t.Fatal("expected error for empty protobuf input")
	}

	reEncodedHex, err := app.EncodeProtobufRawHex(*nodeHex)
	if err != nil || reEncodedHex != "089601120568656c6c6f" {
		t.Fatalf("EncodeProtobufRawHex err=%v hex=%q", err, reEncodedHex)
	}

	// 19-20. SolveAES128DFA & GenerateDFAFaultScript
	var key, pt [16]byte
	copy(key[:], []byte("0123456789abcdef"))
	copy(pt[:], []byte("cap-dfa-test-blk"))
	var validHex string
	var faults []string
	// Inject 2 faults per column (columns 0,1,2,3 -> byte indices 0,4,8,12)
	for _, colByte := range []int{0, 4, 8, 12} {
		for _, mask := range []byte{0x01, 0x73} {
			v, f := cryptolab.SimulateAES128Round9Fault(key, pt, colByte, mask)
			validHex = hex.EncodeToString(v[:])
			faults = append(faults, hex.EncodeToString(f[:]))
		}
	}
	dfaRes, err := app.SolveAES128DFA(cryptolab.DFARequest{
		ValidCiphertextHex:   validHex,
		FaultyCiphertextsHex: faults,
		PlaintextHex:         hex.EncodeToString(pt[:]),
	})
	if err != nil || !dfaRes.Solved || !dfaRes.VerifiedWithPlaintext || dfaRes.MasterKeyHex != hex.EncodeToString(key[:]) {
		t.Fatalf("SolveAES128DFA err=%v res=%+v", err, dfaRes)
	}

	dfaScript := app.GenerateDFAFaultScript("qiling", cryptolab.DFAScriptConfig{
		BinaryPath:    "/tmp/libwb.so",
		FaultHookAddr: "0x1400",
	})
	if dfaScript == nil || dfaScript.Engine != "qiling" || dfaScript.Code == "" {
		t.Fatalf("GenerateDFAFaultScript failed: %+v", dfaScript)
	}
}

func TestTLSKitGUIBindings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	app := newTestREGatewayApp(t, nil)

	tmp := t.TempDir()
	certPath, keyPath, certPEM := generateTestClientKeyPair(t, tmp)

	// 21. ScanAPKForCertificates
	apkPath := filepath.Join(tmp, "tls_app.apk")
	nscXML := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">api.acme.test</domain>
    <pin-set expiration="2030-01-01">
      <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
    </pin-set>
  </domain-config>
</network-security-config>`
	writeZipForTest(t, apkPath, map[string][]byte{
		"res/raw/server_ca.pem":               []byte(certPEM),
		"res/xml/network_security_config.xml": []byte(nscXML),
		"assets/client.p12":                   []byte{0x30, 0x82, 0x01, 0x00},
	})
	scanRep, err := app.ScanAPKForCertificates(apkPath)
	if err != nil || len(scanRep.Certificates) == 0 || !scanRep.HasPinning || !scanRep.HasMTLSIndicators {
		t.Fatalf("ScanAPKForCertificates err=%v rep=%+v", err, scanRep)
	}

	// 22. InspectCertPEM
	certs, err := app.InspectCertPEM(certPEM)
	if err != nil || len(certs) != 1 || certs[0].CommonName != "cap-test-client" {
		t.Fatalf("InspectCertPEM err=%v certs=%+v", err, certs)
	}

	// 23. ValidateMTLSKeyPair
	mtlsRes, err := app.ValidateMTLSKeyPair(certPath, keyPath)
	if err != nil || !mtlsRes.Valid || !mtlsRes.KeyPairMatch || !mtlsRes.HasClientAuthEKU {
		t.Fatalf("ValidateMTLSKeyPair err=%v res=%+v", err, mtlsRes)
	}

	// 24-26. ListTLSProfiles, ComputeTLSProfileJA3, DetectCurlImpersonate
	profiles := app.ListTLSProfiles()
	if len(profiles) != 6 {
		t.Fatalf("ListTLSProfiles len = %d, want 6", len(profiles))
	}
	ja3 := app.ComputeTLSProfileJA3("chrome_131")
	if ja3 == nil || ja3.JA3Hash == "" {
		t.Fatalf("ComputeTLSProfileJA3(chrome_131) failed: %+v", ja3)
	}
	ci := app.DetectCurlImpersonate()
	if len(ci.SearchedPatterns) == 0 {
		t.Fatalf("DetectCurlImpersonate returned empty SearchedPatterns: %+v", ci)
	}

	// 27-29. Compat Frida scripts
	if sc := app.GenerateFlutterProxyDebugScript(tlskit.FlutterDebugOptions{OffsetHex: "0x5a1230", ProxyHost: "127.0.0.1", ProxyPort: 8080}); sc == nil || !strings.Contains(sc.Code, "0x5a1230") {
		t.Fatalf("GenerateFlutterProxyDebugScript failed: %+v", sc)
	}
	if sc := app.GenerateCronetHTTP2Script(tlskit.DefaultCronetOptions()); sc == nil || sc.Code == "" {
		t.Fatalf("GenerateCronetHTTP2Script failed: %+v", sc)
	}
	if sc := app.GenerateMTLSObserverScript(tlskit.DefaultMTLSObserverOptions()); sc == nil || sc.Code == "" {
		t.Fatalf("GenerateMTLSObserverScript failed: %+v", sc)
	}
}

func TestGatewayProGUIBindings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	app := newTestREGatewayApp(t, nil)
	defer app.Shutdown(context.Background())

	// 30-35. Account Pool CRUD + Config + MarkHealthy
	acc, err := app.SaveGatewayAccount(gateway.AccountProfile{
		Name:      "QA Account",
		Username:  "alice",
		Token:     "tok-123",
		Tags:      []string{"vip"},
		Enabled:   true,
		Status:    gateway.AccountStatusExpired,
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	if err != nil || acc.ID == "" {
		t.Fatalf("SaveGatewayAccount err=%v acc=%+v", err, acc)
	}
	if len(app.ListGatewayAccounts()) != 1 {
		t.Fatalf("expected 1 gateway account")
	}
	if err := app.UpdateAccountPoolConfig(gateway.AccountPoolConfig{Strategy: gateway.StrategyLeastUsed}); err != nil {
		t.Fatalf("UpdateAccountPoolConfig: %v", err)
	}
	if got := app.GetAccountPoolConfig().Strategy; got != gateway.StrategyLeastUsed {
		t.Fatalf("AccountPoolConfig.Strategy = %q, want least_used", got)
	}
	if err := app.MarkGatewayAccountHealthy(acc.ID); err != nil {
		t.Fatalf("MarkGatewayAccountHealthy: %v", err)
	}
	if accounts := app.ListGatewayAccounts(); accounts[0].Status != gateway.AccountStatusActive {
		t.Fatalf("expected account status active after MarkGatewayAccountHealthy, got %q", accounts[0].Status)
	}
	if err := app.DeleteGatewayAccount(acc.ID); err != nil {
		t.Fatalf("DeleteGatewayAccount: %v", err)
	}

	// 36-42. Managed Worker Pool CRUD + Start/Stop/Restart
	worker, err := app.SaveGatewayWorker(gateway.ManagedWorkerSpec{
		Name:        "Sleep Worker",
		Kind:        gateway.WorkerKindCustom,
		Command:     "/bin/sh",
		Args:        []string{"-c", "sleep 30"},
		BasePort:    29450,
		Instances:   1,
		AutoRestart: false,
		Enabled:     true,
	})
	if err != nil || worker.ID == "" {
		t.Fatalf("SaveGatewayWorker err=%v worker=%+v", err, worker)
	}
	if len(app.ListGatewayWorkers()) != 1 {
		t.Fatalf("expected 1 gateway worker")
	}
	if statuses := app.ListGatewayWorkerStatuses(); len(statuses) != 1 || statuses[0].Spec.ID != worker.ID {
		t.Fatalf("unexpected worker statuses: %+v", statuses)
	}
	if err := app.StartGatewayWorker(worker.ID); err != nil {
		t.Fatalf("StartGatewayWorker: %v", err)
	}
	if err := app.RestartGatewayWorker(worker.ID); err != nil {
		t.Fatalf("RestartGatewayWorker: %v", err)
	}
	if err := app.StopGatewayWorker(worker.ID); err != nil {
		t.Fatalf("StopGatewayWorker: %v", err)
	}
	if err := app.DeleteGatewayWorker(worker.ID); err != nil {
		t.Fatalf("DeleteGatewayWorker: %v", err)
	}

	// 43-47. Circuit Breaker, Cache Clear, Prometheus Metrics, Docker Export
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"err":"boom"}`))
	}))
	defer upstream.Close()

	route, err := app.SaveGatewayRoute(gateway.ServiceRoute{
		Slug:                 "flaky-api",
		Name:                 "Flaky API",
		Enabled:              true,
		UpstreamMethod:       "GET",
		UpstreamURL:          upstream.URL + "/fail",
		CacheTTLSec:          30,
		CircuitFailThreshold: 1,
		CircuitCooldownSec:   60,
	})
	if err != nil {
		t.Fatalf("SaveGatewayRoute: %v", err)
	}
	_, _ = app.TestGatewayRoute(route.Slug, gateway.TestInvokeRequest{})

	circuits := app.GetGatewayCircuitStates()
	snap, ok := circuits[route.Slug]
	if !ok || snap.State != gateway.CircuitStateOpen {
		t.Fatalf("expected open circuit for %s, got %+v", route.Slug, circuits)
	}
	if err := app.ResetGatewayCircuit(route.Slug); err != nil {
		t.Fatalf("ResetGatewayCircuit: %v", err)
	}
	if got := app.GetGatewayCircuitStates()[route.Slug].State; got != gateway.CircuitStateClosed {
		t.Fatalf("expected closed circuit after reset, got %q", got)
	}
	if err := app.ClearGatewayRouteCache(route.Slug); err != nil {
		t.Fatalf("ClearGatewayRouteCache: %v", err)
	}

	prom := app.GetGatewayPrometheusMetrics()
	if !strings.Contains(prom, "cap_gateway_requests_total") || !strings.Contains(prom, "cap_gateway_route_circuit_state") {
		t.Fatalf("unexpected Prometheus output:\n%s", prom)
	}

	bundle := app.ExportGatewayDockerBundle("0.0.0.0:9191")
	if !strings.Contains(bundle.Dockerfile, "0.0.0.0:9191") || !strings.Contains(bundle.DockerCompose, "9191:9191") {
		t.Fatalf("unexpected Docker bundle: %+v", bundle)
	}
}
