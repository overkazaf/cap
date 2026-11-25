package cli

import (
	"archive/zip"
	"bytes"
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
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/cryptolab"
	"github.com/overkazaf/cap/internal/gateway"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/repro"
	"github.com/overkazaf/cap/internal/tlskit"
)

func execCLI(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if stdin != "" {
		cmd.SetIn(strings.NewReader(stdin))
	}
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func writeTestZipCLI(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
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

func buildTestMachO64CLI(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint32(buf[0:4], macho.Magic64)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(macho.CpuArm64))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(macho.TypeExec))
	binary.LittleEndian.PutUint32(buf[24:28], uint32(macho.FlagPIE|macho.FlagNoHeapExecution))
	return buf
}

func generateTestMTLSFilesCLI(t *testing.T, dir string) (certPath, keyPath, certPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2026),
		Subject:               pkix.Name{CommonName: "cli-mtls-client"},
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
	kDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	kPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kDER})

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

func TestRootHelpIncludesProCommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	orig := i18n.Lang()
	defer i18n.SetLang(string(orig))
	i18n.SetLang("en")

	out, err := execCLI(t, "", "--help")
	if err != nil {
		t.Fatalf("cap --help failed: %v", err)
	}
	for _, want := range []string{"repro", "crypto", "tls", "gateway"} {
		if !strings.Contains(out, want) {
			t.Errorf("cap --help missing command %q:\n%s", want, out)
		}
	}
}

func TestCLIReproSubcommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmp := t.TempDir()

	// 1. autostub via --stdin --json and --file
	unidbgLog := "java.lang.UnsupportedOperationException: callObjectMethodV: android/content/Context->getPackageName()Ljava/lang/String;\n" +
		"WARN [ARM64SyscallHandler] - openat dirfd=-100, pathname=/proc/self/cmdline, oflags=0x0 => -2\n"
	out, err := execCLI(t, unidbgLog, "repro", "autostub", "--stdin", "--json")
	if err != nil {
		t.Fatalf("cap repro autostub --stdin --json: %v\n%s", err, out)
	}
	var diag repro.UnidbgStubDiagnosis
	if err := json.Unmarshal([]byte(out), &diag); err != nil {
		t.Fatalf("unmarshal autostub JSON: %v\n%s", err, out)
	}
	if len(diag.MissingJNI) != 1 || len(diag.MissingFiles) != 1 {
		t.Fatalf("unexpected diagnosis: %+v", diag)
	}

	logFile := filepath.Join(tmp, "unidbg.log")
	if err := os.WriteFile(logFile, []byte(unidbgLog), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = execCLI(t, "", "repro", "autostub", "--file", logFile)
	if err != nil || !strings.Contains(out, "getPackageName") {
		t.Fatalf("cap repro autostub --file failed: err=%v out=%s", err, out)
	}

	// 2. env-snapshot --pkg --out
	snapOut := filepath.Join(tmp, "env_snapshot.js")
	out, err = execCLI(t, "", "repro", "env-snapshot", "--pkg", "com.acme.shop", "--out", snapOut)
	if err != nil {
		t.Fatalf("cap repro env-snapshot: %v\n%s", err, out)
	}
	snapCode, err := os.ReadFile(snapOut)
	if err != nil || !strings.Contains(string(snapCode), "com.acme.shop") {
		t.Fatalf("env-snapshot file unexpected: err=%v", err)
	}

	// 3. jadx (<apk> --search / --class / --link-so / --register-natives / --json)
	mockJadx := filepath.Join(tmp, "mock-jadx")
	mockScript := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "1.5.2-cli"; exit 0; fi
OUT=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-d" ]; then OUT="$2"; shift 2; continue; fi
  shift
done
mkdir -p "$OUT/sources/com/acme"
cat > "$OUT/sources/com/acme/Vault.java" <<'EOF'
package com.acme;
public class Vault {
    public native String seal(String msg);
}
EOF
exit 0
`
	if err := os.WriteFile(mockJadx, []byte(mockScript), 0o755); err != nil {
		t.Fatal(err)
	}
	apkPath := filepath.Join(tmp, "vault.apk")
	writeTestZipCLI(t, apkPath, map[string][]byte{"AndroidManifest.xml": []byte("m")})

	out, err = execCLI(t, "", "repro", "jadx", apkPath, "--jadx", mockJadx, "--search", "seal", "--json")
	if err != nil {
		t.Fatalf("cap repro jadx --search: %v\n%s", err, out)
	}
	var hits []repro.JadxSearchHit
	if err := json.Unmarshal([]byte(out), &hits); err != nil || len(hits) != 1 {
		t.Fatalf("unexpected search hits: err=%v out=%s", err, out)
	}

	out, err = execCLI(t, "", "repro", "jadx", apkPath, "--jadx", mockJadx, "--class", "com.acme.Vault")
	if err != nil || !strings.Contains(out, "public native String seal") {
		t.Fatalf("cap repro jadx --class failed: err=%v out=%s", err, out)
	}

	regJSON := `[{"class":"com/acme/Vault","name":"seal","signature":"(Ljava/lang/String;)Ljava/lang/String;","fnPtr":"0x2200","module":"libvault.so"}]`
	out, err = execCLI(t, "", "repro", "jadx", apkPath, "--jadx", mockJadx, "--register-natives", regJSON, "--json")
	if err != nil {
		t.Fatalf("cap repro jadx --register-natives: %v\n%s", err, out)
	}
	var linkRep repro.JavaNativeLinkReport
	if err := json.Unmarshal([]byte(out), &linkRep); err != nil || linkRep.DynamicCount != 1 {
		t.Fatalf("unexpected link report: err=%v rep=%+v", err, linkRep)
	}

	// 4. symbols --in --format ida|ghidra|json --out
	symIn := filepath.Join(tmp, "symbols.json")
	symDoc := `{"binary_name":"libvault.so","arch":"arm64","image_base":"0x1000","functions":[{"name":"vault_seal","address":"0x2200"}],"comments":[]}`
	if err := os.WriteFile(symIn, []byte(symDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	idaOut := filepath.Join(tmp, "vault_ida.py")
	if out, err = execCLI(t, "", "repro", "symbols", "--in", symIn, "--format", "ida", "--out", idaOut); err != nil {
		t.Fatalf("cap repro symbols ida: %v\n%s", err, out)
	}
	if raw, err := os.ReadFile(idaOut); err != nil || !strings.Contains(string(raw), "vault_seal") {
		t.Fatalf("IDA output unexpected: err=%v", err)
	}
	if out, err = execCLI(t, "", "repro", "symbols", "--in", symIn, "--format", "ghidra"); err != nil || !strings.Contains(out, "createLabel") {
		t.Fatalf("cap repro symbols ghidra: err=%v out=%s", err, out)
	}
	if _, err = execCLI(t, "", "repro", "symbols", "--in", symIn, "--format", "invalid"); err == nil {
		t.Fatal("expected error for unknown symbols --format")
	}

	// 5. ios, ios-harness, ios-stealth
	machoPath := filepath.Join(tmp, "VaultApp")
	if err := os.WriteFile(machoPath, buildTestMachO64CLI(t), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err = execCLI(t, "", "repro", "ios", machoPath, "--json")
	if err != nil {
		t.Fatalf("cap repro ios: %v\n%s", err, out)
	}
	var iosRep repro.IOSBinaryReport
	if err := json.Unmarshal([]byte(out), &iosRep); err != nil || iosRep.FileKind != repro.IOSKindMachO {
		t.Fatalf("unexpected ios report: err=%v rep=%+v", err, iosRep)
	}

	out, err = execCLI(t, "", "repro", "ios-harness", "--bundle-id", "com.acme.ios", "--objc-class", "Vault", "--objc-selector", "seal:")
	if err != nil || !strings.Contains(out, "DarwinEmulatorBuilder") {
		t.Fatalf("cap repro ios-harness failed: err=%v out=%s", err, out)
	}
	out, err = execCLI(t, "", "repro", "ios-stealth", "--bundle-id", "com.acme.ios")
	if err != nil || !strings.Contains(out, "PT_DENY_ATTACH") {
		t.Fatalf("cap repro ios-stealth failed: err=%v out=%s", err, out)
	}
}

func TestCLICryptoSubcommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmp := t.TempDir()

	// 1. ops --json
	out, err := execCLI(t, "", "crypto", "ops", "--json")
	if err != nil {
		t.Fatalf("cap crypto ops --json: %v\n%s", err, out)
	}
	var ops []cryptolab.OperationSpec
	if err := json.Unmarshal([]byte(out), &ops); err != nil || len(ops) < 10 {
		t.Fatalf("unexpected crypto ops: err=%v len=%d", err, len(ops))
	}

	// 2. identify <input> --json
	out, err = execCLI(t, "", "crypto", "identify", "SGVsbG8gV29ybGQ=", "--json")
	if err != nil {
		t.Fatalf("cap crypto identify: %v\n%s", err, out)
	}
	var idRes cryptolab.IdentifyResult
	if err := json.Unmarshal([]byte(out), &idRes); err != nil || len(idRes.Candidates) == 0 {
		t.Fatalf("unexpected identify result: err=%v res=%+v", err, idRes)
	}

	// 3. run --op and --pipeline-json
	out, err = execCLI(t, "", "crypto", "run", "--op", "base64_encode", "--input", "hello", "--json")
	if err != nil {
		t.Fatalf("cap crypto run --op: %v\n%s", err, out)
	}
	var pipeRes cryptolab.PipelineResult
	if err := json.Unmarshal([]byte(out), &pipeRes); err != nil || !pipeRes.Success || pipeRes.OutputUTF8 != "aGVsbG8=" {
		t.Fatalf("unexpected pipeline result: err=%v res=%+v", err, pipeRes)
	}

	out, err = execCLI(t, "", "crypto", "run",
		"--pipeline-json", `[{"op":"hex_encode"}]`,
		"--input", "68656c6c6f",
		"--input-format", "hex",
	)
	if err != nil || strings.TrimSpace(out) != "68656c6c6f" {
		t.Fatalf("cap crypto run --pipeline-json failed: err=%v out=%q", err, out)
	}

	// 4. protobuf --decode (hex & base64) and --encode-json
	wireHex := "089601120568656c6c6f"
	wireBytes, _ := hex.DecodeString(wireHex)
	out, err = execCLI(t, "", "crypto", "protobuf", "--decode", base64.StdEncoding.EncodeToString(wireBytes))
	if err != nil {
		t.Fatalf("cap crypto protobuf --decode: %v\n%s", err, out)
	}
	astFile := filepath.Join(tmp, "pb_ast.json")
	if err := os.WriteFile(astFile, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = execCLI(t, "", "crypto", "protobuf", "--encode-json", astFile)
	if err != nil || strings.TrimSpace(out) != wireHex {
		t.Fatalf("cap crypto protobuf --encode-json err=%v out=%q want=%q", err, strings.TrimSpace(out), wireHex)
	}

	// 5. dfa --valid --fault ... --plaintext --json
	var key, pt [16]byte
	copy(key[:], []byte("fedcba9876543210"))
	copy(pt[:], []byte("0011223344556677"))
	var validHex string
	dfaArgs := []string{"crypto", "dfa", "--plaintext", hex.EncodeToString(pt[:]), "--json"}
	for _, colByte := range []int{0, 4, 8, 12} {
		for _, mask := range []byte{0x02, 0x55} {
			v, f := cryptolab.SimulateAES128Round9Fault(key, pt, colByte, mask)
			validHex = hex.EncodeToString(v[:])
			dfaArgs = append(dfaArgs, "--fault", hex.EncodeToString(f[:]))
		}
	}
	dfaArgs = append(dfaArgs, "--valid", validHex)
	out, err = execCLI(t, "", dfaArgs...)
	if err != nil {
		t.Fatalf("cap crypto dfa: %v\n%s", err, out)
	}
	var dfaRes cryptolab.DFAResult
	if err := json.Unmarshal([]byte(out), &dfaRes); err != nil || !dfaRes.Solved || dfaRes.MasterKeyHex != hex.EncodeToString(key[:]) {
		t.Fatalf("unexpected dfa result: err=%v res=%+v", err, dfaRes)
	}

	// 6. dfa-script --engine unidbg|qiling --out
	dfaScriptPath := filepath.Join(tmp, "dfa_unidbg.java")
	out, err = execCLI(t, "", "crypto", "dfa-script", "--engine", "unidbg", "--out", dfaScriptPath)
	if err != nil {
		t.Fatalf("cap crypto dfa-script: %v\n%s", err, out)
	}
	if raw, err := os.ReadFile(dfaScriptPath); err != nil || !strings.Contains(string(raw), "[CAP_RE]") {
		t.Fatalf("unexpected dfa-script output: err=%v", err)
	}
}

func TestCLITLSKitSubcommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmp := t.TempDir()

	// 1. profiles --json
	out, err := execCLI(t, "", "tls", "profiles", "--json")
	if err != nil {
		t.Fatalf("cap tls profiles: %v\n%s", err, out)
	}
	var profiles []tlskit.TLSProfileSpec
	if err := json.Unmarshal([]byte(out), &profiles); err != nil || len(profiles) != 6 {
		t.Fatalf("unexpected profiles: err=%v len=%d", err, len(profiles))
	}

	// 2. ja3 <profile>
	out, err = execCLI(t, "", "tls", "ja3", "chrome_131", "--json")
	if err != nil {
		t.Fatalf("cap tls ja3: %v\n%s", err, out)
	}
	var ja3 tlskit.JA3Summary
	if err := json.Unmarshal([]byte(out), &ja3); err != nil || ja3.JA3Hash == "" {
		t.Fatalf("unexpected ja3: err=%v res=%+v", err, ja3)
	}
	if _, err := execCLI(t, "", "tls", "ja3", "nonexistent_profile"); err == nil {
		t.Fatal("expected error for unknown TLS profile")
	}

	// 3-4. scan-apk & validate-mtls
	certPath, keyPath, certPEM := generateTestMTLSFilesCLI(t, tmp)
	apkPath := filepath.Join(tmp, "mtls.apk")
	writeTestZipCLI(t, apkPath, map[string][]byte{
		"res/raw/root.pem": []byte(certPEM),
	})
	out, err = execCLI(t, "", "tls", "scan-apk", apkPath, "--json")
	if err != nil {
		t.Fatalf("cap tls scan-apk: %v\n%s", err, out)
	}
	var scanRep tlskit.APKCertScanReport
	if err := json.Unmarshal([]byte(out), &scanRep); err != nil || len(scanRep.Certificates) == 0 {
		t.Fatalf("unexpected scan-apk report: err=%v rep=%+v", err, scanRep)
	}

	out, err = execCLI(t, "", "tls", "validate-mtls", "--cert", certPath, "--key", keyPath, "--json")
	if err != nil {
		t.Fatalf("cap tls validate-mtls: %v\n%s", err, out)
	}
	var mtlsRes tlskit.MTLSValidationResult
	if err := json.Unmarshal([]byte(out), &mtlsRes); err != nil || !mtlsRes.Valid {
		t.Fatalf("unexpected validate-mtls result: err=%v res=%+v", err, mtlsRes)
	}

	// 5-8. flutter, cronet, mtls-observer, curl-impersonate
	flutterOut := filepath.Join(tmp, "flutter.js")
	if out, err = execCLI(t, "", "tls", "flutter", "--offset", "0x5a1230", "--proxy", "127.0.0.1:8080", "--out", flutterOut); err != nil {
		t.Fatalf("cap tls flutter: %v\n%s", err, out)
	}
	if raw, err := os.ReadFile(flutterOut); err != nil || !strings.Contains(string(raw), "0x5a1230") {
		t.Fatalf("unexpected flutter script: err=%v", err)
	}

	cronetOut := filepath.Join(tmp, "cronet.js")
	if out, err = execCLI(t, "", "tls", "cronet", "--out", cronetOut); err != nil {
		t.Fatalf("cap tls cronet: %v\n%s", err, out)
	}
	if raw, err := os.ReadFile(cronetOut); err != nil || len(raw) == 0 {
		t.Fatalf("unexpected cronet script: err=%v", err)
	}

	mtlsOut := filepath.Join(tmp, "mtls_obs.js")
	if out, err = execCLI(t, "", "tls", "mtls-observer", "--out", mtlsOut); err != nil {
		t.Fatalf("cap tls mtls-observer: %v\n%s", err, out)
	}
	if raw, err := os.ReadFile(mtlsOut); err != nil || len(raw) == 0 {
		t.Fatalf("unexpected mtls-observer script: err=%v", err)
	}

	out, err = execCLI(t, "", "tls", "curl-impersonate", "--json")
	if err != nil {
		t.Fatalf("cap tls curl-impersonate: %v\n%s", err, out)
	}
	var ci tlskit.CurlImpersonateInfo
	if err := json.Unmarshal([]byte(out), &ci); err != nil || len(ci.SearchedPatterns) == 0 {
		t.Fatalf("unexpected curl-impersonate info: err=%v info=%+v", err, ci)
	}
}

func TestCLIGatewayProSubcommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmp := t.TempDir()

	// 1. accounts --add / --mark-healthy / --delete / --json
	out, err := execCLI(t, "", "gateway", "accounts", "--add", "CLI-Acc", "--token", "secret-tok", "--tags", "prod", "--json")
	if err != nil {
		t.Fatalf("cap gateway accounts --add: %v\n%s", err, out)
	}
	var acc gateway.AccountProfile
	if err := json.Unmarshal([]byte(out), &acc); err != nil || acc.ID == "" {
		t.Fatalf("unexpected added account: err=%v out=%s", err, out)
	}
	if out, err = execCLI(t, "", "gateway", "accounts", "--mark-healthy", acc.ID); err != nil || !strings.Contains(out, acc.ID) {
		t.Fatalf("cap gateway accounts --mark-healthy: err=%v out=%s", err, out)
	}
	if out, err = execCLI(t, "", "gateway", "accounts", "--json"); err != nil || !strings.Contains(out, acc.ID) {
		t.Fatalf("cap gateway accounts --json: err=%v out=%s", err, out)
	}
	if out, err = execCLI(t, "", "gateway", "accounts", "--delete", acc.ID); err != nil || !strings.Contains(out, "Deleted account") {
		t.Fatalf("cap gateway accounts --delete: err=%v out=%s", err, out)
	}

	// 2. workers --add / --status / --stop / --delete / --json
	out, err = execCLI(t, "", "gateway", "workers", "--add", "CLI-Worker", "--cmd", "/bin/sh", "--args", "-c", "--args", "sleep 5", "--base-port", "29480", "--json")
	if err != nil {
		t.Fatalf("cap gateway workers --add: %v\n%s", err, out)
	}
	var worker gateway.ManagedWorkerSpec
	if err := json.Unmarshal([]byte(out), &worker); err != nil || worker.ID == "" {
		t.Fatalf("unexpected added worker: err=%v out=%s", err, out)
	}
	if out, err = execCLI(t, "", "gateway", "workers", "--status", "--json"); err != nil || !strings.Contains(out, worker.ID) {
		t.Fatalf("cap gateway workers --status: err=%v out=%s", err, out)
	}
	if out, err = execCLI(t, "", "gateway", "workers", "--stop", worker.ID); err != nil {
		t.Fatalf("cap gateway workers --stop: err=%v out=%s", err, out)
	}
	if out, err = execCLI(t, "", "gateway", "workers", "--delete", worker.ID); err != nil {
		t.Fatalf("cap gateway workers --delete: err=%v out=%s", err, out)
	}

	// 3. circuits --reset / --clear-cache / --json
	if out, err = execCLI(t, "", "gateway", "circuits", "--json"); err != nil || strings.TrimSpace(out) != "{}" {
		t.Fatalf("cap gateway circuits --json: err=%v out=%s", err, out)
	}
	if out, err = execCLI(t, "", "gateway", "circuits", "--reset", "demo-route", "--clear-cache", "demo-route"); err != nil || !strings.Contains(out, "demo-route") {
		t.Fatalf("cap gateway circuits --reset/--clear-cache: err=%v out=%s", err, out)
	}

	// 4. prometheus
	out, err = execCLI(t, "", "gateway", "prometheus")
	if err != nil || !strings.Contains(out, "cap_gateway_requests_total") {
		t.Fatalf("cap gateway prometheus: err=%v out=%s", err, out)
	}

	// 5. export-docker --addr --out-dir
	dockerDir := filepath.Join(tmp, "docker-out")
	out, err = execCLI(t, "", "gateway", "export-docker", "--addr", "0.0.0.0:9292", "--out-dir", dockerDir)
	if err != nil {
		t.Fatalf("cap gateway export-docker: %v\n%s", err, out)
	}
	df, err := os.ReadFile(filepath.Join(dockerDir, "Dockerfile"))
	if err != nil || !strings.Contains(string(df), "0.0.0.0:9292") {
		t.Fatalf("Dockerfile unexpected: err=%v", err)
	}
	dc, err := os.ReadFile(filepath.Join(dockerDir, "docker-compose.yml"))
	if err != nil || !strings.Contains(string(dc), "9292:9292") {
		t.Fatalf("docker-compose.yml unexpected: err=%v", err)
	}

	// 6. serve --help verifies 0.0.0.0:9090 default + clean shutdown via context cancel
	helpOut, err := execCLI(t, "", "gateway", "serve", "--help")
	if err != nil || !strings.Contains(helpOut, "0.0.0.0:9090") {
		t.Fatalf("cap gateway serve --help unexpected: err=%v out=%s", err, helpOut)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	serveCmd := NewRootCmd()
	var serveOut bytes.Buffer
	serveCmd.SetOut(&serveOut)
	serveCmd.SetErr(&serveOut)
	serveCmd.SetArgs([]string{"gateway", "serve", "--addr", "127.0.0.1:0", "--start-workers=false"})
	if err := serveCmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("cap gateway serve clean shutdown failed: %v\n%s", err, serveOut.String())
	}
	if !strings.Contains(serveOut.String(), "Listening: http://127.0.0.1:") || !strings.Contains(serveOut.String(), "Shutting down Open API Gateway...") {
		t.Fatalf("unexpected serve output:\n%s", serveOut.String())
	}
}
