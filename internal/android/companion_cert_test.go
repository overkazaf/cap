package android

import (
	"archive/zip"
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapCompanionAPKEmbedded(t *testing.T) {
	apk := CapCompanionAPK()
	if len(apk) < 4096 {
		t.Fatalf("embedded cap-companion.apk unexpectedly small: %d bytes", len(apk))
	}
	if !bytes.HasPrefix(apk, []byte("PK\x03\x04")) {
		t.Fatalf("embedded cap-companion.apk does not start with ZIP magic")
	}

	zr, err := zip.NewReader(bytes.NewReader(apk), int64(len(apk)))
	if err != nil {
		t.Fatalf("embedded cap-companion.apk is not a valid zip: %v", err)
	}

	required := map[string]bool{
		"AndroidManifest.xml": false,
		"classes.dex":         false,
		"resources.arsc":      false,
	}
	hasSignature := false
	for _, f := range zr.File {
		if _, ok := required[f.Name]; ok {
			required[f.Name] = true
		}
		if strings.HasPrefix(f.Name, "META-INF/") && (strings.HasSuffix(f.Name, ".RSA") || strings.HasSuffix(f.Name, ".SF")) {
			hasSignature = true
		}
	}
	for name, found := range required {
		if !found {
			t.Errorf("embedded APK missing required entry %q", name)
		}
	}
	if !hasSignature {
		t.Errorf("embedded APK missing META-INF signature files")
	}
}

func TestParseCertCheckOutput(t *testing.T) {
	const hash = "9a5ba575.0"
	tests := []struct {
		name        string
		output      string
		wantInstall bool
		wantStore   string
		wantMethod  string
		wantReboot  bool
	}{
		{
			name:        "android 14+ apex dir with apex cert installed",
			output:      "HAS_APEX_DIR\nAPEX\nSYSTEM\n",
			wantInstall: true,
			wantStore:   "system",
			wantMethod:  "apex",
		},
		{
			name:        "android 14+ apex dir with ONLY legacy system cert must report NOT installed",
			output:      "HAS_APEX_DIR\nSYSTEM\n",
			wantInstall: false,
			wantStore:   "none",
			wantMethod:  "legacy_system_only",
		},
		{
			name:        "android 14+ apex dir with user cert only",
			output:      "HAS_APEX_DIR\nUSER\n",
			wantInstall: true,
			wantStore:   "user",
			wantMethod:  "user",
		},
		{
			name:        "apex and system",
			output:      "APEX\nSYSTEM\n",
			wantInstall: true,
			wantStore:   "system",
			wantMethod:  "apex",
		},
		{
			name:        "android 10-13 system only (no apex dir)",
			output:      "SYSTEM\n",
			wantInstall: true,
			wantStore:   "system",
			wantMethod:  "system",
		},
		{
			name:        "magisk pending reboot",
			output:      "MAGISK\n",
			wantInstall: false,
			wantStore:   "system",
			wantMethod:  "magisk",
			wantReboot:  true,
		},
		{
			name:        "user store",
			output:      "USER\n",
			wantInstall: true,
			wantStore:   "user",
			wantMethod:  "user",
		},
		{
			name:        "not installed",
			output:      "",
			wantInstall: false,
			wantStore:   "none",
			wantMethod:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseCertCheckOutput(hash, tt.output)
			if got.Installed != tt.wantInstall || got.Store != tt.wantStore || got.Method != tt.wantMethod || got.NeedsReboot != tt.wantReboot || got.Hash != hash {
				t.Errorf("ParseCertCheckOutput(%q) = %+v, want installed=%v store=%q method=%q reboot=%v",
					tt.output, got, tt.wantInstall, tt.wantStore, tt.wantMethod, tt.wantReboot)
			}
		})
	}
}

func TestCertFingerprintAndSubject(t *testing.T) {
	certPath := filepath.Join("testdata", "test-ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Skip("testdata/test-ca.crt not available")
	}

	fp := CertSHA256Fingerprint(certPath)
	if len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Fatalf("unexpected SHA-256 fingerprint format: %q", fp)
	}
	if subj := CertSubject(certPath); subj == "" {
		t.Errorf("expected non-empty subject for test cert")
	}
	if fpBad := CertSHA256Fingerprint(filepath.Join("testdata", "missing.crt")); fpBad != "" {
		t.Errorf("expected empty fingerprint for missing file, got %q", fpBad)
	}
}

func TestParseCompanionPackageDump(t *testing.T) {
	installedDump := `
Packages:
  Package [com.overkazaf.cap.companion] (abc123):
    versionCode=1 minSdk=24 targetSdk=34
    versionName=1.0.0
    install permissions:
      android.permission.INTERNET: granted=true
      android.permission.WRITE_SECURE_SETTINGS: granted=true
`
	inst, ver, code, hasPerm := ParseCompanionPackageDump(installedDump)
	if !inst || ver != "1.0.0" || code != 1 || !hasPerm {
		t.Fatalf("got (%v, %q, %d, %v), want (true, \"1.0.0\", 1, true)", inst, ver, code, hasPerm)
	}

	missingDump := "Unable to find package: com.overkazaf.cap.companion"
	inst, ver, code, hasPerm = ParseCompanionPackageDump(missingDump)
	if inst || ver != "" || code != 0 || hasPerm {
		t.Fatalf("missing package: got (%v, %q, %d, %v), want all false/empty", inst, ver, code, hasPerm)
	}
}

func TestParseCompanionServiceRunning(t *testing.T) {
	runningOut := `
ACTIVITY MANAGER SERVICES (dumpsys activity services)
  User 0 active services:
  * ServiceRecord{a1b2c3 u0 com.overkazaf.cap.companion/.ProxyGuardService}
    app=ProcessRecord{d4e5f6 1234:com.overkazaf.cap.companion/u0a200}
    isForeground=true foregroundId=1001
`
	if !ParseCompanionServiceRunning(runningOut) {
		t.Errorf("expected running service to be detected")
	}
	if ParseCompanionServiceRunning("  (nothing)") {
		t.Errorf("expected (nothing) to report not running")
	}
	if ParseCompanionServiceRunning("") {
		t.Errorf("expected empty output to report not running")
	}
}

func TestParseBatteryWhitelisted(t *testing.T) {
	out := "system,com.android.vending,10001\nuser,com.overkazaf.cap.companion,10234\n"
	if !ParseBatteryWhitelisted(out) {
		t.Errorf("expected companion package to be detected in whitelist")
	}
	if ParseBatteryWhitelisted("system,com.android.vending,10001\n") {
		t.Errorf("expected companion package not to be detected")
	}
}

func TestBuildTeardownCommandsAndIptablesScript(t *testing.T) {
	cmds := BuildTeardownProxyCommands()
	wantSubstrings := []string{
		"settings put global http_proxy :0",
		"settings delete global global_http_proxy_host",
		"settings delete global global_http_proxy_port",
		"settings delete global global_http_proxy_exclusion_list",
		"settings delete global http_proxy",
	}
	if len(cmds) != len(wantSubstrings) {
		t.Fatalf("got %d proxy teardown commands, want %d", len(cmds), len(wantSubstrings))
	}
	for i, w := range wantSubstrings {
		if cmds[i] != w {
			t.Errorf("cmd[%d] = %q, want %q", i, cmds[i], w)
		}
	}

	script := BuildTeardownIptablesScript("9988", "9988", "")
	for _, needle := range []string{
		"pkill -f cap-redir",
		"while iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 9988",
		"while iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 9988",
		"while iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 9999",
		"while iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 9999",
	} {
		if !strings.Contains(script, needle) {
			t.Errorf("teardown iptables script missing %q:\n%s", needle, script)
		}
	}
	if strings.Count(script, "--to-port 9988") != 2 {
		t.Errorf("expected port 9988 deduplicated to 2 rules (80 & 443), got:\n%s", script)
	}
}

func TestSetupAndTeardownWithMockADB(t *testing.T) {
	certPath := filepath.Join("testdata", "test-ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Skip("testdata/test-ca.crt not available")
	}

	origExec := adbExecFunc
	t.Cleanup(func() { adbExecFunc = origExec })

	var log []string
	companionInstalled := false
	watchdogStarted := false
	certInjected := false
	proxyValue := "null"

	adbExecFunc = func(args ...string) (string, error) {
		joined := strings.Join(args, " ")
		log = append(log, joined)

		if len(args) == 1 && args[0] == "devices" {
			return "List of devices attached\nMOCK001\tdevice\n", nil
		}
		// Strip -s MOCK001
		cmdArgs := args
		if len(cmdArgs) >= 2 && cmdArgs[0] == "-s" {
			cmdArgs = cmdArgs[2:]
		}
		if len(cmdArgs) == 0 {
			return "", nil
		}

		switch cmdArgs[0] {
		case "install":
			companionInstalled = true
			return "Success", nil
		case "push":
			return "1 file pushed", nil
		case "shell":
			sh := strings.Join(cmdArgs[1:], " ")
			switch {
			case sh == "su -c id":
				return "uid=0(root) gid=0(root)", nil
			case strings.Contains(sh, "===CAP_PKG==="):
				pkgSection := "Unable to find package: " + CompanionPackage
				if companionInstalled {
					pkgSection = "Package [" + CompanionPackage + "]\n  versionCode=2\n  versionName=1.1.0\n  android.permission.WRITE_SECURE_SETTINGS: granted=true"
				}
				svcSection := "  (nothing)"
				if watchdogStarted {
					svcSection = "* ServiceRecord{123 com.overkazaf.cap.companion/.ProxyGuardService}\n  isForeground=true"
				}
				wlSection := ""
				if companionInstalled {
					wlSection = "user," + CompanionPackage + ",10200"
				}
				return "===CAP_PKG===\n" + pkgSection + "\n===CAP_SVC===\n" + svcSection + "\n===CAP_WL===\n" + wlSection + "\n", nil
			case strings.HasPrefix(sh, "dumpsys package "+CompanionPackage):
				if !companionInstalled {
					return "Unable to find package: " + CompanionPackage, nil
				}
				return "Package [" + CompanionPackage + "]\n  versionCode=1\n  versionName=1.0.0\n  android.permission.WRITE_SECURE_SETTINGS: granted=true\n", nil
			case strings.HasPrefix(sh, "dumpsys activity services "+CompanionService):
				if watchdogStarted {
					return "* ServiceRecord{123 com.overkazaf.cap.companion/.ProxyGuardService}\n  isForeground=true\n", nil
				}
				return "  (nothing)", nil
			case sh == "dumpsys deviceidle whitelist":
				if companionInstalled {
					return "user," + CompanionPackage + ",10200", nil
				}
				return "", nil
			case strings.Contains(sh, "/apex/com.android.conscrypt/cacerts/") && strings.Contains(sh, "echo APEX"):
				if certInjected {
					return "APEX\nSYSTEM\n", nil
				}
				return "", nil
			case strings.Contains(sh, "mount --bind"):
				certInjected = true
				return "OK", nil
			case strings.HasPrefix(sh, "settings put global http_proxy "):
				proxyValue = strings.TrimPrefix(sh, "settings put global http_proxy ")
				return "", nil
			case sh == "settings delete global http_proxy":
				proxyValue = "null"
				return "", nil
			case sh == "settings get global http_proxy":
				return proxyValue, nil
			case strings.Contains(sh, companionActionStart):
				watchdogStarted = true
				return "Starting service", nil
			case strings.Contains(sh, companionActionStop):
				watchdogStarted = false
				return "Stopping service", nil
			case strings.Contains(sh, "cat "+redirPortStateFile):
				return "9988", nil
			case strings.Contains(sh, "pkill -f cap-redir"):
				return "OK", nil
			default:
				return "", nil
			}
		}
		return "", nil
	}

	res, err := SetupDetailed(SetupOptions{
		Serial:      "MOCK001",
		ProxyHost:   "192.168.1.50",
		ProxyPort:   "8080",
		CACertPath:  certPath,
		InstallCert: true,
	})
	if err != nil {
		t.Fatalf("SetupDetailed failed: %v", err)
	}
	if res.Serial != "MOCK001" || res.ProxyHost != "192.168.1.50" || res.Mode != "proxy" {
		t.Errorf("unexpected SetupResult: %+v", res)
	}
	if !res.CertStatus.Installed || res.CertStatus.Store != "system" {
		t.Errorf("expected system cert installed, got %+v", res.CertStatus)
	}
	if !res.CompanionStatus.Installed || !res.CompanionStatus.HasSecureSettings || !res.CompanionStatus.WatchdogRunning {
		t.Errorf("expected companion installed & watchdog running, got %+v", res.CompanionStatus)
	}
	if proxyValue != "192.168.1.50:8080" {
		t.Errorf("expected global proxy set to 192.168.1.50:8080, got %q", proxyValue)
	}

	if err := Teardown("MOCK001"); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
	if proxyValue != "null" {
		t.Errorf("expected proxy cleared to null, got %q", proxyValue)
	}
	if watchdogStarted {
		t.Errorf("expected companion guard to be stopped during Teardown")
	}

	// Verify recorded redir port 9988 was included in iptables teardown
	foundCustomPort := false
	for _, entry := range log {
		if strings.Contains(entry, "--to-port 9988") && strings.Contains(entry, "--to-port 9999") {
			foundCustomPort = true
			break
		}
	}
	if !foundCustomPort {
		t.Errorf("expected teardown iptables script to clean both 9988 and 9999")
	}
}

func TestInstallCACertNonRootedCompanionFlow(t *testing.T) {
	certPath := filepath.Join("testdata", "test-ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Skip("testdata/test-ca.crt not available")
	}

	origExec := adbExecFunc
	t.Cleanup(func() { adbExecFunc = origExec })

	launchedCompanion := false
	adbExecFunc = func(args ...string) (string, error) {
		if len(args) == 1 && args[0] == "devices" {
			return "List of devices attached\nNONROOT\tdevice\n", nil
		}
		cmdArgs := args
		if len(cmdArgs) >= 2 && cmdArgs[0] == "-s" {
			cmdArgs = cmdArgs[2:]
		}
		if cmdArgs[0] == "shell" {
			sh := strings.Join(cmdArgs[1:], " ")
			if sh == "su -c id" {
				return "su: not found", os.ErrNotExist
			}
			if strings.HasPrefix(sh, "dumpsys package "+CompanionPackage) {
				return "Package [" + CompanionPackage + "]\n  versionCode=2\n  versionName=1.1.0\n  android.permission.WRITE_SECURE_SETTINGS: granted=true\n", nil
			}
			if strings.Contains(sh, CompanionActivity) && strings.Contains(sh, "--ez install_cert true") {
				launchedCompanion = true
				return "Starting: Intent", nil
			}
		}
		return "", nil
	}

	res, err := InstallCACert("NONROOT", certPath)
	if err != nil {
		t.Fatalf("InstallCACert non-rooted failed: %v", err)
	}
	if !res.Success || res.Method != "companion_keychain" || !res.NeedsManual || !launchedCompanion {
		t.Errorf("unexpected non-rooted InstallCACert result: %+v (launched=%v)", res, launchedCompanion)
	}
}

func TestParseBatchedDeviceStatusOutput(t *testing.T) {
	batched := `
===CAP_META===
MODEL=Pixel 7 Pro
BRAND=google
RELEASE=14
SDK=34
PROXY=192.168.1.50:8080
ROOT=uid=0(root) gid=0(root)
REDIR_PID=4321
REDIR_PORT=9988
===CAP_CERT===
APEX
SYSTEM
===CAP_PKG===
Package [com.overkazaf.cap.companion] (abc):
  versionCode=1 minSdk=24 targetSdk=34
  versionName=1.0.0
  android.permission.WRITE_SECURE_SETTINGS: granted=true
===CAP_SVC===
  * ServiceRecord{1234 u0 com.overkazaf.cap.companion/.ProxyGuardService}
    isForeground=true
===CAP_WL===
user,com.overkazaf.cap.companion,10222
`
	st := ParseBatchedDeviceStatusOutput("PIXEL7", "9a5ba575.0", true, batched)
	if st.Model != "Pixel 7 Pro" || st.Brand != "google" || st.AndroidVersion != "14" || st.SDK != "34" {
		t.Errorf("unexpected device metadata: %+v", st)
	}
	if !st.Rooted || st.ProxyAddress != "192.168.1.50:8080" || !st.VPNActive || st.RedirPort != "9988" {
		t.Errorf("unexpected proxy/vpn/root state: %+v", st)
	}
	if !st.CertStatus.Installed || st.CertStatus.Store != "system" || st.CertStatus.Method != "apex" {
		t.Errorf("unexpected cert status: %+v", st.CertStatus)
	}
	if !st.CompanionStatus.Installed || !st.CompanionStatus.HasSecureSettings || !st.CompanionStatus.WatchdogRunning || !st.CompanionStatus.BatteryWhitelisted {
		t.Errorf("unexpected companion status: %+v", st.CompanionStatus)
	}
}

func TestSelectBestHostIPInterfaceRanking(t *testing.T) {
	candidates := []hostIPCandidate{
		{ifaceName: "lo0", ip: net.ParseIP("127.0.0.1"), up: true, loopback: true},
		{ifaceName: "utun3", ip: net.ParseIP("198.18.0.1"), up: true},
		{ifaceName: "utun4", ip: net.ParseIP("100.64.1.2"), up: true},
		{ifaceName: "awdl0", ip: net.ParseIP("169.254.12.34"), up: true},
		{ifaceName: "bridge100", ip: net.ParseIP("192.168.64.1"), up: true},
		{ifaceName: "docker0", ip: net.ParseIP("172.17.0.1"), up: true},
		{ifaceName: "en0", ip: net.ParseIP("192.168.1.42"), up: true},
		{ifaceName: "en5", ip: net.ParseIP("10.0.0.5"), up: false}, // down
	}

	if got := selectBestHostIP(candidates); got != "192.168.1.42" {
		t.Errorf("selectBestHostIP() = %q, want 192.168.1.42 (en0 LAN IP)", got)
	}

	// Only virtual non-link-local fallback available (198.18.* must still be rejected)
	onlyVirtual := []hostIPCandidate{
		{ifaceName: "utun0", ip: net.ParseIP("198.18.0.1"), up: true},
		{ifaceName: "bridge100", ip: net.ParseIP("192.168.64.1"), up: true},
	}
	if got := selectBestHostIP(onlyVirtual); got != "192.168.64.1" {
		t.Errorf("selectBestHostIP(onlyVirtual) = %q, want 192.168.64.1", got)
	}
}

func TestBuildBindMountScript_HTTPToolkitAndroid14Compliance(t *testing.T) {
	script := BuildBindMountScript("d7932d1e.0", "/data/local/tmp/d7932d1e.0")
	mustContain := []string{
		"mount -t tmpfs tmpfs \"$SYSTEM_CERTS\"",
		"u:object_r:system_security_cacerts_file:s0",
		"chown system:system",
		"zygote zygote64 webview_zygote",
		"system_server",
		"readlink \"/proc/$PID/ns/mnt\"",
		"nsenter --mount=\"/proc/$PID/ns/mnt\" -- mount --bind \"$SYSTEM_CERTS\" \"$APEX_CERTS\"",
		"nsenter --mount=\"/proc/$ZPID/ns/mnt\" -- test -r \"$APEX_CERTS/$HASH\"",
		"am broadcast -a android.security.action.TRUST_STORE_CHANGED",
	}
	for _, needle := range mustContain {
		if !strings.Contains(script, needle) {
			t.Errorf("BuildBindMountScript missing required Android 14+ directive %q", needle)
		}
	}
	// Must never bind-mount /data/local/tmp directly onto /system or /apex
	if strings.Contains(script, `mount --bind "$TMPDIR"`) || strings.Contains(script, `mount --bind "$STAGE"`) {
		t.Errorf("BuildBindMountScript must mount tmpfs rather than bind-mounting /data/local/tmp")
	}
}

func TestCertHashFilenameMatchesOpenSSLAndSupportsDER(t *testing.T) {
	certPath := filepath.Join("testdata", "test-ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Skip("testdata/test-ca.crt not available")
	}
	// Verified via: openssl x509 -in internal/android/testdata/test-ca.crt -noout -subject_hash_old -> 28fca1f7
	if got := CertHashFilename(certPath); got != "28fca1f7.0" {
		t.Fatalf("CertHashFilename(test-ca.crt) = %q, want 28fca1f7.0", got)
	}

	// Verify raw DER file parsing fallback produces the exact same subject_hash_old
	cert, err := parseCertFile(certPath)
	if err != nil {
		t.Fatalf("parseCertFile failed: %v", err)
	}
	derPath := filepath.Join(t.TempDir(), "test-ca.der")
	if err := os.WriteFile(derPath, cert.Raw, 0o644); err != nil {
		t.Fatalf("write DER cert: %v", err)
	}
	if got := CertHashFilename(derPath); got != "28fca1f7.0" {
		t.Fatalf("CertHashFilename(DER) = %q, want 28fca1f7.0", got)
	}
}

func TestParseCompanionCertBroadcast(t *testing.T) {
	const hash = "d7932d1e.0"
	tests := []struct {
		name        string
		output      string
		wantOK      bool
		wantInstall bool
		wantStore   string
		wantMethod  string
	}{
		{
			name:        "android 14+ system store via AndroidCAStore",
			output:      `Broadcasting: Intent { ... }` + "\n" + `Broadcast completed: result=-1, data="installed=true;store=system;method=android_ca_store_system;alias=system:d7932d1e.0;hash=d7932d1e.0;apex_dir=true;legacy_only=false;fp_mismatch=false;file_ready=false"`,
			wantOK:      true,
			wantInstall: true,
			wantStore:   "system",
			wantMethod:  "apex",
		},
		{
			name:        "non-rooted user store via AndroidCAStore",
			output:      `Broadcast completed: result=-1, data="installed=true;store=user;method=android_ca_store_user;alias=user:d7932d1e.0;hash=d7932d1e.0;apex_dir=true;legacy_only=false;fp_mismatch=false;file_ready=true"`,
			wantOK:      true,
			wantInstall: true,
			wantStore:   "user",
			wantMethod:  "user",
		},
		{
			name:        "fingerprint mismatch",
			output:      `Broadcast completed: result=-1, data="installed=false;store=none;method=none;hash=d7932d1e.0;apex_dir=true;legacy_only=false;fp_mismatch=true"`,
			wantOK:      true,
			wantInstall: false,
			wantStore:   "none",
			wantMethod:  "fingerprint_mismatch",
		},
		{
			name:        "legacy system only",
			output:      `Broadcast completed: result=-1, data="installed=false;store=none;method=legacy_system_only;hash=d7932d1e.0;apex_dir=true;legacy_only=true;fp_mismatch=false"`,
			wantOK:      true,
			wantInstall: false,
			wantStore:   "none",
			wantMethod:  "legacy_system_only",
		},
		{
			name:   "empty or missing receiver output",
			output: `Broadcast completed: result=0`,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseCompanionCertBroadcast(hash, tt.output)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got=%+v)", ok, tt.wantOK, got)
			}
			if !ok {
				return
			}
			if got.Installed != tt.wantInstall || got.Store != tt.wantStore || got.Method != tt.wantMethod || got.Hash != hash {
				t.Errorf("got %+v, want installed=%v store=%q method=%q hash=%q",
					got, tt.wantInstall, tt.wantStore, tt.wantMethod, hash)
			}
		})
	}
}

func TestCheckCertStatusRootProbeRunsOnLegacySystemOnly(t *testing.T) {
	certPath := filepath.Join("testdata", "test-ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Skip("testdata/test-ca.crt not available")
	}

	origExec := adbExecFunc
	t.Cleanup(func() { adbExecFunc = origExec })

	rootProbed := false
	adbExecFunc = func(args ...string) (string, error) {
		cmdArgs := args
		if len(cmdArgs) >= 2 && cmdArgs[0] == "-s" {
			cmdArgs = cmdArgs[2:]
		}
		if len(cmdArgs) > 0 && cmdArgs[0] == "shell" {
			sh := strings.Join(cmdArgs[1:], " ")
			switch {
			case strings.Contains(sh, "echo HAS_APEX_DIR"):
				// Unprivileged adb shell sees legacy /system only (cannot see zygote ns or /data/misc/user/0)
				return "HAS_APEX_DIR\nSYSTEM\n", nil
			case sh == "su -c id":
				return "uid=0(root) gid=0(root)", nil
			case strings.Contains(sh, "su --mount-master") && strings.Contains(sh, "cacerts-added"):
				rootProbed = true
				return "APEX\n", nil
			}
		}
		return "", nil
	}

	st := CheckCertStatus("PIXEL14", certPath)
	if !rootProbed {
		t.Fatalf("expected root probe to run even when initial probe returned legacy_system_only")
	}
	if !st.Installed || st.Store != "system" || st.Method != "apex" {
		t.Fatalf("expected APEX system cert after root namespace probe, got %+v", st)
	}
}

func TestCheckCertStatusNonRootedCompanionFallback(t *testing.T) {
	certPath := filepath.Join("testdata", "test-ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Skip("testdata/test-ca.crt not available")
	}

	origExec := adbExecFunc
	t.Cleanup(func() { adbExecFunc = origExec })

	adbExecFunc = func(args ...string) (string, error) {
		cmdArgs := args
		if len(cmdArgs) >= 2 && cmdArgs[0] == "-s" {
			cmdArgs = cmdArgs[2:]
		}
		if len(cmdArgs) > 0 && cmdArgs[0] == "shell" {
			sh := strings.Join(cmdArgs[1:], " ")
			switch {
			case strings.Contains(sh, "echo HAS_APEX_DIR"):
				// Non-rooted adb shell cannot read /data/misc/user/0/cacerts-added
				return "HAS_APEX_DIR\n", nil
			case sh == "su -c id":
				return "su: not found", os.ErrNotExist
			case strings.Contains(sh, CompanionCertReceiver) && strings.Contains(sh, companionActionCheckCert):
				return `Broadcast completed: result=-1, data="installed=true;store=user;method=android_ca_store_user;alias=user:28fca1f7.0;hash=28fca1f7.0;apex_dir=true"`, nil
			}
		}
		return "", nil
	}

	st := CheckCertStatus("NONROOT14", certPath)
	if !st.Installed || st.Store != "user" || st.Method != "user" || st.Hash != "28fca1f7.0" {
		t.Fatalf("expected non-rooted companion AndroidCAStore user cert detection, got %+v", st)
	}
}

func TestInstallCompanionReplacesOnSignatureMismatch(t *testing.T) {
	origExec := adbExecFunc
	t.Cleanup(func() { adbExecFunc = origExec })

	uninstalled := false
	installAttempts := 0
	adbExecFunc = func(args ...string) (string, error) {
		if len(args) == 1 && args[0] == "devices" {
			return "List of devices attached\nDEV1\tdevice\n", nil
		}
		cmdArgs := args
		if len(cmdArgs) >= 2 && cmdArgs[0] == "-s" {
			cmdArgs = cmdArgs[2:]
		}
		switch cmdArgs[0] {
		case "shell":
			sh := strings.Join(cmdArgs[1:], " ")
			if strings.Contains(sh, "===CAP_PKG===") {
				// Old versionCode=1 triggers upgrade to CompanionVersionCode=2
				return "===CAP_PKG===\nPackage [" + CompanionPackage + "]\n  versionCode=1\n  versionName=1.0.0\n===CAP_SVC===\n===CAP_WL===\n", nil
			}
			return "", nil
		case "install":
			installAttempts++
			if !uninstalled {
				return "Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Signatures do not match previously installed version]", os.ErrPermission
			}
			return "Success", nil
		case "uninstall":
			if len(cmdArgs) >= 2 && cmdArgs[1] == CompanionPackage {
				uninstalled = true
				return "Success", nil
			}
		}
		return "", nil
	}

	if err := InstallCompanion("DEV1"); err != nil {
		t.Fatalf("InstallCompanion failed on signature mismatch recovery: %v", err)
	}
	if !uninstalled || installAttempts < 3 {
		t.Fatalf("expected uninstall + reinstall recovery, uninstalled=%v attempts=%d", uninstalled, installAttempts)
	}
}
