package android

import (
	"archive/zip"
	"bytes"
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
			name:        "apex and system",
			output:      "APEX\nSYSTEM\n",
			wantInstall: true,
			wantStore:   "system",
			wantMethod:  "apex",
		},
		{
			name:        "system only",
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
				return "Package [" + CompanionPackage + "]\n  versionCode=1\n  versionName=1.0.0\n  android.permission.WRITE_SECURE_SETTINGS: granted=true\n", nil
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
