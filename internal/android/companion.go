package android

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/overkazaf/cap/internal/proxy"
)

const (
	// CompanionPackage is the Android application ID of the embedded Cap Guard APK.
	CompanionPackage = "com.overkazaf.cap.companion"
	// CompanionVersionCode is the versionCode baked into the embedded APK.
	CompanionVersionCode = 7
	// CompanionVersionName is the versionName baked into the embedded APK.
	CompanionVersionName = "1.3.2"
	// CompanionService is the full component name of ProxyGuardService.
	CompanionService = CompanionPackage + "/.ProxyGuardService"
	// CompanionActivity is the full component name of MainActivity.
	CompanionActivity = CompanionPackage + "/.MainActivity"
	// CompanionCertReceiver is the BroadcastReceiver that queries AndroidCAStore
	// and syncs CA cert metadata into app-private storage without requiring root.
	CompanionCertReceiver = CompanionPackage + "/.CertStatusReceiver"
	// CompanionCertPath is the standard path on device storage where CA certs are pushed.
	CompanionCertPath = "/sdcard/Download/cap-ca.crt"
	// companionAppCertPath is inside the companion app's own external files dir
	// so Android 11+ Scoped Storage always allows MainActivity to read it.
	companionAppCertPath = "/sdcard/Android/data/" + CompanionPackage + "/files/cap-ca.crt"

	companionActionStart     = CompanionPackage + ".ACTION_START"
	companionActionStop      = CompanionPackage + ".ACTION_STOP"
	companionActionCheckCert = CompanionPackage + ".ACTION_CHECK_CERT"
	companionActionSyncCert  = CompanionPackage + ".ACTION_SYNC_CERT"
)

// CompanionStatus describes the installation, permissions, and watchdog state
// of the Cap Guard Android Companion APK on a connected device.
type CompanionStatus struct {
	Installed          bool   `json:"installed"`
	Version            string `json:"version"`
	VersionCode        int    `json:"version_code"`
	HasSecureSettings  bool   `json:"has_secure_settings"`
	WatchdogRunning    bool   `json:"watchdog_running"`
	BatteryWhitelisted bool   `json:"battery_whitelisted"`
	Error              string `json:"error,omitempty"`
}

// InstallCompanion ensures the embedded Cap Guard APK is installed at the
// current version on the target device, grants WRITE_SECURE_SETTINGS (for
// rootless proxy cleanup), and configures background/battery whitelisting so
// OEM power managers do not kill the proxy watchdog.
func InstallCompanion(serial string) error {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}
	serial = resolved

	status := GetCompanionStatus(serial)
	if !status.Installed || status.VersionCode < CompanionVersionCode {
		if len(capCompanionAPK) == 0 {
			return fmt.Errorf("embedded cap-companion.apk is empty")
		}
		tmpFile, err := os.CreateTemp("", "cap-companion-*.apk")
		if err != nil {
			return fmt.Errorf("create temp companion apk: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)

		if _, err := tmpFile.Write(capCompanionAPK); err != nil {
			tmpFile.Close()
			return fmt.Errorf("write temp companion apk: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("close temp companion apk: %w", err)
		}

		out, err := AdbCmd(serial, "install", "-r", "-g", tmpPath)
		if err != nil {
			// Fallback without -g for older or stricter OEM package installers
			out2, err2 := AdbCmd(serial, "install", "-r", tmpPath)
			if err2 != nil {
				combined := out + " / " + out2
				if strings.Contains(combined, "INSTALL_FAILED_UPDATE_INCOMPATIBLE") ||
					strings.Contains(combined, "INSTALL_FAILED_VERSION_DOWNGRADE") {
					// Cleanly replace only our own companion package when local signing key changed.
					_, _ = AdbCmd(serial, "uninstall", CompanionPackage)
					out3, err3 := AdbCmd(serial, "install", "-g", tmpPath)
					if err3 != nil {
						out4, err4 := AdbCmd(serial, "install", tmpPath)
						if err4 != nil {
							return fmt.Errorf("install companion apk after clean replace: %v (%s / %s)", err4, out3, out4)
						}
					}
				} else {
					return fmt.Errorf("install companion apk: %v (%s)", err2, combined)
				}
			}
		}
	}

	// Grant WRITE_SECURE_SETTINGS so the companion can clear http_proxy without root
	if out, err := AdbShell(serial, "pm grant "+CompanionPackage+" android.permission.WRITE_SECURE_SETTINGS"); err != nil {
		// On some Android builds pm grant writes warnings but still succeeds; verify below.
		_ = out
	}

	// Best-effort grant POST_NOTIFICATIONS (Android 13+) and OEM background whitelists
	_, _ = AdbShell(serial, "pm grant "+CompanionPackage+" android.permission.POST_NOTIFICATIONS 2>/dev/null || true")
	_, _ = AdbShell(serial, "appops set "+CompanionPackage+" RUN_IN_BACKGROUND allow 2>/dev/null || true")
	_, _ = AdbShell(serial, "appops set "+CompanionPackage+" RUN_ANY_IN_BACKGROUND allow 2>/dev/null || true")
	_, _ = AdbShell(serial, "dumpsys deviceidle whitelist +"+CompanionPackage+" 2>/dev/null || true")

	// Best-effort sync of the host companion API token so newly installed or
	// upgraded devices can authenticate with /_cap/companion/* immediately.
	_ = syncCompanionConfig(serial, "", "")

	return nil
}

// companionAPITokenFunc resolves the host's companion API token. Overridden in
// tests to avoid touching the real user's ~/.cap directory when needed.
var companionAPITokenFunc = func() string {
	tok, err := proxy.EnsureCompanionToken("")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(tok)
}

func companionAPIToken() string {
	if companionAPITokenFunc == nil {
		return ""
	}
	return strings.TrimSpace(companionAPITokenFunc())
}

// SetupADBReverse creates a best-effort USB reverse tunnel (`adb reverse tcp:<port> tcp:<port>`)
// so the Companion APK (and loopback proxy reconnection) can reach the desktop Cap proxy
// over USB even when device Wi-Fi is disconnected or isolated.
func SetupADBReverse(serial, port string) error {
	port = strings.TrimSpace(port)
	if port == "" {
		port = "8080"
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("invalid reverse port: %q", port)
	}
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}
	spec := "tcp:" + port
	if out, err := AdbCmd(resolved, "reverse", spec, spec); err != nil {
		return fmt.Errorf("adb reverse %s: %v (%s)", spec, err, out)
	}
	return nil
}

// SyncCompanionConfig pushes the host's companion API token (and optional
// proxyHost/proxyPort) silently into the Companion APK via ACTION_SYNC_CERT
// so the Traffic tab stays paired with the host proxy.
func SyncCompanionConfig(serial, proxyHost, proxyPort string) error {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}
	if strings.TrimSpace(proxyPort) != "" {
		_ = SetupADBReverse(resolved, proxyPort)
	}
	return syncCompanionConfig(resolved, proxyHost, proxyPort)
}

func syncCompanionConfig(serial, proxyHost, proxyPort string) error {
	tok := companionAPIToken()
	proxyHost = strings.TrimSpace(proxyHost)
	proxyPort = strings.TrimSpace(proxyPort)
	if tok == "" && proxyHost == "" && proxyPort == "" {
		return nil
	}

	var extras strings.Builder
	if tok != "" {
		extras.WriteString(" --es api_token " + shellQuote(tok))
	}
	if proxyHost != "" {
		extras.WriteString(" --es proxy_host " + shellQuote(proxyHost))
	}
	if proxyPort != "" {
		extras.WriteString(" --es proxy_port " + shellQuote(proxyPort))
	}

	cmd := fmt.Sprintf(
		"am broadcast --include-stopped-packages -n %s -a %s%s",
		CompanionCertReceiver,
		companionActionSyncCert,
		extras.String(),
	)
	out, err := AdbShell(serial, cmd)
	if err != nil || strings.Contains(out, "Error:") {
		return fmt.Errorf("sync companion config: %v (%s)", err, out)
	}
	return nil
}

// StartCompanionGuard starts ProxyGuardService with default heartbeat (3000ms)
// and miss threshold (3).
func StartCompanionGuard(serial, proxyHost, proxyPort, mode, redirPort string) error {
	return StartCompanionGuardWithConfig(serial, proxyHost, proxyPort, mode, redirPort, 3000, 3)
}

// StartCompanionGuardWithConfig starts ProxyGuardService on the device so it
// actively monitors proxyHost:proxyPort and autonomously clears device proxy
// settings on disconnect.
func StartCompanionGuardWithConfig(serial, proxyHost, proxyPort, mode, redirPort string, heartbeatMs, missThreshold int) error {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}
	serial = resolved

	if strings.TrimSpace(proxyHost) == "" {
		return fmt.Errorf("proxyHost is required to start companion guard")
	}
	if strings.TrimSpace(proxyPort) == "" {
		proxyPort = "8080"
	}
	if mode != "vpn" {
		mode = "proxy"
	}
	if strings.TrimSpace(redirPort) == "" {
		redirPort = "9999"
	}
	if heartbeatMs <= 0 {
		heartbeatMs = 3000
	}
	if missThreshold <= 0 {
		missThreshold = 3
	}

	extras := fmt.Sprintf(
		"-n %s -a %s --es proxy_host %s --es proxy_port %s --es mode %s --es redir_port %s --ei heartbeat_ms %d --ei miss_threshold %d",
		CompanionService,
		companionActionStart,
		shellQuote(proxyHost),
		shellQuote(proxyPort),
		shellQuote(mode),
		shellQuote(redirPort),
		heartbeatMs,
		missThreshold,
	)
	if tok := companionAPIToken(); tok != "" {
		extras += " --es api_token " + shellQuote(tok)
	}

	out, err := AdbShell(serial, "am start-foreground-service "+extras)
	if err != nil || strings.Contains(out, "Error:") || strings.Contains(out, "Exception") {
		// Fallback for Android 7 (API 24-25) which lacks start-foreground-service
		out2, err2 := AdbShell(serial, "am startservice "+extras)
		if err2 != nil || strings.Contains(out2, "Error:") {
			return fmt.Errorf("start companion guard: %v (%s / %s)", err2, out, out2)
		}
	}
	return nil
}

// StopCompanionGuard sends ACTION_STOP to ProxyGuardService so it cleanly
// clears device proxy settings, dismisses the active watchdog notification,
// and stops itself.
func StopCompanionGuard(serial string) error {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}
	serial = resolved

	cmd := fmt.Sprintf("am startservice -n %s -a %s", CompanionService, companionActionStop)
	out, err := AdbShell(serial, cmd)
	if err != nil || strings.Contains(out, "Error:") {
		// Try start-foreground-service fallback in case background start is restricted
		fgCmd := fmt.Sprintf("am start-foreground-service -n %s -a %s", CompanionService, companionActionStop)
		if out2, err2 := AdbShell(serial, fgCmd); err2 != nil || strings.Contains(out2, "Error:") {
			return fmt.Errorf("stop companion guard: %v (%s / %s)", err2, out, out2)
		}
	}
	return nil
}

// TriggerCompanionCertInstall pushes certPath to /sdcard/Download/cap-ca.crt
// (and the companion's Scoped-Storage-accessible files dir), ensures the
// companion APK is installed, and launches MainActivity with install_cert=true
// so non-rooted users get an instant KeyChain install prompt across Android 7–15.
func TriggerCompanionCertInstall(serial, certPath string) error {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}
	serial = resolved

	if _, err := AdbCmd(serial, "push", certPath, CompanionCertPath); err != nil {
		return fmt.Errorf("push cert to %s: %w", CompanionCertPath, err)
	}

	if err := InstallCompanion(serial); err != nil {
		return fmt.Errorf("install companion for cert install: %w", err)
	}

	// Best-effort copy into companion app's external files dir for Scoped Storage (Android 11+)
	_, _ = AdbShell(serial, "mkdir -p /sdcard/Android/data/"+CompanionPackage+"/files 2>/dev/null || true")
	_, _ = AdbCmd(serial, "push", certPath, companionAppCertPath)

	extraB64 := ""
	if certBytes, readErr := os.ReadFile(certPath); readErr == nil && len(certBytes) > 0 && len(certBytes) < 32*1024 {
		extraB64 = " --es cert_b64 " + shellQuote(base64.StdEncoding.EncodeToString(certBytes))
	}
	extraMeta := ""
	if hashName := CertHashFilename(certPath); hashName != "" {
		extraMeta += " --es cert_hash " + shellQuote(hashName)
	}
	if fp := CertSHA256Fingerprint(certPath); fp != "" {
		extraMeta += " --es cert_fp " + shellQuote(fp)
	}

	launchCmd := fmt.Sprintf(
		"am start -n %s --ez install_cert true --es cert_path %s%s%s",
		CompanionActivity,
		shellQuote(CompanionCertPath),
		extraMeta,
		extraB64,
	)
	out, err := AdbShell(serial, launchCmd)
	if err != nil || strings.Contains(out, "Error:") {
		return fmt.Errorf("launch companion cert installer: %v (%s)", err, out)
	}
	return nil
}

// SyncCompanionCert pushes the active CA certificate metadata (hash, SHA-256
// fingerprint) and PEM bytes silently into the Companion APK's app-private
// storage via CertStatusReceiver so the APK can verify the exact host CA and
// launch KeyChain even under Android 11+ Scoped Storage.
func SyncCompanionCert(serial, certPath string) error {
	if certPath == "" {
		return nil
	}
	hashName := CertHashFilename(certPath)
	fp := CertSHA256Fingerprint(certPath)
	if hashName == "" && fp == "" {
		return nil
	}
	var extras strings.Builder
	if hashName != "" {
		extras.WriteString(" --es expected_hash " + shellQuote(hashName))
	}
	if fp != "" {
		extras.WriteString(" --es expected_fp " + shellQuote(fp))
	}
	if certBytes, err := os.ReadFile(certPath); err == nil && len(certBytes) > 0 && len(certBytes) < 32*1024 {
		extras.WriteString(" --es cert_b64 " + shellQuote(base64.StdEncoding.EncodeToString(certBytes)))
	}
	if tok := companionAPIToken(); tok != "" {
		extras.WriteString(" --es api_token " + shellQuote(tok))
	}
	cmd := fmt.Sprintf(
		"am broadcast --include-stopped-packages -n %s -a %s%s",
		CompanionCertReceiver,
		companionActionSyncCert,
		extras.String(),
	)
	out, err := AdbShell(serial, cmd)
	if err != nil || strings.Contains(out, "Error:") {
		return fmt.Errorf("sync companion cert: %v (%s)", err, out)
	}
	return nil
}

// CheckCertViaCompanion queries the installed Cap Guard Companion APK's
// CertStatusReceiver over an ordered ADB broadcast to inspect Android's live
// AndroidCAStore without requiring root (especially critical on non-rooted
// Android 10–15 where adb shell cannot read /data/misc/user/0/cacerts-added).
func CheckCertViaCompanion(serial, certPath string) (CertStatus, bool) {
	hashName := CertHashFilename(certPath)
	fp := CertSHA256Fingerprint(certPath)
	if hashName == "" && fp == "" {
		return CertStatus{}, false
	}
	var extras strings.Builder
	if hashName != "" {
		extras.WriteString(" --es expected_hash " + shellQuote(hashName))
	}
	if fp != "" {
		extras.WriteString(" --es expected_fp " + shellQuote(fp))
	}
	cmd := fmt.Sprintf(
		"am broadcast --include-stopped-packages -n %s -a %s%s",
		CompanionCertReceiver,
		companionActionCheckCert,
		extras.String(),
	)
	out, err := AdbShell(serial, cmd)
	if err != nil || strings.TrimSpace(out) == "" {
		return CertStatus{}, false
	}
	return ParseCompanionCertBroadcast(hashName, out)
}

// ParseCompanionCertBroadcast parses `am broadcast` ordered output returned by
// CertStatusReceiver (e.g. `Broadcast completed: result=-1, data="installed=true;store=user;..."`).
func ParseCompanionCertBroadcast(fallbackHash, output string) (CertStatus, bool) {
	targetLine := output
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Broadcast completed:") && strings.Contains(line, `data="`) {
			targetLine = strings.TrimSpace(line)
			break
		}
	}
	idx := strings.Index(targetLine, `data="`)
	if idx < 0 {
		return CertStatus{}, false
	}
	rest := targetLine[idx+len(`data="`):]
	endIdx := strings.LastIndexByte(rest, '"')
	if endIdx < 0 {
		return CertStatus{}, false
	}
	payload := strings.TrimSpace(rest[:endIdx])
	if payload == "" {
		return CertStatus{}, false
	}

	kv := make(map[string]string, 12)
	for _, part := range strings.Split(payload, ";") {
		if eq := strings.IndexByte(part, '='); eq > 0 {
			kv[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
		}
	}
	if _, ok := kv["installed"]; !ok {
		return CertStatus{}, false
	}

	installed := strings.EqualFold(kv["installed"], "true")
	store := kv["store"]
	if store == "" {
		store = "none"
	}
	method := kv["method"]
	hash := kv["hash"]
	if hash == "" {
		hash = fallbackHash
	}
	hasApexDir := strings.EqualFold(kv["apex_dir"], "true")
	legacyOnly := strings.EqualFold(kv["legacy_only"], "true")
	fpMismatch := strings.EqualFold(kv["fp_mismatch"], "true")

	if installed && store == "system" {
		m := "system"
		details := "verified in AndroidCAStore system trust store (via Cap Guard)"
		if hasApexDir {
			m = "apex"
			details = "verified in Android 14+ AndroidCAStore / APEX system trust store (via Cap Guard)"
		}
		return CertStatus{
			Installed: true,
			Store:     "system",
			Hash:      hash,
			Method:    m,
			Details:   details,
		}, true
	}
	if installed && store == "user" {
		details := "verified in AndroidCAStore user trust store (via Cap Guard)"
		if hasApexDir {
			details = "verified in user trust store via AndroidCAStore (missing from Android 14+ APEX system store)"
		}
		return CertStatus{
			Installed: true,
			Store:     "user",
			Hash:      hash,
			Method:    "user",
			Details:   details,
		}, true
	}
	if fpMismatch {
		return CertStatus{
			Installed: false,
			Store:     "none",
			Hash:      hash,
			Method:    "fingerprint_mismatch",
			Details:   "different Cap CA certificate detected in AndroidCAStore (fingerprint mismatch)",
		}, true
	}
	if legacyOnly || method == "legacy_system_only" {
		return CertStatus{
			Installed: false,
			Store:     "none",
			Hash:      hash,
			Method:    "legacy_system_only",
			Details:   "present in legacy /system only — missing from Android 14+ APEX Conscrypt",
		}, true
	}
	return CertStatus{
		Installed: false,
		Store:     "none",
		Hash:      hash,
		Details:   "CA certificate not detected in AndroidCAStore",
	}, true
}

// GetCompanionStatus inspects the connected device in a single batched
// `adb shell` invocation to report whether Cap Guard is installed, its
// version, whether WRITE_SECURE_SETTINGS is granted, whether
// ProxyGuardService is currently running, and battery whitelist state.
func GetCompanionStatus(serial string) CompanionStatus {
	script := fmt.Sprintf(
		`echo "===CAP_PKG==="; dumpsys package %s 2>/dev/null; `+
			`echo "===CAP_SVC==="; dumpsys activity services %s 2>/dev/null; `+
			`echo "===CAP_WL==="; dumpsys deviceidle whitelist 2>/dev/null; true`,
		CompanionPackage, CompanionService,
	)
	out, err := AdbShell(serial, script)
	if err != nil && strings.TrimSpace(out) == "" {
		return CompanionStatus{Error: err.Error()}
	}
	return ParseBatchedCompanionOutput(out)
}

// ParseBatchedCompanionOutput parses the sectioned stdout emitted by
// GetCompanionStatus (and GetDeviceStatus) into a CompanionStatus.
func ParseBatchedCompanionOutput(output string) CompanionStatus {
	pkgSec := extractSection(output, "===CAP_PKG===", "===CAP_SVC===")
	svcSec := extractSection(output, "===CAP_SVC===", "===CAP_WL===")
	wlSec := extractSection(output, "===CAP_WL===", "")

	// Fallback for unsectioned mock outputs in legacy tests
	if pkgSec == "" && !strings.Contains(output, "===CAP_PKG===") {
		pkgSec = output
	}

	installed, verName, verCode, hasSecure := ParseCompanionPackageDump(pkgSec)
	status := CompanionStatus{
		Installed:         installed,
		Version:           verName,
		VersionCode:       verCode,
		HasSecureSettings: hasSecure,
	}
	if !installed {
		return status
	}
	status.WatchdogRunning = ParseCompanionServiceRunning(svcSec)
	status.BatteryWhitelisted = ParseBatteryWhitelisted(wlSec)
	return status
}

func extractSection(output, startMarker, endMarker string) string {
	startIdx := strings.Index(output, startMarker)
	if startIdx < 0 {
		return ""
	}
	rest := output[startIdx+len(startMarker):]
	if endMarker != "" {
		if endIdx := strings.Index(rest, endMarker); endIdx >= 0 {
			rest = rest[:endIdx]
		}
	}
	return strings.TrimSpace(rest)
}

// ParseCompanionPackageDump extracts installation state, versionName,
// versionCode, and WRITE_SECURE_SETTINGS grant state from `dumpsys package`.
func ParseCompanionPackageDump(output string) (installed bool, versionName string, versionCode int, hasSecureSettings bool) {
	if strings.TrimSpace(output) == "" || strings.Contains(output, "Unable to find package") {
		return false, "", 0, false
	}

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "Package ["+CompanionPackage+"]") ||
			strings.HasPrefix(line, "versionName=") ||
			strings.HasPrefix(line, "versionCode=") {
			installed = true
		}
		if strings.HasPrefix(line, "versionName=") {
			versionName = strings.TrimSpace(strings.TrimPrefix(line, "versionName="))
		}
		if strings.HasPrefix(line, "versionCode=") {
			val := strings.TrimPrefix(line, "versionCode=")
			if fields := strings.Fields(val); len(fields) > 0 {
				if n, err := strconv.Atoi(fields[0]); err == nil {
					versionCode = n
				}
			}
		}
		if strings.Contains(line, "android.permission.WRITE_SECURE_SETTINGS") &&
			strings.Contains(line, "granted=true") {
			hasSecureSettings = true
		}
	}
	return installed, versionName, versionCode, hasSecureSettings
}

// ParseCompanionServiceRunning reports whether `dumpsys activity services`
// shows ProxyGuardService as actively running.
func ParseCompanionServiceRunning(output string) bool {
	if strings.TrimSpace(output) == "" || strings.Contains(output, "(nothing)") {
		return false
	}
	hasRecord := strings.Contains(output, "ProxyGuardService") && strings.Contains(output, "ServiceRecord{")
	if !hasRecord {
		return false
	}
	// A live service record has either isForeground=true, createTime=, or an active ProcessRecord.
	return strings.Contains(output, "isForeground=true") ||
		strings.Contains(output, "app=ProcessRecord{") ||
		strings.Contains(output, "startRequested=true")
}

// ParseBatteryWhitelisted checks whether CompanionPackage appears in
// `dumpsys deviceidle whitelist` output.
func ParseBatteryWhitelisted(output string) bool {
	return strings.Contains(output, CompanionPackage)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
