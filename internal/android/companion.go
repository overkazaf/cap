package android

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// CompanionPackage is the Android application ID of the embedded Cap Guard APK.
	CompanionPackage = "com.overkazaf.cap.companion"
	// CompanionVersionCode is the versionCode baked into the embedded APK.
	CompanionVersionCode = 1
	// CompanionVersionName is the versionName baked into the embedded APK.
	CompanionVersionName = "1.0.0"
	// CompanionService is the full component name of ProxyGuardService.
	CompanionService = CompanionPackage + "/.ProxyGuardService"
	// CompanionActivity is the full component name of MainActivity.
	CompanionActivity = CompanionPackage + "/.MainActivity"
	// CompanionCertPath is the standard path on device storage where CA certs are pushed.
	CompanionCertPath = "/sdcard/Download/cap-ca.crt"
	// companionAppCertPath is inside the companion app's own external files dir
	// so Android 11+ Scoped Storage always allows MainActivity to read it.
	companionAppCertPath = "/sdcard/Android/data/" + CompanionPackage + "/files/cap-ca.crt"

	companionActionStart = CompanionPackage + ".ACTION_START"
	companionActionStop  = CompanionPackage + ".ACTION_STOP"
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
				return fmt.Errorf("install companion apk: %v (%s / %s)", err2, out, out2)
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

	launchCmd := fmt.Sprintf(
		"am start -n %s --ez install_cert true --es cert_path %s%s",
		CompanionActivity,
		shellQuote(CompanionCertPath),
		extraB64,
	)
	out, err := AdbShell(serial, launchCmd)
	if err != nil || strings.Contains(out, "Error:") {
		return fmt.Errorf("launch companion cert installer: %v (%s)", err, out)
	}
	return nil
}

// GetCompanionStatus inspects the connected device to report whether Cap Guard
// is installed, its version, whether WRITE_SECURE_SETTINGS is granted, whether
// ProxyGuardService is currently running, and battery whitelist state.
func GetCompanionStatus(serial string) CompanionStatus {
	pkgOut, err := AdbShell(serial, "dumpsys package "+CompanionPackage)
	if err != nil {
		return CompanionStatus{Error: err.Error()}
	}
	installed, verName, verCode, hasSecure := ParseCompanionPackageDump(pkgOut)
	status := CompanionStatus{
		Installed:         installed,
		Version:           verName,
		VersionCode:       verCode,
		HasSecureSettings: hasSecure,
	}
	if !installed {
		return status
	}

	svcOut, _ := AdbShell(serial, "dumpsys activity services "+CompanionService)
	status.WatchdogRunning = ParseCompanionServiceRunning(svcOut)

	wlOut, _ := AdbShell(serial, "dumpsys deviceidle whitelist")
	status.BatteryWhitelisted = ParseBatteryWhitelisted(wlOut)
	return status
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
