package android

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// CertStatus describes where (if anywhere) cap's CA certificate is installed
// on an Android device.
type CertStatus struct {
	Installed   bool   `json:"installed"`
	Store       string `json:"store"`                  // "system", "user", "none"
	Hash        string `json:"hash"`                   // "<hash>.0"
	Method      string `json:"method,omitempty"`       // "apex", "system", "magisk", "user"
	NeedsReboot bool   `json:"needs_reboot"`           // true when installed via Magisk awaiting reboot
	Details     string `json:"details,omitempty"`      // human-readable diagnostic
}

// CertInstallResult describes the outcome of InstallCACert.
type CertInstallResult struct {
	Success     bool   `json:"success"`
	Store       string `json:"store"`        // "system", "user", "none"
	Method      string `json:"method"`       // "already_installed", "bind_mount", "magisk", "legacy_remount", "companion_keychain", "system_intent"
	Hash        string `json:"hash"`         // "<hash>.0"
	NeedsReboot bool   `json:"needs_reboot"` // true for Magisk module installation
	NeedsManual bool   `json:"needs_manual"` // true when user must confirm on device screen
	Message     string `json:"message"`
}

func parseCertFile(certPath string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", certPath)
	}
	return x509.ParseCertificate(block.Bytes)
}

// CertHashFilename computes the filename Android's native trust store
// expects: "<hash>.0", where hash is OpenSSL's legacy "subject_hash_old".
func CertHashFilename(certPath string) string {
	cert, err := parseCertFile(certPath)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%08x.0", subjectHashOld(cert.RawSubject))
}

// CertSHA256Fingerprint returns the uppercase colon-separated SHA-256
// fingerprint of the PEM certificate at certPath, or "" on error.
func CertSHA256Fingerprint(certPath string) string {
	cert, err := parseCertFile(certPath)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// CertSubject returns the certificate Subject CommonName (or full Subject),
// or "" on error.
func CertSubject(certPath string) string {
	cert, err := parseCertFile(certPath)
	if err != nil {
		return ""
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

func subjectHashOld(rawSubject []byte) uint32 {
	sum := md5.Sum(rawSubject)
	return binary.LittleEndian.Uint32(sum[:4])
}

// CheckCertStatus inspects the device's system, APEX Conscrypt, Magisk module,
// and user trust stores to report accurate CA certificate installation status.
func CheckCertStatus(serial, certPath string) CertStatus {
	hashName := CertHashFilename(certPath)
	if hashName == "" {
		return CertStatus{
			Installed: false,
			Store:     "none",
			Details:   "local CA certificate file not found or invalid",
		}
	}

	probeCmd := fmt.Sprintf(
		`[ -f /apex/com.android.conscrypt/cacerts/%s ] && echo APEX; `+
			`[ -f /system/etc/security/cacerts/%s ] && echo SYSTEM; `+
			`[ -f /data/misc/user/0/cacerts-added/%s ] && echo USER; `+
			`[ -f /data/adb/modules/cap-cert/system/etc/security/cacerts/%s ] && echo MAGISK; `+
			`true`,
		hashName, hashName, hashName, hashName,
	)
	out, err := AdbShell(serial, probeCmd)
	if err != nil && out == "" {
		return CertStatus{
			Installed: false,
			Store:     "none",
			Hash:      hashName,
			Details:   fmt.Sprintf("check failed: %v", err),
		}
	}

	// /data/adb/modules is root-only on Magisk; probe via su only if not already in system/apex
	status := ParseCertCheckOutput(hashName, out)
	if !status.Installed && status.Method == "" && IsRooted(serial) {
		suOut, _ := SuShell(serial, fmt.Sprintf(
			`[ -f /data/adb/modules/cap-cert/system/etc/security/cacerts/%s ] && echo MAGISK; `+
				`[ -f /data/misc/user/0/cacerts-added/%s ] && echo USER; true`,
			hashName, hashName,
		))
		if suOut != "" {
			status = ParseCertCheckOutput(hashName, out+"\n"+suOut)
		}
	}
	return status
}

// ParseCertCheckOutput converts the marker lines emitted by CheckCertStatus's
// shell probe into a structured CertStatus.
func ParseCertCheckOutput(hashName, output string) CertStatus {
	hasApex := false
	hasSystem := false
	hasUser := false
	hasMagisk := false

	for _, line := range strings.Split(output, "\n") {
		switch strings.TrimSpace(line) {
		case "APEX":
			hasApex = true
		case "SYSTEM":
			hasSystem = true
		case "USER":
			hasUser = true
		case "MAGISK":
			hasMagisk = true
		}
	}

	switch {
	case hasApex:
		return CertStatus{
			Installed: true,
			Store:     "system",
			Hash:      hashName,
			Method:    "apex",
			Details:   "installed in APEX Conscrypt system trust store",
		}
	case hasSystem:
		return CertStatus{
			Installed: true,
			Store:     "system",
			Hash:      hashName,
			Method:    "system",
			Details:   "installed in /system/etc/security/cacerts",
		}
	case hasMagisk:
		return CertStatus{
			Installed:   false,
			Store:       "system",
			Hash:        hashName,
			Method:      "magisk",
			NeedsReboot: true,
			Details:     "Magisk module staged — reboot device to activate",
		}
	case hasUser:
		return CertStatus{
			Installed: true,
			Store:     "user",
			Hash:      hashName,
			Method:    "user",
			Details:   "installed in user trust store",
		}
	default:
		return CertStatus{
			Installed: false,
			Store:     "none",
			Hash:      hashName,
			Details:   "CA certificate not installed on device",
		}
	}
}

// InstallCACert installs cap's CA certificate on the device using the best
// available method for rooted or non-rooted devices, verifying visibility and
// returning a structured CertInstallResult.
func InstallCACert(serial, certPath string) (CertInstallResult, error) {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return CertInstallResult{}, err
	}
	serial = resolved

	hashName := CertHashFilename(certPath)
	if hashName == "" {
		return CertInstallResult{}, fmt.Errorf("could not compute trust-store hash for %s", certPath)
	}

	// Short-circuit if already trusted in system store
	existing := CheckCertStatus(serial, certPath)
	if existing.Installed && existing.Store == "system" {
		return CertInstallResult{
			Success: true,
			Store:   "system",
			Method:  "already_installed",
			Hash:    hashName,
			Message: "CA certificate already installed in system trust store",
		}, nil
	}

	if IsRooted(serial) {
		return installCACertRootedDetailed(serial, certPath, hashName)
	}
	return installCACertUserDetailed(serial, certPath, hashName)
}

func installCACert(serial, certPath string) error {
	_, err := InstallCACert(serial, certPath)
	return err
}

// installCACertRootedDetailed tries 3 strategies in order:
//  1. mount --bind (HTTP Toolkit style, works on Android 10+ system-as-root) + visibility verification
//  2. Magisk module (persistent, requires reboot)
//  3. Legacy remount /system (Android 9 and below) + visibility verification
func installCACertRootedDetailed(serial, certPath, hashName string) (CertInstallResult, error) {
	remotePath := "/data/local/tmp/" + hashName
	if _, err := AdbCmd(serial, "push", certPath, remotePath); err != nil {
		return CertInstallResult{Hash: hashName, Store: "none"}, fmt.Errorf("push cert: %w", err)
	}

	// Strategy 1: mount --bind (non-persistent, no reboot, works on Android 10+)
	if err := installBindMount(serial, hashName, remotePath); err == nil {
		verified := CheckCertStatus(serial, certPath)
		if verified.Installed && verified.Store == "system" {
			fmt.Println("CA cert injected via mount --bind (active until reboot)")
			return CertInstallResult{
				Success: true,
				Store:   "system",
				Method:  "bind_mount",
				Hash:    hashName,
				Message: "CA certificate injected into system trust store via mount --bind (active immediately)",
			}, nil
		}
		// Re-push remotePath if bind-mount cleaned it up before verification failed
		_, _ = AdbCmd(serial, "push", certPath, remotePath)
	}

	// Strategy 2: Magisk module (persistent across reboots)
	if HasMagisk(serial) {
		if err := installMagiskModule(serial, hashName, remotePath); err == nil {
			fmt.Println("CA cert installed as Magisk module (reboot to activate)")
			return CertInstallResult{
				Success:     true,
				Store:       "system",
				Method:      "magisk",
				Hash:        hashName,
				NeedsReboot: true,
				Message:     "CA certificate installed as Magisk module (reboot device to activate)",
			}, nil
		}
	}

	// Strategy 3: Legacy remount (Android 9 and below)
	if err := installLegacyRemount(serial, hashName, remotePath); err == nil {
		verified := CheckCertStatus(serial, certPath)
		if verified.Installed && verified.Store == "system" {
			fmt.Println("CA cert installed via /system remount")
			return CertInstallResult{
				Success: true,
				Store:   "system",
				Method:  "legacy_remount",
				Hash:    hashName,
				Message: "CA certificate installed via /system remount",
			}, nil
		}
	}

	// cleanup
	_, _ = SuShell(serial, "rm -f "+remotePath)
	return CertInstallResult{Hash: hashName, Store: "none"}, fmt.Errorf("all root cert install methods failed — try installing manually")
}

// installBindMount injects a CA certificate into the system trust store
// without rebooting, using the same approach as HTTP Toolkit:
//
//  1. Clean up any stale cap bind mounts from previous runs.
//  2. Build a temp dir with all existing system certs + ours. On Android
//     14+ the originals live under the versioned APEX path
//     (/apex/com.android.conscrypt@<ver>/cacerts/), because the
//     non-versioned path may be covered by tmpfs overlays.
//  3. Bind-mount the temp dir over every cert dir in init's namespace
//     (via Magisk's su --mount-master).
//  4. Use nsenter to inject the mount into Zygote's namespace (so new
//     apps inherit it) and every already-running app process.
func installBindMount(serial, hashName, remoteCertPath string) error {
	script := fmt.Sprintf(`
set -e

TMPDIR=/data/local/tmp/cap-cacerts
APEX_CERTS=/apex/com.android.conscrypt/cacerts
SYSTEM_CERTS=/system/etc/security/cacerts

# --- Clean up stale cap mounts from previous runs ---
for TARGET in "$SYSTEM_CERTS" "$APEX_CERTS"; do
    umount "$TARGET" 2>/dev/null || true
    umount "$TARGET" 2>/dev/null || true
done
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

# --- Find original system certs ---
# On Android 14+ the versioned APEX path has the originals;
# the non-versioned path may be covered by tmpfs.
VERSIONED=$(ls -d /apex/com.android.conscrypt@*/cacerts 2>/dev/null | head -1)
if [ -n "$VERSIONED" ] && [ "$(ls "$VERSIONED" 2>/dev/null | wc -l)" -gt 0 ]; then
    cp "$VERSIONED"/* "$TMPDIR/"
elif [ "$(ls "$SYSTEM_CERTS" 2>/dev/null | wc -l)" -gt 0 ]; then
    cp "$SYSTEM_CERTS"/* "$TMPDIR/"
elif [ "$(ls "$APEX_CERTS" 2>/dev/null | wc -l)" -gt 0 ]; then
    cp "$APEX_CERTS"/* "$TMPDIR/"
fi

# Add our cert
cp %s "$TMPDIR/%s"
chmod 644 "$TMPDIR"/*
chcon u:object_r:system_file:s0 "$TMPDIR"/* 2>/dev/null || true

CERT_COUNT=$(ls "$TMPDIR" | wc -l)
[ "$CERT_COUNT" -lt 2 ] && echo "FAIL: only $CERT_COUNT cert(s)" && exit 1

# --- Bind-mount into init namespace ---
nsenter --mount=/proc/1/ns/mnt -- mount --bind "$TMPDIR" "$SYSTEM_CERTS"
if [ -d "$APEX_CERTS" ]; then
    nsenter --mount=/proc/1/ns/mnt -- mount --bind "$TMPDIR" "$APEX_CERTS" 2>/dev/null || true
fi

# --- Inject into Zygote so new apps inherit the mount ---
for ZNAME in zygote zygote64; do
    ZPID=$(pidof "$ZNAME" 2>/dev/null || true)
    [ -z "$ZPID" ] && continue
    nsenter --mount=/proc/$ZPID/ns/mnt -- mount --bind "$TMPDIR" "$SYSTEM_CERTS" 2>/dev/null || true
    if [ -d "$APEX_CERTS" ]; then
        nsenter --mount=/proc/$ZPID/ns/mnt -- mount --bind "$TMPDIR" "$APEX_CERTS" 2>/dev/null || true
    fi
done

# --- Inject into already-running app processes ---
for PID in /proc/[0-9]*; do
    PID=${PID##*/}
    [ ! -f "/proc/$PID/cmdline" ] && continue
    CMD=$(cat /proc/$PID/cmdline 2>/dev/null | tr '\0' '\n' | head -1 || true)
    case "$CMD" in com.*|org.*|net.*|io.*|cn.*|tv.*)
        nsenter --mount=/proc/$PID/ns/mnt -- mount --bind "$TMPDIR" "$SYSTEM_CERTS" 2>/dev/null || true
        if [ -d "$APEX_CERTS" ]; then
            nsenter --mount=/proc/$PID/ns/mnt -- mount --bind "$TMPDIR" "$APEX_CERTS" 2>/dev/null || true
        fi
    ;; esac
done

rm -f %s
echo "OK"
`, remoteCertPath, hashName, remoteCertPath)

	out, err := SuShellMountMaster(serial, script)
	if err != nil || !strings.Contains(out, "OK") {
		return fmt.Errorf("bind mount failed: %s %v", out, err)
	}
	return nil
}

// installMagiskModule creates a Magisk overlay module that adds the cert
// to the system trust store. Persistent across reboots but requires one reboot.
func installMagiskModule(serial, hashName, remoteCertPath string) error {
	script := fmt.Sprintf(`
set -e
MODDIR=/data/adb/modules/cap-cert
mkdir -p "$MODDIR/system/etc/security/cacerts"
cp %s "$MODDIR/system/etc/security/cacerts/%s"
chmod 644 "$MODDIR/system/etc/security/cacerts/%s"
cat > "$MODDIR/module.prop" << 'PROP'
id=cap-cert
name=Cap CA Certificate
version=1.0
versionCode=1
author=cap
description=MITM CA certificate for cap proxy
PROP
rm -f %s
echo "OK"
`, remoteCertPath, hashName, hashName, remoteCertPath)

	out, err := SuShell(serial, script)
	if err != nil || !strings.Contains(out, "OK") {
		return fmt.Errorf("magisk module failed: %s %v", out, err)
	}
	return nil
}

// installLegacyRemount uses the old remount approach for Android 9 and below.
func installLegacyRemount(serial, hashName, remoteCertPath string) error {
	systemPath := "/system/etc/security/cacerts/" + hashName
	cmds := []string{
		"mount -o remount,rw /system",
		fmt.Sprintf("cp %s %s", remoteCertPath, systemPath),
		fmt.Sprintf("chmod 644 %s", systemPath),
		"mount -o remount,ro /system",
		"rm -f " + remoteCertPath,
	}
	for _, c := range cmds {
		if _, err := SuShell(serial, c); err != nil {
			return fmt.Errorf("%s: %w", c, err)
		}
	}
	return nil
}

// installCACertUserDetailed handles non-rooted devices by pushing the CA cert
// to /sdcard/Download/cap-ca.crt and opening the Cap Guard KeyChain installer
// (falling back to Android's credentials/security intent).
func installCACertUserDetailed(serial, certPath, hashName string) (CertInstallResult, error) {
	// Preferred path: push to /sdcard/Download/cap-ca.crt and launch Cap Guard KeyChain prompt
	if err := TriggerCompanionCertInstall(serial, certPath); err == nil {
		return CertInstallResult{
			Success:     true,
			Store:       "user",
			Method:      "companion_keychain",
			Hash:        hashName,
			NeedsManual: true,
			Message:     "CA cert pushed to /sdcard/Download/cap-ca.crt and KeyChain installer opened on device; tap OK to install",
		}, nil
	}

	// Fallback: ensure cert is pushed to /sdcard/Download/cap-ca.crt and launch system installer
	if _, err := AdbCmd(serial, "push", certPath, CompanionCertPath); err != nil {
		return CertInstallResult{Hash: hashName, Store: "none"}, fmt.Errorf("push cert: %w", err)
	}

	if out, err := AdbShell(serial, "am start -a android.credentials.INSTALL"); err == nil && !strings.Contains(out, "Error:") {
		return CertInstallResult{
			Success:     true,
			Store:       "user",
			Method:      "system_intent",
			Hash:        hashName,
			NeedsManual: true,
			Message:     "CA cert pushed to /sdcard/Download/cap-ca.crt; select it in the system certificate installer",
		}, nil
	}

	_, _ = AdbShell(serial, "am start -a android.settings.SECURITY_SETTINGS")
	return CertInstallResult{
		Success:     true,
		Store:       "user",
		Method:      "system_intent",
		Hash:        hashName,
		NeedsManual: true,
		Message:     "CA cert pushed to /sdcard/Download/cap-ca.crt; install manually via Settings > Security > Encryption & credentials > Install a certificate > CA certificate",
	}, nil
}

// RemoveCACert cleans up bind-mounted or Magisk-staged CA certs on rooted
// devices and removes pushed cert files from temporary/download storage.
func RemoveCACert(serial, certPath string) error {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}
	serial = resolved

	_, _ = AdbShell(serial, "rm -f "+CompanionCertPath+" /data/local/tmp/cap-ca.crt")

	if IsRooted(serial) {
		hashName := ""
		if certPath != "" {
			hashName = CertHashFilename(certPath)
		}
		script := `
APEX_CERTS=/apex/com.android.conscrypt/cacerts
SYSTEM_CERTS=/system/etc/security/cacerts
for TARGET in "$SYSTEM_CERTS" "$APEX_CERTS"; do
    umount "$TARGET" 2>/dev/null || true
    umount "$TARGET" 2>/dev/null || true
done
rm -rf /data/local/tmp/cap-cacerts
rm -rf /data/adb/modules/cap-cert
`
		if hashName != "" {
			script += fmt.Sprintf("rm -f /data/local/tmp/%s\n", hashName)
		}
		script += "echo OK\n"
		if out, err := SuShellMountMaster(serial, script); err != nil || !strings.Contains(out, "OK") {
			return fmt.Errorf("remove root CA cert: %s %v", out, err)
		}
	}

	return nil
}
