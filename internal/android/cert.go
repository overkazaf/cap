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
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" || block.Type == "TRUSTED CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	// Fallback for raw DER-encoded X.509 certificate files
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}
	return nil, fmt.Errorf("no valid X.509 certificate found in %s", certPath)
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

// buildRootCertProbeCmd builds a root shell probe that checks:
//   - Android 14+ APEX Conscrypt cacerts in both global and zygote mount namespaces
//   - Magisk staged cap-cert module
//   - User trust stores across all Android users (/data/misc/user/*/cacerts-added)
func buildRootCertProbeCmd(hashName string) string {
	return fmt.Sprintf(
		`[ -f /apex/com.android.conscrypt/cacerts/%s ] && echo APEX; `+
			`for ZP in $(pidof zygote64 zygote 2>/dev/null); do `+
			`nsenter --mount="/proc/$ZP/ns/mnt" -- test -f /apex/com.android.conscrypt/cacerts/%s 2>/dev/null && echo APEX && break; `+
			`done; `+
			`[ -f /data/adb/modules/cap-cert/system/etc/security/cacerts/%s ] && echo MAGISK; `+
			`for UDIR in /data/misc/user/*/cacerts-added; do `+
			`[ -f "$UDIR/%s" ] && echo USER && break; `+
			`done; true`,
		hashName, hashName, hashName, hashName,
	)
}

// CheckCertStatus inspects the device's system, APEX Conscrypt, Magisk module,
// and user trust stores to report accurate CA certificate installation status.
// On Android 14+ (where /apex/com.android.conscrypt/cacerts exists), a cert
// present ONLY in legacy /system/etc/security/cacerts is NOT considered
// installed in the active system trust store.
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
		`[ -d /apex/com.android.conscrypt/cacerts ] && echo HAS_APEX_DIR; `+
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

	// Unprivileged adb shell cannot read /data/adb/modules or /data/misc/user/0/cacerts-added
	// (Permission denied on Android 10–15) and may sit in a separate Magisk mount namespace.
	// Probe via root whenever not yet confirmed installed (including legacy_system_only!).
	status := ParseCertCheckOutput(hashName, out)
	if !status.Installed && IsRooted(serial) {
		suOut, _ := SuShellMountMaster(serial, buildRootCertProbeCmd(hashName))
		if strings.TrimSpace(suOut) != "" {
			status = ParseCertCheckOutput(hashName, out+"\n"+suOut)
		}
	}

	// Zero-root fallback: on non-rooted Android 10–15, adb shell gets Permission denied on
	// /data/misc/user/0/cacerts-added, so ask Cap Guard's CertStatusReceiver to inspect the
	// live AndroidCAStore directly.
	if !status.Installed {
		if compStatus, ok := CheckCertViaCompanion(serial, certPath); ok &&
			(compStatus.Installed || (status.Method == "" && compStatus.Method == "fingerprint_mismatch")) {
			status = compStatus
		}
	}
	return status
}

// ParseCertCheckOutput converts the marker lines emitted by CheckCertStatus's
// shell probe into a structured CertStatus.
func ParseCertCheckOutput(hashName, output string) CertStatus {
	hasApexDir := false
	hasApex := false
	hasSystem := false
	hasUser := false
	hasMagisk := false

	for _, line := range strings.Split(output, "\n") {
		switch strings.TrimSpace(line) {
		case "HAS_APEX_DIR":
			hasApexDir = true
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

	// Android 14+ (APEX Conscrypt trust store active): Conscrypt reads CA certs
	// from /apex/com.android.conscrypt/cacerts, NOT /system/etc/security/cacerts.
	if hasApexDir {
		switch {
		case hasApex:
			return CertStatus{
				Installed: true,
				Store:     "system",
				Hash:      hashName,
				Method:    "apex",
				Details:   "installed in Android 14+ APEX Conscrypt system trust store",
			}
		case hasUser:
			return CertStatus{
				Installed: true,
				Store:     "user",
				Hash:      hashName,
				Method:    "user",
				Details:   "installed in user trust store (missing from Android 14+ APEX Conscrypt)",
			}
		case hasSystem:
			return CertStatus{
				Installed: false,
				Store:     "none",
				Hash:      hashName,
				Method:    "legacy_system_only",
				Details:   "present in legacy /system only — missing from Android 14+ APEX Conscrypt",
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
		default:
			return CertStatus{
				Installed: false,
				Store:     "none",
				Hash:      hashName,
				Details:   "CA certificate not installed in Android 14+ APEX Conscrypt",
			}
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
			_ = SyncCompanionCert(serial, certPath)
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

// BuildBindMountScript builds the root shell script implementing HTTP Toolkit's
// Android 10–16 CA certificate injection algorithm:
//
//  1. Never bind-mounts /data/local/tmp/... directly onto /system or /apex
//     (SELinux Enforcing blocks untrusted apps from reading /data/local/tmp).
//  2. Stages all original system/APEX certs + our cert into a temp staging dir,
//     mounts a real in-memory tmpfs onto /system/etc/security/cacerts, copies
//     all certs in, and applies the exact SELinux label
//     u:object_r:system_security_cacerts_file:s0 (fallback u:object_r:system_file:s0).
//  3. On Android 14+ (where /apex/com.android.conscrypt/cacerts exists):
//     - If APEX cacerts (or versioned @*/cacerts) is already a writable tmpfs,
//       copies our cert directly with system:system ownership, 0644 mode, and
//       u:object_r:system_security_cacerts_file:s0 context.
//     - Propagates the tmpfs mount into every unique mount namespace across
//       init (PID 1), zygote, zygote64, webview_zygote, system_server, and ALL
//       running children whose PPID is any zygote PID (deduplicated by
//       readlink /proc/$PID/ns/mnt).
//     - Verifies the cert is readable inside zygote64/zygote's mount namespace.
func BuildBindMountScript(hashName, remoteCertPath string) string {
	return fmt.Sprintf(`
set -e

HASH=%s
REMOTE_CERT=%s
STAGE=/data/local/tmp/cap-cacerts-stage
APEX_CERTS=/apex/com.android.conscrypt/cacerts
SYSTEM_CERTS=/system/etc/security/cacerts

rm -rf "$STAGE"
mkdir -p "$STAGE"

# --- Stage all original system/APEX certs ---
VERSIONED=$(ls -d /apex/com.android.conscrypt@*/cacerts 2>/dev/null | head -n 1 || true)
if [ -d "$APEX_CERTS" ] && [ "$(ls "$APEX_CERTS" 2>/dev/null | wc -l)" -gt 0 ]; then
    cp "$APEX_CERTS"/* "$STAGE/"
elif [ -n "$VERSIONED" ] && [ "$(ls "$VERSIONED" 2>/dev/null | wc -l)" -gt 0 ]; then
    cp "$VERSIONED"/* "$STAGE/"
elif [ "$(ls "$SYSTEM_CERTS" 2>/dev/null | wc -l)" -gt 0 ]; then
    cp "$SYSTEM_CERTS"/* "$STAGE/"
fi

# Add our CA cert
cp "$REMOTE_CERT" "$STAGE/$HASH"

CERT_COUNT=$(ls "$STAGE" 2>/dev/null | wc -l)
if [ "$CERT_COUNT" -lt 2 ]; then
    echo "FAIL: only $CERT_COUNT cert(s) staged"
    rm -rf "$STAGE"
    exit 1
fi

# --- Mount real in-memory tmpfs over /system/etc/security/cacerts ---
# Never bind-mount /data/local/tmp onto /system or /apex (blocked by SELinux Enforcing).
if grep -q " $SYSTEM_CERTS tmpfs " /proc/mounts 2>/dev/null; then
    umount "$SYSTEM_CERTS" 2>/dev/null || true
fi
mount -t tmpfs tmpfs "$SYSTEM_CERTS"
cp "$STAGE"/* "$SYSTEM_CERTS/"
chown root:root "$SYSTEM_CERTS" 2>/dev/null || true
chown root:root "$SYSTEM_CERTS"/* 2>/dev/null || true
chmod 755 "$SYSTEM_CERTS"
chmod 644 "$SYSTEM_CERTS"/*
chcon u:object_r:system_security_cacerts_file:s0 "$SYSTEM_CERTS" "$SYSTEM_CERTS"/* 2>/dev/null || \
    chcon u:object_r:system_file:s0 "$SYSTEM_CERTS" "$SYSTEM_CERTS"/* 2>/dev/null || true

# --- Android 14+ APEX Conscrypt injection & deduplicated nsenter propagation ---
if [ -d "$APEX_CERTS" ]; then
    # Match APEX ownership (dir root:shell, files system:system) & SELinux context
    chown root:shell "$SYSTEM_CERTS" 2>/dev/null || true
    chown system:system "$SYSTEM_CERTS"/* 2>/dev/null || true
    chcon u:object_r:system_security_cacerts_file:s0 "$SYSTEM_CERTS" "$SYSTEM_CERTS"/* 2>/dev/null || true

    # Fast path: if APEX cacerts (or versioned @*/cacerts) is already a writable tmpfs
    # (e.g. Magisk/Pixel overlay), write our cert directly with exact ownership & SELinux label.
    for ADIR in "$APEX_CERTS" /apex/com.android.conscrypt@*/cacerts; do
        [ ! -d "$ADIR" ] && continue
        if cp "$STAGE/$HASH" "$ADIR/$HASH" 2>/dev/null; then
            chown system:system "$ADIR/$HASH" 2>/dev/null || chown root:root "$ADIR/$HASH" 2>/dev/null || true
            chmod 644 "$ADIR/$HASH" 2>/dev/null || true
            chcon u:object_r:system_security_cacerts_file:s0 "$ADIR/$HASH" 2>/dev/null || \
                chcon u:object_r:system_file:s0 "$ADIR/$HASH" 2>/dev/null || true
        fi
    done

    # Collect zygote PIDs + all child app PIDs whose PPID is any zygote PID
    ZYGOTE_PIDS=""
    for ZNAME in zygote zygote64 webview_zygote; do
        ZP=$(pidof "$ZNAME" 2>/dev/null || true)
        [ -n "$ZP" ] && ZYGOTE_PIDS="$ZYGOTE_PIDS $ZP"
    done

    TARGET_PIDS="1 $ZYGOTE_PIDS $(pidof system_server 2>/dev/null || true)"

    if [ -n "$ZYGOTE_PIDS" ]; then
        for PROC in /proc/[0-9]*; do
            PID=${PROC##*/}
            [ ! -r "$PROC/stat" ] && continue
            STAT=$(cat "$PROC/stat" 2>/dev/null || true)
            [ -z "$STAT" ] && continue
            REST=${STAT##*\) }
            set -- $REST
            PPID_VAL=$2
            case " $ZYGOTE_PIDS " in
                *" $PPID_VAL "*) TARGET_PIDS="$TARGET_PIDS $PID" ;;
            esac
        done
    fi

    # Deduplicate by mount namespace inode so each namespace is entered ONCE
    SEEN_NS=" "
    for PID in $TARGET_PIDS; do
        [ ! -e "/proc/$PID/ns/mnt" ] && continue
        NS=$(readlink "/proc/$PID/ns/mnt" 2>/dev/null || true)
        [ -z "$NS" ] && continue
        case "$SEEN_NS" in
            *" $NS "*) continue ;;
        esac
        SEEN_NS="$SEEN_NS$NS "

        # If this namespace doesn't already see our cert in APEX, bind-mount our tmpfs over APEX
        if ! nsenter --mount="/proc/$PID/ns/mnt" -- test -r "$APEX_CERTS/$HASH" 2>/dev/null; then
            nsenter --mount="/proc/$PID/ns/mnt" -- mount --bind "$SYSTEM_CERTS" "$APEX_CERTS" 2>/dev/null || true
            for VDIR in /apex/com.android.conscrypt@*/cacerts; do
                [ -d "$VDIR" ] && nsenter --mount="/proc/$PID/ns/mnt" -- mount --bind "$SYSTEM_CERTS" "$VDIR" 2>/dev/null || true
            done
        fi
    done

    # Verify cert is readable inside zygote64/zygote mount namespace (or global APEX)
    VERIFIED=0
    for ZPID in $ZYGOTE_PIDS; do
        if nsenter --mount="/proc/$ZPID/ns/mnt" -- test -r "$APEX_CERTS/$HASH" 2>/dev/null; then
            VERIFIED=1
            break
        fi
    done
    if [ "$VERIFIED" -eq 0 ] && [ -r "$APEX_CERTS/$HASH" ]; then
        VERIFIED=1
    fi
    if [ "$VERIFIED" -ne 1 ]; then
        echo "FAIL: cert not visible in APEX/zygote mount namespace"
        rm -rf "$STAGE" "$REMOTE_CERT"
        exit 1
    fi
else
    # Android 10-13 verification
    if [ ! -r "$SYSTEM_CERTS/$HASH" ]; then
        echo "FAIL: cert not visible in $SYSTEM_CERTS"
        rm -rf "$STAGE" "$REMOTE_CERT"
        exit 1
    fi
fi

rm -rf "$STAGE" "$REMOTE_CERT"
am broadcast -a android.security.action.TRUST_STORE_CHANGED >/dev/null 2>&1 || true
echo "OK"
`, shellQuote(hashName), shellQuote(remoteCertPath))
}

func installBindMount(serial, hashName, remoteCertPath string) error {
	script := BuildBindMountScript(hashName, remoteCertPath)
	out, err := SuShellMountMaster(serial, script)
	if err != nil || !strings.Contains(out, "OK") {
		return fmt.Errorf("bind mount failed: %s %v", out, err)
	}
	return nil
}

// installMagiskModule creates a Magisk overlay module that adds the cert
// to the system trust store AND includes an Android 14+ APEX-compatible
// service.sh boot injector. Persistent across reboots (requires one reboot).
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
version=2.0
versionCode=2
author=cap
description=MITM CA certificate for cap proxy (Android 10-16 + APEX Conscrypt)
PROP
cat > "$MODDIR/service.sh" << 'SVC'
#!/system/bin/sh
MODDIR=${0%%/*}
APEX_CERTS=/apex/com.android.conscrypt/cacerts
SYSTEM_CERTS=/system/etc/security/cacerts
[ ! -d "$APEX_CERTS" ] && exit 0
for i in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(ls "$APEX_CERTS" 2>/dev/null | wc -l)" -gt 0 ] && break
    sleep 1
done
STAGE=/data/local/tmp/cap-magisk-stage
rm -rf "$STAGE" && mkdir -p "$STAGE"
cp "$APEX_CERTS"/* "$STAGE/" 2>/dev/null || true
cp "$MODDIR/system/etc/security/cacerts/"* "$STAGE/" 2>/dev/null || true
mount -t tmpfs tmpfs "$SYSTEM_CERTS" 2>/dev/null || true
cp "$STAGE"/* "$SYSTEM_CERTS/" 2>/dev/null || true
chown root:shell "$SYSTEM_CERTS" 2>/dev/null || true
chown system:system "$SYSTEM_CERTS"/* 2>/dev/null || true
chmod 755 "$SYSTEM_CERTS"
chmod 644 "$SYSTEM_CERTS"/* 2>/dev/null || true
chcon u:object_r:system_security_cacerts_file:s0 "$SYSTEM_CERTS" "$SYSTEM_CERTS"/* 2>/dev/null || true
for PID in 1 $(pidof zygote zygote64 webview_zygote system_server 2>/dev/null); do
    nsenter --mount="/proc/$PID/ns/mnt" -- mount --bind "$SYSTEM_CERTS" "$APEX_CERTS" 2>/dev/null || true
done
rm -rf "$STAGE"
am broadcast -a android.security.action.TRUST_STORE_CHANGED >/dev/null 2>&1 || true
SVC
chmod 755 "$MODDIR/service.sh"
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
rm -rf /data/local/tmp/cap-cacerts /data/local/tmp/cap-cacerts-stage
rm -rf /data/adb/modules/cap-cert
`
		if hashName != "" {
			script += fmt.Sprintf("rm -f /data/local/tmp/%s /apex/com.android.conscrypt/cacerts/%s /apex/com.android.conscrypt@*/cacerts/%s 2>/dev/null || true\n", hashName, hashName, hashName)
		}
		script += "echo OK\n"
		if out, err := SuShellMountMaster(serial, script); err != nil || !strings.Contains(out, "OK") {
			return fmt.Errorf("remove root CA cert: %s %v", out, err)
		}
	}

	return nil
}
