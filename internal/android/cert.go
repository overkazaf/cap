package android

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// CertHashFilename computes the filename Android's native trust store
// expects: "<hash>.0", where hash is OpenSSL's legacy "subject_hash_old".
func CertHashFilename(certPath string) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%08x.0", subjectHashOld(cert.RawSubject))
}

func subjectHashOld(rawSubject []byte) uint32 {
	sum := md5.Sum(rawSubject)
	return binary.LittleEndian.Uint32(sum[:4])
}

func installCACert(serial, certPath string) error {
	if IsRooted(serial) {
		return installCACertRooted(serial, certPath)
	}
	return installCACertUser(serial, certPath)
}

// installCACertRooted tries 3 strategies in order:
//  1. mount --bind (HTTP Toolkit style, works on Android 10+ system-as-root)
//  2. Magisk module (persistent, requires reboot)
//  3. Legacy remount /system (Android 9 and below)
func installCACertRooted(serial, certPath string) error {
	hashName := CertHashFilename(certPath)
	if hashName == "" {
		return fmt.Errorf("could not compute trust-store hash for %s", certPath)
	}

	remotePath := "/data/local/tmp/" + hashName
	if _, err := AdbCmd(serial, "push", certPath, remotePath); err != nil {
		return fmt.Errorf("push cert: %w", err)
	}

	// Strategy 1: mount --bind (non-persistent, no reboot, works on Android 10+)
	if err := installBindMount(serial, hashName, remotePath); err == nil {
		fmt.Println("CA cert injected via mount --bind (active until reboot)")
		return nil
	}

	// Strategy 2: Magisk module (persistent across reboots)
	if HasMagisk(serial) {
		if err := installMagiskModule(serial, hashName, remotePath); err == nil {
			fmt.Println("CA cert installed as Magisk module (reboot to activate)")
			return nil
		}
	}

	// Strategy 3: Legacy remount (Android 9 and below)
	if err := installLegacyRemount(serial, hashName, remotePath); err == nil {
		fmt.Println("CA cert installed via /system remount")
		return nil
	}

	// cleanup
	SuShell(serial, "rm -f "+remotePath)
	return fmt.Errorf("all root cert install methods failed — try installing manually")
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

func installCACertUser(serial, certPath string) error {
	remotePath := "/data/local/tmp/cap-ca.crt"
	if _, err := AdbCmd(serial, "push", certPath, remotePath); err != nil {
		return fmt.Errorf("push cert: %w", err)
	}

	intent := fmt.Sprintf(
		"am start -a android.intent.action.VIEW -t application/x-x509-ca-cert -d file://%s",
		remotePath,
	)
	if _, err := AdbShell(serial, intent); err != nil {
		_, _ = AdbShell(serial, "am start -a android.settings.SECURITY_SETTINGS")
		return fmt.Errorf("cert pushed to %s, install manually from Settings > Security: %w", remotePath, err)
	}
	return nil
}

