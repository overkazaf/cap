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
	if isRooted(serial) {
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
	if _, err := adbCmd(serial, "push", certPath, remotePath); err != nil {
		return fmt.Errorf("push cert: %w", err)
	}

	// Strategy 1: mount --bind (non-persistent, no reboot, works on Android 10+)
	if err := installBindMount(serial, hashName, remotePath); err == nil {
		fmt.Println("CA cert injected via mount --bind (active until reboot)")
		return nil
	}

	// Strategy 2: Magisk module (persistent across reboots)
	if hasMagisk(serial) {
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
	suShell(serial, "rm -f "+remotePath)
	return fmt.Errorf("all root cert install methods failed — try installing manually")
}

// installBindMount copies all existing system certs + ours into a temp dir,
// then bind-mounts it over /system/etc/security/cacerts.
// This is the approach HTTP Toolkit uses on modern Android.
func installBindMount(serial, hashName, remoteCertPath string) error {
	script := fmt.Sprintf(`
set -e
TMPDIR=/data/local/tmp/cap-cacerts
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"
cp /system/etc/security/cacerts/* "$TMPDIR/" 2>/dev/null || true
cp %s "$TMPDIR/%s"
chmod 644 "$TMPDIR"/*
mount --bind "$TMPDIR" /system/etc/security/cacerts
rm -f %s
echo "OK"
`, remoteCertPath, hashName, remoteCertPath)

	out, err := suShell(serial, script)
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

	out, err := suShell(serial, script)
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
		if _, err := suShell(serial, c); err != nil {
			return fmt.Errorf("%s: %w", c, err)
		}
	}
	return nil
}

func hasMagisk(serial string) bool {
	out, _ := suShell(serial, "ls /data/adb/magisk 2>/dev/null && echo YES")
	return strings.Contains(out, "YES")
}

func suShell(serial, cmd string) (string, error) {
	return adbShell(serial, fmt.Sprintf("su -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''")))
}

func installCACertUser(serial, certPath string) error {
	remotePath := "/data/local/tmp/cap-ca.crt"
	if _, err := adbCmd(serial, "push", certPath, remotePath); err != nil {
		return fmt.Errorf("push cert: %w", err)
	}

	intent := fmt.Sprintf(
		"am start -a android.intent.action.VIEW -t application/x-x509-ca-cert -d file://%s",
		remotePath,
	)
	if _, err := adbShell(serial, intent); err != nil {
		_, _ = adbShell(serial, "am start -a android.settings.SECURITY_SETTINGS")
		return fmt.Errorf("cert pushed to %s, install manually from Settings > Security: %w", remotePath, err)
	}
	return nil
}

func isRooted(serial string) bool {
	out, err := adbShell(serial, "su -c id")
	return err == nil && strings.Contains(out, "uid=0")
}
