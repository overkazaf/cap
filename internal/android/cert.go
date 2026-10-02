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
// expects for a CA certificate dropped directly into
// /system/etc/security/cacerts/: "<hash>.0", where hash is OpenSSL's
// legacy "subject_hash_old" — the first 4 bytes of the MD5 digest of the
// DER-encoded subject name, read as a little-endian uint32 and printed as
// 8 lowercase hex digits. This matches what
//
//	openssl x509 -noout -subject_hash_old -in cert.pem
//
// prints, which is the value Android (via Conscrypt/BoringSSL,
// compatible with pre-1.0.0 OpenSSL c_rehash behavior) uses to name both
// system and user-added trust anchors.
//
// Returns "" if certPath cannot be read or does not contain a valid PEM
// certificate.
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

// subjectHashOld replicates OpenSSL's X509_NAME_hash_old algorithm.
func subjectHashOld(rawSubject []byte) uint32 {
	sum := md5.Sum(rawSubject)
	return binary.LittleEndian.Uint32(sum[:4])
}

// installCACert pushes certPath to the device and installs it into the
// trust store, picking the rooted or non-root flow based on su
// availability.
func installCACert(serial, certPath string) error {
	if isRooted(serial) {
		return installCACertRooted(serial, certPath)
	}
	return installCACertUser(serial, certPath)
}

// installCACertRooted copies the cert into
// /system/etc/security/cacerts/<hash>.0, remounting /system read-write for
// the copy and back to read-only afterward. This makes the cert a fully
// trusted system CA, accepted by apps that reject user-added certs
// (Android 7+ default behavior for apps targeting API 24+).
func installCACertRooted(serial, certPath string) error {
	hashName := CertHashFilename(certPath)
	if hashName == "" {
		return fmt.Errorf("could not compute trust-store hash for %s (not a valid PEM certificate?)", certPath)
	}

	remotePath := "/data/local/tmp/" + hashName
	systemPath := "/system/etc/security/cacerts/" + hashName

	if _, err := adbCmd(serial, "push", certPath, remotePath); err != nil {
		return fmt.Errorf("push cert: %w", err)
	}

	cmds := []string{
		"mount -o remount,rw /system",
		fmt.Sprintf("cp %s %s", remotePath, systemPath),
		fmt.Sprintf("chmod 644 %s", systemPath),
		"mount -o remount,ro /system",
		"rm -f " + remotePath,
	}
	for _, c := range cmds {
		if _, err := adbShell(serial, fmt.Sprintf("su -c '%s'", c)); err != nil {
			return fmt.Errorf("su -c %q: %w", c, err)
		}
	}
	return nil
}

// installCACertUser pushes the cert to a world-readable location and opens
// Android's certificate installer so the user can trust it as a
// user-added CA. If the installer intent can't be started (older/newer
// Android variants expose this differently), falls back to opening
// Security Settings so the cert can be imported manually.
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
		return fmt.Errorf("could not open cert installer automatically (cert pushed to %s, install manually from Settings > Security): %w", remotePath, err)
	}
	return nil
}

// isRooted reports whether `su -c id` succeeds and reports uid=0.
func isRooted(serial string) bool {
	out, err := adbShell(serial, "su -c id")
	return err == nil && strings.Contains(out, "uid=0")
}
