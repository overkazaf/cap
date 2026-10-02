package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// caValidityYears is how long a generated CA certificate remains valid.
const caValidityYears = 10

// EnsureCA returns the paths to an ECDSA P-256 CA certificate and private key
// under dir, generating a fresh 10-year CA (CN="Cap MITM CA") on first use.
// This CA is meant to be installed as a trust anchor (e.g. on an Android
// device via `cap android connect`) so the MITM proxy's dynamically generated
// leaf certificates are trusted.
//
// EnsureCA is idempotent: if both cap-ca.crt and cap-ca.key already exist in
// dir, their paths are returned unchanged without regenerating anything, so
// a previously-installed trust relationship keeps working across restarts.
func EnsureCA(dir string) (certFile, keyFile string, err error) {
	certFile = filepath.Join(dir, "cap-ca.crt")
	keyFile = filepath.Join(dir, "cap-ca.key")

	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("proxy: create cert dir %s: %w", dir, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("proxy: generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("proxy: generate CA serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Cap MITM CA",
			Organization: []string{"cap"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(caValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("proxy: create CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("proxy: marshal CA key: %w", err)
	}

	if err := writePEMFile(certFile, "CERTIFICATE", certDER, 0o644); err != nil {
		return "", "", err
	}
	if err := writePEMFile(keyFile, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func writePEMFile(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("proxy: open %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("proxy: write %s: %w", path, err)
	}
	return nil
}
