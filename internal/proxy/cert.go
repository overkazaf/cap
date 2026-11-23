package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

// caValidityYears is how long a generated CA certificate remains valid.
const caValidityYears = 10

const (
	// leafValidityDays stays strictly under the 398-day hard limit enforced by
	// Chrome, Apple, and Android 12–15 Conscrypt. Combined with the 24-hour
	// NotBefore skew buffer, total lifetime is 366 days.
	leafValidityDays = 365

	// leafRefreshMargin refreshes cached leaf certs before they get close to
	// expiring on long-running proxy sessions.
	leafRefreshMargin = 24 * time.Hour

	// maxLeafCacheEntries bounds memory usage for cached leaf certificates.
	maxLeafCacheEntries = 2048

	// maxCommonNameLen obeys RFC 5280 ub-common-name (64 octets).
	maxCommonNameLen = 64
)

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

	serial, err := randomSerialNumber()
	if err != nil {
		return "", "", fmt.Errorf("proxy: generate CA serial: %w", err)
	}

	ski, err := computeSubjectKeyID(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("proxy: compute CA subject key id: %w", err)
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
		SubjectKeyId:          ski,
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

type cachedLeaf struct {
	cert      *tls.Certificate
	notAfter  time.Time
	createdAt time.Time
}

type leafCertSigner struct {
	ca      tls.Certificate
	caLeaf  *x509.Certificate
	caAKI   []byte
	leafKey *ecdsa.PrivateKey
	leafSKI []byte

	mu    sync.RWMutex
	cache map[string]cachedLeaf
}

// NewTLSConfigFromCA returns a goproxy TLSConfig factory that signs modern,
// Android 12–15 / Chrome / Apple compliant X.509v3 leaf certificates with a
// bounded thread-safe in-memory cache and full CA certificate chains.
func NewTLSConfigFromCA(ca tls.Certificate) func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	signer, initErr := newLeafCertSigner(ca)
	return func(host string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
		if initErr != nil {
			return nil, initErr
		}
		normHost := normalizeCertHost(host)
		cert, err := signer.certForHost(normHost)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello != nil && hello.ServerName != "" {
					sni := normalizeCertHost(hello.ServerName)
					if sni != "" && sni != normHost {
						return signer.certForHost(sni)
					}
				}
				return cert, nil
			},
		}, nil
	}
}

func newLeafCertSigner(ca tls.Certificate) (*leafCertSigner, error) {
	if len(ca.Certificate) == 0 || ca.PrivateKey == nil {
		return nil, fmt.Errorf("proxy: CA certificate and private key are required")
	}

	caLeaf := ca.Leaf
	if caLeaf == nil {
		parsed, err := x509.ParseCertificate(ca.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("proxy: parse CA certificate: %w", err)
		}
		caLeaf = parsed
	}

	caAKI := caLeaf.SubjectKeyId
	if len(caAKI) == 0 {
		ski, err := computeSubjectKeyID(caLeaf.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("proxy: compute CA authority key id: %w", err)
		}
		caAKI = ski
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxy: generate leaf key: %w", err)
	}
	leafSKI, err := computeSubjectKeyID(&leafKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("proxy: compute leaf subject key id: %w", err)
	}

	return &leafCertSigner{
		ca:      ca,
		caLeaf:  caLeaf,
		caAKI:   caAKI,
		leafKey: leafKey,
		leafSKI: leafSKI,
		cache:   make(map[string]cachedLeaf, 64),
	}, nil
}

func (s *leafCertSigner) certForHost(host string) (*tls.Certificate, error) {
	if host == "" {
		host = "localhost"
	}
	now := time.Now()

	// Fast path: read-lock cache lookup.
	s.mu.RLock()
	if entry, ok := s.cache[host]; ok && now.Add(leafRefreshMargin).Before(entry.notAfter) {
		s.mu.RUnlock()
		return entry.cert, nil
	}
	s.mu.RUnlock()

	// Slow path: double-check under write lock so concurrent handshakes for
	// the same host share one newly minted certificate.
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.cache[host]; ok && now.Add(leafRefreshMargin).Before(entry.notAfter) {
		return entry.cert, nil
	}

	cert, notAfter, err := s.mintLeafCert(host, now)
	if err != nil {
		return nil, err
	}

	if len(s.cache) >= maxLeafCacheEntries {
		s.evictLocked(now)
	}
	s.cache[host] = cachedLeaf{
		cert:      cert,
		notAfter:  notAfter,
		createdAt: now,
	}
	return cert, nil
}

func (s *leafCertSigner) evictLocked(now time.Time) {
	// First drop expired or soon-to-expire entries.
	for k, v := range s.cache {
		if !now.Add(leafRefreshMargin).Before(v.notAfter) {
			delete(s.cache, k)
		}
	}
	if len(s.cache) < maxLeafCacheEntries {
		return
	}
	// Evict oldest entry to stay strictly bounded.
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range s.cache {
		if first || v.createdAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.createdAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(s.cache, oldestKey)
	}
}

func (s *leafCertSigner) mintLeafCert(host string, now time.Time) (*tls.Certificate, time.Time, error) {
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("proxy: generate leaf serial: %w", err)
	}

	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.AddDate(0, 0, leafValidityDays)

	cn := host
	if len(cn) > maxCommonNameLen {
		cn = cn[:maxCommonNameLen]
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"cap"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          s.leafSKI,
		AuthorityKeyId:        s.caAKI,
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.caLeaf, &s.leafKey.PublicKey, s.ca.PrivateKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("proxy: sign leaf cert for %q: %w", host, err)
	}
	leafParsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("proxy: parse signed leaf cert for %q: %w", host, err)
	}

	chain := make([][]byte, 0, 1+len(s.ca.Certificate))
	chain = append(chain, leafDER)
	chain = append(chain, s.ca.Certificate...)

	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  s.leafKey,
		Leaf:        leafParsed,
	}, notAfter, nil
}

// normalizeCertHost strips any ":port", brackets around IPv6 literals,
// trailing FQDN dot, and normalizes DNS hostnames to lowercase.
func normalizeCertHost(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return strings.ToLower(h)
}

// randomSerialNumber returns a strictly positive random 127-bit serial number
// (RFC 5280 §4.1.2.2 requires positive, non-zero serial numbers <= 20 octets).
func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	// Ensure serial is never 0.
	return n.Add(n, big.NewInt(1)), nil
}

// computeSubjectKeyID computes the RFC 5280 §4.2.1.2 SHA-1 key identifier
// over the public key's PKIX DER representation.
func computeSubjectKeyID(pub any) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki)
	return sum[:], nil
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
