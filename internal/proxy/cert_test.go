package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func loadTestCA(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	ca, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	ca.Leaf = leaf

	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("ReadFile CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("failed to append CA PEM to root pool")
	}
	return ca, pool
}

func TestEnsureCAIdempotentAndSubjectKeyId(t *testing.T) {
	dir := t.TempDir()
	cert1, key1, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}
	origCert, err := os.ReadFile(cert1)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	origKey, err := os.ReadFile(key1)
	if err != nil {
		t.Fatalf("read CA key: %v", err)
	}

	ca, err := tls.LoadX509KeyPair(cert1, key1)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	parsed, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !parsed.IsCA || !parsed.BasicConstraintsValid {
		t.Fatalf("CA BasicConstraints invalid: IsCA=%v BasicConstraintsValid=%v", parsed.IsCA, parsed.BasicConstraintsValid)
	}
	if len(parsed.SubjectKeyId) == 0 {
		t.Fatal("expected non-empty SubjectKeyId on newly generated CA")
	}
	if parsed.SerialNumber == nil || parsed.SerialNumber.Sign() <= 0 {
		t.Fatalf("expected positive serial number, got %v", parsed.SerialNumber)
	}

	// Second call must NOT overwrite existing CA files.
	cert2, key2, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}
	if cert2 != cert1 || key2 != key1 {
		t.Fatalf("paths changed: (%s,%s) vs (%s,%s)", cert2, key2, cert1, key1)
	}
	afterCert, _ := os.ReadFile(cert2)
	afterKey, _ := os.ReadFile(key2)
	if !bytes.Equal(origCert, afterCert) || !bytes.Equal(origKey, afterKey) {
		t.Fatal("EnsureCA overwrote existing CA cert/key")
	}
}

func TestLeafCertDNSValidation(t *testing.T) {
	ca, pool := loadTestCA(t)
	factory := NewTLSConfigFromCA(ca)

	cfg, err := factory("api.example.com:443", nil)
	if err != nil {
		t.Fatalf("NewTLSConfigFromCA(api.example.com:443): %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2 (%#x)", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos = %v, want [http/1.1]", cfg.NextProtos)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(cfg.Certificates))
	}
	cert := cfg.Certificates[0]
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf + CA)", len(cert.Certificate))
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// Verify against CA using Go's x509 verifier (mirrors Conscrypt/Chrome checks).
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "api.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf.Verify(api.example.com) failed: %v", err)
	}

	// Strict Chrome / Apple / Android 12–15 validity <= 397 days.
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime > 397*24*time.Hour {
		t.Errorf("leaf validity %v exceeds 397 days", lifetime)
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid {
		t.Errorf("leaf BasicConstraints: IsCA=%v BasicConstraintsValid=%v, want false/true", leaf.IsCA, leaf.BasicConstraintsValid)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("leaf missing KeyUsageDigitalSignature")
	}
	hasServerAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Errorf("leaf missing ExtKeyUsageServerAuth: %v", leaf.ExtKeyUsage)
	}
	if len(leaf.SubjectKeyId) == 0 {
		t.Error("leaf missing SubjectKeyId")
	}
	if !bytes.Equal(leaf.AuthorityKeyId, ca.Leaf.SubjectKeyId) {
		t.Errorf("leaf AuthorityKeyId %x != CA SubjectKeyId %x", leaf.AuthorityKeyId, ca.Leaf.SubjectKeyId)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "api.example.com" {
		t.Errorf("DNSNames = %v, want [api.example.com]", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 0 {
		t.Errorf("unexpected IPAddresses on DNS leaf: %v", leaf.IPAddresses)
	}
}

func TestLeafCertIPValidation(t *testing.T) {
	ca, pool := loadTestCA(t)
	factory := NewTLSConfigFromCA(ca)

	cases := []struct {
		rawHost string
		wantIP  string
	}{
		{"127.0.0.1:443", "127.0.0.1"},
		{"192.168.1.50", "192.168.1.50"},
		{"[::1]:8443", "::1"},
	}

	for _, tc := range cases {
		t.Run(tc.rawHost, func(t *testing.T) {
			cfg, err := factory(tc.rawHost, nil)
			if err != nil {
				t.Fatalf("factory(%q): %v", tc.rawHost, err)
			}
			leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if len(leaf.DNSNames) != 0 {
				t.Errorf("IP leaf must not set DNSNames, got %v", leaf.DNSNames)
			}
			if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP(tc.wantIP)) {
				t.Errorf("IPAddresses = %v, want [%s]", leaf.IPAddresses, tc.wantIP)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:     pool,
				DNSName:   tc.wantIP,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				t.Fatalf("leaf.Verify(%q) failed: %v", tc.wantIP, err)
			}
		})
	}
}

func TestLeafCertLegacyCAWithoutSKI(t *testing.T) {
	// Simulate an older ~/.cap/cap-ca.crt generated without SubjectKeyId.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Legacy Cap CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	ca := tls.Certificate{
		Certificate: [][]byte{caDER},
		PrivateKey:  key,
	}

	pool := x509.NewCertPool()
	pool.AddCert(caParsed)

	factory := NewTLSConfigFromCA(ca)
	cfg, err := factory("legacy-check.example.org:443", nil)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}
	if len(leaf.AuthorityKeyId) == 0 {
		t.Fatal("expected computed AuthorityKeyId even when CA lacks SubjectKeyId")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "legacy-check.example.org",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf.Verify against legacy CA failed: %v", err)
	}
}

func TestLeafCertCacheHitConcurrencyAndSNI(t *testing.T) {
	ca, pool := loadTestCA(t)
	factory := NewTLSConfigFromCA(ca)

	cfg1, err := factory("Cache.Example.COM:443", nil)
	if err != nil {
		t.Fatalf("first factory call: %v", err)
	}
	cfg2, err := factory("cache.example.com:8443", nil)
	if err != nil {
		t.Fatalf("second factory call: %v", err)
	}
	if !bytes.Equal(cfg1.Certificates[0].Certificate[0], cfg2.Certificates[0].Certificate[0]) {
		t.Fatal("expected normalized host cache hit to return identical leaf DER")
	}

	// Long hostname (> 64 bytes) must truncate CN <= 64 while preserving full SAN.
	longHost := "a1234567890.b1234567890.c1234567890.d1234567890.e1234567890.example.com"
	cfgLong, err := factory(longHost+":443", nil)
	if err != nil {
		t.Fatalf("factory(longHost): %v", err)
	}
	longLeaf, _ := x509.ParseCertificate(cfgLong.Certificates[0].Certificate[0])
	if len(longLeaf.Subject.CommonName) > maxCommonNameLen {
		t.Errorf("CommonName length %d exceeds %d", len(longLeaf.Subject.CommonName), maxCommonNameLen)
	}
	if _, err := longLeaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: longHost}); err != nil {
		t.Fatalf("longHost leaf.Verify failed: %v", err)
	}

	// SNI override when CONNECT target is an IP (e.g. transparent redirect).
	cfgIP, err := factory("10.0.0.1:443", nil)
	if err != nil {
		t.Fatalf("factory(IP): %v", err)
	}
	sniCert, err := cfgIP.GetCertificate(&tls.ClientHelloInfo{ServerName: "sni.example.net"})
	if err != nil {
		t.Fatalf("GetCertificate(SNI): %v", err)
	}
	sniLeaf, _ := x509.ParseCertificate(sniCert.Certificate[0])
	if _, err := sniLeaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "sni.example.net"}); err != nil {
		t.Fatalf("SNI leaf.Verify failed: %v", err)
	}

	// Concurrent cache stress under -race.
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			host := "concurrent.example.com:443"
			if id%2 == 1 {
				host = "other.example.com:443"
			}
			c, err := factory(host, nil)
			if err != nil {
				t.Errorf("concurrent factory(%s): %v", host, err)
				return
			}
			if len(c.Certificates) == 0 || len(c.Certificates[0].Certificate) != 2 {
				t.Errorf("unexpected cert chain for %s", host)
			}
		}(i)
	}
	wg.Wait()
}
