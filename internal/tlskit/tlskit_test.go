package tlskit

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
)

// --- Synthetic X.509 certificate helpers ---

type testCertBundle struct {
	cert    *x509.Certificate
	der     []byte
	certPEM []byte
	keyPEM  []byte
	key     any
}

func generateTestCA(t *testing.T, cn string) testCertBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Cap Test CA"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	return testCertBundle{
		cert:    parsed,
		der:     der,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		key:     key,
	}
}

func generateSignedTestCert(
	t *testing.T,
	ca testCertBundle,
	cn string,
	serial int64,
	notBefore, notAfter time.Time,
	dnsNames []string,
	ips []net.IP,
	eku []x509.ExtKeyUsage,
	useRSA bool,
) testCertBundle {
	t.Helper()

	var pub any
	var key any
	var keyPEM []byte
	if useRSA {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		pub = &rk.PublicKey
		key = rk
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rk),
		})
	} else {
		ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ECDSA key: %v", err)
		}
		pub = &ek.PublicKey
		key = ek
		kder, err := x509.MarshalECPrivateKey(ek)
		if err != nil {
			t.Fatalf("marshal ECDSA key: %v", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Cap Test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}

	parent := ca.cert
	signer := ca.key
	if parent == nil {
		parent = tmpl
		signer = key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("create signed cert %q: %v", cn, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse signed cert %q: %v", cn, err)
	}
	return testCertBundle{
		cert:    parsed,
		der:     der,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  keyPEM,
		key:     key,
	}
}

func assertValidJSSyntax(t *testing.T, label, code string) {
	t.Helper()
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required for JS syntax verification: %v", err)
	}
	scriptPath := filepath.Join(t.TempDir(), label+".js")
	if err := os.WriteFile(scriptPath, []byte(code), 0o600); err != nil {
		t.Fatalf("write temp script %s: %v", label, err)
	}
	cmd := exec.Command(nodePath, "--check", scriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node --check failed for %s: %v\noutput:\n%s\ncode:\n%s", label, err, string(out), code)
	}
}

// --- 1. Compat JS Generators & Adversarial Sanitization ---

func TestCompatScriptGeneratorsNodeCheck(t *testing.T) {
	flutter := GenerateFlutterProxyDebugScript(FlutterDebugOptions{
		PackageName:           "com.example.flutterapp",
		Platform:              "android",
		ProxyHost:             "127.0.0.1",
		ProxyPort:             8888,
		OffsetHex:             "0x5a1230",
		ForceAllowLocalVerify: true,
	})
	if flutter.Kind != "flutter_proxy_debug" {
		t.Fatalf("unexpected flutter kind: %q", flutter.Kind)
	}
	if !strings.Contains(flutter.Code, "libflutter.so") || !strings.Contains(flutter.Code, "0x5a1230") {
		t.Fatalf("flutter script missing expected module/offset")
	}
	assertValidJSSyntax(t, "flutter_offset", flutter.Code)

	flutterIOS := GenerateFlutterProxyDebugScript(FlutterDebugOptions{
		PackageName:  "com.example.iosflutter",
		Platform:     "ios",
		VerifySymbol: "ssl_verify_peer_cert",
	})
	if !strings.Contains(flutterIOS.Code, `"Flutter"`) || !strings.Contains(flutterIOS.Code, "ssl_verify_peer_cert") {
		t.Fatalf("flutter iOS script missing Flutter module or symbol")
	}
	assertValidJSSyntax(t, "flutter_ios_symbol", flutterIOS.Code)

	cronet := GenerateCronetHTTP2Script(CronetOptions{
		PackageName: "com.example.cronetapp",
		ProxyHint:   "127.0.0.1:8080",
	})
	if cronet.Kind != "cronet_http2" {
		t.Fatalf("unexpected cronet kind: %q", cronet.Kind)
	}
	for _, want := range []string{
		"org.chromium.net.CronetEngine$Builder",
		"enableQuic(false)",
		"Builder.build",
		"cronet_build_applied",
		"okhttp3.OkHttpClient$Builder",
		"HTTP_2",
		"HTTP_1_1",
		"alt-svc",
		"send(",
	} {
		if !strings.Contains(cronet.Code, want) {
			t.Errorf("cronet script missing %q", want)
		}
	}
	assertValidJSSyntax(t, "cronet_http2", cronet.Code)

	mtlsObs := GenerateMTLSObserverScript(MTLSObserverOptions{
		PackageName: "com.example.mtlsapp",
	})
	if mtlsObs.Kind != "mtls_observer" {
		t.Fatalf("unexpected mtls observer kind: %q", mtlsObs.Kind)
	}
	for _, want := range []string{
		"java.security.KeyStore",
		"javax.net.ssl.KeyManagerFactory",
		"javax.net.ssl.SSLContext",
		"getSubjectX500Principal",
		"getIssuerX500Principal",
		"getSerialNumber",
		"send(",
	} {
		if !strings.Contains(mtlsObs.Code, want) {
			t.Errorf("mtls observer script missing %q", want)
		}
	}
	// Security invariant: NEVER dump private keys or plaintext passwords.
	for _, forbidden := range []string{
		"getPrivateKey",
		".getKey(",
		".getEncoded(",
		"String.valueOf(secretChars",
		"secretChars.join",
	} {
		if strings.Contains(mtlsObs.Code, forbidden) {
			t.Errorf("mtls observer script must NOT contain %q", forbidden)
		}
	}
	assertValidJSSyntax(t, "mtls_observer", mtlsObs.Code)
}

func TestCompatScriptAdversarialSanitization(t *testing.T) {
	payload := "com.evil\n*/; globalThis.__PWNED__ = 1; //\r\n\"\u0085\u009f\u2028\u2029\u202e\u2066\u200f</script>'`\\"
	forbiddenRunes := []rune{'\u0085', '\u009f', '\u2028', '\u2029', '\u202e', '\u2066', '\u200f'}

	flutter := GenerateFlutterProxyDebugScript(FlutterDebugOptions{
		PackageName:  payload,
		ModuleName:   "libflutter.so\"; evil();//\n\u0085\u202e",
		ProxyHost:    "127.0.0.1'; process.exit(1);//\u2028\u202e",
		ProxyPort:    -99,
		OffsetHex:    "0x1234); evil(); //",
		VerifySymbol: "sym\n*/); evil();//\"`\u0085\u202e",
	})
	assertValidJSSyntax(t, "flutter_adversarial", flutter.Code)
	if len(flutter.Warnings) == 0 {
		t.Errorf("expected warning for invalid adversarial OffsetHex")
	}
	if !strings.Contains(flutter.Code, "offsetHex: null") {
		t.Errorf("invalid OffsetHex should fall back to null, got:\n%s", flutter.Code)
	}
	if strings.Contains(flutter.Code, "</script>") {
		t.Errorf("raw </script> tag should be escaped in generated JS")
	}
	for _, r := range forbiddenRunes {
		if strings.ContainsRune(flutter.Code, r) {
			t.Errorf("flutter script contains raw forbidden rune U+%04X", r)
		}
	}
	// Ensure no comment line broke into an uncommented globalThis.__PWNED__ statement.
	for _, line := range strings.Split(flutter.Code, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "*/;") || strings.HasPrefix(trimmed, "globalThis.__PWNED__") {
			t.Fatalf("comment breakout detected on line: %q", line)
		}
	}

	cronet := GenerateCronetHTTP2Script(CronetOptions{
		PackageName: payload,
		ProxyHint:   payload,
	})
	assertValidJSSyntax(t, "cronet_adversarial", cronet.Code)
	for _, r := range forbiddenRunes {
		if strings.ContainsRune(cronet.Code, r) {
			t.Errorf("cronet script contains raw forbidden rune U+%04X", r)
		}
	}

	mtlsObs := GenerateMTLSObserverScript(MTLSObserverOptions{
		PackageName:        payload,
		MaxAliasesPerStore: 999999,
	})
	assertValidJSSyntax(t, "mtls_adversarial", mtlsObs.Code)
	for _, r := range forbiddenRunes {
		if strings.ContainsRune(mtlsObs.Code, r) {
			t.Errorf("mtls observer script contains raw forbidden rune U+%04X", r)
		}
	}
	if !strings.Contains(mtlsObs.Code, "maxAliasesPerStore: 256") {
		t.Errorf("expected maxAliasesPerStore to clamp to 256")
	}
}

// --- 2. Synthetic APK Certificate, Keystore, and Network Security Config Scan ---

func TestScanAPKForCertificates(t *testing.T) {
	now := time.Now().UTC()
	ca := generateTestCA(t, "Cap Embedded Test Root CA")
	leafPEM := generateSignedTestCert(
		t, ca, "api.example.com", 0x2A4B,
		now.Add(-time.Hour), now.Add(48*time.Hour),
		[]string{"api.example.com", "cdn.example.com"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		false,
	)
	expiredDER := generateSignedTestCert(
		t, testCertBundle{}, "legacy.example.com", 0x99F1,
		now.Add(-72*time.Hour), now.Add(-24*time.Hour),
		[]string{"legacy.example.com"},
		nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		true,
	)

	spkiHash := sha256.Sum256(leafPEM.cert.RawSubjectPublicKeyInfo)
	expectedPin := base64.StdEncoding.EncodeToString(spkiHash[:])
	backupPin := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

	nscXML := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="@raw/embedded_ca" />
    </trust-anchors>
  </base-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <domain includeSubdomains="false">auth.example.com</domain>
    <pin-set expiration="2028-01-01">
      <pin digest="SHA-256">` + expectedPin + `</pin>
      <pin digest="SHA-256">` + backupPin + `</pin>
    </pin-set>
  </domain-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>`

	apkPath := filepath.Join(t.TempDir(), "synthetic-test.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create synthetic apk: %v", err)
	}
	zw := zip.NewWriter(f)

	writeEntry := func(name string, content []byte) {
		t.Helper()
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}

	// Combined PEM bundle (leaf + CA)
	writeEntry("assets/certs/bundle.pem", append(append([]byte(nil), leafPEM.certPEM...), ca.certPEM...))
	// Raw DER expired RSA cert
	writeEntry("res/raw/legacy.der", expiredDER.der)
	// Keystore markers with realistic magic bytes
	writeEntry("assets/client_mtls.p12", []byte{0x30, 0x82, 0x01, 0x20, 0x02, 0x01, 0x03})
	bksPayload := make([]byte, 16)
	binary.BigEndian.PutUint32(bksPayload[:4], 2)
	writeEntry("res/raw/truststore.bks", bksPayload)
	writeEntry("assets/custom.jks", []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02})
	// Plain XML network_security_config.xml
	writeEntry("res/xml/network_security_config.xml", []byte(nscXML))
	// Unrelated XML under res/xml/ should be silently ignored
	writeEntry("res/xml/file_paths.xml", []byte(`<paths><cache-path name="c" path="."/></paths>`))
	// Zip-slip path MUST be skipped safely with a warning
	writeEntry("../../evil/escape.pem", leafPEM.certPEM)
	// Oversized entry (> 4 MiB) MUST be skipped safely with a warning
	writeEntry("assets/huge.pem", bytes.Repeat([]byte("A"), maxAPKEntryBytes+1024))

	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close apk file: %v", err)
	}

	report, err := ScanAPKForCertificates(apkPath)
	if err != nil {
		t.Fatalf("ScanAPKForCertificates failed: %v", err)
	}

	// Expect 3 parsed certificates: leaf PEM + CA PEM + legacy DER (zip-slip entry skipped).
	if len(report.Certificates) != 3 {
		t.Fatalf("expected 3 certificates, got %d: %+v", len(report.Certificates), report.Certificates)
	}

	var sawLeaf, sawCA, sawExpiredDER bool
	for _, c := range report.Certificates {
		if len(c.SHA256Fingerprint) != 64 {
			t.Errorf("invalid SHA-256 fingerprint length for %s: %q", c.CommonName, c.SHA256Fingerprint)
		}
		switch c.CommonName {
		case "api.example.com":
			sawLeaf = true
			if c.Format != "PEM" || c.Expired || c.IsCA {
				t.Errorf("unexpected leaf cert metadata: %+v", c)
			}
			if c.Serial != "2A4B" {
				t.Errorf("leaf serial = %q, want 2A4B", c.Serial)
			}
			if c.PublicKeyAlgorithm != "ECDSA" || c.PublicKeyBits != 256 {
				t.Errorf("leaf pubkey = %s/%d, want ECDSA/256", c.PublicKeyAlgorithm, c.PublicKeyBits)
			}
			if len(c.SANs) != 3 {
				t.Errorf("expected 3 SANs (2 DNS + 1 IP), got %v", c.SANs)
			}
			if c.SPKISHA256 != expectedPin {
				t.Errorf("leaf SPKISHA256 = %q, want %q", c.SPKISHA256, expectedPin)
			}
		case "Cap Embedded Test Root CA":
			sawCA = true
			if !c.IsCA || !c.SelfSigned {
				t.Errorf("expected CA cert IsCA=true SelfSigned=true, got %+v", c)
			}
		case "legacy.example.com":
			sawExpiredDER = true
			if c.Format != "DER" || !c.Expired {
				t.Errorf("expected expired DER cert, got %+v", c)
			}
			if c.PublicKeyAlgorithm != "RSA" || c.PublicKeyBits != 2048 {
				t.Errorf("expected RSA/2048 for legacy cert, got %s/%d", c.PublicKeyAlgorithm, c.PublicKeyBits)
			}
		}
	}
	if !sawLeaf || !sawCA || !sawExpiredDER {
		t.Fatalf("missing expected certs: leaf=%v ca=%v expiredDER=%v", sawLeaf, sawCA, sawExpiredDER)
	}

	// Expect 3 keystore findings: .p12, .bks, .jks
	if len(report.Keystores) != 3 || !report.HasMTLSIndicators {
		t.Fatalf("expected 3 keystores with HasMTLSIndicators=true, got %d (flag=%v)", len(report.Keystores), report.HasMTLSIndicators)
	}
	ksByFormat := make(map[string]KeystoreFinding)
	for _, ks := range report.Keystores {
		ksByFormat[ks.Format] = ks
		if !ks.RequiresMTLSConfig || !ks.MagicVerified {
			t.Errorf("expected RequiresMTLSConfig & MagicVerified for %+v", ks)
		}
	}
	if _, ok := ksByFormat["PKCS12"]; !ok {
		t.Errorf("missing PKCS12 keystore finding")
	}
	if _, ok := ksByFormat["BKS"]; !ok {
		t.Errorf("missing BKS keystore finding")
	}
	if _, ok := ksByFormat["JKS"]; !ok {
		t.Errorf("missing JKS keystore finding")
	}

	// Network security config + pins
	if len(report.NetworkSecurityConfigs) != 1 || !report.HasPinning {
		t.Fatalf("expected 1 network_security_config with HasPinning=true, got %d (HasPinning=%v)", len(report.NetworkSecurityConfigs), report.HasPinning)
	}
	nsc := report.NetworkSecurityConfigs[0]
	if nsc.CleartextPermitted == nil || *nsc.CleartextPermitted {
		t.Errorf("expected cleartextTrafficPermitted=false, got %v", nsc.CleartextPermitted)
	}
	if !nsc.TrustsSystemCerts || !nsc.TrustsUserCerts || len(nsc.CustomTrustAnchors) != 1 || nsc.CustomTrustAnchors[0] != "@raw/embedded_ca" {
		t.Errorf("unexpected trust anchors: %+v", nsc)
	}
	if len(report.Pins) != 2 {
		t.Fatalf("expected 2 pins, got %d: %+v", len(report.Pins), report.Pins)
	}
	if report.Pins[0].Value != expectedPin || report.Pins[0].Digest != "SHA-256" || report.Pins[0].Expiration != "2028-01-01" {
		t.Errorf("unexpected pin[0]: %+v", report.Pins[0])
	}
	if len(report.Pins[0].Domains) != 2 {
		t.Errorf("expected 2 domains on pin[0], got %v", report.Pins[0].Domains)
	}

	// Verify zip-slip and oversized entry produced warnings.
	joinedWarn := strings.Join(report.Warnings, "\n")
	if !strings.Contains(joinedWarn, "unsafe zip entry path") {
		t.Errorf("expected zip-slip warning, got warnings: %v", report.Warnings)
	}
	if !strings.Contains(joinedWarn, "exceeds 4 MiB per-entry limit") {
		t.Errorf("expected oversized entry warning, got warnings: %v", report.Warnings)
	}

	// Verify clean JSON marshaling.
	if _, err := json.Marshal(report); err != nil {
		t.Fatalf("marshal APKCertScanReport failed: %v", err)
	}
}

func TestInspectCertPEM(t *testing.T) {
	ca := generateTestCA(t, "Inspect PEM Root")
	leaf := generateSignedTestCert(
		t, ca, "service.internal", 42,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		[]string{"service.internal"}, nil, nil, false,
	)
	combined := append(append([]byte(nil), leaf.certPEM...), ca.certPEM...)
	certs, err := InspectCertPEM(combined)
	if err != nil {
		t.Fatalf("InspectCertPEM failed: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	wantFP := sha256.Sum256(leaf.der)
	if certs[0].SHA256Fingerprint != hex.EncodeToString(wantFP[:]) {
		t.Errorf("fingerprint mismatch: got %s, want %x", certs[0].SHA256Fingerprint, wantFP)
	}

	if _, err := InspectCertPEM([]byte("not a pem")); err == nil {
		t.Errorf("expected error for invalid PEM")
	}
}

// --- 3. ValidateMTLSKeyPair (Valid + Mismatched + Expired) ---

func TestValidateMTLSKeyPair(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	ca := generateTestCA(t, "mTLS Test CA")

	validClient := generateSignedTestCert(
		t, ca, "mobile-client-01", 2001,
		now.Add(-time.Hour), now.Add(48*time.Hour),
		[]string{"client.cap.local"}, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		false,
	)
	otherClient := generateSignedTestCert(
		t, ca, "mobile-client-02", 2002,
		now.Add(-time.Hour), now.Add(48*time.Hour),
		nil, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		false,
	)
	expiredClient := generateSignedTestCert(
		t, ca, "expired-client", 2003,
		now.Add(-96*time.Hour), now.Add(-2*time.Hour),
		nil, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		true,
	)

	validCertPath := filepath.Join(dir, "valid.crt")
	validKeyPath := filepath.Join(dir, "valid.key")
	otherKeyPath := filepath.Join(dir, "other.key")
	expiredCertPath := filepath.Join(dir, "expired.crt")
	expiredKeyPath := filepath.Join(dir, "expired.key")

	// Include CA in valid cert file to verify chain length > 1 too.
	_ = os.WriteFile(validCertPath, append(append([]byte(nil), validClient.certPEM...), ca.certPEM...), 0o600)
	_ = os.WriteFile(validKeyPath, validClient.keyPEM, 0o600)
	_ = os.WriteFile(otherKeyPath, otherClient.keyPEM, 0o600)
	_ = os.WriteFile(expiredCertPath, expiredClient.certPEM, 0o600)
	_ = os.WriteFile(expiredKeyPath, expiredClient.keyPEM, 0o600)

	// Case 1: Valid key pair
	res, err := ValidateMTLSKeyPair(validCertPath, validKeyPath)
	if err != nil {
		t.Fatalf("valid key pair returned error: %v", err)
	}
	if !res.Valid || !res.KeyPairMatch || res.Expired || res.NotYetValid {
		t.Fatalf("unexpected valid key pair result: %+v", res)
	}
	if res.Leaf == nil || res.Leaf.CommonName != "mobile-client-01" || res.ChainLength != 2 || !res.HasClientAuthEKU {
		t.Fatalf("unexpected valid leaf/chain metadata: %+v", res)
	}

	// Case 2: Mismatched cert and key
	mismatchRes, err := ValidateMTLSKeyPair(validCertPath, otherKeyPath)
	if err == nil {
		t.Fatalf("expected error for mismatched cert/key")
	}
	if mismatchRes == nil || mismatchRes.Valid || mismatchRes.KeyPairMatch {
		t.Fatalf("expected Valid=false KeyPairMatch=false on mismatch, got %+v", mismatchRes)
	}
	if mismatchRes.Leaf == nil || mismatchRes.Leaf.CommonName != "mobile-client-01" {
		t.Errorf("expected leaf metadata to still be populated on mismatch")
	}

	// Case 3: Expired certificate with matching key
	expRes, err := ValidateMTLSKeyPair(expiredCertPath, expiredKeyPath)
	if err != nil {
		t.Fatalf("expired cert with matching key returned unexpected error: %v", err)
	}
	if expRes.Valid || !expRes.KeyPairMatch || !expRes.Expired {
		t.Fatalf("expected Valid=false KeyPairMatch=true Expired=true, got %+v", expRes)
	}
	if expRes.Leaf == nil || !expRes.Leaf.Expired || expRes.Leaf.PublicKeyBits != 2048 {
		t.Fatalf("unexpected expired leaf metadata: %+v", expRes.Leaf)
	}
}

// pipeListener is an in-process net.Listener backed by net.Pipe so full TLS
// and mTLS handshakes still run end-to-end inside sandboxes that disallow
// TCP loopback connect().
type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		ch:     make(chan net.Conn, 8),
		closed: make(chan struct{}),
	}
}

func (p *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-p.ch:
		return c, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (p *pipeListener) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}

func (p *pipeListener) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	select {
	case p.ch <- serverConn:
		return clientConn, nil
	case <-p.closed:
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, ctx.Err()
	}
}

// --- 4. Real TLS & Real Mutual TLS (mTLS) Handshake Tests ---

func TestRealTLSAndMTLSHandshakes(t *testing.T) {
	// 4a. Standard TLS handshake using chrome_131 profile against httptest.NewTLSServer
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("chrome-tls-ok"))
	})
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	tlsCfg, err := BuildTLSConfig("chrome_131", true, "", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig(chrome_131) failed: %v", err)
	}
	transport := &http.Transport{
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	usePipeFallback := false
	resp, err := client.Get(srv.URL)
	if err != nil && errors.Is(err, syscall.EPERM) {
		// Sandbox disallows loopback TCP connect(); execute the exact same real
		// httptest + crypto/tls handshake over an in-memory net.Pipe listener.
		usePipeFallback = true
		pl := newPipeListener()
		pipedSrv := httptest.NewUnstartedServer(handler)
		_ = pipedSrv.Listener.Close()
		pipedSrv.Listener = pl
		pipedSrv.EnableHTTP2 = true
		pipedSrv.StartTLS()
		defer pipedSrv.Close()

		pipedClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:   tlsCfg,
				ForceAttemptHTTP2: true,
				DialContext:       pl.DialContext,
			},
			Timeout: 5 * time.Second,
		}
		resp, err = pipedClient.Get(pipedSrv.URL)
	}
	if err != nil {
		t.Fatalf("TLS handshake with chrome_131 failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "chrome-tls-ok" {
		t.Fatalf("unexpected TLS response: status=%d body=%q", resp.StatusCode, string(body))
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("expected TLS >= 1.2 handshake state, got %+v", resp.TLS)
	}

	// 4b. Full Mutual TLS (mTLS) handshake with RequireAndVerifyClientCert
	now := time.Now().UTC()
	ca := generateTestCA(t, "Cap mTLS Root CA")
	serverCert := generateSignedTestCert(
		t, ca, "127.0.0.1", 3001,
		now.Add(-time.Hour), now.Add(24*time.Hour),
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		false,
	)
	clientCert := generateSignedTestCert(
		t, ca, "cap-mtls-client", 3002,
		now.Add(-time.Hour), now.Add(24*time.Hour),
		nil, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		false,
	)
	expiredCert := generateSignedTestCert(
		t, ca, "cap-mtls-expired", 3003,
		now.Add(-48*time.Hour), now.Add(-time.Hour),
		nil, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		false,
	)

	dir := t.TempDir()
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client.key")
	expiredCertPath := filepath.Join(dir, "expired.pem")
	expiredKeyPath := filepath.Join(dir, "expired.key")
	_ = os.WriteFile(clientCertPath, clientCert.certPEM, 0o600)
	_ = os.WriteFile(clientKeyPath, clientCert.keyPEM, 0o600)
	_ = os.WriteFile(expiredCertPath, expiredCert.certPEM, 0o600)
	_ = os.WriteFile(expiredKeyPath, expiredCert.keyPEM, 0o600)

	serverTLSPair, err := tls.X509KeyPair(serverCert.certPEM, serverCert.keyPEM)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)

	mtlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "missing client cert", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("mtls:" + r.TLS.PeerCertificates[0].Subject.CommonName))
	}))
	var dialFn func(ctx context.Context, network, addr string) (net.Conn, error)
	if usePipeFallback {
		pl := newPipeListener()
		_ = mtlsSrv.Listener.Close()
		mtlsSrv.Listener = pl
		dialFn = pl.DialContext
	}
	mtlsSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	mtlsSrv.StartTLS()
	defer mtlsSrv.Close()

	// Without client cert -> handshake must fail.
	noClientCfg, err := BuildTLSConfig("okhttp_android", false, "", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig(okhttp_android) failed: %v", err)
	}
	noClientCfg.RootCAs = caPool
	noCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: noClientCfg,
			DialContext:     dialFn,
		},
		Timeout: 5 * time.Second,
	}
	if _, err := noCertClient.Get(mtlsSrv.URL); err == nil {
		t.Fatalf("expected mTLS server to reject client without certificate")
	}

	// Expired client cert -> BuildTLSConfig must refuse it.
	if _, err := BuildTLSConfig("okhttp_android", false, expiredCertPath, expiredKeyPath); err == nil {
		t.Fatalf("expected BuildTLSConfig to reject expired mTLS client cert")
	}

	// Valid client cert + CA RootCAs -> full verified mTLS handshake succeeds.
	mtlsCfg, err := BuildTLSConfig("okhttp_android", false, clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("BuildTLSConfig with mTLS cert failed: %v", err)
	}
	mtlsCfg.RootCAs = caPool
	mtlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtlsCfg,
			DialContext:     dialFn,
		},
		Timeout: 5 * time.Second,
	}
	mResp, err := mtlsClient.Get(mtlsSrv.URL)
	if err != nil {
		t.Fatalf("mTLS handshake failed: %v", err)
	}
	mBody, _ := io.ReadAll(mResp.Body)
	mResp.Body.Close()
	if mResp.StatusCode != http.StatusOK || string(mBody) != "mtls:cap-mtls-client" {
		t.Fatalf("unexpected mTLS response: status=%d body=%q", mResp.StatusCode, string(mBody))
	}
	if mResp.TLS == nil || !mResp.TLS.HandshakeComplete {
		t.Fatalf("expected completed mTLS handshake state, got %+v", mResp.TLS)
	}
}

// --- 5. All 6 TLS Profiles, Deterministic JA3 Summaries, & Host Probe ---

func TestTLSProfilesAndDeterministicJA3(t *testing.T) {
	profiles := ListTLSProfiles()
	wantIDs := []string{
		"go_default",
		"chrome_131",
		"safari_17",
		"firefox_132",
		"okhttp_android",
		"ios_cfnetwork",
	}
	if len(profiles) != len(wantIDs) {
		t.Fatalf("expected %d TLS profiles, got %d", len(wantIDs), len(profiles))
	}

	hashes := make(map[string]string, len(profiles))
	for i, p := range profiles {
		if p.ID != wantIDs[i] {
			t.Errorf("profile[%d].ID = %q, want %q", i, p.ID, wantIDs[i])
		}
		if p.MinVersion != tls.VersionTLS12 || p.MaxVersion != tls.VersionTLS13 {
			t.Errorf("profile %s unexpected TLS bounds: %x..%x", p.ID, p.MinVersion, p.MaxVersion)
		}
		if len(p.CipherSuites) == 0 || len(p.CurvePreferences) == 0 || len(p.ALPN) == 0 {
			t.Errorf("profile %s missing cipher/curve/ALPN specs", p.ID)
		}
		if len(p.HeaderOrder) == 0 || len(p.DefaultHeaders) == 0 {
			t.Errorf("profile %s missing header order or default headers", p.ID)
		}

		ja3a := ComputeProfileJA3Summary(p.ID)
		ja3b := ComputeProfileJA3Summary(p.ID)
		if ja3a == nil || ja3b == nil {
			t.Fatalf("ComputeProfileJA3Summary(%q) returned nil", p.ID)
		}
		if ja3a.JA3String != ja3b.JA3String || ja3a.JA3Hash != ja3b.JA3Hash {
			t.Fatalf("non-deterministic JA3 for %q", p.ID)
		}
		parts := strings.Split(ja3a.JA3String, ",")
		if len(parts) != 5 {
			t.Errorf("profile %s JA3 string must have 5 comma-separated fields, got %q", p.ID, ja3a.JA3String)
		}
		wantMD5 := md5.Sum([]byte(ja3a.JA3String))
		if ja3a.JA3Hash != hex.EncodeToString(wantMD5[:]) {
			t.Errorf("profile %s JA3Hash mismatch: got %s, want %x", p.ID, ja3a.JA3Hash, wantMD5)
		}
		if prev, dup := hashes[ja3a.JA3Hash]; dup {
			t.Errorf("profiles %q and %q unexpectedly share identical JA3 hash %s", prev, p.ID, ja3a.JA3Hash)
		}
		hashes[ja3a.JA3Hash] = p.ID

		// Verify BuildTLSConfig works for every profile and isolates mutations.
		cfg, err := BuildTLSConfig(p.ID, false, "", "")
		if err != nil {
			t.Fatalf("BuildTLSConfig(%q) failed: %v", p.ID, err)
		}
		if len(cfg.CipherSuites) != len(p.CipherSuites) {
			t.Errorf("profile %s cipher suite count mismatch", p.ID)
		}
		cfg.NextProtos[0] = "mutated"
		p.DefaultHeaders["User-Agent"] = "mutated"
	}

	// Ensure mutating returned copies did not affect global profile registry.
	fresh, err := GetTLSProfile("chrome_131")
	if err != nil {
		t.Fatalf("GetTLSProfile failed: %v", err)
	}
	if fresh.ALPN[0] != "h2" || fresh.DefaultHeaders["User-Agent"] == "mutated" {
		t.Fatalf("global TLS profile state was mutated by caller")
	}

	// Unknown profile error / nil handling
	if _, err := BuildTLSConfig("nonexistent_profile", false, "", ""); err == nil {
		t.Errorf("expected error for unknown TLS profile")
	}
	if got := ComputeProfileJA3Summary("nonexistent_profile"); got != nil {
		t.Errorf("expected nil JA3Summary for unknown profile, got %+v", got)
	}
	if def := ComputeProfileJA3Summary(""); def == nil || def.ProfileID != "go_default" {
		t.Errorf("expected empty profile ID to default to go_default, got %+v", def)
	}

	// Concurrency / -race safety across readers
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := wantIDs[idx%len(wantIDs)]
			_ = ListTLSProfiles()
			_ = ComputeProfileJA3Summary(id)
			_, _ = BuildTLSConfig(id, false, "", "")
		}(i)
	}
	wg.Wait()
}

func TestDetectCurlImpersonate(t *testing.T) {
	// Smoke test against host PATH (must never panic or return nil slices).
	hostInfo := DetectCurlImpersonate()
	if hostInfo.Binaries == nil || len(hostInfo.SearchedPatterns) == 0 {
		t.Fatalf("unexpected empty metadata from DetectCurlImpersonate: %+v", hostInfo)
	}

	// Deterministic temp-directory detection test
	dir := t.TempDir()
	bins := []string{"curl_chrome131", "curl_safari17", "curl_ff132", "curl-impersonate-chrome"}
	for _, name := range bins {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
			t.Fatalf("create fake bin %s: %v", name, err)
		}
	}
	// Non-executable file with matching name should be ignored.
	_ = os.WriteFile(filepath.Join(dir, "curl_chrome_not_exec"), []byte("nope"), 0o644)
	// Unrelated executable should be ignored.
	_ = os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/bin/sh\n"), 0o755)

	found := detectCurlImpersonateInDirs([]string{dir})
	if !found.Available {
		t.Fatalf("expected Available=true, got %+v", found)
	}
	if len(found.Binaries) != len(bins) {
		t.Fatalf("expected %d binaries, got %d: %+v", len(bins), len(found.Binaries), found.Binaries)
	}
	if !strings.Contains(found.PrimaryBinary, "chrome") {
		t.Errorf("expected primary binary to prefer chrome family, got %q", found.PrimaryBinary)
	}

	empty := detectCurlImpersonateInDirs([]string{t.TempDir()})
	if empty.Available || len(empty.Binaries) != 0 || empty.InstallHint == "" {
		t.Fatalf("unexpected result for empty PATH dir: %+v", empty)
	}

	// Deduplication across multiple PATH directories and symlinks
	dir2 := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir2, "curl_chrome131"), []byte("#!/bin/sh\necho dup\n"), 0o755)
	_ = os.Symlink(filepath.Join(dir, "curl-impersonate-chrome"), filepath.Join(dir2, "curl-impersonate-chrome"))
	deduped := detectCurlImpersonateInDirs([]string{dir, dir2})
	if len(deduped.Binaries) != len(bins) {
		t.Fatalf("expected deduplicated count %d across two PATH dirs, got %d: %+v", len(bins), len(deduped.Binaries), deduped.Binaries)
	}
	if curlBinaryDedupKey("CURL-IMPERSONATE-CHROME.EXE") != curlBinaryDedupKey("curl-impersonate-chrome") {
		t.Errorf("case/suffix normalization mismatch in curlBinaryDedupKey")
	}
}

// --- 6. Boundary, DoS, AXML, and mTLS Edge-Case Regression Tests ---

func buildSyntheticAXML(strs []string, utf8Mode bool) []byte {
	var strBlob bytes.Buffer
	offsets := make([]uint32, len(strs))
	for i, s := range strs {
		offsets[i] = uint32(strBlob.Len())
		if utf8Mode {
			u16len := len(utf16.Encode([]rune(s)))
			strBlob.WriteByte(byte(u16len))
			strBlob.WriteByte(byte(len(s)))
			strBlob.WriteString(s)
			strBlob.WriteByte(0)
		} else {
			u16 := utf16.Encode([]rune(s))
			var lenBuf [2]byte
			binary.LittleEndian.PutUint16(lenBuf[:], uint16(len(u16)))
			strBlob.Write(lenBuf[:])
			for _, cu := range u16 {
				binary.LittleEndian.PutUint16(lenBuf[:], cu)
				strBlob.Write(lenBuf[:])
			}
			strBlob.Write([]byte{0, 0})
		}
	}
	for strBlob.Len()%4 != 0 {
		strBlob.WriteByte(0)
	}

	stringsStart := uint32(28 + len(strs)*4)
	chunkSize := stringsStart + uint32(strBlob.Len())
	totalSize := 8 + chunkSize

	buf := make([]byte, totalSize)
	// AXML file header: type=0x0003, headerSize=0x0008, totalSize
	binary.LittleEndian.PutUint16(buf[0:2], 0x0003)
	binary.LittleEndian.PutUint16(buf[2:4], 0x0008)
	binary.LittleEndian.PutUint32(buf[4:8], totalSize)
	// String pool chunk header at offset 8
	off := 8
	binary.LittleEndian.PutUint16(buf[off:off+2], 0x0001)
	binary.LittleEndian.PutUint16(buf[off+2:off+4], 28)
	binary.LittleEndian.PutUint32(buf[off+4:off+8], chunkSize)
	binary.LittleEndian.PutUint32(buf[off+8:off+12], uint32(len(strs)))
	if utf8Mode {
		binary.LittleEndian.PutUint32(buf[off+16:off+20], 1<<8)
	}
	binary.LittleEndian.PutUint32(buf[off+20:off+24], stringsStart)
	for i, o := range offsets {
		binary.LittleEndian.PutUint32(buf[off+28+i*4:off+28+i*4+4], o)
	}
	copy(buf[off+int(stringsStart):], strBlob.Bytes())
	return buf
}

func TestScanAPKForCertificatesBoundariesAndAXML(t *testing.T) {
	// 1. Total 32 MiB budget cap -> Truncated=true
	budgetAPK := filepath.Join(t.TempDir(), "budget.apk")
	{
		f, err := os.Create(budgetAPK)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		// 9 entries * ~3.9 MiB = ~35.1 MiB > 32 MiB budget (each < 4 MiB per-entry limit).
		payload := bytes.Repeat([]byte("X"), (3900 * 1024))
		for i := 0; i < 9; i++ {
			hdr := &zip.FileHeader{
				Name:   fmt.Sprintf("assets/blob_%02d.pem", i),
				Method: zip.Deflate,
			}
			w, err := zw.CreateHeader(hdr)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
		_ = zw.Close()
		_ = f.Close()
	}
	budgetReport, err := ScanAPKForCertificates(budgetAPK)
	if err != nil {
		t.Fatalf("ScanAPKForCertificates(budget) failed: %v", err)
	}
	if !budgetReport.Truncated {
		t.Fatalf("expected Truncated=true when hitting 32 MiB total budget, got %+v", budgetReport)
	}
	if budgetReport.TotalBytesRead > maxAPKTotalReadBytes {
		t.Fatalf("TotalBytesRead %d exceeded cap %d", budgetReport.TotalBytesRead, maxAPKTotalReadBytes)
	}

	// 2. Entry count > 20,000 cap -> Truncated=true & EntriesScanned == 20000
	manyAPK := filepath.Join(t.TempDir(), "many.apk")
	{
		f, err := os.Create(manyAPK)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		for i := 0; i < maxAPKZipEntries+5; i++ {
			hdr := &zip.FileHeader{
				Name:   fmt.Sprintf("assets/f%05d.txt", i),
				Method: zip.Store,
			}
			if _, err := zw.CreateHeader(hdr); err != nil {
				t.Fatal(err)
			}
		}
		_ = zw.Close()
		_ = f.Close()
	}
	manyReport, err := ScanAPKForCertificates(manyAPK)
	if err != nil {
		t.Fatalf("ScanAPKForCertificates(many) failed: %v", err)
	}
	if !manyReport.Truncated || manyReport.EntriesScanned != maxAPKZipEntries {
		t.Fatalf("expected Truncated=true EntriesScanned=%d, got Truncated=%v EntriesScanned=%d",
			maxAPKZipEntries, manyReport.Truncated, manyReport.EntriesScanned)
	}

	// 3. Valid compiled AXML (UTF-16LE + UTF-8) + hostile/malformed AXML + deeply nested XML
	pinUTF16 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	pinUTF8 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))

	axmlUTF16 := buildSyntheticAXML([]string{"network-security-config", "system", "user", pinUTF16}, false)
	axmlUTF8 := buildSyntheticAXML([]string{"network-security-config", "system", pinUTF8}, true)

	// Hostile AXML buffers that must never panic
	hostileCases := [][]byte{
		// Truncated header
		{0x03, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00},
		// stringsStart = 0x80000000 (high-bit overflow attempt)
		func() []byte {
			b := make([]byte, 64)
			binary.LittleEndian.PutUint16(b[0:2], 0x0003)
			binary.LittleEndian.PutUint16(b[2:4], 0x0008)
			binary.LittleEndian.PutUint32(b[4:8], 64)
			binary.LittleEndian.PutUint16(b[8:10], 0x0001)
			binary.LittleEndian.PutUint32(b[12:16], 56)
			binary.LittleEndian.PutUint32(b[16:20], 1)
			binary.LittleEndian.PutUint32(b[28:32], 0x80000000)
			return b
		}(),
		// stringsStart < 28 (header overlap attempt)
		func() []byte {
			b := make([]byte, 64)
			binary.LittleEndian.PutUint16(b[0:2], 0x0003)
			binary.LittleEndian.PutUint16(b[2:4], 0x0008)
			binary.LittleEndian.PutUint32(b[4:8], 64)
			binary.LittleEndian.PutUint16(b[8:10], 0x0001)
			binary.LittleEndian.PutUint32(b[12:16], 56)
			binary.LittleEndian.PutUint32(b[16:20], 1)
			binary.LittleEndian.PutUint32(b[28:32], 4)
			return b
		}(),
		// charLen = 0x7fffffff (2-word UTF-16LE OOM/overflow attempt)
		func() []byte {
			b := make([]byte, 64)
			binary.LittleEndian.PutUint16(b[0:2], 0x0003)
			binary.LittleEndian.PutUint16(b[2:4], 0x0008)
			binary.LittleEndian.PutUint32(b[4:8], 64)
			binary.LittleEndian.PutUint16(b[8:10], 0x0001)
			binary.LittleEndian.PutUint32(b[12:16], 56)
			binary.LittleEndian.PutUint32(b[16:20], 1)
			binary.LittleEndian.PutUint32(b[28:32], 32) // stringsStart
			binary.LittleEndian.PutUint32(b[36:40], 0)  // rel=0
			// At offset 8+32=40: high-bit UTF-16 length = 0xffff, 0xffff => 0x7fffffff
			binary.LittleEndian.PutUint16(b[40:42], 0xffff)
			binary.LittleEndian.PutUint16(b[42:44], 0xffff)
			return b
		}(),
		// chunkSize = 0xffffffff
		func() []byte {
			b := make([]byte, 64)
			binary.LittleEndian.PutUint16(b[0:2], 0x0003)
			binary.LittleEndian.PutUint16(b[2:4], 0x0008)
			binary.LittleEndian.PutUint32(b[4:8], 64)
			binary.LittleEndian.PutUint16(b[8:10], 0x0001)
			binary.LittleEndian.PutUint32(b[12:16], 0xffffffff)
			return b
		}(),
	}
	for i, raw := range hostileCases {
		if strs := extractAXMLStringPool(raw); len(strs) != 0 {
			t.Errorf("hostile AXML case %d unexpectedly returned %d strings", i, len(strs))
		}
	}

	// Deeply nested <domain-config> XML (> maxXMLNestingDepth)
	var deepXML strings.Builder
	deepXML.WriteString("<network-security-config>")
	for i := 0; i < maxXMLNestingDepth+20; i++ {
		deepXML.WriteString("<domain-config>")
	}
	for i := 0; i < maxXMLNestingDepth+20; i++ {
		deepXML.WriteString("</domain-config>")
	}
	deepXML.WriteString("</network-security-config>")

	axmlAPK := filepath.Join(t.TempDir(), "axml-and-deep.apk")
	{
		f, err := os.Create(axmlAPK)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		add := func(name string, data []byte) {
			w, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(data)
		}
		add("res/xml/network_security_config.xml", axmlUTF16)
		add("res/xml/network_security_config_utf8.xml", axmlUTF8)
		add("res/xml/network_security_hostile.xml", hostileCases[3])
		add("res/xml/network_security_deep.xml", []byte(deepXML.String()))
		_ = zw.Close()
		_ = f.Close()
	}

	axmlReport, err := ScanAPKForCertificates(axmlAPK)
	if err != nil {
		t.Fatalf("ScanAPKForCertificates(axml) failed: %v", err)
	}
	if len(axmlReport.NetworkSecurityConfigs) != 2 || !axmlReport.HasPinning || len(axmlReport.Pins) != 2 {
		t.Fatalf("expected 2 valid binary AXML NSC findings with 2 pins, got configs=%d pins=%d warnings=%v",
			len(axmlReport.NetworkSecurityConfigs), len(axmlReport.Pins), axmlReport.Warnings)
	}
	for _, cfg := range axmlReport.NetworkSecurityConfigs {
		if !cfg.BinaryXML {
			t.Errorf("expected BinaryXML=true for %s", cfg.Path)
		}
	}
	if !strings.Contains(strings.Join(axmlReport.Warnings, "\n"), "XML nesting depth exceeds limit") {
		t.Errorf("expected XML depth warning for deeply nested domain-config, got warnings: %v", axmlReport.Warnings)
	}
}

func TestValidateMTLSKeyPairEdgeCases(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	ca := generateTestCA(t, "Edge Case CA")

	// 1. Empty paths
	if res, err := ValidateMTLSKeyPair("", ""); err == nil || res == nil || res.Valid {
		t.Fatalf("expected error & Valid=false for empty paths, got (%+v, %v)", res, err)
	}
	// 2. Missing cert / missing key files
	if res, err := ValidateMTLSKeyPair(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key")); err == nil || res == nil || res.Valid {
		t.Fatalf("expected error for missing cert file, got (%+v, %v)", res, err)
	}
	validCert := generateSignedTestCert(
		t, ca, "present-cert", 4001,
		now.Add(-time.Hour), now.Add(24*time.Hour),
		nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false,
	)
	presentCertPath := filepath.Join(dir, "present.crt")
	_ = os.WriteFile(presentCertPath, validCert.certPEM, 0o600)
	if res, err := ValidateMTLSKeyPair(presentCertPath, filepath.Join(dir, "missing.key")); err == nil || res == nil || res.Valid {
		t.Fatalf("expected error for missing key file, got (%+v, %v)", res, err)
	}

	// 3. Not-yet-valid certificate
	futureCert := generateSignedTestCert(
		t, ca, "future-client", 4002,
		now.Add(24*time.Hour), now.Add(72*time.Hour),
		nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false,
	)
	futureCertPath := filepath.Join(dir, "future.crt")
	futureKeyPath := filepath.Join(dir, "future.key")
	_ = os.WriteFile(futureCertPath, futureCert.certPEM, 0o600)
	_ = os.WriteFile(futureKeyPath, futureCert.keyPEM, 0o600)

	futureRes, err := ValidateMTLSKeyPair(futureCertPath, futureKeyPath)
	if err != nil {
		t.Fatalf("not-yet-valid cert with matching key returned unexpected error: %v", err)
	}
	if futureRes.Valid || !futureRes.KeyPairMatch || !futureRes.NotYetValid || futureRes.Expired {
		t.Fatalf("expected Valid=false KeyPairMatch=true NotYetValid=true Expired=false, got %+v", futureRes)
	}
	if futureRes.Leaf == nil || !futureRes.Leaf.NotYetValid {
		t.Fatalf("expected leaf metadata NotYetValid=true, got %+v", futureRes.Leaf)
	}
	if _, err := BuildTLSConfig("chrome_131", false, futureCertPath, futureKeyPath); err == nil {
		t.Fatalf("expected BuildTLSConfig to reject not-yet-valid mTLS client cert")
	}
}
