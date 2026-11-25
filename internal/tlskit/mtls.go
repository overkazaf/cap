package tlskit

import (
	"archive/zip"
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	// Strict resource bounds for APK zip scanning.
	maxAPKZipEntries     = 20000
	maxAPKEntryBytes     = 4 << 20  // 4 MiB per inspected entry
	maxAPKTotalReadBytes = 32 << 20 // 32 MiB cumulative read across all entries

	// Maximum size accepted when reading PEM cert/key files from disk.
	maxPEMFileBytes = 4 << 20

	// Maximum XML element nesting depth allowed in network_security_config.xml.
	maxXMLNestingDepth = 64
)

var (
	certExtensions = map[string]bool{
		".pem": true,
		".crt": true,
		".cer": true,
		".der": true,
	}

	keystoreExtensions = map[string]string{
		".p12": "PKCS12",
		".pfx": "PKCS12",
		".bks": "BKS",
		".jks": "JKS",
	}
)

// ScanAPKForCertificates safely scans an APK zip archive in pure Go for
// embedded X.509 certificates, keystore/truststore files (.p12, .pfx, .bks,
// .jks), and Android network_security_config.xml files.
//
// Archive inspection is strictly bounded: at most 20,000 entries, at most
// 4 MiB per inspected entry, at most 32 MiB total bytes read, and all entry
// paths are validated against zip-slip traversal. No files are written to disk.
func ScanAPKForCertificates(apkPath string) (*APKCertScanReport, error) {
	apkPath = strings.TrimSpace(apkPath)
	if apkPath == "" {
		return nil, errors.New("tlskit: apk path is empty")
	}

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("tlskit: open apk %q: %w", apkPath, err)
	}
	defer zr.Close()

	now := time.Now().UTC()
	report := &APKCertScanReport{
		APKPath:                apkPath,
		ScannedAt:              now,
		Certificates:           []CertSummary{},
		Keystores:              []KeystoreFinding{},
		NetworkSecurityConfigs: []NetworkSecurityConfigFinding{},
		Pins:                   []PinEntry{},
	}

	limit := len(zr.File)
	if limit > maxAPKZipEntries {
		report.Truncated = true
		report.Warnings = append(report.Warnings, fmt.Sprintf("apk entry count %d exceeds limit %d; scanning first %d entries", len(zr.File), maxAPKZipEntries, maxAPKZipEntries))
		limit = maxAPKZipEntries
	}

	for i := 0; i < limit; i++ {
		f := zr.File[i]
		report.EntriesScanned++

		cleanName, ok := sanitizeZipEntryPath(f.Name)
		if !ok {
			report.Warnings = append(report.Warnings, fmt.Sprintf("skipped unsafe zip entry path: %q", f.Name))
			continue
		}
		if f.FileInfo().IsDir() {
			continue
		}

		ext := strings.ToLower(path.Ext(cleanName))
		base := strings.ToLower(path.Base(cleanName))
		isCertExt := certExtensions[ext]
		ksFormat, isKeystoreExt := keystoreExtensions[ext]
		isNetSecXML := isNetworkSecurityConfigPath(cleanName, base, ext)

		if !isCertExt && !isKeystoreExt && !isNetSecXML {
			continue
		}

		if report.TotalBytesRead >= maxAPKTotalReadBytes {
			report.Truncated = true
			report.Warnings = append(report.Warnings, fmt.Sprintf("stopped reading entries after reaching %d MiB total scan budget", maxAPKTotalReadBytes>>20))
			break
		}

		// Record keystores even if large, while bounding any magic-byte sniff.
		if isKeystoreExt {
			var header []byte
			if f.UncompressedSize64 <= maxAPKEntryBytes {
				remaining := maxAPKTotalReadBytes - report.TotalBytesRead
				sniffMax := int64(64)
				if remaining < sniffMax {
					sniffMax = remaining
				}
				if sniffMax > 0 {
					var readErr error
					header, readErr = readBoundedZipBytes(f, sniffMax)
					if readErr != nil {
						report.Warnings = append(report.Warnings, fmt.Sprintf("failed to inspect keystore %s: %v", cleanName, readErr))
					} else {
						report.TotalBytesRead += int64(len(header))
					}
				}
			} else {
				report.Warnings = append(report.Warnings, fmt.Sprintf("keystore %s exceeds %d MiB per-entry read cap; recorded metadata only", cleanName, maxAPKEntryBytes>>20))
			}

			sizeBytes := int64(f.UncompressedSize64)
			if f.UncompressedSize64 > math.MaxInt64 {
				sizeBytes = math.MaxInt64
			}
			magicOK := verifyKeystoreMagic(ksFormat, header)
			note := fmt.Sprintf("Embedded %s store detected; inspect whether this holds an mTLS client identity or custom truststore", ksFormat)
			if ksFormat == "PKCS12" {
				note = "Embedded PKCS#12 (.p12/.pfx) store detected; likely client certificate/key material for mTLS configuration"
			}
			report.Keystores = append(report.Keystores, KeystoreFinding{
				Path:               cleanName,
				Format:             ksFormat,
				SizeBytes:          sizeBytes,
				MagicVerified:      magicOK,
				RequiresMTLSConfig: true,
				Note:               note,
			})
			report.HasMTLSIndicators = true
			continue
		}

		// Reject oversized entries before decompressing (and enforce via LimitReader too).
		if f.UncompressedSize64 > maxAPKEntryBytes {
			report.Warnings = append(report.Warnings, fmt.Sprintf("skipped %s: size %d exceeds %d MiB per-entry limit", cleanName, f.UncompressedSize64, maxAPKEntryBytes>>20))
			continue
		}

		remaining := maxAPKTotalReadBytes - report.TotalBytesRead
		entryCap := int64(maxAPKEntryBytes)
		if remaining < entryCap {
			entryCap = remaining
		}
		data, oversized, readErr := readZipEntryBounded(f, entryCap)
		if readErr != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("failed to read %s: %v", cleanName, readErr))
			continue
		}
		report.TotalBytesRead += int64(len(data))
		if oversized {
			if int64(len(data)) >= remaining && remaining < maxAPKEntryBytes {
				report.Truncated = true
				report.Warnings = append(report.Warnings, fmt.Sprintf("stopped at %s: total scan budget %d MiB reached", cleanName, maxAPKTotalReadBytes>>20))
				break
			}
			report.Warnings = append(report.Warnings, fmt.Sprintf("skipped %s: decompressed payload exceeds %d MiB per-entry limit", cleanName, maxAPKEntryBytes>>20))
			continue
		}

		if isCertExt {
			certs, parseErr := parseCertBytes(data, cleanName, now)
			if parseErr != nil {
				report.Warnings = append(report.Warnings, fmt.Sprintf("could not parse certificate %s: %v", cleanName, parseErr))
				continue
			}
			report.Certificates = append(report.Certificates, certs...)
			continue
		}

		if isNetSecXML {
			finding, matched, parseErr := parseNetworkSecurityConfig(cleanName, data)
			if parseErr != nil {
				report.Warnings = append(report.Warnings, fmt.Sprintf("could not parse %s: %v", cleanName, parseErr))
				continue
			}
			if !matched {
				continue
			}
			report.NetworkSecurityConfigs = append(report.NetworkSecurityConfigs, finding)
			if len(finding.Pins) > 0 {
				report.Pins = append(report.Pins, finding.Pins...)
				report.HasPinning = true
			}
		}
	}

	return report, nil
}

// InspectCertPEM parses one or more PEM-encoded X.509 CERTIFICATE blocks and
// returns structured metadata summaries for each certificate.
func InspectCertPEM(pemData []byte) ([]CertSummary, error) {
	if len(bytes.TrimSpace(pemData)) == 0 {
		return nil, errors.New("tlskit: pem data is empty")
	}
	now := time.Now().UTC()
	certs, err := parseCertPEM(pemData, "", now)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// ValidateMTLSKeyPair loads and validates a user-provided PEM client
// certificate and private key via tls.X509KeyPair, returning leaf certificate
// metadata, chain information, and expiry status.
//
// If the files cannot be read, parsed, or the certificate and key do not match,
// both a populated MTLSValidationResult (with Valid=false) and a non-nil error
// are returned. If the key pair matches cryptographically but the leaf
// certificate is expired or not yet valid, err is nil while Valid=false and
// Expired/NotYetValid reflect the certificate status.
func ValidateMTLSKeyPair(certPath, keyPath string) (*MTLSValidationResult, error) {
	res, _, err := validateAndLoadMTLSKeyPair(certPath, keyPath)
	return res, err
}

func validateAndLoadMTLSKeyPair(certPath, keyPath string) (*MTLSValidationResult, tls.Certificate, error) {
	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	res := &MTLSValidationResult{
		CertPath: certPath,
		KeyPath:  keyPath,
		Chain:    []CertSummary{},
	}

	if certPath == "" || keyPath == "" {
		err := errors.New("tlskit: both certPath and keyPath are required")
		res.Error = err.Error()
		return res, tls.Certificate{}, err
	}

	certPEM, err := readBoundedFile(certPath, maxPEMFileBytes)
	if err != nil {
		err = fmt.Errorf("tlskit: read client cert %q: %w", certPath, err)
		res.Error = err.Error()
		return res, tls.Certificate{}, err
	}
	keyPEM, err := readBoundedFile(keyPath, maxPEMFileBytes)
	if err != nil {
		err = fmt.Errorf("tlskit: read client key %q: %w", keyPath, err)
		res.Error = err.Error()
		return res, tls.Certificate{}, err
	}

	now := time.Now().UTC()
	// Best-effort parse cert chain first so metadata is available even on key mismatch.
	if chain, chainErr := parseCertPEM(certPEM, certPath, now); chainErr == nil && len(chain) > 0 {
		res.Chain = chain
		res.ChainLength = len(chain)
		leafCopy := chain[0]
		res.Leaf = &leafCopy
		res.Expired = leafCopy.Expired
		res.NotYetValid = leafCopy.NotYetValid
		res.ExpiresInDays = int(math.Floor(leafCopy.NotAfter.Sub(now).Hours() / 24))
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		err = fmt.Errorf("tlskit: validate mTLS key pair: %w", err)
		res.KeyPairMatch = false
		res.Valid = false
		res.Error = err.Error()
		return res, tls.Certificate{}, err
	}
	if len(pair.Certificate) == 0 {
		err := errors.New("tlskit: key pair contained no certificates")
		res.Error = err.Error()
		return res, tls.Certificate{}, err
	}

	leafCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		err = fmt.Errorf("tlskit: parse leaf certificate: %w", err)
		res.Error = err.Error()
		return res, tls.Certificate{}, err
	}
	pair.Leaf = leafCert

	summary := summarizeX509Cert(leafCert, certPath, "PEM", now)
	res.KeyPairMatch = true
	res.Leaf = &summary
	res.Expired = summary.Expired
	res.NotYetValid = summary.NotYetValid
	res.ExpiresInDays = int(math.Floor(leafCert.NotAfter.Sub(now).Hours() / 24))
	res.ChainLength = len(pair.Certificate)

	// Re-populate chain cleanly from pair.Certificate order if needed.
	if len(res.Chain) != len(pair.Certificate) {
		res.Chain = make([]CertSummary, 0, len(pair.Certificate))
		for _, der := range pair.Certificate {
			if c, perr := x509.ParseCertificate(der); perr == nil {
				res.Chain = append(res.Chain, summarizeX509Cert(c, certPath, "PEM", now))
			}
		}
	}

	res.HasClientAuthEKU = certAllowsClientAuth(leafCert)
	if !res.HasClientAuthEKU {
		res.Warnings = append(res.Warnings, "leaf certificate ExtendedKeyUsage does not include ClientAuth")
	}
	if res.Expired {
		res.Warnings = append(res.Warnings, fmt.Sprintf("leaf certificate expired on %s", leafCert.NotAfter.UTC().Format(time.RFC3339)))
	}
	if res.NotYetValid {
		res.Warnings = append(res.Warnings, fmt.Sprintf("leaf certificate is not valid until %s", leafCert.NotBefore.UTC().Format(time.RFC3339)))
	}

	res.Valid = res.KeyPairMatch && !res.Expired && !res.NotYetValid
	return res, pair, nil
}

// sanitizeZipEntryPath ensures a zip archive entry path is relative and cannot
// escape a root via zip-slip traversal.
func sanitizeZipEntryPath(raw string) (string, bool) {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", false
	}
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if strings.HasPrefix(normalized, "/") {
		return "", false
	}
	// Reject Windows drive letter prefixes such as "C:/..."
	if len(normalized) >= 2 && normalized[1] == ':' && ((normalized[0] >= 'a' && normalized[0] <= 'z') || (normalized[0] >= 'A' && normalized[0] <= 'Z')) {
		return "", false
	}
	for _, seg := range strings.Split(normalized, "/") {
		if seg == ".." {
			return "", false
		}
	}
	cleaned := path.Clean(normalized)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", false
	}
	return cleaned, true
}

func isNetworkSecurityConfigPath(cleanName, base, ext string) bool {
	if ext != ".xml" {
		return false
	}
	if base == "network_security_config.xml" || strings.Contains(base, "network_security") || strings.Contains(base, "network-security") {
		return true
	}
	// Also inspect res/xml/*.xml since apps frequently give custom filenames
	// referenced by android:networkSecurityConfig="@xml/..."
	return strings.HasPrefix(strings.ToLower(cleanName), "res/xml/")
}

func readBoundedZipBytes(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limit))
}

func readZipEntryBounded(f *zip.File, maxBytes int64) ([]byte, bool, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return data[:maxBytes], true, nil
	}
	return data, false, nil
}

func readBoundedFile(filePath string, maxBytes int64) ([]byte, error) {
	clean := filepath.Clean(filePath)
	f, err := os.Open(clean)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%q is a directory", clean)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file size %d exceeds maximum allowed %d bytes", info.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file size exceeds maximum allowed %d bytes", maxBytes)
	}
	return data, nil
}

func verifyKeystoreMagic(format string, header []byte) bool {
	switch format {
	case "JKS":
		// Java KeyStore magic: 0xFEEDFEED (or JCEKS 0xCECECECE)
		return len(header) >= 4 &&
			((header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFE && header[3] == 0xED) ||
				(header[0] == 0xCE && header[1] == 0xCE && header[2] == 0xCE && header[3] == 0xCE))
	case "BKS":
		// BouncyCastle KeyStore big-endian version int32: 1 or 2
		if len(header) < 4 {
			return false
		}
		ver := binary.BigEndian.Uint32(header[:4])
		return ver == 1 || ver == 2
	case "PKCS12":
		// PKCS#12 PFX starts with ASN.1 DER SEQUENCE tag 0x30
		return len(header) >= 2 && header[0] == 0x30
	default:
		return false
	}
}

func parseCertBytes(data []byte, sourcePath string, now time.Time) ([]CertSummary, error) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		certs, err := parseCertPEM(data, sourcePath, now)
		if err == nil && len(certs) > 0 {
			return certs, nil
		}
	}

	// Fallback: try raw DER (single certificate or concatenated DER).
	if cert, err := x509.ParseCertificate(data); err == nil {
		return []CertSummary{summarizeX509Cert(cert, sourcePath, "DER", now)}, nil
	}
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		out := make([]CertSummary, 0, len(certs))
		for _, c := range certs {
			out = append(out, summarizeX509Cert(c, sourcePath, "DER", now))
		}
		return out, nil
	}
	return nil, errors.New("no valid PEM or DER X.509 certificates found")
}

func parseCertPEM(pemData []byte, sourcePath string, now time.Time) ([]CertSummary, error) {
	var certs []CertSummary
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" && block.Type != "TRUSTED CERTIFICATE" && block.Type != "X509 CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tlskit: parse X.509 PEM block: %w", err)
		}
		certs = append(certs, summarizeX509Cert(cert, sourcePath, "PEM", now))
	}
	if len(certs) == 0 {
		return nil, errors.New("tlskit: no PEM CERTIFICATE blocks found")
	}
	return certs, nil
}

func summarizeX509Cert(cert *x509.Certificate, sourcePath, format string, now time.Time) CertSummary {
	fp := sha256.Sum256(cert.Raw)
	var spkiPin string
	if len(cert.RawSubjectPublicKeyInfo) > 0 {
		spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		spkiPin = base64.StdEncoding.EncodeToString(spkiHash[:])
	}

	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		sans = append(sans, u.String())
	}

	serial := ""
	if cert.SerialNumber != nil {
		serial = strings.ToUpper(cert.SerialNumber.Text(16))
	}

	return CertSummary{
		SourcePath:         sourcePath,
		Format:             format,
		Subject:            cert.Subject.String(),
		CommonName:         cert.Subject.CommonName,
		Issuer:             cert.Issuer.String(),
		Serial:             serial,
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		Expired:            now.After(cert.NotAfter),
		NotYetValid:        now.Before(cert.NotBefore),
		SANs:               sans,
		SHA256Fingerprint:  hex.EncodeToString(fp[:]),
		SPKISHA256:         spkiPin,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:      publicKeyBits(cert.PublicKey),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		SelfSigned:         bytes.Equal(cert.RawIssuer, cert.RawSubject),
	}
}

func publicKeyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k != nil && k.N != nil {
			return k.N.BitLen()
		}
	case *ecdsa.PublicKey:
		if k != nil && k.Curve != nil {
			return k.Curve.Params().BitSize
		}
	case ed25519.PublicKey:
		return ed25519.PublicKeySize * 8
	case *dsa.PublicKey:
		if k != nil && k.P != nil {
			return k.P.BitLen()
		}
	}
	return 0
}

func certAllowsClientAuth(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// --- Android network_security_config.xml parser (plain XML + AXML fallback) ---

type xmlNetSecConfig struct {
	XMLName        xml.Name          `xml:"network-security-config"`
	BaseConfig     *xmlBaseConfig    `xml:"base-config"`
	DomainConfigs  []xmlDomainConfig `xml:"domain-config"`
	DebugOverrides *xmlBaseConfig    `xml:"debug-overrides"`
}

type xmlBaseConfig struct {
	Cleartext    string           `xml:"cleartextTrafficPermitted,attr"`
	TrustAnchors *xmlTrustAnchors `xml:"trust-anchors"`
	PinSet       *xmlPinSet       `xml:"pin-set"`
}

type xmlDomainConfig struct {
	Cleartext     string            `xml:"cleartextTrafficPermitted,attr"`
	Domains       []xmlDomain       `xml:"domain"`
	TrustAnchors  *xmlTrustAnchors  `xml:"trust-anchors"`
	PinSet        *xmlPinSet        `xml:"pin-set"`
	DomainConfigs []xmlDomainConfig `xml:"domain-config"`
}

type xmlDomain struct {
	IncludeSubdomains string `xml:"includeSubdomains,attr"`
	Name              string `xml:",chardata"`
}

type xmlTrustAnchors struct {
	Certificates []xmlCertAnchor `xml:"certificates"`
}

type xmlCertAnchor struct {
	Src string `xml:"src,attr"`
}

type xmlPinSet struct {
	Expiration string   `xml:"expiration,attr"`
	Pins       []xmlPin `xml:"pin"`
}

type xmlPin struct {
	Digest string `xml:"digest,attr"`
	Value  string `xml:",chardata"`
}

func parseNetworkSecurityConfig(sourcePath string, data []byte) (NetworkSecurityConfigFinding, bool, error) {
	finding := NetworkSecurityConfigFinding{
		Path: sourcePath,
	}

	// Android compiled binary XML (AXML) starts with chunk type 0x0003 and header size 0x0008.
	if len(data) >= 8 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x08 && data[3] == 0x00 {
		return parseBinaryNetworkSecurityConfig(sourcePath, data)
	}

	if !bytes.Contains(data, []byte("<network-security-config")) {
		return finding, false, nil
	}

	if err := checkXMLMaxDepth(data, maxXMLNestingDepth); err != nil {
		return finding, true, err
	}

	var doc xmlNetSecConfig
	if err := xml.Unmarshal(data, &doc); err != nil {
		return finding, true, err
	}

	domainSeen := make(map[string]bool)
	anchorSeen := make(map[string]bool)

	addDomain := func(d string) {
		d = strings.TrimSpace(d)
		if d != "" && !domainSeen[d] {
			domainSeen[d] = true
			finding.Domains = append(finding.Domains, d)
		}
	}
	processAnchors := func(ta *xmlTrustAnchors) {
		if ta == nil {
			return
		}
		for _, c := range ta.Certificates {
			src := strings.TrimSpace(c.Src)
			switch src {
			case "system":
				finding.TrustsSystemCerts = true
			case "user":
				finding.TrustsUserCerts = true
			default:
				if src != "" && !anchorSeen[src] {
					anchorSeen[src] = true
					finding.CustomTrustAnchors = append(finding.CustomTrustAnchors, src)
				}
			}
		}
	}
	processCleartext := func(raw string) {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if raw == "true" {
			v := true
			finding.CleartextPermitted = &v
		} else if raw == "false" && finding.CleartextPermitted == nil {
			v := false
			finding.CleartextPermitted = &v
		}
	}
	processPinSet := func(ps *xmlPinSet, domains []string) {
		if ps == nil {
			return
		}
		exp := strings.TrimSpace(ps.Expiration)
		for _, p := range ps.Pins {
			val := strings.TrimSpace(p.Value)
			if val == "" {
				continue
			}
			digest := strings.TrimSpace(p.Digest)
			if digest == "" {
				digest = "SHA-256"
			}
			var domCopy []string
			if len(domains) > 0 {
				domCopy = append([]string(nil), domains...)
			}
			finding.Pins = append(finding.Pins, PinEntry{
				Digest:     digest,
				Value:      val,
				Domains:    domCopy,
				Expiration: exp,
				SourcePath: sourcePath,
			})
		}
	}

	if doc.BaseConfig != nil {
		processCleartext(doc.BaseConfig.Cleartext)
		processAnchors(doc.BaseConfig.TrustAnchors)
		processPinSet(doc.BaseConfig.PinSet, nil)
	}
	if doc.DebugOverrides != nil {
		processAnchors(doc.DebugOverrides.TrustAnchors)
		processPinSet(doc.DebugOverrides.PinSet, nil)
	}

	var walkDomainConfigs func(cfgs []xmlDomainConfig, parentDomains []string, depth int)
	walkDomainConfigs = func(cfgs []xmlDomainConfig, parentDomains []string, depth int) {
		if depth > maxXMLNestingDepth {
			return
		}
		for _, dc := range cfgs {
			processCleartext(dc.Cleartext)
			processAnchors(dc.TrustAnchors)
			localDomains := append([]string(nil), parentDomains...)
			for _, d := range dc.Domains {
				name := strings.TrimSpace(d.Name)
				if name != "" {
					addDomain(name)
					localDomains = append(localDomains, name)
				}
			}
			processPinSet(dc.PinSet, localDomains)
			if len(dc.DomainConfigs) > 0 {
				walkDomainConfigs(dc.DomainConfigs, localDomains, depth+1)
			}
		}
	}
	walkDomainConfigs(doc.DomainConfigs, nil, 0)

	return finding, true, nil
}

func checkXMLMaxDepth(data []byte, maxDepth int) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
			if depth > maxDepth {
				return fmt.Errorf("tlskit: XML nesting depth exceeds limit %d", maxDepth)
			}
		case xml.EndElement:
			if depth > 0 {
				depth--
			}
		}
	}
}

// parseBinaryNetworkSecurityConfig performs best-effort pure-Go extraction from
// compiled Android Binary XML (AXML) string pools.
func parseBinaryNetworkSecurityConfig(sourcePath string, data []byte) (NetworkSecurityConfigFinding, bool, error) {
	finding := NetworkSecurityConfigFinding{
		Path:      sourcePath,
		BinaryXML: true,
	}
	strs := extractAXMLStringPool(data)
	if len(strs) == 0 {
		return finding, false, nil
	}

	isNSC := false
	for _, s := range strs {
		if s == "network-security-config" {
			isNSC = true
			break
		}
	}
	if !isNSC {
		return finding, false, nil
	}

	for _, s := range strs {
		switch s {
		case "user":
			finding.TrustsUserCerts = true
		case "system":
			finding.TrustsSystemCerts = true
		default:
			if isLikelySHA256PinBase64(s) {
				finding.Pins = append(finding.Pins, PinEntry{
					Digest:     "SHA-256",
					Value:      s,
					SourcePath: sourcePath,
				})
			}
		}
	}
	return finding, true, nil
}

func extractAXMLStringPool(data []byte) []string {
	// AXML header is 8 bytes; string pool chunk immediately follows at offset 8
	// with chunk type 0x0001. All offset/length checks use uint64 to avoid
	// signed integer overflow on 32-bit platforms or crafted headers.
	dataLen := uint64(len(data))
	if dataLen < 36 {
		return nil
	}
	const off uint64 = 8
	chunkType := binary.LittleEndian.Uint16(data[off : off+2])
	chunkSize := uint64(binary.LittleEndian.Uint32(data[off+4 : off+8]))
	if chunkType != 0x0001 || chunkSize < 28 || chunkSize > dataLen-off {
		return nil
	}
	end := off + chunkSize

	strCount := uint64(binary.LittleEndian.Uint32(data[off+8 : off+12]))
	flags := binary.LittleEndian.Uint32(data[off+16 : off+20])
	stringsStart := uint64(binary.LittleEndian.Uint32(data[off+20 : off+24]))
	isUTF8 := (flags & (1 << 8)) != 0

	if strCount == 0 || strCount > 8192 {
		return nil
	}
	if stringsStart < 28 || stringsStart >= chunkSize {
		return nil
	}
	offsetsBase := off + 28
	offsetsBytes := strCount * 4
	if offsetsBytes > chunkSize-28 {
		return nil
	}
	dataBase := off + stringsStart
	if offsetsBase+offsetsBytes > dataBase || dataBase >= end {
		return nil
	}

	out := make([]string, 0, int(strCount))
	for i := uint64(0); i < strCount; i++ {
		rel := uint64(binary.LittleEndian.Uint32(data[offsetsBase+i*4 : offsetsBase+i*4+4]))
		if rel >= end-dataBase {
			continue
		}
		pos := dataBase + rel
		if isUTF8 {
			// Skip UTF-16 char len (1-2 bytes), then read UTF-8 byte len (1-2 bytes).
			if pos >= end {
				continue
			}
			if data[pos]&0x80 != 0 {
				if end-pos < 2 {
					continue
				}
				pos += 2
			} else {
				pos++
			}
			if pos >= end {
				continue
			}
			var byteLen uint64
			if data[pos]&0x80 != 0 {
				if end-pos < 2 {
					continue
				}
				byteLen = (uint64(data[pos]&0x7f) << 8) | uint64(data[pos+1])
				pos += 2
			} else {
				byteLen = uint64(data[pos])
				pos++
			}
			if byteLen > 0 && byteLen <= end-pos {
				out = append(out, string(data[pos:pos+byteLen]))
			}
		} else {
			if end-pos < 2 {
				continue
			}
			charLen := uint64(binary.LittleEndian.Uint16(data[pos : pos+2]))
			pos += 2
			if charLen&0x8000 != 0 {
				if end-pos < 2 {
					continue
				}
				charLen = ((charLen & 0x7fff) << 16) | uint64(binary.LittleEndian.Uint16(data[pos:pos+2]))
				pos += 2
			}
			// Overflow-safe check before allocating u16 slice.
			if charLen > 0 && charLen <= (end-pos)/2 {
				u16 := make([]uint16, int(charLen))
				for j := uint64(0); j < charLen; j++ {
					u16[j] = binary.LittleEndian.Uint16(data[pos+j*2 : pos+j*2+2])
				}
				out = append(out, string(utf16.Decode(u16)))
			}
		}
	}
	return out
}

func isLikelySHA256PinBase64(s string) bool {
	if len(s) != 44 || s[43] != '=' {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == sha256.Size
}
