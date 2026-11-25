// Package tlskit provides modern TLS/mTLS diagnostics, pure-Go APK certificate
// and network security config scanning, curated TLS/HTTP2 client profiles,
// deterministic JA3 summaries, host curl-impersonate probing, and authorized
// local-proxy Frida diagnostic script generation for cap.
package tlskit

import (
	"crypto/tls"
	"time"
)

// CertSummary holds parsed X.509 certificate metadata.
type CertSummary struct {
	SourcePath         string    `json:"source_path,omitempty"`
	Format             string    `json:"format"` // "PEM" or "DER"
	Subject            string    `json:"subject"`
	CommonName         string    `json:"common_name,omitempty"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	Expired            bool      `json:"expired"`
	NotYetValid        bool      `json:"not_yet_valid"`
	SANs               []string  `json:"sans,omitempty"`
	SHA256Fingerprint  string    `json:"sha256_fingerprint"`
	SPKISHA256         string    `json:"spki_sha256,omitempty"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	IsCA               bool      `json:"is_ca"`
	SelfSigned         bool      `json:"self_signed"`
}

// KeystoreFinding flags an embedded keystore or truststore archive inside an
// APK that may hold client mTLS credentials or custom trust anchors.
type KeystoreFinding struct {
	Path               string `json:"path"`
	Format             string `json:"format"` // "PKCS12", "BKS", "JKS"
	SizeBytes          int64  `json:"size_bytes"`
	MagicVerified      bool   `json:"magic_verified"`
	RequiresMTLSConfig bool   `json:"requires_mtls_config"`
	Note               string `json:"note,omitempty"`
}

// PinEntry describes a public-key pin extracted from an Android
// network_security_config.xml file.
type PinEntry struct {
	Digest     string   `json:"digest"`
	Value      string   `json:"value"`
	Domains    []string `json:"domains,omitempty"`
	Expiration string   `json:"expiration,omitempty"`
	SourcePath string   `json:"source_path,omitempty"`
}

// NetworkSecurityConfigFinding summarizes an Android network_security_config.xml
// discovered inside an APK.
type NetworkSecurityConfigFinding struct {
	Path               string     `json:"path"`
	BinaryXML          bool       `json:"binary_xml"`
	CleartextPermitted *bool      `json:"cleartext_permitted,omitempty"`
	TrustsUserCerts    bool       `json:"trusts_user_certs"`
	TrustsSystemCerts  bool       `json:"trusts_system_certs"`
	CustomTrustAnchors []string   `json:"custom_trust_anchors,omitempty"`
	Domains            []string   `json:"domains,omitempty"`
	Pins               []PinEntry `json:"pins,omitempty"`
}

// APKCertScanReport is the complete pure-Go certificate, keystore, and
// network_security_config.xml analysis for an APK archive.
type APKCertScanReport struct {
	APKPath                string                         `json:"apk_path"`
	ScannedAt              time.Time                      `json:"scanned_at"`
	EntriesScanned         int                            `json:"entries_scanned"`
	TotalBytesRead         int64                          `json:"total_bytes_read"`
	Truncated              bool                           `json:"truncated"`
	Certificates           []CertSummary                  `json:"certificates"`
	Keystores              []KeystoreFinding              `json:"keystores"`
	NetworkSecurityConfigs []NetworkSecurityConfigFinding `json:"network_security_configs"`
	Pins                   []PinEntry                     `json:"pins"`
	HasPinning             bool                           `json:"has_pinning"`
	HasMTLSIndicators      bool                           `json:"has_mtls_indicators"`
	Warnings               []string                       `json:"warnings,omitempty"`
}

// MTLSValidationResult reports the result of loading and validating a PEM
// client certificate and private key pair for mutual TLS.
type MTLSValidationResult struct {
	Valid            bool          `json:"valid"`
	KeyPairMatch     bool          `json:"key_pair_match"`
	CertPath         string        `json:"cert_path"`
	KeyPath          string        `json:"key_path"`
	Leaf             *CertSummary  `json:"leaf,omitempty"`
	Chain            []CertSummary `json:"chain,omitempty"`
	ChainLength      int           `json:"chain_length"`
	Expired          bool          `json:"expired"`
	NotYetValid      bool          `json:"not_yet_valid"`
	ExpiresInDays    int           `json:"expires_in_days"`
	HasClientAuthEKU bool          `json:"has_client_auth_eku"`
	Warnings         []string      `json:"warnings,omitempty"`
	Error            string        `json:"error,omitempty"`
}

// JA3Summary represents a deterministic JA3 client TLS fingerprint summary.
type JA3Summary struct {
	ProfileID   string `json:"profile_id"`
	JA3String   string `json:"ja3_string"`
	JA3Hash     string `json:"ja3_hash"`
	TLSVersion  uint16 `json:"tls_version"`
	CipherCount int    `json:"cipher_count"`
	CurveCount  int    `json:"curve_count"`
}

// TLSProfileSpec describes a curated TLS + HTTP/2 client profile.
type TLSProfileSpec struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	Platform          string            `json:"platform"`
	MinVersion        uint16            `json:"min_version"`
	MaxVersion        uint16            `json:"max_version"`
	MinVersionName    string            `json:"min_version_name"`
	MaxVersionName    string            `json:"max_version_name"`
	CipherSuites      []uint16          `json:"cipher_suites"`
	CipherSuiteNames  []string          `json:"cipher_suite_names"`
	TLS13CipherSuites []uint16          `json:"tls13_cipher_suites,omitempty"`
	CurvePreferences  []tls.CurveID     `json:"curve_preferences"`
	CurveNames        []string          `json:"curve_names"`
	ALPN              []string          `json:"alpn"`
	HeaderOrder       []string          `json:"header_order"`
	DefaultHeaders    map[string]string `json:"default_headers"`
	JA3               *JA3Summary       `json:"ja3,omitempty"`
	Notes             []string          `json:"notes,omitempty"`
}

// CurlImpersonateBinary describes a discovered curl-impersonate binary on PATH.
type CurlImpersonateBinary struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Family string `json:"family"` // "chrome", "safari", "firefox", "edge", "generic"
}

// CurlImpersonateInfo reports host detection results for optional
// curl-impersonate binaries.
type CurlImpersonateInfo struct {
	Available        bool                    `json:"available"`
	PrimaryBinary    string                  `json:"primary_binary,omitempty"`
	Binaries         []CurlImpersonateBinary `json:"binaries"`
	SearchedPatterns []string                `json:"searched_patterns"`
	InstallHint      string                  `json:"install_hint,omitempty"`
}

// FlutterDebugOptions configures the authorized local-proxy Flutter diagnostic
// Frida script generator.
type FlutterDebugOptions struct {
	PackageName           string `json:"package_name,omitempty"`
	Platform              string `json:"platform,omitempty"`                 // "android" (default) or "ios"
	ModuleName            string `json:"module_name,omitempty"`              // defaults to "libflutter.so" (Android) or "Flutter" (iOS)
	ProxyHost             string `json:"proxy_host,omitempty"`               // defaults to "127.0.0.1"
	ProxyPort             int    `json:"proxy_port,omitempty"`               // defaults to 8080
	OffsetHex             string `json:"offset_hex,omitempty"`               // optional local debug symbol offset (e.g. "0x5a1230")
	VerifySymbol          string `json:"verify_symbol,omitempty"`            // optional BoringSSL symbol name
	ForceAllowLocalVerify bool   `json:"force_allow_local_verify,omitempty"` // opt-in local dev override for your own build
}

// CronetOptions configures the Cronet / OkHttp HTTP/2 proxy compatibility
// Frida script generator.
type CronetOptions struct {
	PackageName              string `json:"package_name,omitempty"`
	DisableQUIC              bool   `json:"disable_quic"`
	ConfigureOkHttpProtocols bool   `json:"configure_okhttp_protocols"`
	LogAltSvcHeaders         bool   `json:"log_alt_svc_headers"`
	ProxyHint                string `json:"proxy_hint,omitempty"`
}

// MTLSObserverOptions configures the strictly diagnostic mTLS observer Frida
// script generator.
type MTLSObserverOptions struct {
	PackageName         string `json:"package_name,omitempty"`
	ObserveKeyStore     bool   `json:"observe_keystore"`
	ObserveKeyManager   bool   `json:"observe_key_manager"`
	ObserveSSLContext   bool   `json:"observe_ssl_context"`
	ObserveCertificates bool   `json:"observe_certificates"`
	MaxAliasesPerStore  int    `json:"max_aliases_per_store,omitempty"`
}

// GeneratedCompatScript holds a rendered local-proxy diagnostic Frida script
// along with metadata and any input sanitization notes/warnings.
type GeneratedCompatScript struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"` // "flutter_proxy_debug", "cronet_http2", "mtls_observer"
	Description string   `json:"description"`
	PackageName string   `json:"package_name,omitempty"`
	Code        string   `json:"code"`
	Notes       []string `json:"notes,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	GeneratedAt string   `json:"generated_at"`
}
