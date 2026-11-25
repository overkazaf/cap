package wailsgui

import (
	"github.com/overkazaf/cap/internal/tlskit"
)

// ==================== Modern TLS / mTLS / Compat Toolkit ====================

// ScanAPKForCertificates scans an APK archive in pure Go for X.509 certificates,
// keystores, network_security_config.xml, and pinning/mTLS indicators.
func (a *App) ScanAPKForCertificates(apkPath string) (*tlskit.APKCertScanReport, error) {
	return tlskit.ScanAPKForCertificates(apkPath)
}

// InspectCertPEM parses one or more PEM-encoded X.509 CERTIFICATE blocks.
func (a *App) InspectCertPEM(pemText string) ([]tlskit.CertSummary, error) {
	return tlskit.InspectCertPEM([]byte(pemText))
}

// ValidateMTLSKeyPair validates a PEM client certificate and private key pair.
func (a *App) ValidateMTLSKeyPair(certPath, keyPath string) (*tlskit.MTLSValidationResult, error) {
	return tlskit.ValidateMTLSKeyPair(certPath, keyPath)
}

// ListTLSProfiles returns all curated TLS / HTTP2 client profiles.
func (a *App) ListTLSProfiles() []tlskit.TLSProfileSpec {
	return tlskit.ListTLSProfiles()
}

// ComputeTLSProfileJA3 returns the deterministic JA3 summary for profileID.
func (a *App) ComputeTLSProfileJA3(profileID string) *tlskit.JA3Summary {
	return tlskit.ComputeProfileJA3Summary(profileID)
}

// DetectCurlImpersonate probes PATH for installed curl-impersonate binaries.
func (a *App) DetectCurlImpersonate() tlskit.CurlImpersonateInfo {
	return tlskit.DetectCurlImpersonate()
}

// GenerateFlutterProxyDebugScript generates an authorized local-proxy Flutter
// diagnostic Frida script.
func (a *App) GenerateFlutterProxyDebugScript(opts tlskit.FlutterDebugOptions) *tlskit.GeneratedCompatScript {
	return tlskit.GenerateFlutterProxyDebugScript(opts)
}

// GenerateCronetHTTP2Script generates a Cronet/OkHttp HTTP/2 local-proxy compatibility
// Frida script.
func (a *App) GenerateCronetHTTP2Script(opts tlskit.CronetOptions) *tlskit.GeneratedCompatScript {
	return tlskit.GenerateCronetHTTP2Script(opts)
}

// GenerateMTLSObserverScript generates a strictly diagnostic mTLS observer Frida script.
func (a *App) GenerateMTLSObserverScript(opts tlskit.MTLSObserverOptions) *tlskit.GeneratedCompatScript {
	return tlskit.GenerateMTLSObserverScript(opts)
}
