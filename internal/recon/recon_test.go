package recon

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeFakeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script test helpers require unix")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatalf("write fake script %s: %v", name, err)
	}
	return p
}

func TestDetectToolchain_CustomOverridesAndMissing(t *testing.T) {
	tmp := t.TempDir()
	fakeNmap := writeFakeScript(t, tmp, "nmap", `echo "Nmap version 7.95 ( https://nmap.org )"`)
	fakeSubfinder := writeFakeScript(t, tmp, "subfinder", `echo "[INF] Current Version: v2.6.7" >&2`)
	// Simulate BSD/macOS whois where --version exits non-zero.
	fakeWhois := writeFakeScript(t, tmp, "whois", `echo "whois: illegal option -- -" >&2; exit 64`)
	fakeDig := writeFakeScript(t, tmp, "dig", `echo "DiG 9.18.24" >&2`)

	info := DetectToolchain(ToolchainConfig{
		NmapPath:      fakeNmap,
		SubfinderPath: fakeSubfinder,
		WhoisPath:     fakeWhois,
		DigPath:       fakeDig,
	})

	if !info.Nmap.Ready || info.Nmap.Version != "7.95" || info.Nmap.Path != fakeNmap {
		t.Fatalf("unexpected nmap status: %+v", info.Nmap)
	}
	if !info.Subfinder.Ready || info.Subfinder.Version != "2.6.7" {
		t.Fatalf("unexpected subfinder status: %+v", info.Subfinder)
	}
	if !info.Whois.Ready || info.Whois.Path != fakeWhois {
		t.Fatalf("unexpected whois status (expected BSD existence fallback): %+v", info.Whois)
	}
	if !info.Dig.Ready || info.Dig.Version != "9.18.24" {
		t.Fatalf("unexpected dig status: %+v", info.Dig)
	}
	if len(info.Issues) != 0 {
		t.Fatalf("expected 0 issues, got: %v", info.Issues)
	}

	// Missing explicit overrides should strictly fail without falling back to PATH.
	missing := DetectToolchain(ToolchainConfig{
		NmapPath:      filepath.Join(tmp, "no-such-nmap"),
		SubfinderPath: filepath.Join(tmp, "no-such-subfinder"),
		WhoisPath:     filepath.Join(tmp, "no-such-whois"),
		DigPath:       filepath.Join(tmp, "no-such-dig"),
	})
	if missing.Nmap.Ready || missing.Subfinder.Ready || missing.Whois.Ready || missing.Dig.Ready {
		t.Fatalf("expected all missing overrides to be not ready: %+v", missing)
	}
	if len(missing.Issues) != 4 {
		t.Fatalf("expected 4 issues, got %d: %v", len(missing.Issues), missing.Issues)
	}
}

func TestNormalizeDomainTargetAndRootDomain(t *testing.T) {
	validCases := []struct {
		in       string
		wantHost string
		wantPort int
		wantRoot string
	}{
		{"https://API.Shop.Example.COM:8443/v1/users?a=1", "api.shop.example.com", 8443, "example.com"},
		{"http://sub.example.com.cn/path", "sub.example.com.cn", 0, "example.com.cn"},
		{"Example.CO.UK.", "example.co.uk", 0, "example.co.uk"},
		{"api.demo.co.uk:9443", "api.demo.co.uk", 9443, "demo.co.uk"},
		{"127.0.0.1", "127.0.0.1", 0, "127.0.0.1"},
		{"::1", "::1", 0, "::1"},
		{"[::1]:8443", "::1", 8443, "::1"},
	}
	for _, tc := range validCases {
		h, p, err := NormalizeDomainTarget(tc.in)
		if err != nil {
			t.Errorf("NormalizeDomainTarget(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if h != tc.wantHost || p != tc.wantPort {
			t.Errorf("NormalizeDomainTarget(%q) = (%q, %d), want (%q, %d)", tc.in, h, p, tc.wantHost, tc.wantPort)
		}
		if root := ExtractRootDomain(h); root != tc.wantRoot {
			t.Errorf("ExtractRootDomain(%q) = %q, want %q", h, root, tc.wantRoot)
		}
	}

	invalidCases := []string{
		"",
		"   ",
		"-example.com",
		"--help",
		"example.com;id",
		"example.com && whoami",
		"example.com|cat /etc/passwd",
		"$(whoami).example.com",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"bad host.com",
		"https://-bad.example.com",
	}
	for _, in := range invalidCases {
		if h, p, err := NormalizeDomainTarget(in); err == nil {
			t.Errorf("NormalizeDomainTarget(%q) unexpectedly succeeded: (%q, %d)", in, h, p)
		}
	}
}

func TestDetectCDNAndWAF(t *testing.T) {
	cdn, waf := DetectCDNAndWAF(
		"shop.example.com.cdn.cloudflare.net",
		[]string{"ns1.alidns.com", "ns2.dnspod.net"},
		[]string{"v=spf1 include:_spf.google.com ~all"},
		"shop.example.com",
	)
	for _, want := range []string{"Cloudflare", "Aliyun DNS", "Tencent DNSPod"} {
		if !slices.Contains(cdn, want) {
			t.Errorf("expected CDN/infra %q in %v", want, cdn)
		}
	}
	if !slices.Contains(waf, "Cloudflare") {
		t.Errorf("expected Cloudflare in WAFHints, got %v", waf)
	}
}

func TestLookupWhoisAndParseWhoisOutput(t *testing.T) {
	tmp := t.TempDir()
	fakeWhois := writeFakeScript(t, tmp, "whois", `
if [ "$1" = "big.example.com" ]; then
  echo "Registrar: Big Test Registrar"
  head -c 40000 /dev/zero | tr '\0' 'A'
  exit 0
fi
cat <<'EOF'
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2030-08-13T04:00:00Z
Updated Date: 2025-08-14T07:01:31Z
Name Server: NS2.EXAMPLE.COM
Name Server: NS1.EXAMPLE.COM 192.0.2.1
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
EOF
`)

	// Reject leading hyphen / injection.
	if _, err := LookupWhois(context.Background(), "-h evil.com", fakeWhois); err == nil {
		t.Fatal("expected leading hyphen whois target to be rejected")
	}

	ws, err := LookupWhois(context.Background(), "example.com", fakeWhois)
	if err != nil {
		t.Fatalf("LookupWhois failed: %v", err)
	}
	if ws.Registrar != "Example Registrar, Inc." {
		t.Errorf("Registrar = %q", ws.Registrar)
	}
	if ws.CreationDate != "1995-08-14T04:00:00Z" || ws.ExpiryDate != "2030-08-13T04:00:00Z" || ws.UpdatedDate != "2025-08-14T07:01:31Z" {
		t.Errorf("unexpected dates: %+v", ws)
	}
	if !slices.Equal(ws.NameServers, []string{"ns1.example.com", "ns2.example.com"}) {
		t.Errorf("NameServers = %v", ws.NameServers)
	}
	if len(ws.Statuses) != 2 || !slices.Contains(ws.Statuses, "clientDeleteProhibited") {
		t.Errorf("Statuses = %v", ws.Statuses)
	}
	if ws.Truncated {
		t.Errorf("expected Truncated=false for normal output")
	}

	// Verify 32 KiB raw output cap.
	big, err := LookupWhois(context.Background(), "big.example.com", fakeWhois)
	if err != nil {
		t.Fatalf("LookupWhois big failed: %v", err)
	}
	if !big.Truncated || len(big.Raw) > MaxWhoisRawBytes {
		t.Fatalf("expected truncated <= %d bytes, got truncated=%v len=%d", MaxWhoisRawBytes, big.Truncated, len(big.Raw))
	}
}

func TestInspectTLS_LocalTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	report, err := InspectTLS(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("InspectTLS failed: %v", err)
	}
	if report.Host != "127.0.0.1" || report.Port != port {
		t.Fatalf("unexpected host/port: %s:%d", report.Host, report.Port)
	}
	if !strings.HasPrefix(report.TLSVersion, "TLS ") || report.CipherSuite == "" {
		t.Fatalf("missing negotiated TLS params: version=%q cipher=%q", report.TLSVersion, report.CipherSuite)
	}
	if report.Leaf == nil || len(report.Chain) == 0 {
		t.Fatalf("expected non-empty leaf and chain")
	}
	if report.Leaf.Subject == "" || report.Leaf.Issuer == "" || report.Leaf.Serial == "" {
		t.Fatalf("incomplete leaf cert metadata: %+v", report.Leaf)
	}
	if len(report.Leaf.SHA256Fingerprint) != 64 {
		t.Fatalf("expected 64-hex SHA256 fingerprint, got %q", report.Leaf.SHA256Fingerprint)
	}
	if !slices.Contains(report.Leaf.SANs, "127.0.0.1") && !slices.Contains(report.Leaf.SANs, "example.com") {
		t.Fatalf("expected SANs on test TLS cert, got %v", report.Leaf.SANs)
	}
	if report.Leaf.PubKeyAlgo == "" || report.Leaf.PubKeyBits == 0 {
		t.Fatalf("expected PubKeyAlgo and PubKeyBits, got %s/%d", report.Leaf.PubKeyAlgo, report.Leaf.PubKeyBits)
	}
	if report.Verified {
		t.Fatalf("expected httptest self-signed cert to report Verified=false")
	}
	if report.VerifyError == "" {
		t.Fatalf("expected non-empty VerifyError for untrusted test cert")
	}
}

func TestProbeSite_LocalTLSServer(t *testing.T) {
	faviconData := []byte("CAP-FAKE-ICO-DATA-123456")
	wantFaviconSum := sha256.Sum256(faviconData)
	wantFaviconHex := hex.EncodeToString(wantFaviconSum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/mid", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/mid", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app", http.StatusFound)
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.4")
		w.Header().Set("X-Powered-By", "Next.js")
		w.Header().Set("CF-Ray", "8abc123456-SIN")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=()")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "demo"})
		_, _ = w.Write([]byte(`<!doctype html>
<html>
<head>
  <title>  Cap Recon &amp; Portal  </title>
  <meta name="generator" content="WordPress 6.6.1">
</head>
<body>
  <div id="__next" data-reactroot="">Hello</div>
  <script id="__NEXT_DATA__" type="application/json">{}</script>
  <link rel="stylesheet" href="/wp-content/themes/demo/style.css">
  <script src="/swagger-ui/swagger-initializer.js"></script>
</body>
</html>`))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\nDisallow: /internal/\nAllow: /public/\nSitemap: https://example.local/sitemap.xml\n"))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.local/app</loc></url>
  <url><loc>https://example.local/docs</loc></url>
  <url><loc>https://example.local/api</loc></url>
</urlset>`))
	})
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Contact: mailto:security@example.local\nExpires: 2030-01-01T00:00:00Z\n"))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://example.local","jwks_uri":"https://example.local/.well-known/jwks.json"}`))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(faviconData)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	profile, err := ProbeSite(context.Background(), srv.URL+"/start", SiteProbeOptions{
		InsecureSkipVerify: true,
		TimeoutMs:          5000,
	})
	if err != nil {
		t.Fatalf("ProbeSite failed: %v", err)
	}

	if profile.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", profile.StatusCode)
	}
	if !strings.HasSuffix(profile.FinalURL, "/app") {
		t.Fatalf("FinalURL = %q, want suffix /app", profile.FinalURL)
	}
	if len(profile.RedirectChain) != 2 {
		t.Fatalf("RedirectChain len = %d, want 2: %+v", len(profile.RedirectChain), profile.RedirectChain)
	}
	if profile.Title != "Cap Recon & Portal" {
		t.Errorf("Title = %q, want %q", profile.Title, "Cap Recon & Portal")
	}
	if profile.MetaGenerator != "WordPress 6.6.1" {
		t.Errorf("MetaGenerator = %q", profile.MetaGenerator)
	}
	if profile.Server != "nginx/1.25.4" {
		t.Errorf("Server = %q", profile.Server)
	}
	if profile.SecurityScore != 100 {
		t.Errorf("SecurityScore = %d, want 100 (headers=%+v)", profile.SecurityScore, profile.SecurityHeaders)
	}
	if len(profile.SecurityHeaders) != 7 {
		t.Errorf("expected 7 security header audits, got %d", len(profile.SecurityHeaders))
	}

	techNames := make([]string, 0, len(profile.Technologies))
	for _, tm := range profile.Technologies {
		techNames = append(techNames, tm.Name)
	}
	for _, want := range []string{"Nginx", "Cloudflare", "Next.js", "React", "WordPress", "Spring / Java", "Swagger / OpenAPI"} {
		if !slices.Contains(techNames, want) {
			t.Errorf("expected technology %q in %v", want, techNames)
		}
	}
	if !slices.Contains(profile.CDNProviders, "Cloudflare") {
		t.Errorf("expected Cloudflare in CDNProviders, got %v", profile.CDNProviders)
	}

	if profile.FaviconSHA256 != wantFaviconHex {
		t.Errorf("FaviconSHA256 = %q, want %q", profile.FaviconSHA256, wantFaviconHex)
	}
	if profile.RobotsRules == nil || !profile.RobotsRules.Found {
		t.Fatalf("expected RobotsRules.Found=true, got %+v", profile.RobotsRules)
	}
	if !slices.Contains(profile.RobotsRules.Disallow, "/admin") || !slices.Contains(profile.RobotsRules.Allow, "/public/") {
		t.Errorf("unexpected robots rules: %+v", profile.RobotsRules)
	}
	if len(profile.SitemapURLs) != 3 {
		t.Errorf("expected 3 sitemap URLs, got %v", profile.SitemapURLs)
	}
	foundSecTxt, foundOIDC := false, false
	for _, wk := range profile.WellKnownPaths {
		if wk.Path == "/.well-known/security.txt" && wk.Found {
			foundSecTxt = true
		}
		if wk.Path == "/.well-known/openid-configuration" && wk.Found {
			foundOIDC = true
		}
	}
	if !foundSecTxt || !foundOIDC {
		t.Errorf("expected both .well-known hits found, got %+v", profile.WellKnownPaths)
	}

	// Verify dangerous wildcard CORS + credentials drops CORS header score to 0.
	badHeaders := http.Header{}
	badHeaders.Set("Access-Control-Allow-Origin", "*")
	badHeaders.Set("Access-Control-Allow-Credentials", "true")
	audits, badScore := AuditSecurityHeaders(badHeaders, false)
	if badScore != 0 {
		t.Errorf("expected insecure HTTP headers with wildcard+creds CORS to score 0, got %d (%+v)", badScore, audits)
	}
}

func TestValidateScanTarget_InjectionAndBoundaries(t *testing.T) {
	valid := []struct {
		in   string
		want string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
		{"example.com", "example.com"},
		{"API.Example.COM.", "api.example.com"},
		{"localhost", "localhost"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"10.0.0.5/32", "10.0.0.5/32"},
	}
	for _, tc := range valid {
		got, err := ValidateScanTarget(tc.in)
		if err != nil {
			t.Errorf("ValidateScanTarget(%q) unexpected error: %v", tc.in, err)
		} else if got != tc.want {
			t.Errorf("ValidateScanTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	invalid := []string{
		"",
		"   ",
		"-sS",
		"--script=vuln",
		"-iL /etc/hosts",
		"127.0.0.1;id",
		"127.0.0.1 && whoami",
		"127.0.0.1|ls",
		"$(whoami)",
		"`id`",
		"127.0.0.1 127.0.0.2",
		"10.0.0.0/16",
		"10.0.0.0/23",
		"10.0.0.0/8",
		"2001:db8::/64",
		"example.com:80",
		"example.com/path",
	}
	for _, in := range invalid {
		if got, err := ValidateScanTarget(in); err == nil {
			t.Errorf("ValidateScanTarget(%q) unexpectedly succeeded with %q", in, got)
		}
	}
}

func TestParsePortSpec_BoundariesAndErrors(t *testing.T) {
	ports, err := ParsePortSpec("443,22,80,80,8000-8003")
	if err != nil {
		t.Fatalf("ParsePortSpec valid failed: %v", err)
	}
	want := []int{22, 80, 443, 8000, 8001, 8002, 8003}
	if !slices.Equal(ports, want) {
		t.Fatalf("ParsePortSpec = %v, want %v", ports, want)
	}
	if canonical := FormatCanonicalPortSpec(ports); canonical != "22,80,443,8000-8003" {
		t.Fatalf("FormatCanonicalPortSpec = %q, want 22,80,443,8000-8003", canonical)
	}

	// Exact boundary: 4096 ports allowed, 4097 rejected.
	if p4096, err := ParsePortSpec("1-4096"); err != nil || len(p4096) != 4096 {
		t.Fatalf("expected 1-4096 to succeed, got len=%d err=%v", len(p4096), err)
	}

	invalidSpecs := []string{
		"",
		"   ",
		"0",
		"65536",
		"-80",
		"80,,443",
		"80,",
		"8010-8000",
		"1-4097",
		"1-65535",
		"1-2050,3000-5050", // 2050 + 2051 = 4101 > 4096
		"80;id",
		"http",
		"80-90-100",
	}
	for _, spec := range invalidSpecs {
		if got, err := ParsePortSpec(spec); err == nil {
			t.Errorf("ParsePortSpec(%q) unexpectedly succeeded with %d ports", spec, len(got))
		}
	}
}

func TestRunPortScan_NativeTCPAndBannerGrab(t *testing.T) {
	// Listener 1: greeting-first banner (SSH style).
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 1: %v", err)
	}
	defer ln1.Close()
	go func() {
		for {
			c, aErr := ln1.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6p1 TestHost\r\n"))
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()

	// Listener 2: HTTP HEAD responder.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 2: %v", err)
	}
	defer ln2.Close()
	go func() {
		for {
			c, aErr := ln2.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				r := bufio.NewReader(conn)
				line, _ := r.ReadString('\n')
				if strings.HasPrefix(line, "HEAD ") {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.25.4\r\nContent-Length: 0\r\n\r\n"))
				}
			}(c)
		}
	}()

	// Listener 3: immediately closed so we have a guaranteed closed port.
	lnClosed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen closed: %v", err)
	}
	closedPort := lnClosed.Addr().(*net.TCPAddr).Port
	_ = lnClosed.Close()

	port1 := ln1.Addr().(*net.TCPAddr).Port
	port2 := ln2.Addr().(*net.TCPAddr).Port

	var progressMu sync.Mutex
	var progress []string
	res, err := RunPortScan(context.Background(), PortScanRequest{
		Target:         "127.0.0.1",
		Engine:         PortScanEngineNative,
		Preset:         PresetCustom,
		PortsSpec:      fmt.Sprintf("%d,%d,%d", port1, port2, closedPort),
		ServiceVersion: true,
		TimeoutMs:      1000,
		Concurrency:    8,
	}, ToolchainConfig{}, func(msg string) {
		progressMu.Lock()
		progress = append(progress, msg)
		progressMu.Unlock()
	})
	if err != nil {
		t.Fatalf("RunPortScan native failed: %v", err)
	}

	if res.Engine != PortScanEngineNative {
		t.Fatalf("Engine = %q, want native", res.Engine)
	}
	if res.TotalScanned != 3 || res.OpenCount != 2 {
		t.Fatalf("TotalScanned=%d OpenCount=%d, want 3 / 2", res.TotalScanned, res.OpenCount)
	}
	if len(res.Hosts) != 1 || len(res.Hosts[0].Ports) != 2 {
		t.Fatalf("unexpected hosts/ports: %+v", res.Hosts)
	}

	byPort := map[int]OpenPort{}
	for _, op := range res.Hosts[0].Ports {
		byPort[op.Port] = op
	}
	p1, ok1 := byPort[port1]
	p2, ok2 := byPort[port2]
	if !ok1 || !ok2 {
		t.Fatalf("missing expected open ports %d, %d in %+v", port1, port2, byPort)
	}
	if !strings.Contains(p1.Banner, "OpenSSH_9.6p1") || p1.Service != "ssh" || p1.Product != "OpenSSH" {
		t.Errorf("unexpected banner/service for listener 1: %+v", p1)
	}
	if !strings.Contains(p2.Banner, "nginx/1.25.4") || p2.Service != "http" || p2.Product != "nginx" || p2.Version != "1.25.4" {
		t.Errorf("unexpected banner/service for listener 2: %+v", p2)
	}
	if len(progress) == 0 {
		t.Errorf("expected progress callbacks to be emitted")
	}
}

func TestParseNmapXML_AndFakeNmapEndToEnd(t *testing.T) {
	sampleXML := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -T4 -p 22,80,443 -sV --version-light -oX - -- 127.0.0.1" version="7.95">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.25.4" extrainfo="TLSv1.3"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15" accuracy="88"/>
      <osmatch name="macOS 14.4" accuracy="96"/>
    </os>
  </host>
  <runstats>
    <finished elapsed="0.42" summary="Nmap done at Wed Nov 25 17:00:00 2026; 1 IP address (1 host up) scanned in 0.42 seconds"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>`

	hosts, err := ParseNmapXML([]byte(sampleXML))
	if err != nil {
		t.Fatalf("ParseNmapXML failed: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	h := hosts[0]
	if h.Address != "127.0.0.1" || h.Hostname != "localhost" || h.State != "up" || h.OSGuess != "macOS 14.4" {
		t.Fatalf("unexpected parsed host: %+v", h)
	}
	if len(h.Ports) != 2 || h.Ports[0].Port != 22 || h.Ports[1].Port != 443 {
		t.Fatalf("expected sorted ports [22, 443], got %+v", h.Ports)
	}
	if h.Ports[1].Product != "nginx" || h.Ports[1].Version != "1.25.4" || h.Ports[1].ExtraInfo != "TLSv1.3" {
		t.Errorf("unexpected port 443 service metadata: %+v", h.Ports[1])
	}

	// End-to-end fake nmap executable verifying allowlisted argv + XML parsing.
	tmp := t.TempDir()
	argsFile := filepath.Join(tmp, "nmap-args.txt")
	xmlFile := filepath.Join(tmp, "nmap-out.xml")
	if err := os.WriteFile(xmlFile, []byte(sampleXML), 0644); err != nil {
		t.Fatal(err)
	}
	fakeNmap := writeFakeScript(t, tmp, "nmap", fmt.Sprintf(`
if [ "$1" = "--version" ]; then
  echo "Nmap version 7.95"
  exit 0
fi
printf '%%s\n' "$@" > %q
echo "Scanning 127.0.0.1 [3 ports]" >&2
cat %q
`, argsFile, xmlFile))

	var progress []string
	res, err := RunPortScan(context.Background(), PortScanRequest{
		Target:            "127.0.0.1",
		Engine:            PortScanEngineNmap,
		Preset:            PresetCustom,
		PortsSpec:         "22,80,443",
		ServiceVersion:    true,
		SkipHostDiscovery: true,
	}, ToolchainConfig{NmapPath: fakeNmap}, func(msg string) {
		progress = append(progress, msg)
	})
	if err != nil {
		t.Fatalf("RunPortScan nmap failed: %v", err)
	}

	rawArgs, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read recorded nmap args: %v", err)
	}
	argv := strings.Fields(string(rawArgs))
	wantArgv := []string{"-sT", "-T4", "-Pn", "-p", "22,80,443", "-sV", "--version-light", "-oX", "-", "--", "127.0.0.1"}
	if !slices.Equal(argv, wantArgv) {
		t.Fatalf("recorded nmap argv = %v, want %v", argv, wantArgv)
	}
	if res.Engine != PortScanEngineNmap || res.OpenCount != 2 || res.TotalScanned != 3 {
		t.Fatalf("unexpected nmap scan result: engine=%s open=%d total=%d", res.Engine, res.OpenCount, res.TotalScanned)
	}
	if !strings.Contains(res.RawXMLSummary, "Nmap done") {
		t.Errorf("unexpected RawXMLSummary: %q", res.RawXMLSummary)
	}
	if len(progress) < 2 {
		t.Errorf("expected progress events from nmap stderr, got %v", progress)
	}
}

func TestEnumerateSubdomains_MockSubfinderCTAndWildcard(t *testing.T) {
	tmp := t.TempDir()
	fakeSubfinder := writeFakeScript(t, tmp, "subfinder", `
if [ "$1" = "-version" ]; then
  echo "v2.6.7"
  exit 0
fi
echo "api.demo.test"
echo "auth.demo.test"
echo "evil.otherdomain.org"
`)

	// Mock CT log server returning crt.sh JSON array.
	ctSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"name_value": "api.demo.test\n*.cdn.demo.test", "common_name": "api.demo.test"},
			{"name_value": "pay.demo.test", "common_name": "pay.demo.test"},
			{"name_value": "unrelated.example.net", "common_name": "unrelated.example.net"},
		})
	}))
	defer ctSrv.Close()

	// Override package DNS resolver hooks hermetically to test wildcard filtering + common DNS.
	origLookupIP := subdomainLookupIP
	origLookupCNAME := subdomainLookupCNAME
	t.Cleanup(func() {
		subdomainLookupIP = origLookupIP
		subdomainLookupCNAME = origLookupCNAME
	})

	const wildcardIP = "203.0.113.99"
	const realGWIP = "198.51.100.10"
	const realAPIIP = "198.51.100.20"

	subdomainLookupIP = func(ctx context.Context, host string) ([]string, error) {
		switch host {
		case "gw.demo.test":
			return []string{realGWIP}, nil
		case "api.demo.test":
			return []string{realAPIIP}, nil
		default:
			// Simulate wildcard DNS returning wildcardIP for nonexistent labels.
			if strings.HasSuffix(host, ".demo.test") {
				return []string{wildcardIP}, nil
			}
			return nil, fmt.Errorf("nxdomain")
		}
	}
	subdomainLookupCNAME = func(ctx context.Context, host string) (string, error) {
		if host == "gw.demo.test" {
			return "gw-edge.cdn.example.net", nil
		}
		return "", nil
	}

	report, err := EnumerateSubdomains(context.Background(), SubdomainRequest{
		Domain:       "demo.test",
		UseSubfinder: true,
		UseCTLog:     true,
		UseCommonDNS: true,
		ResolveDNS:   true,
		CTEndpoint:   ctSrv.URL,
	}, ToolchainConfig{SubfinderPath: fakeSubfinder})
	if err != nil {
		t.Fatalf("EnumerateSubdomains failed: %v", err)
	}

	if !report.WildcardDetected || !slices.Equal(report.WildcardIPs, []string{wildcardIP}) {
		t.Fatalf("expected WildcardDetected with %s, got %v / %v", wildcardIP, report.WildcardDetected, report.WildcardIPs)
	}
	for _, src := range []string{"common_dns", "ct_log", "subfinder"} {
		if !slices.Contains(report.SourcesUsed, src) {
			t.Errorf("expected source %q in SourcesUsed=%v", src, report.SourcesUsed)
		}
	}

	byHost := map[string]SubdomainEntry{}
	for _, s := range report.Subdomains {
		byHost[s.Hostname] = s
	}

	// Out-of-scope domains must NEVER appear.
	if _, bad := byHost["evil.otherdomain.org"]; bad {
		t.Errorf("out-of-scope subfinder host leaked into report")
	}
	if _, bad := byHost["unrelated.example.net"]; bad {
		t.Errorf("out-of-scope CT host leaked into report")
	}
	// Wildcard-only common DNS probes like "jenkins.demo.test" must be filtered out!
	if _, polluted := byHost["jenkins.demo.test"]; polluted {
		t.Errorf("wildcard-polluted common_dns host leaked into report")
	}

	// api.demo.test came from subfinder + ct_log + common_dns (non-wildcard IP).
	apiEntry, ok := byHost["api.demo.test"]
	if !ok {
		t.Fatalf("missing api.demo.test in %+v", byHost)
	}
	if !slices.Contains(apiEntry.Sources, "subfinder") || !slices.Contains(apiEntry.Sources, "ct_log") || !slices.Contains(apiEntry.Sources, "common_dns") {
		t.Errorf("expected merged sources on api.demo.test, got %v", apiEntry.Sources)
	}
	if !slices.Equal(apiEntry.IPs, []string{realAPIIP}) {
		t.Errorf("expected IP %s on api.demo.test, got %v", realAPIIP, apiEntry.IPs)
	}

	// gw.demo.test came from common_dns with real IP & CNAME.
	gwEntry, ok := byHost["gw.demo.test"]
	if !ok {
		t.Fatalf("missing gw.demo.test in %+v", byHost)
	}
	if gwEntry.CNAME != "gw-edge.cdn.example.net" || !slices.Equal(gwEntry.IPs, []string{realGWIP}) {
		t.Errorf("unexpected gw.demo.test entry: %+v", gwEntry)
	}

	// Wildcard prefix stripped from *.cdn.demo.test -> cdn.demo.test.
	if _, ok := byHost["cdn.demo.test"]; !ok {
		t.Errorf("expected cdn.demo.test (stripped from *.cdn.demo.test) in %+v", byHost)
	}
}

func TestManager_AsyncJobsCancelHistoryAndShutdown(t *testing.T) {
	capDir := t.TempDir()
	mgr, err := NewManager(capDir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Shutdown()

	// 1. Toolchain config caching & invalidation.
	tmp := t.TempDir()
	fakeDig := writeFakeScript(t, tmp, "dig", `echo "DiG 9.19.1" >&2`)
	mgr.SetToolchainConfig(ToolchainConfig{
		NmapPath:      filepath.Join(tmp, "missing-nmap"),
		SubfinderPath: filepath.Join(tmp, "missing-sf"),
		WhoisPath:     filepath.Join(tmp, "missing-whois"),
		DigPath:       fakeDig,
	})
	tc1 := mgr.GetToolchain(false)
	tc2 := mgr.GetToolchain(false)
	if !tc1.Dig.Ready || tc1.Dig.Version != "9.19.1" || tc1.CheckedAt != tc2.CheckedAt {
		t.Fatalf("expected cached toolchain result: tc1=%+v tc2=%+v", tc1, tc2)
	}

	// 2. Async site scan job with callbacks + history persistence.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Async Recon Target</title></head><body>ok</body></html>`))
	}))
	defer srv.Close()

	var (
		cbMu     sync.Mutex
		logCount int
		statuses []string
	)
	mgr.SetCallbacks(
		func(ev ReconJobEvent) {
			cbMu.Lock()
			logCount++
			cbMu.Unlock()
		},
		func(st *ReconJobState) {
			cbMu.Lock()
			statuses = append(statuses, st.Status)
			cbMu.Unlock()
		},
	)

	startSnap, err := mgr.StartScanJob(ReconJobRequest{
		Kind:   JobKindSite,
		Target: srv.URL,
		SiteOptions: &SiteProbeOptions{
			SkipDiscovery: true,
			TimeoutMs:     3000,
		},
	})
	if err != nil {
		t.Fatalf("StartScanJob site failed: %v", err)
	}
	if startSnap.Status != StatusRunning || !startSnap.Running {
		t.Fatalf("expected initial running snapshot, got %+v", startSnap)
	}

	doneSnap, err := mgr.WaitJob(context.Background())
	if err != nil {
		t.Fatalf("WaitJob failed: %v", err)
	}
	if doneSnap.Status != StatusDone || doneSnap.Running {
		t.Fatalf("expected done snapshot, got %+v", doneSnap)
	}
	if doneSnap.SiteProfile == nil || doneSnap.SiteProfile.Title != "Async Recon Target" {
		t.Fatalf("unexpected site profile on job state: %+v", doneSnap.SiteProfile)
	}
	if doneSnap.HistoryID == "" {
		t.Fatalf("expected HistoryID to be persisted on completed job")
	}

	cbMu.Lock()
	gotLogs := logCount
	gotStatuses := append([]string(nil), statuses...)
	cbMu.Unlock()
	if gotLogs < 2 || !slices.Contains(gotStatuses, StatusRunning) || !slices.Contains(gotStatuses, StatusDone) {
		t.Fatalf("expected live callbacks, logs=%d statuses=%v", gotLogs, gotStatuses)
	}

	// Verify ClearJobLogs resets events cleanly.
	mgr.ClearJobLogs()
	if st := mgr.GetJobState(); len(st.Events) != 0 || st.EventCount != 0 {
		t.Fatalf("expected cleared job logs, got len=%d count=%d", len(st.Events), st.EventCount)
	}

	// 3. Cancellation of a long-running nmap subprocess + process-group cleanup.
	slowNmap := writeFakeScript(t, tmp, "slow-nmap", `
echo "starting slow scan" >&2
sleep 30
`)
	mgr.SetToolchainConfig(ToolchainConfig{NmapPath: slowNmap})
	_, err = mgr.StartScanJob(ReconJobRequest{
		Kind: JobKindPortScan,
		PortScan: &PortScanRequest{
			Target:    "127.0.0.1",
			Engine:    PortScanEngineNmap,
			Preset:    PresetCustom,
			PortsSpec: "80",
		},
	})
	if err != nil {
		t.Fatalf("StartScanJob slow nmap failed: %v", err)
	}
	time.Sleep(120 * time.Millisecond)

	cancelStart := time.Now()
	if err := mgr.CancelJob(); err != nil {
		t.Fatalf("CancelJob failed: %v", err)
	}
	if elapsed := time.Since(cancelStart); elapsed > 4*time.Second {
		t.Fatalf("CancelJob took too long (%v) — subprocess group not killed cleanly", elapsed)
	}
	cancelledState := mgr.GetJobState()
	if cancelledState.Status != StatusCancelled || cancelledState.Running {
		t.Fatalf("expected cancelled state, got %+v", cancelledState)
	}

	// 4. Persistent history CRUD, path traversal rejection, and 50-entry pruning cap.
	gotHist, ok := mgr.GetHistory(doneSnap.HistoryID)
	if !ok || gotHist.Target != srv.URL {
		t.Fatalf("GetHistory(%q) = (%+v, %v)", doneSnap.HistoryID, gotHist, ok)
	}
	if _, bad := mgr.GetHistory("../etc/passwd"); bad {
		t.Fatalf("expected path traversal GetHistory to fail")
	}
	if err := mgr.DeleteHistory("../escape"); err == nil {
		t.Fatalf("expected path traversal DeleteHistory to fail")
	}
	if err := mgr.DeleteHistory(doneSnap.HistoryID); err != nil {
		t.Fatalf("DeleteHistory failed: %v", err)
	}
	if _, exists := mgr.GetHistory(doneSnap.HistoryID); exists {
		t.Fatalf("expected deleted history entry to be gone")
	}

	// Insert 55 entries and verify strict cap at MaxHistoryEntries (50).
	for i := 0; i < 55; i++ {
		_, sErr := mgr.SaveHistory(ReconHistoryEntry{
			ID:        fmt.Sprintf("hist-%03d", i),
			Kind:      JobKindDomain,
			Target:    fmt.Sprintf("host-%03d.example.com", i),
			Summary:   "ok",
			Status:    StatusDone,
			CreatedAt: fmt.Sprintf("2026-11-25T17:00:%02d.000000Z", i),
		})
		if sErr != nil {
			t.Fatalf("SaveHistory #%d failed: %v", i, sErr)
		}
	}
	listed := mgr.ListHistory()
	if len(listed) != MaxHistoryEntries {
		t.Fatalf("expected history capped at %d entries, got %d", MaxHistoryEntries, len(listed))
	}
	if listed[0].ID != "hist-054" || listed[len(listed)-1].ID != "hist-005" {
		t.Fatalf("unexpected newest/oldest after pruning: newest=%s oldest=%s", listed[0].ID, listed[len(listed)-1].ID)
	}

	if err := mgr.ClearHistory(); err != nil {
		t.Fatalf("ClearHistory failed: %v", err)
	}
	if remaining := mgr.ListHistory(); len(remaining) != 0 {
		t.Fatalf("expected 0 entries after ClearHistory, got %d", len(remaining))
	}
}

func TestHardeningEdgeCases(t *testing.T) {
	// 1. ParseNmapXML rejects empty and malformed XML cleanly.
	if _, err := ParseNmapXML(nil); err == nil {
		t.Fatal("expected empty nmap XML to fail")
	}
	if _, err := ParseNmapXML([]byte("   \n\t  ")); err == nil {
		t.Fatal("expected whitespace-only nmap XML to fail")
	}
	if _, err := ParseNmapXML([]byte("<nmaprun><host><broken>")); err == nil {
		t.Fatal("expected malformed nmap XML to fail")
	}

	// 2. ProbeSite rejects redirect chains exceeding MaxRedirects (10).
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		http.Redirect(w, r, fmt.Sprintf("/hop/%d", n+1), http.StatusFound)
	}))
	defer redirSrv.Close()
	if _, err := ProbeSite(context.Background(), redirSrv.URL+"/hop/0", SiteProbeOptions{
		SkipDiscovery: true,
		TimeoutMs:     3000,
	}); err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("expected >10 redirect rejection error, got %v", err)
	}

	// 3. Fake nmap with IPv6 target passes -6 and handles >64 KiB stderr line cleanly.
	tmp := t.TempDir()
	argsFile := filepath.Join(tmp, "ipv6-args.txt")
	fakeNmap := writeFakeScript(t, tmp, "nmap", fmt.Sprintf(`
printf '%%s\n' "$@" > %q
# Emit a >70 KiB stderr line plus a trailing line without newline.
head -c 72000 /dev/zero | tr '\0' 'X' >&2
printf '\ntrailing-stderr-line' >&2
cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="::1" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
EOF
`, argsFile))

	var progress []string
	res, err := RunPortScan(context.Background(), PortScanRequest{
		Target:    "::1",
		Engine:    PortScanEngineNmap,
		Preset:    PresetCustom,
		PortsSpec: "8080",
	}, ToolchainConfig{NmapPath: fakeNmap}, func(msg string) {
		progress = append(progress, msg)
	})
	if err != nil {
		t.Fatalf("RunPortScan IPv6 failed: %v", err)
	}
	rawArgs, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read ipv6 args: %v", err)
	}
	argv := strings.Fields(string(rawArgs))
	wantArgv := []string{"-sT", "-T4", "-6", "-p", "8080", "-oX", "-", "--", "::1"}
	if !slices.Equal(argv, wantArgv) {
		t.Fatalf("IPv6 nmap argv = %v, want %v", argv, wantArgv)
	}
	if res.OpenCount != 1 || len(res.Hosts) != 1 || res.Hosts[0].Address != "::1" {
		t.Fatalf("unexpected IPv6 nmap result: %+v", res)
	}
	if !slices.Contains(progress, "[nmap] trailing-stderr-line") {
		t.Errorf("expected trailing stderr line to be flushed without race, got %v", progress)
	}

	// 4. Custom CTEndpoint with percent-encoded query (%25.%s) does not corrupt %25.
	var gotRawQuery string
	ctSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name_value":"ok.pct.test"}]`))
	}))
	defer ctSrv.Close()

	subRep, err := EnumerateSubdomains(context.Background(), SubdomainRequest{
		Domain:     "pct.test",
		UseCTLog:   true,
		CTEndpoint: ctSrv.URL + "/?q=%25.%s&output=json",
	}, ToolchainConfig{})
	if err != nil {
		t.Fatalf("EnumerateSubdomains CT template failed: %v", err)
	}
	if gotRawQuery != "q=%25.pct.test&output=json" {
		t.Fatalf("CT endpoint query corrupted: got %q, want %q", gotRawQuery, "q=%25.pct.test&output=json")
	}
	if subRep.TotalCount != 1 || subRep.Subdomains[0].Hostname != "ok.pct.test" {
		t.Fatalf("unexpected CT subdomain report: %+v", subRep)
	}

	// 5. Manager rejects leading-dot history IDs and IP subdomain jobs synchronously.
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Shutdown()

	for _, badID := range []string{".", "..", ".hidden", ".DS_Store"} {
		if _, ok := mgr.GetHistory(badID); ok {
			t.Errorf("GetHistory(%q) unexpectedly succeeded", badID)
		}
		if err := mgr.DeleteHistory(badID); err == nil {
			t.Errorf("DeleteHistory(%q) unexpectedly succeeded", badID)
		}
	}
	if _, err := mgr.StartScanJob(ReconJobRequest{
		Kind:   JobKindSubdomain,
		Target: "127.0.0.1",
	}); err == nil {
		t.Fatal("expected StartScanJob(subdomain, IP) to fail synchronously")
	}

	// 6. AnalyzeDomain propagates cancelled context error.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AnalyzeDomain(canceledCtx, "127.0.0.1", ToolchainConfig{}); err == nil {
		t.Fatal("expected AnalyzeDomain to propagate cancelled context error")
	}
}
