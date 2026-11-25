package recon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultDNSTimeout   = 5 * time.Second
	defaultWhoisTimeout = 8 * time.Second
	defaultTLSTimeout   = 6 * time.Second
)

var multiPartPublicSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "net.uk": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"com.hk": true, "org.hk": true, "gov.hk": true, "edu.hk": true,
	"com.tw": true, "org.tw": true, "gov.tw": true, "edu.tw": true,
	"com.au": true, "net.au": true, "org.au": true, "gov.au": true, "edu.au": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "go.jp": true, "ac.jp": true,
	"co.kr": true, "or.kr": true, "go.kr": true,
	"com.sg": true, "org.sg": true, "gov.sg": true,
	"com.br": true, "org.br": true, "gov.br": true,
	"com.mx": true, "org.mx": true, "gob.mx": true,
	"co.in": true, "net.in": true, "org.in": true, "gov.in": true,
	"co.nz": true, "org.nz": true, "govt.nz": true,
	"com.tr": true, "com.my": true, "com.vn": true, "co.id": true,
	"com.ph": true, "com.ar": true, "co.za": true, "com.ru": true,
}

type infraPattern struct {
	Needle   string
	Provider string
	IsWAF    bool
}

var dnsInfraPatterns = []infraPattern{
	{Needle: "cloudflare", Provider: "Cloudflare", IsWAF: true},
	{Needle: "akamaiedge", Provider: "Akamai", IsWAF: true},
	{Needle: "akamaitechnologies", Provider: "Akamai", IsWAF: true},
	{Needle: "edgesuite.net", Provider: "Akamai", IsWAF: false},
	{Needle: "edgekey.net", Provider: "Akamai", IsWAF: true},
	{Needle: "akamai", Provider: "Akamai", IsWAF: false},
	{Needle: "fastly", Provider: "Fastly", IsWAF: false},
	{Needle: "cloudfront.net", Provider: "AWS CloudFront", IsWAF: false},
	{Needle: "awsdns-", Provider: "AWS Route53", IsWAF: false},
	{Needle: "amazonaws.com", Provider: "AWS", IsWAF: false},
	{Needle: "alikunlun", Provider: "Aliyun CDN", IsWAF: false},
	{Needle: "kunlun", Provider: "Aliyun CDN", IsWAF: false},
	{Needle: "aliyuncs.com", Provider: "Alibaba Cloud", IsWAF: false},
	{Needle: "alidns", Provider: "Aliyun DNS", IsWAF: false},
	{Needle: "hichina.com", Provider: "Aliyun DNS", IsWAF: false},
	{Needle: "yundunwaf", Provider: "Aliyun WAF", IsWAF: true},
	{Needle: "cdn.dnsv1.com", Provider: "Tencent Cloud CDN", IsWAF: false},
	{Needle: "cdntip.com", Provider: "Tencent Cloud CDN", IsWAF: false},
	{Needle: "qcloudcdn", Provider: "Tencent Cloud CDN", IsWAF: false},
	{Needle: "dnspod.net", Provider: "Tencent DNSPod", IsWAF: false},
	{Needle: "eo.dnse", Provider: "Tencent EdgeOne", IsWAF: true},
	{Needle: "qiniudns", Provider: "Qiniu CDN", IsWAF: false},
	{Needle: "qbox.me", Provider: "Qiniu CDN", IsWAF: false},
	{Needle: "clouddn.com", Provider: "Qiniu CDN", IsWAF: false},
	{Needle: "wscdns", Provider: "Wangsu CDN", IsWAF: false},
	{Needle: "wscloudcdn", Provider: "Wangsu CDN", IsWAF: false},
	{Needle: "lxdns.com", Provider: "Wangsu CDN", IsWAF: false},
	{Needle: "chinanetcenter", Provider: "Wangsu CDN", IsWAF: false},
	{Needle: "cdnhwc", Provider: "Huawei Cloud CDN", IsWAF: false},
	{Needle: "huaweicloud", Provider: "Huawei Cloud", IsWAF: false},
	{Needle: "hwcdn", Provider: "Huawei Cloud CDN", IsWAF: false},
	{Needle: "yunjiasu", Provider: "Baidu Cloud CDN", IsWAF: true},
	{Needle: "bdydns", Provider: "Baidu Cloud", IsWAF: false},
	{Needle: "incapdns.net", Provider: "Imperva", IsWAF: true},
	{Needle: "impervadns.net", Provider: "Imperva", IsWAF: true},
	{Needle: "azurefd.net", Provider: "Azure Front Door", IsWAF: true},
	{Needle: "azureedge.net", Provider: "Azure CDN", IsWAF: false},
	{Needle: "azure-dns", Provider: "Azure DNS", IsWAF: false},
	{Needle: "ghs.googlehosted.com", Provider: "Google Cloud", IsWAF: false},
	{Needle: "ns-cloud-", Provider: "Google Cloud DNS", IsWAF: false},
	{Needle: "googledomains", Provider: "Google Cloud DNS", IsWAF: false},
	{Needle: "sucuri.net", Provider: "Sucuri", IsWAF: true},
	{Needle: "stackpathdns", Provider: "StackPath CDN", IsWAF: false},
	{Needle: "netlify.app", Provider: "Netlify", IsWAF: false},
	{Needle: "netlify.com", Provider: "Netlify", IsWAF: false},
	{Needle: "vercel-dns.com", Provider: "Vercel", IsWAF: false},
	{Needle: "vercel.app", Provider: "Vercel", IsWAF: false},
}

// NormalizeDomainTarget validates and normalizes a URL or bare hostname/IP target.
// It strips scheme, port, and path, lowercases the hostname, and rejects empty,
// malformed, shell-unsafe, or leading-hyphen inputs.
func NormalizeDomainTarget(raw string) (host string, port int, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, errors.New("recon: target is empty")
	}
	if strings.HasPrefix(s, "-") {
		return "", 0, fmt.Errorf("recon: invalid target %q: leading hyphen is not allowed", raw)
	}
	if hasUnsafeControlOrShellChars(s, true) {
		return "", 0, fmt.Errorf("recon: invalid target %q: contains disallowed characters", raw)
	}

	if strings.Contains(s, "://") {
		u, parseErr := url.Parse(s)
		if parseErr != nil {
			return "", 0, fmt.Errorf("recon: parse target URL: %w", parseErr)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", 0, fmt.Errorf("recon: unsupported URL scheme %q (expected http or https)", u.Scheme)
		}
		host = strings.TrimSpace(u.Hostname())
		if ps := strings.TrimSpace(u.Port()); ps != "" {
			p, convErr := strconv.Atoi(ps)
			if convErr != nil || p < 1 || p > 65535 {
				return "", 0, fmt.Errorf("recon: invalid port %q", ps)
			}
			port = p
		}
	} else {
		// Check bare IPv4/IPv6 first so IPv6 colons aren't confused with host:port.
		if ip := net.ParseIP(s); ip != nil {
			return ip.String(), 0, nil
		}
		// Strip any path/query/fragment suffix.
		if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
			s = s[:idx]
		}
		if s == "" {
			return "", 0, fmt.Errorf("recon: invalid target %q", raw)
		}
		if strings.HasPrefix(s, "[") || strings.Count(s, ":") == 1 {
			h, ps, splitErr := net.SplitHostPort(s)
			if splitErr != nil {
				return "", 0, fmt.Errorf("recon: invalid host:port %q: %w", raw, splitErr)
			}
			p, convErr := strconv.Atoi(ps)
			if convErr != nil || p < 1 || p > 65535 {
				return "", 0, fmt.Errorf("recon: invalid port %q", ps)
			}
			host = h
			port = p
		} else {
			host = s
		}
	}

	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return "", 0, fmt.Errorf("recon: empty host in target %q", raw)
	}
	if strings.HasPrefix(host, "-") {
		return "", 0, fmt.Errorf("recon: invalid host %q: leading hyphen is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), port, nil
	}
	if !isValidHostname(host) {
		return "", 0, fmt.Errorf("recon: invalid hostname %q", host)
	}
	return host, port, nil
}

// ExtractRootDomain derives the registrable root domain (eTLD+1 approximation)
// for a normalized hostname. IPs and single-label hostnames are returned unchanged.
func ExtractRootDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || net.ParseIP(host) != nil {
		return host
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	lastTwo := labels[len(labels)-2] + "." + labels[len(labels)-1]
	if multiPartPublicSuffixes[lastTwo] && len(labels) >= 3 {
		return labels[len(labels)-3] + "." + lastTwo
	}
	return lastTwo
}

// AnalyzeDomain performs comprehensive domain intelligence: pure-Go DNS records,
// CDN/WAF fingerprinting, WHOIS metadata lookup, and live TLS certificate inspection.
func AnalyzeDomain(ctx context.Context, target string, cfg ToolchainConfig) (*DomainReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	host, explicitPort, err := NormalizeDomainTarget(target)
	if err != nil {
		return nil, err
	}

	rootDomain := ExtractRootDomain(host)
	report := &DomainReport{
		Target:     host,
		RootDomain: rootDomain,
		IPv4:       []string{},
		IPv6:       []string{},
		DNSRecords: DNSRecords{
			A:    []string{},
			AAAA: []string{},
			MX:   []MXRecord{},
			NS:   []string{},
			TXT:  []string{},
			PTR:  []string{},
		},
		CDNProviders: []string{},
		WAFHints:     []string{},
		CheckedAt:    nowRFC3339(),
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		warnings []string
	)
	addWarn := func(msg string) {
		if strings.TrimSpace(msg) == "" {
			return
		}
		mu.Lock()
		warnings = append(warnings, msg)
		mu.Unlock()
	}

	// 1. Pure-Go DNS record resolution.
	wg.Add(1)
	go func() {
		defer wg.Done()
		dnsCtx, cancel := context.WithTimeout(ctx, defaultDNSTimeout)
		defer cancel()
		recs, v4, v6, dnsWarn := lookupAllDNS(dnsCtx, host)
		mu.Lock()
		report.DNSRecords = recs
		report.IPv4 = v4
		report.IPv6 = v6
		mu.Unlock()
		if dnsWarn != "" {
			addWarn(dnsWarn)
		}
	}()

	// 2. WHOIS lookup (for non-IP domains).
	if net.ParseIP(host) == nil && strings.Contains(rootDomain, ".") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			whoisCtx, cancel := context.WithTimeout(ctx, defaultWhoisTimeout)
			defer cancel()
			ws, wErr := LookupWhois(whoisCtx, rootDomain, cfg.WhoisPath)
			if wErr != nil {
				addWarn("whois: " + wErr.Error())
				return
			}
			mu.Lock()
			report.Whois = ws
			mu.Unlock()
		}()
	}

	// 3. Live TLS inspection.
	tlsPort := 443
	if explicitPort > 0 {
		tlsPort = explicitPort
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		tlsCtx, cancel := context.WithTimeout(ctx, defaultTLSTimeout)
		defer cancel()
		tlsRep, tErr := InspectTLS(tlsCtx, host, tlsPort)
		if tErr != nil {
			addWarn(fmt.Sprintf("tls (%s:%d): %v", host, tlsPort, tErr))
			return
		}
		mu.Lock()
		report.TLS = tlsRep
		mu.Unlock()
	}()

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cdn, waf := DetectCDNAndWAF(report.DNSRecords.CNAME, report.DNSRecords.NS, report.DNSRecords.TXT, host)
	report.CDNProviders = cdn
	report.WAFHints = waf
	if len(warnings) > 0 {
		sort.Strings(warnings)
		report.Warnings = warnings
	}
	report.ElapsedMs = time.Since(start).Milliseconds()
	return report, nil
}

func lookupAllDNS(ctx context.Context, host string) (DNSRecords, []string, []string, string) {
	recs := DNSRecords{
		A:    []string{},
		AAAA: []string{},
		MX:   []MXRecord{},
		NS:   []string{},
		TXT:  []string{},
		PTR:  []string{},
	}
	v4Set := make(map[string]bool)
	v6Set := make(map[string]bool)

	resolver := net.DefaultResolver
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ipErr error

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			v4Set[ip4.String()] = true
		} else {
			v6Set[ip.String()] = true
		}
	} else {
		wg.Add(5)
		go func() {
			defer wg.Done()
			addrs, err := resolver.LookupIPAddr(ctx, host)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				ipErr = err
				return
			}
			for _, a := range addrs {
				if ip4 := a.IP.To4(); ip4 != nil {
					v4Set[ip4.String()] = true
				} else if a.IP != nil {
					v6Set[a.IP.String()] = true
				}
			}
		}()
		go func() {
			defer wg.Done()
			cname, err := resolver.LookupCNAME(ctx, host)
			if err != nil {
				return
			}
			cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
			if cname != "" && cname != host {
				mu.Lock()
				recs.CNAME = cname
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			mxs, err := resolver.LookupMX(ctx, host)
			if err != nil {
				return
			}
			out := make([]MXRecord, 0, len(mxs))
			for _, m := range mxs {
				h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(m.Host), "."))
				if h != "" {
					out = append(out, MXRecord{Host: h, Pref: m.Pref})
				}
			}
			sort.Slice(out, func(i, j int) bool {
				if out[i].Pref != out[j].Pref {
					return out[i].Pref < out[j].Pref
				}
				return out[i].Host < out[j].Host
			})
			mu.Lock()
			recs.MX = out
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			nss, err := resolver.LookupNS(ctx, host)
			if err != nil {
				return
			}
			seen := make(map[string]bool)
			var out []string
			for _, n := range nss {
				h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n.Host), "."))
				if h != "" && !seen[h] {
					seen[h] = true
					out = append(out, h)
				}
			}
			sort.Strings(out)
			mu.Lock()
			recs.NS = out
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			txts, err := resolver.LookupTXT(ctx, host)
			if err != nil {
				return
			}
			mu.Lock()
			recs.TXT = append(recs.TXT, txts...)
			mu.Unlock()
		}()
		wg.Wait()
	}

	v4 := mapKeysSorted(v4Set)
	v6 := mapKeysSorted(v6Set)
	recs.A = append([]string{}, v4...)
	recs.AAAA = append([]string{}, v6...)

	// PTR reverse lookup for up to 3 resolved IP addresses.
	ptrTargets := make([]string, 0, 3)
	for _, ip := range v4 {
		if len(ptrTargets) < 3 {
			ptrTargets = append(ptrTargets, ip)
		}
	}
	for _, ip := range v6 {
		if len(ptrTargets) < 3 {
			ptrTargets = append(ptrTargets, ip)
		}
	}
	if len(ptrTargets) > 0 {
		ptrSeen := make(map[string]bool)
		var ptrWG sync.WaitGroup
		for _, ip := range ptrTargets {
			ptrWG.Add(1)
			go func(addr string) {
				defer ptrWG.Done()
				pCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				names, err := resolver.LookupAddr(pCtx, addr)
				if err != nil {
					return
				}
				mu.Lock()
				for _, n := range names {
					n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
					if n != "" && !ptrSeen[n] {
						ptrSeen[n] = true
					}
				}
				mu.Unlock()
			}(ip)
		}
		ptrWG.Wait()
		recs.PTR = mapKeysSorted(ptrSeen)
	}

	warn := ""
	if ipErr != nil && len(v4) == 0 && len(v6) == 0 && recs.CNAME == "" && len(recs.NS) == 0 {
		warn = fmt.Sprintf("dns resolution failed: %v", ipErr)
	}
	return recs, v4, v6, warn
}

// DetectCDNAndWAF inspects CNAME, NS, TXT, and host strings for known CDN and WAF providers.
func DetectCDNAndWAF(cname string, ns, txt []string, host string) (cdn []string, waf []string) {
	cdnSet := make(map[string]bool)
	wafSet := make(map[string]bool)

	candidates := make([]string, 0, 2+len(ns)+len(txt))
	if cname != "" {
		candidates = append(candidates, strings.ToLower(cname))
	}
	if host != "" {
		candidates = append(candidates, strings.ToLower(host))
	}
	for _, n := range ns {
		candidates = append(candidates, strings.ToLower(n))
	}
	for _, t := range txt {
		candidates = append(candidates, strings.ToLower(t))
	}

	for _, c := range candidates {
		for _, pat := range dnsInfraPatterns {
			if strings.Contains(c, pat.Needle) {
				cdnSet[pat.Provider] = true
				if pat.IsWAF {
					wafSet[pat.Provider] = true
				}
			}
		}
	}

	return mapKeysSorted(cdnSet), mapKeysSorted(wafSet)
}

// LookupWhois invokes the host whois binary directly (never via a shell) for a
// validated domain and parses structured registration fields with raw output capped at 32 KiB.
func LookupWhois(ctx context.Context, domain, whoisPath string) (*WhoisSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	host, _, err := NormalizeDomainTarget(domain)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(host, "-") {
		return nil, fmt.Errorf("recon: refusing whois target with leading hyphen: %q", host)
	}

	bin, ok := resolveToolBinary(whoisPath, "whois")
	if !ok {
		return nil, errors.New("whois binary not found on host")
	}

	wCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		wCtx, cancel = context.WithTimeout(ctx, defaultWhoisTimeout)
		defer cancel()
	}

	// Pass the strictly validated host directly without a shell; host is guaranteed
	// never to begin with '-' or contain shell metacharacters.
	cmd := exec.CommandContext(wCtx, bin, host)
	configureProcGroup(cmd)
	var outBuf cappedBuffer
	outBuf.limit = MaxWhoisRawBytes + 1
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	runErr := cmd.Run()
	rawBytes := outBuf.Bytes()
	truncated := len(rawBytes) > MaxWhoisRawBytes
	if truncated {
		rawBytes = rawBytes[:MaxWhoisRawBytes]
	}
	rawText := strings.TrimSpace(string(rawBytes))

	if runErr != nil && rawText == "" {
		return nil, fmt.Errorf("whois failed: %w", runErr)
	}

	summary := ParseWhoisOutput(host, rawText)
	summary.Truncated = truncated
	return summary, nil
}

// ParseWhoisOutput parses structured fields from raw WHOIS text.
func ParseWhoisOutput(domain, raw string) *WhoisSummary {
	truncated := false
	if len(raw) > MaxWhoisRawBytes {
		raw = raw[:MaxWhoisRawBytes]
		truncated = true
	}
	summary := &WhoisSummary{
		Domain:      domain,
		NameServers: []string{},
		Statuses:    []string{},
		Raw:         raw,
		Truncated:   truncated,
	}

	nsSet := make(map[string]bool)
	statusSet := make(map[string]bool)

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		if val == "" {
			continue
		}

		switch key {
		case "registrar", "sponsoring registrar", "registrar name":
			if summary.Registrar == "" {
				summary.Registrar = val
			}
		case "creation date", "created on", "created", "registration time", "registered on", "created date":
			if summary.CreationDate == "" {
				summary.CreationDate = val
			}
		case "registry expiry date", "registrar registration expiration date", "expiration time", "expiration date", "expiry date", "expires on", "paid-till":
			if summary.ExpiryDate == "" {
				summary.ExpiryDate = val
			}
		case "updated date", "last updated on", "last modified", "changed", "modified":
			if summary.UpdatedDate == "" {
				summary.UpdatedDate = val
			}
		case "name server", "nserver", "nameserver", "dns":
			// Strip optional trailing IP annotation (e.g. "ns1.example.com 1.2.3.4")
			fields := strings.Fields(val)
			if len(fields) > 0 {
				ns := strings.ToLower(strings.TrimSuffix(fields[0], "."))
				if ns != "" {
					nsSet[ns] = true
				}
			}
		case "domain status", "status":
			// Strip explanatory EPP URL suffix if present.
			fields := strings.Fields(val)
			if len(fields) > 0 {
				statusSet[fields[0]] = true
			}
		}
	}

	summary.NameServers = mapKeysSorted(nsSet)
	summary.Statuses = mapKeysSorted(statusSet)
	return summary
}

// InspectTLS dials host:port via pure-Go TLS (default port 443) and inspects
// the negotiated protocol, cipher suite, ALPN, and full peer certificate chain.
// Certificates are always captured even if untrusted or expired, with Verified
// and VerifyError reporting standard x509 chain verification status.
func InspectTLS(ctx context.Context, host string, port int) (*TLSInspectReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	normHost, parsedPort, err := NormalizeDomainTarget(host)
	if err != nil {
		return nil, err
	}
	if port <= 0 {
		if parsedPort > 0 {
			port = parsedPort
		} else {
			port = 443
		}
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("recon: invalid TLS port %d", port)
	}

	serverName := ""
	if net.ParseIP(normHost) == nil {
		serverName = normHost
	}

	dialCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		dialCtx, cancel = context.WithTimeout(ctx, defaultTLSTimeout)
		defer cancel()
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: defaultTLSTimeout},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // Always capture certs; verified explicitly below.
			NextProtos:         []string{"h2", "http/1.1"},
		},
	}

	addr := net.JoinHostPort(normHost, strconv.Itoa(port))
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok {
		return nil, errors.New("recon: unexpected non-TLS connection")
	}
	cs := tlsConn.ConnectionState()

	now := time.Now().UTC()
	report := &TLSInspectReport{
		Host:        normHost,
		Port:        port,
		ServerName:  serverName,
		TLSVersion:  tlsVersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
		ALPN:        cs.NegotiatedProtocol,
		Chain:       make([]TLSCertInfo, 0, len(cs.PeerCertificates)),
		ElapsedMs:   time.Since(start).Milliseconds(),
		CheckedAt:   now.Format(time.RFC3339),
	}

	if len(cs.PeerCertificates) > 0 {
		for _, cert := range cs.PeerCertificates {
			report.Chain = append(report.Chain, buildTLSCertInfo(cert, now))
		}
		leafCopy := report.Chain[0]
		report.Leaf = &leafCopy

		intermediates := x509.NewCertPool()
		for _, ic := range cs.PeerCertificates[1:] {
			intermediates.AddCert(ic)
		}
		verifyOpts := x509.VerifyOptions{
			DNSName:       normHost,
			Intermediates: intermediates,
			CurrentTime:   now,
		}
		if _, vErr := cs.PeerCertificates[0].Verify(verifyOpts); vErr != nil {
			report.Verified = false
			report.VerifyError = vErr.Error()
		} else {
			report.Verified = true
		}
	}

	return report, nil
}

func buildTLSCertInfo(cert *x509.Certificate, now time.Time) TLSCertInfo {
	sum := sha256.Sum256(cert.Raw)
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		sans = append(sans, u.String())
	}

	daysUntil := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24.0))
	selfSigned := cert.Issuer.String() == cert.Subject.String() && cert.CheckSignatureFrom(cert) == nil

	algo, bits := publicKeyDetails(cert)

	return TLSCertInfo{
		Subject:           cert.Subject.String(),
		CommonName:        cert.Subject.CommonName,
		Issuer:            cert.Issuer.String(),
		Serial:            strings.ToUpper(cert.SerialNumber.Text(16)),
		NotBefore:         cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          cert.NotAfter.UTC().Format(time.RFC3339),
		DaysUntilExpiry:   daysUntil,
		Expired:           now.After(cert.NotAfter),
		SelfSigned:        selfSigned,
		IsCA:              cert.IsCA,
		SANs:              sans,
		SHA256Fingerprint: hex.EncodeToString(sum[:]),
		PubKeyAlgo:        algo,
		PubKeyBits:        bits,
		SignatureAlgo:     cert.SignatureAlgorithm.String(),
	}
}

func publicKeyDetails(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// --- Shared validation & buffer helpers ------------------------------------

func hasUnsafeControlOrShellChars(s string, allowURLChars bool) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
		switch r {
		case ';', '&', '|', '$', '`', '(', ')', '<', '>', '\\', '\'', '"', '*', '{', '}':
			return true
		case '?', '#', '%', '=', '+', '@':
			if !allowURLChars {
				return true
			}
		}
	}
	return false
}

func isValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	if strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func mapKeysSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// cappedBuffer writes up to limit bytes into an internal bytes.Buffer and
// silently discards excess bytes (still implementing io.Writer without error)
// so subprocesses never block on full pipes.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	origLen := len(p)
	if c.limit <= 0 {
		return origLen, nil
	}
	rem := c.limit - c.buf.Len()
	if rem > 0 {
		if len(p) > rem {
			p = p[:rem]
		}
		_, _ = c.buf.Write(p)
	}
	return origLen, nil
}

func (c *cappedBuffer) Bytes() []byte {
	return c.buf.Bytes()
}

func readBodyCapped(r io.Reader, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}
