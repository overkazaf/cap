package recon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultSiteTimeoutMs = 10000
	defaultReconUA       = "cap-recon/1.0 (+authorized-diagnostics)"
)

var (
	htmlTitleRe     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaTagRe       = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	metaAttrNameRe  = regexp.MustCompile(`(?i)\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	metaAttrContRe  = regexp.MustCompile(`(?i)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	hstsMaxAgeRe    = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)
	headerVersionRe = regexp.MustCompile(`(?i)([a-z0-9._-]+)/(\d+(?:\.\d+)*)`)
)

// NormalizeSiteURL validates and normalizes an HTTP/HTTPS site URL.
// Bare hosts default to https://; non-HTTP schemes, empty strings, leading
// hyphens, and shell-unsafe inputs are rejected.
func NormalizeSiteURL(rawURL string) (normalized string, hadScheme bool, err error) {
	s := strings.TrimSpace(rawURL)
	if s == "" {
		return "", false, errors.New("recon: site URL is empty")
	}
	if strings.HasPrefix(s, "-") {
		return "", false, fmt.Errorf("recon: invalid site URL %q: leading hyphen is not allowed", rawURL)
	}
	if hasUnsafeControlOrShellChars(s, true) {
		return "", false, fmt.Errorf("recon: invalid site URL %q: contains disallowed characters", rawURL)
	}

	if strings.Contains(s, "://") {
		hadScheme = true
	} else {
		s = "https://" + s
	}

	u, parseErr := url.Parse(s)
	if parseErr != nil {
		return "", hadScheme, fmt.Errorf("recon: parse URL %q: %w", rawURL, parseErr)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", hadScheme, fmt.Errorf("recon: unsupported URL scheme %q (expected http or https)", u.Scheme)
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", hadScheme, fmt.Errorf("recon: missing hostname in URL %q", rawURL)
	}
	if strings.HasPrefix(host, "-") {
		return "", hadScheme, fmt.Errorf("recon: invalid hostname %q in URL", host)
	}
	if net.ParseIP(host) == nil && !isValidHostname(strings.ToLower(strings.TrimSuffix(host, "."))) {
		return "", hadScheme, fmt.Errorf("recon: invalid hostname %q in URL", host)
	}
	if ps := u.Port(); ps != "" {
		p, convErr := strconv.Atoi(ps)
		if convErr != nil || p < 1 || p > 65535 {
			return "", hadScheme, fmt.Errorf("recon: invalid port %q in URL", ps)
		}
	}
	u.Scheme = scheme
	return u.String(), hadScheme, nil
}

// ProbeSite fetches the target HTTP/HTTPS URL, records redirects, fingerprints
// web technologies/CDN/WAF, audits HTTP security headers, and optionally runs
// bounded discovery probes for robots.txt, sitemap.xml, .well-known, and favicon.
func ProbeSite(ctx context.Context, rawURL string, opts SiteProbeOptions) (*SiteProfile, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	targetURL, hadScheme, err := NormalizeSiteURL(rawURL)
	if err != nil {
		return nil, err
	}

	timeoutMs := opts.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = defaultSiteTimeoutMs
	}
	if timeoutMs < 1000 {
		timeoutMs = 1000
	}
	if timeoutMs > 60000 {
		timeoutMs = 60000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	ua := strings.TrimSpace(opts.UserAgent)
	if ua == "" {
		ua = defaultReconUA
	}

	var transport http.RoundTripper
	var ownTransport *http.Transport
	if opts.Client != nil && opts.Client.Transport != nil {
		transport = opts.Client.Transport
	} else {
		ownTransport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   minDuration(timeout, 6*time.Second),
				KeepAlive: 15 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: minDuration(timeout, 6*time.Second),
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        16,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.InsecureSkipVerify,
			},
		}
		defer ownTransport.CloseIdleConnections()
		transport = ownTransport
	}

	var (
		redirMu       sync.Mutex
		redirectChain = []RedirectHop{}
		warnings      []string
	)

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 {
				prev := via[len(via)-1]
				hop := RedirectHop{
					URL: prev.URL.String(),
				}
				if req.Response != nil {
					hop.StatusCode = req.Response.StatusCode
					hop.Location = req.Response.Header.Get("Location")
				}
				redirMu.Lock()
				redirectChain = append(redirectChain, hop)
				redirMu.Unlock()
			}
			if opts.NoRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", MaxRedirects)
			}
			return nil
		},
	}

	doFetch := func(fetchURL string) (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		for k, v := range opts.CustomHeaders {
			if strings.TrimSpace(k) != "" {
				req.Header.Set(k, v)
			}
		}
		return client.Do(req)
	}

	resp, fetchErr := doFetch(targetURL)
	if fetchErr != nil && !hadScheme && ctx.Err() == nil && strings.HasPrefix(targetURL, "https://") {
		// Bare host defaulted to HTTPS and failed; fall back cleanly to HTTP.
		fallbackURL := "http://" + strings.TrimPrefix(targetURL, "https://")
		redirMu.Lock()
		redirectChain = []RedirectHop{}
		redirMu.Unlock()
		resp2, fbErr := doFetch(fallbackURL)
		if fbErr == nil {
			warnings = append(warnings, fmt.Sprintf("HTTPS probe failed (%v); fell back to HTTP", fetchErr))
			resp = resp2
			fetchErr = nil
		}
	}
	if fetchErr != nil {
		return nil, fmt.Errorf("probe site %s: %w", targetURL, fetchErr)
	}
	defer resp.Body.Close()

	bodyBytes, truncated, readErr := readBodyCapped(resp.Body, MaxHTTPBodyBytes)
	if readErr != nil {
		warnings = append(warnings, fmt.Sprintf("response body read error: %v", readErr))
	}
	if truncated {
		warnings = append(warnings, fmt.Sprintf("response body truncated at %d bytes", MaxHTTPBodyBytes))
	}

	finalURL := targetURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	flatHeaders := flattenHeaders(resp.Header)
	bodyText := string(bodyBytes)
	title := extractHTMLTitle(bodyText)
	metaGen := extractMetaGenerator(bodyText)

	contentLen := resp.ContentLength
	if contentLen < 0 {
		contentLen = int64(len(bodyBytes))
	}

	techs, cdnProviders, wafHints := DetectTechnologies(resp.Header, resp.Cookies(), bodyText, metaGen, finalURL)
	isHTTPS := strings.HasPrefix(strings.ToLower(finalURL), "https://")
	secHeaders, secScore := AuditSecurityHeaders(resp.Header, isHTTPS)

	redirMu.Lock()
	chainCopy := append([]RedirectHop{}, redirectChain...)
	redirMu.Unlock()

	profile := &SiteProfile{
		TargetURL:       targetURL,
		FinalURL:        finalURL,
		StatusCode:      resp.StatusCode,
		Protocol:        resp.Proto,
		Title:           title,
		MetaGenerator:   metaGen,
		Server:          strings.TrimSpace(resp.Header.Get("Server")),
		ContentType:     strings.TrimSpace(resp.Header.Get("Content-Type")),
		ContentLength:   contentLen,
		RedirectChain:   chainCopy,
		Headers:         flatHeaders,
		Technologies:    techs,
		CDNProviders:    cdnProviders,
		WAFHints:        wafHints,
		SecurityHeaders: secHeaders,
		SecurityScore:   secScore,
		SitemapURLs:     []string{},
		WellKnownPaths:  []WellKnownHit{},
		CheckedAt:       nowRFC3339(),
	}

	if !opts.SkipDiscovery {
		runDiscoveryProbes(ctx, transport, ua, finalURL, minDuration(timeout, 5*time.Second), profile, &warnings)
	}

	if len(warnings) > 0 {
		profile.Warnings = warnings
	}
	profile.ElapsedMs = time.Since(start).Milliseconds()
	return profile, nil
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		if len(vals) == 0 {
			continue
		}
		if strings.EqualFold(k, "Set-Cookie") {
			names := make([]string, 0, len(vals))
			for _, v := range vals {
				if eq := strings.IndexByte(v, '='); eq > 0 {
					names = append(names, strings.TrimSpace(v[:eq]))
				}
			}
			if len(names) > 0 {
				out[k] = strings.Join(names, ", ")
			} else {
				out[k] = fmt.Sprintf("%d cookie(s)", len(vals))
			}
			continue
		}
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

func extractHTMLTitle(body string) string {
	m := htmlTitleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	s := html.UnescapeString(m[1])
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 256 {
		s = s[:256]
	}
	return strings.TrimSpace(s)
}

func extractMetaGenerator(body string) string {
	for _, tag := range metaTagRe.FindAllString(body, 64) {
		nm := metaAttrNameRe.FindStringSubmatch(tag)
		if len(nm) < 4 {
			continue
		}
		name := strings.ToLower(firstNonEmpty(nm[1], nm[2], nm[3]))
		if name != "generator" {
			continue
		}
		cm := metaAttrContRe.FindStringSubmatch(tag)
		if len(cm) >= 4 {
			val := strings.TrimSpace(html.UnescapeString(firstNonEmpty(cm[1], cm[2], cm[3])))
			if val != "" {
				return val
			}
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// DetectTechnologies fingerprints web servers, proxies, CDNs, WAFs, backend frameworks,
// frontend stacks, APIs, and CMS platforms from HTTP headers, cookies, and HTML body.
func DetectTechnologies(headers http.Header, cookies []*http.Cookie, body, metaGen, finalURL string) ([]TechMatch, []string, []string) {
	found := make(map[string]TechMatch)
	cdnSet := make(map[string]bool)
	wafSet := make(map[string]bool)

	add := func(name, category, version, confidence, evidence string) {
		key := strings.ToLower(name)
		if prev, exists := found[key]; exists {
			if prev.Version == "" && version != "" {
				prev.Version = version
				found[key] = prev
			}
			if confidenceRank(confidence) > confidenceRank(prev.Confidence) {
				prev.Confidence = confidence
				prev.Evidence = evidence
				found[key] = prev
			}
			return
		}
		found[key] = TechMatch{
			Name:       name,
			Category:   category,
			Version:    version,
			Confidence: confidence,
			Evidence:   evidence,
		}
		if category == "cdn" {
			cdnSet[name] = true
		}
		if category == "waf" {
			wafSet[name] = true
		}
	}

	getH := func(k string) string { return strings.TrimSpace(headers.Get(k)) }
	hasH := func(k string) bool { return getH(k) != "" }

	server := getH("Server")
	serverLow := strings.ToLower(server)
	poweredBy := getH("X-Powered-By")
	poweredLow := strings.ToLower(poweredBy)
	via := strings.ToLower(getH("Via"))
	genLow := strings.ToLower(metaGen)
	xGenLow := strings.ToLower(getH("X-Generator"))

	// Sample first 256 KiB of body lowercased for fast signal checks.
	bodySample := body
	if len(bodySample) > 256*1024 {
		bodySample = bodySample[:256*1024]
	}
	bodyLow := strings.ToLower(bodySample)
	urlLow := strings.ToLower(finalURL)

	cookieNames := make(map[string]bool, len(cookies))
	cookieNamesLow := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c != nil && c.Name != "" {
			cookieNames[c.Name] = true
			cookieNamesLow = append(cookieNamesLow, strings.ToLower(c.Name))
		}
	}
	// Also parse raw Set-Cookie header in case cookies wasn't populated.
	for _, sc := range headers.Values("Set-Cookie") {
		if eq := strings.IndexByte(sc, '='); eq > 0 {
			nm := strings.TrimSpace(sc[:eq])
			if nm != "" && !cookieNames[nm] {
				cookieNames[nm] = true
				cookieNamesLow = append(cookieNamesLow, strings.ToLower(nm))
			}
		}
	}
	hasCookie := func(prefix string) bool {
		prefix = strings.ToLower(prefix)
		for _, cn := range cookieNamesLow {
			if cn == prefix || strings.HasPrefix(cn, prefix) {
				return true
			}
		}
		return false
	}

	extractProductVersion := func(val, product string) string {
		for _, m := range headerVersionRe.FindAllStringSubmatch(val, -1) {
			if len(m) >= 3 && strings.Contains(strings.ToLower(m[1]), strings.ToLower(product)) {
				return m[2]
			}
		}
		return ""
	}

	// --- Web Servers & Proxies ---
	if strings.Contains(serverLow, "openresty") {
		add("OpenResty", "web-server", extractProductVersion(server, "openresty"), "high", "Server: "+server)
	}
	if strings.Contains(serverLow, "tengine") {
		add("Tengine", "web-server", extractProductVersion(server, "tengine"), "high", "Server: "+server)
		cdnSet["Aliyun / Alibaba Cloud"] = true
	}
	if strings.Contains(serverLow, "nginx") {
		add("Nginx", "web-server", extractProductVersion(server, "nginx"), "high", "Server: "+server)
	}
	if strings.Contains(serverLow, "apache") && !strings.Contains(serverLow, "coyote") {
		add("Apache HTTP Server", "web-server", extractProductVersion(server, "apache"), "high", "Server: "+server)
	}
	if strings.Contains(serverLow, "apache-coyote") || strings.Contains(serverLow, "tomcat") {
		add("Apache Tomcat", "web-server", extractProductVersion(server, "coyote"), "high", "Server: "+server)
	}
	if strings.Contains(serverLow, "caddy") {
		add("Caddy", "web-server", extractProductVersion(server, "caddy"), "high", "Server: "+server)
	}
	if strings.Contains(serverLow, "envoy") || hasH("X-Envoy-Upstream-Service-Time") || hasH("X-Envoy-Decorator-Operation") {
		add("Envoy", "proxy", "", "high", "Envoy header/server")
	}
	if strings.Contains(serverLow, "microsoft-iis") {
		add("Microsoft IIS", "web-server", extractProductVersion(server, "iis"), "high", "Server: "+server)
	}
	if strings.Contains(serverLow, "litespeed") {
		add("LiteSpeed", "web-server", extractProductVersion(server, "litespeed"), "high", "Server: "+server)
	}
	if strings.Contains(serverLow, "traefik") {
		add("Traefik", "proxy", "", "high", "Server: "+server)
	}
	if strings.Contains(serverLow, "haproxy") || hasH("X-Haproxy-Server-State") {
		add("HAProxy", "proxy", "", "high", "HAProxy header")
	}
	if strings.Contains(serverLow, "jetty") {
		add("Jetty", "web-server", extractProductVersion(server, "jetty"), "high", "Server: "+server)
	}
	if strings.Contains(via, "varnish") || hasH("X-Varnish") {
		add("Varnish", "proxy", "", "high", "X-Varnish/Via header")
	}

	// --- CDN & Edge ---
	if hasH("CF-Ray") || strings.Contains(serverLow, "cloudflare") || hasH("CF-Cache-Status") || hasCookie("__cf_bm") {
		add("Cloudflare", "cdn", "", "high", "CF-Ray / Server: cloudflare")
		wafSet["Cloudflare WAF"] = true
		if hasH("CF-Mitigated") {
			add("Cloudflare WAF", "waf", "", "high", "CF-Mitigated header")
		}
	}
	if hasH("X-Akamai-Transformed") || hasH("Akamai-GRN") || hasH("X-Akamai-Request-ID") || strings.Contains(serverLow, "akamaighost") {
		add("Akamai", "cdn", "", "high", "Akamai response header")
		if hasCookie("ak_bmsc") || hasCookie("bm_sz") {
			add("Akamai Kona WAF", "waf", "", "high", "Akamai bot/WAF cookie")
		}
	}
	if hasH("X-Fastly-Request-ID") || strings.Contains(strings.ToLower(getH("X-Served-By")), "cache-") || strings.Contains(via, "fastly") {
		add("Fastly", "cdn", "", "high", "Fastly response header")
	}
	if hasH("X-Amz-Cf-Id") || hasH("X-Amz-Cf-Pop") || strings.Contains(via, "cloudfront") {
		add("AWS CloudFront", "cdn", "", "high", "X-Amz-Cf-Id / Via CloudFront")
	}
	if strings.Contains(serverLow, "awselb") || hasCookie("AWSALB") || hasCookie("AWSALBCORS") {
		add("AWS ALB/ELB", "proxy", "", "high", "AWSALB / awselb")
		cdnSet["AWS ALB/ELB"] = true
	}
	if hasH("Ali-Swift-Global-Savetime") || hasH("EagleId") || hasH("X-Oss-Request-Id") || strings.Contains(via, "kunlun") {
		add("Aliyun CDN", "cdn", "", "high", "Aliyun / EagleId / Kunlun header")
	}
	if hasH("X-NWS-LOG-UUID") || hasH("X-Daa-Tunnel") || hasH("EO-LOG-UUID") || (hasH("X-Cache-Lookup") && strings.Contains(serverLow, "nws")) {
		add("Tencent Cloud CDN", "cdn", "", "high", "X-NWS-LOG-UUID / Tencent header")
	}
	if hasH("X-Azure-Ref") || hasH("X-FD-HealthProbe") {
		add("Azure Front Door", "cdn", "", "high", "X-Azure-Ref header")
	}
	if strings.Contains(serverLow, "gfe") || strings.Contains(serverLow, "gws") || strings.Contains(via, "1.1 google") || hasH("X-Cloud-Trace-Context") {
		add("Google Cloud", "cdn", "", "medium", "Google Front End / Cloud Trace header")
	}
	if hasH("X-Vercel-Id") || strings.Contains(serverLow, "vercel") {
		add("Vercel", "cdn", "", "high", "X-Vercel-Id / Server: Vercel")
	}
	if hasH("X-NF-Request-ID") || strings.Contains(serverLow, "netlify") {
		add("Netlify", "cdn", "", "high", "X-NF-Request-ID / Server: Netlify")
	}

	// --- WAF Signals ---
	if hasH("X-Amzn-Waf-Action") {
		add("AWS WAF", "waf", "", "high", "X-Amzn-Waf-Action header")
	}
	if hasCookie("acw_tc") || hasCookie("acw_sc__v2") || hasCookie("cdn_sec_tc") {
		add("Aliyun WAF", "waf", "", "high", "Aliyun WAF cookie (acw_tc/cdn_sec_tc)")
	}
	if hasH("X-WAF-Event-Info") || hasH("EO-LOG-UUID") {
		add("Tencent WAF", "waf", "", "medium", "Tencent WAF/EdgeOne header")
	}
	if hasH("X-Iinfo") || strings.Contains(strings.ToLower(getH("X-CDN")), "imperva") || hasCookie("visid_incap_") || hasCookie("incap_ses_") {
		add("Imperva / Incapsula", "waf", "", "high", "Imperva header/cookie")
	}
	if hasCookie("BIGipServer") || hasCookie("TS01") || hasH("X-WA-Info") {
		add("F5 BIG-IP ASM", "waf", "", "high", "F5 BIG-IP cookie/header")
	}
	if strings.Contains(serverLow, "mod_security") || strings.Contains(serverLow, "noyb") {
		add("ModSecurity", "waf", "", "medium", "Server: "+server)
	}
	if hasH("X-Sucuri-ID") || hasH("X-Sucuri-Cache") || strings.Contains(serverLow, "sucuri") {
		add("Sucuri WAF", "waf", "", "high", "Sucuri header")
	}

	// --- Backend Frameworks & Languages ---
	if hasCookie("JSESSIONID") || hasH("X-Application-Context") || strings.Contains(bodyLow, "whitelabel error page") {
		add("Spring / Java", "framework", "", "medium", "JSESSIONID / Spring signature")
	}
	if strings.Contains(poweredLow, "gin") || strings.Contains(serverLow, "go-http-server") || strings.Contains(poweredLow, "golang") {
		add("Go / Gin", "framework", "", "high", "X-Powered-By/Server Go/Gin")
	}
	if strings.Contains(poweredLow, "express") || hasCookie("connect.sid") {
		add("Node.js / Express", "framework", "", "high", "X-Powered-By: Express / connect.sid")
	}
	if hasCookie("csrftoken") || strings.Contains(bodyLow, "csrfmiddlewaretoken") || strings.Contains(poweredLow, "django") {
		add("Django", "framework", "", "medium", "Django CSRF token / header")
	}
	if strings.Contains(bodyLow, "fastapi") || strings.Contains(poweredLow, "fastapi") || (strings.Contains(bodyLow, "swagger-ui") && strings.Contains(bodyLow, "/openapi.json")) {
		add("FastAPI", "framework", "", "medium", "FastAPI / OpenAPI signature")
	}
	if strings.Contains(serverLow, "werkzeug") || strings.Contains(poweredLow, "flask") {
		add("Flask", "framework", extractProductVersion(server, "werkzeug"), "high", "Werkzeug / Flask header")
	}
	if strings.Contains(poweredLow, "php") || hasCookie("PHPSESSID") {
		add("PHP", "language", extractProductVersion(poweredBy, "php"), "high", "X-Powered-By / PHPSESSID")
	}
	if hasCookie("laravel_session") || (hasCookie("XSRF-TOKEN") && strings.Contains(bodyLow, "laravel")) {
		add("Laravel", "framework", "", "high", "laravel_session cookie")
	}
	if (hasH("X-Runtime") && hasH("X-Request-Id") && strings.Contains(bodyLow, "authenticity_token")) || strings.Contains(poweredLow, "phusion passenger") || strings.Contains(bodyLow, `name="csrf-param" content="authenticity_token"`) {
		add("Ruby on Rails", "framework", "", "high", "Rails authenticity_token / X-Runtime")
	}
	if hasH("X-AspNet-Version") || strings.Contains(poweredLow, "asp.net") || hasCookie("ASP.NET_SessionId") {
		add("ASP.NET", "framework", getH("X-AspNet-Version"), "high", "X-AspNet-Version / ASP.NET")
	}

	// --- Frontend Frameworks ---
	if strings.Contains(poweredLow, "next.js") || strings.Contains(bodyLow, "__next_data__") || strings.Contains(bodyLow, "/_next/static/") {
		add("Next.js", "frontend", "", "high", "__NEXT_DATA__ / X-Powered-By: Next.js")
	}
	if strings.Contains(poweredLow, "nuxt") || strings.Contains(bodyLow, "__nuxt__") || strings.Contains(bodyLow, "/_nuxt/") {
		add("Nuxt", "frontend", "", "high", "__NUXT__ / /_nuxt/")
	}
	if strings.Contains(bodyLow, "data-reactroot") || strings.Contains(bodyLow, "data-reactid") || strings.Contains(bodyLow, "react-dom") || strings.Contains(bodyLow, "__react_devtools") {
		add("React", "frontend", "", "medium", "React DOM markers")
	}
	if strings.Contains(bodyLow, "data-v-") || strings.Contains(bodyLow, "__vue__") || strings.Contains(bodyLow, "vue.runtime") {
		add("Vue.js", "frontend", "", "medium", "Vue data-v / __VUE__ marker")
	}
	if strings.Contains(bodyLow, "__sveltekit") || strings.Contains(bodyLow, "data-sveltekit") || strings.Contains(bodyLow, "svelte-") {
		add("Svelte", "frontend", "", "medium", "Svelte/SvelteKit HTML markers")
	}
	if strings.Contains(bodyLow, "ng-version=") || strings.Contains(bodyLow, "<app-root") {
		add("Angular", "frontend", "", "medium", "Angular ng-version/app-root")
	}
	if strings.Contains(bodyLow, "/@vite/client") || strings.Contains(bodyLow, "vite/preload-helper") {
		add("Vite", "frontend", "", "medium", "Vite client markers")
	}

	// --- API & CMS ---
	if strings.Contains(urlLow, "/graphql") || strings.Contains(bodyLow, "graphiql") || strings.Contains(bodyLow, "graphql-playground") || strings.Contains(bodyLow, `"__schema"`) {
		add("GraphQL", "api", "", "medium", "GraphQL endpoint/UI markers")
	}
	if strings.Contains(bodyLow, "swagger-ui") || strings.Contains(bodyLow, "swagger-initializer.js") || strings.Contains(bodyLow, "redoc.standalone.js") || strings.Contains(urlLow, "swagger") || strings.Contains(urlLow, "openapi") {
		add("Swagger / OpenAPI", "api", "", "high", "Swagger UI / OpenAPI markers")
	}
	if strings.Contains(genLow, "wordpress") || strings.Contains(bodyLow, "/wp-content/") || strings.Contains(bodyLow, "/wp-includes/") || strings.Contains(strings.ToLower(getH("Link")), "wp-json") {
		ver := ""
		if strings.Contains(genLow, "wordpress") {
			ver = extractToolVersion(metaGen)
		}
		add("WordPress", "cms", ver, "high", "WordPress generator / wp-content")
	}
	if strings.Contains(genLow, "drupal") || strings.Contains(xGenLow, "drupal") || strings.Contains(bodyLow, "/sites/default/files") {
		add("Drupal", "cms", "", "high", "Drupal generator / path")
	}
	if hasH("X-ShopId") || hasH("X-Shopify-Stage") || strings.Contains(bodyLow, "cdn.shopify.com") {
		add("Shopify", "cms", "", "high", "Shopify header / CDN")
	}
	if strings.Contains(genLow, "hugo") {
		add("Hugo", "cms", extractToolVersion(metaGen), "high", "meta generator: "+metaGen)
	}

	techs := make([]TechMatch, 0, len(found))
	for _, tm := range found {
		techs = append(techs, tm)
	}
	sort.Slice(techs, func(i, j int) bool {
		if techs[i].Category != techs[j].Category {
			return techs[i].Category < techs[j].Category
		}
		return techs[i].Name < techs[j].Name
	})

	return techs, mapKeysSorted(cdnSet), mapKeysSorted(wafSet)
}

func confidenceRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// AuditSecurityHeaders audits standard HTTP security headers and calculates a
// deterministic 0..100 score with actionable remediation recommendations.
func AuditSecurityHeaders(headers http.Header, isHTTPS bool) ([]HeaderAuditItem, int) {
	items := make([]HeaderAuditItem, 0, 7)
	totalScore := 0

	// 1. Strict-Transport-Security (weight 20)
	hstsVal := strings.TrimSpace(headers.Get("Strict-Transport-Security"))
	hstsItem := HeaderAuditItem{
		Header:  "Strict-Transport-Security",
		Present: hstsVal != "",
		Value:   hstsVal,
		Weight:  20,
	}
	switch {
	case !isHTTPS:
		hstsItem.Status = "fail"
		hstsItem.Score = 0
		hstsItem.Recommendation = "Serve the site over HTTPS and set Strict-Transport-Security: max-age=31536000; includeSubDomains."
	case hstsVal == "":
		hstsItem.Status = "fail"
		hstsItem.Score = 0
		hstsItem.Recommendation = "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."
	default:
		maxAge := 0
		if m := hstsMaxAgeRe.FindStringSubmatch(hstsVal); len(m) >= 2 {
			maxAge, _ = strconv.Atoi(m[1])
		}
		if maxAge >= 15552000 {
			hstsItem.Status = "pass"
			hstsItem.Score = 20
		} else {
			hstsItem.Status = "warn"
			hstsItem.Score = 12
			hstsItem.Recommendation = "Increase HSTS max-age to at least 15552000 (180 days) or 31536000 (1 year)."
		}
	}
	items = append(items, hstsItem)
	totalScore += hstsItem.Score

	// 2. Content-Security-Policy (weight 25)
	cspVal := strings.TrimSpace(headers.Get("Content-Security-Policy"))
	cspLow := strings.ToLower(cspVal)
	cspItem := HeaderAuditItem{
		Header:  "Content-Security-Policy",
		Present: cspVal != "",
		Value:   cspVal,
		Weight:  25,
	}
	if cspVal == "" {
		cspItem.Status = "fail"
		cspItem.Score = 0
		cspItem.Recommendation = "Define a Content-Security-Policy restricting script-src, object-src, and frame-ancestors."
	} else if strings.Contains(cspLow, "'unsafe-inline'") || strings.Contains(cspLow, "'unsafe-eval'") {
		cspItem.Status = "warn"
		cspItem.Score = 15
		cspItem.Recommendation = "Tighten Content-Security-Policy to eliminate 'unsafe-inline' and 'unsafe-eval' using nonces or hashes."
	} else {
		cspItem.Status = "pass"
		cspItem.Score = 25
	}
	items = append(items, cspItem)
	totalScore += cspItem.Score

	// 3. X-Frame-Options (weight 15)
	xfoVal := strings.TrimSpace(headers.Get("X-Frame-Options"))
	xfoUpper := strings.ToUpper(xfoVal)
	hasFrameAncestors := strings.Contains(cspLow, "frame-ancestors")
	xfoItem := HeaderAuditItem{
		Header:  "X-Frame-Options",
		Present: xfoVal != "",
		Value:   xfoVal,
		Weight:  15,
	}
	switch {
	case xfoUpper == "DENY" || xfoUpper == "SAMEORIGIN":
		xfoItem.Status = "pass"
		xfoItem.Score = 15
	case xfoVal == "" && hasFrameAncestors:
		xfoItem.Status = "pass"
		xfoItem.Score = 15
		xfoItem.Recommendation = "Protected via CSP frame-ancestors; optionally set X-Frame-Options: DENY for legacy clients."
	case xfoVal != "":
		xfoItem.Status = "warn"
		xfoItem.Score = 8
		xfoItem.Recommendation = "Use X-Frame-Options: DENY or SAMEORIGIN (and CSP frame-ancestors)."
	default:
		xfoItem.Status = "fail"
		xfoItem.Score = 0
		xfoItem.Recommendation = "Add X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors) to prevent clickjacking."
	}
	items = append(items, xfoItem)
	totalScore += xfoItem.Score

	// 4. X-Content-Type-Options (weight 15)
	xctoVal := strings.TrimSpace(headers.Get("X-Content-Type-Options"))
	xctoItem := HeaderAuditItem{
		Header:  "X-Content-Type-Options",
		Present: xctoVal != "",
		Value:   xctoVal,
		Weight:  15,
	}
	switch {
	case strings.EqualFold(xctoVal, "nosniff"):
		xctoItem.Status = "pass"
		xctoItem.Score = 15
	case xctoVal != "":
		xctoItem.Status = "warn"
		xctoItem.Score = 5
		xctoItem.Recommendation = "Set X-Content-Type-Options strictly to nosniff."
	default:
		xctoItem.Status = "fail"
		xctoItem.Score = 0
		xctoItem.Recommendation = "Add X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks."
	}
	items = append(items, xctoItem)
	totalScore += xctoItem.Score

	// 5. Referrer-Policy (weight 10)
	rpVal := strings.TrimSpace(headers.Get("Referrer-Policy"))
	rpLow := strings.ToLower(rpVal)
	rpItem := HeaderAuditItem{
		Header:  "Referrer-Policy",
		Present: rpVal != "",
		Value:   rpVal,
		Weight:  10,
	}
	switch rpLow {
	case "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin":
		rpItem.Status = "pass"
		rpItem.Score = 10
	case "":
		rpItem.Status = "fail"
		rpItem.Score = 0
		rpItem.Recommendation = "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer."
	default:
		rpItem.Status = "warn"
		rpItem.Score = 5
		rpItem.Recommendation = "Prefer Referrer-Policy: strict-origin-when-cross-origin or no-referrer."
	}
	items = append(items, rpItem)
	totalScore += rpItem.Score

	// 6. Permissions-Policy (weight 10)
	ppVal := strings.TrimSpace(headers.Get("Permissions-Policy"))
	ppItem := HeaderAuditItem{
		Header:  "Permissions-Policy",
		Present: ppVal != "",
		Value:   ppVal,
		Weight:  10,
	}
	if ppVal != "" {
		ppItem.Status = "pass"
		ppItem.Score = 10
	} else {
		ppItem.Status = "fail"
		ppItem.Score = 0
		ppItem.Recommendation = "Add Permissions-Policy to disable unneeded browser features (e.g. geolocation=(), camera=())."
	}
	items = append(items, ppItem)
	totalScore += ppItem.Score

	// 7. Access-Control-Allow-Origin (weight 5)
	acaoVal := strings.TrimSpace(headers.Get("Access-Control-Allow-Origin"))
	acacVal := strings.TrimSpace(headers.Get("Access-Control-Allow-Credentials"))
	acaoItem := HeaderAuditItem{
		Header:  "Access-Control-Allow-Origin",
		Present: acaoVal != "",
		Value:   acaoVal,
		Weight:  5,
	}
	switch {
	case acaoVal == "*" && strings.EqualFold(acacVal, "true"):
		acaoItem.Status = "fail"
		acaoItem.Score = 0
		acaoItem.Recommendation = "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true."
	case acaoVal == "*":
		acaoItem.Status = "warn"
		acaoItem.Score = 3
		acaoItem.Recommendation = "Wildcard CORS (*) allows any origin to read responses; restrict to trusted origins if sensitive."
	default:
		acaoItem.Status = "pass"
		acaoItem.Score = 5
	}
	items = append(items, acaoItem)
	totalScore += acaoItem.Score

	if totalScore < 0 {
		totalScore = 0
	}
	if totalScore > 100 {
		totalScore = 100
	}
	return items, totalScore
}

func runDiscoveryProbes(
	ctx context.Context,
	transport http.RoundTripper,
	ua string,
	finalURL string,
	timeout time.Duration,
	profile *SiteProfile,
	warnings *[]string,
) {
	u, err := url.Parse(finalURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return
	}
	origin := u.Scheme + "://" + u.Host

	discClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	fetchSmall := func(target string, maxBytes int64) (status int, contentType string, body []byte, fetchErr error) {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, rErr := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
		if rErr != nil {
			return 0, "", nil, rErr
		}
		req.Header.Set("User-Agent", ua)
		resp, dErr := discClient.Do(req)
		if dErr != nil {
			return 0, "", nil, dErr
		}
		defer resp.Body.Close()
		data, _, rdErr := readBodyCapped(resp.Body, maxBytes)
		return resp.StatusCode, strings.TrimSpace(resp.Header.Get("Content-Type")), data, rdErr
	}

	var (
		mu             sync.Mutex
		wg             sync.WaitGroup
		robotsSummary  *RobotsSummary
		sitemapURLs    []string
		wellKnownHits  []WellKnownHit
		faviconSHA256  string
		robotsSitemaps []string
	)

	// 1. /robots.txt
	wg.Add(1)
	go func() {
		defer wg.Done()
		st, _, data, fErr := fetchSmall(origin+"/robots.txt", 256*1024)
		if fErr != nil {
			return
		}
		rs := parseRobotsTxt(st, string(data))
		mu.Lock()
		robotsSummary = rs
		if rs != nil {
			robotsSitemaps = append(robotsSitemaps, rs.Sitemaps...)
		}
		mu.Unlock()
	}()

	// 2. /favicon.ico
	wg.Add(1)
	go func() {
		defer wg.Done()
		st, _, data, fErr := fetchSmall(origin+"/favicon.ico", MaxFaviconBytes)
		if fErr != nil || st != http.StatusOK || len(data) == 0 {
			return
		}
		sum := sha256.Sum256(data)
		mu.Lock()
		faviconSHA256 = hex.EncodeToString(sum[:])
		mu.Unlock()
	}()

	// 3 & 4. /.well-known/security.txt & /.well-known/openid-configuration
	wellKnownTargets := []string{
		"/.well-known/security.txt",
		"/.well-known/openid-configuration",
	}
	for _, wkPath := range wellKnownTargets {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			full := origin + p
			st, ct, data, fErr := fetchSmall(full, 128*1024)
			if fErr != nil {
				return
			}
			hit := WellKnownHit{
				Path:        p,
				URL:         full,
				StatusCode:  st,
				ContentType: ct,
				Found:       st == http.StatusOK && len(bytes.TrimSpace(data)) > 0,
			}
			if hit.Found {
				// Avoid false positives when SPAs return HTML 200 for unknown routes.
				lowCT := strings.ToLower(ct)
				trimmed := bytes.TrimSpace(data)
				if strings.HasSuffix(p, "openid-configuration") {
					if !bytes.HasPrefix(trimmed, []byte("{")) {
						hit.Found = false
					}
				} else if strings.Contains(lowCT, "text/html") && bytes.Contains(bytes.ToLower(trimmed), []byte("<html")) {
					hit.Found = false
				}
			}
			if hit.Found {
				snip := strings.TrimSpace(string(data))
				if len(snip) > 240 {
					snip = snip[:240]
				}
				hit.Snippet = snip
			}
			mu.Lock()
			wellKnownHits = append(wellKnownHits, hit)
			mu.Unlock()
		}(wkPath)
	}

	// 5. /sitemap.xml
	wg.Add(1)
	go func() {
		defer wg.Done()
		st, _, data, fErr := fetchSmall(origin+"/sitemap.xml", MaxHTTPBodyBytes)
		if fErr != nil || st != http.StatusOK || len(data) == 0 {
			return
		}
		locs := parseSitemapXML(data, MaxSitemapSamples)
		if len(locs) > 0 {
			mu.Lock()
			sitemapURLs = locs
			mu.Unlock()
		}
	}()

	wg.Wait()

	// If /sitemap.xml was missing but robots.txt declared a same-origin HTTP/HTTPS Sitemap URL, probe up to 3.
	if len(sitemapURLs) == 0 && len(robotsSitemaps) > 0 && ctx.Err() == nil {
		probed := 0
		for _, sm := range robotsSitemaps {
			if ctx.Err() != nil || probed >= 3 {
				break
			}
			smU, pErr := url.Parse(sm)
			if pErr != nil || smU == nil {
				continue
			}
			scheme := strings.ToLower(smU.Scheme)
			if (scheme != "http" && scheme != "https") || !strings.EqualFold(smU.Host, u.Host) {
				continue
			}
			probed++
			st, _, data, fErr := fetchSmall(sm, MaxHTTPBodyBytes)
			if fErr == nil && st == http.StatusOK && len(data) > 0 {
				locs := parseSitemapXML(data, MaxSitemapSamples)
				if len(locs) > 0 {
					sitemapURLs = locs
					break
				}
			}
		}
	}

	sort.Slice(wellKnownHits, func(i, j int) bool {
		return wellKnownHits[i].Path < wellKnownHits[j].Path
	})

	profile.RobotsRules = robotsSummary
	profile.FaviconSHA256 = faviconSHA256
	if sitemapURLs != nil {
		profile.SitemapURLs = sitemapURLs
	}
	if wellKnownHits != nil {
		profile.WellKnownPaths = wellKnownHits
	}
	_ = warnings
}

func parseRobotsTxt(statusCode int, raw string) *RobotsSummary {
	rs := &RobotsSummary{
		Found:      statusCode == http.StatusOK && strings.TrimSpace(raw) != "",
		StatusCode: statusCode,
		Allow:      []string{},
		Disallow:   []string{},
		Sitemaps:   []string{},
	}
	if !rs.Found {
		return rs
	}
	allowSeen := make(map[string]bool)
	disallowSeen := make(map[string]bool)
	sitemapSeen := make(map[string]bool)

	lines := strings.Split(raw, "\n")
	rs.RawLines = len(lines)
	for _, line := range lines {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
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
		case "allow":
			if !allowSeen[val] && len(rs.Allow) < 100 {
				allowSeen[val] = true
				rs.Allow = append(rs.Allow, val)
			}
		case "disallow":
			if !disallowSeen[val] && len(rs.Disallow) < 100 {
				disallowSeen[val] = true
				rs.Disallow = append(rs.Disallow, val)
			}
		case "sitemap":
			if !sitemapSeen[val] && len(rs.Sitemaps) < 20 {
				sitemapSeen[val] = true
				rs.Sitemaps = append(rs.Sitemaps, val)
			}
		}
	}
	return rs
}

func parseSitemapXML(data []byte, maxLocs int) []string {
	if maxLocs <= 0 {
		maxLocs = MaxSitemapSamples
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	seen := make(map[string]bool)
	var out []string
	for len(out) < maxLocs {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || !strings.EqualFold(se.Name.Local, "loc") {
			continue
		}
		var loc string
		if decErr := dec.DecodeElement(&loc, &se); decErr != nil {
			continue
		}
		loc = strings.TrimSpace(loc)
		if loc != "" && !seen[loc] {
			seen[loc] = true
			out = append(out, loc)
		}
	}
	return out
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
