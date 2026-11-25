package recon

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultSubdomainTimeout = 30 * time.Second
	defaultCTTimeout        = 10 * time.Second
	maxSubfinderOutBytes    = 4 << 20 // 4 MiB
)

// Curated high-signal mobile, API, web, and infrastructure subdomain labels
// used by the bounded wildcard-guarded Common DNS source.
var commonSubdomainLabels = []string{
	"www", "api", "api-v1", "api-v2", "m", "mobile", "app", "apps",
	"gw", "gateway", "edge", "auth", "login", "sso", "oauth", "id",
	"account", "accounts", "passport", "user", "users", "profile",
	"cdn", "static", "assets", "img", "image", "images", "media",
	"files", "dl", "download", "upload", "ws", "wss", "socket", "push",
	"h5", "web", "wap", "pay", "payment", "billing", "order", "shop",
	"store", "docs", "doc", "developer", "openapi", "swagger", "graphql",
	"admin", "console", "portal", "dashboard", "ops", "manage",
	"dev", "test", "qa", "uat", "staging", "stage", "beta", "pre", "sandbox",
	"mail", "smtp", "imap", "vpn", "git", "gitlab", "ci", "jenkins",
	"monitor", "metrics", "status", "grafana", "sentry", "log", "logs",
	"internal", "corp",
}

// Package-level resolver hooks overridable in unit tests for hermetic DNS/wildcard tests.
var (
	subdomainLookupIP = func(ctx context.Context, host string) ([]string, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		seen := make(map[string]bool)
		out := make([]string, 0, len(addrs))
		for _, a := range addrs {
			if a.IP != nil {
				s := a.IP.String()
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
		sort.Strings(out)
		return out, nil
	}
	subdomainLookupCNAME = func(ctx context.Context, host string) (string, error) {
		c, err := net.DefaultResolver.LookupCNAME(ctx, host)
		if err != nil {
			return "", err
		}
		c = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c), "."))
		if c == host {
			return "", nil
		}
		return c, nil
	}
)

// EnumerateSubdomains discovers subdomains using subfinder, passive CT logs,
// and wildcard-guarded common DNS lookups with cross-source deduplication.
func EnumerateSubdomains(ctx context.Context, req SubdomainRequest, cfg ToolchainConfig) (*SubdomainReport, error) {
	return EnumerateSubdomainsWithProgress(ctx, req, cfg, nil)
}

// EnumerateSubdomainsWithProgress runs subdomain enumeration while emitting
// progress messages to an optional callback.
func EnumerateSubdomainsWithProgress(ctx context.Context, req SubdomainRequest, cfg ToolchainConfig, onProgress func(string)) (*SubdomainReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()

	domain, _, err := NormalizeDomainTarget(req.Domain)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(domain) != nil {
		return nil, fmt.Errorf("recon: subdomain enumeration requires a domain name, got IP %q", domain)
	}
	if !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("recon: subdomain enumeration requires a multi-label domain name, got %q", domain)
	}

	// If no sources were explicitly selected, enable all standard sources.
	if !req.UseSubfinder && !req.UseCTLog && !req.UseCommonDNS {
		req.UseSubfinder = true
		req.UseCTLog = true
		req.UseCommonDNS = true
	}

	enumCtx := ctx
	var cancel context.CancelFunc
	if req.TimeoutSec > 0 {
		enumCtx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutSec)*time.Second)
		defer cancel()
	} else if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		enumCtx, cancel = context.WithTimeout(ctx, defaultSubdomainTimeout)
		defer cancel()
	}

	report := &SubdomainReport{
		Domain:      domain,
		Subdomains:  []SubdomainEntry{},
		SourcesUsed: []string{},
		CheckedAt:   nowRFC3339(),
	}

	emit := func(msg string) {
		if onProgress != nil && msg != "" {
			onProgress(msg)
		}
	}

	// Step 1: Wildcard DNS detection using a random nonexistent label.
	wildcardSet := make(map[string]bool)
	if req.UseCommonDNS || req.ResolveDNS {
		wcHost := fmt.Sprintf("cap-wc-%s.%s", randomHexBytes(6), domain)
		wcCtx, wcCancel := context.WithTimeout(enumCtx, 2*time.Second)
		wcIPs, wcErr := subdomainLookupIP(wcCtx, wcHost)
		wcCancel()
		if wcErr == nil && len(wcIPs) > 0 {
			report.WildcardDetected = true
			report.WildcardIPs = wcIPs
			for _, ip := range wcIPs {
				wildcardSet[ip] = true
			}
			warn := fmt.Sprintf("wildcard DNS detected for *.%s (%s); wildcard-only answers will be filtered", domain, strings.Join(wcIPs, ", "))
			report.Warnings = append(report.Warnings, warn)
			emit(warn)
		}
	}

	type accEntry struct {
		sources map[string]bool
		ips     map[string]bool
		cname   string
	}
	var (
		mu          sync.Mutex
		entries     = make(map[string]*accEntry)
		sourcesUsed = make(map[string]bool)
		warnings    = append([]string{}, report.Warnings...)
	)

	addFinding := func(hostname, source string, ips []string, cname string) {
		h := normalizeSubdomainCandidate(hostname, domain)
		if h == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		e, ok := entries[h]
		if !ok {
			e = &accEntry{
				sources: make(map[string]bool),
				ips:     make(map[string]bool),
			}
			entries[h] = e
		}
		if source != "" {
			e.sources[source] = true
		}
		for _, ip := range ips {
			if ip != "" {
				e.ips[ip] = true
			}
		}
		if e.cname == "" && cname != "" {
			e.cname = cname
		}
	}
	addWarn := func(w string) {
		if strings.TrimSpace(w) == "" {
			return
		}
		mu.Lock()
		warnings = append(warnings, w)
		mu.Unlock()
	}
	markSource := func(s string) {
		mu.Lock()
		sourcesUsed[s] = true
		mu.Unlock()
	}

	var wg sync.WaitGroup

	// Source 1: subfinder binary (direct exec, no shell).
	if req.UseSubfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bin, ok := resolveToolBinary(cfg.SubfinderPath, "subfinder")
			if !ok {
				addWarn("subfinder binary not installed; skipping subfinder source")
				return
			}
			markSource("subfinder")
			emit(fmt.Sprintf("Running subfinder for %s...", domain))
			found, sfErr := runSubfinder(enumCtx, bin, domain)
			if sfErr != nil {
				addWarn("subfinder: " + sfErr.Error())
			}
			for _, h := range found {
				addFinding(h, "subfinder", nil, "")
			}
			emit(fmt.Sprintf("subfinder finished (%d candidate(s))", len(found)))
		}()
	}

	// Source 2: Passive Certificate Transparency log (crt.sh or CTEndpoint override).
	if req.UseCTLog {
		wg.Add(1)
		go func() {
			defer wg.Done()
			markSource("ct_log")
			emit(fmt.Sprintf("Querying CT log for *.%s...", domain))
			found, ctErr := queryCTLog(enumCtx, domain, req.CTEndpoint)
			if ctErr != nil {
				addWarn("ct_log: " + ctErr.Error())
				return
			}
			for _, h := range found {
				addFinding(h, "ct_log", nil, "")
			}
			emit(fmt.Sprintf("CT log finished (%d candidate(s))", len(found)))
		}()
	}

	// Source 3: Wildcard-guarded common DNS lookup with bounded worker pool (<= 16).
	if req.UseCommonDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			markSource("common_dns")
			emit(fmt.Sprintf("Probing %d common DNS subdomain labels...", len(commonSubdomainLabels)))
			jobs := make(chan string, len(commonSubdomainLabels))
			for _, lbl := range commonSubdomainLabels {
				jobs <- lbl + "." + domain
			}
			close(jobs)

			var poolWG sync.WaitGroup
			workers := MaxSubdomainWorker
			if len(commonSubdomainLabels) < workers {
				workers = len(commonSubdomainLabels)
			}
			for i := 0; i < workers; i++ {
				poolWG.Add(1)
				go func() {
					defer poolWG.Done()
					for candidate := range jobs {
						if enumCtx.Err() != nil {
							return
						}
						qCtx, qCancel := context.WithTimeout(enumCtx, 2*time.Second)
						ips, lErr := subdomainLookupIP(qCtx, candidate)
						qCancel()
						if lErr != nil || len(ips) == 0 {
							continue
						}
						if len(wildcardSet) > 0 && allInSet(ips, wildcardSet) {
							continue
						}
						cCtx, cCancel := context.WithTimeout(enumCtx, 1500*time.Millisecond)
						cname, _ := subdomainLookupCNAME(cCtx, candidate)
						cCancel()
						addFinding(candidate, "common_dns", ips, cname)
					}
				}()
			}
			poolWG.Wait()
		}()
	}

	wg.Wait()

	// Optional DNS resolution pass for passively discovered entries lacking IPs.
	if req.ResolveDNS && enumCtx.Err() == nil {
		var toResolve []string
		mu.Lock()
		for h, e := range entries {
			if len(e.ips) == 0 {
				toResolve = append(toResolve, h)
			}
		}
		mu.Unlock()

		if len(toResolve) > 0 {
			emit(fmt.Sprintf("Resolving DNS for %d discovered subdomain(s)...", len(toResolve)))
			jobs := make(chan string, len(toResolve))
			for _, h := range toResolve {
				jobs <- h
			}
			close(jobs)

			workers := MaxSubdomainWorker
			if len(toResolve) < workers {
				workers = len(toResolve)
			}
			var rWG sync.WaitGroup
			for i := 0; i < workers; i++ {
				rWG.Add(1)
				go func() {
					defer rWG.Done()
					for host := range jobs {
						if enumCtx.Err() != nil {
							return
						}
						qCtx, qCancel := context.WithTimeout(enumCtx, 2*time.Second)
						ips, lErr := subdomainLookupIP(qCtx, host)
						qCancel()
						if lErr != nil || len(ips) == 0 {
							continue
						}
						if len(wildcardSet) > 0 && allInSet(ips, wildcardSet) {
							continue
						}
						cCtx, cCancel := context.WithTimeout(enumCtx, 1500*time.Millisecond)
						cname, _ := subdomainLookupCNAME(cCtx, host)
						cCancel()
						addFinding(host, "", ips, cname)
					}
				}()
			}
			rWG.Wait()
		}
	}

	out := make([]SubdomainEntry, 0, len(entries))
	for h, e := range entries {
		entry := SubdomainEntry{
			Hostname: h,
			Sources:  mapKeysSorted(e.sources),
			CNAME:    e.cname,
		}
		if len(e.ips) > 0 {
			entry.IPs = mapKeysSorted(e.ips)
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Hostname < out[j].Hostname
	})

	report.Subdomains = out
	report.TotalCount = len(out)
	report.SourcesUsed = mapKeysSorted(sourcesUsed)
	if len(warnings) > 0 {
		sort.Strings(warnings)
		report.Warnings = warnings
	}
	report.ElapsedMs = time.Since(start).Milliseconds()

	if enumCtx.Err() != nil && ctx.Err() != nil {
		return report, ctx.Err()
	}
	return report, nil
}

func runSubfinder(ctx context.Context, bin, domain string) ([]string, error) {
	// Strictly validated domain; direct exec with fixed allowlisted flags.
	cmd := exec.CommandContext(ctx, bin, "-silent", "-d", domain)
	configureProcGroup(cmd)
	var outBuf cappedBuffer
	outBuf.limit = maxSubfinderOutBytes
	var errBuf cappedBuffer
	errBuf.limit = 16 * 1024
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	var results []string
	scanner := bufio.NewScanner(strings.NewReader(string(outBuf.Bytes())))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			results = append(results, line)
		}
	}
	if err != nil && len(results) == 0 {
		errMsg := strings.TrimSpace(string(errBuf.Bytes()))
		if errMsg != "" {
			return nil, fmt.Errorf("%v: %s", err, errMsg)
		}
		return nil, err
	}
	return results, nil
}

type ctRecord struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

func queryCTLog(ctx context.Context, domain, endpointOverride string) ([]string, error) {
	ep := strings.TrimSpace(endpointOverride)
	if ep == "" {
		ep = fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))
	} else if strings.Contains(ep, "%s") {
		ep = fmt.Sprintf(ep, url.QueryEscape(domain))
	}

	u, err := url.Parse(ep)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid CT endpoint %q", ep)
	}

	reqCtx, cancel := context.WithTimeout(ctx, defaultCTTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ep, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultReconUA)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: defaultCTTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CT endpoint returned HTTP %d", resp.StatusCode)
	}

	body, _, err := readBodyCapped(resp.Body, MaxCTBodyBytes)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, nil
	}

	var records []ctRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("parse CT JSON: %w", err)
	}

	seen := make(map[string]bool)
	var out []string
	addCand := func(raw string) {
		for _, part := range strings.Split(raw, "\n") {
			h := normalizeSubdomainCandidate(part, domain)
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	for _, r := range records {
		addCand(r.NameValue)
		addCand(r.CommonName)
	}
	return out, nil
}

func normalizeSubdomainCandidate(raw, rootDomain string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || !isValidHostname(s) {
		return ""
	}
	if s != rootDomain && !strings.HasSuffix(s, "."+rootDomain) {
		return ""
	}
	return s
}

func allInSet(items []string, set map[string]bool) bool {
	if len(items) == 0 {
		return false
	}
	for _, it := range items {
		if !set[it] {
			return false
		}
	}
	return true
}

func randomHexBytes(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
