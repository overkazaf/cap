package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultNmapScanTimeout   = 120 * time.Second
	defaultNativeScanTimeout = 60 * time.Second
)

var (
	presetQuickPorts = []int{
		21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
		445, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 27017,
	}
	presetWebPorts = []int{
		80, 81, 443, 591, 3000, 4000, 5000, 5173, 8000, 8008,
		8080, 8081, 8088, 8090, 8443, 8880, 8888, 9000, 9090, 9443,
	}
	presetServicePorts = []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 389, 443, 445, 465, 587, 636, 993, 995, 1433,
		1521, 2049, 2181, 2375, 3000, 3306, 3389, 5432, 5672, 5900,
		6379, 6443, 8000, 8080, 8443, 9092, 9200, 11211, 27017,
	}
	presetTop100Ports = []int{
		7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
		79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
		139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
		465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
		636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
		1029, 1110, 1433, 1521, 1720, 1723, 1755, 1900, 2000, 2001,
		2049, 2121, 2181, 2375, 2717, 3000, 3128, 3306, 3389, 3986,
		4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
		5666, 5672, 5800, 5900, 6000, 6001, 6379, 6443, 6646, 7070,
		8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9200, 27017,
	}

	httpLikePorts = map[int]bool{
		80: true, 81: true, 443: true, 591: true, 3000: true, 4000: true,
		5000: true, 5173: true, 8000: true, 8008: true, 8080: true, 8081: true,
		8088: true, 8090: true, 8443: true, 8880: true, 8888: true, 9000: true,
		9090: true, 9443: true,
	}

	wellKnownServices = map[int]string{
		7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh",
		23: "telnet", 25: "smtp", 53: "domain", 79: "finger", 80: "http",
		81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp",
		135: "msrpc", 139: "netbios-ssn", 143: "imap", 179: "bgp", 389: "ldap",
		443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog", 548: "afp",
		554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
		990: "ftps", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
		1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-s",
		3000: "http", 3128: "squid-http", 3306: "mysql", 3389: "ms-wbt-server",
		4000: "http", 5000: "http", 5060: "sip", 5173: "http", 5432: "postgresql",
		5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "kubernetes-api",
		8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
		8081: "http-alt", 8088: "http", 8090: "http", 8443: "https-alt",
		8880: "http", 8888: "http-alt", 9000: "cslistener", 9090: "http",
		9092: "kafka", 9200: "elasticsearch", 9443: "https-alt", 11211: "memcached",
		27017: "mongodb",
	}

	sshBannerRe   = regexp.MustCompile(`^SSH-[0-9.]+-([^\s]+)`)
	httpServerRe  = regexp.MustCompile(`(?im)^Server:\s*([^\r\n]+)`)
	httpStatusRe  = regexp.MustCompile(`^HTTP/\d\.\d\s+(\d{3}[^\r\n]*)`)
	redisBannerRe = regexp.MustCompile(`(?i)^(redis|\+PONG|-ERR|-NOAUTH)`)
	mysqlBannerRe = regexp.MustCompile(`(?i)mysql|mariadb`)
	smtpBannerRe  = regexp.MustCompile(`^220[\s-].*(?i:smtp|esmtp|mail)`)
	ftpBannerRe   = regexp.MustCompile(`^220[\s-].*(?i:ftp|vsftpd|proftpd|pure-ftpd)`)
)

// ValidateScanTarget validates a target for authorized port scanning.
// Accepts a valid hostname, IPv4, IPv6, or IPv4 CIDR with prefix >= /24 (<= 256 hosts).
// Strictly rejects empty strings, whitespace, shell metacharacters, and leading '-'.
func ValidateScanTarget(target string) (string, error) {
	s := strings.TrimSpace(target)
	if s == "" {
		return "", errors.New("recon: scan target is empty")
	}
	if strings.HasPrefix(s, "-") {
		return "", fmt.Errorf("recon: invalid scan target %q: leading hyphen is prohibited", target)
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return "", fmt.Errorf("recon: invalid scan target %q: whitespace/control characters are prohibited", target)
		}
		switch r {
		case ';', '&', '|', '$', '`', '(', ')', '<', '>', '\\', '\'', '"', '*', '?', '{', '}', ',', '~', '!', '#', '@', '%', '^', '=', '+':
			return "", fmt.Errorf("recon: invalid scan target %q: disallowed character %q", target, r)
		}
	}

	if strings.Contains(s, "/") {
		if strings.Count(s, "/") != 1 {
			return "", fmt.Errorf("recon: invalid CIDR target %q", target)
		}
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return "", fmt.Errorf("recon: invalid CIDR target %q: %w", target, err)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return "", fmt.Errorf("recon: IPv6 CIDR target %q is not supported; use an individual IPv6 address or IPv4 /24..32 CIDR", target)
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 32 || ones < 24 {
			return "", fmt.Errorf("recon: CIDR prefix /%d exceeds maximum allowed scope (/24, max 256 hosts)", ones)
		}
		return fmt.Sprintf("%s/%d", ip4.String(), ones), nil
	}

	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), nil
	}

	if strings.Contains(s, ":") {
		return "", fmt.Errorf("recon: invalid scan target %q (do not include port in target)", target)
	}
	host := strings.ToLower(strings.TrimSuffix(s, "."))
	if !isValidHostname(host) {
		return "", fmt.Errorf("recon: invalid hostname scan target %q", target)
	}
	return host, nil
}

// ParsePortSpec parses a validated port list/range specification such as
// "22,80,443,8000-8010", deduplicates ports, enforces 1..65535 and at most 4096 ports.
func ParsePortSpec(spec string) ([]int, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil, errors.New("recon: port specification is empty")
	}
	if strings.HasPrefix(s, "-") {
		return nil, fmt.Errorf("recon: invalid port specification %q", spec)
	}

	seen := make(map[int]bool)
	parts := strings.Split(s, ",")
	for _, rawPart := range parts {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			return nil, fmt.Errorf("recon: empty port token in %q", spec)
		}
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("recon: invalid port range %q", part)
			}
			lo, err1 := parseStrictPort(bounds[0])
			hi, err2 := parseStrictPort(bounds[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("recon: invalid port range %q", part)
			}
			if lo > hi {
				return nil, fmt.Errorf("recon: inverted port range %d-%d", lo, hi)
			}
			// Guard before expanding huge ranges such as 1-65535.
			if hi-lo+1 > MaxCustomPorts {
				return nil, fmt.Errorf("recon: port range %d-%d exceeds maximum allowed %d ports", lo, hi, MaxCustomPorts)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					if len(seen) > MaxCustomPorts {
						return nil, fmt.Errorf("recon: total ports exceed maximum allowed %d ports", MaxCustomPorts)
					}
				}
			}
		} else {
			p, err := parseStrictPort(part)
			if err != nil {
				return nil, fmt.Errorf("recon: invalid port %q", part)
			}
			if !seen[p] {
				seen[p] = true
				if len(seen) > MaxCustomPorts {
					return nil, fmt.Errorf("recon: total ports exceed maximum allowed %d ports", MaxCustomPorts)
				}
			}
		}
	}

	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func parseStrictPort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 5 {
		return 0, errors.New("invalid port")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("non-digit in port")
		}
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, errors.New("port out of range 1..65535")
	}
	return p, nil
}

// FormatCanonicalPortSpec formats a sorted list of validated ports into a compact
// range specification (e.g. "22,80,443,8000-8010") safe to pass to nmap -p.
func FormatCanonicalPortSpec(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	var b strings.Builder
	start := sorted[0]
	prev := sorted[0]
	writeSeg := func(lo, hi int) {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		if lo == hi {
			b.WriteString(strconv.Itoa(lo))
		} else {
			b.WriteString(strconv.Itoa(lo))
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(hi))
		}
	}
	for i := 1; i < len(sorted); i++ {
		p := sorted[i]
		if p == prev {
			continue
		}
		if p == prev+1 {
			prev = p
			continue
		}
		writeSeg(start, prev)
		start = p
		prev = p
	}
	writeSeg(start, prev)
	return b.String()
}

// --- Nmap XML Parser -------------------------------------------------------

type nmapRunXML struct {
	XMLName xml.Name      `xml:"nmaprun"`
	Scanner string        `xml:"scanner,attr"`
	Args    string        `xml:"args,attr"`
	Version string        `xml:"version,attr"`
	Hosts   []nmapHostXML `xml:"host"`
	RunStat *nmapRunStats `xml:"runstats"`
}

type nmapRunStats struct {
	Finished *nmapFinishedXML `xml:"finished"`
	Hosts    *nmapHostsStat   `xml:"hosts"`
}

type nmapFinishedXML struct {
	Summary string `xml:"summary,attr"`
	Elapsed string `xml:"elapsed,attr"`
}

type nmapHostsStat struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

type nmapHostXML struct {
	Status    nmapStatusXML     `xml:"status"`
	Addresses []nmapAddressXML  `xml:"address"`
	Hostnames []nmapHostnameXML `xml:"hostnames>hostname"`
	Ports     []nmapPortXML     `xml:"ports>port"`
	OSMatches []nmapOSMatchXML  `xml:"os>osmatch"`
}

type nmapStatusXML struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapAddressXML struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnameXML struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPortXML struct {
	Protocol string          `xml:"protocol,attr"`
	PortID   int             `xml:"portid,attr"`
	State    nmapStateXML    `xml:"state"`
	Service  *nmapServiceXML `xml:"service"`
}

type nmapStateXML struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapServiceXML struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

type nmapOSMatchXML struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// ParseNmapXML parses Nmap `-oX -` XML output into structured ScannedHost records.
func ParseNmapXML(xmlData []byte) ([]ScannedHost, error) {
	hosts, _, err := parseNmapXMLDetailed(xmlData)
	return hosts, err
}

func parseNmapXMLDetailed(xmlData []byte) ([]ScannedHost, string, error) {
	trimmed := bytes.TrimSpace(xmlData)
	if len(trimmed) == 0 {
		return nil, "", errors.New("recon: empty nmap XML output")
	}

	var run nmapRunXML
	if err := xml.Unmarshal(trimmed, &run); err != nil {
		return nil, "", fmt.Errorf("recon: parse nmap XML: %w", err)
	}

	hosts := make([]ScannedHost, 0, len(run.Hosts))
	for _, h := range run.Hosts {
		sh := ScannedHost{
			State: strings.TrimSpace(h.Status.State),
			Ports: make([]OpenPort, 0, len(h.Ports)),
		}
		if sh.State == "" {
			sh.State = "unknown"
		}
		// Prefer IPv4/IPv6 over MAC address.
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				sh.Address = a.Addr
				sh.AddrType = a.AddrType
				break
			}
			if sh.Address == "" {
				sh.Address = a.Addr
				sh.AddrType = a.AddrType
			}
		}
		for _, hn := range h.Hostnames {
			if strings.TrimSpace(hn.Name) != "" {
				sh.Hostname = strings.TrimSpace(hn.Name)
				break
			}
		}
		bestAcc := -1
		for _, om := range h.OSMatches {
			acc, _ := strconv.Atoi(strings.TrimSpace(om.Accuracy))
			if acc > bestAcc && strings.TrimSpace(om.Name) != "" {
				bestAcc = acc
				sh.OSGuess = strings.TrimSpace(om.Name)
			}
		}
		for _, p := range h.Ports {
			op := OpenPort{
				Port:     p.PortID,
				Protocol: strings.TrimSpace(p.Protocol),
				State:    strings.TrimSpace(p.State.State),
			}
			if op.Protocol == "" {
				op.Protocol = "tcp"
			}
			if p.Service != nil {
				op.Service = strings.TrimSpace(p.Service.Name)
				op.Product = strings.TrimSpace(p.Service.Product)
				op.Version = strings.TrimSpace(p.Service.Version)
				op.ExtraInfo = strings.TrimSpace(p.Service.ExtraInfo)
			}
			if op.Service == "" {
				op.Service = wellKnownServices[op.Port]
			}
			sh.Ports = append(sh.Ports, op)
		}
		sort.Slice(sh.Ports, func(i, j int) bool {
			if sh.Ports[i].Port != sh.Ports[j].Port {
				return sh.Ports[i].Port < sh.Ports[j].Port
			}
			return sh.Ports[i].Protocol < sh.Ports[j].Protocol
		})
		hosts = append(hosts, sh)
	}

	summary := ""
	if run.RunStat != nil && run.RunStat.Finished != nil && strings.TrimSpace(run.RunStat.Finished.Summary) != "" {
		summary = strings.TrimSpace(run.RunStat.Finished.Summary)
	} else {
		summary = fmt.Sprintf("nmap %s scanned %d host(s)", strings.TrimSpace(run.Version), len(hosts))
	}
	return hosts, summary, nil
}

// --- Port Scan Execution ---------------------------------------------------

// RunPortScan runs an authorized TCP port/service scan using either the safe
// allowlisted Nmap XML wrapper or the pure-Go concurrent TCP connect & banner scanner.
func RunPortScan(ctx context.Context, req PortScanRequest, cfg ToolchainConfig, onProgress func(string)) (*PortScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()

	target, err := ValidateScanTarget(req.Target)
	if err != nil {
		return nil, err
	}

	engine := strings.ToLower(strings.TrimSpace(req.Engine))
	if engine == "" {
		engine = PortScanEngineAuto
	}
	switch engine {
	case PortScanEngineAuto, PortScanEngineNmap, PortScanEngineNative:
	default:
		return nil, fmt.Errorf("recon: unsupported port scan engine %q (expected auto, nmap, or native)", req.Engine)
	}

	preset := strings.ToLower(strings.TrimSpace(req.Preset))
	if preset == "" {
		if strings.TrimSpace(req.PortsSpec) != "" {
			preset = PresetCustom
		} else {
			preset = PresetQuick
		}
	}

	serviceVersion := req.ServiceVersion
	var ports []int
	switch preset {
	case PresetQuick:
		ports = append([]int(nil), presetQuickPorts...)
	case PresetTop100:
		ports = append([]int(nil), presetTop100Ports...)
	case PresetWeb:
		ports = append([]int(nil), presetWebPorts...)
	case PresetService:
		ports = append([]int(nil), presetServicePorts...)
		serviceVersion = true
	case PresetCustom:
		ports, err = ParsePortSpec(req.PortsSpec)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("recon: unsupported port scan preset %q (expected quick, top100, web, service, or custom)", req.Preset)
	}

	canonicalPorts := FormatCanonicalPortSpec(ports)

	timeoutMs := req.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = DefaultPortTimeout
	}
	if timeoutMs < 100 {
		timeoutMs = 100
	}
	if timeoutMs > 15000 {
		timeoutMs = 15000
	}

	var warnings []string
	var nmapBin string
	selectedEngine := engine
	switch engine {
	case PortScanEngineNmap:
		bin, ok := resolveToolBinary(cfg.NmapPath, "nmap")
		if !ok {
			return nil, errors.New("recon: nmap binary not found; install nmap or use engine \"native\"")
		}
		nmapBin = bin
	case PortScanEngineAuto:
		if bin, ok := resolveToolBinary(cfg.NmapPath, "nmap"); ok {
			nmapBin = bin
			selectedEngine = PortScanEngineNmap
		} else {
			selectedEngine = PortScanEngineNative
			warnings = append(warnings, "nmap not found on host; automatically fell back to pure-Go TCP scanner")
		}
	}

	scanCtx := ctx
	var cancel context.CancelFunc
	if req.TimeoutSec > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutSec)*time.Second)
		defer cancel()
	} else if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		if selectedEngine == PortScanEngineNmap {
			scanCtx, cancel = context.WithTimeout(ctx, defaultNmapScanTimeout)
		} else {
			scanCtx, cancel = context.WithTimeout(ctx, defaultNativeScanTimeout)
		}
		defer cancel()
	}

	var res *PortScanResult
	if selectedEngine == PortScanEngineNmap {
		res, err = runNmapScan(scanCtx, nmapBin, target, preset, canonicalPorts, len(ports), serviceVersion, req.SkipHostDiscovery, timeoutMs, onProgress)
	} else {
		concurrency := req.Concurrency
		if concurrency <= 0 {
			concurrency = MaxNativeWorkers
		}
		if concurrency > MaxNativeWorkers {
			concurrency = MaxNativeWorkers
		}
		res, err = runNativePortScan(scanCtx, target, preset, canonicalPorts, ports, serviceVersion, timeoutMs, concurrency, onProgress)
	}
	if err != nil {
		return nil, err
	}

	if len(warnings) > 0 {
		res.Warnings = append(warnings, res.Warnings...)
	}
	res.ElapsedMs = time.Since(start).Milliseconds()
	res.CheckedAt = nowRFC3339()
	return res, nil
}

func runNmapScan(
	ctx context.Context,
	nmapBin string,
	target string,
	preset string,
	canonicalPorts string,
	portCount int,
	serviceVersion bool,
	skipHostDiscovery bool,
	timeoutMs int,
	onProgress func(string),
) (*PortScanResult, error) {
	// Strict allowlisted Nmap arguments ONLY — never accepts raw user flags or --script.
	args := []string{"-sT", "-T4"}
	if skipHostDiscovery {
		args = append(args, "-Pn")
	}
	args = append(args, "-p", canonicalPorts)
	if serviceVersion {
		args = append(args, "-sV", "--version-light")
	}
	args = append(args, "-oX", "-", "--", target)

	displayCmd := nmapBin + " " + strings.Join(args, " ")
	if onProgress != nil {
		onProgress("Executing safe nmap scan: " + displayCmd)
	}

	cmd := exec.CommandContext(ctx, nmapBin, args...)
	configureProcGroup(cmd)

	var stdoutBuf cappedBuffer
	stdoutBuf.limit = MaxNmapXMLBytes

	stderrPipe, pipeErr := cmd.StderrPipe()
	if pipeErr != nil {
		return nil, fmt.Errorf("recon: nmap stderr pipe: %w", pipeErr)
	}
	cmd.Stdout = &stdoutBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("recon: start nmap: %w", err)
	}

	var stderrLines []string
	var stderrWG sync.WaitGroup
	stderrWG.Add(1)
	go func() {
		defer stderrWG.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if len(stderrLines) < 50 {
				stderrLines = append(stderrLines, line)
			}
			if onProgress != nil {
				onProgress("[nmap] " + line)
			}
		}
	}()

	waitErr := cmd.Wait()
	stderrWG.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	hosts, xmlSummary, parseErr := parseNmapXMLDetailed(stdoutBuf.Bytes())
	if parseErr != nil {
		if waitErr != nil {
			detail := strings.Join(stderrLines, "; ")
			if detail != "" {
				return nil, fmt.Errorf("nmap failed (%w): %s", waitErr, detail)
			}
			return nil, fmt.Errorf("nmap failed: %w", waitErr)
		}
		return nil, parseErr
	}

	openCount := 0
	for _, h := range hosts {
		for _, p := range h.Ports {
			if p.State == "open" {
				openCount++
			}
		}
	}

	hostCount := len(hosts)
	if hostCount == 0 {
		hostCount = 1
	}

	res := &PortScanResult{
		Target:         target,
		Engine:         PortScanEngineNmap,
		Preset:         preset,
		PortsSpec:      canonicalPorts,
		ServiceVersion: serviceVersion,
		TimeoutMs:      timeoutMs,
		Hosts:          hosts,
		Command:        displayCmd,
		RawXMLSummary:  xmlSummary,
		TotalScanned:   hostCount * portCount,
		OpenCount:      openCount,
	}
	if waitErr != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("nmap exited with warning: %v", waitErr))
	}
	if onProgress != nil {
		onProgress(fmt.Sprintf("nmap finished: %d host(s), %d open port(s)", len(hosts), openCount))
	}
	return res, nil
}

func runNativePortScan(
	ctx context.Context,
	target string,
	preset string,
	canonicalPorts string,
	ports []int,
	serviceVersion bool,
	timeoutMs int,
	concurrency int,
	onProgress func(string),
) (*PortScanResult, error) {
	targets, err := expandScanTargets(target)
	if err != nil {
		return nil, err
	}

	totalTasks := len(targets) * len(ports)
	if onProgress != nil {
		onProgress(fmt.Sprintf("Starting pure-Go TCP scan on %s (%d host(s) x %d port(s), %d workers)", target, len(targets), len(ports), concurrency))
	}

	type scanTask struct {
		host string
		port int
	}

	tasks := make(chan scanTask, minInt(totalTasks, concurrency*4))
	go func() {
		defer close(tasks)
		for _, h := range targets {
			for _, p := range ports {
				select {
				case <-ctx.Done():
					return
				case tasks <- scanTask{host: h, port: p}:
				}
			}
		}
	}()

	var (
		mu       sync.Mutex
		hostHits = make(map[string][]OpenPort)
		scanned  atomic.Int64
	)

	perPortTimeout := time.Duration(timeoutMs) * time.Millisecond
	workers := minInt(concurrency, totalTasks)
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: perPortTimeout}
			for task := range tasks {
				if ctx.Err() != nil {
					return
				}
				dialStart := time.Now()
				pCtx, cancel := context.WithTimeout(ctx, perPortTimeout)
				conn, dErr := dialer.DialContext(pCtx, "tcp", net.JoinHostPort(task.host, strconv.Itoa(task.port)))
				cancel()
				scanned.Add(1)
				if dErr != nil {
					continue
				}
				latency := time.Since(dialStart).Milliseconds()
				banner := grabTCPBanner(conn, task.host, task.port, serviceVersion, minDuration(perPortTimeout, 800*time.Millisecond))
				_ = conn.Close()

				service, product, version := inferServiceFromPortAndBanner(task.port, banner)
				op := OpenPort{
					Port:      task.port,
					Protocol:  "tcp",
					State:     "open",
					Service:   service,
					Product:   product,
					Version:   version,
					Banner:    banner,
					LatencyMs: latency,
				}
				mu.Lock()
				hostHits[task.host] = append(hostHits[task.host], op)
				mu.Unlock()
				if onProgress != nil {
					onProgress(fmt.Sprintf("open %s:%d/tcp (%s) %dms", task.host, task.port, service, latency))
				}
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	hosts := make([]ScannedHost, 0, len(targets))
	openCount := 0
	for _, h := range targets {
		openPorts := hostHits[h]
		if len(openPorts) == 0 && len(targets) > 1 {
			continue
		}
		sort.Slice(openPorts, func(i, j int) bool {
			return openPorts[i].Port < openPorts[j].Port
		})
		if openPorts == nil {
			openPorts = []OpenPort{}
		}
		openCount += len(openPorts)
		state := "up"
		if len(openPorts) == 0 {
			state = "unknown"
		}
		addrType := "hostname"
		hostname := ""
		if ip := net.ParseIP(h); ip != nil {
			if ip.To4() != nil {
				addrType = "ipv4"
			} else {
				addrType = "ipv6"
			}
		} else {
			hostname = h
		}
		hosts = append(hosts, ScannedHost{
			Address:  h,
			AddrType: addrType,
			Hostname: hostname,
			State:    state,
			Ports:    openPorts,
		})
	}

	if onProgress != nil {
		onProgress(fmt.Sprintf("Pure-Go TCP scan finished: %d/%d open port(s)", openCount, scanned.Load()))
	}

	return &PortScanResult{
		Target:         target,
		Engine:         PortScanEngineNative,
		Preset:         preset,
		PortsSpec:      canonicalPorts,
		ServiceVersion: serviceVersion,
		TimeoutMs:      timeoutMs,
		Hosts:          hosts,
		Command:        fmt.Sprintf("native-tcp -p %s %s", canonicalPorts, target),
		TotalScanned:   int(scanned.Load()),
		OpenCount:      openCount,
	}, nil
}

func expandScanTargets(target string) ([]string, error) {
	if !strings.Contains(target, "/") {
		return []string{target}, nil
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, err
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil, errors.New("recon: only IPv4 CIDRs are supported")
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 24 {
		return nil, fmt.Errorf("recon: CIDR /%d exceeds max /24 scope", ones)
	}
	hostCount := 1 << uint(32-ones)
	base := binary.BigEndian.Uint32(ip4)
	out := make([]string, 0, hostCount)
	for i := 0; i < hostCount; i++ {
		// For subnets /24../30 skip network and broadcast addresses.
		if ones <= 30 && (i == 0 || i == hostCount-1) {
			continue
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base+uint32(i))
		out = append(out, net.IP(b[:]).String())
	}
	return out, nil
}

func grabTCPBanner(conn net.Conn, host string, port int, probeHTTP bool, timeout time.Duration) string {
	if timeout < 150*time.Millisecond {
		timeout = 150 * time.Millisecond
	}
	buf := make([]byte, 512)

	// Step 1: Passive greeting read (catches SSH, FTP, SMTP, POP3, IMAP, MySQL, custom listeners).
	passiveWait := minDuration(timeout/2, 250*time.Millisecond)
	_ = conn.SetReadDeadline(time.Now().Add(passiveWait))
	n, _ := conn.Read(buf)
	if n > 0 {
		return sanitizeBanner(buf[:n])
	}

	// Step 2: Lightweight HTTP HEAD probe for HTTP-like ports (or when service version is enabled).
	if httpLikePorts[port] || probeHTTP {
		req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", host, defaultReconUA)
		_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, wErr := io.WriteString(conn, req); wErr == nil {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
			n2, _ := conn.Read(buf)
			if n2 > 0 {
				return sanitizeBanner(buf[:n2])
			}
		}
	}
	return ""
}

func sanitizeBanner(raw []byte) string {
	var b strings.Builder
	b.Grow(minInt(len(raw), 200))
	prevSpace := false
	for _, c := range raw {
		if b.Len() >= 200 {
			break
		}
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			if !prevSpace && b.Len() > 0 {
				b.WriteByte(' ')
				prevSpace = true
			}
		case c >= 0x20 && c <= 0x7e:
			b.WriteByte(c)
			prevSpace = (c == ' ')
		}
	}
	return strings.TrimSpace(b.String())
}

func inferServiceFromPortAndBanner(port int, banner string) (service, product, version string) {
	service = wellKnownServices[port]
	if service == "" {
		service = "tcp"
	}
	if banner == "" {
		return service, "", ""
	}
	if m := sshBannerRe.FindStringSubmatch(banner); len(m) >= 2 {
		service = "ssh"
		parts := strings.SplitN(m[1], "_", 2)
		product = parts[0]
		if len(parts) == 2 {
			version = parts[1]
		}
		return service, product, version
	}
	if httpStatusRe.MatchString(banner) {
		if service == "tcp" {
			service = "http"
		}
		if sm := httpServerRe.FindStringSubmatch(strings.ReplaceAll(banner, " Server:", "\nServer:")); len(sm) >= 2 {
			srv := strings.TrimSpace(sm[1])
			if idx := strings.IndexByte(srv, ' '); idx > 0 {
				srv = srv[:idx]
			}
			if slash := strings.IndexByte(srv, '/'); slash > 0 {
				product = srv[:slash]
				version = srv[slash+1:]
			} else {
				product = srv
			}
		}
		return service, product, version
	}
	if ftpBannerRe.MatchString(banner) {
		return "ftp", "", ""
	}
	if smtpBannerRe.MatchString(banner) {
		return "smtp", "", ""
	}
	if redisBannerRe.MatchString(banner) {
		return "redis", "Redis", ""
	}
	if mysqlBannerRe.MatchString(banner) {
		return "mysql", "MySQL", ""
	}
	return service, "", ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
