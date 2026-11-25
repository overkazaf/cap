// Package recon implements cap's Site Reconnaissance, Domain Intelligence,
// Subdomain Discovery, and Safe Port/Service Scanner subsystem.
//
// Strictly focused on authorized network diagnostics, asset inventory,
// security header auditing, TLS certificate inspection, and standard
// TCP/Nmap service enumeration.
package recon

import (
	"net/http"
	"time"
)

const (
	// Async recon job kinds.
	JobKindDomain    = "domain"
	JobKindSite      = "site"
	JobKindSubdomain = "subdomain"
	JobKindPortScan  = "portscan"

	// Async recon job lifecycle statuses.
	StatusIdle      = "idle"
	StatusRunning   = "running"
	StatusDone      = "done"
	StatusError     = "error"
	StatusCancelled = "cancelled"

	// Port scan engines.
	PortScanEngineAuto   = "auto"
	PortScanEngineNmap   = "nmap"
	PortScanEngineNative = "native"

	// Port scan presets.
	PresetQuick   = "quick"
	PresetTop100  = "top100"
	PresetWeb     = "web"
	PresetService = "service"
	PresetCustom  = "custom"

	// Bounded safety limits.
	MaxJobEvents       = 1000
	MaxHistoryEntries  = 50
	MaxCustomPorts     = 4096
	MaxHTTPBodyBytes   = 1 << 20   // 1 MiB
	MaxCTBodyBytes     = 2 << 20   // 2 MiB
	MaxFaviconBytes    = 512 << 10 // 512 KiB
	MaxWhoisRawBytes   = 32 << 10  // 32 KiB
	MaxNmapXMLBytes    = 16 << 20  // 16 MiB
	MaxSitemapSamples  = 30
	MaxRedirects       = 10
	MaxNativeWorkers   = 64
	MaxSubdomainWorker = 16
	DefaultPortTimeout = 1200 // ms
)

// ToolchainConfig allows overriding auto-discovered host binaries.
// When a field is non-empty, detection strictly probes only that path.
type ToolchainConfig struct {
	NmapPath      string `json:"nmap_path,omitempty"`
	SubfinderPath string `json:"subfinder_path,omitempty"`
	WhoisPath     string `json:"whois_path,omitempty"`
	DigPath       string `json:"dig_path,omitempty"`
}

// ToolStatus reports discovery status, version, path, and install guidance for
// one host reconnaissance binary.
type ToolStatus struct {
	Name    string `json:"name"`
	Ready   bool   `json:"ready"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Issue   string `json:"issue,omitempty"`
	Install string `json:"install,omitempty"`
}

// ToolchainInfo summarizes host readiness across nmap, subfinder, whois, and dig.
type ToolchainInfo struct {
	Nmap      ToolStatus `json:"nmap"`
	Subfinder ToolStatus `json:"subfinder"`
	Whois     ToolStatus `json:"whois"`
	Dig       ToolStatus `json:"dig"`
	Issues    []string   `json:"issues,omitempty"`
	CheckedAt string     `json:"checked_at,omitempty"`
}

// MXRecord represents a DNS mail exchanger record.
type MXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

// DNSRecords aggregates standard pure-Go DNS resolution records for a host.
type DNSRecords struct {
	A     []string   `json:"a"`
	AAAA  []string   `json:"aaaa"`
	CNAME string     `json:"cname,omitempty"`
	MX    []MXRecord `json:"mx"`
	NS    []string   `json:"ns"`
	TXT   []string   `json:"txt"`
	PTR   []string   `json:"ptr"`
}

// WhoisSummary holds structured WHOIS registration metadata and a capped raw transcript.
type WhoisSummary struct {
	Domain       string   `json:"domain"`
	Registrar    string   `json:"registrar,omitempty"`
	CreationDate string   `json:"creation_date,omitempty"`
	ExpiryDate   string   `json:"expiry_date,omitempty"`
	UpdatedDate  string   `json:"updated_date,omitempty"`
	NameServers  []string `json:"name_servers,omitempty"`
	Statuses     []string `json:"statuses,omitempty"`
	Raw          string   `json:"raw,omitempty"`
	Truncated    bool     `json:"truncated,omitempty"`
}

// TLSCertInfo holds inspected X.509 certificate metadata from a live TLS peer.
type TLSCertInfo struct {
	Subject           string   `json:"subject"`
	CommonName        string   `json:"common_name,omitempty"`
	Issuer            string   `json:"issuer"`
	Serial            string   `json:"serial"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	DaysUntilExpiry   int      `json:"days_until_expiry"`
	Expired           bool     `json:"expired"`
	SelfSigned        bool     `json:"self_signed"`
	IsCA              bool     `json:"is_ca"`
	SANs              []string `json:"sans"`
	SHA256Fingerprint string   `json:"sha256_fingerprint"`
	PubKeyAlgo        string   `json:"pub_key_algo"`
	PubKeyBits        int      `json:"pub_key_bits"`
	SignatureAlgo     string   `json:"signature_algo,omitempty"`
}

// TLSInspectReport holds live TLS handshake negotiation and peer certificate chain details.
type TLSInspectReport struct {
	Host        string        `json:"host"`
	Port        int           `json:"port"`
	ServerName  string        `json:"server_name,omitempty"`
	TLSVersion  string        `json:"tls_version"`
	CipherSuite string        `json:"cipher_suite"`
	ALPN        string        `json:"alpn,omitempty"`
	Verified    bool          `json:"verified"`
	VerifyError string        `json:"verify_error,omitempty"`
	Leaf        *TLSCertInfo  `json:"leaf,omitempty"`
	Chain       []TLSCertInfo `json:"chain"`
	ElapsedMs   int64         `json:"elapsed_ms"`
	CheckedAt   string        `json:"checked_at"`
}

// DomainReport aggregates DNS, CDN/WAF, WHOIS, and TLS intelligence for a target domain.
type DomainReport struct {
	Target       string            `json:"target"`
	RootDomain   string            `json:"root_domain"`
	IPv4         []string          `json:"ipv4"`
	IPv6         []string          `json:"ipv6"`
	DNSRecords   DNSRecords        `json:"dns_records"`
	CDNProviders []string          `json:"cdn_providers"`
	WAFHints     []string          `json:"waf_hints"`
	Whois        *WhoisSummary     `json:"whois,omitempty"`
	TLS          *TLSInspectReport `json:"tls,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
	ElapsedMs    int64             `json:"elapsed_ms"`
	CheckedAt    string            `json:"checked_at"`
}

// SiteProbeOptions configures HTTP site fingerprinting and discovery probes.
type SiteProbeOptions struct {
	TimeoutMs          int               `json:"timeout_ms,omitempty"`
	NoRedirects        bool              `json:"no_redirects,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
	SkipDiscovery      bool              `json:"skip_discovery,omitempty"`
	UserAgent          string            `json:"user_agent,omitempty"`
	CustomHeaders      map[string]string `json:"custom_headers,omitempty"`
	Client             *http.Client      `json:"-"`
}

// RedirectHop records one HTTP redirect step encountered while probing a URL.
type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location,omitempty"`
}

// TechMatch represents a detected web server, framework, CDN, WAF, or platform signal.
type TechMatch struct {
	Name       string `json:"name"`
	Category   string `json:"category"` // "web-server" | "cdn" | "waf" | "framework" | "frontend" | "language" | "api" | "cms" | "proxy"
	Version    string `json:"version,omitempty"`
	Confidence string `json:"confidence"` // "high" | "medium" | "low"
	Evidence   string `json:"evidence"`
}

// HeaderAuditItem evaluates a single HTTP security header and its score contribution.
type HeaderAuditItem struct {
	Header         string `json:"header"`
	Present        bool   `json:"present"`
	Value          string `json:"value,omitempty"`
	Status         string `json:"status"` // "pass" | "warn" | "fail"
	Weight         int    `json:"weight"`
	Score          int    `json:"score"`
	Recommendation string `json:"recommendation,omitempty"`
}

// RobotsSummary holds parsed directives from /robots.txt.
type RobotsSummary struct {
	Found      bool     `json:"found"`
	StatusCode int      `json:"status_code,omitempty"`
	Allow      []string `json:"allow"`
	Disallow   []string `json:"disallow"`
	Sitemaps   []string `json:"sitemaps"`
	RawLines   int      `json:"raw_lines,omitempty"`
}

// WellKnownHit records the discovery status of a standard /.well-known endpoint.
type WellKnownHit struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type,omitempty"`
	Found       bool   `json:"found"`
	Snippet     string `json:"snippet,omitempty"`
}

// SiteProfile holds HTTP response metadata, technology fingerprints, security header audit,
// and standard site discovery artifacts.
type SiteProfile struct {
	TargetURL       string            `json:"target_url"`
	FinalURL        string            `json:"final_url"`
	StatusCode      int               `json:"status_code"`
	Protocol        string            `json:"protocol"`
	Title           string            `json:"title,omitempty"`
	MetaGenerator   string            `json:"meta_generator,omitempty"`
	Server          string            `json:"server,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	ContentLength   int64             `json:"content_length"`
	ElapsedMs       int64             `json:"elapsed_ms"`
	RedirectChain   []RedirectHop     `json:"redirect_chain"`
	Headers         map[string]string `json:"headers"`
	Technologies    []TechMatch       `json:"technologies"`
	CDNProviders    []string          `json:"cdn_providers"`
	WAFHints        []string          `json:"waf_hints"`
	SecurityHeaders []HeaderAuditItem `json:"security_headers"`
	SecurityScore   int               `json:"security_score"`
	FaviconSHA256   string            `json:"favicon_sha256,omitempty"`
	RobotsRules     *RobotsSummary    `json:"robots_rules,omitempty"`
	SitemapURLs     []string          `json:"sitemap_urls"`
	WellKnownPaths  []WellKnownHit    `json:"well_known_paths"`
	Warnings        []string          `json:"warnings,omitempty"`
	CheckedAt       string            `json:"checked_at"`
}

// SubdomainRequest configures multi-source subdomain discovery.
type SubdomainRequest struct {
	Domain       string `json:"domain"`
	UseSubfinder bool   `json:"use_subfinder"`
	UseCTLog     bool   `json:"use_ct_log"`
	UseCommonDNS bool   `json:"use_common_dns"`
	ResolveDNS   bool   `json:"resolve_dns"`
	TimeoutSec   int    `json:"timeout_sec,omitempty"`
	CTEndpoint   string `json:"ct_endpoint,omitempty"`
}

// SubdomainEntry represents one deduplicated discovered subdomain.
type SubdomainEntry struct {
	Hostname string   `json:"hostname"`
	Sources  []string `json:"sources"`
	IPs      []string `json:"ips,omitempty"`
	CNAME    string   `json:"cname,omitempty"`
}

// SubdomainReport holds aggregated subdomain enumeration findings and wildcard status.
type SubdomainReport struct {
	Domain           string           `json:"domain"`
	WildcardDetected bool             `json:"wildcard_detected"`
	WildcardIPs      []string         `json:"wildcard_ips,omitempty"`
	Subdomains       []SubdomainEntry `json:"subdomains"`
	TotalCount       int              `json:"total_count"`
	SourcesUsed      []string         `json:"sources_used"`
	ElapsedMs        int64            `json:"elapsed_ms"`
	Warnings         []string         `json:"warnings,omitempty"`
	CheckedAt        string           `json:"checked_at"`
}

// PortScanRequest configures an authorized Nmap or pure-Go TCP port/service scan.
type PortScanRequest struct {
	Target            string `json:"target"`
	Engine            string `json:"engine,omitempty"`              // "auto" | "nmap" | "native"
	Preset            string `json:"preset,omitempty"`              // "quick" | "top100" | "web" | "service" | "custom"
	PortsSpec         string `json:"ports_spec,omitempty"`          // validated port list/ranges when preset=="custom"
	ServiceVersion    bool   `json:"service_version,omitempty"`     // enables -sV --version-light / HTTP banner probe
	SkipHostDiscovery bool   `json:"skip_host_discovery,omitempty"` // enables -Pn for nmap
	TimeoutMs         int    `json:"timeout_ms,omitempty"`          // per-port dial timeout for native scanner (default 1200)
	Concurrency       int    `json:"concurrency,omitempty"`         // bounded <= 64
	TimeoutSec        int    `json:"timeout_sec,omitempty"`         // overall scan timeout
}

// OpenPort describes a single discovered port and its identified service/banner.
type OpenPort struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"` // "tcp" | "udp"
	State     string `json:"state"`    // "open" | "filtered" | "closed"
	Service   string `json:"service,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"`
	Banner    string `json:"banner,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
}

// ScannedHost aggregates scan findings for a single target host.
type ScannedHost struct {
	Address  string     `json:"address"`
	AddrType string     `json:"addr_type,omitempty"`
	Hostname string     `json:"hostname,omitempty"`
	State    string     `json:"state"` // "up" | "down" | "unknown"
	OSGuess  string     `json:"os_guess,omitempty"`
	Ports    []OpenPort `json:"ports"`
}

// PortScanResult summarizes a completed Nmap or pure-Go TCP port scan.
type PortScanResult struct {
	Target         string        `json:"target"`
	Engine         string        `json:"engine"` // "nmap" | "native"
	Preset         string        `json:"preset"`
	PortsSpec      string        `json:"ports_spec,omitempty"`
	ServiceVersion bool          `json:"service_version"`
	TimeoutMs      int           `json:"timeout_ms"`
	Hosts          []ScannedHost `json:"hosts"`
	Command        string        `json:"command,omitempty"`
	RawXMLSummary  string        `json:"raw_xml_summary,omitempty"`
	TotalScanned   int           `json:"total_scanned"`
	OpenCount      int           `json:"open_count"`
	ElapsedMs      int64         `json:"elapsed_ms"`
	Warnings       []string      `json:"warnings,omitempty"`
	CheckedAt      string        `json:"checked_at"`
}

// ReconJobEvent represents one streamed progress/status log line emitted by an async recon job.
type ReconJobEvent struct {
	Seq         int64  `json:"seq"`
	JobID       string `json:"job_id"`
	TimestampMs int64  `json:"timestamp_ms"`
	Kind        string `json:"kind"`  // "domain" | "site" | "subdomain" | "portscan"
	Level       string `json:"level"` // "info" | "warn" | "error" | "system" | "progress" | "result"
	Message     string `json:"message"`
}

// ReconJobRequest configures launching an asynchronous, cancellable recon job.
type ReconJobRequest struct {
	Kind        string            `json:"kind"` // "domain" | "site" | "subdomain" | "portscan"
	Target      string            `json:"target,omitempty"`
	SiteOptions *SiteProbeOptions `json:"site_options,omitempty"`
	Subdomain   *SubdomainRequest `json:"subdomain,omitempty"`
	PortScan    *PortScanRequest  `json:"port_scan,omitempty"`
	TimeoutSec  int               `json:"timeout_sec,omitempty"`
	SaveHistory *bool             `json:"save_history,omitempty"`
}

// ReconJobState holds the live or most recent asynchronous recon job snapshot.
type ReconJobState struct {
	ID              string           `json:"id"`
	Kind            string           `json:"kind"`
	Target          string           `json:"target"`
	Status          string           `json:"status"` // "idle" | "running" | "done" | "error" | "cancelled"
	Running         bool             `json:"running"`
	Command         string           `json:"command,omitempty"`
	StartedAtMs     int64            `json:"started_at_ms,omitempty"`
	FinishedAtMs    int64            `json:"finished_at_ms,omitempty"`
	ElapsedMs       int64            `json:"elapsed_ms,omitempty"`
	Error           string           `json:"error,omitempty"`
	EventCount      int              `json:"event_count"`
	Events          []ReconJobEvent  `json:"events"`
	HistoryID       string           `json:"history_id,omitempty"`
	DomainReport    *DomainReport    `json:"domain_report,omitempty"`
	SiteProfile     *SiteProfile     `json:"site_profile,omitempty"`
	SubdomainReport *SubdomainReport `json:"subdomain_report,omitempty"`
	PortScanResult  *PortScanResult  `json:"port_scan_result,omitempty"`
}

// ReconHistoryEntry is a persisted reconnaissance record stored under ~/.cap/recon-history/*.json.
type ReconHistoryEntry struct {
	ID              string           `json:"id"`
	Kind            string           `json:"kind"`
	Target          string           `json:"target"`
	Summary         string           `json:"summary"`
	Status          string           `json:"status"`
	ElapsedMs       int64            `json:"elapsed_ms"`
	CreatedAt       string           `json:"created_at"`
	DomainReport    *DomainReport    `json:"domain_report,omitempty"`
	SiteProfile     *SiteProfile     `json:"site_profile,omitempty"`
	SubdomainReport *SubdomainReport `json:"subdomain_report,omitempty"`
	PortScanResult  *PortScanResult  `json:"port_scan_result,omitempty"`
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
