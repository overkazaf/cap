// Package gateway implements cap's Serviceization & Full-Chain Integration
// Gateway engine: Proxy IP Pool, Device Pool & Virtual Fingerprint Profiles,
// Pluggable Signer Providers (Script / HTTP / Unidbg HTTP / Frida RPC /
// Built-in HMAC), and an embedded Open API Gateway HTTP server with OpenAPI
// 3.0.3 export, API Key authentication, per-route rate limiting, and live
// telemetry.
package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// Proxy & account pool rotation strategies.
	StrategyRoundRobin   = "round_robin"
	StrategyRandom       = "random"
	StrategyLeastLatency = "least_latency"
	StrategyStickyDevice = "sticky_device"
	StrategyLeastUsed    = "least_used"

	// Account lifecycle statuses.
	AccountStatusActive     = "active"
	AccountStatusExpired    = "expired"
	AccountStatusChallenged = "challenged"
	AccountStatusDisabled   = "disabled"

	// Managed signer worker pool kinds.
	WorkerKindUnidbgHTTP = "unidbg_http"
	WorkerKindQilingHTTP = "qiling_http"
	WorkerKindScriptHTTP = "script_http"
	WorkerKindCustom     = "custom"

	// Upstream TLS fingerprint profiles.
	TLSProfileGoDefault     = "go_default"
	TLSProfileChrome131     = "chrome_131"
	TLSProfileSafari17      = "safari_17"
	TLSProfileFirefox132    = "firefox_132"
	TLSProfileOkHttpAndroid = "okhttp_android"
	TLSProfileIOSCFNetwork  = "ios_cfnetwork"

	// Per-route circuit breaker states.
	CircuitStateClosed   = "closed"
	CircuitStateOpen     = "open"
	CircuitStateHalfOpen = "half_open"

	// Dynamic IP provider response formats.
	ProviderFormatLines = "lines"
	ProviderFormatJSON  = "json"

	// Device profile kinds.
	DeviceKindVirtual  = "virtual"
	DeviceKindPhysical = "physical"

	// Signer provider kinds.
	SignerKindScript      = "script"
	SignerKindHTTP        = "http"
	SignerKindUnidbgHTTP  = "unidbg_http"
	SignerKindFridaRPC    = "frida_rpc"
	SignerKindBuiltinHMAC = "builtin_hmac"

	// Signer injection targets.
	InjectTargetQuery    = "query"
	InjectTargetHeader   = "header"
	InjectTargetBodyJSON = "body_json"

	// Operational defaults.
	DefaultListenAddr             = "127.0.0.1:9090"
	DefaultMaxLogs                = 500
	DefaultTimeoutSec             = 15
	DefaultSignerTimeoutSec       = 10
	DefaultFailoverRetries        = 2
	DefaultHealthCheckURL         = "http://connectivitycheck.gstatic.com/generate_204"
	DefaultWorkerHealthPath       = "/health"
	DefaultWorkerSignPath         = "/sign"
	DefaultWorkerMaxRestarts      = 5
	DefaultWorkerRestartBackoffMs = 500
	DefaultCacheMaxEntries        = 512
	DefaultCircuitCooldownSec     = 30
	DefaultMaxRefreshAttempts     = 1
)

// ProxyNode represents one outbound proxy server in the Proxy IP Pool.
type ProxyNode struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	URL          string   `json:"url"` // http://, https://, socks5://, socks5h://
	Username     string   `json:"username,omitempty"`
	Password     string   `json:"password,omitempty"`
	Region       string   `json:"region,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Enabled      bool     `json:"enabled"`
	Healthy      bool     `json:"healthy"`
	LatencyMs    int64    `json:"latency_ms"`
	SuccessCount int64    `json:"success_count"`
	FailCount    int64    `json:"fail_count"`
	LastChecked  string   `json:"last_checked,omitempty"`
	LastError    string   `json:"last_error,omitempty"`
}

// ProxyPoolConfig configures proxy rotation, dynamic provider fetching,
// health probing, and failover retries.
type ProxyPoolConfig struct {
	Strategy           string `json:"strategy"` // "round_robin"|"random"|"least_latency"|"sticky_device"
	ProviderURL        string `json:"provider_url,omitempty"`
	ProviderFormat     string `json:"provider_format,omitempty"` // "lines"|"json"
	ProviderJSONPath   string `json:"provider_json_path,omitempty"`
	RefreshIntervalSec int    `json:"refresh_interval_sec,omitempty"`
	HealthCheckURL     string `json:"health_check_url,omitempty"`
	FailoverRetries    int    `json:"failover_retries"`
}

// ProxySelectOptions constrains proxy selection during request execution.
type ProxySelectOptions struct {
	Tags          []string
	Region        string
	StickyProxyID string
	ExcludeIDs    map[string]bool
	Strategy      string
}

// DeviceFingerprint holds realistic client/device identity attributes used for
// header synthesis and template variable expansion.
type DeviceFingerprint struct {
	Model        string            `json:"model"`
	Brand        string            `json:"brand"`
	OSVersion    string            `json:"os_version"`
	SDK          int               `json:"sdk"`
	UserAgent    string            `json:"user_agent"`
	DeviceID     string            `json:"device_id,omitempty"`
	AndroidID    string            `json:"android_id,omitempty"`
	OAID         string            `json:"oaid,omitempty"`
	Locale       string            `json:"locale,omitempty"`
	Timezone     string            `json:"timezone,omitempty"`
	Screen       string            `json:"screen,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// DeviceProfile represents a virtual or physical Android device identity in
// the Device Pool, including optional sticky proxy affinity and session state.
type DeviceProfile struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"` // "virtual"|"physical"
	ADBSerial     string            `json:"adb_serial,omitempty"`
	Enabled       bool              `json:"enabled"`
	Tags          []string          `json:"tags,omitempty"`
	StickyProxyID string            `json:"sticky_proxy_id,omitempty"`
	ProxyRegion   string            `json:"proxy_region,omitempty"`
	Fingerprint   DeviceFingerprint `json:"fingerprint"`
	Cookies       map[string]string `json:"cookies,omitempty"`
	AuthHeaders   map[string]string `json:"auth_headers,omitempty"`
	Tokens        map[string]string `json:"tokens,omitempty"`
	InUseCount    int64             `json:"in_use_count"`
	LastUsedAt    string            `json:"last_used_at,omitempty"`
	CreatedAt     string            `json:"created_at,omitempty"`
	UpdatedAt     string            `json:"updated_at,omitempty"`
}

// DevicePreset describes a curated virtual Android device template.
type DevicePreset struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Tags        []string          `json:"tags,omitempty"`
	Fingerprint DeviceFingerprint `json:"fingerprint"`
}

// SignerProvider defines a pluggable request-signing backend.
type SignerProvider struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind"` // "script"|"http"|"unidbg_http"|"frida_rpc"|"builtin_hmac"
	Enabled       bool              `json:"enabled"`
	Description   string            `json:"description,omitempty"`
	Runtime       string            `json:"runtime,omitempty"` // "python3"|"node"|"sh"
	ScriptCode    string            `json:"script_code,omitempty"`
	EndpointURL   string            `json:"endpoint_url,omitempty"`
	WorkerPoolID  string            `json:"worker_pool_id,omitempty"`
	HTTPMethod    string            `json:"http_method,omitempty"`
	TimeoutSec    int               `json:"timeout_sec,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	HMACAlgorithm string            `json:"hmac_algorithm,omitempty"` // "md5"|"sha1"|"sha256"|"hmac-sha256"
	HMACSecret    string            `json:"hmac_secret,omitempty"`
	FridaSerial   string            `json:"frida_serial,omitempty"`
	FridaPackage  string            `json:"frida_package,omitempty"`
	FridaExport   string            `json:"frida_export,omitempty"`
	InjectTarget  string            `json:"inject_target,omitempty"` // "query"|"header"|"body_json"
	InjectField   string            `json:"inject_field,omitempty"`
	OutputMapping map[string]string `json:"output_mapping,omitempty"`
}

// SignerInput is the normalized request payload delivered to a signer backend.
type SignerInput struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Path      string            `json:"path"`
	Query     map[string]string `json:"query"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Timestamp int64             `json:"timestamp"`
	Nonce     string            `json:"nonce"`
	Device    *DeviceProfile    `json:"device,omitempty"`
	Account   *AccountProfile   `json:"account,omitempty"`
	Input     map[string]string `json:"input,omitempty"`
}

// SignerOutput captures signature fields produced by a signer backend.
type SignerOutput struct {
	Sign       string            `json:"sign,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyFields map[string]any    `json:"body_fields,omitempty"`
	Raw        map[string]any    `json:"raw,omitempty"`
	LatencyMs  int64             `json:"latency_ms"`
}

// AccountRefreshConfig defines defaults for automatic session refresh and
// non-refreshable challenge alerting.
type AccountRefreshConfig struct {
	RefreshRouteSlug    string `json:"refresh_route_slug,omitempty"`
	RefreshOnStatuses   []int  `json:"refresh_on_statuses,omitempty"` // e.g. [401, 403]
	RefreshOnBodySubstr string `json:"refresh_on_body_substr,omitempty"`
	ChallengeWebhookURL string `json:"challenge_webhook_url,omitempty"`
	MaxRefreshAttempts  int    `json:"max_refresh_attempts,omitempty"`
}

// AccountPoolConfig configures multi-account rotation and default refresh policy.
type AccountPoolConfig struct {
	Strategy string               `json:"strategy"` // "round_robin"|"least_used"|"sticky_device"
	Refresh  AccountRefreshConfig `json:"refresh,omitempty"`
}

// AccountProfile represents one authenticated account/session in the Account Pool.
type AccountProfile struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Username       string            `json:"username,omitempty"`
	Token          string            `json:"token,omitempty"`
	RefreshToken   string            `json:"refresh_token,omitempty"`
	Cookie         string            `json:"cookie,omitempty"`
	Cookies        map[string]string `json:"cookies,omitempty"`
	AuthHeaders    map[string]string `json:"auth_headers,omitempty"`
	Tokens         map[string]string `json:"tokens,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	StickyDeviceID string            `json:"sticky_device_id,omitempty"`
	StickyProxyID  string            `json:"sticky_proxy_id,omitempty"`
	Enabled        bool              `json:"enabled"`
	Status         string            `json:"status,omitempty"` // "active"|"expired"|"challenged"|"disabled"
	ExpiresAt      string            `json:"expires_at,omitempty"`
	UseCount       int64             `json:"use_count"`
	FailCount      int64             `json:"fail_count"`
	RefreshCount   int64             `json:"refresh_count"`
	LastUsedAt     string            `json:"last_used_at,omitempty"`
	LastRefreshed  string            `json:"last_refreshed,omitempty"`
	LastError      string            `json:"last_error,omitempty"`
	Notes          string            `json:"notes,omitempty"`
	CreatedAt      string            `json:"created_at,omitempty"`
	UpdatedAt      string            `json:"updated_at,omitempty"`
}

// AccountSelectOptions constrains account acquisition during route execution.
type AccountSelectOptions struct {
	Tags           []string
	ExplicitID     string
	DeviceID       string
	Strategy       string
	IncludeExpired bool
}

// ManagedWorkerSpec configures a pool of locally supervised HTTP signer worker
// processes bound to consecutive loopback ports (`127.0.0.1:<BasePort+i>`).
type ManagedWorkerSpec struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Kind             string            `json:"kind"` // "unidbg_http"|"qiling_http"|"script_http"|"custom"
	Command          string            `json:"command"`
	Args             []string          `json:"args,omitempty"`
	WorkDir          string            `json:"work_dir,omitempty"`
	Env              map[string]string `json:"env,omitempty"`
	BasePort         int               `json:"base_port"`
	Instances        int               `json:"instances"` // 1..8
	HealthPath       string            `json:"health_path,omitempty"`
	SignPath         string            `json:"sign_path,omitempty"`
	AutoRestart      bool              `json:"auto_restart"`
	MaxRestarts      int               `json:"max_restarts,omitempty"`
	RestartBackoffMs int               `json:"restart_backoff_ms,omitempty"`
	Enabled          bool              `json:"enabled"`
	Description      string            `json:"description,omitempty"`
	CreatedAt        string            `json:"created_at,omitempty"`
	UpdatedAt        string            `json:"updated_at,omitempty"`
}

// ManagedWorkerInstance reports live runtime and health telemetry for one worker process.
type ManagedWorkerInstance struct {
	Index      int    `json:"index"`
	Port       int    `json:"port"`
	Endpoint   string `json:"endpoint"`
	SignURL    string `json:"sign_url"`
	PID        int    `json:"pid,omitempty"`
	Running    bool   `json:"running"`
	Healthy    bool   `json:"healthy"`
	InFlight   int64  `json:"in_flight"`
	Restarts   int    `json:"restarts"`
	LatencyMs  int64  `json:"latency_ms,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	LastProbe  string `json:"last_probe,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	StderrTail string `json:"stderr_tail,omitempty"`
}

// ManagedWorkerStatus summarizes a ManagedWorkerSpec and all of its instances.
type ManagedWorkerStatus struct {
	Spec             ManagedWorkerSpec       `json:"spec"`
	Running          bool                    `json:"running"`
	HealthyInstances int                     `json:"healthy_instances"`
	TotalInstances   int                     `json:"total_instances"`
	Instances        []ManagedWorkerInstance `json:"instances"`
}

// CircuitSnapshot captures the live circuit breaker state for a route.
type CircuitSnapshot struct {
	RouteSlug           string `json:"route_slug"`
	State               string `json:"state"` // "closed"|"open"|"half_open"
	ConsecutiveFailures int    `json:"consecutive_failures"`
	Threshold           int    `json:"threshold"`
	CooldownSec         int    `json:"cooldown_sec"`
	OpenedAt            string `json:"opened_at,omitempty"`
	NextProbeAt         string `json:"next_probe_at,omitempty"`
	LastFailure         string `json:"last_failure,omitempty"`
	TripCount           int64  `json:"trip_count"`
}

// DockerDeployBundle holds generated container deployment files for headless
// `cap gateway serve` operation.
type DockerDeployBundle struct {
	ListenAddr    string `json:"listen_addr"`
	Dockerfile    string `json:"dockerfile"`
	DockerCompose string `json:"docker_compose"`
}

// ServiceRoute publishes an upstream reverse-engineered API endpoint behind
// the embedded Open API Gateway at `/gw/{slug}`.
type ServiceRoute struct {
	ID                   string            `json:"id"`
	Slug                 string            `json:"slug"`
	Name                 string            `json:"name"`
	Description          string            `json:"description,omitempty"`
	Enabled              bool              `json:"enabled"`
	UpstreamMethod       string            `json:"upstream_method"`
	UpstreamURL          string            `json:"upstream_url"` // supports {{input.x}}, {{device.oaid}}, {{account.token}}, etc.
	StaticHeaders        map[string]string `json:"static_headers,omitempty"`
	StaticQuery          map[string]string `json:"static_query,omitempty"`
	BodyTemplate         string            `json:"body_template,omitempty"`
	SignerID             string            `json:"signer_id,omitempty"`
	DeviceTags           []string          `json:"device_tags,omitempty"`
	ProxyTags            []string          `json:"proxy_tags,omitempty"`
	RequireProxy         bool              `json:"require_proxy"`
	RequireDevice        bool              `json:"require_device"`
	AccountTags          []string          `json:"account_tags,omitempty"`
	RequireAccount       bool              `json:"require_account,omitempty"`
	AutoRefresh          bool              `json:"auto_refresh,omitempty"`
	RefreshRouteSlug     string            `json:"refresh_route_slug,omitempty"`
	RefreshOnStatuses    []int             `json:"refresh_on_statuses,omitempty"`
	RefreshOnBodySubstr  string            `json:"refresh_on_body_substr,omitempty"`
	ChallengeWebhookURL  string            `json:"challenge_webhook_url,omitempty"`
	TLSProfile           string            `json:"tls_profile,omitempty"` // "go_default"|"chrome_131"|"safari_17"|"firefox_132"|"okhttp_android"|"ios_cfnetwork"
	MTLSCertPath         string            `json:"mtls_cert_path,omitempty"`
	MTLSKeyPath          string            `json:"mtls_key_path,omitempty"`
	CacheTTLSec          int               `json:"cache_ttl_sec,omitempty"`
	CacheKeyFields       []string          `json:"cache_key_fields,omitempty"`
	CacheMaxEntries      int               `json:"cache_max_entries,omitempty"`
	CircuitFailThreshold int               `json:"circuit_fail_threshold,omitempty"`
	CircuitCooldownSec   int               `json:"circuit_cooldown_sec,omitempty"`
	RateLimitRPS         float64           `json:"rate_limit_rps,omitempty"`
	TimeoutSec           int               `json:"timeout_sec,omitempty"`
	SourceFlowID         string            `json:"source_flow_id,omitempty"`
	CreatedAt            string            `json:"created_at,omitempty"`
	UpdatedAt            string            `json:"updated_at,omitempty"`
}

// GatewayConfig holds runtime settings for the embedded Open API Gateway.
type GatewayConfig struct {
	ListenAddr  string   `json:"listen_addr"` // default "127.0.0.1:9090"
	RequireAuth bool     `json:"require_auth"`
	APIKeys     []string `json:"api_keys,omitempty"`
	CORSOrigins []string `json:"cors_origins,omitempty"`
	MaxLogs     int      `json:"max_logs,omitempty"`
}

// GatewayStatus describes the live server lifecycle state emitted to listeners.
type GatewayStatus struct {
	Running    bool   `json:"running"`
	ListenAddr string `json:"listen_addr"`
	StartedAt  string `json:"started_at,omitempty"`
	Error      string `json:"error,omitempty"`
}

// InvocationRecord captures telemetry for a single gateway route execution.
type InvocationRecord struct {
	ID               string `json:"id"`
	Timestamp        string `json:"timestamp"`
	RouteID          string `json:"route_id,omitempty"`
	RouteSlug        string `json:"route_slug"`
	Method           string `json:"method"`
	UpstreamURL      string `json:"upstream_url"`
	StatusCode       int    `json:"status_code"`
	LatencyMs        int64  `json:"latency_ms"`
	ProxyID          string `json:"proxy_id,omitempty"`
	ProxyName        string `json:"proxy_name,omitempty"`
	DeviceID         string `json:"device_id,omitempty"`
	DeviceName       string `json:"device_name,omitempty"`
	AccountID        string `json:"account_id,omitempty"`
	AccountName      string `json:"account_name,omitempty"`
	SignerID         string `json:"signer_id,omitempty"`
	SignerMs         int64  `json:"signer_ms,omitempty"`
	Retries          int    `json:"retries,omitempty"`
	CacheHit         bool   `json:"cache_hit,omitempty"`
	CircuitTripped   bool   `json:"circuit_tripped,omitempty"`
	RefreshTriggered bool   `json:"refresh_triggered,omitempty"`
	TLSProfile       string `json:"tls_profile,omitempty"`
	OK               bool   `json:"ok"`
	Error            string `json:"error,omitempty"`
	ClientIP         string `json:"client_ip,omitempty"`
}

// GatewayStats summarizes gateway health, traffic, and resource pool metrics.
type GatewayStats struct {
	Running         bool    `json:"running"`
	ListenAddr      string  `json:"listen_addr"`
	StartedAt       string  `json:"started_at,omitempty"`
	TotalRequests   int64   `json:"total_requests"`
	SuccessRequests int64   `json:"success_requests"`
	ErrorRequests   int64   `json:"error_requests"`
	RateLimited     int64   `json:"rate_limited"`
	AuthFailures    int64   `json:"auth_failures"`
	AvgLatencyMs    float64 `json:"avg_latency_ms"`
	ProxyTotal      int     `json:"proxy_total"`
	ProxyHealthy    int     `json:"proxy_healthy"`
	DeviceTotal     int     `json:"device_total"`
	DeviceEnabled   int     `json:"device_enabled"`
	SignerTotal     int     `json:"signer_total"`
	RouteTotal      int     `json:"route_total"`
	RouteEnabled    int     `json:"route_enabled"`
	TotalAccounts   int     `json:"total_accounts"`
	ActiveAccounts  int     `json:"active_accounts"`
	TotalWorkers    int     `json:"total_workers"`
	HealthyWorkers  int     `json:"healthy_workers"`
	CacheHits       int64   `json:"cache_hits"`
	CacheMisses     int64   `json:"cache_misses"`
	OpenCircuits    int     `json:"open_circuits"`
}

// TestInvokeRequest specifies inputs for direct route testing via InvokeRoute.
type TestInvokeRequest struct {
	RouteSlug   string            `json:"route_slug,omitempty"`
	Method      string            `json:"method,omitempty"`
	Input       map[string]string `json:"input,omitempty"`
	Query       map[string]string `json:"query,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	DeviceID    string            `json:"device_id,omitempty"`
	ProxyID     string            `json:"proxy_id,omitempty"`
	AccountID   string            `json:"account_id,omitempty"`
	BypassCache bool              `json:"bypass_cache,omitempty"`
	Raw         bool              `json:"raw,omitempty"`
}

// TestInvokeResult is the response envelope returned by both InvokeRoute and
// HTTP calls to `/gw/{slug}` (unless `?raw=1` passthrough is requested).
type TestInvokeResult struct {
	OK               bool              `json:"ok"`
	Status           int               `json:"status"`
	LatencyMs        int64             `json:"latency_ms"`
	SignerMs         int64             `json:"signer_ms,omitempty"`
	UpstreamURL      string            `json:"upstream_url,omitempty"`
	Proxy            string            `json:"proxy,omitempty"`
	ProxyID          string            `json:"proxy_id,omitempty"`
	Device           string            `json:"device,omitempty"`
	DeviceID         string            `json:"device_id,omitempty"`
	Account          string            `json:"account,omitempty"`
	AccountID        string            `json:"account_id,omitempty"`
	CacheHit         bool              `json:"cache_hit,omitempty"`
	CircuitTripped   bool              `json:"circuit_tripped,omitempty"`
	RefreshTriggered bool              `json:"refresh_triggered,omitempty"`
	TLSProfile       string            `json:"tls_profile,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Body             string            `json:"body,omitempty"`
	Data             any               `json:"data,omitempty"`
	Error            string            `json:"error,omitempty"`
	Retries          int               `json:"retries,omitempty"`
	SignedParams     map[string]string `json:"signed_params,omitempty"`
	SignedHeaders    map[string]string `json:"signed_headers,omitempty"`
}

var (
	idSanitizeRe  = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	urlUserInfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@]+)@`)
)

// redactSecrets scrubs embedded URL userinfo (scheme://user:pass@host) and any
// explicitly provided secret values (longest-first to avoid partial-substring
// leaks) from logs, URLs, and error messages.
func redactSecrets(text string, secrets ...string) string {
	if text == "" {
		return ""
	}
	out := urlUserInfoRe.ReplaceAllString(text, "${1}REDACTED@")
	if len(secrets) == 0 {
		return out
	}
	sorted := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if s != "" {
			sorted = append(sorted, s)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})
	for _, secret := range sorted {
		out = strings.ReplaceAll(out, secret, "[REDACTED]")
		if esc := url.QueryEscape(secret); esc != "" && esc != secret {
			out = strings.ReplaceAll(out, esc, "[REDACTED]")
		}
		if pesc := url.PathEscape(secret); pesc != "" && pesc != secret {
			out = strings.ReplaceAll(out, pesc, "[REDACTED]")
		}
	}
	return out
}

func redactURLString(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil {
		return u.Redacted()
	}
	return redactSecrets(raw)
}

func validateHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", redactURLString(raw), err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q (only http and https are allowed)", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("URL %q is missing host", redactURLString(raw))
	}
	return u, nil
}

func setHeaderFold(headers map[string]string, key, val string) {
	for existing := range headers {
		if strings.EqualFold(existing, key) {
			delete(headers, existing)
			break
		}
	}
	headers[key] = val
}

func jsonStringLiteral(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func randomHex(nBytes int) string {
	if nBytes <= 0 {
		nBytes = 8
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func sanitizeID(raw, fallback string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = idSanitizeRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		return fallback
	}
	return s
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	cp := make(map[string]string, len(m))
	maps.Copy(cp, m)
	return cp
}

func cloneStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		clean := strings.TrimSpace(t)
		if clean == "" {
			continue
		}
		key := strings.ToLower(clean)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hasAllTags(itemTags, reqTags []string) bool {
	if len(reqTags) == 0 {
		return true
	}
	if len(itemTags) == 0 {
		return false
	}
	have := make(map[string]struct{}, len(itemTags))
	for _, t := range itemTags {
		have[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}
	for _, req := range reqTags {
		r := strings.ToLower(strings.TrimSpace(req))
		if r == "" {
			continue
		}
		if _, ok := have[r]; !ok {
			return false
		}
	}
	return true
}

func cloneIntSlice(s []int) []int {
	if s == nil {
		return nil
	}
	cp := make([]int, len(s))
	copy(cp, s)
	return cp
}

func cloneProxyNode(n ProxyNode) ProxyNode {
	n.Tags = cloneStringSlice(n.Tags)
	return n
}

func cloneDeviceProfile(d DeviceProfile) DeviceProfile {
	d.Tags = cloneStringSlice(d.Tags)
	d.Fingerprint.ExtraHeaders = cloneStringMap(d.Fingerprint.ExtraHeaders)
	d.Cookies = cloneStringMap(d.Cookies)
	d.AuthHeaders = cloneStringMap(d.AuthHeaders)
	d.Tokens = cloneStringMap(d.Tokens)
	return d
}

func cloneAccountProfile(a AccountProfile) AccountProfile {
	a.Tags = cloneStringSlice(a.Tags)
	a.Cookies = cloneStringMap(a.Cookies)
	a.AuthHeaders = cloneStringMap(a.AuthHeaders)
	a.Tokens = cloneStringMap(a.Tokens)
	return a
}

func cloneAccountPoolConfig(c AccountPoolConfig) AccountPoolConfig {
	c.Refresh.RefreshOnStatuses = cloneIntSlice(c.Refresh.RefreshOnStatuses)
	return c
}

func cloneManagedWorkerSpec(w ManagedWorkerSpec) ManagedWorkerSpec {
	w.Args = cloneStringSlice(w.Args)
	w.Env = cloneStringMap(w.Env)
	return w
}

func cloneSignerProvider(s SignerProvider) SignerProvider {
	s.Headers = cloneStringMap(s.Headers)
	s.OutputMapping = cloneStringMap(s.OutputMapping)
	return s
}

func cloneServiceRoute(r ServiceRoute) ServiceRoute {
	r.StaticHeaders = cloneStringMap(r.StaticHeaders)
	r.StaticQuery = cloneStringMap(r.StaticQuery)
	r.DeviceTags = cloneStringSlice(r.DeviceTags)
	r.ProxyTags = cloneStringSlice(r.ProxyTags)
	r.AccountTags = cloneStringSlice(r.AccountTags)
	r.RefreshOnStatuses = cloneIntSlice(r.RefreshOnStatuses)
	r.CacheKeyFields = cloneStringSlice(r.CacheKeyFields)
	return r
}

func cloneGatewayConfig(c GatewayConfig) GatewayConfig {
	c.APIKeys = cloneStringSlice(c.APIKeys)
	c.CORSOrigins = cloneStringSlice(c.CORSOrigins)
	return c
}
