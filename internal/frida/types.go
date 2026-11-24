// Package frida implements cap's Frida dynamic instrumentation subsystem:
// host toolchain discovery, Android frida-server lifecycle and deployment,
// embedded Python Frida bridge with automatic frida-cli fallback, live
// hook session management with hot-reload and structured send() events,
// persistent script library, and DeepTrace-to-Frida hook code generation.
package frida

import "time"

const (
	DefaultPort       = 27042
	DefaultRemoteDir  = "/data/local/tmp"
	DefaultRemoteName = "frida-server"

	DriverAuto         = "auto"
	DriverPythonBridge = "python-bridge"
	DriverFridaCLI     = "frida-cli"
	DriverNone         = "none"

	ModeSpawn  = "spawn"
	ModeAttach = "attach"

	StatusIdle     = "idle"
	StatusStarting = "starting"
	StatusRunning  = "running"
	StatusStopped  = "stopped"
	StatusError    = "error"

	VersionMatchExact   = "match"
	VersionMatchMinor   = "minor_diff"
	VersionMatchMajor   = "major_mismatch"
	VersionMatchUnknown = "unknown"

	MaxSessionEvents = 1000
)

// ToolchainConfig allows overriding auto-discovered host binaries.
type ToolchainConfig struct {
	PythonPath string `json:"python_path,omitempty"`
	FridaPath  string `json:"frida_path,omitempty"`
}

// ToolchainInfo summarizes host-side Frida runtime readiness.
type ToolchainInfo struct {
	Driver          string   `json:"driver"` // "python-bridge" | "frida-cli" | "none"
	Ready           bool     `json:"ready"`
	PythonPath      string   `json:"python_path,omitempty"`
	PythonVersion   string   `json:"python_version,omitempty"`
	FridaModuleOK   bool     `json:"frida_module_ok"`
	FridaVersion    string   `json:"frida_version,omitempty"`
	FridaCLIPath    string   `json:"frida_cli_path,omitempty"`
	FridaCLIOK      bool     `json:"frida_cli_ok"`
	FridaCLIVersion string   `json:"frida_cli_version,omitempty"`
	FridaPSPath     string   `json:"frida_ps_path,omitempty"`
	ADBPath         string   `json:"adb_path,omitempty"`
	ADBReady        bool     `json:"adb_ready"`
	Issues          []string `json:"issues,omitempty"`
	CheckedAt       string   `json:"checked_at,omitempty"`
}

// ServerStatus represents the state of frida-server on an Android device.
type ServerStatus struct {
	Serial         string   `json:"serial"`
	Connected      bool     `json:"connected"`
	Rooted         bool     `json:"rooted"`
	DeviceABI      string   `json:"device_abi,omitempty"`
	FridaArch      string   `json:"frida_arch,omitempty"`
	Running        bool     `json:"running"`
	PID            string   `json:"pid,omitempty"`
	ProcessName    string   `json:"process_name,omitempty"`
	BinaryPath     string   `json:"binary_path,omitempty"`
	BinaryName     string   `json:"binary_name,omitempty"`
	AllBinaries    []string `json:"all_binaries,omitempty"`
	ServerVersion  string   `json:"server_version,omitempty"`
	HostVersion    string   `json:"host_version,omitempty"`
	VersionMatch   string   `json:"version_match"` // "match" | "minor_diff" | "major_mismatch" | "unknown"
	Port           int      `json:"port"`
	ListenAddr     string   `json:"listen_addr,omitempty"`
	Forwarded      bool     `json:"forwarded"`
	RemoteEndpoint string   `json:"remote_endpoint,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// DeployProgressEvent reports download/extract/push stages during server deploy.
type DeployProgressEvent struct {
	Serial  string `json:"serial"`
	Stage   string `json:"stage"` // "resolve" | "download" | "extract" | "push" | "start" | "done" | "error"
	Detail  string `json:"detail"`
	Percent int    `json:"percent"`
}

// DeployOptions configures deploying frida-server to an Android device.
type DeployOptions struct {
	Serial          string `json:"serial"`
	Version         string `json:"version,omitempty"`           // empty = host version or latest GitHub release
	Arch            string `json:"arch,omitempty"`              // empty = auto-detect from device ABI
	LocalBinaryPath string `json:"local_binary_path,omitempty"` // optional local frida-server (raw or .xz)
	RemoteName      string `json:"remote_name,omitempty"`       // default "frida-server"; supports stealth rename
	RemoteDir       string `json:"remote_dir,omitempty"`        // default "/data/local/tmp"
	Port            int    `json:"port,omitempty"`              // default 27042
	AutoStart       bool   `json:"auto_start"`
	ForwardPort     bool   `json:"forward_port"`
	CacheDir        string `json:"-"`
	OnProgress      func(DeployProgressEvent) `json:"-"`
}

// DeployResult summarizes a completed frida-server deployment.
type DeployResult struct {
	Serial        string        `json:"serial"`
	Version       string        `json:"version"`
	Arch          string        `json:"arch"`
	RemotePath    string        `json:"remote_path"`
	FromCache     bool          `json:"from_cache"`
	LocalFilePath string        `json:"local_file_path,omitempty"`
	Started       bool          `json:"started"`
	Status        *ServerStatus `json:"status,omitempty"`
	Message       string        `json:"message"`
}

// StartServerOptions configures launching frida-server on the device.
type StartServerOptions struct {
	Serial      string `json:"serial"`
	BinaryPath  string `json:"binary_path,omitempty"` // empty = auto-detect in /data/local/tmp
	Port        int    `json:"port,omitempty"`        // default 27042
	ListenHost  string `json:"listen_host,omitempty"` // default "0.0.0.0" (or "127.0.0.1")
	ForwardPort bool   `json:"forward_port"`
	HostVersion string `json:"host_version,omitempty"`
}

// ProcessEntry represents an installed application or running process on device.
type ProcessEntry struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Identifier string `json:"identifier,omitempty"`
	Running    bool   `json:"running"`
	Source     string `json:"source"` // "frida" | "adb"
}

// Script represents a built-in or user-saved Frida JavaScript hook script.
type Script struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Category      string   `json:"category"` // "unpin" | "anti-detect" | "network" | "crypto" | "trace" | "native" | "codeshare" | "custom"
	Code          string   `json:"code"`
	Builtin       bool     `json:"builtin"`
	SourceSlug    string   `json:"source_slug,omitempty"`
	TargetPackage string   `json:"target_package,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	CreatedAt     string   `json:"created_at,omitempty"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
}

// SessionConfig configures starting a live Frida instrumentation session.
type SessionConfig struct {
	Serial     string `json:"serial"`
	Target     string `json:"target"`                // package name, process name, or PID
	Mode       string `json:"mode"`                  // "spawn" | "attach"
	ScriptCode string `json:"script_code"`           // JS source to inject
	ScriptID   string `json:"script_id,omitempty"`   // optional script ID
	ScriptName string `json:"script_name,omitempty"` // display label
	RemoteHost string `json:"remote_host,omitempty"` // optional host:port (e.g. 127.0.0.1:27042)
	Port       int    `json:"port,omitempty"`        // if >0 and != DefaultPort, connects via 127.0.0.1:<port>
	NoPause    bool   `json:"no_pause"`              // resume immediately after spawn (default true if unset via helper)
	Driver     string `json:"driver,omitempty"`      // "auto" | "python-bridge" | "frida-cli"
	PythonPath string `json:"python_path,omitempty"`
	FridaPath  string `json:"frida_path,omitempty"`
}

// LogEvent is a single structured or console output record emitted by a Frida session.
type LogEvent struct {
	Seq         int64          `json:"seq"`
	SessionID   string         `json:"session_id"`
	TimestampMs int64          `json:"timestamp_ms"`
	Level       string         `json:"level"`    // "hook" | "send" | "console" | "info" | "warn" | "error" | "system"
	Category    string         `json:"category"` // "ssl" | "crypto" | "http" | "jni" | "java" | "native" | "trace" | "lifecycle" | "script"
	Message     string         `json:"message"`
	Payload     map[string]any `json:"payload,omitempty"`
	DataHex     string         `json:"data_hex,omitempty"`
	Raw         string         `json:"raw,omitempty"`
}

// SessionState captures the live or most recent Frida session snapshot.
type SessionState struct {
	ID           string     `json:"id"`
	Serial       string     `json:"serial"`
	Target       string     `json:"target"`
	Mode         string     `json:"mode"`
	ScriptID     string     `json:"script_id,omitempty"`
	ScriptName   string     `json:"script_name,omitempty"`
	Driver       string     `json:"driver"`
	Status       string     `json:"status"` // "idle" | "starting" | "running" | "stopped" | "error"
	Running      bool       `json:"running"`
	Paused       bool       `json:"paused"`
	PID          int        `json:"pid,omitempty"`
	RemoteHost   string     `json:"remote_host,omitempty"`
	CanHotReload bool       `json:"can_hot_reload"`
	ReloadCount  int        `json:"reload_count"`
	EventCount   int        `json:"event_count"`
	HookCount    int        `json:"hook_count"`
	ErrorCount   int        `json:"error_count"`
	StartedAtMs  int64      `json:"started_at_ms,omitempty"`
	StoppedAtMs  int64      `json:"stopped_at_ms,omitempty"`
	ElapsedMs    int64      `json:"elapsed_ms,omitempty"`
	Error        string     `json:"error,omitempty"`
	Events       []LogEvent `json:"events"`
}

// HookGenOptions controls DeepTrace -> Frida hook script synthesis.
type HookGenOptions struct {
	TargetPackage     string   `json:"target_package,omitempty"`
	IncludeJava       bool     `json:"include_java"`
	IncludeDexXRefs   bool     `json:"include_dex_xrefs"`
	IncludeNative     bool     `json:"include_native"`
	IncludeCrypto     bool     `json:"include_crypto"`
	IncludeSSLUnpin   bool     `json:"include_ssl_unpin"`
	IncludeBacktrace  bool     `json:"include_backtrace"`
	SelectedClasses   []string `json:"selected_classes,omitempty"`
	SelectedNativeSOs []string `json:"selected_native_sos,omitempty"`
	MaxHooks          int      `json:"max_hooks,omitempty"`
}

// HookTarget describes one Java or Native target included in a generated hook script.
type HookTarget struct {
	Kind       string `json:"kind"` // "java" | "native"
	ClassName  string `json:"class_name,omitempty"`
	MethodName string `json:"method_name,omitempty"`
	SOFile     string `json:"so_file,omitempty"`
	Symbol     string `json:"symbol,omitempty"`
	Source     string `json:"source,omitempty"` // "java_trace" | "dex_xref" | "origin_chain" | "native_trace" | "manual"
	Reason     string `json:"reason,omitempty"`
}

// GeneratedHook carries the generated Frida JS script and target inventory.
type GeneratedHook struct {
	ScriptName    string       `json:"script_name"`
	TargetPackage string       `json:"target_package"`
	FlowID        string       `json:"flow_id,omitempty"`
	FlowSummary   string       `json:"flow_summary,omitempty"`
	Code          string       `json:"code"`
	Summary       string       `json:"summary"`
	JavaTargets   []HookTarget `json:"java_targets"`
	NativeTargets []HookTarget `json:"native_targets"`
	SignParams    []string     `json:"sign_params,omitempty"`
	GeneratedAt   string       `json:"generated_at"`
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
