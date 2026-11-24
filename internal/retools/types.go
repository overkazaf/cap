// Package retools implements cap's Native Reverse Engineering & Algorithm
// Emulation subsystem covering radare2 (with pure-Go ELF/Mach-O fallback),
// Unidbg (Android JNI emulation + optional HTTP signer server), Qiling
// (multi-arch binary/shared-library emulation), and angr (symbolic execution).
//
// It provides host toolchain probing, binary/function static analysis,
// curated starter templates, DeepTrace-to-harness code synthesis, persistent
// project management (~/.cap/re-projects/*.json), and async cancellable job
// execution with live log streaming and structured [CAP_RE] result extraction.
package retools

import "time"

const (
	// Analysis and emulation engine identifiers.
	EngineRadare2   = "radare2"
	EnginePureGoELF = "pure-go-elf"
	EnginePureGoMO  = "pure-go-macho"
	EngineUnidbg    = "unidbg"
	EngineQiling    = "qiling"
	EngineAngr      = "angr"

	// Job lifecycle statuses.
	StatusIdle      = "idle"
	StatusRunning   = "running"
	StatusDone      = "done"
	StatusError     = "error"
	StatusCancelled = "cancelled"

	// RELRO mitigation levels.
	RELROFull    = "full"
	RELROPartial = "partial"
	RELRONone    = "none"
	RELROUnknown = "unknown"

	// MaxJobEvents bounds the in-memory ring buffer of log lines per job.
	MaxJobEvents = 1000

	// StructuredOutputPrefix marks a stdout line carrying a JSON object
	// emitted by generated Unidbg/Qiling/angr harnesses for structured capture.
	StructuredOutputPrefix = "[CAP_RE]"
)

// ToolchainConfig allows overriding auto-discovered host binaries and paths.
// When a field is non-empty, toolchain detection probes only that configured
// location rather than falling back to system PATH.
type ToolchainConfig struct {
	R2Path       string `json:"r2_path,omitempty"`
	JavaPath     string `json:"java_path,omitempty"`
	MvnPath      string `json:"mvn_path,omitempty"`
	UnidbgDir    string `json:"unidbg_dir,omitempty"`
	PythonPath   string `json:"python_path,omitempty"`
	QilingRootFS string `json:"qiling_rootfs,omitempty"`
}

// ToolStatus reports discovery status, version, path, and install guidance for
// one host reverse-engineering tool or runtime dependency.
type ToolStatus struct {
	Name    string `json:"name"`
	Ready   bool   `json:"ready"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Issue   string `json:"issue,omitempty"`
	Install string `json:"install,omitempty"`
}

// ToolchainInfo summarizes host readiness across radare2, Java/Maven/Unidbg,
// and Python/Qiling/angr.
type ToolchainInfo struct {
	R2     ToolStatus `json:"r2"`
	Java   ToolStatus `json:"java"`
	Mvn    ToolStatus `json:"mvn"`
	Unidbg ToolStatus `json:"unidbg"`
	Python ToolStatus `json:"python"`
	Qiling ToolStatus `json:"qiling"`
	Angr   ToolStatus `json:"angr"`

	// Top-level engine readiness summaries.
	R2Ready      bool     `json:"r2_ready"`
	UnidbgReady  bool     `json:"unidbg_ready"`
	QilingReady  bool     `json:"qiling_ready"`
	AngrReady    bool     `json:"angr_ready"`
	JavacPath    string   `json:"javac_path,omitempty"`
	UnidbgJars   []string `json:"unidbg_jars,omitempty"`
	QilingRootFS string   `json:"qiling_rootfs,omitempty"`
	Issues       []string `json:"issues,omitempty"`
	CheckedAt    string   `json:"checked_at,omitempty"`
}

// SecurityMitigations records binary hardening properties.
type SecurityMitigations struct {
	PIE      bool   `json:"pie"`
	NX       bool   `json:"nx"`
	Canary   bool   `json:"canary"`
	RELRO    string `json:"relro"` // "full" | "partial" | "none" | "unknown"
	Stripped bool   `json:"stripped"`
}

// BinaryFunction represents one discovered function in a native binary.
type BinaryFunction struct {
	Name      string `json:"name"`
	Addr      string `json:"addr"`
	Offset    uint64 `json:"offset"`
	Size      uint64 `json:"size"`
	Signature string `json:"signature,omitempty"`
	CallCount int    `json:"call_count,omitempty"`
	IsJNI     bool   `json:"is_jni,omitempty"`
}

// BinarySymbol represents an exported or imported symbol in a native binary.
type BinarySymbol struct {
	Name    string `json:"name"`
	Addr    string `json:"addr,omitempty"`
	Offset  uint64 `json:"offset,omitempty"`
	Size    uint64 `json:"size,omitempty"`
	Type    string `json:"type,omitempty"`
	Bind    string `json:"bind,omitempty"`
	Library string `json:"library,omitempty"`
	IsJNI   bool   `json:"is_jni,omitempty"`
}

// BinaryString represents one extracted printable string literal.
type BinaryString struct {
	Value   string `json:"value"`
	Addr    string `json:"addr,omitempty"`
	Offset  uint64 `json:"offset,omitempty"`
	Section string `json:"section,omitempty"`
	Length  int    `json:"length,omitempty"`
	Type    string `json:"type,omitempty"`
}

// BinaryXRef represents a code or data cross-reference between two addresses.
type BinaryXRef struct {
	From     string `json:"from"`
	FromName string `json:"from_name,omitempty"`
	To       string `json:"to"`
	ToName   string `json:"to_name,omitempty"`
	Type     string `json:"type,omitempty"`
	Opcode   string `json:"opcode,omitempty"`
}

// BinaryAnalysis holds static analysis results produced by radare2 or the
// pure-Go ELF/Mach-O fallback engine.
type BinaryAnalysis struct {
	FilePath    string              `json:"file_path"`
	FileName    string              `json:"file_name"`
	FileSize    int64               `json:"file_size"`
	Format      string              `json:"format"`
	Arch        string              `json:"arch"`
	Bits        int                 `json:"bits"`
	Endian      string              `json:"endian"` // "little" | "big"
	OS          string              `json:"os,omitempty"`
	BinaryType  string              `json:"binary_type,omitempty"`
	EntryPoint  string              `json:"entry_point,omitempty"`
	Mitigations SecurityMitigations `json:"mitigations"`
	Functions   []BinaryFunction    `json:"functions"`
	Exports     []BinarySymbol      `json:"exports"`
	Imports     []BinarySymbol      `json:"imports"`
	Strings     []BinaryString      `json:"strings"`
	XRefs       []BinaryXRef        `json:"xrefs"`
	Engine      string              `json:"engine"` // "radare2" | "pure-go-elf" | "pure-go-macho"
	Warnings    []string            `json:"warnings,omitempty"`
	AnalyzedAt  string              `json:"analyzed_at"`
	ElapsedMs   int64               `json:"elapsed_ms"`
}

// DisasmLine is one disassembled instruction within a function.
type DisasmLine struct {
	Addr    string `json:"addr"`
	Bytes   string `json:"bytes,omitempty"`
	Disasm  string `json:"disasm"`
	Type    string `json:"type,omitempty"`
	Comment string `json:"comment,omitempty"`
	Jump    string `json:"jump,omitempty"`
}

// FunctionDetail holds detailed per-function disassembly, pseudo-C, and xrefs.
type FunctionDetail struct {
	Name          string       `json:"name"`
	Addr          string       `json:"addr"`
	Size          uint64       `json:"size"`
	Disasm        string       `json:"disasm"`
	DisasmLines   []DisasmLine `json:"disasm_lines,omitempty"`
	PseudoC       string       `json:"pseudo_c"`
	PseudoCEngine string       `json:"pseudo_c_engine,omitempty"` // "pdg" | "pdc" | ""
	XRefsTo       []BinaryXRef `json:"xrefs_to"`
	XRefsFrom     []BinaryXRef `json:"xrefs_from"`
	Engine        string       `json:"engine"`
	Warnings      []string     `json:"warnings,omitempty"`
}

// R2CommandResult holds output from a sanitized read-only radare2 command.
type R2CommandResult struct {
	BinaryPath string `json:"binary_path"`
	Command    string `json:"command"`
	Output     string `json:"output"`
	ElapsedMs  int64  `json:"elapsed_ms"`
}

// REProject is a persistent reverse-engineering or algorithm-emulation project
// stored in ~/.cap/re-projects/*.json (or shipped as a built-in template).
type REProject struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Engine       string   `json:"engine"` // "unidbg" | "qiling" | "angr" | "radare2"
	Description  string   `json:"description"`
	BinaryPath   string   `json:"binary_path,omitempty"`
	APKPath      string   `json:"apk_path,omitempty"`
	TargetClass  string   `json:"target_class,omitempty"`
	TargetMethod string   `json:"target_method,omitempty"`
	TargetSymbol string   `json:"target_symbol,omitempty"`
	TargetAddr   string   `json:"target_addr,omitempty"`
	FindAddr     string   `json:"find_addr,omitempty"`
	AvoidAddr    string   `json:"avoid_addr,omitempty"`
	Args         []string `json:"args,omitempty"`
	RootFS       string   `json:"rootfs,omitempty"`
	Code         string   `json:"code"`
	Builtin      bool     `json:"builtin"`
	Tags         []string `json:"tags,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	UpdatedAt    string   `json:"updated_at,omitempty"`
}

// JobLogEvent is one streamed log line or structured result emitted by an
// executing RE job.
type JobLogEvent struct {
	Seq         int64          `json:"seq"`
	JobID       string         `json:"job_id"`
	TimestampMs int64          `json:"timestamp_ms"`
	Stream      string         `json:"stream"` // "stdout" | "stderr" | "system" | "result"
	Level       string         `json:"level"`  // "info" | "warn" | "error" | "system" | "result"
	Message     string         `json:"message"`
	Data        map[string]any `json:"data,omitempty"`
	Raw         string         `json:"raw,omitempty"`
}

// JobResult stores a structured concrete result (e.g. emulated signature,
// symbolic solution, or HTTP server URL) parsed from [CAP_RE] output lines.
type JobResult struct {
	Kind    string         `json:"kind"`
	Summary string         `json:"summary"`
	Payload map[string]any `json:"payload"`
}

// JobState captures the live or most recent RE execution job snapshot.
type JobState struct {
	ID           string        `json:"id"`
	ProjectID    string        `json:"project_id,omitempty"`
	ProjectName  string        `json:"project_name,omitempty"`
	Engine       string        `json:"engine"`
	Status       string        `json:"status"` // "idle" | "running" | "done" | "error" | "cancelled"
	Running      bool          `json:"running"`
	PID          int           `json:"pid,omitempty"`
	Command      string        `json:"command,omitempty"`
	ExitCode     int           `json:"exit_code"`
	StartedAtMs  int64         `json:"started_at_ms,omitempty"`
	FinishedAtMs int64         `json:"finished_at_ms,omitempty"`
	ElapsedMs    int64         `json:"elapsed_ms,omitempty"`
	Error        string        `json:"error,omitempty"`
	EventCount   int           `json:"event_count"`
	Events       []JobLogEvent `json:"events"`
	Results      []JobResult   `json:"results"`
}

// RunJobRequest configures launching an asynchronous RE execution job.
type RunJobRequest struct {
	ProjectID   string            `json:"project_id,omitempty"`
	ProjectName string            `json:"project_name,omitempty"`
	Engine      string            `json:"engine"` // "unidbg" | "qiling" | "angr" | "radare2"
	Code        string            `json:"code,omitempty"`
	BinaryPath  string            `json:"binary_path,omitempty"`
	APKPath     string            `json:"apk_path,omitempty"`
	RootFS      string            `json:"rootfs,omitempty"`
	TargetAddr  string            `json:"target_addr,omitempty"`
	FindAddr    string            `json:"find_addr,omitempty"`
	AvoidAddr   string            `json:"avoid_addr,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	TimeoutSec  int               `json:"timeout_sec,omitempty"`
	R2Command   string            `json:"r2_command,omitempty"`
	WorkDir     string            `json:"work_dir,omitempty"`
}

// GenerateOptions controls parameterized harness generation and
// DeepTrace -> Unidbg / Qiling / angr / radare2 synthesis.
type GenerateOptions struct {
	PackageName     string   `json:"package_name,omitempty"`
	APKPath         string   `json:"apk_path,omitempty"`
	BinaryPath      string   `json:"binary_path,omitempty"`
	SOFile          string   `json:"so_file,omitempty"`
	TargetClass     string   `json:"target_class,omitempty"`
	TargetMethod    string   `json:"target_method,omitempty"`
	TargetSymbol    string   `json:"target_symbol,omitempty"`
	TargetAddr      string   `json:"target_addr,omitempty"`
	FindAddr        string   `json:"find_addr,omitempty"`
	AvoidAddr       string   `json:"avoid_addr,omitempty"`
	MethodSignature string   `json:"method_signature,omitempty"`
	Args            []string `json:"args,omitempty"`
	RootFS          string   `json:"rootfs,omitempty"`
	Arch            string   `json:"arch,omitempty"`             // "arm64" | "arm" | "x86_64" | "x86"
	HTTPServerMode  bool     `json:"http_server_mode,omitempty"` // Unidbg embedded HTTP signer mode
	HTTPPort        int      `json:"http_port,omitempty"`        // default 8899
	InputLen        int      `json:"input_len,omitempty"`        // angr symbolic byte length (default 32)
	ClassName       string   `json:"class_name,omitempty"`       // Java class name for Unidbg
}

// GeneratedHarness carries a synthesized emulation or analysis harness along
// with metadata and a ready-to-save REProject.
type GeneratedHarness struct {
	Name         string    `json:"name"`
	Engine       string    `json:"engine"`
	Language     string    `json:"language"` // "java" | "python" | "r2"
	FileName     string    `json:"file_name"`
	Description  string    `json:"description"`
	Summary      string    `json:"summary"`
	Code         string    `json:"code"`
	Project      REProject `json:"project"`
	BinaryPath   string    `json:"binary_path,omitempty"`
	APKPath      string    `json:"apk_path,omitempty"`
	TargetClass  string    `json:"target_class,omitempty"`
	TargetMethod string    `json:"target_method,omitempty"`
	TargetSymbol string    `json:"target_symbol,omitempty"`
	TargetAddr   string    `json:"target_addr,omitempty"`
	SignParams   []string  `json:"sign_params,omitempty"`
	Notes        []string  `json:"notes,omitempty"`
	GeneratedAt  string    `json:"generated_at"`
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
