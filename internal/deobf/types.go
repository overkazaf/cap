// Package deobf implements cap's Anti-Obfuscation, Anti-Debug / Anti-Frida
// Stealth, DEX Unpacking, and VMP (Virtual Machine Protection) Analysis &
// Devirtualization engine.
//
// All binary detection and trace analysis runs in pure Go (stdlib only, no
// external processes or network calls), while dynamic bypasses, unpackers,
// OLLVM de-flattening, string decryption, and VMP tracers synthesize ready-to-
// run Frida, angr, Qiling, and Unidbg scripts tailored to static audit findings.
package deobf

import (
	"encoding/json"
	"math"
	"time"
)

const (
	TargetKindAPK = "apk"
	TargetKindELF = "elf"

	HardeningNone    = "none"
	HardeningLow     = "low"
	HardeningMedium  = "medium"
	HardeningHigh    = "high"
	HardeningExtreme = "extreme"

	ObfOLLVMCFF         = "ollvm_cff"
	ObfOLLVMBCF         = "ollvm_bcf"
	ObfOLLVMSUB         = "ollvm_sub"
	ObfIndirectBranch   = "indirect_branch"
	ObfStringEncryption = "string_encryption"
	ObfSymbolStripped   = "symbol_stripped"
	ObfSectionTampered  = "section_tampered"
	ObfDexProguard      = "dex_proguard"
	ObfDex2C            = "dex2c"

	VMPNative = "native_vmp"
	VMPDex    = "dex_vmp"
	VMPDex2C  = "dex2c"

	AntiDebugPtrace         = "ptrace"
	AntiDebugTracerPid      = "tracer_pid"
	AntiDebugProcMaps       = "proc_maps"
	AntiDebugFridaDetect    = "frida_detect"
	AntiDebugInlineSVC      = "inline_svc"
	AntiDebugWatchdogThread = "watchdog_thread"
	AntiDebugTimingCheck    = "timing_check"
	AntiDebugInotify        = "inotify"
	AntiDebugJavaDebug      = "java_debug"
	AntiDebugRootDetect     = "root_detect"

	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"

	EngineFrida  = "frida"
	EngineAngr   = "angr"
	EngineQiling = "qiling"
	EngineUnidbg = "unidbg"
)

// ProtectionReport aggregates the full multi-layer security, packing,
// obfuscation, VMP, and anti-debug audit of an APK archive or ELF .so binary.
type ProtectionReport struct {
	TargetPath        string               `json:"target_path"`
	TargetKind        string               `json:"target_kind"`     // "apk" | "elf"
	RiskScore         int                  `json:"risk_score"`      // 0..100
	HardeningLevel    string               `json:"hardening_level"` // "none" | "low" | "medium" | "high" | "extreme"
	Packers           []PackerFinding      `json:"packers"`
	Obfuscation       []ObfuscationFinding `json:"obfuscation"`
	VMPIndicators     []VMPFinding         `json:"vmp_indicators"`
	AntiDebugFindings []AntiDebugFinding   `json:"anti_debug_findings"`
	SOAudits          []SOBinaryAudit      `json:"so_audits"`
	Recommendations   []string             `json:"recommendations"`
	Summary           string               `json:"summary"`
	AnalyzedAt        string               `json:"analyzed_at"`
}

// PackerFinding records a detected commercial Android packer / protector shell.
type PackerFinding struct {
	Name           string   `json:"name"`
	Vendor         string   `json:"vendor"`
	Confidence     float64  `json:"confidence"` // 0.0..1.0
	Evidence       []string `json:"evidence"`
	UnpackStrategy string   `json:"unpack_strategy"`
}

// ObfuscationFinding records a native or Dalvik obfuscation technique finding.
type ObfuscationFinding struct {
	Kind        string   `json:"kind"` // "ollvm_cff"|"ollvm_bcf"|"ollvm_sub"|"indirect_branch"|"string_encryption"|"symbol_stripped"|"section_tampered"|"dex_proguard"|"dex2c"
	Module      string   `json:"module"`
	Confidence  float64  `json:"confidence"` // 0.0..1.0
	Entropy     float64  `json:"entropy,omitempty"`
	Evidence    []string `json:"evidence"`
	Remediation string   `json:"remediation"`
}

// VMPFinding captures evidence of Virtual Machine Protection or Dex2C lifting.
type VMPFinding struct {
	Kind                 string   `json:"kind"` // "native_vmp"|"dex_vmp"|"dex2c"
	Module               string   `json:"module"`
	Section              string   `json:"section,omitempty"`
	Confidence           float64  `json:"confidence"` // 0.0..1.0
	HandlerTableEstimate int      `json:"handler_table_estimate,omitempty"`
	Entropy              float64  `json:"entropy,omitempty"`
	Evidence             []string `json:"evidence"`
	Strategy             string   `json:"strategy"`
}

// AntiDebugFinding records a detected anti-debugging, anti-Frida, or
// anti-tampering check with its location and recommended countermeasure.
type AntiDebugFinding struct {
	Kind            string `json:"kind"` // "ptrace"|"tracer_pid"|"proc_maps"|"frida_detect"|"inline_svc"|"watchdog_thread"|"timing_check"|"inotify"|"java_debug"|"root_detect"
	Module          string `json:"module"`
	SymbolOrPattern string `json:"symbol_or_pattern"`
	OffsetHex       string `json:"offset_hex,omitempty"`
	Severity        string `json:"severity"` // "low"|"medium"|"high"|"critical"
	Countermeasure  string `json:"countermeasure"`
}

// SOBinaryAudit summarizes structural, entropy, instruction-level, and
// mitigation metrics for a single ELF shared object.
type SOBinaryAudit struct {
	Name                string          `json:"name"`
	Arch                string          `json:"arch"`
	FileSize            int64           `json:"file_size,omitempty"`
	Entropy             float64         `json:"entropy"`
	TextEntropy         float64         `json:"text_entropy"`
	RodataEntropy       float64         `json:"rodata_entropy"`
	Stripped            bool            `json:"stripped"`
	InitArrayCount      int             `json:"init_array_count"`
	InlineSVCCount      int             `json:"inline_svc_count"`
	IndirectBranchCount int             `json:"indirect_branch_count"`
	SuspiciousSections  []string        `json:"suspicious_sections"`
	SecurityFlags       map[string]bool `json:"security_flags"`
}

// StealthOptions configures composable Anti-Debug / Anti-Frida Frida modules.
type StealthOptions struct {
	TargetPackage            string   `json:"target_package,omitempty"`
	TargetSO                 string   `json:"target_so,omitempty"`
	BypassTracerPidAndProcFS bool     `json:"bypass_tracer_pid_and_proc_fs"`
	BypassPtraceAndSignals   bool     `json:"bypass_ptrace_and_signals"`
	PatchInlineSVC           bool     `json:"patch_inline_svc"`
	BypassTimingAndInotify   bool     `json:"bypass_timing_and_inotify"`
	BypassJavaDebugChecks    bool     `json:"bypass_java_debug_checks"`
	WatchdogBlockOffsets     []string `json:"watchdog_block_offsets,omitempty"`
	CustomHideTokens         []string `json:"custom_hide_tokens,omitempty"`
	DryRunSVCPatch           bool     `json:"dry_run_svc_patch,omitempty"`
}

// GeneratedScript carries a synthesized Frida, angr, Qiling, or Unidbg script
// along with metadata, enabled modules, and usage guidance.
type GeneratedScript struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"` // "stealth"|"unpack"|"ollvm"|"string_decrypt"|"java_deobf"|"vmp_stalker"|"vmp_jni"|"vmp_unidbg"
	Engine      string   `json:"engine"`   // "frida"|"angr"|"qiling"|"unidbg"
	Language    string   `json:"language"` // "javascript"|"python"|"java"
	Target      string   `json:"target,omitempty"`
	Description string   `json:"description"`
	Code        string   `json:"code"`
	Modules     []string `json:"modules,omitempty"`
	Usage       string   `json:"usage,omitempty"`
	Notes       []string `json:"notes,omitempty"`
	GeneratedAt string   `json:"generated_at"`
}

// VMPHotspot describes a high-frequency PC identified as a VMP fetch-decode
// dispatcher candidate or virtual opcode handler entry point.
type VMPHotspot struct {
	Address       string   `json:"address"`
	OffsetHex     string   `json:"offset_hex,omitempty"`
	Hits          int      `json:"hits"`
	UniqueTargets int      `json:"unique_targets,omitempty"`
	SharePercent  float64  `json:"share_percent"`
	SampleInsn    string   `json:"sample_insn,omitempty"`
	Role          string   `json:"role"` // "dispatcher" | "handler" | "helper"
	NextTargets   []string `json:"next_targets,omitempty"`
}

// VMPMemSpot captures a repeatedly accessed memory address in a VMP trace
// (e.g., virtual PC slot, VM stack frame, or bytecode/handler lookup table).
type VMPMemSpot struct {
	Address  string `json:"address"`
	Reads    int    `json:"reads"`
	Writes   int    `json:"writes"`
	TotalOps int    `json:"total_ops"`
	Role     string `json:"role"` // "bytecode_cursor" | "vm_stack" | "vm_context" | "lookup_table" | "data"
}

// VMPExternalCall records an external libc, crypto, JNI, or syscall invocation
// observed leaving the VMP-protected module during execution tracing.
type VMPExternalCall struct {
	Target   string `json:"target"`
	CallerPC string `json:"caller_pc,omitempty"`
	Count    int    `json:"count"`
	Category string `json:"category"` // "crypto" | "jni" | "libc" | "antidebug" | "syscall" | "external"
}

// VMPTraceAnalysis summarizes the structural insights extracted from a raw
// Frida Stalker, Unidbg, or Tenet instruction trace of a virtualized function.
type VMPTraceAnalysis struct {
	ModuleBase           string            `json:"module_base,omitempty"`
	TotalInstructions    int               `json:"total_instructions"`
	UniquePCs            int               `json:"unique_pcs"`
	DispatcherCandidates []VMPHotspot      `json:"dispatcher_candidates"`
	HandlerEntries       []VMPHotspot      `json:"handler_entries"`
	MemoryHotspots       []VMPMemSpot      `json:"memory_hotspots"`
	ExternalCalls        []VMPExternalCall `json:"external_calls"`
	RecommendedHooks     []string          `json:"recommended_hooks"`
	Summary              string            `json:"summary"`
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func jsQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func pyQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func javaQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func boolJS(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}
