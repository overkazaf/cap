// Package exectrace implements cap's dynamic execution trace engine:
// multi-format trace parsing (Unidbg, Frida Stalker, Qiling, Java/JNI call trees,
// JSONL, Tenet), call-tree reconstruction, cryptographic constant & round-loop
// detection, ARM64/ARM/x86 instruction-level forward and backward register+memory
// taint propagation, ASLR-normalized differential trace analysis, ready-to-run
// collector script generation, and persistent session storage/export.
package exectrace

// TraceFormat identifies the input format of a dynamic execution trace.
type TraceFormat string

const (
	FormatAuto     TraceFormat = "auto"
	FormatUnidbg   TraceFormat = "unidbg"
	FormatStalker  TraceFormat = "stalker"
	FormatQiling   TraceFormat = "qiling"
	FormatJavaCall TraceFormat = "java_call"
	FormatJSONL    TraceFormat = "jsonl"
	FormatTenet    TraceFormat = "tenet"
)

// Event kind constants for TraceEvent.Kind.
const (
	KindInsn      = "insn"
	KindCall      = "call"
	KindRet       = "ret"
	KindMemRead   = "mem_read"
	KindMemWrite  = "mem_write"
	KindJNI       = "jni"
	KindJavaEnter = "java_enter"
	KindJavaExit  = "java_exit"
	KindSyscall   = "syscall"
)

// Source constants for ExecTraceSession.Source.
const (
	SourceUnidbg   = "unidbg"
	SourceStalker  = "stalker"
	SourceQiling   = "qiling"
	SourceJava     = "java"
	SourceImported = "imported"
)

// Export format constants for ExportTrace / ExportSession.
const (
	ExportTenet    = "tenet"
	ExportJSONL    = "jsonl"
	ExportMarkdown = "markdown"
)

// Taint direction constants.
const (
	TaintForward  = "forward"
	TaintBackward = "backward"
)

// Memory region inferred role hints.
const (
	RoleInputBuffer  = "input_buffer"
	RoleOutputBuffer = "output_buffer"
	RoleLookupTable  = "lookup_table"
	RoleStack        = "stack"
	RoleState        = "state"
)

// TraceEvent represents a single normalized dynamic execution event.
type TraceEvent struct {
	Seq         int               `json:"seq"`
	TimestampMs int64             `json:"timestamp_ms,omitempty"`
	ThreadID    int               `json:"thread_id,omitempty"`
	Kind        string            `json:"kind"` // "insn" | "call" | "ret" | "mem_read" | "mem_write" | "jni" | "java_enter" | "java_exit" | "syscall"
	Module      string            `json:"module,omitempty"`
	Address     uint64            `json:"address,omitempty"`
	Offset      uint64            `json:"offset,omitempty"`
	Mnemonic    string            `json:"mnemonic,omitempty"`
	Operands    string            `json:"operands,omitempty"`
	RawBytes    string            `json:"raw_bytes,omitempty"`
	Symbol      string            `json:"symbol,omitempty"`
	RegsBefore  map[string]uint64 `json:"regs_before,omitempty"`
	RegsAfter   map[string]uint64 `json:"regs_after,omitempty"`
	MemAddr     uint64            `json:"mem_addr,omitempty"`
	MemSize     int               `json:"mem_size,omitempty"`
	MemValueHex string            `json:"mem_value_hex,omitempty"`
	Depth       int               `json:"depth,omitempty"`
	Args        []string          `json:"args,omitempty"`
	RetVal      string            `json:"ret_val,omitempty"`
	Raw         string            `json:"raw,omitempty"`
}

// ExecTraceSession stores a parsed dynamic execution trace along with metadata
// and pre-computed analytical summaries.
type ExecTraceSession struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Source        string         `json:"source"` // "unidbg" | "stalker" | "qiling" | "java" | "imported"
	Format        TraceFormat    `json:"format,omitempty"`
	TargetPackage string         `json:"target_package,omitempty"`
	TargetModule  string         `json:"target_module,omitempty"`
	Arch          string         `json:"arch,omitempty"`
	ModuleBase    uint64         `json:"module_base,omitempty"`
	TotalEvents   int            `json:"total_events"`
	InsnCount     int            `json:"insn_count"`
	MemOpCount    int            `json:"mem_op_count"`
	CallCount     int            `json:"call_count"`
	UniquePCs     int            `json:"unique_pcs"`
	CreatedAt     string         `json:"created_at"`
	Summary       *TraceAnalysis `json:"summary,omitempty"`
	Events        []TraceEvent   `json:"events,omitempty"`
}

// EventFilter specifies pagination and filtering criteria for QueryEvents.
type EventFilter struct {
	Offset   int    `json:"offset,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Module   string `json:"module,omitempty"`
	Address  uint64 `json:"address,omitempty"` // matches either Address or Offset
	MinAddr  uint64 `json:"min_addr,omitempty"`
	MaxAddr  uint64 `json:"max_addr,omitempty"`
	MinSeq   int    `json:"min_seq,omitempty"`
	MaxSeq   int    `json:"max_seq,omitempty"`
	ThreadID int    `json:"thread_id,omitempty"`
	Search   string `json:"search,omitempty"`
}

// EventPage is a paginated slice of TraceEvents returned by QueryEvents.
type EventPage struct {
	SessionID string       `json:"session_id"`
	Total     int          `json:"total"`
	Offset    int          `json:"offset"`
	Limit     int          `json:"limit"`
	HasMore   bool         `json:"has_more"`
	Events    []TraceEvent `json:"events"`
}

// FunctionStat aggregates execution frequency and instruction cost per function.
type FunctionStat struct {
	Name       string `json:"name"`
	Module     string `json:"module,omitempty"`
	Address    uint64 `json:"address,omitempty"`
	Offset     uint64 `json:"offset,omitempty"`
	Hits       int    `json:"hits"`
	InsnCount  int    `json:"insn_count"`
	ChildCalls int    `json:"child_calls"`
}

// CallNode represents a node in the reconstructed dynamic call hierarchy.
type CallNode struct {
	ID         int        `json:"id"`
	Name       string     `json:"name"`
	Module     string     `json:"module,omitempty"`
	Address    uint64     `json:"address,omitempty"`
	Offset     uint64     `json:"offset,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Depth      int        `json:"depth"`
	EnterSeq   int        `json:"enter_seq"`
	ExitSeq    int        `json:"exit_seq,omitempty"`
	InsnCount  int        `json:"insn_count"`
	DurationMs int64      `json:"duration_ms,omitempty"`
	Args       []string   `json:"args,omitempty"`
	RetVal     string     `json:"ret_val,omitempty"`
	Children   []CallNode `json:"children,omitempty"`
}

// CryptoPatternHit records a detected cryptographic constant, instruction, or
// custom XOR/rotate mixing signature observed during execution.
type CryptoPatternHit struct {
	Algorithm  string  `json:"algorithm"` // "MD5"|"SHA-1"|"SHA-256"|"SM3"|"AES"|"SM4"|"ChaCha20"|"TEA/XXTEA"|"CRC32"|"RC4"|"Custom-XOR-Rot"
	Seq        int     `json:"seq"`
	Address    uint64  `json:"address,omitempty"`
	Offset     uint64  `json:"offset,omitempty"`
	Module     string  `json:"module,omitempty"`
	Evidence   string  `json:"evidence"`
	Confidence float64 `json:"confidence"`
}

// MemoryRegionStat summarizes memory reads and writes aggregated by 4KB page/buffer.
type MemoryRegionStat struct {
	BaseAddr    uint64 `json:"base_addr"`
	EndAddr     uint64 `json:"end_addr"`
	BaseAddrHex string `json:"base_addr_hex,omitempty"`
	EndAddrHex  string `json:"end_addr_hex,omitempty"`
	ReadCount   int    `json:"read_count"`
	WriteCount  int    `json:"write_count"`
	UniqueAddrs int    `json:"unique_addrs"`
	SampleHex   string `json:"sample_hex,omitempty"`
	RoleHint    string `json:"role_hint"` // "input_buffer"|"output_buffer"|"lookup_table"|"stack"|"state"
}

// LoopStat describes a detected hot execution loop (backward branch cluster).
type LoopStat struct {
	StartAddr   uint64  `json:"start_addr"`
	EndAddr     uint64  `json:"end_addr"`
	StartOffset uint64  `json:"start_offset,omitempty"`
	EndOffset   uint64  `json:"end_offset,omitempty"`
	Module      string  `json:"module,omitempty"`
	Iterations  int     `json:"iterations"`
	BodyInsns   int     `json:"body_insns"`
	FirstSeq    int     `json:"first_seq"`
	LastSeq     int     `json:"last_seq"`
	CryptoRatio float64 `json:"crypto_ratio,omitempty"`
	Hint        string  `json:"hint,omitempty"`
}

// SyscallStat summarizes observed system calls.
type SyscallStat struct {
	Name      string `json:"name"`
	Number    int    `json:"number,omitempty"`
	Count     int    `json:"count"`
	FirstSeq  int    `json:"first_seq"`
	SampleRaw string `json:"sample_raw,omitempty"`
}

// TraceAnalysis holds the full automated analysis output for a trace session.
type TraceAnalysis struct {
	HotFunctions  []FunctionStat     `json:"hot_functions,omitempty"`
	CallTree      []CallNode         `json:"call_tree,omitempty"`
	CryptoHits    []CryptoPatternHit `json:"crypto_hits,omitempty"`
	MemoryRegions []MemoryRegionStat `json:"memory_regions,omitempty"`
	HotLoops      []LoopStat         `json:"hot_loops,omitempty"`
	Syscalls      []SyscallStat      `json:"syscalls,omitempty"`
	SummaryText   string             `json:"summary_text"`
}

// TaintRequest configures a forward or backward register/memory taint slice.
type TaintRequest struct {
	SessionID    string `json:"session_id,omitempty"`
	Direction    string `json:"direction"` // "forward" | "backward"
	StartSeq     int    `json:"start_seq"`
	SeedReg      string `json:"seed_reg,omitempty"`
	SeedMemAddr  uint64 `json:"seed_mem_addr,omitempty"`
	SeedValueHex string `json:"seed_value_hex,omitempty"`
	MaxSteps     int    `json:"max_steps,omitempty"`
}

// TaintStep represents a single instruction that propagated taint.
type TaintStep struct {
	Seq       int               `json:"seq"`
	Address   uint64            `json:"address,omitempty"`
	Offset    uint64            `json:"offset,omitempty"`
	Module    string            `json:"module,omitempty"`
	Mnemonic  string            `json:"mnemonic,omitempty"`
	Operands  string            `json:"operands,omitempty"`
	Reason    string            `json:"reason"`
	SrcRegs   []string          `json:"src_regs,omitempty"`
	DstRegs   []string          `json:"dst_regs,omitempty"`
	MemAddr   uint64            `json:"mem_addr,omitempty"`
	MemOp     string            `json:"mem_op,omitempty"` // "read" | "write"
	RegsAfter map[string]uint64 `json:"regs_after,omitempty"`
}

// TaintResult is the output of RunTaint.
type TaintResult struct {
	Direction       string      `json:"direction"`
	Seed            string      `json:"seed"`
	StartSeq        int         `json:"start_seq"`
	TaintedSteps    []TaintStep `json:"tainted_steps"`
	TaintedRegs     []string    `json:"tainted_regs"`
	TaintedMemAddrs []string    `json:"tainted_mem_addrs"`
	SourcesOrSinks  []string    `json:"sources_or_sinks"`
	Summary         string      `json:"summary"`
}

// DivergencePoint marks a location where two execution traces diverged.
type DivergencePoint struct {
	Index    int      `json:"index"`
	SeqA     int      `json:"seq_a"`
	SeqB     int      `json:"seq_b"`
	ModuleA  string   `json:"module_a,omitempty"`
	ModuleB  string   `json:"module_b,omitempty"`
	AddressA uint64   `json:"address_a,omitempty"`
	AddressB uint64   `json:"address_b,omitempty"`
	OffsetA  uint64   `json:"offset_a,omitempty"`
	OffsetB  uint64   `json:"offset_b,omitempty"`
	InsnA    string   `json:"insn_a,omitempty"`
	InsnB    string   `json:"insn_b,omitempty"`
	RegDiffs []string `json:"reg_diffs,omitempty"`
	Reason   string   `json:"reason"`
}

// TraceDiffResult summarizes an ASLR-normalized comparison of two traces.
type TraceDiffResult struct {
	SessionA         string            `json:"session_a"`
	SessionB         string            `json:"session_b"`
	TotalInsnsA      int               `json:"total_insns_a"`
	TotalInsnsB      int               `json:"total_insns_b"`
	CommonPrefixLen  int               `json:"common_prefix_len"`
	FirstDivergence  *DivergencePoint  `json:"first_divergence,omitempty"`
	DivergencePoints []DivergencePoint `json:"divergence_points,omitempty"`
	OnlyInA          []string          `json:"only_in_a,omitempty"`
	OnlyInB          []string          `json:"only_in_b,omitempty"`
	Summary          string            `json:"summary"`
}

// CollectorConfig parameterizes ready-to-run trace collector script generation.
type CollectorConfig struct {
	TargetPackage string   `json:"target_package,omitempty"`
	TargetModule  string   `json:"target_module,omitempty"`
	TargetSymbol  string   `json:"target_symbol,omitempty"`
	TargetOffset  string   `json:"target_offset,omitempty"`
	Arch          string   `json:"arch,omitempty"` // "arm64" | "arm" | "x86_64"
	ClassFilter   string   `json:"class_filter,omitempty"`
	MethodFilter  string   `json:"method_filter,omitempty"`
	IncludeRegs   bool     `json:"include_regs"`
	IncludeMem    bool     `json:"include_mem"`
	IncludeCalls  bool     `json:"include_calls"`
	MaxEvents     int      `json:"max_events,omitempty"`
	BinaryPath    string   `json:"binary_path,omitempty"`
	APKPath       string   `json:"apk_path,omitempty"`
	RootFS        string   `json:"rootfs,omitempty"`
	Args          []string `json:"args,omitempty"`
}

// GeneratedCollector holds a generated trace collector script ready for execution.
type GeneratedCollector struct {
	Kind        string   `json:"kind"` // "stalker" | "java_call" | "unidbg" | "qiling"
	Name        string   `json:"name"`
	Language    string   `json:"language"` // "javascript" | "java" | "python"
	Filename    string   `json:"filename"`
	Description string   `json:"description"`
	Code        string   `json:"code"`
	UsageSteps  []string `json:"usage_steps,omitempty"`
	GeneratedAt string   `json:"generated_at"`
}
