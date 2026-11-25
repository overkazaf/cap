// Package cryptolab provides a CyberChef-style composable codec/crypto pipeline
// engine, pure-Go symmetric ciphers (AES, SM4, ChaCha20, RC4), custom-IV hash
// functions, payload auto-identification, schema-less Protobuf wire inspection
// and re-encoding, and a White-Box AES-128 Round-9 Differential Fault Analysis
// (DFA) master-key recovery solver with emulator fault-injection templates.
package cryptolab

// OperationParamSpec describes a single configurable parameter for a pipeline
// operation so frontends can render dynamic parameter forms automatically.
type OperationParamSpec struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Type        string   `json:"type"` // "string", "select", "boolean", "number", "hex"
	Default     string   `json:"default,omitempty"`
	Options     []string `json:"options,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description,omitempty"`
}

// OperationSpec is a self-describing entry in the pipeline operations catalog.
type OperationSpec struct {
	Name        string               `json:"name"`
	Category    string               `json:"category"` // "codec", "compression", "xor", "hash", "hmac", "cipher", "protobuf"
	Label       string               `json:"label"`
	Description string               `json:"description"`
	Params      []OperationParamSpec `json:"params,omitempty"`
}

// PipelineStep represents one operation node in an ordered transformation chain.
type PipelineStep struct {
	Op       string            `json:"op"`
	Params   map[string]string `json:"params,omitempty"`
	Disabled bool              `json:"disabled,omitempty"`
}

// PipelineRequest carries the input payload and ordered list of steps to run.
type PipelineRequest struct {
	Input         string         `json:"input"`
	InputEncoding string         `json:"input_encoding,omitempty"` // "utf8" (default), "hex", "base64"
	Steps         []PipelineStep `json:"steps"`
}

// PipelineStepResult captures per-step execution output and telemetry.
type PipelineStepResult struct {
	Index      int    `json:"index"`
	Op         string `json:"op"`
	Disabled   bool   `json:"disabled,omitempty"`
	OutputUTF8 string `json:"output_utf8"`
	OutputHex  string `json:"output_hex"`
	ByteLen    int    `json:"byte_len"`
	ElapsedUS  int64  `json:"elapsed_us"`
	Error      string `json:"error,omitempty"`
}

// PipelineResult holds the final output, timing, and per-step trace of a pipeline run.
type PipelineResult struct {
	Success        bool                 `json:"success"`
	OutputUTF8     string               `json:"output_utf8"`
	OutputHex      string               `json:"output_hex"`
	OutputBase64   string               `json:"output_base64"`
	ByteLen        int                  `json:"byte_len"`
	TotalElapsedUS int64                `json:"total_elapsed_us"`
	FailedStep     int                  `json:"failed_step"` // -1 when succeeded or failed before step 0
	Error          string               `json:"error,omitempty"`
	Steps          []PipelineStepResult `json:"steps"`
}

// XORCandidate represents one ranked candidate from single-byte XOR brute-forcing.
type XORCandidate struct {
	KeyByte        byte    `json:"key_byte"`
	KeyHex         string  `json:"key_hex"`
	Score          float64 `json:"score"`
	PrintableRatio float64 `json:"printable_ratio"`
	OutputUTF8     string  `json:"output_utf8"`
	OutputHex      string  `json:"output_hex"`
}

// IdentifyCandidate is a single format/encoding heuristic match.
type IdentifyCandidate struct {
	Format     string  `json:"format"`
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"` // 0.0..1.0
	Details    string  `json:"details,omitempty"`
	Preview    string  `json:"preview,omitempty"`
}

// RecommendedRecipe is a suggested pipeline recipe produced by IdentifyPayload.
type RecommendedRecipe struct {
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	InputEncoding string         `json:"input_encoding,omitempty"`
	Steps         []PipelineStep `json:"steps"`
}

// JWTPreview contains decoded header/payload JSON for a detected JWT token.
type JWTPreview struct {
	HeaderJSON   string `json:"header_json"`
	PayloadJSON  string `json:"payload_json"`
	SignatureB64 string `json:"signature_b64"`
	Algorithm    string `json:"algorithm,omitempty"`
}

// IdentifyResult summarizes format detection, entropy, and suggested recipes.
type IdentifyResult struct {
	InputLen        int                 `json:"input_len"`
	DecodedByteLen  int                 `json:"decoded_byte_len"`
	Entropy         float64             `json:"entropy"`
	EntropyClass    string              `json:"entropy_class"`
	IsPrintableUTF8 bool                `json:"is_printable_utf8"`
	Candidates      []IdentifyCandidate `json:"candidates"`
	JWT             *JWTPreview         `json:"jwt,omitempty"`
	Recipes         []RecommendedRecipe `json:"recipes,omitempty"`
}

// ProtoFieldNode represents a single wire-level Protobuf field in a schema-less AST.
type ProtoFieldNode struct {
	FieldNumber  int               `json:"field_number"`
	WireType     int               `json:"wire_type"`      // 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit
	WireTypeName string            `json:"wire_type_name"` // "varint", "fixed64", "length_delimited", "fixed32"
	Kind         string            `json:"kind"`           // "varint", "uint64", "int64", "sint64", "fixed64", "sfixed64", "double", "fixed32", "sfixed32", "float", "string", "bytes", "message"
	VarintU64    *uint64           `json:"varint_u64,omitempty"`
	VarintI64    *int64            `json:"varint_i64,omitempty"`
	VarintS64    *int64            `json:"varint_s64,omitempty"` // ZigZag decoded
	Fixed64U     *uint64           `json:"fixed64_u,omitempty"`
	Fixed64S     *int64            `json:"fixed64_s,omitempty"`
	DoubleVal    *float64          `json:"double_val,omitempty"`
	Fixed32U     *uint32           `json:"fixed32_u,omitempty"`
	Fixed32S     *int32            `json:"fixed32_s,omitempty"`
	FloatVal     *float64          `json:"float_val,omitempty"`
	StringVal    string            `json:"string_val,omitempty"`
	BytesHex     string            `json:"bytes_hex,omitempty"`
	ByteLen      int               `json:"byte_len,omitempty"`
	Nested       *ProtoMessageNode `json:"nested,omitempty"`
	RawHex       string            `json:"raw_hex,omitempty"`
}

// ProtoMessageNode is a schema-less decoded Protobuf message tree.
type ProtoMessageNode struct {
	Fields    []ProtoFieldNode `json:"fields"`
	ByteLen   int              `json:"byte_len"`
	Truncated bool             `json:"truncated,omitempty"`
	Warnings  []string         `json:"warnings,omitempty"`
}

// DFARequest carries a valid ciphertext and faulty ciphertexts for AES-128 Round-9 DFA.
type DFARequest struct {
	ValidCiphertextHex   string   `json:"valid_ciphertext_hex"`
	FaultyCiphertextsHex []string `json:"faulty_ciphertexts_hex"`
	PlaintextHex         string   `json:"plaintext_hex,omitempty"` // optional 16-byte plaintext for end-to-end verification
}

// DFAColumnStatus reports recovery progress for one ShiftRows column group of K10.
type DFAColumnStatus struct {
	GroupIndex     int    `json:"group_index"`
	ByteIndices    [4]int `json:"byte_indices"`
	FaultCount     int    `json:"fault_count"`
	CandidateCount int    `json:"candidate_count"`
	Solved         bool   `json:"solved"`
	SubkeyBytesHex string `json:"subkey_bytes_hex,omitempty"`
}

// DFAResult holds the recovered AES-128 key material and per-column diagnostics.
type DFAResult struct {
	Solved                bool               `json:"solved"`
	MasterKeyHex          string             `json:"master_key_hex,omitempty"`
	Round10KeyHex         string             `json:"round10_key_hex,omitempty"`
	VerifiedWithPlaintext bool               `json:"verified_with_plaintext,omitempty"`
	ValidCiphertextHex    string             `json:"valid_ciphertext_hex"`
	TotalFaultsInput      int                `json:"total_faults_input"`
	UsableFaults          int                `json:"usable_faults"`
	IgnoredFaults         int                `json:"ignored_faults"`
	Columns               [4]DFAColumnStatus `json:"columns"`
	ElapsedUS             int64              `json:"elapsed_us"`
	Notes                 []string           `json:"notes,omitempty"`
}

// DFAScriptConfig configures Unidbg or Qiling fault-injection script generation.
type DFAScriptConfig struct {
	BinaryPath      string `json:"binary_path,omitempty"`
	APKPath         string `json:"apk_path,omitempty"`
	PackageName     string `json:"package_name,omitempty"`
	Arch            string `json:"arch,omitempty"` // "arm64", "arm", "x86_64"
	RootFS          string `json:"rootfs,omitempty"`
	TargetClass     string `json:"target_class,omitempty"`
	TargetMethod    string `json:"target_method,omitempty"`
	MethodSignature string `json:"method_signature,omitempty"`
	TargetSymbol    string `json:"target_symbol,omitempty"`
	TargetAddr      string `json:"target_addr,omitempty"`
	FaultHookAddr   string `json:"fault_hook_addr,omitempty"`
	StateBufReg     string `json:"state_buf_reg,omitempty"`
	StateBufAddr    string `json:"state_buf_addr,omitempty"`
	PlaintextHex    string `json:"plaintext_hex,omitempty"`
	FaultXOR        byte   `json:"fault_xor,omitempty"`
	FaultsPerByte   int    `json:"faults_per_byte,omitempty"`
	ClassName       string `json:"class_name,omitempty"`
}

// GeneratedDFAScript holds a generated fault-injection harness script.
type GeneratedDFAScript struct {
	Engine      string   `json:"engine"` // "unidbg" or "qiling"
	Language    string   `json:"language"`
	FileName    string   `json:"file_name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Code        string   `json:"code"`
	Notes       []string `json:"notes,omitempty"`
}
