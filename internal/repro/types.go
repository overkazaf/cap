// Package repro implements cap's P1 Professional Reverse-Engineering Extensions:
//
//  1. Unidbg Smart Auto-Stub & Runtime Environment Assistant (autostub.go)
//  2. JADX Decompiler Workspace & Java<->JNI Cross-Linker (jadx.go)
//  3. IDA Pro / Ghidra / Binary Ninja Symbol & Comment Bridge (symbols.go)
//  4. iOS Mach-O / IPA Static Inspector & Emulation/Stealth Templates (ios.go)
//
// All analysis and code generation runs in pure Go using the standard library
// (plus optional external jadx invocation with graceful pure-Go DEX fallback).
package repro

import "time"

const (
	// Unidbg AbstractJni callback identifiers.
	CallbackCallObjectMethodV       = "callObjectMethodV"
	CallbackCallStaticObjectMethodV = "callStaticObjectMethodV"
	CallbackGetObjectField          = "getObjectField"
	CallbackGetStaticObjectField    = "getStaticObjectField"
	CallbackGetIntField             = "getIntField"
	CallbackCallIntMethodV          = "callIntMethodV"
	CallbackCallBooleanMethodV      = "callBooleanMethodV"
	CallbackNewObjectV              = "newObjectV"
	CallbackResolveClass            = "resolveClass"

	// Java<->Native binding kinds.
	BindingStaticExport    = "static_export"
	BindingDynamicRegister = "dynamic_register"
	BindingUnresolved      = "unresolved"

	// JADX workspace modes.
	WorkspaceModeJadx      = "jadx"
	WorkspaceModePureGoDEX = "pure-go-dex"

	// iOS binary container kinds.
	IOSKindMachO    = "macho"
	IOSKindFatMachO = "fat-macho"
	IOSKindIPA      = "ipa"

	// SymbolBundle schema version.
	SymbolBundleVersion = "1.0"
)

// GeneratedToolScript holds a generated Frida JS, Unidbg Java, or Python bridge
// script together with human-readable metadata.
type GeneratedToolScript struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Engine      string   `json:"engine"`   // "frida" | "unidbg" | "ida" | "ghidra"
	Language    string   `json:"language"` // "javascript" | "java" | "python"
	FileName    string   `json:"file_name"`
	Description string   `json:"description"`
	Summary     string   `json:"summary"`
	Code        string   `json:"code"`
	Notes       []string `json:"notes,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	GeneratedAt string   `json:"generated_at"`
}

// --- 1. Unidbg Smart Auto-Stub & Runtime Environment Assistant ---------------

// MissingJNIItem represents one deduplicated missing JNI method/field/class
// detected in a Unidbg runtime exception log.
type MissingJNIItem struct {
	Callback      string `json:"callback"`
	Signature     string `json:"signature"`
	ClassName     string `json:"class_name"`
	MemberName    string `json:"member_name,omitempty"`
	Descriptor    string `json:"descriptor,omitempty"`
	Count         int    `json:"count"`
	SmartMatch    bool   `json:"smart_match"`
	SuggestedCode string `json:"suggested_code"`
	Note          string `json:"note,omitempty"`
}

// MissingFileItem represents one deduplicated missing filesystem path accessed
// during Unidbg emulation (for IOResolver<AndroidFileIO>).
type MissingFileItem struct {
	Path             string `json:"path"`
	Count            int    `json:"count"`
	SuggestedContent string `json:"suggested_content,omitempty"`
	Note             string `json:"note,omitempty"`
}

// MissingSysPropItem represents one deduplicated Android system property key
// queried via __system_property_get during Unidbg emulation.
type MissingSysPropItem struct {
	Key            string `json:"key"`
	Count          int    `json:"count"`
	SuggestedValue string `json:"suggested_value"`
	Note           string `json:"note,omitempty"`
}

// MissingLibraryItem represents one deduplicated missing shared library (.so)
// referenced during Unidbg loading.
type MissingLibraryItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Note  string `json:"note,omitempty"`
}

// UnidbgStubDiagnosis aggregates all parsed Unidbg missing-environment items
// and ready-to-compile Java stub snippets.
type UnidbgStubDiagnosis struct {
	TotalErrors         int                  `json:"total_errors"`
	MissingJNI          []MissingJNIItem     `json:"missing_jni"`
	MissingClasses      []string             `json:"missing_classes,omitempty"`
	MissingFiles        []MissingFileItem    `json:"missing_files"`
	MissingSysProps     []MissingSysPropItem `json:"missing_sys_props"`
	MissingLibraries    []MissingLibraryItem `json:"missing_libraries"`
	AbstractJniSnippet  string               `json:"abstract_jni_snippet"`
	IOResolverSnippet   string               `json:"io_resolver_snippet"`
	SysPropHookSnippet  string               `json:"sys_prop_hook_snippet"`
	CombinedJavaSnippet string               `json:"combined_java_snippet"`
	Summary             string               `json:"summary"`
	AnalyzedAt          string               `json:"analyzed_at"`
}

// --- 2. JADX Decompiler Workspace & Java<->JNI Cross-Linker ------------------

// JadxInfo reports host jadx CLI availability, resolved path, version, and
// diagnostic details if unavailable.
type JadxInfo struct {
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	Issue     string `json:"issue,omitempty"`
}

// JadxWorkspace describes a deterministic cached APK/DEX decompilation
// workspace produced by jadx or the pure-Go DEX fallback.
type JadxWorkspace struct {
	APKPath          string   `json:"apk_path"`
	WorkspaceDir     string   `json:"workspace_dir"`
	CacheKey         string   `json:"cache_key"`
	CacheHit         bool     `json:"cache_hit"`
	Mode             string   `json:"mode"` // "jadx" | "pure-go-dex"
	ClassCount       int      `json:"class_count"`
	NativeClassCount int      `json:"native_class_count"`
	JadxVersion      string   `json:"jadx_version,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	DecompiledAt     string   `json:"decompiled_at"`
	ElapsedMs        int64    `json:"elapsed_ms"`
}

// JadxClassEntry summarizes one Java class inside a decompiled workspace.
type JadxClassEntry struct {
	ClassName     string   `json:"class_name"`
	PackageName   string   `json:"package_name"`
	SimpleName    string   `json:"simple_name"`
	RelPath       string   `json:"rel_path"`
	Size          int64    `json:"size"`
	HasNative     bool     `json:"has_native"`
	NativeMethods []string `json:"native_methods,omitempty"`
}

// NativeMethodDecl represents a single Java `native` method declaration parsed
// from decompiled Java source code along with its JNI descriptors.
type NativeMethodDecl struct {
	ClassName    string   `json:"class_name"`
	MethodName   string   `json:"method_name"`
	ReturnType   string   `json:"return_type"`
	ParamTypes   []string `json:"param_types,omitempty"`
	JNISignature string   `json:"jni_signature"`
	MangledShort string   `json:"mangled_short"`
	MangledLong  string   `json:"mangled_long"`
	Line         int      `json:"line"`
	IsStatic     bool     `json:"is_static"`
	RelPath      string   `json:"rel_path,omitempty"`
}

// JadxClassSource contains the full decompiled source code and metadata of a
// single Java class.
type JadxClassSource struct {
	ClassName     string             `json:"class_name"`
	RelPath       string             `json:"rel_path"`
	Source        string             `json:"source"`
	LineCount     int                `json:"line_count"`
	HasNative     bool               `json:"has_native"`
	NativeMethods []NativeMethodDecl `json:"native_methods,omitempty"`
}

// JadxSearchHit records one case-insensitive source search match.
type JadxSearchHit struct {
	ClassName string `json:"class_name"`
	RelPath   string `json:"rel_path"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	Snippet   string `json:"snippet"`
}

// JavaNativeBinding links a Java `native` method declaration to a native ELF
// export or dynamic RegisterNatives target.
type JavaNativeBinding struct {
	JavaClass     string `json:"java_class"`
	JavaMethod    string `json:"java_method"`
	JavaSignature string `json:"java_signature"`
	JavaLine      int    `json:"java_line,omitempty"`
	JavaRelPath   string `json:"java_rel_path,omitempty"`
	MangledName   string `json:"mangled_name"`
	NativeSymbol  string `json:"native_symbol,omitempty"`
	NativeAddr    string `json:"native_addr,omitempty"`
	NativeOffset  uint64 `json:"native_offset,omitempty"`
	NativeSize    uint64 `json:"native_size,omitempty"`
	SOName        string `json:"so_name,omitempty"`
	BindingKind   string `json:"binding_kind"` // "static_export" | "dynamic_register" | "unresolved"
}

// JavaNativeLinkReport aggregates Java<->JNI cross-linking results across a
// decompiled workspace, an optional ELF .so binary, and optional Frida
// RegisterNatives mappings.
type JavaNativeLinkReport struct {
	WorkspaceDir       string              `json:"workspace_dir"`
	SOPath             string              `json:"so_path,omitempty"`
	SOName             string              `json:"so_name,omitempty"`
	SOArch             string              `json:"so_arch,omitempty"`
	TotalNativeMethods int                 `json:"total_native_methods"`
	StaticCount        int                 `json:"static_count"`
	DynamicCount       int                 `json:"dynamic_count"`
	UnresolvedCount    int                 `json:"unresolved_count"`
	Bindings           []JavaNativeBinding `json:"bindings"`
	OrphanExports      []string            `json:"orphan_exports,omitempty"`
	Warnings           []string            `json:"warnings,omitempty"`
	Summary            string              `json:"summary"`
}

// --- 3. IDA Pro / Ghidra / Binary Ninja Symbol & Comment Bridge --------------

// SymbolItem represents one named function or data symbol in a SymbolBundle.
type SymbolItem struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Size      uint64 `json:"size,omitempty"`
	Signature string `json:"signature,omitempty"`
	Type      string `json:"type,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

// CommentItem represents one address-anchored disassembly comment.
type CommentItem struct {
	Address    string `json:"address"`
	Text       string `json:"text"`
	Repeatable bool   `json:"repeatable,omitempty"`
}

// SymbolBundle is the portable JSON interchange format for syncing function
// names, disassembly comments, and JNI bindings with IDA Pro, Ghidra, and
// Binary Ninja.
type SymbolBundle struct {
	Version     string              `json:"version,omitempty"`
	BinaryName  string              `json:"binary_name"`
	Arch        string              `json:"arch,omitempty"`
	ImageBase   string              `json:"image_base,omitempty"`
	Functions   []SymbolItem        `json:"functions"`
	Comments    []CommentItem       `json:"comments"`
	JNIBindings []JavaNativeBinding `json:"jni_bindings,omitempty"`
	CreatedAt   string              `json:"created_at,omitempty"`
}

// --- 4. iOS Mach-O / IPA Static Inspector & Emulation/Stealth Templates ------

// IOSArchInfo describes one Mach-O architecture slice.
type IOSArchInfo struct {
	Arch        string `json:"arch"`
	CPUType     string `json:"cpu_type"`
	CPUSubtype  string `json:"cpu_subtype,omitempty"`
	Bits        int    `json:"bits"`
	FileType    string `json:"file_type"`
	MinOS       string `json:"min_os,omitempty"`
	SDKVersion  string `json:"sdk_version,omitempty"`
	Platform    string `json:"platform,omitempty"`
	PIE         bool   `json:"pie"`
	NX          bool   `json:"nx"`
	ARC         bool   `json:"arc"`
	StackCanary bool   `json:"stack_canary"`
	Encrypted   bool   `json:"encrypted"`
	CryptID     uint32 `json:"crypt_id"`
	CryptOff    uint32 `json:"crypt_off,omitempty"`
	CryptSize   uint32 `json:"crypt_size,omitempty"`
}

// IOSPlistInfo captures key security and packaging fields from an iOS app's
// Info.plist.
type IOSPlistInfo struct {
	BundleID                string   `json:"bundle_id,omitempty"`
	BundleName              string   `json:"bundle_name,omitempty"`
	DisplayName             string   `json:"display_name,omitempty"`
	Executable              string   `json:"executable,omitempty"`
	Version                 string   `json:"version,omitempty"`
	BuildVersion            string   `json:"build_version,omitempty"`
	MinimumOSVersion        string   `json:"minimum_os_version,omitempty"`
	URLSchemes              []string `json:"url_schemes,omitempty"`
	QueriesSchemes          []string `json:"queries_schemes,omitempty"`
	ATSAllowsArbitraryLoads bool     `json:"ats_allows_arbitrary_loads"`
	ATSExceptionDomains     []string `json:"ats_exception_domains,omitempty"`
	RawFormat               string   `json:"raw_format,omitempty"` // "xml" | "bplist"
}

// IOSBinaryReport aggregates static analysis findings for a standalone Mach-O,
// Universal Fat Mach-O, or .ipa archive.
type IOSBinaryReport struct {
	FilePath          string        `json:"file_path"`
	FileName          string        `json:"file_name"`
	FileKind          string        `json:"file_kind"` // "macho" | "fat-macho" | "ipa"
	FileSize          int64         `json:"file_size"`
	MainBinaryName    string        `json:"main_binary_name,omitempty"`
	IsUniversal       bool          `json:"is_universal"`
	Architectures     []IOSArchInfo `json:"architectures"`
	PIE               bool          `json:"pie"`
	NX                bool          `json:"nx"`
	ARC               bool          `json:"arc"`
	StackCanary       bool          `json:"stack_canary"`
	FairPlayEncrypted bool          `json:"fairplay_encrypted"`
	CryptID           uint32        `json:"crypt_id"`
	MinOS             string        `json:"min_os,omitempty"`
	LinkedDylibs      []string      `json:"linked_dylibs"`
	Frameworks        []string      `json:"frameworks"`
	ObjCClasses       []string      `json:"objc_classes"`
	ObjCSelectors     []string      `json:"objc_selectors"`
	ExportedSymbols   []string      `json:"exported_symbols,omitempty"`
	InfoPlist         *IOSPlistInfo `json:"info_plist,omitempty"`
	Warnings          []string      `json:"warnings,omitempty"`
	Summary           string        `json:"summary"`
	AnalyzedAt        string        `json:"analyzed_at"`
}

// UnidbgIOSOptions configures GenerateUnidbgIOSHarness.
type UnidbgIOSOptions struct {
	ClassName    string   `json:"class_name,omitempty"`
	BundleID     string   `json:"bundle_id,omitempty"`
	BinaryPath   string   `json:"binary_path,omitempty"`
	IPAPath      string   `json:"ipa_path,omitempty"`
	TargetSymbol string   `json:"target_symbol,omitempty"`
	ObjCClass    string   `json:"objc_class,omitempty"`
	ObjCSelector string   `json:"objc_selector,omitempty"`
	TargetOffset string   `json:"target_offset,omitempty"`
	Args         []string `json:"args,omitempty"`
}

// IOSStealthOptions configures GenerateIOSStealthScript.
type IOSStealthOptions struct {
	BundleID              string   `json:"bundle_id,omitempty"`
	TargetBinary          string   `json:"target_binary,omitempty"`
	BypassPtrace          bool     `json:"bypass_ptrace"`
	BypassSysctl          bool     `json:"bypass_sysctl"`
	BypassGetppid         bool     `json:"bypass_getppid"`
	BypassDyldChecks      bool     `json:"bypass_dyld_checks"`
	BypassJailbreakChecks bool     `json:"bypass_jailbreak_checks"`
	CustomHidePaths       []string `json:"custom_hide_paths,omitempty"`
	CustomHideSchemes     []string `json:"custom_hide_schemes,omitempty"`
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
