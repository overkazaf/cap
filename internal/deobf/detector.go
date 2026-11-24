package deobf

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxScanFileBytes    = 32 * 1024 * 1024 // 32 MiB cap per ELF or DEX entry
	maxScanSectionBytes = 12 * 1024 * 1024 // 12 MiB cap per ELF section
	maxAPKSOAudits      = 24
	maxInlineSVCReports = 12
)

// ShannonEntropy computes the base-2 Shannon entropy of data in bits/byte [0, 8].
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]uint64
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	if h < 0 {
		return 0
	}
	return h
}

// ScanELF reads an ELF binary (.so or executable) from disk and runs deep
// protection, obfuscation, VMP, and anti-debug analysis.
func ScanELF(elfPath string) (*ProtectionReport, error) {
	if strings.TrimSpace(elfPath) == "" {
		return nil, fmt.Errorf("elf path is required")
	}
	f, err := os.Open(elfPath)
	if err != nil {
		return nil, fmt.Errorf("open elf %s: %w", elfPath, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxScanFileBytes))
	if err != nil {
		return nil, fmt.Errorf("read elf %s: %w", elfPath, err)
	}
	report, err := ScanELFBytes(filepath.Base(elfPath), data)
	if err != nil {
		return nil, err
	}
	report.TargetPath = elfPath
	return report, nil
}

// ScanELFBytes analyzes an in-memory ELF binary buffer in pure Go.
func ScanELFBytes(name string, data []byte) (*ProtectionReport, error) {
	if len(data) < 52 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, fmt.Errorf("%s: not a valid ELF binary", name)
	}
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse elf %s: %w", name, err)
	}
	defer ef.Close()

	baseName := filepath.Base(strings.TrimSpace(name))
	if baseName == "" || baseName == "." {
		baseName = "binary.so"
	}

	report := newEmptyReport(name, TargetKindELF)

	audit, obfs, vmps, antiDebugs := inspectELF(baseName, data, ef)
	report.SOAudits = append(report.SOAudits, audit)
	report.Obfuscation = append(report.Obfuscation, obfs...)
	report.VMPIndicators = append(report.VMPIndicators, vmps...)
	report.AntiDebugFindings = append(report.AntiDebugFindings, antiDebugs...)

	// Check filename-based packer hints even when scanning a single .so directly.
	if packers := matchPackersFromEntries([]string{"lib/arm64-v8a/" + baseName}, nil); len(packers) > 0 {
		report.Packers = append(report.Packers, packers...)
	}

	finalizeReport(report)
	return report, nil
}

// ScanAPK performs a full multi-layer security & hardening audit of an Android
// APK archive: commercial packer detection, DEX obfuscation & Dex2C / Dex-VMP
// heuristics, Java anti-debug checks, and deep ELF audits across native .so libs.
func ScanAPK(apkPath string) (*ProtectionReport, error) {
	if strings.TrimSpace(apkPath) == "" {
		return nil, fmt.Errorf("apk path is required")
	}
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk %s: %w", apkPath, err)
	}
	defer zr.Close()

	report := newEmptyReport(apkPath, TargetKindAPK)

	var entryNames []string
	var dexFiles []*zip.File
	var soFiles []*zip.File

	for _, f := range zr.File {
		name := filepath.ToSlash(f.Name)
		entryNames = append(entryNames, name)
		low := strings.ToLower(name)
		if strings.HasPrefix(low, "classes") && strings.HasSuffix(low, ".dex") && !strings.Contains(low, "/") {
			dexFiles = append(dexFiles, f)
		} else if strings.HasPrefix(low, "lib/") && strings.HasSuffix(low, ".so") {
			soFiles = append(soFiles, f)
		}
	}

	// 1. Inspect DEX files for packer wrapper classes, ProGuard/R8, Dex2C/Dex-VMP, and Java anti-debug.
	dexStrings := make(map[string]bool)
	var totalDexBytes int64
	var dexObfs []ObfuscationFinding
	var dexVMPs []VMPFinding
	var dexAntiDebug []AntiDebugFinding

	sort.Slice(dexFiles, func(i, j int) bool { return dexFiles[i].Name < dexFiles[j].Name })
	for _, df := range dexFiles {
		buf, err := readZipBounded(df, maxScanFileBytes)
		if err != nil || len(buf) == 0 {
			continue
		}
		totalDexBytes += int64(len(buf))
		dStrs, dObf, dVmp, dAnti := inspectDexBuffer(df.Name, buf)
		for s := range dStrs {
			dexStrings[s] = true
		}
		dexObfs = append(dexObfs, dObf...)
		dexVMPs = append(dexVMPs, dVmp...)
		dexAntiDebug = append(dexAntiDebug, dAnti...)
	}

	// 2. Match commercial packers across APK entries + DEX wrapper strings.
	report.Packers = matchPackersFromEntries(entryNames, dexStrings)

	// Stub-loader DEX heuristic: packer detected + tiny classes.dex (< 256 KiB).
	if len(report.Packers) > 0 && len(dexFiles) == 1 && totalDexBytes > 0 && totalDexBytes < 256*1024 {
		report.VMPIndicators = append(report.VMPIndicators, VMPFinding{
			Kind:       VMPDex,
			Module:     dexFiles[0].Name,
			Confidence: 0.72,
			Evidence: []string{
				fmt.Sprintf("Stub-sized %s (%d bytes) paired with packer %s", dexFiles[0].Name, totalDexBytes, report.Packers[0].Name),
			},
			Strategy: "Use cap DEX Unpacker (libart.so OpenMemory hook + memory scan) after shell bootstrap completes",
		})
	}

	report.Obfuscation = append(report.Obfuscation, dexObfs...)
	report.VMPIndicators = append(report.VMPIndicators, dexVMPs...)
	report.AntiDebugFindings = append(report.AntiDebugFindings, dexAntiDebug...)

	// 3. Deduplicate SO files by library basename (preferring arm64-v8a > armeabi-v7a > x86_64 > x86)
	//    and prioritize packer/security libraries.
	selectedSOs := selectAPKSOs(soFiles, maxAPKSOAudits)
	for _, sf := range selectedSOs {
		buf, err := readZipBounded(sf, maxScanFileBytes)
		if err != nil || len(buf) < 52 || !bytes.Equal(buf[:4], []byte{0x7f, 'E', 'L', 'F'}) {
			continue
		}
		ef, err := elf.NewFile(bytes.NewReader(buf))
		if err != nil {
			continue
		}
		libBase := filepath.Base(sf.Name)
		audit, obfs, vmps, antiDebugs := inspectELF(libBase, buf, ef)
		_ = ef.Close()
		report.SOAudits = append(report.SOAudits, audit)
		report.Obfuscation = append(report.Obfuscation, obfs...)
		report.VMPIndicators = append(report.VMPIndicators, vmps...)
		report.AntiDebugFindings = append(report.AntiDebugFindings, antiDebugs...)
	}

	finalizeReport(report)
	return report, nil
}

func newEmptyReport(targetPath, kind string) *ProtectionReport {
	return &ProtectionReport{
		TargetPath:        targetPath,
		TargetKind:        kind,
		HardeningLevel:    HardeningNone,
		Packers:           []PackerFinding{},
		Obfuscation:       []ObfuscationFinding{},
		VMPIndicators:     []VMPFinding{},
		AntiDebugFindings: []AntiDebugFinding{},
		SOAudits:          []SOBinaryAudit{},
		Recommendations:   []string{},
		AnalyzedAt:        nowRFC3339(),
	}
}

// ─── ELF Deep Inspection ──────────────────────────────────────────────────────

type arm64InsnStats struct {
	totalInsns      int
	svcOffsets      []uint64
	svcSyscalls     map[uint64]uint16 // vaddr -> syscall nr if preceded by MOVZ X8, #nr
	brCount         int
	blrCount        int
	cntvctOffsets   []uint64
	movzMovk32Count int
	cselCount       int
	bcondCount      int
	logicOpCount    int
	arithOpCount    int
}

func elfArchName(m elf.Machine) string {
	switch m {
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_386:
		return "x86"
	case elf.EM_RISCV:
		return "riscv"
	default:
		return strings.ToLower(strings.TrimPrefix(m.String(), "EM_"))
	}
}

var standardELFSections = map[string]bool{
	"": true, ".text": true, ".rodata": true, ".data": true, ".bss": true,
	".plt": true, ".got": true, ".got.plt": true, ".init": true, ".fini": true,
	".init_array": true, ".fini_array": true, ".preinit_array": true, ".ctors": true, ".dtors": true,
	".dynamic": true, ".dynstr": true, ".dynsym": true, ".hash": true, ".gnu.hash": true,
	".gnu.version": true, ".gnu.version_r": true, ".gnu.version_d": true,
	".rela.dyn": true, ".rela.plt": true, ".rel.dyn": true, ".rel.plt": true,
	".android.rel.dyn": true, ".android.rela.dyn": true,
	".eh_frame": true, ".eh_frame_hdr": true, ".gcc_except_table": true,
	".ARM.exidx": true, ".ARM.extab": true, ".ARM.attributes": true, ".gnu.attributes": true,
	".comment": true, ".shstrtab": true, ".strtab": true, ".symtab": true,
	".tdata": true, ".tbss": true, ".data.rel.ro": true, ".interp": true,
	".jcr": true, ".gnu_debuglink": true, ".gnu_debugdata": true,
}

var vmpSectionKeywords = []string{
	"vmp", ".vm", "bytecode", "sec", "ijm", "qprotect", "jiagu",
	"bangcle", "ollvm", "hikari", "obf", "shield", "pack", "upx",
	"stub", "protect", "mytext", "yidun", "naga", "ali", "dx_",
}

func isStandardSection(name string) bool {
	if standardELFSections[name] {
		return true
	}
	if strings.HasPrefix(name, ".note.") || strings.HasPrefix(name, ".debug_") ||
		strings.HasPrefix(name, ".rodata.") || strings.HasPrefix(name, ".text.") ||
		strings.HasPrefix(name, ".data.") || strings.HasPrefix(name, ".bss.") {
		return true
	}
	return false
}

func isVMPSectionName(name string) bool {
	low := strings.ToLower(name)
	for _, kw := range vmpSectionKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func inspectELF(name string, raw []byte, ef *elf.File) (SOBinaryAudit, []ObfuscationFinding, []VMPFinding, []AntiDebugFinding) {
	arch := elfArchName(ef.Machine)
	ptrSize := uint64(8)
	if ef.Class == elf.ELFCLASS32 {
		ptrSize = 4
	}

	secFlags := map[string]bool{
		"pie":        ef.Type == elf.ET_DYN,
		"nx":         false,
		"relro":      false,
		"full_relro": false,
		"canary":     false,
		"fortify":    false,
		"stripped":   false,
	}

	// Program header mitigations (NX, RELRO).
	for _, ph := range ef.Progs {
		if ph == nil {
			continue
		}
		if ph.Type == elf.PT_GNU_STACK && ph.Flags&elf.PF_X == 0 {
			secFlags["nx"] = true
		}
		if ph.Type == elf.PT_GNU_RELRO {
			secFlags["relro"] = true
		}
	}

	// Check FULL RELRO via dynamic tags.
	if secFlags["relro"] {
		if vals, err := ef.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
			secFlags["full_relro"] = true
		} else if flags, err := ef.DynValue(elf.DT_FLAGS); err == nil {
			for _, f := range flags {
				if f&uint64(elf.DF_BIND_NOW) != 0 {
					secFlags["full_relro"] = true
				}
			}
		}
		if !secFlags["full_relro"] {
			if flags1, err := ef.DynValue(elf.DT_FLAGS_1); err == nil {
				for _, f := range flags1 {
					if f&uint64(elf.DF_1_NOW) != 0 {
						secFlags["full_relro"] = true
					}
				}
			}
		}
	}

	// Collect symbols & imports.
	symNames := make(map[string]uint64)
	importNames := make(map[string]bool)
	jniExportCount := 0
	hasSymtab := false

	if syms, err := ef.Symbols(); err == nil && len(syms) > 0 {
		hasSymtab = true
		for _, s := range syms {
			if s.Name != "" {
				symNames[s.Name] = s.Value
				if strings.HasPrefix(s.Name, "Java_") {
					jniExportCount++
				}
			}
		}
	}
	if dynSyms, err := ef.DynamicSymbols(); err == nil {
		for _, s := range dynSyms {
			if s.Name == "" {
				continue
			}
			if s.Section == elf.SHN_UNDEF {
				importNames[s.Name] = true
			} else {
				if _, exists := symNames[s.Name]; !exists {
					symNames[s.Name] = s.Value
					if strings.HasPrefix(s.Name, "Java_") {
						jniExportCount++
					}
				}
			}
		}
	}
	if imps, err := ef.ImportedSymbols(); err == nil {
		for _, imp := range imps {
			if imp.Name != "" {
				importNames[imp.Name] = true
			}
		}
	}

	for imp := range importNames {
		if imp == "__stack_chk_fail" || imp == "__stack_chk_guard" {
			secFlags["canary"] = true
		}
		if strings.HasSuffix(imp, "_chk") && strings.HasPrefix(imp, "__") {
			secFlags["fortify"] = true
		}
	}
	if !hasSymtab {
		secFlags["stripped"] = true
	}

	audit := SOBinaryAudit{
		Name:               name,
		Arch:               arch,
		FileSize:           int64(len(raw)),
		Entropy:            round3(ShannonEntropy(raw)),
		Stripped:           !hasSymtab,
		SuspiciousSections: []string{},
		SecurityFlags:      secFlags,
	}

	var obfs []ObfuscationFinding
	var vmps []VMPFinding
	var antiDebugs []AntiDebugFinding

	var stats arm64InsnStats
	stats.svcSyscalls = make(map[uint64]uint16)

	var rodataData []byte
	var dataSectionData []byte
	hasText := false
	hasRWXSection := false
	suspSeen := make(map[string]bool)
	antiSeen := make(map[string]bool)

	addAntiDebug := func(f AntiDebugFinding) {
		key := f.Kind + "|" + f.Module + "|" + f.SymbolOrPattern + "|" + f.OffsetHex
		if antiSeen[key] {
			return
		}
		antiSeen[key] = true
		antiDebugs = append(antiDebugs, f)
	}

	type customSecInfo struct {
		name    string
		size    uint64
		entropy float64
		exec    bool
		rwx     bool
		vmpName bool
		data    []byte
	}
	var customSecs []customSecInfo

	for _, sec := range ef.Sections {
		if sec == nil || sec.Type == elf.SHT_NULL || sec.Type == elf.SHT_NOBITS || sec.Size == 0 {
			continue
		}
		secData, err := readSectionBounded(sec, maxScanSectionBytes)
		if err != nil || len(secData) == 0 {
			continue
		}

		ent := ShannonEntropy(secData)

		switch sec.Name {
		case ".text":
			hasText = true
			audit.TextEntropy = round3(ent)
		case ".rodata":
			audit.RodataEntropy = round3(ent)
			rodataData = secData
		case ".data":
			dataSectionData = secData
		case ".init_array", ".preinit_array":
			audit.InitArrayCount += int(sec.Size / ptrSize)
		}

		isExec := sec.Flags&elf.SHF_EXECINSTR != 0
		isWrite := sec.Flags&elf.SHF_WRITE != 0
		if isExec && isWrite {
			hasRWXSection = true
		}

		// Scan executable code sections for ARM64 / ARM32 instructions.
		// Skip high-entropy (>= 7.2) non-standard sections (typically encrypted
		// VMP bytecode or packed payloads) so random data does not skew
		// instruction-density OLLVM heuristics.
		if (isExec && (isStandardSection(sec.Name) || ent < 7.2)) || sec.Name == ".text" {
			baseAddr := sec.Addr
			if baseAddr == 0 {
				baseAddr = sec.Offset
			}
			switch ef.Machine {
			case elf.EM_AARCH64:
				scanARM64Instructions(secData, baseAddr, &stats)
			case elf.EM_ARM:
				scanARM32Instructions(secData, baseAddr, &stats)
			}
		}

		// Scan string-bearing or custom sections for anti-debug / anti-Frida indicators.
		if sec.Name == ".rodata" || sec.Name == ".data" || sec.Name == ".dynstr" ||
			sec.Name == ".text" || !isStandardSection(sec.Name) {
			baseOff := sec.Addr
			if baseOff == 0 {
				baseOff = sec.Offset
			}
			scanBytesForAntiDebug(name, secData, baseOff, addAntiDebug)
		}

		// Identify suspicious / custom sections.
		if !isStandardSection(sec.Name) {
			vmpNamed := isVMPSectionName(sec.Name)
			if vmpNamed || ent >= 6.8 || isExec || (isExec && isWrite) {
				if !suspSeen[sec.Name] {
					suspSeen[sec.Name] = true
					audit.SuspiciousSections = append(audit.SuspiciousSections, sec.Name)
				}
				customSecs = append(customSecs, customSecInfo{
					name:    sec.Name,
					size:    sec.Size,
					entropy: ent,
					exec:    isExec,
					rwx:     isExec && isWrite,
					vmpName: vmpNamed,
					data:    secData,
				})
			}
		}
	}

	audit.InlineSVCCount = len(stats.svcOffsets)
	audit.IndirectBranchCount = stats.brCount + stats.blrCount

	// 1. Check imported / dynamic symbols for anti-debug primitives.
	scanSymbolsForAntiDebug(name, importNames, symNames, addAntiDebug)

	// 2. Report inline SVC #0 hits with exact offsets & decoded ARM64 syscall numbers.
	if len(stats.svcOffsets) > 0 {
		limit := len(stats.svcOffsets)
		if limit > maxInlineSVCReports {
			limit = maxInlineSVCReports
		}
		for i := 0; i < limit; i++ {
			off := stats.svcOffsets[i]
			pattern := "SVC #0 (0xD4000001)"
			if ef.Machine == elf.EM_ARM {
				pattern = "SVC #0 (ARM)"
			}
			if nr, ok := stats.svcSyscalls[off]; ok {
				pattern = fmt.Sprintf("SVC #0 [%s / __NR_%d]", arm64SyscallName(nr), nr)
			}
			addAntiDebug(AntiDebugFinding{
				Kind:            AntiDebugInlineSVC,
				Module:          name,
				SymbolOrPattern: pattern,
				OffsetHex:       fmt.Sprintf("0x%x", off),
				Severity:        SeverityCritical,
				Countermeasure:  "Enable PatchInlineSVC in cap Stealth script (or use Frida Stalker / Unidbg offline emulation)",
			})
		}
	}

	// 3. Report hardware CNTVCT_EL0 timing counter reads.
	if len(stats.cntvctOffsets) > 0 {
		addAntiDebug(AntiDebugFinding{
			Kind:            AntiDebugTimingCheck,
			Module:          name,
			SymbolOrPattern: fmt.Sprintf("MRS Xt, CNTVCT_EL0 (%d site(s))", len(stats.cntvctOffsets)),
			OffsetHex:       fmt.Sprintf("0x%x", stats.cntvctOffsets[0]),
			Severity:        SeverityHigh,
			Countermeasure:  "NOP or patch CNTVCT_EL0 delta comparison, or emulate inside Unidbg",
		})
	}

	// 4. Watchdog thread correlation: pthread_create combined with other anti-debug signals.
	hasOtherAntiDebug := len(antiDebugs) > 0
	if (importNames["pthread_create"] || bytes.Contains(raw, []byte("pthread_create"))) && hasOtherAntiDebug {
		addAntiDebug(AntiDebugFinding{
			Kind:            AntiDebugWatchdogThread,
			Module:          name,
			SymbolOrPattern: "pthread_create (correlated with anti-debug signals)",
			Severity:        SeverityHigh,
			Countermeasure:  "Hook pthread_create via BypassPtraceAndSignals and block watchdog start_routine offsets",
		})
	}

	// 5. Obfuscation findings.
	if !hasText || len(ef.Sections) < 3 || hasRWXSection {
		var ev []string
		if !hasText {
			ev = append(ev, "Missing standard .text section header (possible section table tampering)")
		}
		if len(ef.Sections) < 3 {
			ev = append(ev, fmt.Sprintf("Only %d ELF section headers present", len(ef.Sections)))
		}
		if hasRWXSection {
			ev = append(ev, "Writable + executable (RWX) section detected (runtime self-modifying/unpacking code)")
		}
		obfs = append(obfs, ObfuscationFinding{
			Kind:        ObfSectionTampered,
			Module:      name,
			Confidence:  0.80,
			Entropy:     audit.Entropy,
			Evidence:    ev,
			Remediation: "Dump runtime memory image after linker/init_array unpacking with Frida or rebuild ELF headers with SoFixer",
		})
	}

	if audit.Stripped {
		obfs = append(obfs, ObfuscationFinding{
			Kind:        ObfSymbolStripped,
			Module:      name,
			Confidence:  0.90,
			Evidence:    []string{"No .symtab symbol table present; internal function symbols stripped"},
			Remediation: "Recover JNI bindings via RegisterNatives hook and recover signatures via radare2/Ghidra + DeepTrace",
		})
	}

	// Indirect branching (Hikari / OLLVM indirect branch / VMP computed goto).
	if stats.brCount >= 2 || audit.IndirectBranchCount >= 8 {
		conf := 0.55
		if stats.brCount >= 4 || audit.IndirectBranchCount >= 20 {
			conf = 0.82
		}
		if stats.brCount >= 12 || audit.IndirectBranchCount >= 60 {
			conf = 0.94
		}
		obfs = append(obfs, ObfuscationFinding{
			Kind:       ObfIndirectBranch,
			Module:     name,
			Confidence: conf,
			Entropy:    audit.TextEntropy,
			Evidence: []string{
				fmt.Sprintf("Detected %d BR Xn and %d BLR Xn indirect register branch instructions", stats.brCount, stats.blrCount),
			},
			Remediation: "Trace concrete branch targets with Frida Stalker or resolve target table statically via angr/IDAPython",
		})
	}

	// OLLVM Control Flow Flattening (CFF) heuristic.
	if stats.totalInsns >= 16 {
		cffSignals := 0
		var cffEv []string
		if stats.movzMovk32Count >= 3 && stats.bcondCount >= 3 {
			cffSignals++
			cffEv = append(cffEv, fmt.Sprintf("%d 32-bit state constant loads (MOVZ+MOVK) paired with %d conditional branches", stats.movzMovk32Count, stats.bcondCount))
		}
		if stats.cselCount >= 3 && stats.bcondCount >= 3 {
			cffSignals++
			cffEv = append(cffEv, fmt.Sprintf("%d CSEL/CSINC state-selection instructions alongside %d conditional branches", stats.cselCount, stats.bcondCount))
		}
		if stats.brCount >= 2 && (stats.movzMovk32Count >= 2 || stats.cselCount >= 2) {
			cffSignals++
			cffEv = append(cffEv, fmt.Sprintf("Computed branch dispatchers (%d BR Xn) co-occurring with state-variable updates", stats.brCount))
		}
		if cffSignals > 0 {
			conf := 0.55 + float64(cffSignals)*0.13
			if conf > 0.95 {
				conf = 0.95
			}
			obfs = append(obfs, ObfuscationFinding{
				Kind:        ObfOLLVMCFF,
				Module:      name,
				Confidence:  round3(conf),
				Entropy:     audit.TextEntropy,
				Evidence:    cffEv,
				Remediation: "Run cap's angr OLLVM Control Flow De-flattening script (GenerateOLLVMDeflattenScript) on target function address",
			})
		}

		// OLLVM Instruction Substitution (SUB) heuristic.
		if stats.logicOpCount >= 8 && stats.logicOpCount >= stats.arithOpCount*2 && float64(stats.logicOpCount)/float64(stats.totalInsns) >= 0.25 {
			obfs = append(obfs, ObfuscationFinding{
				Kind:       ObfOLLVMSUB,
				Module:     name,
				Confidence: 0.72,
				Entropy:    audit.TextEntropy,
				Evidence: []string{
					fmt.Sprintf("Abnormally high bitwise logic density (%d EOR/BIC/ORN/AND vs %d ADD/SUB across %d insns)", stats.logicOpCount, stats.arithOpCount, stats.totalInsns),
				},
				Remediation: "Simplify MBA / substituted expressions via angr/Triton symbolic simplification or Hex-Rays microcode optimizer",
			})
		}

		// OLLVM Bogus Control Flow (BCF) heuristic.
		if stats.bcondCount >= 8 && float64(stats.bcondCount)/float64(stats.totalInsns) >= 0.22 && stats.cselCount >= 2 {
			obfs = append(obfs, ObfuscationFinding{
				Kind:       ObfOLLVMBCF,
				Module:     name,
				Confidence: 0.68,
				Entropy:    audit.TextEntropy,
				Evidence: []string{
					fmt.Sprintf("High conditional branch density (%d B.cond in %d insns, %.1f%%) suggestive of opaque predicates", stats.bcondCount, stats.totalInsns, 100*float64(stats.bcondCount)/float64(stats.totalInsns)),
				},
				Remediation: "Prune dead opaque branches using angr/Qiling symbolic predicate evaluation or Binary Ninja/Ghidra dead-code elimination",
			})
		}
	}

	// String encryption heuristic (.rodata entropy + low printable ratio + .init_array constructors).
	roTarget := rodataData
	roLabel := ".rodata"
	if len(roTarget) == 0 && len(dataSectionData) > 0 {
		roTarget = dataSectionData
		roLabel = ".data"
	}
	if len(roTarget) >= 64 {
		roEnt := ShannonEntropy(roTarget)
		printRatio := printableRatio(roTarget)
		if (roEnt >= 6.0 && printRatio < 0.45) || (roEnt >= 5.5 && printRatio < 0.35 && audit.InitArrayCount >= 2) {
			conf := 0.70
			if roEnt >= 6.8 && printRatio < 0.30 {
				conf = 0.88
			}
			if audit.InitArrayCount >= 3 {
				conf = math.Min(0.95, conf+0.07)
			}
			obfs = append(obfs, ObfuscationFinding{
				Kind:       ObfStringEncryption,
				Module:     name,
				Confidence: round3(conf),
				Entropy:    round3(roEnt),
				Evidence: []string{
					fmt.Sprintf("%s entropy %.2f bits/byte with low printable ASCII ratio (%.1f%%)", roLabel, roEnt, printRatio*100),
					fmt.Sprintf("%d .init_array constructor(s) available for runtime string decryption", audit.InitArrayCount),
				},
				Remediation: "Emulate .init_array with cap's Qiling or Unidbg String Decryptor script to diff .data/.rodata and dump plaintext strings",
			})
		}
	}

	// 6. VMP Indicators (Native VMP & Dex2C).
	for _, cs := range customSecs {
		if cs.vmpName || cs.entropy >= 7.2 || cs.rwx {
			conf := 0.62
			if cs.vmpName {
				conf += 0.18
			}
			if cs.entropy >= 7.0 {
				conf += 0.12
			}
			if stats.brCount >= 2 {
				conf += 0.06
			}
			if conf > 0.98 {
				conf = 0.98
			}
			handlerEst := estimateHandlerTableSize(cs.size, stats.brCount, ptrSize)
			ev := []string{
				fmt.Sprintf("Suspicious section %s (%d bytes, entropy %.2f)", cs.name, cs.size, cs.entropy),
			}
			if stats.brCount > 0 {
				ev = append(ev, fmt.Sprintf("%d indirect BR Xn dispatchers present in executable code", stats.brCount))
			}
			if cs.rwx {
				ev = append(ev, "Section is marked RWX (writable + executable)")
			}
			vmps = append(vmps, VMPFinding{
				Kind:                 VMPNative,
				Module:               name,
				Section:              cs.name,
				Confidence:           round3(conf),
				HandlerTableEstimate: handlerEst,
				Entropy:              round3(cs.entropy),
				Evidence:             ev,
				Strategy:             "Hook RegisterNatives to find shared VMP dispatcher entries, record instruction trace via Frida Stalker or Unidbg, and run AnalyzeVMPTrace",
			})
		}
	}

	// Fallback Native VMP indicator if no custom section but very high BR Xn fan-out + high entropy.
	if len(vmps) == 0 && stats.brCount >= 16 && audit.Entropy >= 6.8 {
		vmps = append(vmps, VMPFinding{
			Kind:                 VMPNative,
			Module:               name,
			Section:              ".text",
			Confidence:           0.74,
			HandlerTableEstimate: stats.brCount,
			Entropy:              audit.Entropy,
			Evidence: []string{
				fmt.Sprintf("High indirect BR Xn count (%d) combined with elevated binary entropy (%.2f)", stats.brCount, audit.Entropy),
			},
			Strategy: "Trace runtime execution with Frida Stalker or Unidbg traceCode and feed trace into AnalyzeVMPTrace to isolate dispatcher loop",
		})
	}

	// Dex2C heuristic inside ELF.
	if jniExportCount >= 12 || (bytes.Contains(raw, []byte("dex2c")) || bytes.Contains(raw, []byte("Dex2C"))) {
		conf := 0.72
		var ev []string
		if bytes.Contains(raw, []byte("dex2c")) || bytes.Contains(raw, []byte("Dex2C")) {
			conf = 0.90
			ev = append(ev, "Explicit Dex2C marker string found in binary")
		}
		if jniExportCount >= 12 {
			ev = append(ev, fmt.Sprintf("%d Java_* JNI native exports detected (bulk Java-to-C lifting pattern)", jniExportCount))
		}
		vmps = append(vmps, VMPFinding{
			Kind:       VMPDex2C,
			Module:     name,
			Confidence: conf,
			Entropy:    audit.TextEntropy,
			Evidence:   ev,
			Strategy:   "Map JNI callbacks via RegisterNatives tracer and emulate target native functions directly in Unidbg",
		})
		obfs = append(obfs, ObfuscationFinding{
			Kind:        ObfDex2C,
			Module:      name,
			Confidence:  conf,
			Evidence:    ev,
			Remediation: "Use Unidbg JNI emulation or Frida RegisterNatives + native hooking to observe inputs/outputs without full decompilation",
		})
	}

	return audit, obfs, vmps, antiDebugs
}

func scanARM64Instructions(code []byte, baseAddr uint64, st *arm64InsnStats) {
	n := len(code) / 4
	st.totalInsns += n
	var lastMovzX8Val uint16
	var hasMovzX8 bool
	var lastMovzReg uint32 = 0xff
	var lastMovzIdx = -10

	for i := 0; i < n; i++ {
		off := uint64(i * 4)
		insn := binary.LittleEndian.Uint32(code[off : off+4])

		// MOVZ X8, #imm16 (Linux ARM64 syscall number setup: 0xD2800008 ..)
		// Encoding: sf=1, opc=10, 100101, hw=00, imm16, Rd=8 -> (insn & 0xFFE0001F) == 0xD2800008
		if (insn & 0xFFE0001F) == 0xD2800008 {
			lastMovzX8Val = uint16((insn >> 5) & 0xFFFF)
			hasMovzX8 = true
		} else if (insn & 0xFFE0001F) == 0x52800008 { // MOVZ W8, #imm16
			lastMovzX8Val = uint16((insn >> 5) & 0xFFFF)
			hasMovzX8 = true
		}

		// SVC #0 (0xD4000001) or SVC #imm16 ((insn & 0xFFE0001F) == 0xD4000001)
		if (insn & 0xFFE0001F) == 0xD4000001 {
			vaddr := baseAddr + off
			st.svcOffsets = append(st.svcOffsets, vaddr)
			if hasMovzX8 {
				st.svcSyscalls[vaddr] = lastMovzX8Val
			}
			hasMovzX8 = false
			continue
		}

		// BR Xn: (insn & 0xFFFFFC1F) == 0xD61F0000
		if (insn & 0xFFFFFC1F) == 0xD61F0000 {
			st.brCount++
			hasMovzX8 = false
			continue
		}

		// BLR Xn: (insn & 0xFFFFFC1F) == 0xD63F0000
		if (insn & 0xFFFFFC1F) == 0xD63F0000 {
			st.blrCount++
			hasMovzX8 = false
			continue
		}

		// MRS Xt, CNTVCT_EL0: 0xD53BE040 | Rt
		if (insn & 0xFFFFFFE0) == 0xD53BE040 {
			st.cntvctOffsets = append(st.cntvctOffsets, baseAddr+off)
		}

		// MOVZ Wd/Xd followed shortly by MOVK to same register (32-bit state constant load in OLLVM CFF)
		if (insn & 0x7F800000) == 0x52800000 { // MOVZ
			lastMovzReg = insn & 0x1F
			lastMovzIdx = i
		} else if (insn&0x7F800000) == 0x72800000 && (insn&0x1F) == lastMovzReg && i-lastMovzIdx <= 4 { // MOVK
			st.movzMovk32Count++
			lastMovzReg = 0xff
		}

		// CSEL / CSINC / CSINV / CSNEG: (insn & 0x7FE00C00) == 0x1A800000
		if (insn & 0x7FE00C00) == 0x1A800000 {
			st.cselCount++
		}

		// B.cond: (insn & 0xFF000010) == 0x54000000, or CBZ/CBNZ: (insn & 0x7E000000) == 0x34000000
		if (insn&0xFF000010) == 0x54000000 || (insn&0x7E000000) == 0x34000000 {
			st.bcondCount++
		}

		// Bitwise logic (AND/ORR/EOR/BIC/ORN/EON shifted register): (insn & 0x1F000000) == 0x0A000000
		if (insn & 0x1F000000) == 0x0A000000 {
			st.logicOpCount++
		}
		// Add/Sub shifted register or immediate: (insn & 0x1F000000) == 0x0B000000 || 0x11000000
		if (insn&0x1F000000) == 0x0B000000 || (insn&0x1F000000) == 0x11000000 {
			st.arithOpCount++
		}
	}
}

func scanARM32Instructions(code []byte, baseAddr uint64, st *arm64InsnStats) {
	n := len(code) / 4
	st.totalInsns += n
	for i := 0; i < n; i++ {
		off := uint64(i * 4)
		insn := binary.LittleEndian.Uint32(code[off : off+4])
		// ARM32 SVC #0: 0xEF000000 (cond=AL 0xE, op=0xF, imm24=0)
		if insn == 0xEF000000 {
			st.svcOffsets = append(st.svcOffsets, baseAddr+off)
		}
		// BX Rn (excluding BX LR 0xE12FFF1E which is standard function return)
		if (insn&0x0FFFFFF0) == 0x012FFF10 && (insn&0xF) != 14 {
			st.brCount++
		}
		// BLX Rn
		if (insn & 0x0FFFFFF0) == 0x012FFF30 {
			st.blrCount++
		}
	}
}

func arm64SyscallName(nr uint16) string {
	switch nr {
	case 26:
		return "inotify_init1"
	case 27:
		return "inotify_add_watch"
	case 48:
		return "faccessat"
	case 56:
		return "openat"
	case 57:
		return "close"
	case 63:
		return "read"
	case 78:
		return "readlinkat"
	case 93:
		return "exit"
	case 94:
		return "exit_group"
	case 113:
		return "clock_gettime"
	case 117:
		return "ptrace"
	case 129:
		return "kill"
	case 131:
		return "tgkill"
	case 167:
		return "prctl"
	case 169:
		return "gettimeofday"
	case 172:
		return "getpid"
	case 178:
		return "gettid"
	case 203:
		return "connect"
	case 222:
		return "mmap"
	case 226:
		return "mprotect"
	default:
		return fmt.Sprintf("sys_%d", nr)
	}
}

type antiDebugSig struct {
	kind           string
	pattern        string
	severity       string
	countermeasure string
}

var nativeAntiDebugStringSigs = []antiDebugSig{
	{AntiDebugTracerPid, "TracerPid", SeverityHigh, "Enable BypassTracerPidAndProcFS to rewrite TracerPid: 0 in /proc/self/status"},
	{AntiDebugTracerPid, "/proc/self/status", SeverityHigh, "Enable BypassTracerPidAndProcFS to cloak /proc/self/status reads"},
	{AntiDebugTracerPid, "/proc/%d/status", SeverityHigh, "Enable BypassTracerPidAndProcFS to cloak /proc/<pid>/status reads"},
	{AntiDebugTracerPid, "/proc/self/task", SeverityMedium, "Hook opendir/openat for /proc/self/task thread inspection"},
	{AntiDebugProcMaps, "/proc/self/maps", SeverityHigh, "Enable BypassTracerPidAndProcFS to filter frida/magisk lines from /proc/self/maps"},
	{AntiDebugProcMaps, "/proc/%d/maps", SeverityHigh, "Enable BypassTracerPidAndProcFS to filter /proc/<pid>/maps reads"},
	{AntiDebugProcMaps, "/proc/self/smaps", SeverityMedium, "Enable BypassTracerPidAndProcFS to sanitize /proc/self/smaps"},
	{AntiDebugProcMaps, "/proc/self/fd", SeverityMedium, "Hook readlinkat in BypassTracerPidAndProcFS to cloak suspicious fds"},
	{AntiDebugProcMaps, "/proc/net/tcp", SeverityMedium, "Spoof /proc/net/tcp or run frida-server on a non-default port"},
	{AntiDebugPtrace, "PTRACE_TRACEME", SeverityHigh, "Enable BypassPtraceAndSignals to return 0 from ptrace(PTRACE_TRACEME)"},
	{AntiDebugPtrace, "ptrace", SeverityHigh, "Enable BypassPtraceAndSignals to intercept libc ptrace calls"},
	{AntiDebugFridaDetect, "gum-js-loop", SeverityCritical, "Enable BypassTracerPidAndProcFS and use stealth/hluda frida-server build"},
	{AntiDebugFridaDetect, "frida-agent", SeverityCritical, "Enable BypassTracerPidAndProcFS and rename frida artifacts"},
	{AntiDebugFridaDetect, "frida-server", SeverityHigh, "Deploy frida-server with stealth binary name (cap frida deploy --name)"},
	{AntiDebugFridaDetect, "re.frida.server", SeverityHigh, "Deploy frida-server with custom stealth binary name"},
	{AntiDebugFridaDetect, "LIBFRIDA", SeverityCritical, "Filter LIBFRIDA string/maps scans via BypassTracerPidAndProcFS"},
	{AntiDebugFridaDetect, "linjector", SeverityHigh, "Enable BypassTracerPidAndProcFS to strip linjector references"},
	{AntiDebugFridaDetect, "frida", SeverityMedium, "Cloak frida strings in strstr/openat/maps via BypassTracerPidAndProcFS"},
	{AntiDebugFridaDetect, "27042", SeverityMedium, "Run frida-server on a custom port (-l 127.0.0.1:<port>) instead of 27042"},
	{AntiDebugInotify, "inotify_add_watch", SeverityHigh, "Enable BypassTimingAndInotify to neutralize /proc inotify monitors"},
	{AntiDebugInotify, "inotify_init", SeverityMedium, "Enable BypassTimingAndInotify to intercept inotify initialization"},
	{AntiDebugTimingCheck, "clock_gettime", SeverityMedium, "Enable BypassTimingAndInotify to clamp abnormal time deltas"},
	{AntiDebugTimingCheck, "gettimeofday", SeverityLow, "Enable BypassTimingAndInotify to smooth gettimeofday timing checks"},
	{AntiDebugWatchdogThread, "tgkill", SeverityHigh, "Enable BypassPtraceAndSignals to intercept self-kill tgkill signals with backtrace"},
	{AntiDebugRootDetect, "/system/bin/su", SeverityMedium, "Enable Anti-Root stealth hooks (File.exists / openat / access)"},
	{AntiDebugRootDetect, "/system/xbin/su", SeverityMedium, "Enable Anti-Root stealth hooks (File.exists / openat / access)"},
	{AntiDebugRootDetect, "magisk", SeverityMedium, "Use Magisk DenyList / Shamiko + cap stealth maps cloaking"},
	{AntiDebugRootDetect, "zygisk", SeverityMedium, "Cloak zygisk mappings via BypassTracerPidAndProcFS"},
}

func scanBytesForAntiDebug(module string, data []byte, baseAddr uint64, emit func(AntiDebugFinding)) {
	for _, sig := range nativeAntiDebugStringSigs {
		needle := []byte(sig.pattern)
		idx := bytes.Index(data, needle)
		if idx < 0 {
			continue
		}
		// Guard against overly short false positives for generic "frida" or "ptrace" inside binary noise:
		// verify at least one boundary is non-alphanumeric or start/end of buffer.
		if (sig.pattern == "frida" || sig.pattern == "ptrace" || sig.pattern == "27042" || sig.pattern == "tgkill") &&
			!hasCleanTokenBoundary(data, idx, len(needle)) {
			continue
		}
		emit(AntiDebugFinding{
			Kind:            sig.kind,
			Module:          module,
			SymbolOrPattern: sig.pattern,
			OffsetHex:       fmt.Sprintf("0x%x", baseAddr+uint64(idx)),
			Severity:        sig.severity,
			Countermeasure:  sig.countermeasure,
		})
	}
}

func hasCleanTokenBoundary(data []byte, idx, n int) bool {
	isWord := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
	}
	leftOK := idx == 0 || !isWord(data[idx-1])
	rightOK := idx+n >= len(data) || !isWord(data[idx+n])
	return leftOK && rightOK
}

func scanSymbolsForAntiDebug(module string, imports map[string]bool, defined map[string]uint64, emit func(AntiDebugFinding)) {
	checkSym := func(sym, kind, sev, counter string) {
		if imports[sym] {
			emit(AntiDebugFinding{
				Kind:            kind,
				Module:          module,
				SymbolOrPattern: "import:" + sym,
				Severity:        sev,
				Countermeasure:  counter,
			})
		} else if addr, ok := defined[sym]; ok {
			off := ""
			if addr > 0 {
				off = fmt.Sprintf("0x%x", addr)
			}
			emit(AntiDebugFinding{
				Kind:            kind,
				Module:          module,
				SymbolOrPattern: "sym:" + sym,
				OffsetHex:       off,
				Severity:        sev,
				Countermeasure:  counter,
			})
		}
	}

	checkSym("ptrace", AntiDebugPtrace, SeverityHigh, "Enable BypassPtraceAndSignals to stub ptrace(PTRACE_TRACEME) -> 0")
	checkSym("prctl", AntiDebugPtrace, SeverityMedium, "Hook prctl to ignore PR_SET_DUMPABLE(0) / seccomp restrictions")
	checkSym("inotify_add_watch", AntiDebugInotify, SeverityHigh, "Enable BypassTimingAndInotify to block /proc inotify watches")
	checkSym("inotify_init", AntiDebugInotify, SeverityMedium, "Enable BypassTimingAndInotify to intercept inotify initialization")
	checkSym("inotify_init1", AntiDebugInotify, SeverityMedium, "Enable BypassTimingAndInotify to intercept inotify initialization")
	checkSym("tgkill", AntiDebugWatchdogThread, SeverityHigh, "Enable BypassPtraceAndSignals to log backtrace and block self-termination")
	checkSym("clock_gettime", AntiDebugTimingCheck, SeverityLow, "Enable BypassTimingAndInotify if anti-single-step timing triggers")
}

func printableRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	printable := 0
	for _, b := range data {
		if (b >= 0x20 && b <= 0x7e) || b == 0 || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable) / float64(len(data))
}

func estimateHandlerTableSize(secSize uint64, brCount int, ptrSize uint64) int {
	est := brCount
	if secSize > 0 && ptrSize > 0 {
		// Conservative heuristic: ~1-5% of a VMP section comprises a pointer/offset dispatch table.
		secEst := int((secSize / 64) / ptrSize)
		if secEst > est {
			est = secEst
		}
	}
	if est < 1 && secSize > 0 {
		est = 1
	}
	if est > 512 {
		est = 512
	}
	return est
}

func readSectionBounded(sec *elf.Section, limit int64) ([]byte, error) {
	r := sec.Open()
	if r == nil {
		return nil, fmt.Errorf("section %s unreadable", sec.Name)
	}
	return io.ReadAll(io.LimitReader(r, limit))
}

// ─── APK Packer & DEX Inspection ──────────────────────────────────────────────

type packerRule struct {
	name           string
	vendor         string
	pathPatterns   []string // lowercase substring match against APK zip entry path
	dexMarkers     []string // substring match against DEX strings
	unpackStrategy string
}

var packerRules = []packerRule{
	{
		name:           "360 Jiagu (360加固保)",
		vendor:         "Qihoo 360",
		pathPatterns:   []string{"libjiagu", "assets/.appkey", "assets/libjiagu"},
		dexMarkers:     []string{"com.stub.StubApp", "com.qihoo.util"},
		unpackStrategy: "Attach Frida with BypassTracerPidAndProcFS + PatchInlineSVC and dump decrypted DEX from libart.so OpenMemory / memory scan after StubApp.attachBaseContext",
	},
	{
		name:           "Tencent Legu (腾讯乐固)",
		vendor:         "Tencent",
		pathPatterns:   []string{"libshella-", "libshellx-", "libtup.so", "libtx_shell", "libtosprotection", "assets/tosversion", "assets/0oo00l111l1l", "assets/mix.dex"},
		dexMarkers:     []string{"com.tencent.StubShell.TxAppEntry", "com.tencent.bugly.legu"},
		unpackStrategy: "Bypass anti-Frida/ptrace checks in libshell*, then run cap DEX Unpacker hooking DexFile::OpenCommon or use FART/Youpk ART dumper",
	},
	{
		name:           "Bangcle / SecNeo (梆梆加固)",
		vendor:         "Bangcle / SecNeo",
		pathPatterns:   []string{"libsecexe.so", "libsecmain.so", "libsecshell", "libdexhelper", "assets/secdata0.jar", "assets/bangcle"},
		dexMarkers:     []string{"com.secneo.apkwrapper", "com.bangcle.everisk"},
		unpackStrategy: "Hook libSecShell/libDexHelper with anti-ptrace + maps cloaking enabled; dump unpacked DEX via OpenMemory and trace native VMP entries if present",
	},
	{
		name:           "Ijiami (爱加密)",
		vendor:         "Ijiami",
		pathPatterns:   []string{"ijiami.dat", "ijiami.ajm", "assets/af.bin", "assets/signed.bin", "assets/ijm_lib", "libijmdalvik", "libexecmain.so"},
		dexMarkers:     []string{"s.h.e.l.l.S", "com.shell.SuperApplication"},
		unpackStrategy: "Apply stealth maps/TracerPid bypass + inline SVC patching; dump DEX post-initialization and inspect method code_item extraction (FART)",
	},
	{
		name:           "Baidu Protect (百度加固)",
		vendor:         "Baidu",
		pathPatterns:   []string{"libbaiduprotect", "assets/baiduprotect"},
		dexMarkers:     []string{"com.baidu.protect"},
		unpackStrategy: "Use cap DEX Unpacker after Baidu StubApplication loads, paired with BypassPtraceAndSignals",
	},
	{
		name:           "Naga (娜迦加固)",
		vendor:         "Naga",
		pathPatterns:   []string{"libddog.so", "libfdog.so", "libedog.so", "libchaosvmp.so", "libvdog.so"},
		dexMarkers:     []string{"com.naga."},
		unpackStrategy: "Bypass native watchdog threads in lib*dog.so; for libchaosvmp.so combine DEX dump with RegisterNatives + VMP Stalker/Unidbg tracing",
	},
	{
		name:           "Alibaba SecurityGuard / Jaq (阿里聚安全)",
		vendor:         "Alibaba",
		pathPatterns:   []string{"libsgmain", "libsgsecuritybody", "libmobisec", "libdemolish", "assets/yw_1222"},
		dexMarkers:     []string{"com.ali.mobisecenhance", "com.alibaba.wireless.security"},
		unpackStrategy: "For mobisec shell dump DEX via ART hooks; for libsgmain signing algorithms prefer Unidbg offline emulation with APK + yw_1222 resource image",
	},
	{
		name:           "Dingxiang (顶象加固)",
		vendor:         "Dingxiang",
		pathPatterns:   []string{"libx3g.so", "libdxbase.so", "libdx_vmp.so", "libdxsafe.so", "assets/dx_"},
		dexMarkers:     []string{"com.dingxiang.", "com.dx.mobile"},
		unpackStrategy: "Enable full Frida stealth (TracerPid + inline SVC + inotify) and use Unidbg/Stalker for libdx_vmp native VMP dispatchers",
	},
	{
		name:           "NetEase Yidun (网易易盾)",
		vendor:         "NetEase",
		pathPatterns:   []string{"libnesec.so", "libyd_vmp.so"},
		dexMarkers:     []string{"com.netease.nis.wrapper"},
		unpackStrategy: "Disable ptrace/maps anti-debug in libnesec.so; dump DEX via ART OpenCommon and trace Yidun VMP via RegisterNatives + Unidbg",
	},
	{
		name:           "DexGuard",
		vendor:         "Guardsquare",
		pathPatterns:   []string{"libdexguard", "assets/dexguard"},
		dexMarkers:     []string{"com.guardsquare.dexguard", "o.dexguard"},
		unpackStrategy: "Combine Frida Java Deobfuscator (Class.forName / reflection / String.<init>) with memory DEX dumper and native string-decryption emulation",
	},
	{
		name:           "DexProtector",
		vendor:         "Licel",
		pathPatterns:   []string{"libdexprotector", "assets/dp.arm", "assets/dexprotector"},
		dexMarkers:     []string{"com.licel.dexprotector"},
		unpackStrategy: "Hook ClassLoader/InMemoryDexClassLoader and reflection decryptors with cap Java Deobfuscator + DEX Unpacker",
	},
	{
		name:           "Promon SHIELD",
		vendor:         "Promon",
		pathPatterns:   []string{"libshield.so", "libpromon.so", "assets/shield_"},
		dexMarkers:     []string{"no.promon.shield"},
		unpackStrategy: "Requires early spawn-time stealth (TracerPid + inline SVC + inotify + Java debug bypass) or offline Unidbg emulation of target logic",
	},
	{
		name:           "Kiwisec (几维安全)",
		vendor:         "Kiwisec",
		pathPatterns:   []string{"libkwscmm.so", "libkwsgmain.so", "libkdp.so"},
		dexMarkers:     []string{"com.kiwisec."},
		unpackStrategy: "Run DEX Unpacker for protected DEX layers and angr/Unidbg against OLLVM-hardened native libraries",
	},
}

func matchPackersFromEntries(entries []string, dexStrings map[string]bool) []PackerFinding {
	var out []PackerFinding
	for _, rule := range packerRules {
		var evidence []string
		evSeen := make(map[string]bool)
		addEv := func(s string) {
			if !evSeen[s] {
				evSeen[s] = true
				evidence = append(evidence, s)
			}
		}

		pathHits := 0
		for _, entry := range entries {
			low := strings.ToLower(entry)
			for _, pat := range rule.pathPatterns {
				if strings.Contains(low, pat) {
					addEv("APK entry: " + entry)
					pathHits++
					break
				}
			}
		}

		dexHits := 0
		for _, marker := range rule.dexMarkers {
			for ds := range dexStrings {
				if strings.Contains(ds, marker) {
					addEv("DEX marker: " + marker)
					dexHits++
					break
				}
			}
		}

		if len(evidence) == 0 {
			continue
		}
		conf := 0.65
		if pathHits >= 1 && dexHits >= 1 {
			conf = 0.96
		} else if pathHits >= 2 {
			conf = 0.92
		} else if pathHits == 1 {
			conf = 0.84
		} else if dexHits >= 1 {
			conf = 0.78
		}
		sort.Strings(evidence)
		out = append(out, PackerFinding{
			Name:           rule.name,
			Vendor:         rule.vendor,
			Confidence:     conf,
			Evidence:       evidence,
			UnpackStrategy: rule.unpackStrategy,
		})
	}
	return out
}

func inspectDexBuffer(dexName string, data []byte) (map[string]bool, []ObfuscationFinding, []VMPFinding, []AntiDebugFinding) {
	foundMarkers := make(map[string]bool)
	var obfs []ObfuscationFinding
	var vmps []VMPFinding
	var antiDebugs []AntiDebugFinding

	// Quick validation of DEX magic & header.
	if len(data) < 112 || string(data[:4]) != "dex\n" {
		ent := ShannonEntropy(data)
		if ent >= 7.0 {
			obfs = append(obfs, ObfuscationFinding{
				Kind:        ObfSectionTampered,
				Module:      dexName,
				Confidence:  0.85,
				Entropy:     round3(ent),
				Evidence:    []string{fmt.Sprintf("%s has invalid DEX magic and high entropy (%.2f) — likely encrypted/packed", dexName, ent)},
				Remediation: "Dump runtime decrypted DEX using cap's Frida DEX Unpacker",
			})
		}
		return foundMarkers, obfs, vmps, antiDebugs
	}

	// Scan raw DEX bytes for packer markers and Java anti-debug / root strings.
	for _, rule := range packerRules {
		for _, m := range rule.dexMarkers {
			slashForm := strings.ReplaceAll(m, ".", "/")
			if bytes.Contains(data, []byte(m)) || bytes.Contains(data, []byte(slashForm)) {
				foundMarkers[m] = true
			}
		}
	}

	javaAntiSigs := []antiDebugSig{
		{AntiDebugJavaDebug, "isDebuggerConnected", SeverityMedium, "Enable BypassJavaDebugChecks to hook android.os.Debug.isDebuggerConnected -> false"},
		{AntiDebugJavaDebug, "waitingForDebugger", SeverityMedium, "Enable BypassJavaDebugChecks to hook android.os.Debug.waitingForDebugger -> false"},
		{AntiDebugJavaDebug, "adb_enabled", SeverityLow, "Enable BypassJavaDebugChecks to spoof Settings.Global/Secure adb_enabled -> 0"},
		{AntiDebugJavaDebug, "development_settings_enabled", SeverityLow, "Enable BypassJavaDebugChecks to spoof development_settings_enabled -> 0"},
		{AntiDebugRootDetect, "com.topjohnwu.magisk", SeverityMedium, "Hide root packages via PackageManager.getPackageInfo hook"},
		{AntiDebugRootDetect, "de.robv.android.xposed", SeverityMedium, "Hide Xposed/LSPosed framework packages via PackageManager hook"},
		{AntiDebugFridaDetect, "frida-server", SeverityHigh, "Deploy stealth-named frida-server and hook File.exists / openat"},
	}
	for _, sig := range javaAntiSigs {
		if idx := bytes.Index(data, []byte(sig.pattern)); idx >= 0 {
			antiDebugs = append(antiDebugs, AntiDebugFinding{
				Kind:            sig.kind,
				Module:          dexName,
				SymbolOrPattern: sig.pattern,
				OffsetHex:       fmt.Sprintf("0x%x", idx),
				Severity:        sig.severity,
				Countermeasure:  sig.countermeasure,
			})
		}
	}

	// Parse DEX string_ids & type_ids tables lightly to measure ProGuard/R8 short-name obfuscation.
	strSize := binary.LittleEndian.Uint32(data[0x38:0x3c])
	strOff := binary.LittleEndian.Uint32(data[0x3c:0x40])
	typeSize := binary.LittleEndian.Uint32(data[0x40:0x44])
	typeOff := binary.LittleEndian.Uint32(data[0x44:0x48])

	if uint64(strOff)+uint64(strSize)*4 <= uint64(len(data)) &&
		uint64(typeOff)+uint64(typeSize)*4 <= uint64(len(data)) && typeSize > 0 {
		totalAppClasses := 0
		obfClasses := 0
		maxInspect := typeSize
		if maxInspect > 8000 {
			maxInspect = 8000
		}
		for i := uint32(0); i < maxInspect; i++ {
			strIdx := binary.LittleEndian.Uint32(data[int(typeOff)+int(i)*4 : int(typeOff)+int(i)*4+4])
			if strIdx >= strSize {
				continue
			}
			s := readDexStringAt(data, strOff, strIdx)
			if !strings.HasPrefix(s, "L") || !strings.HasSuffix(s, ";") {
				continue
			}
			inner := s[1 : len(s)-1]
			if strings.HasPrefix(inner, "java/") || strings.HasPrefix(inner, "javax/") ||
				strings.HasPrefix(inner, "android/") || strings.HasPrefix(inner, "androidx/") ||
				strings.HasPrefix(inner, "kotlin/") || strings.HasPrefix(inner, "dalvik/") {
				continue
			}
			totalAppClasses++
			if isShortObfuscatedDescriptor(inner) {
				obfClasses++
			}
		}

		if totalAppClasses >= 4 && float64(obfClasses)/float64(totalAppClasses) >= 0.45 {
			ratio := float64(obfClasses) / float64(totalAppClasses)
			obfs = append(obfs, ObfuscationFinding{
				Kind:       ObfDexProguard,
				Module:     dexName,
				Confidence: round3(math.Min(0.95, 0.55+ratio*0.4)),
				Evidence: []string{
					fmt.Sprintf("%d/%d (%.0f%%) app class descriptors use short obfuscated names (ProGuard/R8/DexGuard)", obfClasses, totalAppClasses, ratio*100),
				},
				Remediation: "Use runtime Frida Java Deobfuscator & DeepTrace string/API cross-referencing to map obfuscated classes back to network/crypto call sites",
			})
		}
	}

	// Check DEX-VMP / Dex2C strings inside DEX.
	if bytes.Contains(data, []byte("vmEntry")) || bytes.Contains(data, []byte("chaosvmp")) || bytes.Contains(data, []byte("dvm_exec")) {
		vmps = append(vmps, VMPFinding{
			Kind:       VMPDex,
			Module:     dexName,
			Confidence: 0.78,
			Evidence:   []string{"DEX contains VM interpreter bridge markers (vmEntry / chaosvmp / dvm_exec)"},
			Strategy:   "Hook RegisterNatives to map virtualized Java methods to their shared native VMP dispatcher",
		})
	}

	return foundMarkers, obfs, vmps, antiDebugs
}

func readDexStringAt(data []byte, strIDsOff, idx uint32) string {
	pos := int(strIDsOff) + int(idx)*4
	if pos+4 > len(data) {
		return ""
	}
	off := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	if off <= 0 || off >= len(data) {
		return ""
	}
	// Skip ULEB128 utf16_size prefix.
	for i := 0; i < 5 && off < len(data); i++ {
		b := data[off]
		off++
		if b&0x80 == 0 {
			break
		}
	}
	end := off
	limit := off + 256
	if limit > len(data) {
		limit = len(data)
	}
	for end < limit && data[end] != 0 {
		end++
	}
	return string(data[off:end])
}

func isShortObfuscatedDescriptor(inner string) bool {
	parts := strings.Split(inner, "/")
	if len(parts) == 0 {
		return false
	}
	cls := parts[len(parts)-1]
	if idx := strings.IndexByte(cls, '$'); idx > 0 {
		cls = cls[:idx]
	}
	if len(cls) <= 2 && len(cls) > 0 {
		return true
	}
	// Classic o0O1lI confusing identifier obfuscation (DexGuard / Allatori)
	if len(cls) >= 4 {
		confusing := 0
		for i := 0; i < len(cls); i++ {
			switch cls[i] {
			case 'O', 'o', '0', 'I', 'l', '1':
				confusing++
			}
		}
		if confusing == len(cls) {
			return true
		}
	}
	return false
}

func selectAPKSOs(files []*zip.File, limit int) []*zip.File {
	type cand struct {
		f    *zip.File
		rank int
		prio int
		base string
	}
	best := make(map[string]cand)
	for _, f := range files {
		slash := filepath.ToSlash(f.Name)
		rest := strings.TrimPrefix(slash, "lib/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			continue
		}
		abi, base := parts[0], parts[1]
		rank := soABIRank(abi)
		prio := soSecurityPriority(base)
		cur, exists := best[base]
		if !exists || rank > cur.rank || (rank == cur.rank && f.Name < cur.f.Name) {
			best[base] = cand{f: f, rank: rank, prio: prio, base: base}
		}
	}
	list := make([]cand, 0, len(best))
	for _, c := range best {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].prio != list[j].prio {
			return list[i].prio > list[j].prio
		}
		return list[i].base < list[j].base
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	out := make([]*zip.File, len(list))
	for i, c := range list {
		out[i] = c.f
	}
	return out
}

func soABIRank(abi string) int {
	switch strings.ToLower(abi) {
	case "arm64-v8a":
		return 5
	case "armeabi-v7a":
		return 4
	case "armeabi":
		return 3
	case "x86_64":
		return 2
	case "x86":
		return 1
	default:
		return 0
	}
}

func soSecurityPriority(base string) int {
	low := strings.ToLower(base)
	for _, rule := range packerRules {
		for _, pat := range rule.pathPatterns {
			if strings.Contains(low, strings.TrimPrefix(pat, "assets/")) {
				return 100
			}
		}
	}
	for _, kw := range []string{"vmp", "sec", "guard", "shield", "sign", "crypt", "enc", "protect", "dex", "jiagu", "shell"} {
		if strings.Contains(low, kw) {
			return 60
		}
	}
	return 10
}

func readZipBounded(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limit))
}

// ─── Scoring, Hardening Classification & Recommendations ─────────────────────

func finalizeReport(r *ProtectionReport) {
	score := 0

	// Packers
	if len(r.Packers) > 0 {
		score += 30 + min((len(r.Packers)-1)*10, 15)
	}

	// VMP / Dex2C
	vmpScore := 0
	for _, v := range r.VMPIndicators {
		if v.Kind == VMPNative || v.Kind == VMPDex {
			vmpScore += 22
		} else {
			vmpScore += 14
		}
	}
	score += min(vmpScore, 30)

	// Obfuscation
	obfScore := 0
	seenObfKind := make(map[string]bool)
	for _, o := range r.Obfuscation {
		if seenObfKind[o.Kind] {
			obfScore += 2
			continue
		}
		seenObfKind[o.Kind] = true
		switch o.Kind {
		case ObfOLLVMCFF, ObfOLLVMBCF, ObfOLLVMSUB, ObfIndirectBranch:
			obfScore += 10
		case ObfStringEncryption, ObfDex2C, ObfSectionTampered:
			obfScore += 8
		case ObfDexProguard, ObfSymbolStripped:
			obfScore += 4
		default:
			obfScore += 5
		}
	}
	score += min(obfScore, 30)

	// Anti-debug
	adScore := 0
	seenADKind := make(map[string]bool)
	for _, ad := range r.AntiDebugFindings {
		first := !seenADKind[ad.Kind]
		seenADKind[ad.Kind] = true
		switch ad.Severity {
		case SeverityCritical:
			if first {
				adScore += 12
			} else {
				adScore += 2
			}
		case SeverityHigh:
			if first {
				adScore += 8
			} else {
				adScore += 1
			}
		case SeverityMedium:
			if first {
				adScore += 4
			}
		default:
			if first {
				adScore += 2
			}
		}
	}
	score += min(adScore, 35)

	if score > 100 {
		score = 100
	}
	r.RiskScore = score

	switch {
	case score >= 80:
		r.HardeningLevel = HardeningExtreme
	case score >= 55:
		r.HardeningLevel = HardeningHigh
	case score >= 30:
		r.HardeningLevel = HardeningMedium
	case score >= 10:
		r.HardeningLevel = HardeningLow
	default:
		r.HardeningLevel = HardeningNone
	}

	// Build tailored, deduplicated recommendations.
	recSeen := make(map[string]bool)
	addRec := func(s string) {
		if s != "" && !recSeen[s] {
			recSeen[s] = true
			r.Recommendations = append(r.Recommendations, s)
		}
	}

	for _, p := range r.Packers {
		addRec(fmt.Sprintf("[%s] %s", p.Name, p.UnpackStrategy))
	}
	if seenADKind[AntiDebugInlineSVC] {
		addRec("Inline ARM64 SVC #0 syscalls detected — enable PatchInlineSVC in GenerateStealthScript or bypass anti-debug entirely with Unidbg offline emulation")
	}
	if seenADKind[AntiDebugTracerPid] || seenADKind[AntiDebugProcMaps] || seenADKind[AntiDebugFridaDetect] || seenADKind[AntiDebugPtrace] {
		addRec("Deploy cap Anti-Debug/Anti-Frida Stealth script (BypassTracerPidAndProcFS + BypassPtraceAndSignals) and use a stealth-renamed frida-server on a custom port")
	}
	if seenADKind[AntiDebugTimingCheck] || seenADKind[AntiDebugInotify] {
		addRec("Enable BypassTimingAndInotify to neutralize /proc inotify watchers and clock_gettime/CNTVCT_EL0 anti-single-step checks")
	}
	if seenADKind[AntiDebugJavaDebug] {
		addRec("Enable BypassJavaDebugChecks to spoof android.os.Debug and Settings adb_enabled flags")
	}
	if seenObfKind[ObfOLLVMCFF] || seenObfKind[ObfIndirectBranch] {
		addRec("Use GenerateOLLVMDeflattenScript (angr) to recover flattened CFG edges and patch dispatcher jump tables")
	}
	if seenObfKind[ObfStringEncryption] {
		addRec("Run GenerateStringDecryptScript (Qiling or Unidbg) to execute .init_array and diff .rodata/.data for plaintext strings")
	}
	if seenObfKind[ObfDexProguard] {
		addRec("Attach GenerateJavaDeobfScript to trace dynamic Class.forName / reflection / Base64 / String.<init> decryption at runtime")
	}
	if len(r.VMPIndicators) > 0 {
		addRec("VMP/Dex2C detected — run GenerateVMPRegisterNativesScript to locate shared dispatcher entries, trace via Frida Stalker or Unidbg, and analyze with AnalyzeVMPTrace")
	}
	if len(r.Recommendations) == 0 {
		addRec("No heavy hardening detected — standard DeepTrace static analysis and Frida hooks can be applied directly")
	}

	// Executive summary line.
	var parts []string
	parts = append(parts, fmt.Sprintf("Hardening: %s (risk %d/100)", strings.ToUpper(r.HardeningLevel), r.RiskScore))
	if len(r.Packers) > 0 {
		names := make([]string, 0, len(r.Packers))
		for _, p := range r.Packers {
			names = append(names, p.Name)
		}
		parts = append(parts, "Packers: "+strings.Join(names, ", "))
	}
	if len(r.VMPIndicators) > 0 {
		parts = append(parts, fmt.Sprintf("VMP/Dex2C: %d indicator(s)", len(r.VMPIndicators)))
	}
	if len(r.Obfuscation) > 0 {
		parts = append(parts, fmt.Sprintf("Obfuscation: %d finding(s)", len(r.Obfuscation)))
	}
	if len(r.AntiDebugFindings) > 0 {
		parts = append(parts, fmt.Sprintf("Anti-Debug: %d finding(s)", len(r.AntiDebugFindings)))
	}
	if len(r.SOAudits) > 0 {
		parts = append(parts, fmt.Sprintf("Audited %d ELF .so", len(r.SOAudits)))
	}
	r.Summary = strings.Join(parts, " | ")
}
