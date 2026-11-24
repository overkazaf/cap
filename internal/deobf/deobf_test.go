package deobf

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Synthetic Binary Builders (100% Pure Go, Network-Safe) ──────────────────

type synthSection struct {
	name    string
	secType elf.SectionType
	flags   elf.SectionFlag
	addr    uint64
	align   uint64
	entsize uint64
	data    []byte
}

// buildSyntheticARM64ELF constructs a valid little-endian ELF64 AArch64 shared
// object (ET_DYN) with program headers (PT_LOAD, PT_GNU_STACK NX, PT_GNU_RELRO)
// and arbitrary custom sections.
func buildSyntheticARM64ELF(sections []synthSection) []byte {
	const (
		ehdrSize = 64
		phdrSize = 56
		shdrSize = 64
		numPhdrs = 3
	)

	// Build .shstrtab
	var shstr bytes.Buffer
	shstr.WriteByte(0)
	nameOffsets := make([]uint32, len(sections)+1) // index 0 = null section
	for i, s := range sections {
		nameOffsets[i] = uint32(shstr.Len())
		shstr.WriteString(s.name)
		shstr.WriteByte(0)
	}
	shstrNameOff := uint32(shstr.Len())
	shstr.WriteString(".shstrtab")
	shstr.WriteByte(0)

	allSecs := append([]synthSection{}, sections...)
	allSecs = append(allSecs, synthSection{
		name:    ".shstrtab",
		secType: elf.SHT_STRTAB,
		align:   1,
		data:    shstr.Bytes(),
	})
	nameOffsets[len(sections)] = shstrNameOff

	var buf bytes.Buffer
	// Reserve ELF header + Program headers
	headerBytes := ehdrSize + numPhdrs*phdrSize
	buf.Write(make([]byte, headerBytes))

	secOffsets := make([]uint64, len(allSecs))
	for i, s := range allSecs {
		// Align to 16 bytes
		for buf.Len()%16 != 0 {
			buf.WriteByte(0)
		}
		secOffsets[i] = uint64(buf.Len())
		buf.Write(s.data)
	}

	// Align section header table to 8 bytes
	for buf.Len()%8 != 0 {
		buf.WriteByte(0)
	}
	shoff := uint64(buf.Len())

	// Write section headers: index 0 is SHT_NULL
	buf.Write(make([]byte, shdrSize))
	for i, s := range allSecs {
		var sh [shdrSize]byte
		binary.LittleEndian.PutUint32(sh[0:4], nameOffsets[i])
		binary.LittleEndian.PutUint32(sh[4:8], uint32(s.secType))
		binary.LittleEndian.PutUint64(sh[8:16], uint64(s.flags))
		binary.LittleEndian.PutUint64(sh[16:24], s.addr)
		binary.LittleEndian.PutUint64(sh[24:32], secOffsets[i])
		binary.LittleEndian.PutUint64(sh[32:40], uint64(len(s.data)))
		align := s.align
		if align == 0 {
			align = 8
		}
		binary.LittleEndian.PutUint64(sh[48:56], align)
		binary.LittleEndian.PutUint64(sh[56:64], s.entsize)
		buf.Write(sh[:])
	}

	raw := buf.Bytes()

	// Fill ELF64 Header
	copy(raw[0:4], []byte{0x7f, 'E', 'L', 'F'})
	raw[4] = byte(elf.ELFCLASS64)
	raw[5] = byte(elf.ELFDATA2LSB)
	raw[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(raw[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(raw[18:20], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(raw[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(raw[32:40], ehdrSize)               // e_phoff
	binary.LittleEndian.PutUint64(raw[40:48], shoff)                  // e_shoff
	binary.LittleEndian.PutUint16(raw[52:54], ehdrSize)               // e_ehsize
	binary.LittleEndian.PutUint16(raw[54:56], phdrSize)               // e_phentsize
	binary.LittleEndian.PutUint16(raw[56:58], numPhdrs)               // e_phnum
	binary.LittleEndian.PutUint16(raw[58:60], shdrSize)               // e_shentsize
	binary.LittleEndian.PutUint16(raw[60:62], uint16(len(allSecs)+1)) // e_shnum
	binary.LittleEndian.PutUint16(raw[62:64], uint16(len(allSecs)))   // e_shstrndx (.shstrtab is last)

	// Fill Program Headers
	writePhdr := func(idx int, pType elf.ProgType, pFlags elf.ProgFlag, off, vaddr, filesz, memsz, align uint64) {
		p := raw[ehdrSize+idx*phdrSize : ehdrSize+(idx+1)*phdrSize]
		binary.LittleEndian.PutUint32(p[0:4], uint32(pType))
		binary.LittleEndian.PutUint32(p[4:8], uint32(pFlags))
		binary.LittleEndian.PutUint64(p[8:16], off)
		binary.LittleEndian.PutUint64(p[16:24], vaddr)
		binary.LittleEndian.PutUint64(p[24:32], vaddr)
		binary.LittleEndian.PutUint64(p[32:40], filesz)
		binary.LittleEndian.PutUint64(p[40:48], memsz)
		binary.LittleEndian.PutUint64(p[48:56], align)
	}
	writePhdr(0, elf.PT_LOAD, elf.PF_R|elf.PF_X, 0, 0, uint64(len(raw)), uint64(len(raw)), 0x1000)
	writePhdr(1, elf.PT_GNU_STACK, elf.PF_R|elf.PF_W, 0, 0, 0, 0, 16)
	writePhdr(2, elf.PT_GNU_RELRO, elf.PF_R, 0, 0x4000, 0x100, 0x100, 1)

	return raw
}

func deterministicHighEntropyBytes(n int) []byte {
	out := make([]byte, n)
	var state uint64 = 0x9e3779b97f4a7c15
	for i := 0; i < n; i++ {
		// SplitMix64 step -> uniform pseudo-random byte distribution (~7.9 bits/byte)
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z = z ^ (z >> 31)
		out[i] = byte(z & 0xff)
	}
	return out
}

func appendU32(dst []byte, insns ...uint32) []byte {
	var tmp [4]byte
	for _, v := range insns {
		binary.LittleEndian.PutUint32(tmp[:], v)
		dst = append(dst, tmp[:]...)
	}
	return dst
}

func buildHardenedTestELF() []byte {
	// .text: real ARM64 instructions
	var text []byte
	// 1. Inline SVC #0 for ptrace (__NR_ptrace = 117): MOVZ X8, #117; SVC #0
	text = appendU32(text, 0xD2800008|(117<<5), 0xD4000001)
	// 2. Inline SVC #0 for tgkill (__NR_tgkill = 131): MOVZ X8, #131; SVC #0
	text = appendU32(text, 0xD2800008|(131<<5), 0xD4000001)
	// 3. Inline SVC #0 for openat (__NR_openat = 56): MOVZ X8, #56; SVC #0
	text = appendU32(text, 0xD2800008|(56<<5), 0xD4000001)
	// 4. Indirect register branches: 4x BR X8 (0xD61F0100), 2x BLR X9 (0xD63F0120)
	text = appendU32(text, 0xD61F0100, 0xD61F0100, 0xD61F0100, 0xD61F0100)
	text = appendU32(text, 0xD63F0120, 0xD63F0120)
	// 5. Hardware timing check: MRS X0, CNTVCT_EL0
	text = appendU32(text, 0xD53BE040)
	// 6. OLLVM CFF state loads (MOVZ + MOVK pairs) + CSEL + B.EQ
	for i := uint32(0); i < 4; i++ {
		text = appendU32(text,
			0x5280000A|((0x1234+i)<<5), // MOVZ W10, #imm
			0x72A0000A|((0xABCD+i)<<5), // MOVK W10, #imm, LSL #16
			0x1A8C016A,                 // CSEL W10, W11, W12, EQ
			0x54000040,                 // B.EQ +8
		)
	}
	// 7. Bitwise EOR instructions for OLLVM SUB heuristic
	for i := 0; i < 12; i++ {
		text = appendU32(text, 0x4A010000) // EOR W0, W0, W1
	}
	// RET
	text = appendU32(text, 0xD65F03C0)

	// .rodata: anti-debug strings + high-entropy encrypted string table blob
	var rodata bytes.Buffer
	rodata.WriteString("TracerPid\x00/proc/self/maps\x00ptrace\x00gum-js-loop\x00inotify_add_watch\x00clock_gettime\x00pthread_create\x00")
	rodata.Write(deterministicHighEntropyBytes(1024))

	// .vmp: high-entropy custom VMP bytecode section (RWX)
	vmpData := deterministicHighEntropyBytes(2048)

	// .init_array: 4 constructor pointers (32 bytes on ELF64)
	initArray := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(initArray[i*8:(i+1)*8], uint64(0x1000+i*0x40))
	}

	return buildSyntheticARM64ELF([]synthSection{
		{name: ".text", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: 0x1000, data: text},
		{name: ".rodata", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: 0x2000, data: rodata.Bytes()},
		{name: ".vmp", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR | elf.SHF_WRITE, addr: 0x3000, data: vmpData},
		{name: ".init_array", secType: elf.SHT_INIT_ARRAY, flags: elf.SHF_ALLOC | elf.SHF_WRITE, addr: 0x4000, entsize: 8, data: initArray},
	})
}

func buildCleanTestELF() []byte {
	// Minimal benign ARM64 function: ADD X0, X0, X1; RET
	var text []byte
	text = appendU32(text, 0x8B010000, 0xD65F03C0)
	rodata := []byte("hello world from clean library\x00version 1.0.0\x00status ok\x00")

	return buildSyntheticARM64ELF([]synthSection{
		{name: ".text", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: 0x1000, data: text},
		{name: ".rodata", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: 0x2000, data: rodata},
	})
}

func buildSyntheticDex(typeDescriptors []string, extraStrings []string) []byte {
	allStrs := append([]string{}, typeDescriptors...)
	allStrs = append(allStrs, extraStrings...)

	const headerSize = 0x70
	strIDsOff := uint32(headerSize)
	typeIDsOff := strIDsOff + uint32(len(allStrs)*4)
	dataStart := typeIDsOff + uint32(len(typeDescriptors)*4)

	var strData bytes.Buffer
	strOffsets := make([]uint32, len(allStrs))
	for i, s := range allStrs {
		strOffsets[i] = dataStart + uint32(strData.Len())
		// ULEB128 length (assumes < 128 for test strings)
		strData.WriteByte(byte(len(s)))
		strData.WriteString(s)
		strData.WriteByte(0)
	}

	totalSize := int(dataStart) + strData.Len()
	dex := make([]byte, totalSize)
	copy(dex[0:8], []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(dex[0x20:0x24], uint32(totalSize))
	binary.LittleEndian.PutUint32(dex[0x24:0x28], headerSize)
	binary.LittleEndian.PutUint32(dex[0x28:0x2c], 0x12345678)
	binary.LittleEndian.PutUint32(dex[0x38:0x3c], uint32(len(allStrs)))
	binary.LittleEndian.PutUint32(dex[0x3c:0x40], strIDsOff)
	binary.LittleEndian.PutUint32(dex[0x40:0x44], uint32(len(typeDescriptors)))
	binary.LittleEndian.PutUint32(dex[0x44:0x48], typeIDsOff)

	for i, off := range strOffsets {
		pos := int(strIDsOff) + i*4
		binary.LittleEndian.PutUint32(dex[pos:pos+4], off)
	}
	for i := range typeDescriptors {
		pos := int(typeIDsOff) + i*4
		binary.LittleEndian.PutUint32(dex[pos:pos+4], uint32(i))
	}
	copy(dex[dataStart:], strData.Bytes())
	return dex
}

func writeTestAPK(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	apkPath := filepath.Join(t.TempDir(), "sample_protected.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create apk: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}
	return apkPath
}

// ─── Tests: Entropy & ELF Scanner ────────────────────────────────────────────

func TestShannonEntropy(t *testing.T) {
	if h := ShannonEntropy(nil); h != 0 {
		t.Fatalf("expected 0 entropy for empty slice, got %v", h)
	}
	zeros := make([]byte, 1024)
	if h := ShannonEntropy(zeros); h != 0 {
		t.Fatalf("expected 0 entropy for constant bytes, got %v", h)
	}
	high := deterministicHighEntropyBytes(4096)
	if h := ShannonEntropy(high); h < 7.8 {
		t.Fatalf("expected high entropy >= 7.8 for uniform bytes, got %.3f", h)
	}
}

func TestScanELFBytes_HardenedARM64(t *testing.T) {
	elfBytes := buildHardenedTestELF()
	rep, err := ScanELFBytes("libshield_vmp.so", elfBytes)
	if err != nil {
		t.Fatalf("ScanELFBytes failed: %v", err)
	}

	if rep.TargetKind != TargetKindELF {
		t.Errorf("expected TargetKind=%q, got %q", TargetKindELF, rep.TargetKind)
	}
	if len(rep.SOAudits) != 1 {
		t.Fatalf("expected 1 SOAudit, got %d", len(rep.SOAudits))
	}

	so := rep.SOAudits[0]
	if so.Arch != "arm64" {
		t.Errorf("expected arch=arm64, got %q", so.Arch)
	}
	if !so.Stripped {
		t.Errorf("expected Stripped=true")
	}
	if so.InitArrayCount != 4 {
		t.Errorf("expected InitArrayCount=4, got %d", so.InitArrayCount)
	}
	if so.InlineSVCCount != 3 {
		t.Errorf("expected InlineSVCCount=3, got %d", so.InlineSVCCount)
	}
	if so.IndirectBranchCount != 6 {
		t.Errorf("expected IndirectBranchCount=6 (4 BR + 2 BLR), got %d", so.IndirectBranchCount)
	}
	if so.RodataEntropy < 6.0 {
		t.Errorf("expected high .rodata entropy >= 6.0, got %.3f", so.RodataEntropy)
	}
	if !so.SecurityFlags["pie"] || !so.SecurityFlags["nx"] || !so.SecurityFlags["relro"] {
		t.Errorf("expected pie/nx/relro security flags true, got %+v", so.SecurityFlags)
	}

	hasSuspVMP := false
	for _, sec := range so.SuspiciousSections {
		if sec == ".vmp" {
			hasSuspVMP = true
		}
	}
	if !hasSuspVMP {
		t.Errorf("expected .vmp in SuspiciousSections, got %v", so.SuspiciousSections)
	}

	// Verify VMP detection
	foundNativeVMP := false
	for _, v := range rep.VMPIndicators {
		if v.Kind == VMPNative && v.Section == ".vmp" && v.Entropy >= 7.0 {
			foundNativeVMP = true
		}
	}
	if !foundNativeVMP {
		t.Errorf("expected native_vmp finding on .vmp with entropy >= 7.0, got %+v", rep.VMPIndicators)
	}

	// Verify Obfuscation findings
	obfKinds := make(map[string]bool)
	for _, o := range rep.Obfuscation {
		obfKinds[o.Kind] = true
	}
	for _, expected := range []string{ObfIndirectBranch, ObfOLLVMCFF, ObfOLLVMSUB, ObfStringEncryption, ObfSymbolStripped, ObfSectionTampered} {
		if !obfKinds[expected] {
			t.Errorf("missing expected obfuscation kind %q; got %+v", expected, obfKinds)
		}
	}

	// Verify Anti-Debug findings including exact inline SVC offsets & decoded syscall names
	adKinds := make(map[string]bool)
	svcOffsets := make(map[string]string)
	for _, ad := range rep.AntiDebugFindings {
		adKinds[ad.Kind] = true
		if ad.Kind == AntiDebugInlineSVC {
			svcOffsets[ad.OffsetHex] = ad.SymbolOrPattern
		}
	}
	for _, expected := range []string{
		AntiDebugInlineSVC, AntiDebugTracerPid, AntiDebugProcMaps,
		AntiDebugPtrace, AntiDebugFridaDetect, AntiDebugInotify,
		AntiDebugTimingCheck, AntiDebugWatchdogThread,
	} {
		if !adKinds[expected] {
			t.Errorf("missing expected anti-debug kind %q; got %+v", expected, adKinds)
		}
	}
	if pat, ok := svcOffsets["0x1004"]; !ok || !strings.Contains(pat, "ptrace") {
		t.Errorf("expected inline SVC at 0x1004 decoded as ptrace, got %+v", svcOffsets)
	}
	if pat, ok := svcOffsets["0x100c"]; !ok || !strings.Contains(pat, "tgkill") {
		t.Errorf("expected inline SVC at 0x100c decoded as tgkill, got %+v", svcOffsets)
	}
	if pat, ok := svcOffsets["0x1014"]; !ok || !strings.Contains(pat, "openat") {
		t.Errorf("expected inline SVC at 0x1014 decoded as openat, got %+v", svcOffsets)
	}

	if rep.RiskScore < 70 {
		t.Errorf("expected high risk score >= 70 for heavily hardened ELF, got %d (%s)", rep.RiskScore, rep.HardeningLevel)
	}
	if len(rep.Recommendations) == 0 || rep.Summary == "" {
		t.Errorf("expected populated Recommendations and Summary")
	}

	// Verify JSON serialization round-trip
	rawJSON, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("json.Marshal(ProtectionReport) failed: %v", err)
	}
	var decoded ProtectionReport
	if err := json.Unmarshal(rawJSON, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(ProtectionReport) failed: %v", err)
	}
	if decoded.RiskScore != rep.RiskScore || len(decoded.SOAudits) != 1 {
		t.Errorf("JSON round-trip mismatch: %+v", decoded)
	}
}

func TestScanELFBytes_CleanAndInvalid(t *testing.T) {
	clean, err := ScanELFBytes("libclean.so", buildCleanTestELF())
	if err != nil {
		t.Fatalf("ScanELFBytes clean failed: %v", err)
	}
	if clean.SOAudits[0].InlineSVCCount != 0 || clean.SOAudits[0].IndirectBranchCount != 0 {
		t.Errorf("expected 0 SVCs and 0 indirect branches on clean ELF, got %+v", clean.SOAudits[0])
	}
	if len(clean.VMPIndicators) != 0 {
		t.Errorf("expected 0 VMP indicators on clean ELF, got %+v", clean.VMPIndicators)
	}
	if clean.RiskScore > 15 {
		t.Errorf("expected low risk score <= 15 on clean ELF, got %d", clean.RiskScore)
	}

	if _, err := ScanELFBytes("bad.so", []byte("not an elf")); err == nil {
		t.Errorf("expected error for non-ELF bytes")
	}

	// Disk-based ScanELF round-trip + error paths
	soPath := filepath.Join(t.TempDir(), "libdisk.so")
	if err := os.WriteFile(soPath, buildHardenedTestELF(), 0644); err != nil {
		t.Fatalf("write temp elf: %v", err)
	}
	diskRep, err := ScanELF(soPath)
	if err != nil {
		t.Fatalf("ScanELF failed: %v", err)
	}
	if diskRep.TargetPath != soPath || diskRep.SOAudits[0].InlineSVCCount != 3 {
		t.Errorf("unexpected ScanELF result: %+v", diskRep)
	}
	if _, err := ScanELF(""); err == nil {
		t.Errorf("expected error for empty elfPath")
	}
	if _, err := ScanAPK(""); err == nil {
		t.Errorf("expected error for empty apkPath")
	}
}

// ─── Tests: APK Packer & Multi-Layer Scanner ─────────────────────────────────

func TestScanAPK_360JiaguAndDexHeuristics(t *testing.T) {
	dexBytes := buildSyntheticDex(
		[]string{"La/a;", "La/b;", "Lb/c;", "Lo/O0O0;", "Lcom/stub/StubApp;"},
		[]string{"isDebuggerConnected", "adb_enabled", "com.stub.StubApp"},
	)
	elfBytes := buildHardenedTestELF()

	apkPath := writeTestAPK(t, map[string][]byte{
		"AndroidManifest.xml":          []byte("manifest"),
		"classes.dex":                  dexBytes,
		"assets/.appkey":               []byte("360-key"),
		"lib/arm64-v8a/libjiagu_64.so": elfBytes,
		"lib/armeabi-v7a/libjiagu.so":  []byte("not-elf-fallback"),
	})

	rep, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK failed: %v", err)
	}
	if rep.TargetKind != TargetKindAPK {
		t.Errorf("expected TargetKind=%q, got %q", TargetKindAPK, rep.TargetKind)
	}

	// Packer detection: 360 Jiagu
	foundJiagu := false
	for _, p := range rep.Packers {
		if strings.Contains(p.Name, "360 Jiagu") && p.Vendor == "Qihoo 360" && p.Confidence >= 0.90 {
			foundJiagu = true
			if p.UnpackStrategy == "" || len(p.Evidence) < 2 {
				t.Errorf("expected rich evidence & strategy for 360 Jiagu, got %+v", p)
			}
		}
	}
	if !foundJiagu {
		t.Fatalf("expected 360 Jiagu packer finding, got %+v", rep.Packers)
	}

	// SO audit present for libjiagu_64.so
	if len(rep.SOAudits) != 1 || rep.SOAudits[0].Name != "libjiagu_64.so" {
		t.Fatalf("expected SOAudit for libjiagu_64.so, got %+v", rep.SOAudits)
	}

	// Verify ProGuard + Java debug + Dex-VMP stub heuristic
	foundProguard := false
	for _, o := range rep.Obfuscation {
		if o.Kind == ObfDexProguard {
			foundProguard = true
		}
	}
	if !foundProguard {
		t.Errorf("expected dex_proguard finding, got %+v", rep.Obfuscation)
	}

	foundJavaDebug := false
	for _, ad := range rep.AntiDebugFindings {
		if ad.Kind == AntiDebugJavaDebug {
			foundJavaDebug = true
		}
	}
	if !foundJavaDebug {
		t.Errorf("expected java_debug finding from classes.dex, got %+v", rep.AntiDebugFindings)
	}

	if rep.HardeningLevel != HardeningExtreme || rep.RiskScore < 80 {
		t.Errorf("expected extreme hardening (>=80) for 360 Jiagu + VMP + inline SVC APK, got %s (%d)", rep.HardeningLevel, rep.RiskScore)
	}
}

func TestScanAPK_MultipleCommercialPackers(t *testing.T) {
	cases := []struct {
		entry  string
		vendor string
	}{
		{"lib/arm64-v8a/libshella-4.1.so", "Tencent"},
		{"lib/arm64-v8a/libSecShell.so", "Bangcle / SecNeo"},
		{"assets/ijiami.dat", "Ijiami"},
		{"lib/arm64-v8a/libbaiduprotect.so", "Baidu"},
		{"lib/arm64-v8a/libchaosvmp.so", "Naga"},
		{"lib/arm64-v8a/libsgmain.so", "Alibaba"},
		{"lib/arm64-v8a/libdx_vmp.so", "Dingxiang"},
		{"lib/arm64-v8a/libnesec.so", "NetEase"},
		{"lib/arm64-v8a/libdexguard.so", "Guardsquare"},
		{"assets/dp.arm-v8.so.dat", "Licel"},
		{"lib/arm64-v8a/libpromon.so", "Promon"},
	}

	for _, tc := range cases {
		apkPath := writeTestAPK(t, map[string][]byte{
			tc.entry: []byte("stub"),
		})
		rep, err := ScanAPK(apkPath)
		if err != nil {
			t.Fatalf("ScanAPK(%s) failed: %v", tc.entry, err)
		}
		matched := false
		for _, p := range rep.Packers {
			if p.Vendor == tc.vendor {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("entry %q: expected vendor %q, got %+v", tc.entry, tc.vendor, rep.Packers)
		}
	}
}

// ─── Tests: Script Generators ────────────────────────────────────────────────

func TestGenerateStealthScript_AutoTailoredAndEscaped(t *testing.T) {
	rep, err := ScanELFBytes("libjiagu_64.so", buildHardenedTestELF())
	if err != nil {
		t.Fatalf("ScanELFBytes: %v", err)
	}

	// Passing empty module toggles with a report auto-tailors all relevant modules!
	script := GenerateStealthScript(StealthOptions{
		TargetPackage:        `com.example."quoted"`,
		WatchdogBlockOffsets: []string{"0x1a2b0"},
		CustomHideTokens:     []string{"hluda-srv"},
	}, rep)

	if script.Engine != EngineFrida || script.Language != "javascript" {
		t.Errorf("unexpected metadata: %+v", script)
	}
	requiredSnippets := []string{
		"BypassTracerPidAndProcFS",
		"BypassPtraceAndSignals",
		"PatchInlineSVC",
		"BypassTimingAndInotify",
		"BypassJavaDebugChecks",
		"TracerPid",
		"01 00 00 d4",
		"inotify_add_watch",
		"clock_gettime",
		"isDebuggerConnected",
		"FLAG_DEBUGGABLE",
		`"libjiagu_64.so"`,
		`"0x1a2b0"`,
		`"hluda-srv"`,
		`"com.example.\"quoted\""`,
	}
	for _, snip := range requiredSnippets {
		if !strings.Contains(script.Code, snip) {
			t.Errorf("generated stealth script missing %q", snip)
		}
	}
	if len(script.Modules) != 5 {
		t.Errorf("expected all 5 stealth modules auto-enabled from hardened report, got %v", script.Modules)
	}

	// Verify selective module toggling includes ONLY requested module + dryRun flag
	onlySVC := GenerateStealthScript(StealthOptions{
		TargetSO:       "libtarget.so",
		PatchInlineSVC: true,
		DryRunSVCPatch: true,
	}, nil)
	if len(onlySVC.Modules) != 1 || onlySVC.Modules[0] != "PatchInlineSVC" {
		t.Errorf("expected only PatchInlineSVC enabled, got %v", onlySVC.Modules)
	}
	if !strings.Contains(onlySVC.Code, "dryRunSVCPatch: true") || strings.Contains(onlySVC.Code, "installProcFSCloak") {
		t.Errorf("selective stealth script failed isolation check")
	}
}

func TestGenerateDexUnpackerScript(t *testing.T) {
	sc := GenerateDexUnpackerScript("com.target.app")
	if sc.Engine != EngineFrida || sc.Category != "unpack" {
		t.Errorf("unexpected metadata: %+v", sc)
	}
	for _, snip := range []string{
		"libart.so",
		"OpenMemory",
		"64 65 78 0a 30 33 ?? 00",
		"64 65 78 0a 30 34 ?? 00",
		"/files/cap_dump/",
		`"com.target.app"`,
		"rpc.exports",
	} {
		if !strings.Contains(sc.Code, snip) {
			t.Errorf("dex unpacker script missing %q", snip)
		}
	}
}

func TestGenerateOLLVMAndStringDecryptAndJavaDeobfScripts(t *testing.T) {
	ollvm := GenerateOLLVMDeflattenScript(`/tmp/my "app"/libsign.so`, "1a400", "arm64")
	if ollvm.Engine != EngineAngr || ollvm.Language != "python" {
		t.Errorf("unexpected OLLVM metadata: %+v", ollvm)
	}
	for _, snip := range []string{
		"import angr",
		"CFGFast",
		"main_dispatcher",
		"pre_dispatcher",
		"encode_arm64_b",
		"export_dot",
		"patch_binary",
		`"/tmp/my \"app\"/libsign.so"`,
		`"0x1a400"`,
	} {
		if !strings.Contains(ollvm.Code, snip) {
			t.Errorf("OLLVM script missing %q", snip)
		}
	}

	ql := GenerateStringDecryptScript("qiling", "/tmp/libsec.so", "")
	if ql.Engine != EngineQiling || ql.Language != "python" {
		t.Errorf("unexpected Qiling metadata: %+v", ql)
	}
	for _, snip := range []string{"from qiling import Qiling", ".init_array", ".rodata", "diff_decrypted_strings", "[CAP_DEOBF]"} {
		if !strings.Contains(ql.Code, snip) {
			t.Errorf("Qiling string decrypt script missing %q", snip)
		}
	}

	ud := GenerateStringDecryptScript("unidbg", "/tmp/libsec.so", "/tmp/app.apk")
	if ud.Engine != EngineUnidbg || ud.Language != "java" {
		t.Errorf("unexpected Unidbg metadata: %+v", ud)
	}
	for _, snip := range []string{"AndroidEmulatorBuilder.for64Bit()", "mem_read", "callJNI_OnLoad", "extractDiffStrings", "[CAP_DEOBF]"} {
		if !strings.Contains(ud.Code, snip) {
			t.Errorf("Unidbg string decrypt script missing %q", snip)
		}
	}

	jDeobf := GenerateJavaDeobfScript("com.example.shop")
	if jDeobf.Engine != EngineFrida || jDeobf.Language != "javascript" {
		t.Errorf("unexpected Java deobf metadata: %+v", jDeobf)
	}
	for _, snip := range []string{"java.lang.Class", "forName", "java.lang.reflect.Method", "String.<init>([B)", "android.util.Base64", `"com.example.shop"`} {
		if !strings.Contains(jDeobf.Code, snip) {
			t.Errorf("Java deobf script missing %q", snip)
		}
	}
}

func TestGenerateVMPScripts(t *testing.T) {
	stalker := GenerateVMPStalkerScript("libvmp.so", "0x2b100", 25000)
	if stalker.Engine != EngineFrida || stalker.Category != "vmp_stalker" {
		t.Errorf("unexpected VMP stalker metadata: %+v", stalker)
	}
	for _, snip := range []string{"Stalker.follow", "ENTRY_IS_OFFSET = true", `"0x2b100"`, "MAX_EVENTS = 25000", "[CAP_VMP]", "inBounds"} {
		if !strings.Contains(stalker.Code, snip) {
			t.Errorf("VMP stalker script missing %q", snip)
		}
	}

	reg := GenerateVMPRegisterNativesScript("com.example.vmp")
	if reg.Engine != EngineFrida || reg.Category != "vmp_jni" {
		t.Errorf("unexpected RegisterNatives metadata: %+v", reg)
	}
	for _, snip := range []string{"libart.so", "RegisterNatives", "shared_vmp_dispatcher", `"com.example.vmp"`, `"com/example/vmp"`} {
		if !strings.Contains(reg.Code, snip) {
			t.Errorf("RegisterNatives script missing %q", snip)
		}
	}

	unidbgVMP := GenerateUnidbgVMPTraceScript("/tmp/app.apk", "libvmp.so", "com.example.Vmp", "calc(Ljava/lang/String;)Ljava/lang/String;")
	if unidbgVMP.Engine != EngineUnidbg || unidbgVMP.Language != "java" {
		t.Errorf("unexpected Unidbg VMP metadata: %+v", unidbgVMP)
	}
	for _, snip := range []string{"traceCode", "traceRead", "traceWrite", "AbstractJni", `"com/example/Vmp"`, `"vmp"`} {
		if !strings.Contains(unidbgVMP.Code, snip) {
			t.Errorf("Unidbg VMP script missing %q", snip)
		}
	}
}

// ─── Tests: Pure-Go VMP Trace Analyzer ───────────────────────────────────────

func TestAnalyzeVMPTrace_DispatcherHandlersMemoryAndCalls(t *testing.T) {
	const modBase uint64 = 0x7000000000

	// Build a realistic multi-cycle VMP execution trace mixing Stalker, Unidbg,
	// and [CAP_VMP] JSON lines:
	//   Dispatcher loop: 0x7000001000 -> 0x7000001004 -> 0x7000001008 (br x8)
	//   Handlers: 6 distinct virtual opcode handlers at +0x2000..+0x2500
	//   Memory hotspots:
	//     0x7000090000 = VM context (vPC read+write every cycle)
	//     0x7000080000 = handler lookup table (read-only every cycle)
	//     0x7000090100 = VM stack (read/write inside handlers)
	//   External calls: EVP_DigestUpdate (crypto), JNI::GetStringUTFChars (jni), libc!memcpy (libc)
	handlers := []uint64{
		modBase + 0x2000,
		modBase + 0x2100,
		modBase + 0x2200,
		modBase + 0x2300,
		modBase + 0x2400,
		modBase + 0x2500,
	}

	var traceBuf strings.Builder
	for cycle := 0; cycle < 18; cycle++ {
		h := handlers[cycle%len(handlers)]
		// Dispatcher fetch-decode-dispatch loop
		fmt.Fprintf(&traceBuf, "[0x%x] ldr w9, [x20] ; MEM_R=0x%x\n", modBase+0x1000, modBase+0x90000)
		fmt.Fprintf(&traceBuf, "[0x%x] ldr x8, [x21, x9, lsl #3] ; MEM_R=0x%x\n", modBase+0x1004, modBase+0x80000)
		fmt.Fprintf(&traceBuf, "0x%x: br x8\n", modBase+0x1008)

		// Virtual handler body
		fmt.Fprintf(&traceBuf, "[CAP_VMP] {\"event\":\"insn\",\"pc\":\"0x%x\",\"insn\":\"add x0, x0, x1\",\"mem_w\":\"0x%x\"}\n", h, modBase+0x90100)
		fmt.Fprintf(&traceBuf, "[12:00:00 100][libvmp.so 0x%x] [00 00 00 14] 0x%x: \"str w9, [x20]\" MEM_W=0x%x\n", (h+4)-modBase, h+4, modBase+0x90000)

		// Periodic external calls
		if cycle%6 == 0 {
			traceBuf.WriteString("CALL EVP_DigestUpdate\n")
		}
		if cycle%9 == 0 {
			traceBuf.WriteString("CALL JNI::GetStringUTFChars\n")
		}
		if cycle == 5 {
			fmt.Fprintf(&traceBuf, "0x%x: bl memcpy\n", h+8)
		}
	}

	analysis := AnalyzeVMPTrace(traceBuf.String(), modBase)

	if analysis.TotalInstructions < 90 {
		t.Fatalf("expected >= 90 parsed instructions, got %d", analysis.TotalInstructions)
	}
	if analysis.UniquePCs < 15 {
		t.Fatalf("expected >= 15 unique PCs, got %d", analysis.UniquePCs)
	}

	// Primary dispatcher MUST be 0x7000001008 (+0x1008) with fan-out == 6
	if len(analysis.DispatcherCandidates) == 0 {
		t.Fatalf("expected dispatcher candidate, got none")
	}
	top := analysis.DispatcherCandidates[0]
	wantDisp := fmt.Sprintf("0x%x", modBase+0x1008)
	if top.Address != wantDisp || top.OffsetHex != "+0x1008" {
		t.Errorf("expected top dispatcher %s (+0x1008), got %+v", wantDisp, top)
	}
	if top.UniqueTargets != 6 {
		t.Errorf("expected dispatcher fan-out=6, got %d", top.UniqueTargets)
	}
	if top.Hits != 18 {
		t.Errorf("expected dispatcher hits=18, got %d", top.Hits)
	}

	// All 6 virtual opcode handlers must be discovered
	handlerAddrs := make(map[string]bool)
	for _, h := range analysis.HandlerEntries {
		handlerAddrs[h.Address] = true
	}
	for _, wantH := range handlers {
		hs := fmt.Sprintf("0x%x", wantH)
		if !handlerAddrs[hs] {
			t.Errorf("missing expected handler entry %s in %+v", hs, analysis.HandlerEntries)
		}
	}

	// Memory hotspots: vPC context (read+write), handler table (read-only), VM stack (write)
	memRoles := make(map[string]VMPMemSpot)
	for _, m := range analysis.MemoryHotspots {
		memRoles[m.Address] = m
	}
	ctxSpot, ok := memRoles[fmt.Sprintf("0x%x", modBase+0x90000)]
	if !ok || ctxSpot.Reads != 18 || ctxSpot.Writes != 18 || ctxSpot.Role != "vm_context" {
		t.Errorf("expected vm_context at 0x%x with 18R/18W, got %+v", modBase+0x90000, ctxSpot)
	}
	tblSpot, ok := memRoles[fmt.Sprintf("0x%x", modBase+0x80000)]
	if !ok || tblSpot.Reads != 18 || tblSpot.Writes != 0 || tblSpot.Role != "lookup_table" {
		t.Errorf("expected lookup_table at 0x%x with 18R/0W, got %+v", modBase+0x80000, tblSpot)
	}
	stkSpot, ok := memRoles[fmt.Sprintf("0x%x", modBase+0x90100)]
	if !ok || stkSpot.Writes != 18 || stkSpot.Role != "vm_stack" {
		t.Errorf("expected vm_stack at 0x%x with 18W, got %+v", modBase+0x90100, stkSpot)
	}

	// External calls extracted & categorized
	extCats := make(map[string]VMPExternalCall)
	for _, ec := range analysis.ExternalCalls {
		extCats[ec.Target] = ec
	}
	if ec, ok := extCats["EVP_DigestUpdate"]; !ok || ec.Category != "crypto" || ec.Count != 3 {
		t.Errorf("expected crypto external call EVP_DigestUpdate x3, got %+v", extCats)
	}
	if ec, ok := extCats["JNI::GetStringUTFChars"]; !ok || ec.Category != "jni" || ec.Count != 2 {
		t.Errorf("expected jni external call JNI::GetStringUTFChars x2, got %+v", extCats)
	}
	if ec, ok := extCats["memcpy"]; !ok || ec.Category != "libc" || ec.Count != 1 {
		t.Errorf("expected libc external call memcpy x1, got %+v", extCats)
	}

	if len(analysis.RecommendedHooks) < 3 {
		t.Errorf("expected >= 3 actionable recommended hooks, got %v", analysis.RecommendedHooks)
	}
	if analysis.Summary == "" {
		t.Errorf("expected non-empty analysis summary")
	}

	// Empty trace degrades gracefully
	empty := AnalyzeVMPTrace("   \n# comment\n", 0)
	if empty.TotalInstructions != 0 || len(empty.DispatcherCandidates) != 0 {
		t.Errorf("expected empty analysis for blank trace, got %+v", empty)
	}
}

func TestGeneratedScripts_SyntaxCheck(t *testing.T) {
	tmp := t.TempDir()

	if nodePath, err := exec.LookPath("node"); err == nil {
		jsScripts := []*GeneratedScript{
			GenerateStealthScript(StealthOptions{
				TargetPackage:            `com.example."demo"`,
				TargetSO:                 "libjiagu_64.so",
				BypassTracerPidAndProcFS: true,
				BypassPtraceAndSignals:   true,
				PatchInlineSVC:           true,
				BypassTimingAndInotify:   true,
				BypassJavaDebugChecks:    true,
				WatchdogBlockOffsets:     []string{"0x1234"},
				CustomHideTokens:         []string{"hluda"},
			}, nil),
			GenerateDexUnpackerScript("com.example.demo"),
			GenerateJavaDeobfScript("com.example.demo"),
			GenerateVMPStalkerScript("libvmp.so", "0x1a00", 10000),
			GenerateVMPRegisterNativesScript("com.example.demo"),
		}
		for _, sc := range jsScripts {
			p := filepath.Join(tmp, sanitizeSlug(sc.ID)+".js")
			if err := os.WriteFile(p, []byte(sc.Code), 0644); err != nil {
				t.Fatalf("write %s: %v", p, err)
			}
			if out, err := exec.Command(nodePath, "--check", p).CombinedOutput(); err != nil {
				t.Errorf("node --check failed for %s: %v\n%s", sc.ID, err, string(out))
			}
		}
	}

	if pyPath, err := exec.LookPath("python3"); err == nil {
		pyScripts := []*GeneratedScript{
			GenerateOLLVMDeflattenScript(`/tmp/my "app"/libsign.so`, "0x1a400", "arm64"),
			GenerateStringDecryptScript("qiling", "/tmp/libsec.so", ""),
		}
		for _, sc := range pyScripts {
			p := filepath.Join(tmp, sanitizeSlug(sc.ID)+".py")
			if err := os.WriteFile(p, []byte(sc.Code), 0644); err != nil {
				t.Fatalf("write %s: %v", p, err)
			}
			if out, err := exec.Command(pyPath, "-m", "py_compile", p).CombinedOutput(); err != nil {
				t.Errorf("py_compile failed for %s: %v\n%s", sc.ID, err, string(out))
			}
		}
	}
}

// ─── Regression Tests (Verifier-2 Review #17) ────────────────────────────────

func TestScanELFBytes_PLTNoFalsePositive(t *testing.T) {
	// Clean .text with no indirect branches, paired with .plt/.plt.got/.init/.fini
	// containing many ARM64 PLT veneer BR X17 (0xD61F0220) instructions.
	var text []byte
	text = appendU32(text, 0x8B010000, 0xD65F03C0) // ADD X0, X0, X1; RET

	var plt []byte
	for i := 0; i < 20; i++ {
		plt = appendU32(plt, 0xD61F0220) // BR X17 (standard AArch64 PLT stub)
	}

	elfBytes := buildSyntheticARM64ELF([]synthSection{
		{name: ".text", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: 0x1000, data: text},
		{name: ".plt", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: 0x2000, data: plt},
		{name: ".plt.got", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: 0x2200, data: plt[:16]},
		{name: ".init", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: 0x2300, data: plt[:8]},
		{name: ".fini", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: 0x2400, data: plt[:8]},
		{name: ".rodata", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: 0x3000, data: []byte("clean library\x00")},
	})

	rep, err := ScanELFBytes("libclean_plt.so", elfBytes)
	if err != nil {
		t.Fatalf("ScanELFBytes failed: %v", err)
	}
	if rep.SOAudits[0].IndirectBranchCount != 0 {
		t.Errorf("expected 0 indirect branches (PLT stubs excluded), got %d", rep.SOAudits[0].IndirectBranchCount)
	}
	for _, o := range rep.Obfuscation {
		if o.Kind == ObfIndirectBranch || o.Kind == ObfOLLVMCFF {
			t.Errorf("false positive obfuscation %q from .plt stubs", o.Kind)
		}
	}
	if len(rep.VMPIndicators) != 0 {
		t.Errorf("false positive VMP indicators from .plt stubs: %+v", rep.VMPIndicators)
	}
}

func TestScanInstructions_SyscallWindowCSINCAndARM32(t *testing.T) {
	// 1. ARM64 syscall window, control-flow clear, X8 overwrite clear, and CSINC/CSINV/CSNEG mask.
	var arm64Code []byte
	// Case A: MOVZ X8, #117; RET; SVC #0 -> cleared by RET (offset 0x1008 must NOT decode as ptrace)
	arm64Code = appendU32(arm64Code, 0xD2800008|(117<<5), 0xD65F03C0, 0xD4000001)
	// Case B: MOVZ X8, #131; 10x NOP; SVC #0 -> beyond 8-insn window (offset 0x1038 must NOT decode as tgkill)
	arm64Code = appendU32(arm64Code, 0xD2800008|(131<<5))
	for i := 0; i < 10; i++ {
		arm64Code = appendU32(arm64Code, 0xD503201F) // NOP
	}
	arm64Code = appendU32(arm64Code, 0xD4000001)
	// Case C: MOVZ X8, #56; ADD X8, X0, #1 (0x91000408 overwrites X8); SVC #0 -> must NOT decode as openat
	arm64Code = appendU32(arm64Code, 0xD2800008|(56<<5), 0x91000408, 0xD4000001)
	// Case D: CSEL, CSINC, CSINV, CSNEG -> all 4 must be counted in cselCount
	arm64Code = appendU32(arm64Code,
		0x1A8C016A, // CSEL  W10, W11, W12, EQ (op=0, o2=0)
		0x1A8C056A, // CSINC W10, W11, W12, EQ (op=0, o2=1)
		0x5A8C016A, // CSINV W10, W11, W12, EQ (op=1, o2=0)
		0x5A8C056A, // CSNEG W10, W11, W12, EQ (op=1, o2=1)
	)

	var st arm64InsnStats
	st.svcSyscalls = make(map[uint64]uint16)
	scanARM64Instructions(arm64Code, 0x1000, &st)

	if len(st.svcOffsets) != 3 {
		t.Fatalf("expected 3 SVC sites, got %d", len(st.svcOffsets))
	}
	if len(st.svcSyscalls) != 0 {
		t.Errorf("expected 0 attributed syscalls across RET / >8-insn window / X8 overwrite, got %+v", st.svcSyscalls)
	}
	if st.cselCount != 4 {
		t.Errorf("expected cselCount=4 (CSEL+CSINC+CSINV+CSNEG), got %d", st.cselCount)
	}

	// 2. ARM32 decoding: reject cond==0xF, match conditional SVC<cc> #0, exclude BX LR
	var arm32Code []byte
	arm32Code = appendU32(arm32Code,
		0x0F000000, // SVCEQ #0 (cond=0x0) -> MUST match
		0xEF000000, // SVCAL #0 (cond=0xE) -> MUST match
		0xFF000000, // cond=0xF -> MUST reject
		0xF12FFF13, // cond=0xF in BX encoding space -> MUST reject
		0xF12FFF34, // cond=0xF in BLX encoding space -> MUST reject
		0xE12FFF1E, // BX LR -> MUST reject (standard return)
		0xE12FFF13, // BX R3 -> MUST match brCount
		0x112FFF34, // BLXNE R4 -> MUST match blrCount
	)
	var st32 arm64InsnStats
	st32.svcSyscalls = make(map[uint64]uint16)
	scanARM32Instructions(arm32Code, 0x2000, &st32)

	if len(st32.svcOffsets) != 2 {
		t.Errorf("expected 2 ARM32 SVCs (SVCEQ + SVCAL), got %d", len(st32.svcOffsets))
	}
	if st32.brCount != 1 || st32.blrCount != 1 {
		t.Errorf("expected ARM32 brCount=1, blrCount=1, got br=%d blr=%d", st32.brCount, st32.blrCount)
	}
}

func TestScanELFBytes_TruncatedMalformedAndAntiDebugBoundaryLoop(t *testing.T) {
	// 1. Truncated/malformed ELF with wildly inflated .init_array sh_size -> must not panic or report bogus count.
	initData := make([]byte, 16)
	elfBytes := buildSyntheticARM64ELF([]synthSection{
		{name: ".text", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, addr: 0x1000, data: appendU32(nil, 0xD65F03C0)},
		{name: ".init_array", secType: elf.SHT_INIT_ARRAY, flags: elf.SHF_ALLOC | elf.SHF_WRITE, addr: 0x4000, entsize: 8, data: initData},
		// Earlier non-boundary matches ("myfrida", "xptrace") followed by clean-boundary "frida" & "ptrace"
		{name: ".rodata", secType: elf.SHT_PROGBITS, flags: elf.SHF_ALLOC, addr: 0x2000, data: []byte("myfrida_noise\x00found frida!\x00xptrace_fake\x00ptrace\x00")},
	})

	// Tamper .init_array sh_size in the section header table to 0x10000000 (256 MiB) while leaving the file small.
	shoff := binary.LittleEndian.Uint64(elfBytes[40:48])
	// Section index 2 is .init_array (index 0 = SHT_NULL, 1 = .text, 2 = .init_array)
	initShdrOff := shoff + 2*64
	binary.LittleEndian.PutUint64(elfBytes[initShdrOff+32:initShdrOff+40], 0x10000000)

	rep, err := ScanELFBytes("libtampered.so", elfBytes)
	if err != nil {
		t.Fatalf("ScanELFBytes should gracefully handle inflated sh_size, got err: %v", err)
	}
	if rep.SOAudits[0].InitArrayCount > 1000 {
		t.Errorf("InitArrayCount trusted raw inflated sh_size: got %d", rep.SOAudits[0].InitArrayCount)
	}

	// Verify scanBytesForAntiDebug continued past "myfrida_noise"/"xptrace_fake" to find clean "frida" & "ptrace".
	foundFrida, foundPtrace := false, false
	for _, ad := range rep.AntiDebugFindings {
		if ad.SymbolOrPattern == "frida" {
			foundFrida = true
		}
		if ad.SymbolOrPattern == "ptrace" {
			foundPtrace = true
		}
	}
	if !foundFrida || !foundPtrace {
		t.Errorf("expected both clean-boundary 'frida' and 'ptrace' findings after earlier non-boundary hits; got %+v", rep.AntiDebugFindings)
	}
}

func TestGeneratedScripts_AdversarialEscapingAndMemorySafety(t *testing.T) {
	tmp := t.TempDir()

	// Adversarial strings with newlines, JS line separators, triple quotes, and trailing backslash
	evilPkg := "com.evil.pkg\nconsole.log('injected');\r\u2028\"\"\"\\"
	evilPath := "/tmp/evil\"\"\"dir\\\nimport os; os.system('id')/libevil.so\\"
	evilAddr := "not_hex\n\"\"\"import os"

	stealth := GenerateStealthScript(StealthOptions{
		TargetPackage:            evilPkg,
		TargetSO:                 "libevil.so\n//break",
		BypassTracerPidAndProcFS: true,
		BypassPtraceAndSignals:   true,
		PatchInlineSVC:           true,
		BypassTimingAndInotify:   true,
		BypassJavaDebugChecks:    true,
		WatchdogBlockOffsets:     []string{"0x1234"},
		CustomHideTokens:         []string{"tok\nbreak"},
	}, &ProtectionReport{Summary: "Hardening: HIGH\nmalicious();"})

	// Verify memory-safety fixes in Stealth script
	if !strings.Contains(stealth.Code, "writeRawBytesClamped") || strings.Contains(stealth.Code, "writeUtf8String(") {
		t.Errorf("stealth script should use writeRawBytesClamped instead of NUL-appending writeUtf8String")
	}
	if !strings.Contains(stealth.Code, "this.bufsiz") || !strings.Contains(stealth.Code, "Process.pointerSize === 8") {
		t.Errorf("stealth script missing readlink bufsiz clamping or 32/64-bit timespec branching")
	}
	if !strings.Contains(stealth.Code, "this.kind === 'maps' || this.kind === 'net_tcp'") {
		t.Errorf("stealth script missing net_tcp handling in fgets")
	}

	stalker := GenerateVMPStalkerScript("libvmp.so\nbreak()", "0x1a00\nbreak()", 5000)
	if !strings.Contains(stalker.Code, "extractBranchReg") || !strings.Contains(stalker.Code, "extractMemOperand") || !strings.Contains(stalker.Code, "this.stalking") {
		t.Errorf("VMP Stalker script missing operand register extraction or per-invocation stalking guard")
	}
	if strings.Contains(stalker.Code, "rec.mem_r = context.x9") || strings.Contains(stalker.Code, "rec.mem_w = context.sp") {
		t.Errorf("VMP Stalker script must not fabricate hardcoded x9/sp memory addresses")
	}

	ollvm := GenerateOLLVMDeflattenScript(evilPath, evilAddr, "arm64\n\"\"\"")
	if !strings.Contains(ollvm.Code, `FUNC_ADDR = int("0x1000", 16)`) {
		t.Errorf("invalid funcAddr should safely fall back to 0x1000, got code:\n%s", ollvm.Code[:400])
	}

	qiling := GenerateStringDecryptScript("qiling", evilPath, "")
	unidbgStr := GenerateStringDecryptScript("unidbg", evilPath, evilPath)
	if strings.Contains(strings.Split(unidbgStr.Code, "\n")[1], "import os") && !strings.HasPrefix(strings.Split(unidbgStr.Code, "\n")[1], "//") {
		t.Errorf("unidbg comment line broke out of // comment")
	}

	if nodePath, err := exec.LookPath("node"); err == nil {
		jsList := []*GeneratedScript{
			stealth,
			GenerateDexUnpackerScript(evilPkg),
			GenerateJavaDeobfScript(evilPkg),
			stalker,
			GenerateVMPRegisterNativesScript(evilPkg),
		}
		for _, sc := range jsList {
			p := filepath.Join(tmp, "adv_"+sanitizeSlug(sc.ID)+".js")
			if err := os.WriteFile(p, []byte(sc.Code), 0644); err != nil {
				t.Fatalf("write %s: %v", p, err)
			}
			if out, err := exec.Command(nodePath, "--check", p).CombinedOutput(); err != nil {
				t.Errorf("adversarial node --check failed for %s: %v\n%s", sc.ID, err, string(out))
			}
		}
	}

	if pyPath, err := exec.LookPath("python3"); err == nil {
		pyList := []*GeneratedScript{ollvm, qiling}
		for _, sc := range pyList {
			p := filepath.Join(tmp, "adv_"+sanitizeSlug(sc.ID)+".py")
			if err := os.WriteFile(p, []byte(sc.Code), 0644); err != nil {
				t.Fatalf("write %s: %v", p, err)
			}
			if out, err := exec.Command(pyPath, "-m", "py_compile", p).CombinedOutput(); err != nil {
				t.Errorf("adversarial py_compile failed for %s: %v\n%s", sc.ID, err, string(out))
			}
		}
	}
}

func TestAnalyzeVMPTrace_TenetUnidbgReadAtAndRetExclusion(t *testing.T) {
	const modBase uint64 = 0x7000000000

	var tb strings.Builder
	// Helper returns (`ret` and `bx lr`) each returning to 5 distinct callers — high fan-out,
	// MUST NOT be misclassified as VMP dispatchers!
	for i := 0; i < 10; i++ {
		callerRet := modBase + 0x5000 + uint64(i%5)*0x20
		callerBx := modBase + 0x6000 + uint64(i%5)*0x20
		fmt.Fprintf(&tb, "0x%x: ret\n", modBase+0x3000)
		fmt.Fprintf(&tb, "0x%x: add x0, x0, #1\n", callerRet)
		fmt.Fprintf(&tb, "0x%x: bx lr\n", modBase+0x3100)
		fmt.Fprintf(&tb, "0x%x: mov r0, r1\n", callerBx)
	}

	// Real VMP dispatcher using Tenet pc=0x... + Unidbg "Memory READ/WRITE at 0x..." lines
	handlers := []uint64{modBase + 0x2000, modBase + 0x2100, modBase + 0x2200, modBase + 0x2300}
	for cycle := 0; cycle < 12; cycle++ {
		h := handlers[cycle%len(handlers)]
		fmt.Fprintf(&tb, "pc=0x%x,x0=0x1,mr=0x%x:01020304\n", modBase+0x1000, modBase+0x90000)
		fmt.Fprintf(&tb, "[12:00:00 100] Memory READ at 0x%x, data size = 4, data value = 0x1234\n", modBase+0x80000)
		fmt.Fprintf(&tb, "0x%x: br x8\n", modBase+0x1008)
		fmt.Fprintf(&tb, "pc=0x%x,mw=0x%x:deadbeef\n", h, modBase+0x90100)
		fmt.Fprintf(&tb, "[12:00:00 101] Memory WRITE at 0x%x, data size = 8, data value = 0x5678\n", modBase+0x90200)
	}

	res := AnalyzeVMPTrace(tb.String(), modBase)

	// Verify ret & bx lr were excluded from DispatcherCandidates
	retAddr := fmt.Sprintf("0x%x", modBase+0x3000)
	bxAddr := fmt.Sprintf("0x%x", modBase+0x3100)
	for _, dc := range res.DispatcherCandidates {
		if dc.Address == retAddr || dc.Address == bxAddr {
			t.Errorf("return instruction %s (%q) polluted DispatcherCandidates", dc.Address, dc.SampleInsn)
		}
	}

	// Real dispatcher 0x7000001008 must be #1
	wantDisp := fmt.Sprintf("0x%x", modBase+0x1008)
	if len(res.DispatcherCandidates) == 0 || res.DispatcherCandidates[0].Address != wantDisp {
		t.Fatalf("expected top dispatcher %s, got %+v", wantDisp, res.DispatcherCandidates)
	}

	// Verify Tenet mr=/mw= AND Unidbg Memory READ/WRITE at 0x... were all captured
	memSet := make(map[string]VMPMemSpot)
	for _, m := range res.MemoryHotspots {
		memSet[m.Address] = m
	}
	for _, wantMem := range []uint64{modBase + 0x90000, modBase + 0x80000, modBase + 0x90100, modBase + 0x90200} {
		key := fmt.Sprintf("0x%x", wantMem)
		if _, ok := memSet[key]; !ok {
			t.Errorf("expected memory hotspot %s from Tenet/Unidbg trace, got %+v", key, memSet)
		}
	}
}
