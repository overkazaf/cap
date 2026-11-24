package retools

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	captrace "github.com/overkazaf/cap/internal/trace"
)

// --- Synthetic ELF64 Builder (Pure-Go Hermetic Fixture) --------------------

type synthELFSym struct {
	name     string
	addr     uint64
	size     uint64
	imported bool
}

// buildSyntheticELF64 produces a valid 64-bit little-endian AArch64 ELF shared
// library with PT_GNU_STACK (non-executable -> NX=true), PT_GNU_RELRO,
// .dynamic (DT_BIND_NOW -> Full RELRO), .dynsym, .dynstr, .text, and .rodata.
func buildSyntheticELF64(t *testing.T, syms []synthELFSym, rodataStrings []string, fullRELRO bool, nx bool) []byte {
	t.Helper()

	shstrtab := []byte{0}
	addShStr := func(s string) uint32 {
		off := uint32(len(shstrtab))
		shstrtab = append(shstrtab, s...)
		shstrtab = append(shstrtab, 0)
		return off
	}
	offShstr := addShStr(".shstrtab")
	offDynstr := addShStr(".dynstr")
	offDynsym := addShStr(".dynsym")
	offDynamic := addShStr(".dynamic")
	offText := addShStr(".text")
	offRodata := addShStr(".rodata")

	dynstr := []byte{0}
	var dynsym bytes.Buffer
	writeSym := func(nameOff uint32, info byte, shndx uint16, val, size uint64) {
		var s elf.Sym64
		s.Name = nameOff
		s.Info = info
		s.Shndx = shndx
		s.Value = val
		s.Size = size
		_ = binary.Write(&dynsym, binary.LittleEndian, s)
	}
	writeSym(0, 0, 0, 0, 0) // STN_UNDEF

	for _, sym := range syms {
		nameOff := uint32(len(dynstr))
		dynstr = append(dynstr, sym.name...)
		dynstr = append(dynstr, 0)
		shndx := uint16(5) // .text section index
		val := sym.addr
		sz := sym.size
		if sz == 0 {
			sz = 32
		}
		if sym.imported {
			shndx = uint16(elf.SHN_UNDEF)
			val = 0
			sz = 0
		}
		writeSym(nameOff, elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC), shndx, val, sz)
	}

	var dynamic bytes.Buffer
	if fullRELRO {
		_ = binary.Write(&dynamic, binary.LittleEndian, elf.Dyn64{Tag: int64(elf.DT_BIND_NOW), Val: 0})
		_ = binary.Write(&dynamic, binary.LittleEndian, elf.Dyn64{Tag: int64(elf.DT_FLAGS_1), Val: elfDF1Now | elfDF1Pie})
	}
	_ = binary.Write(&dynamic, binary.LittleEndian, elf.Dyn64{Tag: int64(elf.DT_NULL), Val: 0})

	// Put realistic AArch64 instructions (nop; ret) inside .text at 0x1000..0x1400
	textData := make([]byte, 0x400)
	for i := 0; i < len(textData); i += 4 {
		// ARM64 RET: 0xd65f03c0
		binary.LittleEndian.PutUint32(textData[i:], 0xd65f03c0)
	}

	var rodata bytes.Buffer
	for _, s := range rodataStrings {
		rodata.WriteString(s)
		rodata.WriteByte(0)
	}
	if rodata.Len() == 0 {
		rodata.WriteByte(0)
	}

	// Layout:
	// [0..64): ELF64 header
	// [64..64+2*56): Program headers (PT_GNU_STACK, PT_GNU_RELRO)
	// sections payload (8-byte aligned)
	// section header table at end (7 headers * 64 bytes)
	const phOff = uint64(64)
	const phNum = uint16(2)
	const phEntSize = uint16(56)

	var out bytes.Buffer
	out.Write(make([]byte, int(phOff)+int(phNum)*int(phEntSize)))

	appendSection := func(data []byte) (uint64, uint64) {
		for out.Len()%8 != 0 {
			out.WriteByte(0)
		}
		off := uint64(out.Len())
		out.Write(data)
		return off, uint64(len(data))
	}

	shstrOff, shstrSize := appendSection(shstrtab)
	dynstrOff, dynstrSize := appendSection(dynstr)
	dynsymOff, dynsymSize := appendSection(dynsym.Bytes())
	dynamicOff, dynamicSize := appendSection(dynamic.Bytes())
	textOff, textSize := appendSection(textData)
	rodataOff, rodataSize := appendSection(rodata.Bytes())

	for out.Len()%8 != 0 {
		out.WriteByte(0)
	}
	shOff := uint64(out.Len())

	headers := []elf.Section64{
		{}, // 0: NULL
		{Name: offShstr, Type: uint32(elf.SHT_STRTAB), Off: shstrOff, Size: shstrSize, Addralign: 1},
		{Name: offDynstr, Type: uint32(elf.SHT_STRTAB), Flags: uint64(elf.SHF_ALLOC), Off: dynstrOff, Size: dynstrSize, Addralign: 1},
		{Name: offDynsym, Type: uint32(elf.SHT_DYNSYM), Flags: uint64(elf.SHF_ALLOC), Off: dynsymOff, Size: dynsymSize, Link: 2, Info: 1, Addralign: 8, Entsize: 24},
		{Name: offDynamic, Type: uint32(elf.SHT_DYNAMIC), Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE), Addr: 0x3000, Off: dynamicOff, Size: dynamicSize, Link: 2, Addralign: 8, Entsize: 16},
		{Name: offText, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: 0x1000, Off: textOff, Size: textSize, Addralign: 4},
		{Name: offRodata, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC), Addr: 0x2000, Off: rodataOff, Size: rodataSize, Addralign: 1},
	}
	for _, h := range headers {
		_ = binary.Write(&out, binary.LittleEndian, h)
	}

	raw := out.Bytes()

	// Write ELF64 header
	var ehdr elf.Header64
	copy(ehdr.Ident[:4], []byte{0x7f, 'E', 'L', 'F'})
	ehdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ehdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ehdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	ehdr.Ident[elf.EI_OSABI] = byte(elf.ELFOSABI_LINUX)
	ehdr.Type = uint16(elf.ET_DYN)
	ehdr.Machine = uint16(elf.EM_AARCH64)
	ehdr.Version = uint32(elf.EV_CURRENT)
	ehdr.Entry = 0x1040
	ehdr.Phoff = phOff
	ehdr.Shoff = shOff
	ehdr.Ehsize = 64
	ehdr.Phentsize = phEntSize
	ehdr.Phnum = phNum
	ehdr.Shentsize = 64
	ehdr.Shnum = uint16(len(headers))
	ehdr.Shstrndx = 1

	var hdrBuf bytes.Buffer
	_ = binary.Write(&hdrBuf, binary.LittleEndian, ehdr)
	copy(raw[:64], hdrBuf.Bytes())

	// Write program headers
	stackFlags := uint32(elf.PF_R | elf.PF_W)
	if !nx {
		stackFlags |= uint32(elf.PF_X)
	}
	progs := []elf.Prog64{
		{Type: uint32(elf.PT_GNU_STACK), Flags: stackFlags, Align: 16},
		{Type: uint32(elf.PT_GNU_RELRO), Flags: uint32(elf.PF_R), Off: dynamicOff, Vaddr: 0x3000, Paddr: 0x3000, Filesz: dynamicSize, Memsz: dynamicSize, Align: 8},
	}
	var phBuf bytes.Buffer
	for _, ph := range progs {
		_ = binary.Write(&phBuf, binary.LittleEndian, ph)
	}
	copy(raw[phOff:int(phOff)+phBuf.Len()], phBuf.Bytes())

	return raw
}

func writeFakeExec(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- 1. Toolchain Probing Tests --------------------------------------------

func TestDetectToolchainWithFakeBinaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub scripts require POSIX")
	}

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	fakeR2 := writeFakeExec(t, binDir, "r2", `echo "radare2 5.9.4 0 @ darwin-arm64"`)
	fakeJava := writeFakeExec(t, binDir, "java", `echo 'openjdk version "17.0.10" 2024-01-16' >&2`)
	fakeJavac := writeFakeExec(t, binDir, "javac", `echo 'javac 17.0.10'`)
	fakeMvn := writeFakeExec(t, binDir, "mvn", `echo 'Apache Maven 3.9.6'`)
	fakePy := writeFakeExec(t, binDir, "python3", `
echo "PY=3.11.9"
echo "QILING=1.4.6"
echo "ANGR=9.2.100"
`)

	unidbgDir := filepath.Join(dir, "unidbg")
	if err := os.MkdirAll(filepath.Join(unidbgDir, "lib"), 0755); err != nil {
		t.Fatal(err)
	}
	jarPath := filepath.Join(unidbgDir, "lib", "unidbg-android-0.9.7.jar")
	if err := os.WriteFile(jarPath, []byte("PK\x03\x04fakejar"), 0644); err != nil {
		t.Fatal(err)
	}

	rootfsDir := filepath.Join(dir, "rootfs", "arm64_linux")
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		t.Fatal(err)
	}

	info := DetectToolchain(ToolchainConfig{
		R2Path:       fakeR2,
		JavaPath:     fakeJava,
		MvnPath:      fakeMvn,
		UnidbgDir:    unidbgDir,
		PythonPath:   fakePy,
		QilingRootFS: rootfsDir,
	})

	if !info.R2Ready || info.R2.Version != "5.9.4" {
		t.Errorf("R2 probe mismatch: %+v", info.R2)
	}
	if !info.Java.Ready || info.Java.Version != "17.0.10" || info.JavacPath != fakeJavac {
		t.Errorf("Java probe mismatch: java=%+v javac=%q", info.Java, info.JavacPath)
	}
	if !info.Mvn.Ready || info.Mvn.Version != "3.9.6" {
		t.Errorf("Mvn probe mismatch: %+v", info.Mvn)
	}
	if !info.UnidbgReady || !info.Unidbg.Ready || info.Unidbg.Version != "0.9.7" || len(info.UnidbgJars) != 1 {
		t.Errorf("Unidbg probe mismatch: unidbg=%+v jars=%v ready=%v", info.Unidbg, info.UnidbgJars, info.UnidbgReady)
	}
	if !info.Python.Ready || info.Python.Version != "3.11.9" {
		t.Errorf("Python probe mismatch: %+v", info.Python)
	}
	if !info.QilingReady || info.Qiling.Version != "1.4.6" || info.QilingRootFS != rootfsDir {
		t.Errorf("Qiling probe mismatch: qiling=%+v rootfs=%q", info.Qiling, info.QilingRootFS)
	}
	if !info.AngrReady || info.Angr.Version != "9.2.100" {
		t.Errorf("Angr probe mismatch: %+v", info.Angr)
	}
	if len(info.Issues) != 0 {
		t.Errorf("expected zero issues for complete fake toolchain, got %v", info.Issues)
	}

	// Test missing / partial toolchain reporting actionable issues + Maven pom.xml Unidbg detection
	pomDir := filepath.Join(dir, "unidbg-maven")
	if err := os.MkdirAll(pomDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(`<project><artifactId>unidbg-parent</artifactId><version>0.9.8</version></project>`), 0644); err != nil {
		t.Fatal(err)
	}
	partialPy := writeFakeExec(t, binDir, "python-bare", `
echo "PY=3.12.1"
echo "QILING="
echo "ANGR="
`)
	missInfo := DetectToolchain(ToolchainConfig{
		R2Path:       filepath.Join(dir, "no-r2"),
		JavaPath:     filepath.Join(dir, "no-java"),
		MvnPath:      filepath.Join(dir, "no-mvn"),
		UnidbgDir:    pomDir,
		PythonPath:   partialPy,
		QilingRootFS: filepath.Join(dir, "no-rootfs"),
	})
	if missInfo.R2Ready || missInfo.UnidbgReady || missInfo.QilingReady || missInfo.AngrReady {
		t.Errorf("expected engines not ready: %+v", missInfo)
	}
	if !missInfo.Unidbg.Ready || missInfo.Unidbg.Version != "0.9.8" {
		t.Errorf("expected Unidbg Maven pom.xml ready with version 0.9.8, got %+v", missInfo.Unidbg)
	}
	if !missInfo.Python.Ready || missInfo.Qiling.Ready || missInfo.Angr.Ready {
		t.Errorf("expected bare Python ready without qiling/angr: py=%+v q=%+v a=%+v", missInfo.Python, missInfo.Qiling, missInfo.Angr)
	}
	if len(missInfo.Issues) < 5 {
		t.Errorf("expected >= 5 actionable issues, got %d: %v", len(missInfo.Issues), missInfo.Issues)
	}
}

// --- 2. Pure-Go ELF Fallback & Host Binary Tests ---------------------------

func TestAnalyzeBinaryPureGoELFFallback(t *testing.T) {
	dir := t.TempDir()
	elfBytes := buildSyntheticELF64(t, []synthELFSym{
		{name: "JNI_OnLoad", addr: 0x1040, size: 64},
		{name: "Java_com_example_Signer_nativeSign", addr: 0x1100, size: 96},
		{name: "helper_sha256", addr: 0x1200, size: 48},
		{name: "__stack_chk_fail", imported: true},
		{name: "EVP_DigestInit", imported: true},
	}, []string{
		"https://api.example.com/v1/checkout",
		"hmac_sha256_salt_v2",
	}, true, true)

	elfPath := filepath.Join(dir, "libsigner.so")
	if err := os.WriteFile(elfPath, elfBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// Force pure-Go fallback by supplying a nonexistent r2 binary path
	res, err := AnalyzeBinary(context.Background(), elfPath, filepath.Join(dir, "missing-r2"))
	if err != nil {
		t.Fatalf("AnalyzeBinary pure-Go ELF failed: %v", err)
	}

	if res.Engine != EnginePureGoELF {
		t.Fatalf("Engine = %q, want %q", res.Engine, EnginePureGoELF)
	}
	if res.Arch != "aarch64" || res.Bits != 64 || res.Endian != "little" || res.Format != "elf64" {
		t.Errorf("unexpected ELF arch/format: arch=%q bits=%d endian=%q format=%q", res.Arch, res.Bits, res.Endian, res.Format)
	}
	if !res.Mitigations.PIE || !res.Mitigations.NX || !res.Mitigations.Canary || res.Mitigations.RELRO != RELROFull || !res.Mitigations.Stripped {
		t.Errorf("unexpected ELF mitigations: %+v", res.Mitigations)
	}
	if len(res.Exports) != 3 || len(res.Functions) != 3 {
		t.Errorf("expected 3 exports & 3 functions, got exports=%d funcs=%d", len(res.Exports), len(res.Functions))
	}
	if len(res.Imports) != 2 {
		t.Errorf("expected 2 imports, got %d: %+v", len(res.Imports), res.Imports)
	}
	foundJNI := false
	for _, fn := range res.Functions {
		if fn.Name == "Java_com_example_Signer_nativeSign" && fn.IsJNI && fn.Addr == "0x1100" {
			foundJNI = true
		}
	}
	if !foundJNI {
		t.Errorf("missing JNI function in pure-Go ELF result: %+v", res.Functions)
	}
	foundStr := false
	for _, s := range res.Strings {
		if s.Value == "hmac_sha256_salt_v2" && s.Section == ".rodata" {
			foundStr = true
		}
	}
	if !foundStr {
		t.Errorf("missing expected .rodata string in %+v", res.Strings)
	}

	// Verify partial RELRO + non-NX detection as well
	partialELF := buildSyntheticELF64(t, []synthELFSym{{name: "JNI_OnLoad", addr: 0x1040}}, []string{"test_str"}, false, false)
	partialPath := filepath.Join(dir, "libpartial.so")
	if err := os.WriteFile(partialPath, partialELF, 0644); err != nil {
		t.Fatal(err)
	}
	res2, err := AnalyzeBinary(context.Background(), partialPath, filepath.Join(dir, "missing-r2"))
	if err != nil {
		t.Fatalf("AnalyzeBinary partial ELF: %v", err)
	}
	if res2.Mitigations.RELRO != RELROPartial || res2.Mitigations.NX || res2.Mitigations.Canary {
		t.Errorf("expected partial RELRO, NX=false, Canary=false; got %+v", res2.Mitigations)
	}

	// Verify InspectFunction pure-Go ELF fallback returns symbol address & raw bytes hex dump
	fnDetail, err := InspectFunction(context.Background(), elfPath, "Java_com_example_Signer_nativeSign", filepath.Join(dir, "missing-r2"))
	if err != nil {
		t.Fatalf("InspectFunction pure-Go fallback: %v", err)
	}
	if fnDetail.Engine != EnginePureGoELF || fnDetail.Addr != "0x1100" || !strings.Contains(fnDetail.Disasm, "raw bytes") {
		t.Errorf("unexpected pure-Go InspectFunction detail: %+v", fnDetail)
	}

	// Also verify pure-Go fallback handles os.Executable() (ELF on Linux, Mach-O on macOS)
	if selfPath, err := os.Executable(); err == nil {
		selfRes, err := AnalyzeBinary(context.Background(), selfPath, filepath.Join(dir, "missing-r2"))
		if err != nil {
			t.Fatalf("AnalyzeBinary(os.Executable()) failed: %v", err)
		}
		if selfRes.Bits != 64 && selfRes.Bits != 32 {
			t.Errorf("unexpected self binary bits: %d", selfRes.Bits)
		}
	}
}

// --- 3. radare2 JSON Parsing, InspectFunction, and Shell-Escape Rejection --

func TestRadare2AnalyzeInspectAndCommandSafety(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub scripts require POSIX")
	}

	dir := t.TempDir()
	dummyBin := filepath.Join(dir, "libtarget.so")
	if err := os.WriteFile(dummyBin, buildSyntheticELF64(t, []synthELFSym{{name: "JNI_OnLoad", addr: 0x1040}}, []string{"hello"}, true, true), 0644); err != nil {
		t.Fatal(err)
	}

	fakeR2 := writeFakeExec(t, dir, "fake-r2", `
cmd=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-c" ]; then
    cmd="$arg"
  fi
  prev="$arg"
done
case "$cmd" in
  "aaa;ij;aflj;iEj;iij;izzj")
    echo "WARN: harmless r2 diagnostic line"
    echo '{"core":{"format":"elf64","size":4096},"bin":{"arch":"arm","bits":64,"endian":"little","bintype":"elf","class":"ELF64","os":"linux","pic":true,"nx":true,"canary":true,"relro":"full","stripped":false,"baddr":4096}}'
    echo '[{"name":"sym.Java_com_demo_Sign_sign","offset":4608,"size":128,"signature":"int sign(void)","callrefs":[{"addr":4864,"type":"CALL","at":4620}]}]'
    echo '[{"name":"Java_com_demo_Sign_sign","vaddr":4608,"size":128,"type":"FUNC","bind":"GLOBAL"}]'
    echo '[{"name":"EVP_MD_CTX_new","plt":4200,"type":"FUNC","bind":"GLOBAL","libname":"libcrypto.so"}]'
    echo '[{"vaddr":8192,"length":13,"section":".rodata","type":"ascii","string":"sign_salt_123"}]'
    ;;
  *"__CAP_PDFJ__"*)
    case "$cmd" in
      *"fallback_pdc"*)
        echo "__CAP_PDFJ__"
        echo ""
        echo "__CAP_PDJ__"
        echo '[{"offset":4864,"bytes":"c0035fd6","disasm":"ret","type":"ret"}]'
        echo "__CAP_AXTJ__"
        echo '[{"from":4620,"type":"CALL","opcode":"bl 0x1300","fcn_name":"sym.caller"}]'
        echo "__CAP_AXFJ__"
        echo '[]'
        echo "__CAP_PDG__"
        echo "Cannot find pdg plugin"
        echo "__CAP_PDC__"
        echo "void fallback_pdc() { return; }"
        ;;
      *)
        echo "__CAP_PDFJ__"
        echo '{"name":"sym.Java_com_demo_Sign_sign","addr":4608,"size":128,"ops":[{"offset":4608,"bytes":"fd7bbfa9","disasm":"stp x29, x30, [sp, -0x10]!","type":"push"},{"offset":4612,"bytes":"c0035fd6","disasm":"ret","type":"ret"}]}'
        echo "__CAP_PDJ__"
        echo '[]'
        echo "__CAP_AXTJ__"
        echo '[{"from":4160,"type":"CALL","opcode":"bl 0x1200","fcn_name":"sym.JNI_OnLoad"}]'
        echo "__CAP_AXFJ__"
        echo '[{"from":4612,"to":4864,"type":"CALL","opcode":"bl sym.hmac","name":"sym.hmac"}]'
        echo "__CAP_PDG__"
        echo "int Java_com_demo_Sign_sign(void *env) { return 42; }"
        echo "__CAP_PDC__"
        echo "pseudo fallback"
        ;;
    esac
    ;;
  *)
    echo "R2_OK: $cmd"
    ;;
esac
`)

	// 1. AnalyzeBinary with fake r2
	analysis, err := AnalyzeBinary(context.Background(), dummyBin, fakeR2)
	if err != nil {
		t.Fatalf("AnalyzeBinary(r2): %v", err)
	}
	if analysis.Engine != EngineRadare2 {
		t.Fatalf("Engine = %q, want %q", analysis.Engine, EngineRadare2)
	}
	if analysis.Arch != "aarch64" || analysis.Bits != 64 || !analysis.Mitigations.PIE || !analysis.Mitigations.NX || !analysis.Mitigations.Canary || analysis.Mitigations.RELRO != RELROFull {
		t.Errorf("unexpected r2 analysis metadata: arch=%q bits=%d mit=%+v", analysis.Arch, analysis.Bits, analysis.Mitigations)
	}
	if len(analysis.Functions) != 1 || !analysis.Functions[0].IsJNI || analysis.Functions[0].Addr != "0x1200" {
		t.Errorf("unexpected r2 functions: %+v", analysis.Functions)
	}
	if len(analysis.Exports) != 1 || len(analysis.Imports) != 1 || len(analysis.Strings) != 1 || len(analysis.XRefs) != 1 {
		t.Errorf("unexpected r2 counts: exp=%d imp=%d str=%d xrefs=%d",
			len(analysis.Exports), len(analysis.Imports), len(analysis.Strings), len(analysis.XRefs))
	}

	// 2. InspectFunction with pdg + pdfj + xrefs
	detail, err := InspectFunction(context.Background(), dummyBin, "sym.Java_com_demo_Sign_sign", fakeR2)
	if err != nil {
		t.Fatalf("InspectFunction(pdg): %v", err)
	}
	if detail.PseudoCEngine != "pdg" || !strings.Contains(detail.PseudoC, "return 42") {
		t.Errorf("expected pdg pseudoC, got engine=%q code=%q", detail.PseudoCEngine, detail.PseudoC)
	}
	if len(detail.DisasmLines) != 2 || len(detail.XRefsTo) != 1 || len(detail.XRefsFrom) != 1 {
		t.Errorf("unexpected disasm/xrefs: lines=%d to=%d from=%d", len(detail.DisasmLines), len(detail.XRefsTo), len(detail.XRefsFrom))
	}

	// 3. InspectFunction fallback to pdj + pdc when pdfj/pdg are unavailable
	detailFB, err := InspectFunction(context.Background(), dummyBin, "fallback_pdc", fakeR2)
	if err != nil {
		t.Fatalf("InspectFunction(pdc fallback): %v", err)
	}
	if detailFB.PseudoCEngine != "pdc" || !strings.Contains(detailFB.PseudoC, "fallback_pdc") {
		t.Errorf("expected pdc fallback, got engine=%q code=%q", detailFB.PseudoCEngine, detailFB.PseudoC)
	}
	if len(detailFB.DisasmLines) != 1 || detailFB.DisasmLines[0].Disasm != "ret" {
		t.Errorf("expected pdj fallback line, got %+v", detailFB.DisasmLines)
	}

	// 4. Reject unsafe function targets in InspectFunction
	if _, err := InspectFunction(context.Background(), dummyBin, "main; !id", fakeR2); err == nil {
		t.Errorf("expected InspectFunction to reject command injection in target")
	}

	// 5. RunR2Command allows safe read-only commands
	res, err := RunR2Command(context.Background(), dummyBin, "ij; iEj; iz~sign", fakeR2)
	if err != nil {
		t.Fatalf("RunR2Command safe failed: %v", err)
	}
	if !strings.Contains(res.Output, "R2_OK: ij; iEj; iz~sign") {
		t.Errorf("unexpected RunR2Command output: %q", res.Output)
	}

	// 6. RunR2Command rejects shell escapes & write/config mutations
	unsafeCmds := []string{
		"!id",
		"!!ls -la",
		"ij; !whoami",
		"iz | sh",
		"px 16 > /tmp/pwn",
		"px `id`",
		"s $(whoami)",
		"wx 9090",
		"wa nop",
		"oo+",
		"#!python",
		"e cfg.sandbox=false; ij",
		"ij\n!id",
		".evil.r2",
		"=h 8080",
	}
	for _, bad := range unsafeCmds {
		if _, err := RunR2Command(context.Background(), dummyBin, bad, fakeR2); err == nil {
			t.Errorf("expected RunR2Command to reject unsafe command %q", bad)
		}
	}
}

// --- 4. Harness Generation & DeepTrace Codegen Tests -----------------------

func TestParseJNISymbol(t *testing.T) {
	cls, meth, sig, ok := ParseJNISymbol("Java_com_example_shop_net_AuthClient_native_1sign__Ljava_lang_String_2J")
	if !ok {
		t.Fatalf("ParseJNISymbol failed")
	}
	if cls != "com/example/shop/net/AuthClient" {
		t.Errorf("class = %q, want com/example/shop/net/AuthClient", cls)
	}
	if meth != "native_sign" {
		t.Errorf("method = %q, want native_sign", meth)
	}
	if sig != "(Ljava/lang/String;J)Ljava/lang/String;" {
		t.Errorf("sig = %q", sig)
	}

	cls2, meth2, _, ok2 := ParseJNISymbol("sym.Java_com_demo_Signer_sign")
	if !ok2 || cls2 != "com/demo/Signer" || meth2 != "sign" {
		t.Errorf("simple JNI parse mismatch: (%q, %q, %v)", cls2, meth2, ok2)
	}

	if _, _, _, ok3 := ParseJNISymbol("JNI_OnLoad"); ok3 {
		t.Errorf("JNI_OnLoad should not parse as Java_* symbol")
	}
}

func TestHarnessGeneratorsAndDeepTraceCodegen(t *testing.T) {
	tr := &captrace.TraceResult{
		FlowID:  "flow-99",
		Method:  "POST",
		URL:     "https://api.example.com/v2/order?sign=abc123&ts=1700000000",
		Package: "com.example.shop",
		APKPath: "/tmp/shop.apk",
		APKInfo: &captrace.APKInfo{
			Package: "com.example.shop",
			SOFiles: []string{
				"lib/armeabi-v7a/libsigner.so",
				"lib/arm64-v8a/libsigner.so",
			},
		},
		JavaTrace: []captrace.JavaRef{
			{
				Class:         "com.example.shop.sec.NativeSigner",
				Method:        "buildHeader",
				CallsNative:   true,
				NativeMethods: []string{"nativeSign", "libsigner.so"},
			},
		},
		DexXRefs: []captrace.DexMethodRef{
			{
				ClassName:    "com.example.shop.sec.NativeSigner",
				MethodName:   "nativeSign",
				Descriptor:   "(Ljava/lang/String;J)Ljava/lang/String;",
				IsNative:     true,
				LoadsLibrary: []string{"signer"},
			},
		},
		NativeTrace: []captrace.NativeRef{
			{
				SOFile:   "lib/arm64-v8a/libsigner.so",
				Function: "Java_com_example_shop_sec_NativeSigner_nativeSign",
				Address:  "0x14a8",
			},
		},
		Report: &captrace.TraceReport{
			ParamProvenance: []captrace.ParamTrace{
				{Name: "sign", Role: "sign", SampleValue: "abc123"},
				{Name: "x-auth", Role: "auth", SampleValue: "tok999"},
			},
		},
	}

	// 1. DeepTrace -> Unidbg (standard + HTTP signer mode)
	uStd, err := GenerateFromTrace(tr, EngineUnidbg, GenerateOptions{})
	if err != nil {
		t.Fatalf("GenerateFromTrace(unidbg): %v", err)
	}
	for _, want := range []string{
		"AndroidEmulatorBuilder.for64Bit()",
		"DalvikModule",
		"AbstractJni",
		"callStaticJniMethodObject",
		"com/example/shop/sec/NativeSigner",
		"nativeSign(Ljava/lang/String;J)Ljava/lang/String;",
		"/tmp/shop.apk",
		"libsigner.so",
		"[CAP_RE]",
	} {
		if !strings.Contains(uStd.Code, want) {
			t.Errorf("Unidbg harness missing %q", want)
		}
	}
	if len(uStd.SignParams) != 2 {
		t.Errorf("expected 2 SignParams, got %v", uStd.SignParams)
	}

	uHTTP, err := GenerateFromTrace(tr, EngineUnidbg, GenerateOptions{HTTPServerMode: true, HTTPPort: 9123, Arch: "arm"})
	if err != nil {
		t.Fatalf("GenerateFromTrace(unidbg http): %v", err)
	}
	for _, want := range []string{"HttpServer", "AndroidEmulatorBuilder.for32Bit()", "/sign", "9123"} {
		if !strings.Contains(uHTTP.Code, want) {
			t.Errorf("Unidbg HTTP signer harness missing %q", want)
		}
	}

	// 2. DeepTrace -> Qiling
	ql, err := GenerateFromTrace(tr, EngineQiling, GenerateOptions{RootFS: "/opt/rootfs/arm64_linux"})
	if err != nil {
		t.Fatalf("GenerateFromTrace(qiling): %v", err)
	}
	for _, want := range []string{
		"from qiling import Qiling",
		"/opt/rootfs/arm64_linux",
		"0x14a8",
		"ql.arch.regs.x0",
		"ql.hook_code",
		"[CAP_RE]",
	} {
		if !strings.Contains(ql.Code, want) {
			t.Errorf("Qiling harness missing %q", want)
		}
	}

	// 3. DeepTrace -> angr
	ag, err := GenerateFromTrace(tr, EngineAngr, GenerateOptions{FindAddr: "0x1520", AvoidAddr: "0x1550", InputLen: 16})
	if err != nil {
		t.Fatalf("GenerateFromTrace(angr): %v", err)
	}
	for _, want := range []string{
		"angr.Project",
		"claripy.BVS",
		"simgr.explore",
		"call_state",
		"0x14a8",
		"0x1520",
		"0x1550",
		"[CAP_RE]",
	} {
		if !strings.Contains(ag.Code, want) {
			t.Errorf("angr harness missing %q", want)
		}
	}

	// 4. DeepTrace -> radare2
	r2h, err := GenerateFromTrace(tr, EngineRadare2, GenerateOptions{})
	if err != nil {
		t.Fatalf("GenerateFromTrace(radare2): %v", err)
	}
	if err := ValidateR2Command(r2h.Code); err != nil {
		t.Errorf("generated r2 harness failed safety validation: %v", err)
	}

	// 5. Unknown engine rejected
	if _, err := GenerateFromTrace(tr, "ghidra-unknown", GenerateOptions{}); err == nil {
		t.Errorf("expected error for unknown engine")
	}
}

// --- 5. Project Store CRUD, Hot-Reload, and Read-Only Degradation ----------

func TestProjectStoreCRUDHotReloadAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	store, err := NewProjectStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	all := store.List()
	if len(all) < 7 {
		t.Fatalf("expected >= 7 built-in projects across engines, got %d", len(all))
	}
	for _, eng := range []string{EngineUnidbg, EngineQiling, EngineAngr, EngineRadare2} {
		if len(store.ListByEngine(eng)) == 0 {
			t.Errorf("expected built-in projects for engine %q", eng)
		}
	}

	// Save custom project
	saved, err := store.Save(REProject{
		Name:         "My Sign Emulator",
		Engine:       EngineUnidbg,
		Description:  "Custom signer",
		BinaryPath:   "/tmp/libsign.so",
		TargetClass:  "com/demo/Sign",
		TargetMethod: "sign",
		Code:         "public class MySign {}",
		Tags:         []string{"custom", "sign"},
	})
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if saved.Builtin || !strings.HasPrefix(saved.ID, "user:") {
		t.Fatalf("unexpected saved project metadata: %+v", saved)
	}

	got, ok := store.Get(saved.ID)
	if !ok || got.Name != "My Sign Emulator" {
		t.Fatalf("Get(%q) = (%+v, %v)", saved.ID, got, ok)
	}

	// Saving a built-in project forks it into user-owned project
	builtin, ok := store.Get("builtin:angr-symbolic-solve")
	if !ok {
		t.Fatalf("expected builtin:angr-symbolic-solve")
	}
	forked, err := store.Save(*builtin)
	if err != nil {
		t.Fatalf("forking built-in failed: %v", err)
	}
	if forked.Builtin || strings.HasPrefix(forked.ID, "builtin:") {
		t.Errorf("forked built-in should become user-owned: %+v", forked)
	}

	// External disk write -> hot-reload picks it up automatically
	extFile := filepath.Join(dir, "external-qiling.json")
	if err := os.WriteFile(extFile, []byte(`{"id":"user:external-qiling","name":"External Qiling","engine":"qiling","code":"print('hi')"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if ext, ok := store.Get("user:external-qiling"); !ok || ext.Name != "External Qiling" {
		t.Fatalf("expected hot-reload to pick up externally written project")
	}

	// Built-in cannot be deleted; custom can be deleted
	if err := store.Delete("builtin:unidbg-jni-sign"); err == nil {
		t.Errorf("expected error deleting built-in template")
	}
	if err := store.Delete(saved.ID); err != nil {
		t.Fatalf("Delete custom project failed: %v", err)
	}
	if _, ok := store.Get(saved.ID); ok {
		t.Errorf("deleted project should no longer exist")
	}

	// Graceful read-only degradation: point store under a regular file so MkdirAll fails
	blockerFile := filepath.Join(dir, "blocker-file")
	if err := os.WriteFile(blockerFile, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	roStore, err := NewProjectStore(filepath.Join(blockerFile, "re-projects"))
	if err != nil {
		t.Fatalf("NewProjectStore should degrade gracefully on unwritable path: %v", err)
	}
	if len(roStore.List()) < 7 {
		t.Errorf("built-in projects should remain readable on unwritable store dir")
	}
}

// --- 6. Live Async Job Execution, Structured Results, and Cancellation -----

func TestManagerLiveJobExecutionAndCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell mock scripts require POSIX")
	}

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Fake python3: probes ok for qiling+angr, and executes whatever shell/mock commands we pass via script content
	fakePy := writeFakeExec(t, binDir, "python3", `
if [ "$1" = "-c" ]; then
  echo "PY=3.11.8"
  echo "QILING=1.4.6"
  echo "ANGR=9.2.100"
  exit 0
fi
script="$2"
if grep -q "MODE_SLEEP" "$script"; then
  echo "starting long solve..."
  sleep 30
  exit 0
fi
echo "exploring paths..."
echo "minor warning on stderr" >&2
echo '[CAP_RE] {"kind":"solution","target":"verify_token","solution_utf8":"cap_secret_42","solution_hex":"636170"}'
exit 0
`)

	// Fake javac + java + unidbg jar
	fakeJava := writeFakeExec(t, binDir, "java", `
if [ "$1" = "-version" ]; then
  echo 'openjdk version "17.0.9"' >&2
  exit 0
fi
echo "running unidbg harness..."
echo '[CAP_RE] {"kind":"signature","sign":"deadbeef1234"}'
exit 0
`)
	_ = writeFakeExec(t, binDir, "javac", `
echo "compiled ok"
exit 0
`)
	unidbgDir := filepath.Join(dir, "unidbg")
	if err := os.MkdirAll(unidbgDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unidbgDir, "unidbg-0.9.7.jar"), []byte("jar"), 0644); err != nil {
		t.Fatal(err)
	}

	fakeR2 := writeFakeExec(t, binDir, "r2", `
if [ "$1" = "-v" ]; then
  echo "radare2 5.9.4"
  exit 0
fi
echo "R2_JOB_OUTPUT"
exit 0
`)
	fakeMvn := writeFakeExec(t, binDir, "mvn", `echo "Apache Maven 3.9.6"`)

	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Shutdown()

	mgr.SetToolchainConfig(ToolchainConfig{
		R2Path:     fakeR2,
		MvnPath:    fakeMvn,
		PythonPath: fakePy,
		JavaPath:   fakeJava,
		UnidbgDir:  unidbgDir,
	})

	var (
		cbMu     sync.Mutex
		logCount int
		statuses []string
	)
	mgr.SetCallbacks(func(ev JobLogEvent) {
		cbMu.Lock()
		logCount++
		cbMu.Unlock()
	}, func(st *JobState) {
		cbMu.Lock()
		statuses = append(statuses, st.Status)
		cbMu.Unlock()
	})

	// 1. Run mock angr job -> verify structured [CAP_RE] result & callbacks
	st, err := mgr.StartJob(RunJobRequest{
		Engine:      EngineAngr,
		ProjectName: "Mock angr Solve",
		Code:        "# mock angr script\nprint('ok')\n",
	})
	if err != nil {
		t.Fatalf("StartJob(angr) failed: %v", err)
	}
	if !st.Running || st.Status != StatusRunning {
		t.Fatalf("expected running initial state: %+v", st)
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finalSt, err := mgr.WaitJob(waitCtx)
	if err != nil {
		t.Fatalf("WaitJob(angr) failed: %v", err)
	}
	if finalSt.Status != StatusDone || finalSt.ExitCode != 0 || finalSt.Running {
		t.Fatalf("expected done exit=0, got status=%q exit=%d err=%q", finalSt.Status, finalSt.ExitCode, finalSt.Error)
	}
	if len(finalSt.Results) != 1 || finalSt.Results[0].Kind != "solution" || finalSt.Results[0].Payload["solution_utf8"] != "cap_secret_42" {
		t.Fatalf("unexpected extracted results: %+v", finalSt.Results)
	}
	cbMu.Lock()
	gotLogs := logCount
	gotStatuses := append([]string(nil), statuses...)
	cbMu.Unlock()
	if gotLogs < 3 || len(gotStatuses) < 2 {
		t.Errorf("expected live callbacks, got logs=%d statuses=%v", gotLogs, gotStatuses)
	}

	// 2. Run mock Unidbg 2-step javac+java job hydrated from a saved project
	savedProj, err := mgr.SaveProject(REProject{
		Name:   "Saved Unidbg Test",
		Engine: EngineUnidbg,
		Code:   "public class SavedSigner { public static void main(String[] a) {} }",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.StartJob(RunJobRequest{ProjectID: savedProj.ID}); err != nil {
		t.Fatalf("StartJob(unidbg) failed: %v", err)
	}
	unidbgFinal, err := mgr.WaitJob(waitCtx)
	if err != nil {
		t.Fatalf("WaitJob(unidbg) failed: %v", err)
	}
	if unidbgFinal.Status != StatusDone || len(unidbgFinal.Results) != 1 || unidbgFinal.Results[0].Payload["sign"] != "deadbeef1234" {
		t.Fatalf("unexpected Unidbg job result: status=%q err=%q results=%+v", unidbgFinal.Status, unidbgFinal.Error, unidbgFinal.Results)
	}

	// 3. Run long-sleeping job & test prompt cancellation via Unix process-group kill
	if _, err := mgr.StartJob(RunJobRequest{
		Engine:      EngineQiling,
		ProjectName: "Long Sleep Job",
		Code:        "# MODE_SLEEP\n",
	}); err != nil {
		t.Fatalf("StartJob(sleep) failed: %v", err)
	}
	// Brief pause so child process starts before cancelling
	time.Sleep(80 * time.Millisecond)

	cancelStart := time.Now()
	if err := mgr.CancelJob(); err != nil {
		t.Fatalf("CancelJob failed: %v", err)
	}
	if elapsed := time.Since(cancelStart); elapsed > 2*time.Second {
		t.Errorf("CancelJob took too long: %v", elapsed)
	}
	cancelledSt := mgr.GetJobState()
	if cancelledSt.Running || cancelledSt.Status != StatusCancelled {
		t.Fatalf("expected cancelled state, got running=%v status=%q", cancelledSt.Running, cancelledSt.Status)
	}

	// 4. ClearJobLogs clears events & results
	mgr.ClearJobLogs()
	cleared := mgr.GetJobState()
	if len(cleared.Events) != 0 || len(cleared.Results) != 0 || cleared.EventCount != 0 {
		t.Errorf("ClearJobLogs did not reset snapshot: %+v", cleared)
	}

	// 5. Verify radare2 job rejects unsafe commands and runs safe read-only commands
	targetFile := filepath.Join(dir, "unidbg", "unidbg-0.9.7.jar")
	if _, err := mgr.StartJob(RunJobRequest{
		Engine:     EngineRadare2,
		BinaryPath: targetFile,
		R2Command:  "!id",
	}); err == nil {
		t.Errorf("expected radare2 job to reject unsafe command")
	}
	if _, err := mgr.StartJob(RunJobRequest{
		Engine:     EngineRadare2,
		BinaryPath: targetFile,
		R2Command:  "ij; iEj",
	}); err != nil {
		t.Fatalf("StartJob(radare2 safe) failed: %v", err)
	}
	r2Final, err := mgr.WaitJob(waitCtx)
	if err != nil || r2Final.Status != StatusDone {
		t.Fatalf("expected radare2 job done, got status=%q err=%v", r2Final.Status, err)
	}

	// 6. Verify TimeoutSec terminates hanging jobs cleanly
	if _, err := mgr.StartJob(RunJobRequest{
		Engine:     EngineQiling,
		Code:       "# MODE_SLEEP\n",
		TimeoutSec: 1,
	}); err != nil {
		t.Fatalf("StartJob(timeout) failed: %v", err)
	}
	toSt, err := mgr.WaitJob(waitCtx)
	if err != nil {
		t.Fatalf("WaitJob(timeout): %v", err)
	}
	if toSt.Status != StatusError || !strings.Contains(toSt.Error, "timed out") {
		t.Errorf("expected timeout error status, got status=%q err=%q", toSt.Status, toSt.Error)
	}

	// 7. Verify bounded event ring buffer (MaxJobEvents)
	mgr.mu.Lock()
	mgr.state = &JobState{ID: "ring-test", Status: StatusRunning}
	mgr.mu.Unlock()
	for i := 0; i < MaxJobEvents+50; i++ {
		mgr.appendLog("ring-test", JobLogEvent{Stream: "stdout", Level: "info", Message: fmt.Sprintf("line-%d", i)})
	}
	ringSt := mgr.GetJobState()
	if len(ringSt.Events) != MaxJobEvents || ringSt.EventCount != MaxJobEvents+50 {
		t.Errorf("ring buffer mismatch: len=%d eventCount=%d", len(ringSt.Events), ringSt.EventCount)
	}
}
