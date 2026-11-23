package trace

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
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

type testELFSymbol struct {
	name     string
	addr     uint64
	imported bool
}

// buildMinimalELF64 constructs a valid 64-bit little-endian AArch64 ELF shared
// library with .shstrtab, .dynstr, .dynsym, .text, and .rodata sections so
// Go's debug/elf parses exports, imports, and strings cleanly in hermetic tests.
func buildMinimalELF64(t *testing.T, syms []testELFSymbol, rodataStrings []string) []byte {
	t.Helper()

	// Build .shstrtab
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
	offText := addShStr(".text")
	offRodata := addShStr(".rodata")

	// Build .dynstr and .dynsym (index 0 is always STN_UNDEF)
	dynstr := []byte{0}
	var dynsym bytes.Buffer
	writeSym := func(nameOff uint32, info byte, shndx uint16, val uint64) {
		var s elf.Sym64
		s.Name = nameOff
		s.Info = info
		s.Shndx = shndx
		s.Value = val
		s.Size = 16
		_ = binary.Write(&dynsym, binary.LittleEndian, s)
	}
	writeSym(0, 0, 0, 0) // STN_UNDEF

	for _, sym := range syms {
		nameOff := uint32(len(dynstr))
		dynstr = append(dynstr, sym.name...)
		dynstr = append(dynstr, 0)
		shndx := uint16(4) // .text
		val := sym.addr
		if sym.imported {
			shndx = uint16(elf.SHN_UNDEF)
			val = 0
		}
		info := elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC)
		writeSym(nameOff, info, shndx, val)
	}

	textData := make([]byte, 16)
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
	// sections payload sequentially aligned to 8 bytes
	// section header table at end (6 headers * 64 bytes)
	var out bytes.Buffer
	out.Write(make([]byte, 64)) // placeholder header

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
		{Name: offText, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), Addr: 0x1000, Off: textOff, Size: textSize, Addralign: 4},
		{Name: offRodata, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC), Addr: 0x2000, Off: rodataOff, Size: rodataSize, Addralign: 1},
	}
	for _, h := range headers {
		_ = binary.Write(&out, binary.LittleEndian, h)
	}

	raw := out.Bytes()
	var ehdr elf.Header64
	copy(ehdr.Ident[:4], []byte{0x7f, 'E', 'L', 'F'})
	ehdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ehdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ehdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	ehdr.Type = uint16(elf.ET_DYN)
	ehdr.Machine = uint16(elf.EM_AARCH64)
	ehdr.Version = uint32(elf.EV_CURRENT)
	ehdr.Shoff = shOff
	ehdr.Ehsize = 64
	ehdr.Shentsize = 64
	ehdr.Shnum = uint16(len(headers))
	ehdr.Shstrndx = 1

	var hdrBuf bytes.Buffer
	_ = binary.Write(&hdrBuf, binary.LittleEndian, ehdr)
	copy(raw[:64], hdrBuf.Bytes())
	return raw
}

func TestDeduplicateSOFiles(t *testing.T) {
	in := []string{
		"/tmp/lib/lib_armeabi-v7a_libfoo.so",
		"/tmp/lib/lib_arm64-v8a_libfoo.so",
		"/tmp/lib/lib_x86_libfoo.so",
		"/tmp/lib/lib_armeabi-v7a_libonly32.so",
		"/tmp/lib/lib_x86_64_libonly32.so",
		"/tmp/lib/lib_arm64-v8a_libsign.so",
	}
	got := deduplicateSOFiles(in)
	if len(got) != 3 {
		t.Fatalf("deduplicateSOFiles len = %d, want 3: %v", len(got), got)
	}
	joined := strings.Join(got, "|")
	for _, want := range []string{"lib_arm64-v8a_libfoo.so", "lib_armeabi-v7a_libonly32.so", "lib_arm64-v8a_libsign.so"} {
		if !strings.Contains(joined, want) {
			t.Errorf("deduplicateSOFiles missing %q in %v", want, got)
		}
	}
}

func TestScanELFFileAndMediaRelevanceFiltering(t *testing.T) {
	dir := t.TempDir()

	// 1. High-relevance security signing library.
	signELF := buildMinimalELF64(t, []testELFSymbol{
		{name: "JNI_OnLoad", addr: 0x1040},
		{name: "Java_com_example_Signer_nativeSign", addr: 0x1200},
		{name: "EVP_DigestInit", imported: true},
		{name: "unrelated_libc_func", imported: true},
	}, []string{"https://api.example.com/v1/checkout", "hmac_sha256_secret", "ordinary_string"})
	signPath := filepath.Join(dir, "lib_arm64-v8a_libsigner.so")
	if err := os.WriteFile(signPath, signELF, 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Heavy media engine library (like libSVAEEngineLib.so) with 45 Java_* exports
	// and NO Java/flow match — must be ELF-scanned (fast, exports capped at 30)
	// AND skipped from r2 disassembly (EligibleForR2 == false)!
	var mediaSyms []testELFSymbol
	for i := 0; i < 45; i++ {
		mediaSyms = append(mediaSyms, testELFSymbol{
			name: fmt.Sprintf("Java_com_media_SVAE_renderFrame%d", i),
			addr: uint64(0x2000 + i*0x20),
		})
	}
	mediaELF := buildMinimalELF64(t, mediaSyms, []string{"audio_frame_buffer"})
	mediaPath := filepath.Join(dir, "lib_arm64-v8a_libSVAEEngineLib.so")
	if err := os.WriteFile(mediaPath, mediaELF, 0o644); err != nil {
		t.Fatal(err)
	}

	signRes, err := scanELFFile(signPath, []string{"nativeSign"}, map[string]bool{"libsigner.so": true}, []string{"/v1/checkout"})
	if err != nil {
		t.Fatalf("scanELFFile(sign): %v", err)
	}
	if !signRes.IsELF || !signRes.EligibleForR2 || !signRes.HasExplicitSignal {
		t.Fatalf("expected signRes eligible with explicit signal: %+v", signRes)
	}
	if len(signRes.Refs) != 2 {
		t.Fatalf("signRes.Refs len = %d, want 2 (nativeSign + JNI_OnLoad): %+v", len(signRes.Refs), signRes.Refs)
	}
	if len(signRes.Refs[0].Imports) != 1 || signRes.Refs[0].Imports[0] != "EVP_DigestInit" {
		t.Errorf("signRes imports = %v, want [EVP_DigestInit]", signRes.Refs[0].Imports)
	}
	if len(signRes.TargetFuncs) != 2 || signRes.TargetFuncs[0].Name != "nativeSign" || signRes.TargetFuncs[0].Addr != 0x1200 {
		t.Errorf("unexpected TargetFuncs order: %+v", signRes.TargetFuncs)
	}

	mediaRes, err := scanELFFile(mediaPath, []string{"nativeSign"}, map[string]bool{"libsigner.so": true}, []string{"/v1/checkout"})
	if err != nil {
		t.Fatalf("scanELFFile(media): %v", err)
	}
	if !mediaRes.HeavyMedia {
		t.Error("expected libSVAEEngineLib.so to be flagged HeavyMedia=true")
	}
	if mediaRes.EligibleForR2 {
		t.Error("expected libSVAEEngineLib.so to be excluded from r2 disasm (EligibleForR2=false)")
	}
	if len(mediaRes.Refs) != maxELFExportsPerSO {
		t.Errorf("mediaRes.Refs = %d, want capped at %d", len(mediaRes.Refs), maxELFExportsPerSO)
	}

	// selectR2Candidates must include libsigner.so and exclude libSVAEEngineLib.so.
	cands := selectR2Candidates([]*elfScanResult{mediaRes, signRes}, maxR2SOFiles)
	if len(cands) != 1 || cands[0].LibName != "libsigner.so" {
		t.Fatalf("selectR2Candidates = %+v, want only libsigner.so", cands)
	}
}

func TestBuildTargetedR2Args_NoGlobalAA(t *testing.T) {
	targets := []elfTargetFunc{
		{Name: "nativeSign", Addr: 0x1200},
		{Name: "JNI_OnLoad", Addr: 0x1040},
	}
	args := buildTargetedR2Args("/tmp/libsec.so", targets)
	joined := strings.Join(args, " ")

	if strings.Contains(joined, "; aa") || strings.Contains(joined, " aa;") || strings.HasPrefix(joined, "aa ") {
		t.Fatalf("targeted r2 args must NEVER invoke global 'aa': %s", joined)
	}
	for _, want := range []string{"bin.relocs.apply=false", "anal.limits=true", "anal.maxreflines=20", "s 0x1200; af; pdfj; s 0x1040; af; pdfj"} {
		if !strings.Contains(joined, want) {
			t.Errorf("targeted r2 args missing %q: %s", want, joined)
		}
	}
}

func TestEnrichWithR2Context_SingleInvocationAndBudgetEnforcement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub scripts require POSIX")
	}
	dir := t.TempDir()

	// Create 4 high-relevance .so files and a slow fake r2 that sleeps 400ms per call.
	// With per-SO timeout = 150ms and overall Stage 7 R2Budget = 320ms, the whole
	// trace must finish promptly (< 1.5s) while keeping all Pure-Go ELF findings!
	entries := map[string][]byte{
		"classes.dex": []byte("/api/v1/budget_test"),
	}
	for i := 1; i <= 4; i++ {
		elfBytes := buildMinimalELF64(t, []testELFSymbol{
			{name: "JNI_OnLoad", addr: 0x1040},
			{name: fmt.Sprintf("Java_com_example_Sec%d_sign", i), addr: 0x1200},
		}, []string{"/api/v1/budget_test", "aes_secret_key"})
		entries[fmt.Sprintf("lib/arm64-v8a/libsec%d.so", i)] = elfBytes
		// Duplicate armeabi-v7a ABI to prove deduplication cuts 8 -> 4.
		entries[fmt.Sprintf("lib/armeabi-v7a/libsec%d.so", i)] = elfBytes
	}
	apkPath := writeTestZip(t, filepath.Join(dir, "budget.apk"), entries)

	invokeLog := filepath.Join(dir, "r2-invokes.txt")
	fakeSlowR2 := writeFakeExecScript(t, dir, "fake-r2-slow", fmt.Sprintf(`
if [ "$1" = "-v" ]; then
  echo "radare2 5.9.0"
  exit 0
fi
echo "$*" >> %q
sleep 0.4
echo '{"ops":[{"type":"call","disasm":"bl sym.sha256"}]}'
`, invokeLog), 0)

	flow := &types.Flow{ID: "f-b", Method: "POST", URL: "https://api.example.com/api/v1/budget_test", Host: "api.example.com", Path: "/api/v1/budget_test"}
	start := time.Now()
	res, err := TraceContext(context.Background(), flow, Options{
		APKPath:   apkPath,
		OutputDir: filepath.Join(dir, "out"),
		JadxPath:  filepath.Join(dir, "no-jadx"),
		R2Path:    fakeSlowR2,
		R2Timeout: 140 * time.Millisecond,
		R2Budget:  320 * time.Millisecond,
	}, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("TraceContext: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Stage 7 budget not enforced: took %v, want < 2s", elapsed)
	}
	// Pure-Go ELF findings MUST be preserved even when r2 timed out!
	if len(res.NativeTrace) != 8 {
		t.Fatalf("expected 8 Pure-Go ELF NativeRefs (4 unique .so * 2 funcs), got %d", len(res.NativeTrace))
	}

	// Verify r2 never received global `aa`.
	loggedBytes, _ := os.ReadFile(invokeLog)
	logged := string(loggedBytes)
	if strings.Contains(logged, "; aa") || strings.Contains(logged, "izzj") {
		t.Errorf("Phase 7B must use targeted 's 0x...; af; pdfj' only, saw: %s", logged)
	}
}
