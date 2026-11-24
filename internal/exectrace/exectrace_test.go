package exectrace

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseMultiFormat(t *testing.T) {
	t.Run("unidbg", func(t *testing.T) {
		raw := `
[15:23:01 100][libsign.so 0x1a20] [a0 00 01 ca] 0x40001a20: "eor x0, x1, x2" x1=0x11223344 x2=0x55667788 => x0=0x444444cc
### Memory READ at 0x7f0010, data size = 4, data value = 0x11223344, pc=0x40001a20
[15:23:01 101][libsign.so 0x1a24] [40 00 00 f9] 0x40001a24: "str x0, [x2]" x0=0x444444cc x2=0x7f0020
Memory WRITE at 0x7f0020, size=4, value=0x444444cc, pc=0x40001a24
[15:23:01 102][libsign.so 0x1a28] [10 00 00 94] 0x40001a28: "bl #0x40001a68"
[15:23:01 103][libsign.so 0x1a68] [c0 03 5f d6] 0x40001a68: "ret"
JNIEnv->NewStringUTF("signed_token") => 0x1234
`
		sess, err := ParseTrace("unidbg-sample", "auto", raw, 0)
		if err != nil {
			t.Fatalf("ParseTrace(unidbg) error: %v", err)
		}
		if sess.Format != FormatUnidbg {
			t.Fatalf("expected FormatUnidbg, got %q", sess.Format)
		}
		if sess.Source != SourceUnidbg {
			t.Fatalf("expected SourceUnidbg, got %q", sess.Source)
		}
		if sess.ModuleBase != 0x40000000 {
			t.Fatalf("expected inferred ModuleBase 0x40000000, got 0x%x", sess.ModuleBase)
		}
		if sess.Arch != "arm64" {
			t.Fatalf("expected arch arm64, got %q", sess.Arch)
		}
		if sess.TargetModule != "libsign.so" {
			t.Fatalf("expected TargetModule libsign.so, got %q", sess.TargetModule)
		}
		if sess.InsnCount != 4 || sess.MemOpCount != 2 || sess.CallCount != 2 {
			t.Fatalf("unexpected counts: insns=%d mem=%d calls=%d", sess.InsnCount, sess.MemOpCount, sess.CallCount)
		}
		ev0 := sess.Events[0]
		if ev0.Offset != 0x1a20 || ev0.Mnemonic != "eor" || ev0.RawBytes != "a00001ca" {
			t.Fatalf("unexpected first event: %+v", ev0)
		}
		if ev0.RegsBefore["x1"] != 0x11223344 || ev0.RegsAfter["x0"] != 0x444444cc {
			t.Fatalf("unexpected regs on ev0: before=%v after=%v", ev0.RegsBefore, ev0.RegsAfter)
		}
		if sess.Summary == nil || len(sess.Summary.CallTree) == 0 {
			t.Fatalf("expected non-empty call tree in summary")
		}
	})

	t.Run("stalker_jsonl", func(t *testing.T) {
		raw := `
[CAP_TRACE] {"seq":1,"ts":1000,"tid":42,"kind":"call","source":"stalker","arch":"arm64","module":"libcrypto.so","module_base":"0x70000000","address":"0x70002000","offset":"0x2000","symbol":"sign_entry"}
[CAP_TRACE] {"seq":2,"ts":1001,"tid":42,"kind":"insn","module":"libcrypto.so","address":"0x70002004","offset":"0x2004","insn":"eor x0, x0, x1","regs":{"x0":"0xdead","x1":"0xbeef"}}
[CAP_TRACE] {"seq":3,"ts":1005,"tid":42,"kind":"ret","module":"libcrypto.so","address":"0x70002008","offset":"0x2008","symbol":"sign_entry","ret_val":"0x6042"}
`
		sess, err := ParseTrace("stalker-sample", "auto", raw, 0)
		if err != nil {
			t.Fatalf("ParseTrace(stalker) error: %v", err)
		}
		if sess.Format != FormatStalker || sess.Source != SourceStalker {
			t.Fatalf("expected stalker format/source, got %q/%q", sess.Format, sess.Source)
		}
		if sess.ModuleBase != 0x70000000 {
			t.Fatalf("expected ModuleBase 0x70000000, got 0x%x", sess.ModuleBase)
		}
		if len(sess.Events) != 3 || sess.Events[1].Mnemonic != "eor" || sess.Events[1].RegsAfter["x0"] != 0xdead {
			t.Fatalf("unexpected stalker events: %+v", sess.Events)
		}
		if len(sess.Summary.CallTree) != 1 || sess.Summary.CallTree[0].DurationMs != 5 {
			t.Fatalf("expected 1 call tree node with duration 5ms, got %+v", sess.Summary.CallTree)
		}
	})

	t.Run("qiling_generic", func(t *testing.T) {
		raw := `
0x00401000: mov r0, r1 ; r0=0x10 r1=0x20
[MEM READ] addr=0x7f0000 size=4 value=0x11223344
0x00401004: add r0, r0, #0x4 ; r0=0x20 => r0=0x24
[MEM WRITE] addr=0x7f0100 size=4 value=0x24
[SYSCALL] openat(dirfd=-100, pathname="/proc/self/maps", flags=0x0) = 3
`
		sess, err := ParseTrace("qiling-sample", "auto", raw, 0x00400000)
		if err != nil {
			t.Fatalf("ParseTrace(qiling) error: %v", err)
		}
		if sess.Format != FormatQiling || sess.Source != SourceQiling {
			t.Fatalf("expected qiling format/source, got %q/%q", sess.Format, sess.Source)
		}
		if sess.InsnCount != 2 || sess.MemOpCount != 2 {
			t.Fatalf("expected 2 insns and 2 mem ops, got %d/%d", sess.InsnCount, sess.MemOpCount)
		}
		if sess.Events[0].Offset != 0x1000 {
			t.Fatalf("expected offset 0x1000, got 0x%x", sess.Events[0].Offset)
		}
		if len(sess.Summary.Syscalls) != 1 || sess.Summary.Syscalls[0].Name != "openat" {
			t.Fatalf("expected openat syscall, got %+v", sess.Summary.Syscalls)
		}
	})

	t.Run("java_call_tree", func(t *testing.T) {
		raw := `
[tid=7] --> com.example.Signer.sign("payload", 12345)
  [tid=7] --> com.example.Crypto.sha256("payload")
  [tid=7] <-- "e3b0c442"
[tid=7] <-- com.example.Signer.sign => "sig_ok"
`
		sess, err := ParseTrace("java-sample", "auto", raw, 0)
		if err != nil {
			t.Fatalf("ParseTrace(java_call) error: %v", err)
		}
		if sess.Format != FormatJavaCall || sess.Source != SourceJava {
			t.Fatalf("expected java_call format/source, got %q/%q", sess.Format, sess.Source)
		}
		if sess.CallCount != 2 {
			t.Fatalf("expected CallCount=2, got %d", sess.CallCount)
		}
		if len(sess.Summary.CallTree) != 1 {
			t.Fatalf("expected 1 root call node, got %d", len(sess.Summary.CallTree))
		}
		root := sess.Summary.CallTree[0]
		if root.Name != "com.example.Signer.sign" || root.RetVal != `"sig_ok"` || len(root.Children) != 1 {
			t.Fatalf("unexpected call tree root: %+v", root)
		}
		if root.Children[0].Name != "com.example.Crypto.sha256" || root.Children[0].RetVal != `"e3b0c442"` {
			t.Fatalf("unexpected child call node: %+v", root.Children[0])
		}
	})

	t.Run("tenet", func(t *testing.T) {
		raw := `
pc=0x40001000,x0=0x1,x1=0x2,mr=0x7f0010:deadbeef
pc=0x40001004,x0=0x3,mw=0x7f0020:03000000
`
		sess, err := ParseTrace("tenet-sample", "auto", raw, 0x40000000)
		if err != nil {
			t.Fatalf("ParseTrace(tenet) error: %v", err)
		}
		if sess.Format != FormatTenet {
			t.Fatalf("expected FormatTenet, got %q", sess.Format)
		}
		if sess.InsnCount != 2 || sess.MemOpCount != 2 {
			t.Fatalf("expected 2 insns and 2 mem ops, got %d/%d", sess.InsnCount, sess.MemOpCount)
		}
		if sess.Events[0].Offset != 0x1000 || sess.Events[1].Kind != KindMemRead || sess.Events[1].MemValueHex != "deadbeef" {
			t.Fatalf("unexpected tenet events: %+v", sess.Events)
		}
	})

	t.Run("empty_error", func(t *testing.T) {
		if _, err := ParseTrace("empty", "auto", "   \n\t  ", 0); err == nil {
			t.Fatal("expected error for empty input")
		}
	})
}

func TestCryptoDetectionAndMemoryRoles(t *testing.T) {
	// Combine SHA-256 constants, AES S-box memory lookup table (read-only >=4 hits),
	// TEA delta, output buffer (write-only), state buffer (read+write), stack, and
	// a custom XOR+ROR hot loop.
	raw := `
[10:00:00 001][libcrypto.so 0x1000] 0x40001000: "mov x0, #0x6a09e667" sp=0x7fff1000 => x0=0x6a09e667
[10:00:00 002][libcrypto.so 0x1004] 0x40001004: "mov x1, #0x428a2f98" => x1=0x428a2f98
[10:00:00 003][libcrypto.so 0x1008] 0x40001008: "mov w2, #0x9e3779b9" => x2=0x9e3779b9
Memory READ at 0x50000000, size=4, value=637c777b
Memory READ at 0x50000004, size=4, value=f26b6fc5
Memory READ at 0x50000008, size=4, value=3001672b
Memory READ at 0x5000000c, size=4, value=fed7ab76
Memory WRITE at 0x60000000, size=4, value=aabbccdd
Memory WRITE at 0x60000004, size=4, value=11223344
Memory WRITE at 0x61000000, size=4, value=00000001
Memory READ at 0x61000000, size=4, value=00000001
Memory WRITE at 0x7fff1010, size=8, value=0102030405060708
[10:00:00 010][libcrypto.so 0x2000] 0x40002000: "eor x3, x3, x4" x3=0x11 x4=0x22 => x3=0x33
[10:00:00 011][libcrypto.so 0x2004] 0x40002004: "ror x3, x3, #7" x3=0x33 => x3=0x6600000000000000
[10:00:00 012][libcrypto.so 0x2008] 0x40002008: "eor x4, x4, x3" x4=0x22 => x4=0x6600000000000022
[10:00:00 013][libcrypto.so 0x200c] 0x4000200c: "lsl x5, x4, #3" x4=0x22 => x5=0x110
[10:00:00 014][libcrypto.so 0x2010] 0x40002010: "b.ne #0x40002000"
[10:00:00 015][libcrypto.so 0x2000] 0x40002000: "eor x3, x3, x4" x3=0x33 x4=0x22 => x3=0x11
[10:00:00 016][libcrypto.so 0x2004] 0x40002004: "ror x3, x3, #7" x3=0x11 => x3=0x2200000000000000
[10:00:00 017][libcrypto.so 0x2008] 0x40002008: "eor x4, x4, x3" x4=0x22 => x4=0x2200000000000022
[10:00:00 018][libcrypto.so 0x200c] 0x4000200c: "lsl x5, x4, #3" x4=0x22 => x5=0x110
[10:00:00 019][libcrypto.so 0x2010] 0x40002010: "b.ne #0x40002000"
[10:00:00 020][libcrypto.so 0x2000] 0x40002000: "eor x3, x3, x4" x3=0x11 x4=0x22 => x3=0x33
`
	sess, err := ParseTrace("crypto-suite", "unidbg", raw, 0)
	if err != nil {
		t.Fatalf("ParseTrace failed: %v", err)
	}
	a := sess.Summary
	if a == nil {
		t.Fatal("expected non-nil TraceAnalysis")
	}

	algos := make(map[string]CryptoPatternHit)
	for _, h := range a.CryptoHits {
		if existing, ok := algos[h.Algorithm]; !ok || h.Confidence > existing.Confidence {
			algos[h.Algorithm] = h
		}
	}

	for _, want := range []string{"SHA-256", "AES", "TEA/XXTEA", "Custom-XOR-Rot"} {
		hit, ok := algos[want]
		if !ok {
			t.Errorf("expected crypto hit for %q, got hits: %+v", want, a.CryptoHits)
		} else if hit.Confidence < 0.60 {
			t.Errorf("expected confidence >= 0.60 for %q, got %.2f", want, hit.Confidence)
		}
	}

	if len(a.HotLoops) == 0 {
		t.Fatalf("expected hot loop detection for 0x40002000..0x40002010")
	}
	if a.HotLoops[0].Iterations < 2 || a.HotLoops[0].CryptoRatio < 0.4 {
		t.Errorf("expected crypto-dense hot loop, got %+v", a.HotLoops[0])
	}

	// Verify inferred memory region roles.
	rolesByPage := make(map[uint64]string)
	for _, r := range a.MemoryRegions {
		rolesByPage[r.BaseAddr&^uint64(0xFFF)] = r.RoleHint
	}
	if rolesByPage[0x50000000] != RoleLookupTable {
		t.Errorf("expected 0x50000000 to be %q, got %q", RoleLookupTable, rolesByPage[0x50000000])
	}
	if rolesByPage[0x60000000] != RoleOutputBuffer {
		t.Errorf("expected 0x60000000 to be %q, got %q", RoleOutputBuffer, rolesByPage[0x60000000])
	}
	if rolesByPage[0x61000000] != RoleState {
		t.Errorf("expected 0x61000000 to be %q, got %q", RoleState, rolesByPage[0x61000000])
	}
	if rolesByPage[0x7fff1000] != RoleStack {
		t.Errorf("expected 0x7fff1000 to be %q, got %q", RoleStack, rolesByPage[0x7fff1000])
	}
}

func TestTaintForwardAndBackwardARM64Chain(t *testing.T) {
	// Realistic ARM64 signing chain:
	//   seq 1: ldr x1, [x10]          ; load secret input from mem[0x7f0000]
	//   seq 2: mov x9, #0xdead        ; IRRELEVANT noise
	//   seq 3: eor x0, x1, x2         ; mix input with key in x2
	//   seq 4: add x8, x9, #0x1       ; IRRELEVANT noise
	//   seq 5: add x0, x0, #0x10      ; add constant offset
	//   seq 6: str x0, [x11]          ; spill intermediate result to mem[0x7f0020]
	//   seq 7: sub x7, x8, x9         ; IRRELEVANT noise
	//   seq 8: mov x0, #0x0           ; overwrite x0 with constant (kills x0 taint!)
	//   seq 9: ldr x3, [x11]          ; reload spilled result from mem[0x7f0020]
	//   seq 10: mov x4, x3            ; move final signature word into x4
	raw := `
[12:00:00 001][libsign.so 0x1000] 0x40001000: "ldr x1, [x10]" x10=0x7f0000 => x1=0x41424344
[12:00:00 002][libsign.so 0x1004] 0x40001004: "mov x9, #0xdead" => x9=0xdead
[12:00:00 003][libsign.so 0x1008] 0x40001008: "eor x0, x1, x2" x1=0x41424344 x2=0x5a5a5a5a => x0=0x1b18191e
[12:00:00 004][libsign.so 0x100c] 0x4000100c: "add x8, x9, #0x1" x9=0xdead => x8=0xdeae
[12:00:00 005][libsign.so 0x1010] 0x40001010: "add x0, x0, #0x10" x0=0x1b18191e => x0=0x1b18192e
[12:00:00 006][libsign.so 0x1014] 0x40001014: "str x0, [x11]" x0=0x1b18192e x11=0x7f0020
[12:00:00 007][libsign.so 0x1018] 0x40001018: "sub x7, x8, x9" x8=0xdeae x9=0xdead => x7=0x1
[12:00:00 008][libsign.so 0x101c] 0x4000101c: "mov x0, #0x0" => x0=0x0
[12:00:00 009][libsign.so 0x1020] 0x40001020: "ldr x3, [x11]" x11=0x7f0020 => x3=0x1b18192e
[12:00:00 010][libsign.so 0x1024] 0x40001024: "mov x4, x3" x3=0x1b18192e => x4=0x1b18192e
`
	sess, err := ParseTrace("signing-chain", "unidbg", raw, 0)
	if err != nil {
		t.Fatalf("ParseTrace error: %v", err)
	}

	// 1. Forward taint from input memory 0x7f0000
	fwd, err := RunTaint(sess, TaintRequest{
		Direction:   TaintForward,
		StartSeq:    1,
		SeedMemAddr: 0x7f0000,
	})
	if err != nil {
		t.Fatalf("RunTaint(forward) error: %v", err)
	}

	wantSeqs := []int{1, 3, 5, 6, 9, 10}
	if len(fwd.TaintedSteps) != len(wantSeqs) {
		t.Fatalf("forward taint expected %d steps (%v), got %d: %+v", len(wantSeqs), wantSeqs, len(fwd.TaintedSteps), fwd.TaintedSteps)
	}
	for i, wantSeq := range wantSeqs {
		if fwd.TaintedSteps[i].Seq != wantSeq {
			t.Errorf("forward step[%d]: want seq %d, got %d (%s)", i, wantSeq, fwd.TaintedSteps[i].Seq, fwd.TaintedSteps[i].Reason)
		}
	}
	// Verify x0 was untainted by seq 8 ("mov x0, #0x0"), while x4 remains live sink!
	hasX4Sink := false
	hasX0Sink := false
	for _, sink := range fwd.SourcesOrSinks {
		if sink == "reg:x4" {
			hasX4Sink = true
		}
		if sink == "reg:x0" {
			hasX0Sink = true
		}
	}
	if !hasX4Sink || hasX0Sink {
		t.Errorf("expected reg:x4 in sinks and reg:x0 killed, got sinks=%v", fwd.SourcesOrSinks)
	}
	if !strings.Contains(fwd.TaintedSteps[3].Reason, "mem[0x7f0020] tainted from x0") {
		t.Errorf("unexpected store taint reason: %q", fwd.TaintedSteps[3].Reason)
	}

	// 2. Backward taint from final sink w4 (tests w4->x4 canonical alias!) at seq 10
	bwd, err := RunTaint(sess, TaintRequest{
		Direction: TaintBackward,
		StartSeq:  10,
		SeedReg:   "w4",
	})
	if err != nil {
		t.Fatalf("RunTaint(backward) error: %v", err)
	}

	if len(bwd.TaintedSteps) != len(wantSeqs) {
		t.Fatalf("backward taint expected %d steps (%v), got %d: %+v", len(wantSeqs), wantSeqs, len(bwd.TaintedSteps), bwd.TaintedSteps)
	}
	for i, wantSeq := range wantSeqs {
		if bwd.TaintedSteps[i].Seq != wantSeq {
			t.Errorf("backward step[%d]: want seq %d, got %d (%s)", i, wantSeq, bwd.TaintedSteps[i].Seq, bwd.TaintedSteps[i].Reason)
		}
	}

	// Irrelevant registers x7, x8, x9 must NEVER appear in tainted regs.
	for _, r := range bwd.TaintedRegs {
		if r == "x7" || r == "x8" || r == "x9" {
			t.Errorf("irrelevant register %s leaked into backward taint: %v", r, bwd.TaintedRegs)
		}
	}

	foundInputMemSource := false
	foundKeyRegSource := false
	for _, src := range bwd.SourcesOrSinks {
		if src == "mem:0x7f0000" {
			foundInputMemSource = true
		}
		if src == "reg:x2" {
			foundKeyRegSource = true
		}
	}
	if !foundInputMemSource || !foundKeyRegSource {
		t.Errorf("expected backward sources to contain mem:0x7f0000 and reg:x2, got %v", bwd.SourcesOrSinks)
	}

	// 3. Value-seeded taint lookup
	valRes, err := RunTaint(sess, TaintRequest{
		Direction:    TaintForward,
		StartSeq:     1,
		SeedValueHex: "0x41424344",
	})
	if err != nil {
		t.Fatalf("RunTaint(value-seed) error: %v", err)
	}
	if len(valRes.TaintedSteps) < 4 {
		t.Fatalf("expected value-seeded forward taint to propagate across chain, got %d steps", len(valRes.TaintedSteps))
	}
}

func TestDiffTracesASLRNormalized(t *testing.T) {
	// Session A loaded at ASLR base 0x40000000; Session B loaded at ASLR base 0x70000000.
	// First 3 instructions match at offsets +0x1000, +0x1004, +0x1008.
	// At index 3, A takes fallthrough +0x100c while B branches to +0x1020.
	// Both reconverge at +0x1040.
	rawA := `
[12:00:00 001][libsign.so 0x1000] 0x40001000: "ldr x0, [x1]" x1=0x100 => x0=0x1
[12:00:00 002][libsign.so 0x1004] 0x40001004: "cmp x0, #0x1" x0=0x1
[12:00:00 003][libsign.so 0x1008] 0x40001008: "b.ne #0x40001020"
[12:00:00 004][libsign.so 0x100c] 0x4000100c: "mov x2, #0xaa" => x2=0xaa
[12:00:00 005][libsign.so 0x1040] 0x40001040: "ret"
`
	rawB := `
[12:05:00 001][libsign.so 0x1000] 0x70001000: "ldr x0, [x1]" x1=0x100 => x0=0x2
[12:05:00 002][libsign.so 0x1004] 0x70001004: "cmp x0, #0x1" x0=0x2
[12:05:00 003][libsign.so 0x1008] 0x70001008: "b.ne #0x70001020"
[12:05:00 004][libsign.so 0x1020] 0x70001020: "mov x2, #0xbb" => x2=0xbb
[12:05:00 005][libsign.so 0x1040] 0x70001040: "ret"
`
	sessA, err := ParseTrace("run-valid", "unidbg", rawA, 0x40000000)
	if err != nil {
		t.Fatalf("ParseTrace A error: %v", err)
	}
	sessB, err := ParseTrace("run-invalid", "unidbg", rawB, 0x70000000)
	if err != nil {
		t.Fatalf("ParseTrace B error: %v", err)
	}

	diff := DiffTraces(sessA, sessB, 10)
	if diff.CommonPrefixLen != 3 {
		t.Fatalf("expected ASLR-normalized CommonPrefixLen=3, got %d (first=%+v)", diff.CommonPrefixLen, diff.FirstDivergence)
	}
	if diff.FirstDivergence == nil {
		t.Fatal("expected non-nil FirstDivergence")
	}
	fd := diff.FirstDivergence
	if fd.Index != 3 || fd.OffsetA != 0x100c || fd.OffsetB != 0x1020 {
		t.Fatalf("unexpected FirstDivergence offsets: %+v", fd)
	}
	if fd.AddressA != 0x4000100c || fd.AddressB != 0x70001020 {
		t.Fatalf("unexpected raw addresses on FirstDivergence: %+v", fd)
	}
	if len(fd.RegDiffs) == 0 || !strings.Contains(fd.RegDiffs[0], "x2: 0xaa vs 0xbb") {
		t.Errorf("expected x2 reg diff, got %v", fd.RegDiffs)
	}
	if len(diff.OnlyInA) != 1 || diff.OnlyInA[0] != "libsign.so+0x100c" {
		t.Errorf("unexpected OnlyInA: %v", diff.OnlyInA)
	}
	if len(diff.OnlyInB) != 1 || diff.OnlyInB[0] != "libsign.so+0x1020" {
		t.Errorf("unexpected OnlyInB: %v", diff.OnlyInB)
	}
	if len(diff.DivergencePoints) != 1 {
		t.Errorf("expected resync after diamond branch (1 divergence), got %d: %+v", len(diff.DivergencePoints), diff.DivergencePoints)
	}
}

func TestCollectorGeneration(t *testing.T) {
	cfg := CollectorConfig{
		TargetPackage: "com.acme.pay",
		TargetModule:  "libsigner.so",
		TargetSymbol:  "Java_com_acme_pay_Sign_compute",
		Arch:          "arm64",
		ClassFilter:   "com.acme.pay.*",
		MethodFilter:  "sign*",
		IncludeRegs:   true,
		IncludeMem:    true,
		IncludeCalls:  true,
		MaxEvents:     20000,
		APKPath:       "/tmp/acme.apk",
		BinaryPath:    "/tmp/libsigner.so",
		RootFS:        "/opt/rootfs/arm64",
	}

	checks := []struct {
		kind     string
		lang     string
		contains []string
	}{
		{"stalker", "javascript", []string{"Stalker.follow", "[CAP_TRACE]", "libsigner.so", "Java_com_acme_pay_Sign_compute", "ctx.x0"}},
		{"java_call", "javascript", []string{"Java.perform", "[CAP_TRACE]", "java_enter", "java_exit", `^com\\.acme\\.pay\\..*$`}},
		{"unidbg", "java", []string{"AndroidEmulatorBuilder.for64Bit()", "traceCode", "traceRead", "traceWrite", "JNIEnv->CallStaticObjectMethodV(%s, %s)%n"}},
		{"qiling", "python", []string{"from qiling import Qiling", "hook_code", "hook_mem_read", "hook_mem_write", "[CAP_TRACE]"}},
	}

	for _, tc := range checks {
		got := GenerateCollector(tc.kind, cfg)
		if got == nil {
			t.Fatalf("GenerateCollector(%q) returned nil", tc.kind)
		}
		if got.Language != tc.lang {
			t.Errorf("%s: expected language %q, got %q", tc.kind, tc.lang, got.Language)
		}
		if strings.Contains(got.Code, "%!") {
			t.Errorf("%s: generated code contains broken fmt verb: %s", tc.kind, got.Code)
		}
		for _, needle := range tc.contains {
			if !strings.Contains(got.Code, needle) {
				t.Errorf("%s: generated code missing %q", tc.kind, needle)
			}
		}
	}
}

func TestStorePersistencePaginationAndExport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "exec-traces")
	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}

	traceRaw := `
[12:00:00 001][libfoo.so 0x1000] 0x40001000: "ldr x1, [x10]" x10=0x7f0000 => x1=0x6a09e667
Memory READ at 0x7f0000, size=4, value=6a09e667, pc=0x40001000
[12:00:00 002][libfoo.so 0x1004] 0x40001004: "eor x0, x1, x2" x1=0x6a09e667 x2=0x11111111 => x0=0x7b18f776
[12:00:00 003][libfoo.so 0x1008] 0x40001008: "str x0, [x11]" x0=0x7b18f776 x11=0x7f0020
Memory WRITE at 0x7f0020, size=4, value=7b18f776, pc=0x40001008
[12:00:00 004][libfoo.so 0x100c] 0x4000100c: "ret"
`
	sess, err := mgr.ImportTrace("foo-trace", "unidbg", traceRaw, 0)
	if err != nil {
		t.Fatalf("ImportTrace error: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected generated session ID")
	}

	// ListSessions omits raw Events slice while keeping Summary intact.
	listed := mgr.ListSessions()
	if len(listed) != 1 {
		t.Fatalf("expected 1 listed session, got %d", len(listed))
	}
	if len(listed[0].Events) != 0 {
		t.Errorf("expected ListSessions to omit raw Events for fast pagination, got %d", len(listed[0].Events))
	}
	if listed[0].Summary == nil || len(listed[0].Summary.CryptoHits) == 0 {
		t.Errorf("expected Summary with SHA-256 crypto hit in listed session")
	}

	// Paginated & filtered QueryEvents
	page1, err := mgr.QueryEvents(sess.ID, EventFilter{Offset: 0, Limit: 2})
	if err != nil {
		t.Fatalf("QueryEvents page1 error: %v", err)
	}
	if page1.Total != 6 || len(page1.Events) != 2 || !page1.HasMore {
		t.Fatalf("unexpected page1: total=%d len=%d hasMore=%v", page1.Total, len(page1.Events), page1.HasMore)
	}

	memPage, err := mgr.QueryEvents(sess.ID, EventFilter{Kind: KindMemWrite})
	if err != nil {
		t.Fatalf("QueryEvents mem_write error: %v", err)
	}
	if memPage.Total != 1 || memPage.Events[0].MemAddr != 0x7f0020 {
		t.Fatalf("unexpected mem_write filter result: %+v", memPage)
	}

	searchPage, err := mgr.QueryEvents(sess.ID, EventFilter{Search: "eor"})
	if err != nil {
		t.Fatalf("QueryEvents search error: %v", err)
	}
	if searchPage.Total != 1 || searchPage.Events[0].Mnemonic != "eor" {
		t.Fatalf("unexpected search filter result: %+v", searchPage)
	}

	// Export to Tenet and verify re-parsing round-trip
	tenetOut, err := mgr.ExportTrace(sess.ID, ExportTenet)
	if err != nil {
		t.Fatalf("ExportTrace(tenet) error: %v", err)
	}
	if !strings.Contains(tenetOut, "pc=0x40001000") || !strings.Contains(tenetOut, "mr=0x7f0000:6a09e667") || !strings.Contains(tenetOut, "mw=0x7f0020:7b18f776") {
		t.Fatalf("unexpected Tenet export:\n%s", tenetOut)
	}
	reparsedTenet, err := ParseTrace("re-tenet", "tenet", tenetOut, 0x40000000)
	if err != nil || reparsedTenet.InsnCount != 4 || reparsedTenet.MemOpCount != 2 {
		t.Fatalf("Tenet round-trip failed: err=%v sess=%+v", err, reparsedTenet)
	}

	// Export to JSONL and verify re-parsing round-trip
	jsonlOut, err := mgr.ExportTrace(sess.ID, ExportJSONL)
	if err != nil {
		t.Fatalf("ExportTrace(jsonl) error: %v", err)
	}
	reparsedJSONL, err := ParseTrace("re-jsonl", "jsonl", jsonlOut, 0x40000000)
	if err != nil || reparsedJSONL.TotalEvents != sess.TotalEvents {
		t.Fatalf("JSONL round-trip failed: err=%v got=%d want=%d", err, reparsedJSONL.TotalEvents, sess.TotalEvents)
	}

	// Export to Markdown report
	mdOut, err := mgr.ExportTrace(sess.ID, ExportMarkdown)
	if err != nil {
		t.Fatalf("ExportTrace(markdown) error: %v", err)
	}
	for _, section := range []string{"# Execution Trace Report: foo-trace", "## Detected Cryptographic Patterns", "SHA-256", "## Memory Regions"} {
		if !strings.Contains(mdOut, section) {
			t.Errorf("Markdown export missing %q:\n%s", section, mdOut)
		}
	}

	// Reload from disk with a brand-new Manager instance
	mgr2, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager reload error: %v", err)
	}
	reloaded, ok := mgr2.GetSession(sess.ID)
	if !ok || reloaded.TotalEvents != sess.TotalEvents {
		t.Fatalf("expected persisted session after reload, ok=%v sess=%+v", ok, reloaded)
	}

	// RunTaint via Manager
	tr, err := mgr2.RunTaint(TaintRequest{
		SessionID: sess.ID,
		Direction: TaintForward,
		StartSeq:  1,
		SeedReg:   "x1",
	})
	if err != nil || len(tr.TaintedSteps) < 2 {
		t.Fatalf("Manager.RunTaint failed: err=%v steps=%d", err, len(tr.TaintedSteps))
	}

	// DiffSessions via Manager
	sess2, err := mgr2.ImportTrace("foo-trace-2", "unidbg", traceRaw, 0)
	if err != nil {
		t.Fatalf("ImportTrace second session error: %v", err)
	}
	diffRes, err := mgr2.DiffSessions(sess.ID, sess2.ID, 10)
	if err != nil || diffRes.FirstDivergence != nil || diffRes.CommonPrefixLen != 4 {
		t.Fatalf("Manager.DiffSessions failed: err=%v diff=%+v", err, diffRes)
	}

	// DeleteSession removes from memory and disk
	if err := mgr2.DeleteSession(sess.ID); err != nil {
		t.Fatalf("DeleteSession error: %v", err)
	}
	if _, ok := mgr2.GetSession(sess.ID); ok {
		t.Fatal("expected deleted session to be removed")
	}

	// Read-only filesystem graceful degradation check (Unix)
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		roDir := filepath.Join(t.TempDir(), "ro-traces")
		if err := os.MkdirAll(roDir, 0555); err != nil {
			t.Fatalf("mkdir roDir: %v", err)
		}
		defer os.Chmod(roDir, 0755)

		roMgr, err := NewManager(roDir)
		if err != nil {
			t.Fatalf("NewManager on read-only dir should not fail: %v", err)
		}
		roSess, err := roMgr.ImportTrace("in-mem-only", "unidbg", traceRaw, 0)
		if err != nil || roSess.TotalEvents == 0 {
			t.Fatalf("ImportTrace on read-only dir should succeed in-memory: err=%v", err)
		}
	}
}

func TestTaintPairAndX86AndAdditionalCrypto(t *testing.T) {
	t.Run("arm64_stp_ldp", func(t *testing.T) {
		raw := `
[12:00:00 001][libfoo.so 0x100] 0x40000100: "stp x1, x2, [sp, #0x10]" x1=0xaaaa x2=0xbbbb sp=0x7f0000
[12:00:00 002][libfoo.so 0x104] 0x40000104: "ldp x3, x4, [sp, #0x10]" sp=0x7f0000 => x3=0xaaaa x4=0xbbbb
[12:00:00 003][libfoo.so 0x108] 0x40000108: "add x5, x4, #0x1" x4=0xbbbb => x5=0xbbbc
`
		sess, err := ParseTrace("pair-taint", "unidbg", raw, 0)
		if err != nil {
			t.Fatalf("ParseTrace error: %v", err)
		}
		// Seed x2 (second register in stp -> lands at sp+0x18 -> reloads into x4, NOT x3!)
		fwd, err := RunTaint(sess, TaintRequest{Direction: TaintForward, StartSeq: 1, SeedReg: "x2"})
		if err != nil {
			t.Fatalf("RunTaint forward pair error: %v", err)
		}
		if len(fwd.TaintedSteps) != 3 {
			t.Fatalf("expected 3 steps (stp -> ldp -> add), got %d: %+v", len(fwd.TaintedSteps), fwd.TaintedSteps)
		}
		for _, r := range fwd.TaintedRegs {
			if r == "x3" {
				t.Errorf("x3 should not be tainted when only x2 (slot 1) was tainted: %v", fwd.TaintedRegs)
			}
		}
		bwd, err := RunTaint(sess, TaintRequest{Direction: TaintBackward, StartSeq: 3, SeedReg: "x5"})
		if err != nil {
			t.Fatalf("RunTaint backward pair error: %v", err)
		}
		if len(bwd.TaintedSteps) != 3 {
			t.Fatalf("expected 3 backward steps, got %d: %+v", len(bwd.TaintedSteps), bwd.TaintedSteps)
		}
	})

	t.Run("x86_64_taint_and_zero_kill", func(t *testing.T) {
		raw := `
0x401000: mov rax, rdi ; rdi=0x1122 => rax=0x1122
0x401003: lea rbx, [rax + 0x10] ; rax=0x1122 => rbx=0x1132
0x401007: xor eax, eax ; => rax=0x0
0x401009: add rcx, rax ; rcx=0x5 rax=0x0 => rcx=0x5
0x40100c: add rdx, rbx ; rdx=0x1 rbx=0x1132 => rdx=0x1133
`
		sess, err := ParseTrace("x64-taint", "qiling", raw, 0x400000)
		if err != nil {
			t.Fatalf("ParseTrace x64 error: %v", err)
		}
		if sess.Arch != "x86_64" {
			t.Fatalf("expected x86_64 arch, got %q", sess.Arch)
		}
		fwd, err := RunTaint(sess, TaintRequest{Direction: TaintForward, StartSeq: 1, SeedReg: "rdi"})
		if err != nil {
			t.Fatalf("RunTaint x64 error: %v", err)
		}
		// Expect seq 1 (mov rax, rdi), seq 2 (lea rbx), seq 5 (add rdx, rbx);
		// seq 3 (xor eax, eax) kills rax so seq 4 (add rcx, rax) must NOT taint rcx!
		if len(fwd.TaintedSteps) != 3 {
			t.Fatalf("expected 3 tainted steps, got %d: %+v", len(fwd.TaintedSteps), fwd.TaintedSteps)
		}
		for _, r := range fwd.TaintedRegs {
			if r == "rcx" {
				t.Errorf("rcx should not be tainted after xor eax, eax killed rax: %v", fwd.TaintedRegs)
			}
		}
	})

	t.Run("additional_crypto_constants", func(t *testing.T) {
		raw := `
0x401000: mov w0, #0xd76aa478 ; => w0=0xd76aa478
0x401004: mov w1, #0x5a827999 ; => w1=0x5a827999
0x401008: mov w2, #0x7380166f ; => w2=0x7380166f
0x40100c: mov w3, #0xa3b1bac6 ; => w3=0xa3b1bac6
0x401010: mov w4, #0x61707865 ; => w4=0x61707865
0x401014: mov w5, #0xedb88320 ; => w5=0xedb88320
`
		sess, err := ParseTrace("all-algos", "qiling", raw, 0x400000)
		if err != nil {
			t.Fatalf("ParseTrace all-algos error: %v", err)
		}
		found := make(map[string]bool)
		for _, h := range sess.Summary.CryptoHits {
			found[h.Algorithm] = true
		}
		for _, want := range []string{"MD5", "SHA-1", "SM3", "SM4", "ChaCha20", "CRC32"} {
			if !found[want] {
				t.Errorf("missing expected algorithm %q in %+v", want, sess.Summary.CryptoHits)
			}
		}
	})
}
