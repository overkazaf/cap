package trace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

func TestParseJadxProgress(t *testing.T) {
	cases := []struct {
		line       string
		wantOK     bool
		wantPct    int
		wantSubstr string
	}{
		{"INFO  - progress: 42% (1200 of 2900)", true, 42, "42%"},
		{"progress: 100%", true, 100, "100%"},
		{"processing (50/200)", true, 25, "25%"},
		{"INFO - loading ...", true, -1, "loading"},
		{"   ", false, 0, ""},
		{"random unrelated stderr", false, 0, ""},
	}
	for _, tc := range cases {
		pct, detail, ok := ParseJadxProgress(tc.line)
		if ok != tc.wantOK || pct != tc.wantPct {
			t.Errorf("ParseJadxProgress(%q) = (%d, %q, %v), want (%d, contains %q, %v)",
				tc.line, pct, detail, ok, tc.wantPct, tc.wantSubstr, tc.wantOK)
		}
		if tc.wantSubstr != "" && !strings.Contains(detail, tc.wantSubstr) {
			t.Errorf("ParseJadxProgress(%q) detail = %q, want substring %q", tc.line, detail, tc.wantSubstr)
		}
	}
}

func TestParsePMPathOutput(t *testing.T) {
	raw := strings.Join([]string{
		"package:/data/app/~~abc/com.example.shop-1/split_config.en.apk",
		"package:/data/app/~~abc/com.example.shop-1/split_config.armeabi_v7a.apk",
		"package:/data/app/~~abc/com.example.shop-1/base.apk",
		"package:/data/app/~~abc/com.example.shop-1/split_config.arm64_v8a.apk",
		"package:/data/app/~~abc/com.example.shop-1/split_config.xxhdpi.apk",
	}, "\n")

	base, splits := parsePMPathOutput(raw)
	if !strings.HasSuffix(base, "/base.apk") {
		t.Fatalf("base = %q, want suffix /base.apk", base)
	}
	if len(splits) != 2 {
		t.Fatalf("splits = %v, want 2 ABI splits", splits)
	}
	if !strings.Contains(splits[0], "arm64_v8a") {
		t.Fatalf("expected arm64_v8a prioritized first, got %v", splits)
	}
}

func TestDecodeR2AnalysisNoisyPrefixAndEmptyFuncs(t *testing.T) {
	// Leading warning banner before JSON array.
	noisy := []byte("WARN: some r2 banner\n[x] Analyze all flags\n" +
		`[{"vaddr":4096,"string":"https://api.example.com/sign"}]` + "\n" +
		`[{"offset":8192,"name":"sym.Java_com_example_Sign_nativeSign"}]`)
	strs, funcs, err := decodeR2Analysis(noisy)
	if err != nil {
		t.Fatalf("decodeR2Analysis(noisy) error = %v", err)
	}
	if len(strs) != 1 || len(funcs) != 1 {
		t.Fatalf("got %d strs, %d funcs; want 1, 1", len(strs), len(funcs))
	}

	// Empty functions array alongside valid strings array.
	emptyFuncs := []byte("WARN: banner\n" + `[{"vaddr":16,"string":"aes_key"}][]`)
	strs2, funcs2, err := decodeR2Analysis(emptyFuncs)
	if err != nil {
		t.Fatalf("decodeR2Analysis(emptyFuncs) error = %v", err)
	}
	if len(strs2) != 1 || len(funcs2) != 0 {
		t.Fatalf("got %d strs, %d funcs; want 1, 0", len(strs2), len(funcs2))
	}
}

func TestCollectSearchTermsEnrichment(t *testing.T) {
	flow := &types.Flow{
		Method:     "POST",
		URL:        "https://api.example.com/api/v2/order/create?sign=abc&page=1&app_key=k",
		Host:       "api.example.com",
		Path:       "/api/v2/order/create",
		ReqHeaders: map[string]string{"X-Signature": "deadbeef", "Accept": "application/json"},
		SignParams: []string{"nonce_token"},
	}
	terms := collectSearchTerms(flow, []string{"custom_hint"})
	joined := strings.Join(terms, " | ")
	for _, want := range []string{"/api/v2/order/create", "order/create", "nonce_token", "sign", "app_key", "X-Signature", "custom_hint"} {
		if !strings.Contains(joined, want) {
			t.Errorf("collectSearchTerms missing %q in %v", want, terms)
		}
	}
}

func TestCheckTools(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub scripts require POSIX")
	}
	dir := t.TempDir()
	fakeADB := writeFakeExecScript(t, dir, "adb", `echo "Android Debug Bridge version 1.0.41"`, 0)
	fakeJadx := writeFakeExecScript(t, dir, "jadx", `echo "1.5.0"`, 0)
	fakeR2 := writeFakeExecScript(t, dir, "r2", `echo "radare2 5.9.0"`, 0)

	st := CheckTools(Options{
		ADBPath:  fakeADB,
		JadxPath: fakeJadx,
		R2Path:   fakeR2,
	})
	if !st.ADB || !strings.Contains(st.ADBVersion, "1.0.41") {
		t.Errorf("ADB status = %+v", st)
	}
	if !st.Jadx || st.JadxVersion != "1.5.0" {
		t.Errorf("Jadx status = %+v", st)
	}
	if !st.R2 || !strings.Contains(st.R2Version, "5.9.0") {
		t.Errorf("R2 status = %+v", st)
	}

	missing := CheckTools(Options{
		ADBPath:  filepath.Join(dir, "missing-adb"),
		JadxPath: filepath.Join(dir, "missing-jadx"),
		R2Path:   filepath.Join(dir, "missing-r2"),
	})
	if missing.ADB || missing.Jadx || missing.R2 {
		t.Errorf("expected all tools unavailable, got %+v", missing)
	}
}

func TestTraceContextStageProgressionCachingAndPartialJadx(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub scripts require POSIX")
	}
	dir := t.TempDir()

	manifest := buildFakeManifest(t, []axmlElem{
		{name: "manifest", attrs: []axmlAttr{strAttr("package", "com.example.demo")}},
	})
	dex1 := bytes.Join([][]byte{
		{0x64, 0x65, 0x78, 0x0a}, []byte("/api/v1/checkout"), []byte("com/example/DemoApi"),
	}, []byte{0x00})
	dex2 := bytes.Join([][]byte{
		{0x64, 0x65, 0x78, 0x0a}, []byte("api.example.com"), []byte("secondary_class"),
	}, []byte{0x00})

	apkPath := writeTestZip(t, filepath.Join(dir, "demo.apk"), map[string][]byte{
		"AndroidManifest.xml":    manifest,
		"classes.dex":            dex1,
		"classes2.dex":           dex2,
		"lib/arm64-v8a/libsec.so": []byte{0x7f, 'E', 'L', 'F', 0, 0},
	})

	countFile := filepath.Join(dir, "jadx-count.txt")
	// Fake jadx: responds to --version, otherwise increments counter, streams
	// progress lines (including \r updates), creates a Java source file, AND
	// exits 1 to verify partial-success handling!
	fakeJadxScript := fmt.Sprintf(`
if [ "$1" = "--version" ]; then
  echo "1.5.1"
  exit 0
fi
outDir="$2"
echo "x" >> %q
printf '%%s\n' 'INFO  - loading ...'
printf '%%s\r' 'INFO  - progress: 25%% (10 of 40)'
printf '%%s\n' 'INFO  - progress: 75%% (30 of 40)'
printf '%%s\n' 'INFO  - progress: 100%% (40 of 40)'
mkdir -p "$outDir/sources/com/example"
cat > "$outDir/sources/com/example/CheckoutApi.java" <<'JAVA'
package com.example;
public class CheckoutApi {
    static { System.loadLibrary("sec"); }
    public static native String nativeSign(String payload);
    @POST("/api/v1/checkout")
    Call<Resp> submitCheckout();
}
JAVA
echo "ERROR - finished with errors, count: 2"
exit 1
`, countFile)
	fakeJadx := writeFakeExecScript(t, dir, "fake-jadx", fakeJadxScript, 0)

	fakeR2Script := `
if [ "$1" = "-v" ]; then
  echo "radare2 5.9.0"
  exit 0
fi
case "$3" in
  *pdfj*)
    echo '{"ops":[{"type":"call","disasm":"bl sym.hmac_sha256"}]}'
    ;;
  *)
    echo '[{"vaddr":4096,"string":"hmac_secret_key"}][{"offset":8192,"name":"sym.Java_com_example_CheckoutApi_nativeSign"}]'
    ;;
esac
`
	fakeR2 := writeFakeExecScript(t, dir, "fake-r2", fakeR2Script, 0)

	flow := &types.Flow{
		ID:     "f42",
		Method: "POST",
		URL:    "https://api.example.com/api/v1/checkout",
		Host:   "api.example.com",
		Path:   "/api/v1/checkout",
	}
	outDir := filepath.Join(dir, "trace-out")
	opts := Options{
		APKPath:   apkPath,
		OutputDir: outDir,
		JadxPath:  fakeJadx,
		R2Path:    fakeR2,
	}

	var mu sync.Mutex
	var events []ProgressEvent
	res, err := TraceContext(context.Background(), flow, opts, func(ev ProgressEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("TraceContext run 1: %v", err)
	}

	// Verify monotonic percent & 100% completion.
	if len(events) < 8 {
		t.Fatalf("expected rich progress events, got only %d", len(events))
	}
	prevPct := -1
	seenStages := make(map[string]bool)
	sawJadxStreaming := false
	for _, ev := range events {
		if ev.Percent < prevPct {
			t.Errorf("non-monotonic percent: %d -> %d (stage %s)", prevPct, ev.Percent, ev.Stage)
		}
		prevPct = ev.Percent
		seenStages[ev.Stage] = true
		if ev.Stage == StageJadxDecompile && ev.Status == "running" && strings.Contains(ev.Detail, "%") {
			sawJadxStreaming = true
		}
	}
	if prevPct != 100 {
		t.Errorf("final percent = %d, want 100", prevPct)
	}
	if !sawJadxStreaming {
		t.Errorf("expected live jadx percentage progress event, got events: %+v", events)
	}
	for _, st := range []string{StagePreflight, StageAPKPull, StageAPKInspect, StageDEXSearch, StageJadxDecompile, StageJavaSearch, StageNative, StageGraphBuild, StageDone} {
		if !seenStages[st] {
			t.Errorf("missing stage %q in emitted progress events", st)
		}
	}

	// Partial jadx exit 1 STILL produced JavaTrace + bridged NativeTrace + CallGraph!
	if len(res.DexStrings) == 0 {
		t.Error("expected DexStrings matches")
	}
	if len(res.JavaTrace) == 0 {
		t.Error("expected JavaTrace matches from partial jadx output")
	}
	if len(res.NativeTrace) == 0 {
		t.Error("expected NativeTrace matches from fake r2")
	}
	if len(res.CallGraph) < 3 {
		t.Errorf("expected multi-hop CallGraph, got %d edges", len(res.CallGraph))
	}

	readCount := func() int {
		b, _ := os.ReadFile(countFile)
		return len(strings.Fields(string(b)))
	}
	if got := readCount(); got != 1 {
		t.Fatalf("jadx invoke count after run 1 = %d, want 1", got)
	}

	// Run 2 (ForceRefresh=false): MUST reuse jadx cache without re-invoking jadx!
	var run2Events []ProgressEvent
	res2, err := TraceContext(context.Background(), flow, opts, func(ev ProgressEvent) {
		run2Events = append(run2Events, ev)
	})
	if err != nil {
		t.Fatalf("TraceContext run 2 (cached): %v", err)
	}
	if got := readCount(); got != 1 {
		t.Fatalf("jadx invoke count after cached run 2 = %d, want 1 (cache hit)", got)
	}
	if len(res2.JavaTrace) != len(res.JavaTrace) {
		t.Fatalf("cached run JavaTrace = %d, want %d", len(res2.JavaTrace), len(res.JavaTrace))
	}
	sawCacheMsg := false
	for _, ev := range run2Events {
		if ev.Stage == StageJadxDecompile && strings.Contains(ev.Detail, "reused cache") {
			sawCacheMsg = true
		}
	}
	if !sawCacheMsg {
		t.Error("expected 'reused cache' detail on cached run 2")
	}

	// Run 3 (ForceRefresh=true): MUST re-run jadx!
	optsForce := opts
	optsForce.ForceRefresh = true
	if _, err := TraceContext(context.Background(), flow, optsForce, nil); err != nil {
		t.Fatalf("TraceContext run 3 (ForceRefresh): %v", err)
	}
	if got := readCount(); got != 2 {
		t.Fatalf("jadx invoke count after ForceRefresh = %d, want 2", got)
	}

	// Run 4 with a DIFFERENT APK in the same OutputDir MUST NOT reuse APK 1's cache!
	apkPath2 := writeTestZip(t, filepath.Join(dir, "other.apk"), map[string][]byte{
		"AndroidManifest.xml": manifest,
		"classes.dex":         []byte("different-apk-content-12345"),
	})
	optsOther := opts
	optsOther.APKPath = apkPath2
	if _, err := TraceContext(context.Background(), flow, optsOther, nil); err != nil {
		t.Fatalf("TraceContext run 4 (different APK): %v", err)
	}
	if got := readCount(); got != 3 {
		t.Fatalf("jadx invoke count after different APK = %d, want 3 (isolated cache dir)", got)
	}
}

func TestTraceContextCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub scripts require POSIX")
	}
	dir := t.TempDir()
	apkPath := writeTestZip(t, filepath.Join(dir, "slow.apk"), map[string][]byte{
		"classes.dex": []byte("/api/v1/slow_endpoint"),
	})

	fakeSlowJadx := writeFakeExecScript(t, dir, "fake-jadx-slow", `
if [ "$1" = "--version" ]; then
  echo "1.5.0"
  exit 0
fi
echo "INFO - progress: 10% (1 of 10)"
sleep 5
`, 0)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	flow := &types.Flow{ID: "f-cancel", Method: "GET", URL: "https://api.example.com/api/v1/slow_endpoint", Host: "api.example.com", Path: "/api/v1/slow_endpoint"}
	opts := Options{
		APKPath:   apkPath,
		OutputDir: filepath.Join(dir, "out"),
		JadxPath:  fakeSlowJadx,
		R2Path:    filepath.Join(dir, "no-r2"),
	}

	start := time.Now()
	var sawCancelled bool
	res, err := TraceContext(ctx, flow, opts, func(ev ProgressEvent) {
		if ev.Status == "cancelled" {
			sawCancelled = true
		}
	})
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v, expected prompt termination", elapsed)
	}
	if !sawCancelled {
		t.Error("expected a 'cancelled' ProgressEvent")
	}
	if res == nil || len(res.DexStrings) == 0 {
		t.Errorf("expected partial TraceResult preserving DexStrings before cancel, got %+v", res)
	}
}

func TestSplitAPKPullCachingAndSOMerge(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub scripts require POSIX")
	}
	dir := t.TempDir()

	// Create real zip files on disk that fake adb will "pull".
	srcBase := writeTestZip(t, filepath.Join(dir, "src-base.apk"), map[string][]byte{
		"classes.dex": []byte("/api/v1/bundle"),
	})
	srcSplit := writeTestZip(t, filepath.Join(dir, "src-arm64.apk"), map[string][]byte{
		"lib/arm64-v8a/libbundle_native.so": []byte{0x7f, 'E', 'L', 'F'},
	})
	pullCountFile := filepath.Join(dir, "pull-count.txt")

	fakeADBScript := fmt.Sprintf(`
case "$*" in
  *"pm path"*)
    echo "package:/data/app/com.bundle/base.apk"
    echo "package:/data/app/com.bundle/split_config.arm64_v8a.apk"
    ;;
  *"stat -c"*)
    echo "12345:1700000000"
    ;;
  *"pull /data/app/com.bundle/base.apk"*)
    echo "p" >> %q
    cp %q "$3"
    ;;
  *"pull /data/app/com.bundle/split_config.arm64_v8a.apk"*)
    cp %q "$3"
    ;;
esac
`, pullCountFile, srcBase, srcSplit)
	fakeADB := writeFakeExecScript(t, dir, "fake-adb", fakeADBScript, 0)

	outDir := filepath.Join(dir, "out")
	base1, splits1, cached1, err := pullAPKContext(context.Background(), fakeADB, "", "com.bundle", outDir, false, nil)
	if err != nil {
		t.Fatalf("pullAPKContext 1: %v", err)
	}
	if cached1 {
		t.Fatal("first pull should not be cached")
	}
	if len(splits1) != 1 {
		t.Fatalf("expected 1 ABI split pulled, got %v", splits1)
	}

	// Verify split .so merges into APKInfo!
	info, err := extractAPKInfoWithSplits(base1, splits1)
	if err != nil {
		t.Fatalf("extractAPKInfoWithSplits: %v", err)
	}
	if len(info.SOFiles) != 1 || info.SOFiles[0] != "lib/arm64-v8a/libbundle_native.so" {
		t.Fatalf("merged SOFiles = %v, want [lib/arm64-v8a/libbundle_native.so]", info.SOFiles)
	}

	// Second pull (ForceRefresh=false) hits cache without calling adb pull again!
	base2, splits2, cached2, err := pullAPKContext(context.Background(), fakeADB, "", "com.bundle", outDir, false, nil)
	if err != nil {
		t.Fatalf("pullAPKContext 2: %v", err)
	}
	if !cached2 || base2 != base1 || len(splits2) != 1 {
		t.Fatalf("expected cache hit: cached=%v base=%s splits=%v", cached2, base2, splits2)
	}
	b, _ := os.ReadFile(pullCountFile)
	if n := len(strings.Fields(string(b))); n != 1 {
		t.Fatalf("adb pull invoked %d times, want 1 (cached on second call)", n)
	}
}
