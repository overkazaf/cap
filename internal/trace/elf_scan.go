package trace

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultR2StageBudget  = 25 * time.Second
	defaultR2PerSOTimeout = 8 * time.Second
	maxR2SOFiles          = 6
	maxR2FuncsPerSO       = 5
	maxR2FileBytes        = 20 * 1024 * 1024 // 20 MiB
	maxELFSectionBytes    = 8 * 1024 * 1024  // 8 MiB per section
	maxELFExportsPerSO    = 30
	elfScanWorkers        = 4
)

var heavyMediaKeywords = []string{
	"svae", "audio", "video", "ffmpeg", "avcodec", "avformat", "swscale",
	"skia", "flutter", "webrtc", "v8", "icu", "unity", "opencv", "ijk",
	"render", "vulkan", "c++_shared", "cronet", "x264", "opus", "speex",
	"lame", "mp3", "aac",
}

var securityLibKeywords = []string{
	"sign", "crypt", "enc", "sec", "auth", "token", "net", "http",
	"sdk", "core", "guard", "shield", "key",
}

var relevantImportRe = regexp.MustCompile(`(?i)(md5|sha\d*|aes|des|rsa|hmac|evp_|ssl_|tls_|bio_|curl|socket|connect|send|recv|getaddrinfo|jni|registernatives|dlopen|dlsym|mprotect|ptrace|encrypt|decrypt|cipher|crypto|pkcs|base64|sign)`)

// abiRank prioritizes arm64-v8a > armeabi-v7a > armeabi > x86_64 > x86.
func abiRank(abi string) int {
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

// parseSOABIAndLib extracts (abi, libraryBasename) from either an in-APK path
// ("lib/arm64-v8a/libfoo.so") or a flattened local extraction filename
// ("/tmp/lib/lib_arm64-v8a_libfoo.so").
func parseSOABIAndLib(path string) (abi, libName string) {
	slash := filepath.ToSlash(path)
	if idx := strings.LastIndex(slash, "/lib/"); idx >= 0 {
		rest := slash[idx+5:]
		if parts := strings.SplitN(rest, "/", 2); len(parts) == 2 && strings.HasSuffix(parts[1], ".so") {
			return parts[0], parts[1]
		}
	}
	if strings.HasPrefix(slash, "lib/") {
		rest := slash[4:]
		if parts := strings.SplitN(rest, "/", 2); len(parts) == 2 && strings.HasSuffix(parts[1], ".so") {
			return parts[0], parts[1]
		}
	}

	base := filepath.Base(path)
	for _, candidate := range []string{"arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86"} {
		prefix := "lib_" + candidate + "_"
		if strings.HasPrefix(base, prefix) {
			return candidate, strings.TrimPrefix(base, prefix)
		}
	}
	return "", base
}

// deduplicateSOFiles removes duplicate ABIs for the same shared library
// basename, preferring arm64-v8a > armeabi-v7a > x86_64 > x86.
func deduplicateSOFiles(paths []string) []string {
	type pick struct {
		path string
		rank int
	}
	best := make(map[string]pick, len(paths))
	for _, p := range paths {
		abi, lib := parseSOABIAndLib(p)
		rank := abiRank(abi)
		cur, exists := best[lib]
		if !exists || rank > cur.rank || (rank == cur.rank && p < cur.path) {
			best[lib] = pick{path: p, rank: rank}
		}
	}
	out := make([]string, 0, len(best))
	for _, pk := range best {
		out = append(out, pk.path)
	}
	sort.Strings(out)
	return out
}

func isHeavyMediaLib(libName string) bool {
	lower := strings.ToLower(libName)
	for _, kw := range heavyMediaKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isSecurityKeywordName(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range securityLibKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

type elfTargetFunc struct {
	Name     string
	Addr     uint64
	Priority int // higher = analyzed first in targeted r2
	RefIdx   int // index into elfScanResult.Refs
}

type elfScanResult struct {
	SOPath            string
	BaseName          string
	LibName           string
	FileSize          int64
	IsELF             bool
	Score             int
	HasExplicitSignal bool
	HeavyMedia        bool
	EligibleForR2     bool
	Refs              []NativeRef
	TargetFuncs       []elfTargetFunc
}

// collectReferencedSOLibs extracts normalized library names (e.g. "libsec.so")
// referenced via System.loadLibrary(...) in Strategy 3's JavaTrace.
func collectReferencedSOLibs(refs []JavaRef) map[string]bool {
	out := make(map[string]bool)
	for _, r := range refs {
		for _, nm := range r.NativeMethods {
			if strings.HasSuffix(strings.ToLower(nm), ".so") {
				out[strings.ToLower(filepath.Base(nm))] = true
			}
		}
	}
	return out
}

// scanELFFile implements Phase 7A: a fast, pure-Go ELF inspection using
// debug/elf (zero external processes!) extracting JNI exports, known native
// method symbols + addresses, relevant imports, bounded .rodata/.data strings,
// and computing a relevance score for optional Phase 7B targeted r2 disasm.
func scanELFFile(soPath string, knownMethods []string, referencedLibs map[string]bool, searchTerms []string) (*elfScanResult, error) {
	base := filepath.Base(soPath)
	_, libName := parseSOABIAndLib(soPath)
	res := &elfScanResult{
		SOPath:     soPath,
		BaseName:   base,
		LibName:    libName,
		HeavyMedia: isHeavyMediaLib(libName),
	}

	if fi, err := os.Stat(soPath); err == nil {
		res.FileSize = fi.Size()
	}

	ef, err := elf.Open(soPath)
	if err != nil {
		return res, err
	}
	defer ef.Close()
	res.IsELF = true

	// 1. Collect exported/defined symbols from DynamicSymbols + Symbols.
	type symInfo struct {
		name string
		addr uint64
	}
	symSeen := make(map[string]bool)
	var syms []symInfo
	addSyms := func(list []elf.Symbol) {
		for _, s := range list {
			if s.Name == "" || s.Section == elf.SHN_UNDEF {
				continue
			}
			if symSeen[s.Name] {
				continue
			}
			symSeen[s.Name] = true
			syms = append(syms, symInfo{name: s.Name, addr: s.Value})
		}
	}
	if dynSyms, err := ef.DynamicSymbols(); err == nil {
		addSyms(dynSyms)
	}
	if allSyms, err := ef.Symbols(); err == nil {
		addSyms(allSyms)
	}

	// 2. Collect relevant crypto / network / JNI imported symbols.
	var imports []string
	impSeen := make(map[string]bool)
	if impSyms, err := ef.ImportedSymbols(); err == nil {
		for _, imp := range impSyms {
			if imp.Name == "" || impSeen[imp.Name] {
				continue
			}
			if relevantImportRe.MatchString(imp.Name) {
				impSeen[imp.Name] = true
				imports = append(imports, imp.Name)
			}
		}
	}
	sort.Strings(imports)

	// 3. Scan .rodata and .data sections (bounded <= maxELFSectionBytes each)
	// for flow searchTerms and interesting crypto/HTTP/sign strings.
	terms := significantTerms(searchTerms)
	var interesting []string
	strSeen := make(map[string]bool)
	matchedSearchTerm := false
	for _, sec := range ef.Sections {
		if sec == nil || (sec.Name != ".rodata" && sec.Name != ".data") {
			continue
		}
		if sec.Size == 0 || sec.Type == elf.SHT_NOBITS {
			continue
		}
		r := sec.Open()
		if r == nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(r, maxELFSectionBytes))
		if err != nil || len(data) == 0 {
			continue
		}
		runs := extractPrintableStrings(data, minPrintableRun)
		for _, run := range runs {
			val := run.value
			if strSeen[val] {
				continue
			}
			termHit := len(terms) > 0 && containsAnyTerm(val, terms)
			if termHit {
				matchedSearchTerm = true
			}
			if termHit || isInterestingNativeString(val, terms) {
				strSeen[val] = true
				if len(interesting) < maxInterestingStrings {
					interesting = append(interesting, val)
				}
			}
		}
	}

	// 4. Match known native methods, JNI_OnLoad, and Java_* exports.
	var refs []NativeRef
	var targets []elfTargetFunc
	refSeen := make(map[string]bool)
	matchedKnown := false
	securityExportHit := false
	genericJavaExports := 0

	addRef := func(displayName string, addr uint64, prio int) {
		if refSeen[displayName] {
			return
		}
		refSeen[displayName] = true
		addrStr := ""
		if addr > 0 {
			addrStr = fmt.Sprintf("0x%x", addr)
		}
		idx := len(refs)
		refs = append(refs, NativeRef{
			SOFile:   base,
			Function: displayName,
			Address:  addrStr,
			Strings:  interesting,
			Imports:  imports,
		})
		if addr > 0 {
			targets = append(targets, elfTargetFunc{
				Name:     displayName,
				Addr:     addr,
				Priority: prio,
				RefIdx:   idx,
			})
		}
	}

	// Pass A: knownMethods matches first (never capped!).
	consumedSyms := make(map[string]bool)
	for _, sym := range syms {
		if m, ok := matchesKnownNativeMethod(sym.name, knownMethods); ok {
			matchedKnown = true
			consumedSyms[sym.name] = true
			addRef(m, sym.addr, 100)
		}
	}
	// Pass B: JNI_OnLoad and Java_* exports (Java_* capped at maxELFExportsPerSO).
	for _, sym := range syms {
		if consumedSyms[sym.name] || !isJNIExport(sym.name) {
			continue
		}
		clean := stripR2Prefix(sym.name)
		if clean == "JNI_OnLoad" {
			addRef(clean, sym.addr, 80)
			continue
		}
		if isSecurityKeywordName(clean) {
			securityExportHit = true
		}
		if genericJavaExports >= maxELFExportsPerSO {
			continue
		}
		genericJavaExports++
		prio := 40
		if isSecurityKeywordName(clean) {
			prio = 65
		}
		addRef(clean, sym.addr, prio)
	}

	// Strings-only fallback if no JNI exports matched but interesting strings exist.
	if len(refs) == 0 && len(interesting) > 0 {
		refs = append(refs, NativeRef{
			SOFile:  base,
			Strings: interesting,
			Imports: imports,
		})
	}

	// Sort target functions by priority descending (tie-break by name) and cap at maxR2FuncsPerSO.
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Priority != targets[j].Priority {
			return targets[i].Priority > targets[j].Priority
		}
		return targets[i].Name < targets[j].Name
	})
	if len(targets) > maxR2FuncsPerSO {
		targets = targets[:maxR2FuncsPerSO]
	}

	// 5. Compute relevance score & r2 eligibility.
	referencedByJava := referencedLibs[strings.ToLower(libName)]
	score := 0
	if matchedKnown {
		score += 100
	}
	if referencedByJava {
		score += 80
	}
	if matchedSearchTerm {
		score += 60
	}
	if isSecurityKeywordName(libName) || securityExportHit {
		score += 30
	}
	if len(targets) > 0 {
		score += 15
	}
	if len(interesting) > 0 || len(imports) > 0 {
		score += 10
	}

	explicitSignal := matchedKnown || referencedByJava || matchedSearchTerm
	eligibleForR2 := false
	if len(targets) > 0 {
		if explicitSignal {
			eligibleForR2 = true
		} else if !res.HeavyMedia && res.FileSize <= maxR2FileBytes && score >= 15 {
			eligibleForR2 = true
		}
	}

	res.Score = score
	res.HasExplicitSignal = explicitSignal
	res.EligibleForR2 = eligibleForR2
	res.Refs = refs
	res.TargetFuncs = targets
	return res, nil
}

// scanELFFilesParallel runs Phase 7A across all unique .so files using a
// bounded worker pool (4 goroutines) and emits progress as each .so finishes.
func scanELFFilesParallel(
	ctx context.Context,
	soFiles []string,
	knownMethods []string,
	referencedLibs map[string]bool,
	searchTerms []string,
	onProgress func(done, total int, lib string, refs int),
) []*elfScanResult {
	total := len(soFiles)
	if total == 0 {
		return nil
	}
	results := make([]*elfScanResult, total)

	workers := elfScanWorkers
	if total < workers {
		workers = total
	}
	jobs := make(chan int, total)
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		completed int
		totalRefs int
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				so := soFiles[idx]
				scanRes, _ := scanELFFile(so, knownMethods, referencedLibs, searchTerms)
				results[idx] = scanRes

				mu.Lock()
				completed++
				if scanRes != nil {
					totalRefs += len(scanRes.Refs)
				}
				c := completed
				rCount := totalRefs
				mu.Unlock()

				if onProgress != nil {
					onProgress(c, total, filepath.Base(so), rCount)
				}
			}
		}()
	}
	wg.Wait()
	return results
}

// buildTargetedR2Args builds ONE single radare2 command that performs targeted
// per-address function analysis (`s 0x<addr>; af; pdfj`) for up to
// maxR2FuncsPerSO functions — NEVER running global `aa` and NEVER respawning
// r2 in a per-function loop.
func buildTargetedR2Args(soPath string, targets []elfTargetFunc) []string {
	if len(targets) > maxR2FuncsPerSO {
		targets = targets[:maxR2FuncsPerSO]
	}
	cmds := make([]string, 0, len(targets))
	for _, t := range targets {
		cmds = append(cmds, fmt.Sprintf("s 0x%x; af; pdfj", t.Addr))
	}
	return []string{
		"-e", "bin.relocs.apply=false",
		"-e", "anal.limits=true",
		"-e", "anal.maxreflines=20",
		"-q",
		"-c", strings.Join(cmds, "; "),
		soPath,
	}
}

// decodeSequentialPDFJ decodes a sequence of JSON objects produced by chained
// `pdfj` commands in a single r2 invocation, skipping any non-JSON noise lines.
func decodeSequentialPDFJ(output []byte) [][]string {
	data := bytes.TrimSpace(output)
	var allCalls [][]string
	pos := 0
	for pos < len(data) {
		rel := bytes.IndexByte(data[pos:], '{')
		if rel < 0 {
			break
		}
		pos += rel
		dec := json.NewDecoder(bytes.NewReader(data[pos:]))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			pos++
			continue
		}
		allCalls = append(allCalls, extractCallTargets(raw))
		consumed := int(dec.InputOffset())
		if consumed <= 0 {
			pos++
		} else {
			pos += consumed
		}
	}
	return allCalls
}

// enrichWithR2Context implements Phase 7B: executes at most ONE targeted r2
// process for scan under a strict per-.so timeout (capped by ctx deadline).
// If r2 fails or times out, Phase 7A Pure-Go ELF findings remain intact.
func enrichWithR2Context(ctx context.Context, r2Path string, scan *elfScanResult, perSOTimeout time.Duration) (int, error) {
	if scan == nil || len(scan.TargetFuncs) == 0 {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if perSOTimeout <= 0 || perSOTimeout > defaultR2PerSOTimeout {
		perSOTimeout = defaultR2PerSOTimeout
	}

	soCtx, cancel := context.WithTimeout(ctx, perSOTimeout)
	defer cancel()

	args := buildTargetedR2Args(scan.SOPath, scan.TargetFuncs)
	cmd := exec.CommandContext(soCtx, r2Path, args...)
	configureCancellableCmd(cmd)

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if soCtx.Err() != nil {
			return 0, fmt.Errorf("r2 targeted timeout (%s) on %s", perSOTimeout, scan.BaseName)
		}
		return 0, fmt.Errorf("r2 targeted %s: %w", scan.BaseName, err)
	}

	callLists := decodeSequentialPDFJ(out)
	enriched := 0
	for i, calls := range callLists {
		if i >= len(scan.TargetFuncs) {
			break
		}
		refIdx := scan.TargetFuncs[i].RefIdx
		if refIdx >= 0 && refIdx < len(scan.Refs) && len(calls) > 0 {
			scan.Refs[refIdx].Calls = calls
			enriched++
		}
	}
	return enriched, nil
}

// selectR2Candidates picks at most maxR2SOFiles highest-relevance ELF scan
// results that are eligible for Phase 7B targeted r2 disassembly.
func selectR2Candidates(scans []*elfScanResult, limit int) []*elfScanResult {
	if limit <= 0 {
		limit = maxR2SOFiles
	}
	var eligible []*elfScanResult
	for _, sc := range scans {
		if sc != nil && sc.EligibleForR2 {
			eligible = append(eligible, sc)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Score != eligible[j].Score {
			return eligible[i].Score > eligible[j].Score
		}
		return eligible[i].BaseName < eligible[j].BaseName
	})
	if len(eligible) > limit {
		eligible = eligible[:limit]
	}
	return eligible
}
