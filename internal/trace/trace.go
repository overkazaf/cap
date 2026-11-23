// Package trace implements cap's "Deep Trace" feature: given one captured
// HTTP flow and the Android APK believed to have issued it, work backwards
// from the request to the code (and, where native libraries are involved,
// the native function) that built it.
//
// Earlier versions of this package worked only when jadx happened to be
// installed, offered no progress feedback during multi-minute decompiles,
// and matched source against the flow using a single exact-path substring
// check. This version runs four independent strategies and keeps whatever
// each one finds instead of needing all of them to succeed:
//
//  1. DEX string search: scan classes*.dex directly for byte strings that
//     look like the flow's URL/host/path. Pure Go (archive/zip + bytes),
//     needs no external tool, and is typically the fastest signal.
//  2. APK/manifest inspection: list every entry in the APK zip to report
//     native libraries, DEX file count, and a best-effort read of
//     AndroidManifest.xml (package, SDK versions, permissions, activities,
//     network_security_config). Also pure Go.
//  3. jadx decompilation: if the jadx binary is available, decompile the
//     APK (bounded by a timeout) and scan the Java source for Retrofit
//     annotations, OkHttp Request.Builder chains, hardcoded URLs, and
//     native method declarations/System.loadLibrary calls.
//  4. radare2 native analysis: if r2 is available, scan every .so file
//     found by strategy 2 for strings, exported JNI functions
//     (JNI_OnLoad, Java_*), and -- for native methods strategy 3 found
//     declared -- the functions they call.
//
// Strategies 3 and 4 degrade gracefully (recorded as a "skip" step, not an
// error) when their tool isn't installed; strategies 1 and 2 always run.
// Trace reports progress through an optional StepCallback as it goes, and
// every step (ok, skipped, or failed) is also recorded in
// TraceResult.Steps for later inspection.
package trace

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/overkazaf/cap/internal/types"
)

// Tunables. Exposed as defaults rather than hardcoded constants wherever
// Options provides an override.
const (
	// minSearchTermLen is the shortest text fragment worth searching for in
	// DEX bytes, Java source, or native strings -- below this, a fragment
	// matches too much unrelated text to be useful signal.
	minSearchTermLen = 3

	// minPrintableRun mirrors the Unix `strings` utility's default minimum
	// match length.
	minPrintableRun = 4

	// dexContextWindow is how many neighboring printable strings (on each
	// side) a DexMatch's Context includes.
	dexContextWindow = 3

	defaultMaxDexMatches    = 50
	defaultJadxTimeout      = 5 * time.Minute
	defaultR2Timeout        = 45 * time.Second
	defaultToolCheckTimeout = 5 * time.Second

	// maxInterestingStrings caps how many of a .so file's "interesting"
	// strings are attached to each NativeRef.
	maxInterestingStrings = 20
)

// StepCallback is invoked as Trace makes progress through its pipeline, so
// a caller (CLI progress line, GUI log pane, ...) gets live status instead
// of silence during what can be a multi-minute call. step is a short
// stable identifier (e.g. "dex_search", "jadx_decompile", "done"); detail
// is a human-readable one-line description of that step's outcome.
//
// onStep may be nil -- Trace simply skips live reporting in that case.
// Every step is recorded in TraceResult.Steps regardless of whether a
// callback was supplied.
type StepCallback func(step string, detail string)

// Options configures Trace. All fields are optional; a zero Options traces
// using only a pre-pulled APK at APKPath (or fails fast if that's also
// empty) and tool defaults found on PATH.
type Options struct {
	Serial     string // adb device serial; empty uses the default/only device
	ADBPath    string // adb binary path/name; empty tries "adb" on PATH
	APKPath    string // pre-pulled APK path; empty pulls from device via Serial+Package
	JadxPath   string // jadx binary path/name; empty tries "jadx" on PATH
	R2Path     string // radare2 binary path/name; empty tries "r2" on PATH
	UnpackPath string // optional unpack tool, run before decompilation
	OutputDir  string // working directory for pulled APKs/decompiled output; empty defaults to ~/.cap/trace
	Package    string // target package name; used to pull the APK when APKPath is empty

	JadxTimeout   time.Duration // max time allowed for jadx to decompile; <=0 defaults to 5 minutes
	R2Timeout     time.Duration // max time allowed per radare2 invocation; <=0 defaults to 45 seconds
	MaxDexMatches int           // cap on how many DexMatch results are returned; <=0 defaults to 50
	SearchTerms   []string      // extra terms to search for, alongside those derived from the flow
	ForceRefresh  bool          // bypass cached pulled APK and cached jadx output
}

// StepResult is one entry in TraceResult.Steps: a record of one pipeline
// step's name, outcome, and timing, independent of whether a StepCallback
// was supplied.
type StepResult struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // "ok", "skip", or "error"
	Detail   string `json:"detail"`
	Duration int64  `json:"duration_ms"`
}

// DexMatch is one hit found by the Strategy 1 (DEX string search): a
// printable string pulled directly out of a classes*.dex file's raw bytes
// that contains one of the flow's search terms, plus its neighboring
// strings for context.
type DexMatch struct {
	String  string   `json:"string"`
	Offset  int64    `json:"offset"`
	Context []string `json:"context"` // nearby strings, in file order
	DexFile string   `json:"dex_file"`
}

// APKInfo is the result of Strategy 2 (APK/manifest inspection): facts
// read directly from the APK zip and a best-effort decode of
// AndroidManifest.xml, without invoking any external tool.
type APKInfo struct {
	Package     string   `json:"package"`
	MinSDK      string   `json:"min_sdk"`
	TargetSDK   string   `json:"target_sdk"`
	Permissions []string `json:"permissions"`
	SOFiles     []string `json:"so_files"` // in-APK paths, e.g. "lib/arm64-v8a/libfoo.so"
	DexCount    int      `json:"dex_count"`
	HasNSConfig bool     `json:"has_ns_config"` // a network_security_config resource was found
	Activities  []string `json:"activities"`
}

// JavaRef is one Java source location (found via Strategy 3, jadx) that
// plausibly issues the traced request: a Retrofit interface method, an
// OkHttp Request.Builder call site, or a hardcoded URL literal.
type JavaRef struct {
	File          string   `json:"file"`
	Class         string   `json:"class"`
	Method        string   `json:"method"`
	Line          int      `json:"line"`
	Snippet       string   `json:"snippet"`
	Annotation    string   `json:"annotation"`
	MatchedTerm   string   `json:"matched_term,omitempty"` // which search term matched this line
	CallsNative   bool     `json:"calls_native"`
	NativeMethods []string `json:"native_methods,omitempty"`
}

// NativeRef is one native (JNI/.so) finding from Strategy 4 (radare2): an
// exported function of interest (a declared native method, JNI_OnLoad, or
// a Java_* JNI export) together with whatever strings/imports/calls r2
// could attribute to it.
type NativeRef struct {
	SOFile   string   `json:"so_file"`
	Function string   `json:"function"`
	Address  string   `json:"address"`
	Calls    []string `json:"calls"`
	Strings  []string `json:"strings"`
	Imports  []string `json:"imports"`
}

// CallEdge is one edge in the reconstructed call graph (App -> HTTP ->
// Java -> JNI -> native), also used to render Mermaid output.
type CallEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Type  string `json:"type"` // "http", "java_call", "jni", or "native_call"
	Label string `json:"label,omitempty"`
}

// TraceResult is everything Trace found, across every strategy that ran.
type TraceResult struct {
	FlowID  string `json:"flow_id"`
	URL     string `json:"url"`
	Method  string `json:"method"`
	Package string `json:"package"`
	APKPath string `json:"apk_path"`

	Steps []StepResult `json:"steps"` // what Trace did, in order, regardless of outcome

	DexStrings  []DexMatch  `json:"dex_strings"`  // Strategy 1
	APKInfo     *APKInfo    `json:"apk_info"`     // Strategy 2
	JavaTrace   []JavaRef   `json:"java_trace"`   // Strategy 3
	NativeTrace []NativeRef `json:"native_trace"` // Strategy 4

	CallGraph []CallEdge `json:"call_graph"`
	Mermaid   string     `json:"mermaid"`
	Summary   string     `json:"summary"`
	ToolsUsed []string   `json:"tools_used"` // which strategies actually produced results
}

// --- search terms -----------------------------------------------------

// buildSearchTerms derives the text fragments worth searching for in DEX
// bytes, Java source, and native strings when tracing flow, ordered from
// most to least specific: the full URL, "host+path" (how code that
// concatenates a base URL and a path would store it), the bare path, the
// path without its leading slash, and the bare host. Terms shorter than
// minSearchTermLen and exact duplicates are dropped; a nil flow yields nil.
//
// This directly replaces the old "exact path substring" check: a request
// can be built from any of these fragments depending on how the app's code
// assembles it, and searching only the exact Path missed all the others.
func buildSearchTerms(flow *types.Flow) []string {
	if flow == nil {
		return nil
	}

	path := cleanPath(flow.Path)
	if path == "" {
		path = cleanPath(pathFromURL(flow.URL))
	}

	var terms []string
	seen := make(map[string]bool)
	add := func(s string) {
		if len(s) < minSearchTermLen || seen[s] {
			return
		}
		seen[s] = true
		terms = append(terms, s)
	}

	add(flow.URL)
	if flow.Host != "" && path != "" {
		add(flow.Host + path)
	}
	add(path)
	add(strings.TrimPrefix(path, "/"))
	add(flow.Host)

	return terms
}

// pathFromURL returns raw's path component, or "" if raw doesn't parse as
// a URL.
func pathFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Path
}

// cleanPath strips a query string and/or fragment from p, if present.
func cleanPath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p
}

// --- printable-string scanning -----------------------------------------

// printableRun is one maximal run of printable ASCII bytes found while
// scanning binary data the way the Unix `strings` utility does.
type printableRun struct {
	offset int64
	value  string
}

// isPrintableByte reports whether b is printable ASCII (space through
// tilde) -- the same definition the Unix `strings` utility uses.
func isPrintableByte(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}

// extractPrintableStrings scans data for every maximal run of printable
// ASCII bytes at least minLen long (minLen<=0 defaults to minPrintableRun),
// returning each in file order with its byte offset. This is the building
// block for both Strategy 1's DEX search and Strategy 2's
// AndroidManifest.xml heuristic fallback: neither needs to understand its
// input's binary format, just to pull human-readable constants out of it.
func extractPrintableStrings(data []byte, minLen int) []printableRun {
	if minLen <= 0 {
		minLen = minPrintableRun
	}

	var runs []printableRun
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minLen {
			runs = append(runs, printableRun{offset: int64(start), value: string(data[start:end])})
		}
		start = -1
	}
	for i, b := range data {
		if isPrintableByte(b) {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(data))
	return runs
}

// --- Strategy 1: DEX string search --------------------------------------

// dexFileNamePattern matches a DEX entry's name inside an APK zip:
// classes.dex, classes2.dex, classes3.dex, ...
var dexFileNamePattern = regexp.MustCompile(`^classes(\d*)\.dex$`)

// searchDexStrings scans every classes*.dex entry in the APK at apkPath for
// printable strings containing any of searchTerms (terms shorter than
// minSearchTermLen are ignored), returning each hit with its byte offset
// and neighboring strings for context. Pure Go: the APK is read as a zip
// (archive/zip) and each DEX file's bytes are scanned directly
// (extractPrintableStrings) -- no jadx, no baksmali, no "strings" binary.
//
// This both replaces and goes beyond the "strings on the dex" idea: rather
// than emitting one flat list, each hit is attributed to the DEX file and
// byte offset it came from, with nearby strings attached so a human (or an
// LLM) can tell at a glance what class/method the matched literal likely
// belongs to even before jadx has run.
func searchDexStrings(apkPath string, searchTerms []string) ([]DexMatch, error) {
	return searchDexStringsLimit(apkPath, searchTerms, defaultMaxDexMatches)
}

// searchDexStringsLimit is searchDexStrings with an explicit cap on the
// number of matches returned (searchDexStrings uses defaultMaxDexMatches).
// A cap matters because a short, generic search term can otherwise match
// an unbounded number of unrelated strings in a large multi-DEX app.
func searchDexStringsLimit(apkPath string, searchTerms []string, maxMatches int) ([]DexMatch, error) {
	return searchDexStringsContext(context.Background(), apkPath, searchTerms, maxMatches, nil)
}

type dexProgressFunc func(dexName string, idx, total, matches int)

func searchDexStringsContext(ctx context.Context, apkPath string, searchTerms []string, maxMatches int, onDex dexProgressFunc) ([]DexMatch, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	terms := significantTerms(searchTerms)
	if len(terms) == 0 {
		return nil, nil
	}
	if maxMatches <= 0 {
		maxMatches = defaultMaxDexMatches
	}

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk %s: %w", apkPath, err)
	}
	defer zr.Close()

	dexFiles := filterAndSortDexFiles(zr.File)
	total := len(dexFiles)

	var matches []DexMatch
	for idx, f := range dexFiles {
		if err := ctx.Err(); err != nil {
			return matches, err
		}
		if len(matches) >= maxMatches {
			break
		}
		if onDex != nil {
			onDex(f.Name, idx+1, total, len(matches))
		}
		data, err := readZipFile(f)
		if err != nil {
			continue
		}

		runs := extractPrintableStrings(data, minPrintableRun)
		for i, run := range runs {
			if len(matches) >= maxMatches {
				break
			}
			if !containsAnyTerm(run.value, terms) {
				continue
			}
			matches = append(matches, DexMatch{
				String:  run.value,
				Offset:  run.offset,
				Context: neighborStrings(runs, i, dexContextWindow),
				DexFile: f.Name,
			})
		}
		if onDex != nil {
			onDex(f.Name, idx+1, total, len(matches))
		}
	}
	return matches, nil
}

// significantTerms filters terms down to those at least minSearchTermLen
// long, since shorter fragments match too much unrelated text to be useful.
func significantTerms(terms []string) []string {
	out := make([]string, 0, len(terms))
	for _, t := range terms {
		if len(t) >= minSearchTermLen {
			out = append(out, t)
		}
	}
	return out
}

// containsAnyTerm reports whether s contains any of terms as a substring.
func containsAnyTerm(s string, terms []string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// neighborStrings returns up to window printable-string values immediately
// before and after runs[i] (excluding runs[i] itself), in file order.
func neighborStrings(runs []printableRun, i, window int) []string {
	lo := i - window
	if lo < 0 {
		lo = 0
	}
	hi := i + window + 1
	if hi > len(runs) {
		hi = len(runs)
	}

	context := make([]string, 0, hi-lo-1)
	for j := lo; j < hi; j++ {
		if j == i {
			continue
		}
		context = append(context, runs[j].value)
	}
	return context
}

// filterAndSortDexFiles returns the entries of files named classes.dex,
// classes2.dex, ..., ordered classes.dex first and then numerically
// (classes2.dex before classes10.dex -- a plain name sort would get that
// backwards).
func filterAndSortDexFiles(files []*zip.File) []*zip.File {
	var dexFiles []*zip.File
	for _, f := range files {
		if dexFileNamePattern.MatchString(f.Name) {
			dexFiles = append(dexFiles, f)
		}
	}
	sort.Slice(dexFiles, func(i, j int) bool {
		return dexFileOrdinal(dexFiles[i].Name) < dexFileOrdinal(dexFiles[j].Name)
	})
	return dexFiles
}

// dexFileOrdinal extracts the numeric suffix from a classes*.dex file name
// ("classes.dex" -> 0, "classes2.dex" -> 2, ...) for numeric sorting.
func dexFileOrdinal(name string) int {
	m := dexFileNamePattern.FindStringSubmatch(name)
	if m == nil || m[1] == "" {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

// readZipFile reads a zip entry's entire contents into memory.
func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// --- Strategy 2: APK / manifest inspection ------------------------------

// nsConfigNamePattern matches a resource file that is (or looks like) an
// Android network_security_config XML resource, regardless of the
// arbitrary short name resource shrinking may have renamed it to -- which
// is why extractAPKInfo also checks AndroidManifest.xml's own
// networkSecurityConfig attribute rather than relying on this alone.
var nsConfigNamePattern = regexp.MustCompile(`(?i)network[_-]?security[_-]?config`)

// extractAPKInfo inspects the APK at apkPath without invoking any external
// tool: it lists the zip's entries directly for native libraries and DEX
// file count, and makes a best-effort read of AndroidManifest.xml (via
// parseAndroidManifest, falling back to heuristicManifestInfo if that
// binary XML document can't be decoded) for the package name, SDK
// versions, permissions, and activities.
//
// It only fails (non-nil error) if apkPath can't be opened as a zip at
// all; any trouble reading or decoding an individual entry within a
// readable zip is absorbed into a partial/empty result rather than
// surfaced as an error -- a missing or malformed manifest shouldn't stop
// the (reliable, zip-level) SOFiles/DexCount facts from being reported.
func extractAPKInfo(apkPath string) (*APKInfo, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk %s: %w", apkPath, err)
	}
	defer zr.Close()

	info := &APKInfo{}
	var manifestEntry *zip.File
	var nsConfigFileSeen bool

	for _, f := range zr.File {
		switch {
		case dexFileNamePattern.MatchString(filepath.Base(f.Name)):
			info.DexCount++
		case strings.HasSuffix(f.Name, ".so"):
			info.SOFiles = append(info.SOFiles, f.Name)
		case f.Name == "AndroidManifest.xml":
			manifestEntry = f
		}
		if nsConfigNamePattern.MatchString(filepath.Base(f.Name)) {
			nsConfigFileSeen = true
		}
	}
	sort.Strings(info.SOFiles)

	if manifestEntry != nil {
		if data, err := readZipFile(manifestEntry); err == nil {
			manifestInfo := parseManifestBestEffort(data)
			info.Package = manifestInfo.Package
			info.MinSDK = manifestInfo.MinSDK
			info.TargetSDK = manifestInfo.TargetSDK
			info.Permissions = manifestInfo.Permissions
			info.Activities = manifestInfo.Activities
			info.HasNSConfig = manifestInfo.HasNSConfig
		}
	}
	info.HasNSConfig = info.HasNSConfig || nsConfigFileSeen

	return info, nil
}

// extractSOFilesTo extracts every .so entry in the APK at apkPath into
// destDir (created if necessary), flattening each entry's in-APK path into
// a single file name (so e.g. lib/arm64-v8a/libfoo.so and
// lib/armeabi-v7a/libfoo.so -- same base name, different ABI -- don't
// collide on disk) so Strategy 4 (radare2) has real local file paths to
// analyze. Returns the local paths written, sorted. An entry that can't be
// read is skipped rather than failing the whole extraction.
func extractSOFilesTo(apkPath, destDir string) ([]string, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk %s: %w", apkPath, err)
	}
	defer zr.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", destDir, err)
	}

	var paths []string
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".so") {
			continue
		}
		data, err := readZipFile(f)
		if err != nil {
			continue
		}
		localPath := filepath.Join(destDir, strings.ReplaceAll(f.Name, "/", "_"))
		if err := os.WriteFile(localPath, data, 0o644); err != nil {
			continue
		}
		paths = append(paths, localPath)
	}
	sort.Strings(paths)
	return paths, nil
}

// --- AndroidManifest.xml: binary XML parser -----------------------------
//
// AndroidManifest.xml inside an APK is not text XML -- it's Android's
// binary XML ("AXML") format: a sequence of type-prefixed chunks (a string
// pool, then one node per element/attribute-set/text node).
// parseAndroidManifest below decodes just enough of that format to answer
// the questions
// APKInfo needs: the <manifest package=...>, <uses-sdk> versions,
// <uses-permission>/<activity> names, and whether <application> declares
// networkSecurityConfig.
//
// The chunk layout implemented here -- an 8-byte ResChunk_header
// (type/headerSize/size); a string pool chunk immediately following the
// file's own wrapping chunk; a StartElement node whose *own* header is 16
// bytes (the 8-byte ResChunk_header plus a 4-byte line number and a 4-byte
// comment ref), followed by a 20-byte attrExt struct (ns/name/
// attributeStart/attributeSize/attributeCount/idIndex/classIndex/
// styleIndex) and then attributeCount * attributeSize attribute records
// (ns/name/rawValue/typedValue, 20 bytes each in practice) -- was not
// taken on faith from memory of the AOSP ResourceTypes.h layout: it was
// cross-checked byte-for-byte against a real production APK's
// AndroidManifest.xml, dumped structurally with `aapt dump xmltree` as
// ground truth, before being written here. In particular the first
// implementation attempt placed the attrExt fields 8 bytes too early
// (right after the ResChunk_header, omitting the line-number/comment
// fields) and silently matched zero elements -- exactly the kind of bug
// that makes "basic" AXML parsing worth getting right once, centrally,
// with real-world validation, instead of leaving every caller to grep for
// lucky substrings.
//
// Anything this parser doesn't need (styled strings, the resource ID map,
// namespace chunks, CDATA, attribute resource-ID resolution) is skipped
// generically via each chunk's own declared size -- not because it's
// assumed absent, but because skipping unknown/uninteresting chunks by
// size is exactly what makes this forward-compatible with chunk kinds it
// has never heard of.
const (
	androidTypeReference = 0x01 // Res_value::dataType: TYPE_REFERENCE
	androidTypeString    = 0x03 // Res_value::dataType: TYPE_STRING
	androidTypeIntDec    = 0x10 // Res_value::dataType: TYPE_INT_DEC

	axmlChunkStringPool   = 0x0001
	axmlChunkStartElement = 0x0102

	axmlUTF8Flag = 1 << 8 // ResStringPool_header.flags bit for UTF-8 (vs UTF-16) string data
)

// axmlAttrValue is one decoded StartElement attribute: its resolved name
// and, depending on dataType, either a resolved string (androidTypeString)
// or a raw 32-bit value (everything else -- notably the plain integers
// minSdkVersion/targetSdkVersion use).
type axmlAttrValue struct {
	name     string
	dataType byte
	str      string
	num      uint32
}

// looksLikeBinaryXML reports whether data starts with the ResChunk_header
// every Android binary XML document begins with (type=RES_XML_TYPE,
// headerSize=8) -- a cheap check used to decide whether parseAndroidManifest
// is even worth attempting before falling back to heuristicManifestInfo.
func looksLikeBinaryXML(data []byte) bool {
	return len(data) >= 8 &&
		binary.LittleEndian.Uint16(data[0:2]) == 0x0003 &&
		binary.LittleEndian.Uint16(data[2:4]) == 8
}

// parseManifestBestEffort extracts whatever it can from an
// AndroidManifest.xml's raw bytes, trying the real binary XML parser first
// and falling back to a printable-string heuristic if the data doesn't
// look like (or fails to decode as) well-formed Android binary XML. It
// never errors -- "nothing reliably extracted" is simply a zero-valued
// APKInfo.
func parseManifestBestEffort(data []byte) APKInfo {
	if looksLikeBinaryXML(data) {
		if info, err := parseAndroidManifest(data); err == nil {
			return info
		}
	}
	return heuristicManifestInfo(data)
}

// parseAndroidManifest decodes an Android binary XML AndroidManifest.xml,
// extracting the facts APKInfo needs. See the package-level comment above
// for the chunk layout this implements and how it was validated.
//
// Any inconsistency it doesn't already check for defensively (an
// unexpected offset landing outside data's bounds, say) is caught via
// recover and reported as an error rather than panicking -- a malformed or
// truncated manifest should degrade this one step, not crash the trace.
func parseAndroidManifest(data []byte) (info APKInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parse AndroidManifest.xml: %v", r)
		}
	}()

	if !looksLikeBinaryXML(data) {
		return APKInfo{}, fmt.Errorf("not an Android binary XML document")
	}

	var pool []string
	var permissions []string
	var activities []string
	seenPerm := make(map[string]bool)
	seenAct := make(map[string]bool)

	offset := 8
	for offset+8 <= len(data) {
		cType := binary.LittleEndian.Uint16(data[offset:])
		cSize := int(binary.LittleEndian.Uint32(data[offset+4:]))
		if cSize < 8 || offset+cSize > len(data) {
			break // truncated/corrupt chunk: stop, keep whatever was already found
		}

		switch cType {
		case axmlChunkStringPool:
			if pool, err = decodeAXMLStringPool(data, offset); err != nil {
				return info, err
			}

		case axmlChunkStartElement:
			name, attrs := decodeAXMLStartElement(data, offset, pool)
			switch name {
			case "manifest":
				if v, ok := axmlStringAttr(attrs, "package"); ok {
					info.Package = v
				}
			case "uses-sdk":
				if v, ok := axmlIntAttr(attrs, "minSdkVersion"); ok {
					info.MinSDK = strconv.Itoa(int(v))
				}
				if v, ok := axmlIntAttr(attrs, "targetSdkVersion"); ok {
					info.TargetSDK = strconv.Itoa(int(v))
				}
			case "uses-permission", "uses-permission-sdk-23":
				if v, ok := axmlStringAttr(attrs, "name"); ok && !seenPerm[v] {
					seenPerm[v] = true
					permissions = append(permissions, v)
				}
			case "activity":
				if v, ok := axmlStringAttr(attrs, "name"); ok && !seenAct[v] {
					seenAct[v] = true
					activities = append(activities, v)
				}
			case "application":
				if _, ok := axmlAnyAttr(attrs, "networkSecurityConfig"); ok {
					info.HasNSConfig = true
				}
			}
		}

		offset += cSize
	}

	sort.Strings(permissions)
	sort.Strings(activities)
	info.Permissions = permissions
	info.Activities = activities
	return info, nil
}

// decodeAXMLStartElement decodes one RES_XML_START_ELEMENT_TYPE chunk
// (chunkStart points at its ResChunk_header) into its element name and
// attribute list, resolving every string reference against pool.
func decodeAXMLStartElement(data []byte, chunkStart int, pool []string) (string, []axmlAttrValue) {
	// ResXMLTree_node common header (16 bytes: 8-byte ResChunk_header +
	// lineNumber + comment) precedes the attrExt struct.
	attrExtBase := chunkStart + 16
	nameIdx := int(int32(binary.LittleEndian.Uint32(data[attrExtBase+4:])))
	attrStart := int(binary.LittleEndian.Uint16(data[attrExtBase+8:]))
	attrSize := int(binary.LittleEndian.Uint16(data[attrExtBase+10:]))
	attrCount := int(binary.LittleEndian.Uint16(data[attrExtBase+12:]))

	name := poolStr(pool, nameIdx)

	attrsBase := attrExtBase + attrStart
	attrs := make([]axmlAttrValue, 0, attrCount)
	for i := 0; i < attrCount; i++ {
		ab := attrsBase + i*attrSize
		if ab+20 > len(data) {
			break // defensive: a corrupt attributeCount/attributeSize shouldn't run past data
		}
		attrNameIdx := int(int32(binary.LittleEndian.Uint32(data[ab+4:])))
		rawValueIdx := int(int32(binary.LittleEndian.Uint32(data[ab+8:])))
		dataType := data[ab+15]
		dataVal := binary.LittleEndian.Uint32(data[ab+16:])

		av := axmlAttrValue{name: poolStr(pool, attrNameIdx), dataType: dataType, num: dataVal}
		if dataType == androidTypeString {
			av.str = poolStr(pool, rawValueIdx)
		}
		attrs = append(attrs, av)
	}
	return name, attrs
}

// poolStr returns pool[idx], or "" if idx is out of range (as happens for
// e.g. a -1 "no namespace" string reference).
func poolStr(pool []string, idx int) string {
	if idx < 0 || idx >= len(pool) {
		return ""
	}
	return pool[idx]
}

// axmlStringAttr returns the string value of attrs' first entry named
// name, provided it's string-typed.
func axmlStringAttr(attrs []axmlAttrValue, name string) (string, bool) {
	for _, a := range attrs {
		if a.name == name && a.dataType == androidTypeString {
			return a.str, true
		}
	}
	return "", false
}

// axmlIntAttr returns the raw numeric value of attrs' first entry named
// name, regardless of its declared dataType (minSdkVersion/
// targetSdkVersion are always a plain literal int in practice, but this
// doesn't insist on exactly androidTypeIntDec so a differently-typed
// encoder still gets read rather than silently ignored).
func axmlIntAttr(attrs []axmlAttrValue, name string) (uint32, bool) {
	for _, a := range attrs {
		if a.name == name {
			return a.num, true
		}
	}
	return 0, false
}

// axmlAnyAttr returns attrs' first entry named name, of any type --used
// where only an attribute's presence matters (networkSecurityConfig),
// not its value.
func axmlAnyAttr(attrs []axmlAttrValue, name string) (axmlAttrValue, bool) {
	for _, a := range attrs {
		if a.name == name {
			return a, true
		}
	}
	return axmlAttrValue{}, false
}

// decodeAXMLStringPool decodes a RES_STRING_POOL_TYPE chunk (chunkStart
// points at its ResChunk_header) into its plain string values, in index
// order. Styled-string runs (style chunk/indices) are ignored -- this
// package only ever needs plain element/attribute names and values.
func decodeAXMLStringPool(data []byte, chunkStart int) ([]string, error) {
	const headerLen = 28 // 8-byte ResChunk_header + 5 uint32 fields
	if chunkStart+headerLen > len(data) {
		return nil, fmt.Errorf("truncated string pool header")
	}

	stringCount := int(binary.LittleEndian.Uint32(data[chunkStart+8:]))
	flags := binary.LittleEndian.Uint32(data[chunkStart+16:])
	stringsStart := int(binary.LittleEndian.Uint32(data[chunkStart+20:]))
	utf8 := flags&axmlUTF8Flag != 0

	offsetsBase := chunkStart + headerLen
	if stringCount < 0 || offsetsBase+stringCount*4 > len(data) {
		return nil, fmt.Errorf("truncated string pool offsets")
	}

	pool := make([]string, stringCount)
	for i := 0; i < stringCount; i++ {
		relOff := int(binary.LittleEndian.Uint32(data[offsetsBase+i*4:]))
		base := chunkStart + stringsStart + relOff
		if base < 0 || base >= len(data) {
			continue // leave pool[i] == "" rather than fail the whole pool
		}
		if utf8 {
			pool[i] = decodeAXMLUTF8String(data, base)
		} else {
			pool[i] = decodeAXMLUTF16String(data, base)
		}
	}
	return pool, nil
}

// decodeAXMLUTF16String decodes one string pool entry stored as UTF-16LE:
// a 1-or-2-uint16 length prefix (readAXMLLen16), that many UTF-16 code
// units, and a terminating 0x0000 (not included in length).
func decodeAXMLUTF16String(data []byte, base int) string {
	n, p := readAXMLLen16(data, base)
	end := p + n*2
	if n < 0 || p < 0 || end > len(data) || end < p {
		return ""
	}
	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = binary.LittleEndian.Uint16(data[p+i*2:])
	}
	return string(utf16.Decode(units))
}

// readAXMLLen16 reads a UTF-16 string pool length prefix at data[p:]: one
// uint16 if its top bit is clear, or two uint16s (combined into a 31-bit
// length) if it's set -- the extended form that lets a single string
// exceed 0x7fff UTF-16 code units.
func readAXMLLen16(data []byte, p int) (n, next int) {
	if p+2 > len(data) {
		return 0, p
	}
	v0 := int(binary.LittleEndian.Uint16(data[p:]))
	if v0&0x8000 == 0 {
		return v0, p + 2
	}
	if p+4 > len(data) {
		return 0, p
	}
	v1 := int(binary.LittleEndian.Uint16(data[p+2:]))
	return ((v0 & 0x7fff) << 16) | v1, p + 4
}

// decodeAXMLUTF8String decodes one string pool entry stored as UTF-8: a
// UTF-16-length prefix (the decoded length, unused here), a UTF-8-length
// prefix, that many UTF-8 bytes, and a terminating 0x00.
func decodeAXMLUTF8String(data []byte, base int) string {
	_, p := readAXMLLen8(data, base) // UTF-16 length, not needed
	n, p2 := readAXMLLen8(data, p)
	end := p2 + n
	if n < 0 || p2 < 0 || end > len(data) || end < p2 {
		return ""
	}
	return string(data[p2:end])
}

// readAXMLLen8 reads a UTF-8 string pool length prefix at data[p:]: one
// byte if its top bit is clear, or two bytes (combined into a 15-bit
// length) if it's set.
func readAXMLLen8(data []byte, p int) (n, next int) {
	if p+1 > len(data) {
		return 0, p
	}
	b0 := int(data[p])
	if b0&0x80 == 0 {
		return b0, p + 1
	}
	if p+2 > len(data) {
		return 0, p
	}
	b1 := int(data[p+1])
	return ((b0 & 0x7f) << 8) | b1, p + 2
}

// --- AndroidManifest.xml: printable-string heuristic fallback -----------
//
// When a manifest isn't (or doesn't parse as) well-formed Android binary
// XML, heuristicManifestInfo falls back to exactly the kind of "grep for
// package info" approach Strategy 2 is named for: pull every printable
// string out of the raw bytes and pattern-match the ones that look like
// permissions, activity classes, or the app's own package name. It can't
// recover MinSDK/TargetSDK this way (those are binary integers, not text,
// even when everything else in the manifest is somehow still readable as
// strings) -- those are simply left blank.
var (
	// dottedIdentPattern matches a Java-style dotted identifier:
	// "com.example.app.MainActivity", "android.permission.INTERNET", etc.
	dottedIdentPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_$]*)+$`)

	// androidPermissionPattern matches a permission name: some dotted
	// prefix (not necessarily "android") followed by ".permission." and an
	// ALL_CAPS identifier -- real manifests declare plenty of
	// non-"android.permission.*" custom permissions (e.g.
	// "com.example.app.permission.ACCESS_FOO") that a narrower pattern
	// would miss.
	androidPermissionPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]*\.permission\.[A-Z0-9_]+$`)
)

// frameworkIdentPrefixes are dotted-identifier prefixes that are never an
// app's own package -- excluded from package-name voting so a
// framework/library class or a permission string (itself a dotted
// identifier) can't outvote the app's actual classes.
var frameworkIdentPrefixes = []string{
	"android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
	"com.google.", "com.android.",
}

// heuristicManifestInfo extracts whatever it can from manifest data that
// isn't necessarily valid Android binary XML, using only printable-string
// pattern matching (see extractPrintableStrings).
func heuristicManifestInfo(data []byte) APKInfo {
	runs := extractPrintableStrings(data, minPrintableRun)

	var idents []string
	var permissions []string
	var activities []string
	seenPerm := make(map[string]bool)
	seenAct := make(map[string]bool)

	for _, r := range runs {
		s := r.value

		if dottedIdentPattern.MatchString(s) {
			if !hasFrameworkPrefix(s) {
				idents = append(idents, s)
			}
			if strings.HasSuffix(s, "Activity") && !seenAct[s] {
				seenAct[s] = true
				activities = append(activities, s)
			}
		}
		if androidPermissionPattern.MatchString(s) && !seenPerm[s] {
			seenPerm[s] = true
			permissions = append(permissions, s)
		}
	}

	sort.Strings(permissions)
	sort.Strings(activities)

	return APKInfo{
		Package:     guessPackageFromIdentifiers(idents),
		Permissions: permissions,
		Activities:  activities,
	}
}

// hasFrameworkPrefix reports whether s starts with a known
// framework/library namespace (see frameworkIdentPrefixes).
func hasFrameworkPrefix(s string) bool {
	for _, p := range frameworkIdentPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// guessPackageFromIdentifiers votes for the most likely app package name
// among a set of dotted identifiers (typically class names): every
// identifier contributes each of its dot-truncated prefixes of at least 2
// segments (excluding the full identifier itself, which is a class, not a
// package) as a candidate, and the candidate shared by the most
// identifiers wins -- ties broken in favor of the longer (more specific)
// candidate, then lexicographically, for determinism.
//
// This works even when the package name never appears in the data as a
// standalone string (only as a prefix of longer class names), which a
// simple "most common dotted string" heuristic would miss entirely.
func guessPackageFromIdentifiers(idents []string) string {
	votes := make(map[string]int)
	for _, id := range idents {
		for _, cand := range dotPrefixes(id) {
			votes[cand]++
		}
	}

	var best string
	var bestVotes int
	for cand, v := range votes {
		if betterPackageCandidate(cand, v, best, bestVotes) {
			best, bestVotes = cand, v
		}
	}
	return best
}

// betterPackageCandidate reports whether (cand, votes) should replace
// (curBest, curVotes) as guessPackageFromIdentifiers' running winner.
func betterPackageCandidate(cand string, votes int, curBest string, curVotes int) bool {
	if votes != curVotes {
		return votes > curVotes
	}
	if len(cand) != len(curBest) {
		return len(cand) > len(curBest)
	}
	return cand < curBest
}

// dotPrefixes returns id's proper dot-separated prefixes of at least 2
// segments (e.g. "com.example.app.MainActivity" -> ["com.example",
// "com.example.app"]), excluding id itself. Identifiers with fewer than 3
// segments yield no candidates -- a 2-segment identifier's only 2-segment
// "prefix" would be itself, which can't be its own package.
func dotPrefixes(id string) []string {
	segs := strings.Split(id, ".")
	if len(segs) < 3 {
		return nil
	}
	prefixes := make([]string, 0, len(segs)-2)
	for i := 2; i < len(segs); i++ {
		prefixes = append(prefixes, strings.Join(segs[:i], "."))
	}
	return prefixes
}

// --- Strategy 3: jadx decompilation --------------------------------------

// retrofitPattern matches a Retrofit HTTP method annotation, e.g.
// @POST("/api/v1/login") or @GET("/api/v1/user/{id}").
var retrofitPattern = regexp.MustCompile(`@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]+)"`)

// retrofitMethodDecl pulls the method name off the Java declaration line
// immediately following a Retrofit annotation.
var retrofitMethodDecl = regexp.MustCompile(`\s+\w+[\w<>,\s]*\s+(\w+)\s*\(`)

// okHttpURLCallPattern matches an OkHttp Request.Builder "url(...)" call.
var okHttpURLCallPattern = regexp.MustCompile(`\.url\s*\(`)

// newURLPattern matches a plain java.net.URL construction, the usual
// entry point for HttpURLConnection-based requests.
var newURLPattern = regexp.MustCompile(`new\s+URL\s*\(`)

// nativeDeclPattern matches a JNI native method declaration, e.g.
// "public static native String nativeSign(String input);".
var nativeDeclPattern = regexp.MustCompile(`\bnative\s+[\w<>\[\],\s]+?\s+(\w+)\s*\(`)

// loadLibraryPattern matches a System.loadLibrary("name") call.
var loadLibraryPattern = regexp.MustCompile(`System\.loadLibrary\s*\(\s*"([^"]+)"`)

// javaMethodDeclPattern matches a Java method signature line (an access
// modifier is required, which is what keeps it from matching an ordinary
// statement), used to find the method enclosing a non-Retrofit call site.
var javaMethodDeclPattern = regexp.MustCompile(`^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?[\w<>\[\],.?\s]+?\s+(\w+)\s*\([^=;]*\)\s*(?:throws\s+[\w,.\s]+)?\s*\{?\s*$`)

// maxEnclosingMethodLookback bounds how far back searchJavaSource scans
// for the Java method enclosing a non-annotation call site.
const maxEnclosingMethodLookback = 60

// searchJavaSource walks jadxDir (a jadx decompilation output directory)
// and returns one JavaRef per line, across every .java file, that contains
// any of searchTerms -- replacing the old "single exact path substring"
// check with the same multi-term, ranked-by-specificity search
// searchDexStrings uses (see buildSearchTerms).
//
// A Retrofit annotation line gets a structured Annotation ("POST
// /api/v1/login") and Method (pulled off the next line's declaration); an
// OkHttp ".url(...)" or "new URL(...)" line gets a plain Annotation tag
// naming which HTTP client it is, plus Method found by scanning backward
// for the enclosing Java method declaration. Any matched line in a file
// that also declares a native method or calls System.loadLibrary is
// flagged CallsNative with those names collected into NativeMethods.
func searchJavaSource(jadxDir string, searchTerms []string) []JavaRef {
	refs, _ := searchJavaSourceContext(context.Background(), jadxDir, searchTerms, nil)
	return refs
}

type javaProgressFunc func(scanned, hits int)

func searchJavaSourceContext(ctx context.Context, jadxDir string, searchTerms []string, onProgress javaProgressFunc) ([]JavaRef, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	terms := significantTerms(searchTerms)
	if len(terms) == 0 {
		return nil, nil
	}

	var refs []JavaRef
	scanned := 0
	lastEmit := time.Now()
	walkErr := filepath.Walk(jadxDir, func(path string, fi os.FileInfo, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || fi == nil || fi.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}
		scanned++
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // one unreadable file shouldn't sink the whole walk
		}
		content := string(data)
		if !containsAnyTerm(content, terms) {
			if onProgress != nil && (scanned%200 == 0 || time.Since(lastEmit) >= 400*time.Millisecond) {
				lastEmit = time.Now()
				onProgress(scanned, len(refs))
			}
			return nil
		}

		relPath, err := filepath.Rel(jadxDir, path)
		if err != nil {
			relPath = path
		}
		relPath = filepath.ToSlash(relPath)
		className := javaClassNameFromPath(relPath)
		lines := strings.Split(content, "\n")
		nativeMethods, loadLibs := scanNativeDeclarations(lines)

		for i, line := range lines {
			term := firstMatchingTerm(line, terms)
			if term == "" {
				continue
			}

			ref := JavaRef{
				File:        relPath,
				Class:       className,
				Line:        i + 1,
				Snippet:     strings.TrimSpace(line),
				MatchedTerm: term,
			}

			if m := retrofitPattern.FindStringSubmatch(line); len(m) >= 3 {
				ref.Annotation = m[1] + " " + m[2]
				if i+1 < len(lines) {
					if dm := retrofitMethodDecl.FindStringSubmatch(lines[i+1]); len(dm) >= 2 {
						ref.Method = dm[1]
					}
				}
			} else {
				ref.Method = findEnclosingJavaMethod(lines, i)
				switch {
				case okHttpURLCallPattern.MatchString(line):
					ref.Annotation = "OkHttp"
				case newURLPattern.MatchString(line):
					ref.Annotation = "HttpURLConnection"
				}
			}

			if len(nativeMethods) > 0 || len(loadLibs) > 0 {
				ref.CallsNative = true
				ref.NativeMethods = append(append([]string{}, nativeMethods...), loadLibs...)
			}

			refs = append(refs, ref)
		}
		if onProgress != nil && (scanned%200 == 0 || time.Since(lastEmit) >= 400*time.Millisecond) {
			lastEmit = time.Now()
			onProgress(scanned, len(refs))
		}
		return nil
	})
	if walkErr != nil && ctx.Err() != nil {
		return refs, ctx.Err()
	}
	return refs, nil
}

// firstMatchingTerm returns the first of terms found in line, or "" if
// none match. Since buildSearchTerms orders terms most-to-least specific,
// "first" here means "most specific".
func firstMatchingTerm(line string, terms []string) string {
	for _, t := range terms {
		if strings.Contains(line, t) {
			return t
		}
	}
	return ""
}

// scanNativeDeclarations scans every line of a Java source file for JNI
// native method declarations and System.loadLibrary calls.
func scanNativeDeclarations(lines []string) (nativeMethods, loadLibs []string) {
	for _, line := range lines {
		if m := nativeDeclPattern.FindStringSubmatch(line); len(m) >= 2 {
			nativeMethods = append(nativeMethods, m[1])
		}
		if m := loadLibraryPattern.FindStringSubmatch(line); len(m) >= 2 {
			loadLibs = append(loadLibs, "lib"+m[1]+".so")
		}
	}
	return nativeMethods, loadLibs
}

// findEnclosingJavaMethod scans backward from lineIdx (inclusive) for the
// nearest Java method declaration, returning its name ("" if none is found
// within maxEnclosingMethodLookback lines).
func findEnclosingJavaMethod(lines []string, lineIdx int) string {
	limit := lineIdx - maxEnclosingMethodLookback
	if limit < 0 {
		limit = 0
	}
	for i := lineIdx; i >= limit; i-- {
		if m := javaMethodDeclPattern.FindStringSubmatch(lines[i]); m != nil {
			return m[1]
		}
	}
	return ""
}

// javaClassNameFromPath derives a fully-qualified class name from a jadx
// output file's path relative to the decompilation root (jadx nests
// decompiled sources under a "sources/" directory, which isn't part of the
// package name).
func javaClassNameFromPath(relPath string) string {
	name := strings.TrimSuffix(relPath, ".java")
	name = strings.ReplaceAll(name, "/", ".")
	name = strings.TrimPrefix(name, "sources.")
	return name
}

// decompileJadx runs `jadxPath -d outDir --no-res apkPath`, bounded by
// timeout (<=0 defaults to defaultJadxTimeout), skipping the run entirely
// if outDir already exists (e.g. from a previous Trace call against the
// same Options.OutputDir).
func decompileJadx(jadxPath, apkPath, outDir string, timeout time.Duration) error {
	if _, err := os.Stat(outDir); err == nil {
		return nil // already decompiled
	}
	if timeout <= 0 {
		timeout = defaultJadxTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, jadxPath, "-d", outDir, "--no-res", apkPath)
	boundCommandWait(cmd, timeout)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("jadx: %w: %s", err, lastLines(string(out), 20))
	}
	return nil
}

// lastLines returns at most n trailing non-empty lines of s, for including
// a bounded amount of a failed command's output in an error message.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// --- external tool availability -----------------------------------------

// toolVersion reports whether the tool at path is runnable: it invokes
// `path args...` (bounded by timeout, <=0 defaults to
// defaultToolCheckTimeout) and, if that exits successfully within the
// timeout, returns the first line of its combined output as version. An
// empty path, a nonexistent binary, a non-zero exit, and exceeding the
// timeout are all simply "not available" (available=false) -- jadx and r2
// are optional, so none of these are treated as errors.
func toolVersion(path string, timeout time.Duration, args ...string) (version string, available bool) {
	if path == "" {
		return "", false
	}
	if timeout <= 0 {
		timeout = defaultToolCheckTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	boundCommandWait(cmd, timeout)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	return firstLine(strings.TrimSpace(string(out))), true
}

// boundCommandWait sets cmd.WaitDelay so that, if ctx cancels cmd but a
// grandchild process it spawned keeps cmd's stdout/stderr pipe open (a
// classic hang with shell-script-wrapped tools: killing the direct child
// does not kill *its* children), Wait/CombinedOutput/Run still return
// after waitFor instead of blocking indefinitely on pipe EOF that may
// never come. See the os/exec package docs on Cmd.WaitDelay and Cmd.Cancel
// for the failure mode this guards against.
func boundCommandWait(cmd *exec.Cmd, waitFor time.Duration) {
	if waitFor <= 0 {
		waitFor = defaultToolCheckTimeout
	}
	cmd.WaitDelay = waitFor
}

// firstLine returns s up to (not including) its first newline, or the
// whole of s if it has none.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// --- Strategy 4: radare2 native analysis ---------------------------------
//
// r2's human-readable table output (`izz`, `afl`) is exactly the kind of
// fragile-to-scrape text the old implementation's "basic" r2 analysis
// relied on -- column layouts vary across r2 versions and a string's own
// content can contain whitespace that defeats naive field-splitting. This
// version uses r2's JSON output instead (`izzj`, `aflj`, `pdfj`), decoded
// with encoding/json: both commands' field names below (vaddr/string,
// offset/name, ops[].type/disasm) were confirmed against a real .so file
// with a real r2 5.8.9 build, not assumed from memory.
//
// izzj and aflj can both be requested in one r2 invocation
// ("izzj; aa; aflj") -- `aa` (basic analysis, needed before aflj returns
// anything) prints nothing itself, so the combined output is just the two
// JSON arrays back to back, which decodeR2Analysis reads as a sequential
// stream rather than needing two separate (slower) process invocations.

// r2StringEntry is the subset of `izzj` fields this package uses.
type r2StringEntry struct {
	Vaddr  int64  `json:"vaddr"`
	String string `json:"string"`
}

// r2FunctionEntry is the subset of `aflj` fields this package uses.
type r2FunctionEntry struct {
	Offset int64  `json:"offset"`
	Name   string `json:"name"`
}

// r2DisasmOp is one instruction from `pdfj`'s ops array.
type r2DisasmOp struct {
	Type   string `json:"type"`
	Disasm string `json:"disasm"`
}

// r2DisasmResult is `pdfj`'s top-level shape.
type r2DisasmResult struct {
	Ops []r2DisasmOp `json:"ops"`
}

// decodeR2Analysis decodes the combined output of
// `r2 -q -c "izzj; aa; aflj" soFile`: a strings array immediately followed
// by a functions array, with no separator between them (aa itself is
// silent) -- read as a sequential JSON stream rather than one document.
func decodeR2Analysis(output []byte) ([]r2StringEntry, []r2FunctionEntry, error) {
	trimmed := skipNonJSONPrefix(output)
	dec := json.NewDecoder(bytes.NewReader(trimmed))

	var strs []r2StringEntry
	if err := dec.Decode(&strs); err != nil {
		return nil, nil, fmt.Errorf("decode izzj output: %w", err)
	}
	var funcs []r2FunctionEntry
	if err := dec.Decode(&funcs); err != nil {
		// Some r2 builds emit warning text between izzj and aflj; try
		// recovering if another JSON array follows in the remainder.
		rem, _ := io.ReadAll(dec.Buffered())
		if rest := skipNonJSONPrefix(rem); len(rest) > 0 && rest[0] == '[' {
			if err2 := json.NewDecoder(bytes.NewReader(rest)).Decode(&funcs); err2 == nil {
				return strs, funcs, nil
			}
		}
		return nil, nil, fmt.Errorf("decode aflj output: %w", err)
	}
	return strs, funcs, nil
}

// skipNonJSONPrefix advances past any leading non-JSON banner lines (such as
// radare2 warnings) to the first plausible JSON array start ("[]" or "[{").
func skipNonJSONPrefix(b []byte) []byte {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return b
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '[' {
			continue
		}
		j := i + 1
		for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\r' || b[j] == '\n') {
			j++
		}
		if j < len(b) && (b[j] == '{' || b[j] == ']') {
			return b[i:]
		}
	}
	return b
}

// nativeInterestingKeyword matches crypto- and signature-related
// vocabulary worth surfacing from a .so file's strings. Delimiters are
// spelled out explicitly (start/end of string, or a non-alphanumeric
// character) rather than using \b, specifically so underscore counts as a
// delimiter: real crypto-ish identifiers are heavily underscore_separated
// ("sign_params", "app_key_secret"), and \b's definition of a word
// character (which includes underscore) would otherwise block a match
// right at the boundary that matters most. This does not reopen the door
// to matching mangled C++ symbols that happen to contain "sign"
// (e.g. "_ZNKSt6...do_negative_signEv") -- those are already excluded
// upfront by isInterestingNativeString's "_Z" prefix check, independent of
// this pattern.
var nativeInterestingKeyword = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(aes|des3?|rsa|md5|sha(1|256|512)?|hmac|base64|pkcs[157]?|cbc|ecb|gcm|crypto|cipher|encrypt|decrypt|signature|sign|secret|app[_-]?key|nonce|salt|token)(?:[^a-z0-9]|$)`)

// isInterestingNativeString reports whether s is worth surfacing as a
// NativeRef string: it mentions one of the flow's own search terms, looks
// like a URL, or matches a crypto/signature-related keyword. Mangled
// C/C++ symbol names (which `izzj` includes among "all strings" since
// they live in the string table too) are excluded outright -- they're
// reported separately, demangled-enough-to-read, via the function list.
func isInterestingNativeString(s string, searchTerms []string) bool {
	if s == "" || strings.HasPrefix(s, "_Z") || strings.HasPrefix(s, "__") {
		return false
	}
	if containsAnyTerm(s, searchTerms) {
		return true
	}
	if strings.Contains(s, "://") {
		return true
	}
	return nativeInterestingKeyword.MatchString(s)
}

// jniExportPattern matches a JNI bridge export: JNI_OnLoad, or a
// Java_<package>_<Class>_<method>-mangled static native implementation.
var jniExportPattern = regexp.MustCompile(`^(Java_[A-Za-z0-9_]+|JNI_OnLoad)$`)

// stripR2Prefix removes r2's symbol-kind prefixes (sym., sym.imp., imp.,
// fcn.) so a function name can be matched/displayed without them.
func stripR2Prefix(name string) string {
	name = strings.TrimPrefix(name, "sym.imp.")
	name = strings.TrimPrefix(name, "sym.")
	name = strings.TrimPrefix(name, "imp.")
	name = strings.TrimPrefix(name, "fcn.")
	return name
}

// isJNIExport reports whether name (as reported by aflj, with its r2
// prefix still attached) is a JNI bridge export.
func isJNIExport(name string) bool {
	return jniExportPattern.MatchString(stripR2Prefix(name))
}

// isImportName reports whether name (as reported by aflj) is an imported
// (externally defined) symbol rather than one defined in this .so.
func isImportName(name string) bool {
	return strings.Contains(name, "imp.")
}

// matchesKnownNativeMethod reports whether name (with its r2 prefix
// stripped) is -- or JNI-mangles to -- one of knownMethods (the native
// method names Strategy 3 found declared in Java), returning the matched
// plain method name. JNI mangles a declared method like "nativeSign" into
// a longer symbol such as "Java_com_example_Signer_nativeSign" (package
// and class folded into underscore-separated segments first), so a plain
// equality check would miss virtually every real native method --
// matching by suffix after the last underscore run catches this without
// needing a full JNI name demangler.
func matchesKnownNativeMethod(name string, knownMethods []string) (string, bool) {
	clean := stripR2Prefix(name)
	for _, m := range knownMethods {
		if m == "" {
			continue
		}
		if clean == m || strings.HasSuffix(clean, "_"+m) {
			return m, true
		}
	}
	return "", false
}

// extractCallTargets pulls the called symbol off each "call"-type op in a
// `pdfj` disassembly (pdfjOutput), in order, deduplicated. Non-call ops
// are ignored; malformed input yields nil rather than an error, since this
// is only ever used to enrich a NativeRef that's already otherwise valid.
func extractCallTargets(pdfjOutput []byte) []string {
	var result r2DisasmResult
	if err := json.Unmarshal(pdfjOutput, &result); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var calls []string
	for _, op := range result.Ops {
		if op.Type != "call" && op.Type != "ucall" {
			continue
		}
		fields := strings.Fields(op.Disasm)
		if len(fields) == 0 {
			continue
		}
		target := fields[len(fields)-1]
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		calls = append(calls, target)
	}
	return calls
}

// buildNativeRefs is the pure core of Strategy 4: given one .so file's
// decoded strings and functions (from decodeR2Analysis, or any test
// fixture shaped the same way) plus the native method names Strategy 3
// found declared in Java, it decides what's worth reporting -- JNI_OnLoad,
// any Java_* JNI export, and any function matching a known declared native
// method -- and assembles a NativeRef for each, all sharing the .so file's
// interesting strings and imports. The deeper per-function disassembly
// used to populate Calls is deferred to disasm (nil-able) so this stays
// independently testable without a real r2 process.
//
// If nothing function-wise matches but the .so still has interesting
// strings, a single summary NativeRef (empty Function) carries them so
// that signal isn't silently dropped; if there's truly nothing of
// interest, buildNativeRefs returns no refs at all.
func buildNativeRefs(soFile string, strs []r2StringEntry, funcs []r2FunctionEntry, knownMethods, searchTerms []string, disasm func(funcName string) []string) []NativeRef {
	interesting := collectInterestingStrings(strs, searchTerms)
	imports := collectImportNames(funcs)

	var refs []NativeRef
	seen := make(map[string]bool)
	addRef := func(name string, offset int64, raw string) {
		if seen[name] {
			return
		}
		seen[name] = true
		var calls []string
		if disasm != nil {
			calls = disasm(raw)
		}
		refs = append(refs, NativeRef{
			SOFile:   soFile,
			Function: name,
			Address:  fmt.Sprintf("0x%x", offset),
			Calls:    calls,
			Strings:  interesting,
			Imports:  imports,
		})
	}

	for _, f := range funcs {
		switch {
		case isJNIExport(f.Name):
			addRef(stripR2Prefix(f.Name), f.Offset, f.Name)
		default:
			if m, ok := matchesKnownNativeMethod(f.Name, knownMethods); ok {
				addRef(m, f.Offset, f.Name)
			}
		}
	}

	if len(refs) == 0 && len(interesting) > 0 {
		refs = append(refs, NativeRef{SOFile: soFile, Strings: interesting, Imports: imports})
	}
	return refs
}

// collectInterestingStrings returns strs' interesting values (see
// isInterestingNativeString), in file order, deduplicated and capped at
// maxInterestingStrings.
func collectInterestingStrings(strs []r2StringEntry, searchTerms []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range strs {
		if seen[s.String] || !isInterestingNativeString(s.String, searchTerms) {
			continue
		}
		seen[s.String] = true
		out = append(out, s.String)
		if len(out) >= maxInterestingStrings {
			break
		}
	}
	return out
}

// collectImportNames returns funcs' imported (externally defined) symbol
// names, r2-prefix stripped, in file order, deduplicated.
func collectImportNames(funcs []r2FunctionEntry) []string {
	seen := make(map[string]bool)
	var out []string
	for _, f := range funcs {
		if !isImportName(f.Name) {
			continue
		}
		clean := stripR2Prefix(f.Name)
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
	}
	return out
}

// analyzeNative runs radare2 against one .so file and turns its findings
// into NativeRefs via buildNativeRefs. It only errors if r2 itself can't
// be run or its output can't be decoded -- "nothing interesting found" is
// a normal, non-error empty result.
func analyzeNative(r2Path, soFile string, knownMethods, searchTerms []string, timeout time.Duration) ([]NativeRef, error) {
	return analyzeNativeContext(context.Background(), r2Path, soFile, knownMethods, searchTerms, timeout)
}

func analyzeNativeContext(parent context.Context, r2Path, soFile string, knownMethods, searchTerms []string, timeout time.Duration) ([]NativeRef, error) {
	if parent == nil {
		parent = context.Background()
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultR2Timeout
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r2Path, "-q", "-c", "izzj; aa; aflj", soFile)
	configureCancellableCmd(cmd)
	out, err := cmd.Output()
	if err != nil {
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		return nil, fmt.Errorf("r2 %s: %w", filepath.Base(soFile), err)
	}

	strs, funcs, err := decodeR2Analysis(out)
	if err != nil {
		return nil, fmt.Errorf("decode r2 output for %s: %w", filepath.Base(soFile), err)
	}

	disasm := func(funcName string) []string {
		return disassembleCallsContext(parent, r2Path, soFile, funcName, timeout)
	}
	return buildNativeRefs(filepath.Base(soFile), strs, funcs, knownMethods, searchTerms, disasm), nil
}

func disassembleCalls(r2Path, soFile, funcName string, timeout time.Duration) []string {
	return disassembleCallsContext(context.Background(), r2Path, soFile, funcName, timeout)
}

func disassembleCallsContext(parent context.Context, r2Path, soFile, funcName string, timeout time.Duration) []string {
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultR2Timeout
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r2Path, "-q", "-c", fmt.Sprintf("aa; pdfj @ %s", funcName), soFile)
	configureCancellableCmd(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return extractCallTargets(out)
}

// --- call graph -----------------------------------------------------------

// buildCallGraph assembles the App -> HTTP -> Java -> JNI -> native call
// graph from one flow's Java and native findings.
//
// The original implementation gave a JNI edge's target node ("native:" +
// method name, representing the *declared* native method) a different id
// than the matching NativeRef's own node (soFile + ":" + function,
// representing the *resolved* r2 symbol) -- even when they were the exact
// same real-world function, so the graph never actually connected a Java
// method to the native analysis found for it; they were two disconnected
// islands that happened to render near each other. This version adds an
// explicit "resolved" bridge edge between them whenever a NativeRef's
// Function matches a JavaRef's declared native method name, so the chain
// HTTP -> Java -> (jni) declared native method -> (resolved) r2 symbol ->
// (native_call) whatever it calls is actually continuous.
func buildCallGraph(flow *types.Flow, javaRefs []JavaRef, nativeRefs []NativeRef) []CallEdge {
	if flow == nil {
		flow = &types.Flow{}
	}

	var edges []CallEdge
	httpNode := strings.TrimSpace(flow.Method + " " + flow.Path)
	if httpNode == "" {
		httpNode = flow.URL
	}
	edges = append(edges, CallEdge{From: "App", To: httpNode, Type: "http", Label: flow.Host})

	nativeByFunc := make(map[string][]NativeRef, len(nativeRefs))
	for _, nr := range nativeRefs {
		nativeByFunc[nr.Function] = append(nativeByFunc[nr.Function], nr)
	}

	for _, jr := range javaRefs {
		javaNode := jr.Class
		if jr.Method != "" {
			javaNode += "." + jr.Method + "()"
		}
		edges = append(edges, CallEdge{From: httpNode, To: javaNode, Type: "java_call", Label: jr.Annotation})

		for _, nm := range jr.NativeMethods {
			if strings.HasSuffix(nm, ".so") {
				edges = append(edges, CallEdge{From: javaNode, To: nm, Type: "jni", Label: "loadLibrary"})
				continue
			}

			nativeSymbolNode := "native:" + nm
			edges = append(edges, CallEdge{From: javaNode, To: nativeSymbolNode, Type: "jni"})
			for _, nr := range nativeByFunc[nm] {
				resolvedNode := nr.SOFile + ":" + nr.Function
				edges = append(edges, CallEdge{From: nativeSymbolNode, To: resolvedNode, Type: "native_call", Label: "resolved"})
			}
		}
	}

	for _, nr := range nativeRefs {
		nativeNode := nr.SOFile + ":" + nr.Function
		for _, call := range nr.Calls {
			edges = append(edges, CallEdge{From: nativeNode, To: call, Type: "native_call"})
		}
	}

	return edges
}

// --- Mermaid rendering ----------------------------------------------------

// mermaidHeader is generateMermaid's fixed preamble: a graph declaration
// plus one classDef per node kind, always emitted (even for an empty
// graph) so a consuming frontend can rely on a stable style contract.
const mermaidHeader = `graph TD
    classDef http fill:#064e3b,color:#34d399
    classDef java fill:#1e3a5f,color:#38bdf8
    classDef jni fill:#422006,color:#fbbf24
    classDef native fill:#4c0519,color:#f87171
`

// maxMermaidLabelLen caps a rendered node/edge label's length (a full URL
// or file path can otherwise make a single Mermaid line unreadable).
const maxMermaidLabelLen = 80

// mermaidIDInvalid matches any run of characters not valid in a bare
// (unquoted) Mermaid node id.
var mermaidIDInvalid = regexp.MustCompile(`[^A-Za-z0-9_]+`)

// mermaidNodeID turns an arbitrary node name (a URL, a file path, a Java
// signature, ...) into a valid bare Mermaid node id: every run of
// non-alphanumeric characters collapses to a single underscore, a
// resulting id starting with a digit is prefixed with "n", and an id that
// collapses to nothing at all (e.g. the input was only punctuation)
// becomes the literal "node".
func mermaidNodeID(name string) string {
	id := mermaidIDInvalid.ReplaceAllString(name, "_")
	if strings.Trim(id, "_") == "" {
		return "node" // name had no alphanumeric content at all (incl. name == "")
	}
	if id[0] >= '0' && id[0] <= '9' {
		return "n" + id
	}
	return id
}

// mermaidLabel renders s as safe-ish text for inside a double-quoted
// Mermaid node/edge label: embedded double quotes become single quotes,
// newlines collapse to spaces, and anything past maxMermaidLabelLen runes
// is truncated with an ASCII "..." marker. Truncation counts runes, not
// bytes, so a multi-byte UTF-8 character (decompiled strings are not
// guaranteed to be ASCII) is never split in half.
func mermaidLabel(s string) string {
	s = strings.ReplaceAll(s, `"`, "'")
	s = strings.ReplaceAll(s, "\n", " ")
	if r := []rune(s); len(r) > maxMermaidLabelLen {
		s = string(r[:maxMermaidLabelLen-3]) + "..."
	}
	return s
}

// mermaidArrowBase returns edgeType's base Mermaid arrow: dashed for a JNI
// hop, thick for a native call, plain otherwise (http and java_call, per
// the task's own example, are both rendered as plain arrows -- the node
// coloring already carries that distinction).
func mermaidArrowBase(edgeType string) string {
	switch edgeType {
	case "jni":
		return "-.->"
	case "native_call":
		return "==>"
	default:
		return "-->"
	}
}

// mermaidNodeClass returns the classDef name a node should carry, derived
// from the type of the first edge found pointing *into* it (edges are
// walked in order, so this is well-defined even if conflicting edge types
// target the same node more than once). A node that's never a "To" --
// "App", the graph's root -- gets no class and renders with Mermaid's
// default styling.
func mermaidNodeClass(edges []CallEdge) map[string]string {
	class := make(map[string]string, len(edges))
	for _, e := range edges {
		if _, ok := class[e.To]; ok {
			continue
		}
		switch e.Type {
		case "http":
			class[e.To] = "http"
		case "java_call":
			class[e.To] = "java"
		case "jni":
			class[e.To] = "jni"
		case "native_call":
			class[e.To] = "native"
		}
	}
	return class
}

// generateMermaid renders edges as a styled Mermaid flowchart: a fixed
// classDef header (see mermaidHeader), then one line per edge, each node
// declared with its label and class the first time it appears and
// referenced by bare id thereafter.
func generateMermaid(edges []CallEdge) string {
	nodeClass := mermaidNodeClass(edges)
	declared := make(map[string]bool, len(edges)*2)

	declare := func(name string) string {
		id := mermaidNodeID(name)
		if declared[id] {
			return id
		}
		declared[id] = true
		if class := nodeClass[name]; class != "" {
			return fmt.Sprintf(`%s["%s"]:::%s`, id, mermaidLabel(name), class)
		}
		return fmt.Sprintf(`%s["%s"]`, id, mermaidLabel(name))
	}

	lines := []string{strings.TrimRight(mermaidHeader, "\n"), ""}
	for _, e := range edges {
		fromPart := declare(e.From)
		toPart := declare(e.To)

		// Only jni and native_call edges render a |label|, matching the
		// task's own example exactly: http and java_call are plain arrows
		// (the node coloring already carries that distinction) even when
		// Label is set to something informative like the request's host.
		var label string
		switch e.Type {
		case "jni":
			label = e.Label
			if label == "" {
				label = "JNI"
			}
		case "native_call":
			label = e.Label
		}

		arrow := mermaidArrowBase(e.Type)
		if label != "" {
			arrow = fmt.Sprintf("%s|%s|", arrow, mermaidLabel(label))
		}

		lines = append(lines, fmt.Sprintf("    %s %s %s", fromPart, arrow, toPart))
	}

	return strings.Join(lines, "\n")
}

// --- top-level orchestration ----------------------------------------------

// Trace runs all four strategies against flow and returns everything they
// found. Strategies 1 (DEX search) and 2 (APK info) always run once an APK
// is available; strategies 3 (jadx) and 4 (radare2) run only if their tool
// is found on PATH (or at the configured Options path), recorded as a
// "skip" step rather than an error when it isn't.
//
// Trace only returns a non-nil error when no APK could be obtained at all
// (neither Options.APKPath nor a pullable Options.Package was given, or
// pulling failed) -- every other failure (a strategy's tool erroring, one
// .so file's analysis failing, ...) is absorbed into that strategy's Steps
// entry so the rest of the pipeline still runs and still reports whatever
// it found. Even in the one error case, Trace still returns a non-nil
// *TraceResult (with Steps/Summary populated) rather than nil, so a caller
// can show the user what was tried.
//
// onStep, if non-nil, is called once per entry appended to
// TraceResult.Steps, in order -- the first call is always step "start",
// the last is always "done".
func Trace(flow *types.Flow, opts Options, onStep StepCallback) (*TraceResult, error) {
	var progressCb ProgressCallback
	if onStep != nil {
		progressCb = func(ev ProgressEvent) {
			if ev.Step != nil {
				onStep(ev.Step.Name, ev.Step.Detail)
			}
		}
	}
	return TraceContext(context.Background(), flow, opts, progressCb)
}

// TraceContext runs DeepTrace with real-time structured progress across all 8
// pipeline stages, full context.Context cancellation (terminating external adb,
// jadx, and r2 subprocesses promptly), split-APK native library support, and
// APK-fingerprinted caching (bypassable via Options.ForceRefresh).
func TraceContext(ctx context.Context, flow *types.Flow, opts Options, onProgress ProgressCallback) (*TraceResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if flow == nil {
		flow = &types.Flow{}
	}
	if opts.OutputDir == "" {
		opts.OutputDir = defaultOutputDir()
	}

	result := &TraceResult{
		FlowID:  flow.ID,
		URL:     flow.URL,
		Method:  flow.Method,
		Package: opts.Package,
	}

	tracker := newProgressTracker(onProgress)

	syncCounts := func() {
		tracker.setCounts(len(result.DexStrings), len(result.JavaTrace), len(result.NativeTrace), len(result.CallGraph))
	}

	// recordStep appends to result.Steps AND emits a ProgressEvent carrying Step.
	recordStep := func(stage string, stageIdx, pct int, stepName, status, detail string, dur time.Duration) {
		syncCounts()
		sr := StepResult{
			Name:     stepName,
			Status:   status,
			Detail:   detail,
			Duration: dur.Milliseconds(),
		}
		result.Steps = append(result.Steps, sr)
		stepCopy := sr
		tracker.emit(stage, stageIdx, pct, status, detail, sr.Duration, &stepCopy)
	}

	// emitLive sends an intermediate running progress update without adding a duplicate StepResult.
	emitLive := func(stage string, stageIdx, pct int, detail string) {
		syncCounts()
		tracker.emit(stage, stageIdx, pct, "running", detail, 0, nil)
	}

	cancelFinish := func(stage string, stageIdx int) (*TraceResult, error) {
		result.CallGraph = buildCallGraph(flow, result.JavaTrace, result.NativeTrace)
		result.Mermaid = generateMermaid(result.CallGraph)
		result.Summary = generateSummary(result)
		recordStep(StageDone, stageIdx, tracker.lastPct, "done", "cancelled", "trace cancelled", 0)
		return result, ctx.Err()
	}

	// Stage 1: Preflight (0% -> 5%)
	tStart := time.Now()
	recordStep(StagePreflight, 1, 2, "start", "ok", fmt.Sprintf("tracing %s %s", flow.Method, flow.URL), 0)

	if err := ctx.Err(); err != nil {
		return cancelFinish(StagePreflight, 1)
	}
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		recordStep(StageDone, 1, 5, "done", "error", err.Error(), time.Since(tStart))
		result.Summary = generateSummary(result)
		return result, fmt.Errorf("create output dir %s: %w", opts.OutputDir, err)
	}

	// Stage 2: APK Pull / Resolve (5% -> 15%)
	emitLive(StageAPKPull, 2, 6, "resolving APK source...")
	t0 := time.Now()
	apkPath, splitPaths, apkCached, apkErr := resolveAPKPathsContext(ctx, opts, func(msg string) {
		emitLive(StageAPKPull, 2, 10, msg)
	})
	if ctx.Err() != nil {
		return cancelFinish(StageAPKPull, 2)
	}
	switch {
	case apkPath != "":
		detail := apkPath
		if apkCached {
			detail += " (cached)"
		}
		if len(splitPaths) > 0 {
			detail += fmt.Sprintf(" +%d ABI split(s)", len(splitPaths))
		}
		recordStep(StageAPKPull, 2, 15, "resolve_apk", "ok", detail, time.Since(t0))
	case apkErr != nil:
		recordStep(StageAPKPull, 2, 15, "resolve_apk", "error", apkErr.Error(), time.Since(t0))
	default:
		recordStep(StageAPKPull, 2, 15, "resolve_apk", "skip", "no APK path or package provided", time.Since(t0))
	}
	result.APKPath = apkPath

	if apkPath == "" {
		err := apkErr
		if err == nil {
			err = fmt.Errorf("no APK available: set Options.APKPath or Options.Package")
		}
		result.CallGraph = buildCallGraph(flow, nil, nil)
		result.Mermaid = generateMermaid(result.CallGraph)
		recordStep(StageDone, 2, 100, "done", "error", err.Error(), 0)
		result.Summary = generateSummary(result)
		return result, err
	}

	// Optional unpack hook (cancellable).
	if opts.UnpackPath != "" {
		emitLive(StageAPKPull, 2, 15, "running unpack tool...")
		if unpacked, err := runUnpackContext(ctx, opts.UnpackPath, apkPath, opts.OutputDir); err == nil && unpacked != "" {
			apkPath = unpacked
			result.APKPath = apkPath
		}
		if ctx.Err() != nil {
			return cancelFinish(StageAPKPull, 2)
		}
	}

	searchTerms := collectSearchTerms(flow, opts.SearchTerms)

	// Stage 3: APK / Manifest Inspection (15% -> 22%)
	emitLive(StageAPKInspect, 3, 17, "inspecting APK manifest, DEX, and native libraries...")
	t0 = time.Now()
	if info, err := extractAPKInfoWithSplits(apkPath, splitPaths); err != nil {
		recordStep(StageAPKInspect, 3, 22, "apk_info", "error", err.Error(), time.Since(t0))
	} else {
		result.APKInfo = info
		if result.Package == "" && info.Package != "" {
			result.Package = info.Package
		}
		result.ToolsUsed = append(result.ToolsUsed, "apk_info")
		recordStep(StageAPKInspect, 3, 22, "apk_info", "ok", summarizeAPKInfo(info), time.Since(t0))
	}

	if ctx.Err() != nil {
		return cancelFinish(StageAPKInspect, 3)
	}

	// Stage 4: DEX String Search (22% -> 38%)
	emitLive(StageDEXSearch, 4, 23, "scanning DEX files for flow signatures...")
	t0 = time.Now()
	matches, dexErr := searchDexStringsContext(ctx, apkPath, searchTerms, opts.MaxDexMatches, func(dexName string, idx, total, hitCount int) {
		pct := 23
		if total > 0 {
			pct = 23 + (idx*14)/total
		}
		tracker.setCounts(hitCount, 0, 0, 0)
		tracker.emit(StageDEXSearch, 4, pct, "running", fmt.Sprintf("Scanning %s (%d/%d) — %d hit(s)", dexName, idx, total, hitCount), 0, nil)
	})
	if ctx.Err() != nil {
		result.DexStrings = matches
		return cancelFinish(StageDEXSearch, 4)
	}
	if dexErr != nil {
		recordStep(StageDEXSearch, 4, 38, "dex_search", "error", dexErr.Error(), time.Since(t0))
	} else {
		result.DexStrings = matches
		if len(matches) > 0 {
			result.ToolsUsed = append(result.ToolsUsed, "dex_search")
		}
		recordStep(StageDEXSearch, 4, 38, "dex_search", "ok", fmt.Sprintf("%d match(es)", len(matches)), time.Since(t0))
	}

	// Stage 5 & 6: jadx Decompile (38% -> 78%) & Java Search (78% -> 88%)
	jadxPath := opts.JadxPath
	if jadxPath == "" {
		jadxPath = "jadx"
	}
	emitLive(StageJadxDecompile, 5, 39, "checking jadx availability...")
	t0 = time.Now()
	if version, ok := toolVersionContext(ctx, jadxPath, defaultToolCheckTimeout, "--version"); ok {
		recordStep(StageJadxDecompile, 5, 40, "jadx_check", "ok", version, time.Since(t0))

		jadxDir := resolveJadxOutDir(opts.OutputDir, apkPath)
		emitLive(StageJadxDecompile, 5, 41, "starting jadx decompilation...")
		t0 = time.Now()
		jadxRes, jadxErr := decompileJadxContext(ctx, jadxPath, apkPath, jadxDir, opts.JadxTimeout, opts.ForceRefresh, func(jpct int, detail string) {
			pct := tracker.lastPct
			if jpct >= 0 {
				pct = 41 + (jpct*36)/100
			}
			emitLive(StageJadxDecompile, 5, pct, detail)
		})
		if ctx.Err() != nil {
			return cancelFinish(StageJadxDecompile, 5)
		}
		if jadxErr != nil {
			recordStep(StageJadxDecompile, 5, 78, "jadx_decompile", "error", jadxErr.Error(), time.Since(t0))
			emitLive(StageJavaSearch, 6, 88, "skipped java search (jadx failed)")
		} else {
			detail := jadxRes.OutDir
			switch {
			case jadxRes.Cached:
				detail = fmt.Sprintf("reused cache (%d .java files)", jadxRes.JavaFiles)
			case jadxRes.Partial:
				detail = fmt.Sprintf("decompiled with warnings (%d .java files)", jadxRes.JavaFiles)
			case jadxRes.JavaFiles > 0:
				detail = fmt.Sprintf("decompiled %d .java files", jadxRes.JavaFiles)
			}
			recordStep(StageJadxDecompile, 5, 78, "jadx_decompile", "ok", detail, time.Since(t0))

			// Stage 6: Java source search
			emitLive(StageJavaSearch, 6, 79, "searching decompiled Java source...")
			t0 = time.Now()
			refs, javaErr := searchJavaSourceContext(ctx, jadxDir, searchTerms, func(scanned, hits int) {
				tracker.setCounts(len(result.DexStrings), hits, 0, 0)
				pct := 79 + min(8, scanned/150)
				tracker.emit(StageJavaSearch, 6, pct, "running", fmt.Sprintf("Scanned %d Java files (%d hit(s))", scanned, hits), 0, nil)
			})
			if ctx.Err() != nil {
				result.JavaTrace = refs
				return cancelFinish(StageJavaSearch, 6)
			}
			if javaErr != nil {
				recordStep(StageJavaSearch, 6, 88, "java_search", "error", javaErr.Error(), time.Since(t0))
			} else {
				result.JavaTrace = refs
				if len(refs) > 0 {
					result.ToolsUsed = append(result.ToolsUsed, "jadx")
				}
				recordStep(StageJavaSearch, 6, 88, "java_search", "ok", fmt.Sprintf("%d source location(s)", len(refs)), time.Since(t0))
			}
		}
	} else {
		if ctx.Err() != nil {
			return cancelFinish(StageJadxDecompile, 5)
		}
		recordStep(StageJadxDecompile, 5, 78, "jadx_check", "skip", "jadx not found (set Options.JadxPath, or install it on PATH)", time.Since(t0))
		tracker.emit(StageJavaSearch, 6, 88, "skip", "skipped (jadx unavailable)", 0, nil)
	}

	// Stage 7: Native .so Analysis via radare2 (88% -> 96%)
	r2Path := opts.R2Path
	if r2Path == "" {
		r2Path = "r2"
	}
	emitLive(StageNative, 7, 89, "checking radare2 availability...")
	t0 = time.Now()
	if version, ok := toolVersionContext(ctx, r2Path, defaultToolCheckTimeout, "-v"); ok {
		recordStep(StageNative, 7, 90, "r2_check", "ok", version, time.Since(t0))

		t0 = time.Now()
		libDir := filepath.Join(opts.OutputDir, "lib")
		soFiles, err := extractSOFilesWithSplits(apkPath, splitPaths, libDir)
		switch {
		case err != nil:
			recordStep(StageNative, 7, 96, "native_analysis", "error", err.Error(), time.Since(t0))
		case len(soFiles) == 0:
			recordStep(StageNative, 7, 96, "native_analysis", "skip", "no .so files found in APK", time.Since(t0))
		default:
			knownMethods := collectNativeMethodNames(result.JavaTrace)
			for i, so := range soFiles {
				if ctx.Err() != nil {
					return cancelFinish(StageNative, 7)
				}
				base := filepath.Base(so)
				pct := 90 + ((i + 1) * 5 / max(1, len(soFiles)))
				emitLive(StageNative, 7, pct, fmt.Sprintf("Analyzing %s (%d/%d)...", base, i+1, len(soFiles)))

				t1 := time.Now()
				refs, err := analyzeNativeContext(ctx, r2Path, so, knownMethods, searchTerms, opts.R2Timeout)
				if ctx.Err() != nil {
					return cancelFinish(StageNative, 7)
				}
				if err != nil {
					recordStep(StageNative, 7, pct, "native_analysis", "error", base+": "+err.Error(), time.Since(t1))
					continue
				}
				result.NativeTrace = append(result.NativeTrace, refs...)
				recordStep(StageNative, 7, pct, "native_analysis", "ok", fmt.Sprintf("%s: %d finding(s)", base, len(refs)), time.Since(t1))
			}
			if len(result.NativeTrace) > 0 {
				result.ToolsUsed = append(result.ToolsUsed, "radare2")
			}
		}
	} else {
		if ctx.Err() != nil {
			return cancelFinish(StageNative, 7)
		}
		recordStep(StageNative, 7, 96, "r2_check", "skip", "r2 not found (set Options.R2Path, or install it on PATH)", time.Since(t0))
	}

	// Stage 8: Call Graph & Mermaid Synthesis (96% -> 100%)
	emitLive(StageGraphBuild, 8, 97, "building call graph and Mermaid diagram...")
	result.CallGraph = buildCallGraph(flow, result.JavaTrace, result.NativeTrace)
	result.Mermaid = generateMermaid(result.CallGraph)
	result.Summary = generateSummary(result)
	syncCounts()
	tracker.emit(StageGraphBuild, 8, 99, "ok", fmt.Sprintf("%d edge(s)", len(result.CallGraph)), 0, nil)
	recordStep(StageDone, 8, 100, "done", "ok", "trace complete", 0)

	return result, nil
}

// resolveJadxOutDir returns an APK-fingerprinted decompilation cache directory
// under outputDir so tracing different apps never silently reuses another app's
// stale jadx output.
func resolveJadxOutDir(outputDir, apkPath string) string {
	fp, err := computeAPKFingerprint(apkPath)
	if err != nil || fp.Key == "" {
		return filepath.Join(outputDir, "jadx-output")
	}
	return filepath.Join(outputDir, "jadx-"+fp.Key)
}

// resolveAPKPathsContext resolves the local base APK (plus optional ABI split
// APKs when pulling from an Android App Bundle device installation).
func resolveAPKPathsContext(ctx context.Context, opts Options, onStatus func(string)) (basePath string, splitPaths []string, cached bool, err error) {
	if opts.APKPath != "" {
		if _, statErr := os.Stat(opts.APKPath); statErr != nil {
			return "", nil, false, fmt.Errorf("local APK %s: %w", opts.APKPath, statErr)
		}
		return opts.APKPath, nil, false, nil
	}
	if opts.Package == "" {
		return "", nil, false, nil
	}
	adbBin := opts.ADBPath
	if adbBin == "" {
		adbBin = "adb"
	}
	return pullAPKContext(ctx, adbBin, opts.Serial, opts.Package, opts.OutputDir, opts.ForceRefresh, onStatus)
}

func pullAPKContext(ctx context.Context, adbBin, serial, pkg, outDir string, forceRefresh bool, onStatus func(string)) (basePath string, splitPaths []string, cached bool, err error) {
	if onStatus != nil {
		onStatus(fmt.Sprintf("querying APK paths for %s...", pkg))
	}
	pmCmd := exec.CommandContext(ctx, adbBin, adbArgs(serial, "shell", "pm", "path", pkg)...)
	configureCancellableCmd(pmCmd)
	out, err := pmCmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", nil, false, ctx.Err()
		}
		return "", nil, false, fmt.Errorf("adb shell pm path %s: %w", pkg, err)
	}

	remoteBase, remoteSplits := parsePMPathOutput(string(out))
	if remoteBase == "" {
		return "", nil, false, fmt.Errorf("package %s not found on device", pkg)
	}

	pkgDir := filepath.Join(outDir, "apks", sanitizeCacheSegment(pkg))
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return "", nil, false, fmt.Errorf("mkdir %s: %w", pkgDir, err)
	}

	// Probe remote base APK stamp (size + mtime) for cache validation.
	remoteStamp := queryRemoteAPKStamp(ctx, adbBin, serial, remoteBase)
	localBase := filepath.Join(pkgDir, filepath.Base(remoteBase))

	if !forceRefresh && remoteStamp != "" {
		if meta, ok := readAPKPullCache(pkgDir); ok &&
			meta.RemoteBasePath == remoteBase &&
			meta.RemoteStamp == remoteStamp &&
			fileExistsNonEmpty(meta.LocalBasePath) {
			allSplitsPresent := true
			for _, sp := range meta.SplitPaths {
				if !fileExistsNonEmpty(sp) {
					allSplitsPresent = false
					break
				}
			}
			if allSplitsPresent {
				return meta.LocalBasePath, meta.SplitPaths, true, nil
			}
		}
	}

	if onStatus != nil {
		onStatus(fmt.Sprintf("pulling %s from device...", filepath.Base(remoteBase)))
	}
	pullCmd := exec.CommandContext(ctx, adbBin, adbArgs(serial, "pull", remoteBase, localBase)...)
	configureCancellableCmd(pullCmd)
	pullOut, err := pullCmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return "", nil, false, ctx.Err()
		}
		return "", nil, false, fmt.Errorf("adb pull %s: %w: %s", remoteBase, err, lastLines(string(pullOut), 10))
	}

	// Pull the primary ABI split APK (e.g. split_config.arm64_v8a.apk) when present
	// so native .so inspection works on modern Android App Bundle installs.
	var localSplits []string
	if len(remoteSplits) > 0 {
		abiRemote := remoteSplits[0]
		abiLocal := filepath.Join(pkgDir, filepath.Base(abiRemote))
		if onStatus != nil {
			onStatus(fmt.Sprintf("pulling native split %s...", filepath.Base(abiRemote)))
		}
		spCmd := exec.CommandContext(ctx, adbBin, adbArgs(serial, "pull", abiRemote, abiLocal)...)
		boundCommandWait(spCmd, 2*time.Minute)
		if _, spErr := spCmd.CombinedOutput(); spErr == nil && fileExistsNonEmpty(abiLocal) {
			localSplits = append(localSplits, abiLocal)
		}
	}

	if remoteStamp != "" {
		writeAPKPullCache(pkgDir, apkPullCacheMeta{
			Package:        pkg,
			RemoteBasePath: remoteBase,
			RemoteStamp:    remoteStamp,
			LocalBasePath:  localBase,
			SplitPaths:     localSplits,
		})
	}

	return localBase, localSplits, false, nil
}

func queryRemoteAPKStamp(ctx context.Context, adbBin, serial, remotePath string) string {
	cmd := exec.CommandContext(ctx, adbBin, adbArgs(serial, "shell", fmt.Sprintf("stat -c '%%s:%%Y' '%s' 2>/dev/null || ls -l '%s' 2>/dev/null", remotePath, remotePath))...)
	boundCommandWait(cmd, 8*time.Second)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func fileExistsNonEmpty(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

func runUnpackContext(ctx context.Context, unpackPath, apkPath, outDir string) (string, error) {
	unpackOut := filepath.Join(outDir, "unpacked.apk")
	cmd := exec.CommandContext(ctx, unpackPath, apkPath, unpackOut)
	boundCommandWait(cmd, 2*time.Minute)
	if err := cmd.Run(); err != nil {
		return "", err
	}
	if fileExistsNonEmpty(unpackOut) {
		return unpackOut, nil
	}
	return "", nil
}

// extractAPKInfoWithSplits merges .so entries from any pulled ABI split APKs
// into the base APK's APKInfo so App Bundle native libraries are surfaced.
func extractAPKInfoWithSplits(baseAPK string, splitAPKs []string) (*APKInfo, error) {
	info, err := extractAPKInfo(baseAPK)
	if err != nil {
		return nil, err
	}
	if len(splitAPKs) == 0 {
		return info, nil
	}
	seenSO := make(map[string]bool, len(info.SOFiles))
	for _, s := range info.SOFiles {
		seenSO[s] = true
	}
	for _, sp := range splitAPKs {
		spInfo, spErr := extractAPKInfo(sp)
		if spErr != nil {
			continue
		}
		for _, so := range spInfo.SOFiles {
			if !seenSO[so] {
				seenSO[so] = true
				info.SOFiles = append(info.SOFiles, so)
			}
		}
	}
	sort.Strings(info.SOFiles)
	return info, nil
}

func extractSOFilesWithSplits(baseAPK string, splitAPKs []string, destDir string) ([]string, error) {
	paths, err := extractSOFilesTo(baseAPK, destDir)
	if err != nil {
		return nil, err
	}
	if len(splitAPKs) == 0 {
		return paths, nil
	}
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		seen[p] = true
	}
	for _, sp := range splitAPKs {
		more, spErr := extractSOFilesTo(sp, destDir)
		if spErr != nil {
			continue
		}
		for _, p := range more {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// defaultOutputDir is Options.OutputDir's default: ~/.cap/trace.
func defaultOutputDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cap", "trace")
}

// adbArgs prepends "-s serial" to rest if serial is set.
func adbArgs(serial string, rest ...string) []string {
	if serial == "" {
		return rest
	}
	return append([]string{"-s", serial}, rest...)
}

var interestingSignParamRe = regexp.MustCompile(`(?i)(sign|sig|token|nonce|digest|hmac|secret|app[_-]?key|auth|checksum|salt)`)

// collectSearchTerms combines buildSearchTerms(flow) with flow sign params,
// interesting query/header parameter names, multi-segment path suffixes, and
// caller-supplied extra terms (Options.SearchTerms), preserving most-to-least
// specific ordering.
func collectSearchTerms(flow *types.Flow, extra []string) []string {
	terms := buildSearchTerms(flow)
	seen := make(map[string]bool, len(terms)+len(extra)+8)
	for _, t := range terms {
		seen[t] = true
	}
	add := func(t string) {
		t = strings.TrimSpace(t)
		if len(t) >= minSearchTermLen && !seen[t] {
			seen[t] = true
			terms = append(terms, t)
		}
	}

	if flow != nil {
		// Last 2 path segments help match split baseURL + endpoint constants (e.g. "order/create").
		path := cleanPath(flow.Path)
		if path == "" {
			path = cleanPath(pathFromURL(flow.URL))
		}
		segs := strings.Split(strings.Trim(path, "/"), "/")
		if len(segs) >= 3 {
			add(strings.Join(segs[len(segs)-2:], "/"))
		}

		// Flow's detected signature parameters.
		for _, sp := range flow.SignParams {
			add(sp)
		}

		// Interesting query parameter keys.
		if u, err := url.Parse(flow.URL); err == nil {
			qKeys := make([]string, 0, len(u.Query()))
			for k := range u.Query() {
				if interestingSignParamRe.MatchString(k) {
					qKeys = append(qKeys, k)
				}
			}
			sort.Strings(qKeys)
			for _, k := range qKeys {
				add(k)
			}
		}

		// Interesting custom request header names (e.g. X-Sign, X-Nonce).
		if len(flow.ReqHeaders) > 0 {
			hKeys := make([]string, 0, 4)
			for k := range flow.ReqHeaders {
				if strings.HasPrefix(strings.ToLower(k), "x-") && interestingSignParamRe.MatchString(k) {
					hKeys = append(hKeys, k)
				}
			}
			sort.Strings(hKeys)
			for _, k := range hKeys {
				add(k)
			}
		}
	}

	for _, t := range extra {
		add(t)
	}
	return terms
}

// collectNativeMethodNames returns the deduplicated plain native method
// names (excluding "*.so" loadLibrary entries) declared across refs, for
// Strategy 4 to try to match against radare2's function list.
func collectNativeMethodNames(refs []JavaRef) []string {
	seen := make(map[string]bool)
	var names []string
	for _, r := range refs {
		for _, nm := range r.NativeMethods {
			if strings.HasSuffix(nm, ".so") || seen[nm] {
				continue
			}
			seen[nm] = true
			names = append(names, nm)
		}
	}
	return names
}

// summarizeAPKInfo renders a one-line summary of info, for the apk_info
// step's detail text.
func summarizeAPKInfo(info *APKInfo) string {
	if info == nil {
		return "no manifest data"
	}
	return fmt.Sprintf("package=%s dex=%d so=%d permissions=%d activities=%d ns_config=%v",
		info.Package, info.DexCount, len(info.SOFiles), len(info.Permissions), len(info.Activities), info.HasNSConfig)
}

// generateSummary renders result as a short human-readable report: the
// flow traced, the package (if known), and how many findings each
// strategy produced, with every Java source location listed.
func generateSummary(result *TraceResult) string {
	if result == nil {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Flow: %s %s\n", result.Method, result.URL)
	if result.APKInfo != nil && result.APKInfo.Package != "" {
		fmt.Fprintf(&b, "Package: %s\n", result.APKInfo.Package)
	}
	if n := len(result.DexStrings); n > 0 {
		fmt.Fprintf(&b, "DEX strings: %d match(es)\n", n)
	}
	if n := len(result.JavaTrace); n > 0 {
		fmt.Fprintf(&b, "Java: %d source location(s)\n", n)
		for _, jr := range result.JavaTrace {
			fmt.Fprintf(&b, "  -> %s:%d\n", jr.File, jr.Line)
		}
	}
	if n := len(result.NativeTrace); n > 0 {
		fmt.Fprintf(&b, "Native: %d finding(s) across .so files\n", n)
	}
	if len(result.ToolsUsed) > 0 {
		fmt.Fprintf(&b, "Strategies used: %s\n", strings.Join(result.ToolsUsed, ", "))
	}

	return strings.TrimRight(b.String(), "\n")
}

// ToJSON renders result as indented JSON, or "" if that somehow fails.
func ToJSON(result *TraceResult) string {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}
