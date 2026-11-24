package retools

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	captrace "github.com/overkazaf/cap/internal/trace"
)

var codegenSecurityKeywords = []string{
	"sign", "crypt", "enc", "sec", "auth", "token", "guard", "shield", "key", "hmac", "aes", "md5", "sha",
}

// GenerateFromTrace extracts native libraries (.so), APKPath, native methods,
// Dalvik descriptors, JNI Java_* exports, and sign/auth parameter hints from a
// DeepTrace TraceResult and synthesizes a tailored Unidbg, Qiling, angr, or
// radare2 harness.
func GenerateFromTrace(res *captrace.TraceResult, engine string, opts GenerateOptions) (*GeneratedHarness, error) {
	eng := normalizeEngineName(engine)
	if eng == "" {
		return nil, fmt.Errorf("unsupported RE engine %q (expected unidbg, qiling, angr, or radare2)", engine)
	}

	merged := opts
	var signParams []string
	var traceNotes []string

	if res != nil {
		if merged.PackageName == "" {
			merged.PackageName = strings.TrimSpace(res.Package)
			if merged.PackageName == "" && res.APKInfo != nil {
				merged.PackageName = strings.TrimSpace(res.APKInfo.Package)
			}
		}
		if merged.APKPath == "" {
			merged.APKPath = strings.TrimSpace(res.APKPath)
		}

		// Collect sign/auth parameters & sample request args from DeepTrace report.
		var sampleArgs []string
		if res.Report != nil {
			seenParam := make(map[string]bool)
			for _, pp := range res.Report.ParamProvenance {
				if pp.Role == "sign" || pp.Role == "auth" {
					if !seenParam[pp.Name] {
						seenParam[pp.Name] = true
						signParams = append(signParams, pp.Name)
					}
				}
				if pp.SampleValue != "" && len(sampleArgs) < 4 {
					sampleArgs = append(sampleArgs, fmt.Sprintf("%s=%s", pp.Name, pp.SampleValue))
				}
			}
		}
		if len(merged.Args) == 0 && len(sampleArgs) > 0 {
			merged.Args = []string{strings.Join(sampleArgs, "&")}
		} else if len(merged.Args) == 0 && res.URL != "" {
			merged.Args = []string{res.URL}
		}

		// Resolve native library, JNI symbol, address, Java class/method, and descriptor.
		extracted := extractNativeTargetFromTrace(res, merged)
		if merged.BinaryPath == "" && merged.SOFile == "" && extracted.soPath != "" {
			merged.BinaryPath = extracted.soPath
			merged.SOFile = extracted.soPath
		}
		if merged.TargetSymbol == "" && extracted.symbol != "" {
			merged.TargetSymbol = extracted.symbol
		}
		if merged.TargetAddr == "" && extracted.addr != "" {
			merged.TargetAddr = extracted.addr
		}
		if merged.TargetClass == "" && extracted.className != "" {
			merged.TargetClass = extracted.className
		}
		if merged.TargetMethod == "" && extracted.methodName != "" {
			merged.TargetMethod = extracted.methodName
		}
		if merged.MethodSignature == "" && extracted.descriptor != "" {
			merged.MethodSignature = extracted.descriptor
		}
		if merged.Arch == "" && extracted.arch != "" {
			merged.Arch = extracted.arch
		}
		traceNotes = append(traceNotes, extracted.notes...)
	}

	// If caller supplied a Java_* TargetSymbol without TargetClass/TargetMethod, decode it.
	if merged.TargetSymbol != "" && (merged.TargetClass == "" || merged.TargetMethod == "") {
		if cls, meth, sig, ok := ParseJNISymbol(merged.TargetSymbol); ok {
			if merged.TargetClass == "" {
				merged.TargetClass = cls
			}
			if merged.TargetMethod == "" {
				merged.TargetMethod = meth
			}
			if merged.MethodSignature == "" && sig != "" {
				merged.MethodSignature = sig
			}
		}
	}

	var harness *GeneratedHarness
	switch eng {
	case EngineUnidbg:
		harness = GenerateUnidbgHarness(merged)
	case EngineQiling:
		harness = GenerateQilingHarness(merged)
	case EngineAngr:
		harness = GenerateAngrHarness(merged)
	case EngineRadare2:
		harness = GenerateR2Harness(merged)
	default:
		return nil, fmt.Errorf("unsupported RE engine %q", engine)
	}

	harness.SignParams = signParams
	if len(traceNotes) > 0 {
		harness.Notes = append(traceNotes, harness.Notes...)
	}
	if res != nil && (res.FlowID != "" || res.URL != "") {
		flowTag := strings.TrimSpace(res.FlowID)
		if flowTag != "" {
			harness.Summary = fmt.Sprintf("%s (from DeepTrace %s)", harness.Summary, flowTag)
		}
		if len(signParams) > 0 {
			harness.Notes = append(harness.Notes, fmt.Sprintf("Tracked DeepTrace sign/auth params: %s", strings.Join(signParams, ", ")))
		}
	}
	return harness, nil
}

// ParseJNISymbol decodes a standard static JNI export symbol name such as
// `Java_com_example_pkg_Signer_native_1sign__Ljava_lang_String_2J` into its
// Dalvik class path (`com/example/pkg/Signer`), Java method name
// (`native_sign`), and optional parameter signature (`(Ljava/lang/String;J)`).
func ParseJNISymbol(sym string) (className, methodName, paramSig string, ok bool) {
	s := stripR2SymPrefix(strings.TrimSpace(sym))
	if !strings.HasPrefix(s, "Java_") {
		return "", "", "", false
	}
	body := strings.TrimPrefix(s, "Java_")
	if body == "" {
		return "", "", "", false
	}

	// Split optional overloaded signature suffix (`__<mangled-params>`)
	rawOverload := ""
	if idx := strings.Index(body, "__"); idx > 0 {
		rawOverload = body[idx+2:]
		body = body[:idx]
	}

	// Tokenize on unescaped `_` (preserving `_1`, `_2`, `_3`, `_0xxxx` escapes).
	parts := splitJNITokens(body)
	if len(parts) < 2 {
		return "", "", "", false
	}
	methodName = unescapeJNIToken(parts[len(parts)-1])
	classParts := make([]string, 0, len(parts)-1)
	for _, p := range parts[:len(parts)-1] {
		classParts = append(classParts, unescapeJNIToken(p))
	}
	className = strings.Join(classParts, "/")

	if rawOverload != "" {
		decoded := decodeJNIOverloadParams(rawOverload)
		if decoded != "" {
			paramSig = "(" + decoded + ")Ljava/lang/String;"
		}
	}
	return className, methodName, paramSig, true
}

func splitJNITokens(s string) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '_' {
			// JNI escape sequence: _1, _2, _3, or _0xxxx
			if i+1 < len(s) {
				next := s[i+1]
				if next == '1' || next == '2' || next == '3' {
					cur.WriteString(s[i : i+2])
					i += 2
					continue
				}
				if next == '0' && i+6 <= len(s) && isHex4(s[i+2:i+6]) {
					cur.WriteString(s[i : i+6])
					i += 6
					continue
				}
			}
			parts = append(parts, cur.String())
			cur.Reset()
			i++
			continue
		}
		cur.WriteByte(s[i])
		i++
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}

func unescapeJNIToken(tok string) string {
	var b strings.Builder
	for i := 0; i < len(tok); {
		if tok[i] == '_' && i+1 < len(tok) {
			switch tok[i+1] {
			case '1':
				b.WriteByte('_')
				i += 2
				continue
			case '2':
				b.WriteByte(';')
				i += 2
				continue
			case '3':
				b.WriteByte('[')
				i += 2
				continue
			case '0':
				if i+6 <= len(tok) && isHex4(tok[i+2:i+6]) {
					if v, err := strconv.ParseUint(tok[i+2:i+6], 16, 16); err == nil {
						b.WriteRune(rune(v))
						i += 6
						continue
					}
				}
			}
		}
		b.WriteByte(tok[i])
		i++
	}
	return b.String()
}

func decodeJNIOverloadParams(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] == '_' && i+1 < len(raw) {
			switch raw[i+1] {
			case '1':
				b.WriteByte('_')
				i += 2
				continue
			case '2':
				b.WriteByte(';')
				i += 2
				continue
			case '3':
				b.WriteByte('[')
				i += 2
				continue
			case '0':
				if i+6 <= len(raw) && isHex4(raw[i+2:i+6]) {
					if v, err := strconv.ParseUint(raw[i+2:i+6], 16, 16); err == nil {
						b.WriteRune(rune(v))
						i += 6
						continue
					}
				}
			default:
				b.WriteByte('/')
				i++
				continue
			}
		}
		b.WriteByte(raw[i])
		i++
	}
	return b.String()
}

func isHex4(s string) bool {
	if len(s) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

type extractedTraceTarget struct {
	soPath     string
	symbol     string
	addr       string
	className  string
	methodName string
	descriptor string
	arch       string
	notes      []string
}

func extractNativeTargetFromTrace(res *captrace.TraceResult, opts GenerateOptions) extractedTraceTarget {
	var out extractedTraceTarget
	wantSO := strings.ToLower(strings.TrimSpace(firstNonEmpty(opts.SOFile, opts.BinaryPath)))
	wantSOBase := ""
	if wantSO != "" {
		wantSOBase = strings.ToLower(filepath.Base(wantSO))
	}

	// 1. Score NativeTrace candidates (prefer Java_* exports, security names, arm64-v8a).
	type nativeCand struct {
		ref   captrace.NativeRef
		score int
	}
	var ncands []nativeCand
	for _, nr := range res.NativeTrace {
		if wantSOBase != "" && strings.ToLower(filepath.Base(nr.SOFile)) != wantSOBase && strings.ToLower(nr.SOFile) != wantSO {
			continue
		}
		score := 10
		fn := stripR2SymPrefix(nr.Function)
		if strings.HasPrefix(fn, "Java_") {
			score += 60
		} else if fn == "JNI_OnLoad" {
			score += 20
		} else if fn != "" {
			score += 35
		}
		if hasSecurityKeyword(fn) || hasSecurityKeyword(nr.SOFile) {
			score += 30
		}
		if strings.Contains(strings.ToLower(nr.SOFile), "arm64") {
			score += 15
		}
		if nr.Address != "" {
			score += 5
		}
		ncands = append(ncands, nativeCand{ref: nr, score: score})
	}
	sort.SliceStable(ncands, func(i, j int) bool {
		return ncands[i].score > ncands[j].score
	})

	if len(ncands) > 0 {
		best := ncands[0].ref
		out.soPath = best.SOFile
		out.symbol = best.Function
		out.addr = best.Address
		out.arch = normalizeEmulationArch("", best.SOFile)
		if cls, meth, sig, ok := ParseJNISymbol(best.Function); ok {
			out.className = cls
			out.methodName = meth
			out.descriptor = sig
			out.notes = append(out.notes, fmt.Sprintf("Decoded JNI export %s -> %s.%s", best.Function, cls, meth))
		}
	}

	// 2. Enrich with DexXRefs (exact Dalvik class, method, and descriptor!)
	for _, dx := range res.DexXRefs {
		if !dx.IsNative && len(dx.LoadsLibrary) == 0 {
			continue
		}
		cls := normalizeJNIDalvikClass(dx.ClassName)
		if out.className == "" && cls != "" {
			out.className = cls
		}
		if out.methodName == "" && dx.IsNative && dx.MethodName != "" {
			out.methodName = dx.MethodName
		}
		if dx.Descriptor != "" && (out.descriptor == "" || (dx.MethodName == out.methodName && cls == out.className)) {
			out.descriptor = dx.Descriptor
		}
		if out.soPath == "" && len(dx.LoadsLibrary) > 0 {
			lib := dx.LoadsLibrary[0]
			if !strings.HasPrefix(lib, "lib") {
				lib = "lib" + lib
			}
			if !strings.HasSuffix(lib, ".so") {
				lib += ".so"
			}
			out.soPath = lib
		}
	}

	// 3. Enrich with JavaTrace native declarations (when jadx ran)
	for _, jr := range res.JavaTrace {
		if !jr.CallsNative && len(jr.NativeMethods) == 0 {
			continue
		}
		cls := normalizeJNIDalvikClass(jr.Class)
		if out.className == "" && cls != "" {
			out.className = cls
		}
		for _, nm := range jr.NativeMethods {
			if strings.HasSuffix(strings.ToLower(nm), ".so") {
				if out.soPath == "" {
					out.soPath = nm
				}
				continue
			}
			if out.methodName == "" && nm != "" {
				out.methodName = nm
			}
		}
	}

	// 4. Fallback .so selection from APKInfo.SOFiles if NativeTrace had no .so path
	if out.soPath == "" && res.APKInfo != nil && len(res.APKInfo.SOFiles) > 0 {
		out.soPath = pickBestSOFromAPK(res.APKInfo.SOFiles)
		out.arch = normalizeEmulationArch("", out.soPath)
	}

	// Resolve bare library name to in-APK path if APKInfo has a matching arm64/arm path
	if out.soPath != "" && !strings.Contains(out.soPath, "/") && res.APKInfo != nil {
		baseLow := strings.ToLower(filepath.Base(out.soPath))
		var matches []string
		for _, p := range res.APKInfo.SOFiles {
			if strings.ToLower(filepath.Base(p)) == baseLow {
				matches = append(matches, p)
			}
		}
		if len(matches) > 0 {
			out.soPath = pickBestSOFromAPK(matches)
			out.arch = normalizeEmulationArch("", out.soPath)
		}
	}

	return out
}

func pickBestSOFromAPK(soFiles []string) string {
	best := ""
	bestScore := -1
	for _, p := range soFiles {
		low := strings.ToLower(p)
		score := 0
		switch {
		case strings.Contains(low, "arm64-v8a"):
			score += 50
		case strings.Contains(low, "armeabi-v7a"):
			score += 40
		case strings.Contains(low, "armeabi"):
			score += 30
		case strings.Contains(low, "x86_64"):
			score += 20
		case strings.Contains(low, "/x86/"):
			score += 10
		}
		if hasSecurityKeyword(filepath.Base(p)) {
			score += 100
		}
		if score > bestScore || (score == bestScore && p < best) {
			best = p
			bestScore = score
		}
	}
	return best
}

func hasSecurityKeyword(s string) bool {
	low := strings.ToLower(s)
	for _, kw := range codegenSecurityKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func normalizeEngineName(engine string) string {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case "", EngineUnidbg:
		return EngineUnidbg
	case EngineQiling:
		return EngineQiling
	case EngineAngr:
		return EngineAngr
	case EngineRadare2, "r2":
		return EngineRadare2
	default:
		return ""
	}
}
