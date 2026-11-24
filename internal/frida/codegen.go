package frida

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	captrace "github.com/overkazaf/cap/internal/trace"
	"github.com/overkazaf/cap/internal/unpin"
)

const defaultMaxGeneratedHooks = 18

// DefaultHookGenOptions returns balanced defaults for DeepTrace -> Frida hook generation.
func DefaultHookGenOptions() HookGenOptions {
	return HookGenOptions{
		IncludeJava:      true,
		IncludeDexXRefs:  true,
		IncludeNative:    true,
		IncludeCrypto:    true,
		IncludeSSLUnpin:  false,
		IncludeBacktrace: true,
		MaxHooks:         defaultMaxGeneratedHooks,
	}
}

// GenerateHookFromTrace synthesizes an immediately runnable Frida JavaScript
// instrumentation script from a DeepTrace TraceResult (Java refs, DEX bytecode
// xrefs, Origin Chain hops, Native .so exports, and sign/auth parameter hints).
func GenerateHookFromTrace(res *captrace.TraceResult, opts HookGenOptions) *GeneratedHook {
	if opts.MaxHooks <= 0 {
		opts.MaxHooks = defaultMaxGeneratedHooks
	}
	if !opts.IncludeJava && !opts.IncludeDexXRefs && !opts.IncludeNative && !opts.IncludeCrypto && !opts.IncludeSSLUnpin {
		opts = DefaultHookGenOptions()
	}

	pkg := strings.TrimSpace(opts.TargetPackage)
	flowID := ""
	flowSummary := ""
	var signParams []string

	if res != nil {
		if pkg == "" {
			pkg = res.Package
		}
		flowID = res.FlowID
		if res.Method != "" || res.URL != "" {
			flowSummary = strings.TrimSpace(res.Method + " " + res.URL)
		}
		if res.Report != nil {
			for _, pp := range res.Report.ParamProvenance {
				if pp.Role == "sign" || pp.Role == "auth" {
					signParams = append(signParams, pp.Name)
				}
			}
		}
	}

	classFilter := toLowerSet(opts.SelectedClasses)
	soFilter := toLowerSet(opts.SelectedNativeSOs)

	javaTargets := collectJavaHookTargets(res, opts, classFilter)
	nativeTargets := collectNativeHookTargets(res, opts, soFilter)

	code := renderGeneratedHookJS(pkg, flowID, flowSummary, signParams, javaTargets, nativeTargets, opts)

	name := "DeepTrace Hook"
	if flowID != "" {
		name = fmt.Sprintf("DeepTrace Hook · %s", flowID)
	} else if pkg != "" {
		name = fmt.Sprintf("Hook · %s", pkg)
	}

	summary := fmt.Sprintf("Generated %d Java hook(s) and %d native hook(s)", len(javaTargets), len(nativeTargets))
	if len(signParams) > 0 {
		summary += fmt.Sprintf(" tracking params [%s]", strings.Join(signParams, ", "))
	}

	return &GeneratedHook{
		ScriptName:    name,
		TargetPackage: pkg,
		FlowID:        flowID,
		FlowSummary:   flowSummary,
		Code:          code,
		Summary:       summary,
		JavaTargets:   javaTargets,
		NativeTargets: nativeTargets,
		SignParams:    signParams,
		GeneratedAt:   nowRFC3339(),
	}
}

// GenerateHookForTargets builds a focused Frida script for an explicit list of
// Java and/or Native hook targets (e.g., clicking "Hook" on one module or .so function).
func GenerateHookForTargets(pkg, title string, targets []HookTarget, includeBacktrace bool) *GeneratedHook {
	var javaTargets, nativeTargets []HookTarget
	for _, t := range targets {
		if t.Kind == "native" {
			nativeTargets = append(nativeTargets, t)
		} else {
			javaTargets = append(javaTargets, t)
		}
	}
	opts := HookGenOptions{
		TargetPackage:    pkg,
		IncludeJava:      len(javaTargets) > 0,
		IncludeNative:    len(nativeTargets) > 0,
		IncludeBacktrace: includeBacktrace,
		MaxHooks:         len(targets),
	}
	code := renderGeneratedHookJS(pkg, "", title, nil, javaTargets, nativeTargets, opts)
	name := strings.TrimSpace(title)
	if name == "" {
		name = "Focused Hook"
	}
	return &GeneratedHook{
		ScriptName:    name,
		TargetPackage: pkg,
		Code:          code,
		Summary:       fmt.Sprintf("Focused script: %d Java + %d native target(s)", len(javaTargets), len(nativeTargets)),
		JavaTargets:   javaTargets,
		NativeTargets: nativeTargets,
		GeneratedAt:   nowRFC3339(),
	}
}

func collectJavaHookTargets(res *captrace.TraceResult, opts HookGenOptions, classFilter map[string]bool) []HookTarget {
	if res == nil || (!opts.IncludeJava && !opts.IncludeDexXRefs) {
		return []HookTarget{}
	}

	type candidate struct {
		target HookTarget
		score  int
	}
	seen := make(map[string]bool)
	var cands []candidate

	add := func(cls, method, source, reason string, score int) {
		cls = cleanJavaClassName(cls)
		method = cleanJavaMethodName(method)
		if cls == "" || isSkippableJavaClass(cls) {
			return
		}
		if len(classFilter) > 0 && !matchesClassFilter(cls, classFilter) {
			return
		}
		key := cls + "#" + method
		if seen[key] {
			return
		}
		seen[key] = true
		cands = append(cands, candidate{
			target: HookTarget{
				Kind:       "java",
				ClassName:  cls,
				MethodName: method,
				Source:     source,
				Reason:     reason,
			},
			score: score,
		})
	}

	// 1. Java source findings (highest precision when jadx ran)
	if opts.IncludeJava {
		for _, jr := range res.JavaTrace {
			score := 90
			if jr.CallsNative {
				score += 20
			}
			if jr.Annotation != "" {
				score += 10
			}
			reason := jr.MatchedTerm
			if reason == "" {
				reason = jr.Annotation
			}
			add(jr.Class, jr.Method, "java_trace", reason, score)
			for _, nm := range jr.NativeMethods {
				add(jr.Class, nm, "java_trace", "declared native method", 115)
			}
		}
	}

	// 2. Pure-Go DEX bytecode XRefs (works even without jadx!)
	if opts.IncludeDexXRefs {
		for _, dx := range res.DexXRefs {
			score := 70
			switch dx.Category {
			case "crypto":
				score = 110
			case "native":
				score = 105
			case "network":
				score = 95
			case "business":
				score = 80
			case "sdk":
				score = 55
			}
			if dx.IsNative {
				score += 15
			}
			reason := strings.Join(dx.MatchedTerms, ", ")
			if reason == "" {
				reason = dx.Category
			}
			add(dx.ClassName, dx.MethodName, "dex_xref", reason, score)
		}
	}

	// 3. Report OriginChain hops as supplemental high-value targets
	if res.Report != nil {
		for _, hop := range res.Report.OriginChain {
			if hop.Layer == "native" || hop.Layer == "http" || hop.Symbol == "" {
				continue
			}
			cls, method := splitSymbol(hop.Symbol)
			if cls != "" {
				add(cls, method, "origin_chain", hop.Title, 85)
			}
		}
	}

	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].score > cands[j].score
	})

	limit := opts.MaxHooks
	if limit > len(cands) {
		limit = len(cands)
	}
	out := make([]HookTarget, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, cands[i].target)
	}
	return out
}

func collectNativeHookTargets(res *captrace.TraceResult, opts HookGenOptions, soFilter map[string]bool) []HookTarget {
	if res == nil || !opts.IncludeNative {
		return []HookTarget{}
	}
	seen := make(map[string]bool)
	var out []HookTarget

	for _, nr := range res.NativeTrace {
		soBase := filepath.Base(nr.SOFile)
		if soBase == "" || soBase == "." {
			continue
		}
		if len(soFilter) > 0 && !soFilter[strings.ToLower(soBase)] && !soFilter[strings.ToLower(nr.SOFile)] {
			continue
		}
		fn := strings.TrimSpace(nr.Function)
		if fn == "" {
			continue
		}
		key := soBase + "!" + fn
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, HookTarget{
			Kind:   "native",
			SOFile: soBase,
			Symbol: fn,
			Source: "native_trace",
			Reason: nr.Address,
		})
		if len(out) >= opts.MaxHooks {
			break
		}
	}
	return out
}

func renderGeneratedHookJS(
	pkg, flowID, flowSummary string,
	signParams []string,
	javaTargets, nativeTargets []HookTarget,
	opts HookGenOptions,
) string {
	var b strings.Builder

	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap Auto-Generated DeepTrace Frida Hook ─────────────────────────\n")
	if pkg != "" {
		fmt.Fprintf(&b, "// Target Package: %s\n", pkg)
	}
	if flowID != "" || flowSummary != "" {
		fmt.Fprintf(&b, "// Traced Flow:    %s %s\n", flowID, flowSummary)
	}
	if len(signParams) > 0 {
		fmt.Fprintf(&b, "// Sign / Auth:    %s\n", strings.Join(signParams, ", "))
	}
	fmt.Fprintf(&b, "// Targets:        %d Java, %d Native\n\n", len(javaTargets), len(nativeTargets))

	// Helper utilities
	b.WriteString(`const CAPTURE_STACK = ` + boolJS(opts.IncludeBacktrace) + `;

function formatVal(v) {
    if (v === null || v === undefined) return String(v);
    try {
        if (typeof v === 'object' && v.$className === '[B') {
            const arr = Java.array('byte', v);
            let hex = '';
            for (let i = 0; i < Math.min(arr.length, 64); i++) {
                hex += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
            }
            return 'byte[' + arr.length + '](' + hex + (arr.length > 64 ? '...' : '') + ')';
        }
        const s = String(v);
        return s.length > 260 ? s.slice(0, 260) + '…' : s;
    } catch (_) {
        return '<unprintable>';
    }
}

function getStack() {
    if (!CAPTURE_STACK) return '';
    try {
        const Log = Java.use('android.util.Log');
        const Ex = Java.use('java.lang.Exception');
        return Log.getStackTraceString(Ex.$new()).split('\n').slice(1, 7).map(l => l.trim()).join('\n');
    } catch (_) {
        return '';
    }
}

function hookJavaMethod(className, methodName, reason) {
    try {
        const cls = Java.use(className);
        if (!methodName || methodName === '*') {
            const declared = cls.class.getDeclaredMethods();
            const seen = {};
            for (let i = 0; i < declared.length; i++) {
                const name = declared[i].getName();
                if (!seen[name] && !name.startsWith('$') && name !== 'toString' && name !== 'hashCode') {
                    seen[name] = true;
                    hookJavaMethod(className, name, reason);
                }
            }
            return;
        }
        const target = cls[methodName];
        if (!target || !target.overloads) return;
        target.overloads.forEach(function (ov) {
            ov.implementation = function () {
                const argList = [];
                for (let i = 0; i < arguments.length; i++) {
                    argList.push(formatVal(arguments[i]));
                }
                const ret = ov.apply(this, arguments);
                send({
                    cap_cat: 'trace',
                    hook: className + '.' + methodName,
                    class_name: className,
                    method: methodName,
                    reason: reason || '',
                    args: argList,
                    retval: formatVal(ret),
                    stack: getStack(),
                });
                return ret;
            };
        });
        console.log('[cap trace] ✓ Java ' + className + '.' + methodName);
    } catch (e) {
        console.log('[cap trace] ✗ Java ' + className + '.' + methodName + ': ' + e.message);
    }
}

function hookNativeExport(soName, symbolName) {
    const attachNow = function () {
        const addr = Module.findExportByName(soName, symbolName);
        if (!addr) return false;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.preview = [];
                for (let i = 0; i < 4; i++) {
                    let s = args[i].toString();
                    try {
                        const maybeStr = args[i].readUtf8String(96);
                        if (maybeStr && /^[\x20-\x7e]{3,}$/.test(maybeStr)) {
                            s += ' ("' + maybeStr + '")';
                        }
                    } catch (_) {}
                    this.preview.push(s);
                }
            },
            onLeave(retval) {
                let retStr = retval.toString();
                try {
                    const maybeStr = retval.readUtf8String(96);
                    if (maybeStr && /^[\x20-\x7e]{3,}$/.test(maybeStr)) {
                        retStr += ' ("' + maybeStr + '")';
                    }
                } catch (_) {}
                send({
                    cap_cat: 'native',
                    hook: soName + '!' + symbolName,
                    module: soName,
                    symbol: symbolName,
                    args: this.preview,
                    retval: retStr,
                });
            }
        });
        console.log('[cap trace] ✓ Native ' + soName + '!' + symbolName + ' @ ' + addr);
        return true;
    };

    if (attachNow()) return;

    // Delayed attach if library is loaded dynamically via dlopen
    ['dlopen', 'android_dlopen_ext'].forEach(function (loader) {
        const loaderAddr = Module.findExportByName(null, loader);
        if (!loaderAddr) return;
        Interceptor.attach(loaderAddr, {
            onEnter(args) {
                this.hit = !args[0].isNull() && String(args[0].readCString()).indexOf(soName) !== -1;
            },
            onLeave() {
                if (this.hit) attachNow();
            }
        });
    });
    console.log('[cap trace] ⏳ Waiting for ' + soName + ' to load for ' + symbolName);
}
`)

	if len(javaTargets) > 0 {
		b.WriteString("\nJava.perform(function () {\n")
		for _, jt := range javaTargets {
			fmt.Fprintf(&b, "    hookJavaMethod(%s, %s, %s);\n",
				jsQuote(jt.ClassName), jsQuote(jt.MethodName), jsQuote(jt.Reason))
		}
		b.WriteString("    send({ cap_cat: 'lifecycle', hook: 'deeptrace', detail: 'Installed " + fmt.Sprintf("%d", len(javaTargets)) + " Java hook(s)' });\n")
		b.WriteString("});\n")
	}

	if len(nativeTargets) > 0 {
		b.WriteString("\n// ── Native SO Export Hooks ──────────────────────────────────────────\n")
		for _, nt := range nativeTargets {
			fmt.Fprintf(&b, "hookNativeExport(%s, %s);\n", jsQuote(nt.SOFile), jsQuote(nt.Symbol))
		}
	}

	if opts.IncludeCrypto {
		b.WriteString("\n// ── Crypto / Signature Correlation Hooks ───────────────────────────\n")
		b.WriteString(`Java.perform(function () {
    try {
        const MD = Java.use('java.security.MessageDigest');
        MD.digest.overload('[B').implementation = function (input) {
            const out = this.digest(input);
            send({ cap_cat: 'crypto', hook: 'MessageDigest.digest', algorithm: this.getAlgorithm(), args: [formatVal(input)], retval: formatVal(out), stack: getStack() });
            return out;
        };
    } catch (_) {}
    try {
        const Mac = Java.use('javax.crypto.Mac');
        Mac.doFinal.overload('[B').implementation = function (input) {
            const out = this.doFinal(input);
            send({ cap_cat: 'crypto', hook: 'Mac.doFinal', algorithm: this.getAlgorithm(), args: [formatVal(input)], retval: formatVal(out), stack: getStack() });
            return out;
        };
    } catch (_) {}
});
`)
	}

	if opts.IncludeSSLUnpin {
		b.WriteString("\n// ── Included Universal SSL Pinning Bypass ──────────────────────────\n")
		b.WriteString(strings.TrimPrefix(unpin.GetFridaScript(), "'use strict';\n"))
	}

	return b.String()
}

func jsQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func boolJS(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func cleanJavaClassName(cls string) string {
	cls = strings.TrimSpace(cls)
	cls = strings.TrimPrefix(cls, "L")
	cls = strings.TrimSuffix(cls, ";")
	cls = strings.ReplaceAll(cls, "/", ".")
	if idx := strings.IndexByte(cls, '('); idx >= 0 {
		cls = cls[:idx]
	}
	return strings.TrimSpace(cls)
}

func cleanJavaMethodName(m string) string {
	m = strings.TrimSpace(m)
	if idx := strings.IndexByte(m, '('); idx >= 0 {
		m = m[:idx]
	}
	if m == "<init>" {
		return "$init"
	}
	if m == "<clinit>" {
		return ""
	}
	return strings.TrimSpace(m)
}

func splitSymbol(sym string) (cls, method string) {
	sym = strings.TrimSpace(sym)
	if idx := strings.IndexByte(sym, '('); idx >= 0 {
		sym = sym[:idx]
	}
	if strings.Contains(sym, "#") {
		parts := strings.SplitN(sym, "#", 2)
		return cleanJavaClassName(parts[0]), cleanJavaMethodName(parts[1])
	}
	lastDot := strings.LastIndex(sym, ".")
	if lastDot <= 0 {
		return "", ""
	}
	return cleanJavaClassName(sym[:lastDot]), cleanJavaMethodName(sym[lastDot+1:])
}

func isSkippableJavaClass(cls string) bool {
	if !strings.Contains(cls, ".") {
		return true
	}
	prefixes := []string{"java.lang.", "android.os.", "android.view.", "androidx.core."}
	for _, p := range prefixes {
		if strings.HasPrefix(cls, p) {
			return true
		}
	}
	return false
}

func toLowerSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, it := range items {
		t := strings.ToLower(strings.TrimSpace(it))
		if t != "" {
			m[t] = true
		}
	}
	return m
}

func matchesClassFilter(cls string, filter map[string]bool) bool {
	low := strings.ToLower(cls)
	if filter[low] {
		return true
	}
	for f := range filter {
		if strings.HasPrefix(low, f) || strings.Contains(low, f) {
			return true
		}
	}
	return false
}
