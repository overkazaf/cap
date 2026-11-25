package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// BuildSystemPrompt constructs a scope-specialized system prompt enforcing a
// strict JSON response matching DiagnoseResult and respecting locale.
func BuildSystemPrompt(scope, locale string) string {
	normScope := NormalizeScope(scope)
	normLocale := NormalizeLocale(locale)

	var domainGuide string
	switch normScope {
	case ScopeUnidbg:
		domainGuide = `Domain expertise: Android/iOS native .so emulation with Unidbg (Java).
- Focus on missing AbstractJni callbacks (callObjectMethodV, callStaticObjectMethodV, getObjectField, getStaticObjectField, getIntField, callIntMethodV, callBooleanMethodV, newObjectV, resolveClass), IOResolver<AndroidFileIO> virtual files, SystemPropertyHook entries, and missing dependent .so libraries.
- When fix_kind is "code_patch", return the COMPLETE compilable Java source file preserving package/imports/class name and existing working stubs.`
	case ScopeQiling:
		domainGuide = `Domain expertise: Qiling Framework (Python) binary emulation on Unicorn.
- Focus on UC_ERR_* unmapped/protection faults (ql.mem.map / ql.mem.protect), rootfs layout, architecture/endianness setup, syscall/API hooks (ql.os.set_syscall / ql.os.set_api), and register/stack initialization.
- If rootfs or Python path configuration is wrong, prefer "config_fix" with allowlisted cap keys (re_qiling_rootfs, re_qiling_python_path).
- When fix_kind is "code_patch", return the COMPLETE valid Python script.`
	case ScopeAngr:
		domainGuide = `Domain expertise: angr (Python) symbolic execution and binary analysis.
- Focus on angr.Project options (auto_load_libs=False), claripy symbolic bitvectors, SimProcedure hooks, state constraints, and find/avoid addresses.
- If the angr Python environment path is misconfigured, use "config_fix" with re_angr_python_path.
- When fix_kind is "code_patch", return the COMPLETE valid Python script.`
	case ScopeFrida:
		domainGuide = `Domain expertise: Frida (JavaScript) dynamic instrumentation on Android/iOS/desktop.
- Focus on Java.perform wrapping, explicit .overload(...) disambiguation, ClassLoader lookup, ObjC.available guards, Module.findExportByName null checks, Interceptor.attach pointer safety, and safe Memory.read*/write*.
- When fix_kind is "code_patch", return the COMPLETE valid JavaScript Frida script.`
	case ScopePlugin:
		domainGuide = `Domain expertise: cap proxy/analysis plugins (JavaScript or Python).
- Focus on hook signatures, null/undefined guards, JSON/header parsing edge cases, and syntax/runtime fixes.
- When fix_kind is "code_patch", return the COMPLETE valid plugin source file.`
	case ScopeSigner:
		domainGuide = `Domain expertise: HTTP request signing, cryptography, and replay scripts.
- Focus on canonical string ordering, HMAC/hash/AES encoding (UTF-8, hex, base64), timestamp/nonce formats, and deterministic execution.
- When fix_kind is "code_patch", return the COMPLETE valid signer script.`
	case ScopeToolchain:
		domainGuide = `Domain expertise: cap reverse-engineering host toolchain diagnostics (radare2, Java, Maven, Unidbg, Python, Qiling, angr, Frida, adb, jadx).
- Prefer "config_fix" using ONLY allowlisted cap settings keys when an executable or rootfs path should be updated, or "command_hint" for safe installation/check commands.`
	case ScopeRecon:
		domainGuide = `Domain expertise: cap reconnaissance and network discovery diagnostics (nmap, subfinder, whois, dig, DNS, TLS, HTTP probing).
- Diagnose missing binaries, permission issues, timeouts, invalid targets, or proxy/gateway configuration. Prefer "config_fix" or "command_hint" where appropriate.`
	default:
		domainGuide = `Domain expertise: network debugging, reverse engineering, and scripting inside cap.
- Diagnose the root cause from logs, error messages, and source code, and provide the smallest reliable fix.`
	}

	var langRule string
	if normLocale == "zh-CN" {
		langRule = "Language requirement: Write root_cause, explanation, and verify_hint in clear, concise Simplified Chinese (简体中文). Keep JSON keys, fix_kind, error_category, source code, setting keys, and shell commands in exact technical form."
	} else {
		langRule = "Language requirement: Write root_cause, explanation, and verify_hint in clear, concise English."
	}

	return fmt.Sprintf(`You are cap's Self-Healing Diagnostic Engine.
%s
%s

STRICT OUTPUT CONTRACT:
Respond with ONLY a single valid JSON object (no surrounding markdown prose) containing these fields:
{
  "root_cause": "concise one-sentence root cause",
  "error_category": "short snake_case category e.g. missing_jni | unmapped_memory | overload_mismatch | syntax_error | missing_dependency | config_error | runtime_error | unknown",
  "confidence": 0.85,
  "fix_kind": "code_patch | config_fix | command_hint | explanation_only",
  "explanation": "clear explanation of what failed and how the fix resolves it",
  "patched_code": "COMPLETE fixed source file when fix_kind is code_patch; empty string otherwise. NEVER use '...' placeholders or partial snippets.",
  "config_changes": {"key": "value"},
  "command_hints": ["safe diagnostic or install command"],
  "verify_hint": "how to verify the fix succeeded"
}

Safety & hygiene rules:
- NEVER emit destructive shell commands (rm -rf /, mkfs, dd if=, fork bombs, raw disk writes).
- For config_changes, ONLY use allowlisted cap keys: re_r2_path, re_java_path, re_mvn_path, re_unidbg_dir, re_python_path, re_qiling_python_path, re_angr_python_path, re_qiling_rootfs, frida_python_path, frida_cli_path, frida_default_port, gateway_addr, proxy_addr.
- If previous_attempts are provided, do NOT repeat an already-failed patch or error.`, domainGuide, langRule)
}

// BuildUserPrompt assembles the diagnostic context sent to the LLM.
func BuildUserPrompt(req DiagnoseRequest, preDiagnosis, compressedLogs string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Scope: %s\n", NormalizeScope(req.Scope))
	if lang := strings.TrimSpace(req.Language); lang != "" {
		fmt.Fprintf(&b, "Language: %s\n", lang)
	}

	if len(req.Metadata) > 0 {
		keys := make([]string, 0, len(req.Metadata))
		for k := range req.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("\nMetadata:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "- %s: %s\n", k, req.Metadata[k])
		}
	}

	if strings.TrimSpace(preDiagnosis) != "" {
		b.WriteString("\nLocal Pre-Diagnosis:\n")
		b.WriteString(strings.TrimSpace(preDiagnosis))
		b.WriteByte('\n')
	}

	if strings.TrimSpace(req.ErrorText) != "" {
		b.WriteString("\nError Summary:\n")
		b.WriteString(strings.TrimSpace(req.ErrorText))
		b.WriteByte('\n')
	}

	if strings.TrimSpace(compressedLogs) != "" {
		b.WriteString("\nExecution Logs:\n```\n")
		b.WriteString(strings.TrimSpace(compressedLogs))
		b.WriteString("\n```\n")
	}

	if strings.TrimSpace(req.Code) != "" {
		langTag := strings.ToLower(strings.TrimSpace(req.Language))
		fmt.Fprintf(&b, "\nCurrent Source Code:\n```%s\n%s\n```\n", langTag, req.Code)
	}

	if len(req.PreviousAttempts) > 0 {
		b.WriteString("\nPrevious Failed Repair Attempts (do NOT repeat these approaches):\n")
		for _, prev := range req.PreviousAttempts {
			fmt.Fprintf(&b, "- Attempt #%d [outcome=%s", prev.Attempt, prev.Outcome)
			if prev.FixKind != "" {
				fmt.Fprintf(&b, ", fix_kind=%s", prev.FixKind)
			}
			if prev.ErrorFingerprint != "" {
				fmt.Fprintf(&b, ", fp=%s", prev.ErrorFingerprint)
			}
			b.WriteString("]:\n")
			if prev.RootCause != "" {
				fmt.Fprintf(&b, "  Prior root cause: %s\n", prev.RootCause)
			}
			if prev.ErrorExcerpt != "" {
				fmt.Fprintf(&b, "  Error excerpt: %s\n", prev.ErrorExcerpt)
			}
			if prev.UnifiedDiff != "" {
				diffExcerpt := prev.UnifiedDiff
				if len(diffExcerpt) > 1200 {
					diffExcerpt = truncatePrefixUTF8(diffExcerpt, 1200) + "\n... [diff truncated]"
				}
				fmt.Fprintf(&b, "  Prior diff:\n%s\n", diffExcerpt)
			}
		}
	}

	b.WriteString("\nReturn ONLY the strict JSON diagnosis object.")
	return b.String()
}

// ParseDiagnoseJSON extracts and parses a DiagnoseResult JSON object from LLM
// text, tolerating raw JSON, ```json fences, and leading/trailing prose.
func ParseDiagnoseJSON(raw string) (*DiagnoseResult, error) {
	cleaned := strings.TrimSpace(strings.TrimPrefix(raw, "\uFEFF"))
	if cleaned == "" {
		return nil, errors.New("empty AI response")
	}

	candidates := collectJSONCandidates(cleaned)
	var lastErr error
	for _, cand := range candidates {
		res, err := unmarshalDiagnoseCandidate(cand)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("failed to parse AI JSON response: %w", lastErr)
	}
	return nil, errors.New("no valid JSON diagnosis object found in AI response")
}

func collectJSONCandidates(text string) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(s string) {
		t := strings.TrimSpace(s)
		if t == "" {
			return
		}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}

	// 1. Direct JSON object.
	if strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}") {
		add(text)
	}

	// 2. Markdown code fences (prefer ```json blocks first, then any ``` block).
	jsonFences, otherFences := extractMarkdownFences(text)
	for _, f := range jsonFences {
		add(f)
	}
	for _, f := range otherFences {
		add(f)
	}

	// 3. String-aware balanced JSON object extraction from surrounding commentary.
	for _, obj := range extractBalancedJSONObjects(text) {
		add(obj)
	}
	return out
}

func extractMarkdownFences(text string) (jsonBlocks []string, otherBlocks []string) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	inFence := false
	isJSON := false
	var buf []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inFence {
			if strings.HasPrefix(trimmed, "```") {
				info := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "```")))
				inFence = true
				isJSON = info == "json" || strings.HasPrefix(info, "json ")
				buf = buf[:0]
			}
			continue
		}
		if trimmed == "```" {
			content := strings.TrimSpace(strings.Join(buf, "\n"))
			if content != "" {
				if isJSON {
					jsonBlocks = append(jsonBlocks, content)
				} else {
					otherBlocks = append(otherBlocks, content)
				}
			}
			inFence = false
			isJSON = false
			buf = buf[:0]
			continue
		}
		buf = append(buf, line)
	}
	return jsonBlocks, otherBlocks
}

// extractBalancedJSONObjects finds top-level `{...}` blocks while respecting
// JSON double-quoted strings and escape sequences.
func extractBalancedJSONObjects(text string) []string {
	var objs []string
	n := len(text)
	i := 0
	for i < n {
		if text[i] != '{' {
			i++
			continue
		}
		start := i
		depth := 0
		inString := false
		escaped := false
		matched := false
		for j := i; j < n; j++ {
			ch := text[j]
			if inString {
				if escaped {
					escaped = false
					continue
				}
				if ch == '\\' {
					escaped = true
					continue
				}
				if ch == '"' {
					inString = false
				}
				continue
			}
			switch ch {
			case '"':
				inString = true
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					objs = append(objs, text[start:j+1])
					i = j + 1
					matched = true
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			i = start + 1
		}
	}
	return objs
}

func unmarshalDiagnoseCandidate(candidate string) (*DiagnoseResult, error) {
	// Ensure it is a JSON object (not array/primitive) and carries at least one
	// recognized diagnosis field so random `{...}` code fragments in prose don't match.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(candidate), &probe); err != nil {
		return nil, err
	}
	if len(probe) == 0 {
		return nil, errors.New("empty JSON object")
	}
	recognized := false
	for _, key := range []string{"root_cause", "fix_kind", "explanation", "patched_code", "config_changes", "command_hints"} {
		if _, ok := probe[key]; ok {
			recognized = true
			break
		}
	}
	if !recognized {
		return nil, errors.New("JSON object does not match diagnosis schema")
	}

	var parsed DiagnoseResult
	if err := json.Unmarshal([]byte(candidate), &parsed); err != nil {
		return nil, err
	}
	normalizeDiagnoseResult(&parsed)
	return &parsed, nil
}

func normalizeDiagnoseResult(res *DiagnoseResult) {
	res.RootCause = strings.TrimSpace(res.RootCause)
	res.ErrorCategory = strings.TrimSpace(res.ErrorCategory)
	if res.ErrorCategory == "" {
		res.ErrorCategory = "unknown"
	}
	if math.IsNaN(res.Confidence) || math.IsInf(res.Confidence, 0) {
		res.Confidence = 0
	} else if res.Confidence < 0 {
		res.Confidence = 0
	} else if res.Confidence > 1 {
		res.Confidence = 1
	}

	res.Explanation = strings.TrimSpace(res.Explanation)
	res.VerifyHint = strings.TrimSpace(res.VerifyHint)
	res.ConfigChanges = SanitizeConfigChanges(res.ConfigChanges)

	if len(res.CommandHints) > 0 {
		cleaned := make([]string, 0, len(res.CommandHints))
		for _, cmd := range res.CommandHints {
			t := strings.TrimSpace(cmd)
			if t == "" {
				continue
			}
			if _, destructive := matchDestructivePattern(t); destructive {
				continue
			}
			cleaned = append(cleaned, t)
		}
		if len(cleaned) == 0 {
			res.CommandHints = nil
		} else {
			res.CommandHints = cleaned
		}
	}

	switch strings.ToLower(strings.TrimSpace(res.FixKind)) {
	case FixKindCodePatch:
		res.FixKind = FixKindCodePatch
	case FixKindConfigFix:
		res.FixKind = FixKindConfigFix
	case FixKindCommandHint:
		res.FixKind = FixKindCommandHint
	case FixKindExplanationOnly:
		res.FixKind = FixKindExplanationOnly
	default:
		switch {
		case strings.TrimSpace(res.PatchedCode) != "":
			res.FixKind = FixKindCodePatch
		case len(res.ConfigChanges) > 0:
			res.FixKind = FixKindConfigFix
		case len(res.CommandHints) > 0:
			res.FixKind = FixKindCommandHint
		default:
			res.FixKind = FixKindExplanationOnly
		}
	}
}
