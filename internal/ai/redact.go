package ai

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/overkazaf/cap/internal/redaction"
	"github.com/overkazaf/cap/internal/repro"
)

const (
	logHeadLines = 40
	logTailLines = 120
	maxLogBytes  = 24 * 1024
)

var (
	// PEM private key blocks (RSA, EC, OPENSSH, ENCRYPTED, generic PKCS#8).
	pemPrivateKeyRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// Proxy / URL embedded credentials: scheme://user:pass@host
	urlCredsRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@"'` + "`" + `]+):([^/\s@"'` + "`" + `]+)@`)

	// JSON sensitive header fields: "Authorization": "...", "X-Api-Key": "..."
	jsonSensitiveHeaderRe = regexp.MustCompile(`(?i)("(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-goog-api-key)"\s*:\s*")([^"]+)(")`)

	// Line-level HTTP headers (Cookie, Set-Cookie, Authorization, X-Api-Key, etc.)
	lineSensitiveHeaderRe = regexp.MustCompile(`(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-goog-api-key)[ \t]*:[ \t]*)([^\r\n]+)$`)

	// Inline sensitive headers embedded in logs or curl flags (e.g. -H 'X-Api-Key: secret').
	inlineSensitiveHeaderRe = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-goog-api-key)([ \t]*:[ \t]*)([^\r\n'"` + "`" + `]+)`)

	// Standalone Bearer / Basic authorization tokens.
	bearerBasicRe = regexp.MustCompile(`(?i)\b(Bearer|Basic)([ \t]+)([A-Za-z0-9._~+/=-]{8,})`)

	// Provider / VCS API key patterns.
	skKeyRe   = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{12,}\b`)
	aizaKeyRe = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{20,}\b`)
	ghKeyRe   = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b`)
	awsKeyRe  = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

	// URLs with query strings for sensitive query parameter scrubbing via internal/redaction.
	urlWithQueryRe = regexp.MustCompile(`https?://[^\s"'` + "`" + `<>)\]]+\?[^\s"'` + "`" + `<>)\]]+`)

	// Pre-diagnosis extractors for Frida, Qiling, Angr, and Toolchain scopes.
	fridaOverloadHeaderRe = regexp.MustCompile(`(?i)([A-Za-z0-9_.$<>]+)\(\)\s*:\s*has more than one overload|has more than one overload`)
	fridaOverloadSigRe    = regexp.MustCompile(`\.overload\(([^)]*)\)`)
	fridaClassNotFoundRe  = regexp.MustCompile(`(?i)(?:ClassNotFoundException|Unable to find class)[:\s]+([A-Za-z0-9_.$]+)`)
	fridaAccessViolRe     = regexp.MustCompile(`(?i)access violation (?:accessing|reading|writing) (0x[0-9a-fA-F]+)`)
	fridaTypeErrRe        = regexp.MustCompile(`(?i)TypeError:\s*([^\r\n]+)`)

	qilingUCErrRe       = regexp.MustCompile(`(UC_ERR_[A-Z0-9_]+)(?:[^\r\n]{0,120})`)
	qilingAddrRe        = regexp.MustCompile(`(?i)(?:pc|addr(?:ess)?|at|accessing)\s*[:=]?\s*(0x[0-9a-fA-F]+)`)
	qilingMissingPathRe = regexp.MustCompile(`(?i)(?:FileNotFoundError|No such file or directory|cannot open shared object file)[^\r\n]*`)

	pyModuleErrRe  = regexp.MustCompile(`(?i)ModuleNotFoundError:\s*No module named ['"]([^'"]+)['"]`)
	execNotFoundRe = regexp.MustCompile(`(?i)(?:executable file not found|command not found|No such file or directory)[^\r\n]*`)
)

// CompressLogs retains at most the first 40 lines and last 120 lines of raw
// logs and enforces a hard 24 KiB byte budget while preserving valid UTF-8.
func CompressLogs(raw string) string {
	if raw == "" {
		return ""
	}
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	lines := strings.Split(normalized, "\n")
	var out string
	if len(lines) > logHeadLines+logTailLines {
		omitted := len(lines) - (logHeadLines + logTailLines)
		head := strings.Join(lines[:logHeadLines], "\n")
		tail := strings.Join(lines[len(lines)-logTailLines:], "\n")
		out = fmt.Sprintf("%s\n... [%d lines omitted] ...\n%s", head, omitted, tail)
	} else {
		out = normalized
	}

	if len(out) <= maxLogBytes {
		return out
	}

	const marker = "\n... [truncated to 24 KiB limit] ...\n"
	budget := maxLogBytes - len(marker)
	headBudget := budget / 4
	tailBudget := budget - headBudget

	headStr := truncatePrefixUTF8(out, headBudget)
	tailStr := truncateSuffixUTF8(out, tailBudget)
	return headStr + marker + tailStr
}

func truncatePrefixUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func truncateSuffixUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	start := len(s) - maxBytes
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return s[start:]
}

// RedactSecrets scrubs credentials, tokens, sensitive headers, API keys, proxy
// URL credentials, and PEM private keys from text, returning the cleaned text
// and the number of redacted occurrences.
func RedactSecrets(text string) (string, int) {
	if text == "" {
		return "", 0
	}
	count := 0
	out := text

	// 1. PEM private key blocks.
	out = pemPrivateKeyRe.ReplaceAllStringFunc(out, func(_ string) string {
		count++
		return redaction.Placeholder
	})

	// 2. Proxy / URL embedded credentials (scheme://user:pass@).
	out = urlCredsRe.ReplaceAllStringFunc(out, func(m string) string {
		sub := urlCredsRe.FindStringSubmatch(m)
		if len(sub) != 4 {
			return m
		}
		if sub[2] == redaction.Placeholder && sub[3] == redaction.Placeholder {
			return m
		}
		count++
		return sub[1] + redaction.Placeholder + ":" + redaction.Placeholder + "@"
	})

	// 3. JSON sensitive header pairs.
	out = jsonSensitiveHeaderRe.ReplaceAllStringFunc(out, func(m string) string {
		sub := jsonSensitiveHeaderRe.FindStringSubmatch(m)
		if len(sub) != 4 || strings.TrimSpace(sub[2]) == redaction.Placeholder {
			return m
		}
		count++
		return sub[1] + redaction.Placeholder + sub[3]
	})

	// 4. Line-level sensitive HTTP headers.
	out = lineSensitiveHeaderRe.ReplaceAllStringFunc(out, func(m string) string {
		sub := lineSensitiveHeaderRe.FindStringSubmatch(m)
		if len(sub) != 3 || strings.TrimSpace(sub[2]) == redaction.Placeholder {
			return m
		}
		count++
		return sub[1] + redaction.Placeholder
	})

	// 5. Inline sensitive headers inside log lines or curl invocations.
	out = inlineSensitiveHeaderRe.ReplaceAllStringFunc(out, func(m string) string {
		sub := inlineSensitiveHeaderRe.FindStringSubmatch(m)
		if len(sub) != 4 || strings.TrimSpace(sub[3]) == redaction.Placeholder {
			return m
		}
		count++
		return sub[1] + sub[2] + redaction.Placeholder
	})

	// 6. Standalone Bearer / Basic credentials.
	out = bearerBasicRe.ReplaceAllStringFunc(out, func(m string) string {
		sub := bearerBasicRe.FindStringSubmatch(m)
		if len(sub) != 4 || sub[3] == redaction.Placeholder {
			return m
		}
		count++
		return sub[1] + sub[2] + redaction.Placeholder
	})

	// 7. Sensitive query parameters in URLs via internal/redaction (run before
	// bare API key matching so keys inside sensitive query params are counted once).
	out = urlWithQueryRe.ReplaceAllStringFunc(out, func(rawURL string) string {
		cleaned := redaction.URL(rawURL)
		if cleaned != rawURL {
			count++
		}
		return cleaned
	})

	// 8. Known API key prefixes (sk-..., AIza..., ghp_..., github_pat_..., AKIA...).
	for _, re := range []*regexp.Regexp{skKeyRe, aizaKeyRe, ghKeyRe, awsKeyRe} {
		out = re.ReplaceAllStringFunc(out, func(_ string) string {
			count++
			return redaction.Placeholder
		})
	}

	return out, count
}

// RedactAndCompressLogs compresses logs first (head 40 + tail 120, <= 24 KiB)
// and redacts secrets when redact is true.
func RedactAndCompressLogs(raw string, redact bool) (string, int) {
	compressed := CompressLogs(raw)
	if !redact {
		return compressed, 0
	}
	return RedactSecrets(compressed)
}

// RedactLiteralSecret strips any literal or URL-escaped occurrence of secret
// from s, plus runs RedactSecrets to ensure errors never leak credentials.
func RedactLiteralSecret(s, secret string) string {
	if s == "" {
		return ""
	}
	out := s
	if trimmed := strings.TrimSpace(secret); trimmed != "" {
		out = strings.ReplaceAll(out, trimmed, redaction.Placeholder)
		if escaped := url.QueryEscape(trimmed); escaped != "" && escaped != trimmed {
			out = strings.ReplaceAll(out, escaped, redaction.Placeholder)
		}
	}
	cleaned, _ := RedactSecrets(out)
	return cleaned
}

// BuildPreDiagnosis runs deterministic local log analysis tailored to req.Scope
// so the LLM receives exact structured findings before synthesizing a fix.
func BuildPreDiagnosis(req DiagnoseRequest) string {
	combined := strings.TrimSpace(strings.TrimSpace(req.ErrorText) + "\n" + strings.TrimSpace(req.Logs))
	if combined == "" {
		return ""
	}
	switch NormalizeScope(req.Scope) {
	case ScopeUnidbg:
		return buildUnidbgPreDiagnosis(combined)
	case ScopeFrida:
		return buildFridaPreDiagnosis(combined)
	case ScopeQiling:
		return buildQilingPreDiagnosis(combined)
	case ScopeAngr, ScopeToolchain, ScopePlugin, ScopeSigner, ScopeRecon:
		return buildGenericToolchainPreDiagnosis(combined)
	default:
		return buildGenericToolchainPreDiagnosis(combined)
	}
}

func buildUnidbgPreDiagnosis(rawLog string) string {
	diag := repro.AnalyzeUnidbgLog(rawLog)
	if diag == nil || diag.TotalErrors == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Deterministic Unidbg Analysis:\n")
	if diag.Summary != "" {
		fmt.Fprintf(&b, "- Summary: %s\n", diag.Summary)
	}
	if len(diag.MissingJNI) > 0 {
		b.WriteString("- Missing JNI Callbacks:\n")
		for i, item := range diag.MissingJNI {
			if i >= 12 {
				fmt.Fprintf(&b, "  - ... and %d more JNI callbacks\n", len(diag.MissingJNI)-12)
				break
			}
			fmt.Fprintf(&b, "  - %s: %s (x%d)", item.Callback, item.Signature, item.Count)
			if item.Note != "" {
				fmt.Fprintf(&b, " — %s", item.Note)
			}
			b.WriteByte('\n')
		}
	}
	if len(diag.MissingClasses) > 0 {
		fmt.Fprintf(&b, "- Missing Classes: %s\n", strings.Join(diag.MissingClasses, ", "))
	}
	if len(diag.MissingFiles) > 0 {
		b.WriteString("- Missing IOResolver Paths:\n")
		for i, item := range diag.MissingFiles {
			if i >= 10 {
				break
			}
			fmt.Fprintf(&b, "  - %s (x%d)", item.Path, item.Count)
			if item.Note != "" {
				fmt.Fprintf(&b, " — %s", item.Note)
			}
			b.WriteByte('\n')
		}
	}
	if len(diag.MissingSysProps) > 0 {
		b.WriteString("- Missing Android System Properties:\n")
		for i, item := range diag.MissingSysProps {
			if i >= 10 {
				break
			}
			fmt.Fprintf(&b, "  - %s (suggested=%q, x%d)\n", item.Key, item.SuggestedValue, item.Count)
		}
	}
	if len(diag.MissingLibraries) > 0 {
		libs := make([]string, 0, len(diag.MissingLibraries))
		for _, lib := range diag.MissingLibraries {
			libs = append(libs, lib.Name)
		}
		fmt.Fprintf(&b, "- Missing Native Libraries: %s\n", strings.Join(libs, ", "))
	}
	if stub := strings.TrimSpace(diag.AbstractJniSnippet); stub != "" {
		if len(stub) > 1500 {
			stub = truncatePrefixUTF8(stub, 1500) + "\n// ... truncated ..."
		}
		b.WriteString("- Suggested AbstractJni Stub Hint:\n")
		b.WriteString(stub)
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

func buildFridaPreDiagnosis(rawLog string) string {
	var hints []string

	if fridaOverloadHeaderRe.MatchString(rawLog) {
		sigs := uniqueMatches(fridaOverloadSigRe.FindAllString(rawLog, 12))
		if len(sigs) > 0 {
			hints = append(hints, fmt.Sprintf("Ambiguous Java method overload detected; explicitly disambiguate with one of: %s", strings.Join(sigs, ", ")))
		} else {
			hints = append(hints, "Ambiguous Java method overload detected; call .overload(...) with exact parameter types.")
		}
	}
	if m := fridaClassNotFoundRe.FindStringSubmatch(rawLog); len(m) == 2 {
		hints = append(hints, fmt.Sprintf("Target Java class not found (%s); verify package/classloader (Java.enumerateClassLoaders) and ensure app class is loaded.", m[1]))
	}
	if m := fridaAccessViolRe.FindStringSubmatch(rawLog); len(m) == 2 {
		hints = append(hints, fmt.Sprintf("Native memory access violation at %s; guard pointers with !ptr.isNull() before Memory.read*/write*.", m[1]))
	}
	if strings.Contains(rawLog, "Java.perform") && strings.Contains(strings.ToLower(rawLog), "not") {
		hints = append(hints, "Ensure all Java.use() calls execute inside Java.perform(function() { ... }).")
	}
	if m := fridaTypeErrRe.FindStringSubmatch(rawLog); len(m) == 2 {
		hints = append(hints, fmt.Sprintf("JavaScript TypeError: %s (check method name, Module.findExportByName null return, or argument types).", strings.TrimSpace(m[1])))
	}
	if len(hints) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Deterministic Frida Analysis:\n")
	for _, h := range hints {
		fmt.Fprintf(&b, "- %s\n", h)
	}
	return strings.TrimSpace(b.String())
}

func buildQilingPreDiagnosis(rawLog string) string {
	var hints []string

	ucMatches := uniqueMatches(qilingUCErrRe.FindAllString(rawLog, 8))
	for _, m := range ucMatches {
		line := strings.TrimSpace(m)
		switch {
		case strings.Contains(line, "UC_ERR_READ_UNMAPPED"),
			strings.Contains(line, "UC_ERR_WRITE_UNMAPPED"),
			strings.Contains(line, "UC_ERR_FETCH_UNMAPPED"):
			hints = append(hints, fmt.Sprintf("Unicorn unmapped memory fault (%s); map the missing page-aligned memory region via ql.mem.map(addr & ~0xfff, size) or verify pointer/register setup.", line))
		case strings.Contains(line, "UC_ERR_READ_PROT"),
			strings.Contains(line, "UC_ERR_WRITE_PROT"),
			strings.Contains(line, "UC_ERR_FETCH_PROT"):
			hints = append(hints, fmt.Sprintf("Unicorn memory protection fault (%s); adjust mapping permissions with ql.mem.protect(...).", line))
		case strings.Contains(line, "UC_ERR_INSN_INVALID"):
			hints = append(hints, fmt.Sprintf("Unicorn invalid instruction (%s); verify CPU architecture/Thumb mode bit and valid code entry address.", line))
		default:
			hints = append(hints, fmt.Sprintf("Unicorn engine error: %s", line))
		}
	}

	if addrs := uniqueSubmatches(qilingAddrRe.FindAllStringSubmatch(rawLog, 8), 1); len(addrs) > 0 {
		hints = append(hints, fmt.Sprintf("Referenced faulting addresses: %s", strings.Join(addrs, ", ")))
	}
	if m := qilingMissingPathRe.FindString(rawLog); m != "" {
		hints = append(hints, fmt.Sprintf("Missing rootfs/library path: %s (check re_qiling_rootfs setting and target architecture rootfs layout).", strings.TrimSpace(m)))
	}
	if m := pyModuleErrRe.FindStringSubmatch(rawLog); len(m) == 2 {
		hints = append(hints, fmt.Sprintf("Missing Python module %q; verify re_qiling_python_path points to the virtualenv containing qiling.", m[1]))
	}

	if len(hints) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Deterministic Qiling Analysis:\n")
	for _, h := range hints {
		fmt.Fprintf(&b, "- %s\n", h)
	}
	return strings.TrimSpace(b.String())
}

func buildGenericToolchainPreDiagnosis(rawLog string) string {
	var hints []string
	if m := pyModuleErrRe.FindStringSubmatch(rawLog); len(m) == 2 {
		hints = append(hints, fmt.Sprintf("Missing Python module %q; install into the configured Python environment or update the corresponding *_python_path setting.", m[1]))
	}
	if m := execNotFoundRe.FindString(rawLog); m != "" {
		hints = append(hints, fmt.Sprintf("Missing executable or file: %s", strings.TrimSpace(m)))
	}
	if len(hints) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Deterministic Pre-Diagnosis:\n")
	for _, h := range hints {
		fmt.Fprintf(&b, "- %s\n", h)
	}
	return strings.TrimSpace(b.String())
}

func uniqueMatches(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func uniqueSubmatches(in [][]string, group int) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, m := range in {
		if len(m) <= group {
			continue
		}
		t := strings.TrimSpace(m[group])
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
