package ai

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	validatorTimeout     = 10 * time.Second
	maxValidatorOutBytes = 64 * 1024
)

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len() < l.max {
		rem := l.max - l.buf.Len()
		if len(p) > rem {
			l.buf.Write(p[:rem])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string {
	return l.buf.String()
}

// Strict allowlist of cap settings keys that AI config_fix suggestions may touch.
var allowedConfigKeys = map[string]struct{}{
	"re_r2_path":            {},
	"re_java_path":          {},
	"re_mvn_path":           {},
	"re_unidbg_dir":         {},
	"re_python_path":        {},
	"re_qiling_python_path": {},
	"re_angr_python_path":   {},
	"re_qiling_rootfs":      {},
	"frida_python_path":     {},
	"frida_cli_path":        {},
	"frida_default_port":    {},
	"gateway_addr":          {},
	"proxy_addr":            {},
}

var destructivePatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{
		name: "recursive root/home deletion (rm -rf /)",
		re:   regexp.MustCompile(`(?i)\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*)\s+(?:--no-preserve-root\s+)?(?:/\*(?:\s|$|["';&|)])|/(?:\s|$|["';&|)])|~(?:/|\s|$|["';&|)])|\$HOME(?:/|\s|$|["';&|)]))`),
	},
	{
		name: "filesystem formatting command (mkfs)",
		re:   regexp.MustCompile(`(?i)\bmkfs(?:\.[a-z0-9_+-]+)?\b`),
	},
	{
		name: "raw block-device copy (dd if=)",
		re:   regexp.MustCompile(`(?i)\bdd\s+if=`),
	},
	{
		name: "shell fork bomb",
		re:   regexp.MustCompile(`:\s*\(\s*\)\s*\{[^}]*\|[^}]*&\s*\}\s*;\s*:`),
	},
	{
		name: "raw block-device overwrite (> /dev/...)",
		re:   regexp.MustCompile(`>\s*/dev/(?:sd[a-z]\d*|nvme\d+n\d+|disk\d+|hd[a-z]\d*)`),
	},
}

var javaTypeDeclRe = regexp.MustCompile(`\b(?:class|interface|enum|record)\s+[A-Za-z_$][A-Za-z0-9_$]*`)

// ValidatePatchedCode checks patchedCode for emptiness, destructive command
// patterns, and language-specific syntactic validity.
func ValidatePatchedCode(lang, oldCode, patchedCode string) PatchValidation {
	res := PatchValidation{
		Passed:    false,
		Validator: "basic",
	}

	if strings.TrimSpace(patchedCode) == "" {
		res.Issues = append(res.Issues, "patched code is empty")
		return res
	}

	for _, pat := range destructivePatterns {
		if pat.re.MatchString(patchedCode) {
			res.Validator = "safety_guard"
			res.Issues = append(res.Issues, fmt.Sprintf("blocked destructive pattern: %s", pat.name))
			return res
		}
	}

	if strings.TrimSpace(oldCode) != "" && normalizeCodeForCompare(oldCode) == normalizeCodeForCompare(patchedCode) {
		res.Warnings = append(res.Warnings, "patched code is identical to original code")
	}

	switch normalizeLanguage(lang) {
	case "javascript":
		return validateJavaScript(patchedCode, res.Warnings)
	case "python":
		return validatePython(patchedCode, res.Warnings)
	case "java":
		return validateJava(patchedCode, res.Warnings)
	default:
		res.Passed = true
		return res
	}
}

func normalizeLanguage(lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "js", "javascript", "mjs", "cjs", "frida":
		return "javascript"
	case "py", "python", "python3":
		return "python"
	case "java":
		return "java"
	default:
		return strings.ToLower(strings.TrimSpace(lang))
	}
}

func validateJavaScript(code string, warnings []string) PatchValidation {
	if nodePath, err := exec.LookPath("node"); err == nil {
		return validateJavaScriptWithNode(nodePath, code, warnings)
	}
	return validateJSBalanced(code, warnings)
}

func validateJavaScriptWithNode(nodePath, code string, warnings []string) PatchValidation {
	res := PatchValidation{
		Validator: "node --check",
		Warnings:  warnings,
	}
	tmp, err := os.CreateTemp("", "cap-ai-js-*.js")
	if err != nil {
		return validateJSBalanced(code, append(warnings, "failed to create temp file for node --check; used balanced-delimiter fallback"))
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.WriteString(code); err != nil {
		_ = tmp.Close()
		res.Issues = append(res.Issues, fmt.Sprintf("write temp js file: %v", err))
		return res
	}
	if err := tmp.Close(); err != nil {
		res.Issues = append(res.Issues, fmt.Sprintf("close temp js file: %v", err))
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), validatorTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nodePath, "--check", tmpPath)
	stderr := &limitedBuffer{max: maxValidatorOutBytes}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 600 {
			msg = truncatePrefixUTF8(msg, 600) + "..."
		}
		res.Issues = append(res.Issues, "JavaScript syntax error: "+msg)
		return res
	}
	res.Passed = true
	return res
}

func validateJSBalanced(code string, warnings []string) PatchValidation {
	res := PatchValidation{
		Validator: "js_balanced_fallback",
		Warnings:  warnings,
	}
	_, issues := scanCStyleCode(code, true)
	if len(issues) > 0 {
		res.Issues = issues
		return res
	}
	res.Passed = true
	return res
}

func validatePython(code string, warnings []string) PatchValidation {
	if pyPath, err := exec.LookPath("python3"); err == nil {
		return validatePythonWithCompiler(pyPath, code, warnings)
	}
	return validatePythonBalanced(code, warnings)
}

func validatePythonWithCompiler(pyPath, code string, warnings []string) PatchValidation {
	res := PatchValidation{
		Validator: "python3 -m py_compile",
		Warnings:  warnings,
	}
	tmpDir, err := os.MkdirTemp("", "cap-ai-py-*")
	if err != nil {
		return validatePythonBalanced(code, append(warnings, "failed to create temp dir for py_compile; used balanced-delimiter fallback"))
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmpFile := filepath.Join(tmpDir, "patch.py")
	if err := os.WriteFile(tmpFile, []byte(code), 0o600); err != nil {
		res.Issues = append(res.Issues, fmt.Sprintf("write temp python file: %v", err))
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), validatorTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, pyPath, "-m", "py_compile", tmpFile)
	out := &limitedBuffer{max: maxValidatorOutBytes}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 600 {
			msg = truncatePrefixUTF8(msg, 600) + "..."
		}
		res.Issues = append(res.Issues, "Python syntax error: "+msg)
		return res
	}
	res.Passed = true
	return res
}

func validatePythonBalanced(code string, warnings []string) PatchValidation {
	res := PatchValidation{
		Validator: "python_balanced_fallback",
		Warnings:  warnings,
	}
	type frame struct {
		ch   byte
		line int
	}
	var stack []frame
	line := 1
	n := len(code)
	for i := 0; i < n; {
		ch := code[i]
		if ch == '\n' {
			line++
			i++
			continue
		}
		// Line comment.
		if ch == '#' {
			for i < n && code[i] != '\n' {
				i++
			}
			continue
		}
		// Triple-quoted string.
		if (ch == '\'' || ch == '"') && i+2 < n && code[i+1] == ch && code[i+2] == ch {
			quote := ch
			startLine := line
			i += 3
			closed := false
			for i < n {
				if code[i] == '\\' {
					i += 2
					continue
				}
				if code[i] == '\n' {
					line++
					i++
					continue
				}
				if code[i] == quote && i+2 < n && code[i+1] == quote && code[i+2] == quote {
					i += 3
					closed = true
					break
				}
				i++
			}
			if !closed {
				res.Issues = append(res.Issues, fmt.Sprintf("unterminated triple-quoted string starting at line %d", startLine))
				return res
			}
			continue
		}
		// Single/double quoted string.
		if ch == '\'' || ch == '"' {
			quote := ch
			startLine := line
			i++
			closed := false
			for i < n {
				if code[i] == '\\' {
					if i+1 < n && code[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if code[i] == '\n' {
					break
				}
				if code[i] == quote {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				res.Issues = append(res.Issues, fmt.Sprintf("unterminated string literal at line %d", startLine))
				return res
			}
			continue
		}

		switch ch {
		case '(', '[', '{':
			stack = append(stack, frame{ch: ch, line: line})
		case ')', ']', '}':
			if len(stack) == 0 || !matchingDelimiter(stack[len(stack)-1].ch, ch) {
				res.Issues = append(res.Issues, fmt.Sprintf("unmatched closing '%c' at line %d", ch, line))
				return res
			}
			stack = stack[:len(stack)-1]
		}
		i++
	}
	if len(stack) > 0 {
		top := stack[len(stack)-1]
		res.Issues = append(res.Issues, fmt.Sprintf("unclosed '%c' opened at line %d", top.ch, top.line))
		return res
	}
	res.Passed = true
	return res
}

func validateJava(code string, warnings []string) PatchValidation {
	res := PatchValidation{
		Validator: "java_structural",
		Warnings:  warnings,
	}
	stripped, issues := scanCStyleCode(code, false)
	if len(issues) > 0 {
		res.Issues = append(res.Issues, issues...)
	}
	if !javaTypeDeclRe.MatchString(stripped) {
		res.Issues = append(res.Issues, "Java source is missing a class/interface/enum/record declaration")
	}
	if !strings.Contains(stripped, "{") || !strings.Contains(stripped, "}") {
		res.Issues = append(res.Issues, "Java source is missing a class body block '{ ... }'")
	}
	res.Passed = len(res.Issues) == 0
	return res
}

// scanCStyleCode strips comments and string/char literals from Java or JS code
// while checking balanced {}, (), [] delimiters outside strings and comments.
func scanCStyleCode(code string, allowBacktickTemplates bool) (stripped string, issues []string) {
	type frame struct {
		ch   byte
		line int
	}
	var stack []frame
	var out strings.Builder
	out.Grow(len(code))

	line := 1
	n := len(code)
	for i := 0; i < n; {
		ch := code[i]
		if ch == '\n' {
			line++
			out.WriteByte('\n')
			i++
			continue
		}
		// Single-line comment //
		if ch == '/' && i+1 < n && code[i+1] == '/' {
			i += 2
			for i < n && code[i] != '\n' {
				i++
			}
			out.WriteByte(' ')
			continue
		}
		// Block comment /* ... */
		if ch == '/' && i+1 < n && code[i+1] == '*' {
			startLine := line
			i += 2
			closed := false
			for i < n {
				if code[i] == '\n' {
					line++
				}
				if code[i] == '*' && i+1 < n && code[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				issues = append(issues, fmt.Sprintf("unterminated block comment starting at line %d", startLine))
				return out.String(), issues
			}
			out.WriteByte(' ')
			continue
		}
		// Java text block """..."""
		if !allowBacktickTemplates && ch == '"' && i+2 < n && code[i+1] == '"' && code[i+2] == '"' {
			startLine := line
			i += 3
			closed := false
			for i < n {
				if code[i] == '\\' {
					if i+1 < n && code[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if code[i] == '\n' {
					line++
					i++
					continue
				}
				if code[i] == '"' && i+2 < n && code[i+1] == '"' && code[i+2] == '"' {
					i += 3
					closed = true
					break
				}
				i++
			}
			if !closed {
				issues = append(issues, fmt.Sprintf("unterminated Java text block starting at line %d", startLine))
				return out.String(), issues
			}
			out.WriteByte(' ')
			continue
		}
		// JS template literal `...`
		if allowBacktickTemplates && ch == '`' {
			startLine := line
			i++
			closed := false
			for i < n {
				if code[i] == '\\' {
					if i+1 < n && code[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if code[i] == '\n' {
					line++
					i++
					continue
				}
				if code[i] == '`' {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				issues = append(issues, fmt.Sprintf("unterminated template literal starting at line %d", startLine))
				return out.String(), issues
			}
			out.WriteByte(' ')
			continue
		}
		// Double-quoted or single-quoted string/char literal.
		if ch == '"' || ch == '\'' {
			quote := ch
			startLine := line
			i++
			closed := false
			for i < n {
				if code[i] == '\\' {
					i += 2
					continue
				}
				if code[i] == '\n' {
					break
				}
				if code[i] == quote {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				issues = append(issues, fmt.Sprintf("unterminated %c literal at line %d", quote, startLine))
				return out.String(), issues
			}
			out.WriteByte(' ')
			continue
		}

		out.WriteByte(ch)
		switch ch {
		case '{', '(', '[':
			stack = append(stack, frame{ch: ch, line: line})
		case '}', ')', ']':
			if len(stack) == 0 || !matchingDelimiter(stack[len(stack)-1].ch, ch) {
				issues = append(issues, fmt.Sprintf("unmatched closing '%c' at line %d", ch, line))
				return out.String(), issues
			}
			stack = stack[:len(stack)-1]
		}
		i++
	}

	if len(stack) > 0 {
		top := stack[len(stack)-1]
		issues = append(issues, fmt.Sprintf("unclosed '%c' opened at line %d", top.ch, top.line))
	}
	return out.String(), issues
}

func matchingDelimiter(open, closeCh byte) bool {
	return (open == '{' && closeCh == '}') ||
		(open == '(' && closeCh == ')') ||
		(open == '[' && closeCh == ']')
}

// SanitizeConfigChanges filters proposed configuration changes strictly against
// cap's safe settings allowlist and rejects empty or control-character values.
func SanitizeConfigChanges(changes map[string]string) map[string]string {
	if len(changes) == 0 {
		return nil
	}
	clean := make(map[string]string)
	for rawKey, rawVal := range changes {
		key := strings.TrimSpace(rawKey)
		if _, allowed := allowedConfigKeys[key]; !allowed {
			continue
		}
		val := strings.TrimSpace(rawVal)
		if val == "" || strings.ContainsAny(val, "\r\n\x00") {
			continue
		}
		switch key {
		case "frida_default_port":
			port, err := strconv.Atoi(val)
			if err != nil || port < 1 || port > 65535 {
				continue
			}
		case "gateway_addr", "proxy_addr":
			if strings.ContainsAny(val, " \t") {
				continue
			}
		}
		clean[key] = val
	}
	if len(clean) == 0 {
		return nil
	}
	return clean
}

func normalizeCodeForCompare(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
}
