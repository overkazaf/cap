package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

const (
	RuntimeBuiltin = "builtin"
	RuntimePython3 = "python3"
	RuntimeNode    = "node"
	RuntimeShell   = "sh"

	defaultTimeoutSec    = 10
	minTimeoutSec        = 1
	maxTimeoutSec        = 60
	maxScriptOutputBytes = 64 * 1024
)

// scriptFlowPayload is the clean, deterministic JSON object passed to external
// script runtimes (python3 / node / sh) on stdin.
type scriptFlowPayload struct {
	ID          string            `json:"id"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Scheme      string            `json:"scheme"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	Query       string            `json:"query"`
	QueryParams map[string]string `json:"query_params"`
	Status      int               `json:"status"`
	LatencyMs   int64             `json:"latency_ms"`
	ReqHeaders  map[string]string `json:"req_headers"`
	RespHeaders map[string]string `json:"resp_headers"`
	ReqBody     string            `json:"req_body"`
	RespBody    string            `json:"resp_body"`
	SignParams  []string          `json:"sign_params"`
}

// normalizeRuntime canonicalizes a plugin runtime identifier.
func normalizeRuntime(rt string) string {
	switch strings.ToLower(strings.TrimSpace(rt)) {
	case "", RuntimeBuiltin:
		return RuntimeBuiltin
	case RuntimePython3, "python":
		return RuntimePython3
	case RuntimeNode, "nodejs", "js", "javascript":
		return RuntimeNode
	case RuntimeShell, "bash", "shell":
		return RuntimeShell
	default:
		return strings.ToLower(strings.TrimSpace(rt))
	}
}

func clampTimeout(sec int) time.Duration {
	if sec <= 0 {
		return time.Duration(defaultTimeoutSec) * time.Second
	}
	if sec < minTimeoutSec {
		sec = minTimeoutSec
	}
	if sec > maxTimeoutSec {
		sec = maxTimeoutSec
	}
	return time.Duration(sec) * time.Second
}

// MatchesFlow reports whether flow satisfies plugin p's Method, HostPattern,
// and PathPattern criteria.
//   - Empty patterns (or "*") match everything.
//   - Patterns wrapped in `/.../` are evaluated as regular expressions (invalid
//     regexes return false without panicking).
//   - Patterns containing `*` use URL-friendly case-insensitive glob matching
//     where ONLY `*` expands to `.*` and `?` matches a literal `?` (so URL
//     query strings like `/v1/items?type=*` work naturally). Path globs without
//     a leading `/` or `*` also accept an optional leading `/`.
//   - All other patterns use case-insensitive substring matching.
//
// HostPattern is tested against both raw host (with optional `:port`) and
// port-stripped hostname. PathPattern is tested against both the bare path and
// the full path+query (`RequestURI`).
func MatchesFlow(p *Plugin, f *types.Flow) bool {
	if p == nil || f == nil {
		return false
	}
	if m := strings.TrimSpace(p.Method); m != "" && !strings.EqualFold(m, "ANY") {
		if !strings.EqualFold(f.Method, m) {
			return false
		}
	}

	rawHost := f.Host
	hostNoPort := ""
	pathOnly := f.Path
	pathWithQuery := ""

	if f.URL != "" {
		if u, err := url.Parse(f.URL); err == nil {
			if rawHost == "" {
				rawHost = u.Host
			}
			hostNoPort = u.Hostname()
			if pathOnly == "" {
				pathOnly = u.Path
			}
			reqURI := u.RequestURI()
			if reqURI != "" {
				pathWithQuery = reqURI
			}
		}
	}

	if hostNoPort == "" && rawHost != "" {
		if h, _, err := net.SplitHostPort(rawHost); err == nil {
			hostNoPort = h
		} else {
			hostNoPort = strings.Trim(rawHost, "[]")
		}
	}

	if idx := strings.IndexByte(pathOnly, '?'); idx >= 0 {
		if pathWithQuery == "" {
			pathWithQuery = pathOnly
		}
		pathOnly = pathOnly[:idx]
	}

	hostMatched := matchPattern(p.HostPattern, rawHost, false) ||
		(hostNoPort != "" && hostNoPort != rawHost && matchPattern(p.HostPattern, hostNoPort, false))
	if !hostMatched {
		return false
	}

	pathMatched := matchPattern(p.PathPattern, pathOnly, true) ||
		(pathWithQuery != "" && pathWithQuery != pathOnly && matchPattern(p.PathPattern, pathWithQuery, true))
	if !pathMatched {
		return false
	}
	return true
}

func matchPattern(pattern, target string, allowOptLeadingSlash bool) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}

	// Regex syntax: /pattern/
	if len(pattern) >= 2 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		expr := pattern[1 : len(pattern)-1]
		re, err := regexp.Compile(expr)
		if err != nil {
			return false
		}
		return re.MatchString(target)
	}

	// URL-friendly wildcard syntax: only '*' expands to '.*'; '?' is treated
	// literally so URL query strings like `/v1/url?album=*` match properly.
	if strings.Contains(pattern, "*") {
		var b strings.Builder
		b.WriteString("(?i)^")
		if allowOptLeadingSlash && !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "*") {
			b.WriteString("/?")
		}
		parts := strings.Split(pattern, "*")
		for i, part := range parts {
			if i > 0 {
				b.WriteString(".*")
			}
			b.WriteString(regexp.QuoteMeta(part))
		}
		b.WriteString("$")
		re, err := regexp.Compile(b.String())
		if err != nil {
			return false
		}
		return re.MatchString(target)
	}

	// Plain case-insensitive substring match
	return strings.Contains(strings.ToLower(target), strings.ToLower(pattern))
}

func buildScriptPayloadStruct(f *types.Flow) scriptFlowPayload {
	if f == nil {
		f = &types.Flow{}
	}
	scheme := ""
	host := f.Host
	path := f.Path
	rawQuery := ""
	queryParams := map[string]string{}

	if f.URL != "" {
		if u, err := url.Parse(f.URL); err == nil {
			scheme = u.Scheme
			if host == "" {
				host = u.Host
			}
			if path == "" {
				path = u.Path
			}
			rawQuery = u.RawQuery
			for k, vals := range u.Query() {
				if len(vals) > 0 {
					queryParams[k] = vals[0]
				} else {
					queryParams[k] = ""
				}
			}
		}
	}
	if rawQuery == "" {
		if idx := strings.IndexByte(path, '?'); idx >= 0 {
			rawQuery = path[idx+1:]
			path = path[:idx]
			if parsed, err := url.ParseQuery(rawQuery); err == nil {
				for k, vals := range parsed {
					if len(vals) > 0 {
						queryParams[k] = vals[0]
					} else {
						queryParams[k] = ""
					}
				}
			}
		}
	}

	reqHeaders := f.ReqHeaders
	if reqHeaders == nil {
		reqHeaders = map[string]string{}
	}
	respHeaders := f.RespHeaders
	if respHeaders == nil {
		respHeaders = map[string]string{}
	}
	signParams := f.SignParams
	if signParams == nil {
		signParams = []string{}
	}

	return scriptFlowPayload{
		ID:          f.ID,
		Method:      f.Method,
		URL:         f.URL,
		Scheme:      scheme,
		Host:        host,
		Path:        path,
		Query:       rawQuery,
		QueryParams: queryParams,
		Status:      f.Status,
		LatencyMs:   f.LatencyMs,
		ReqHeaders:  reqHeaders,
		RespHeaders: respHeaders,
		ReqBody:     string(f.ReqBody),
		RespBody:    string(f.RespBody),
		SignParams:  signParams,
	}
}

func buildScriptPayload(f *types.Flow) ([]byte, error) {
	return json.Marshal(buildScriptPayloadStruct(f))
}

// BuildFlowPayloadJSON returns the exact pretty-printed JSON payload that
// external plugin script runtimes (python3 / node / sh) receive on stdin for f,
// including parsed query and query_params fields.
func BuildFlowPayloadJSON(f *types.Flow) ([]byte, error) {
	return json.MarshalIndent(buildScriptPayloadStruct(f), "", "  ")
}

// limitedBuffer caps captured bytes so runaway scripts cannot exhaust memory.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	origLen := len(p)
	if l.limit <= 0 {
		return origLen, nil
	}
	rem := l.limit - l.buf.Len()
	if rem <= 0 {
		l.truncated = true
		return origLen, nil
	}
	if len(p) > rem {
		l.buf.Write(p[:rem])
		l.truncated = true
		return origLen, nil
	}
	l.buf.Write(p)
	return origLen, nil
}

func (l *limitedBuffer) String() string {
	s := l.buf.String()
	if l.truncated {
		s += "\n... (output truncated at 64 KiB)"
	}
	return s
}

func runtimeSpec(rt string) (interp string, ext string, err error) {
	switch normalizeRuntime(rt) {
	case RuntimePython3:
		return "python3", ".py", nil
	case RuntimeNode:
		return "node", ".js", nil
	case RuntimeShell:
		return "sh", ".sh", nil
	default:
		return "", "", fmt.Errorf("unsupported plugin runtime %q", rt)
	}
}

func runScript(ctx context.Context, p *Plugin, flow *types.Flow) *ExecResult {
	if ctx == nil {
		ctx = context.Background()
	}
	interp, ext, err := runtimeSpec(p.Runtime)
	if err != nil {
		return &ExecResult{Error: err.Error()}
	}
	interpPath, err := exec.LookPath(interp)
	if err != nil {
		return &ExecResult{Error: fmt.Sprintf("runtime %q not found on PATH: %v", interp, err)}
	}

	tmpFile, err := os.CreateTemp("", "cap-plugin-*"+ext)
	if err != nil {
		return &ExecResult{Error: fmt.Sprintf("create temp script: %v", err)}
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		return &ExecResult{Error: fmt.Sprintf("chmod temp script: %v", err)}
	}
	if _, err := tmpFile.WriteString(p.Code); err != nil {
		tmpFile.Close()
		return &ExecResult{Error: fmt.Sprintf("write temp script: %v", err)}
	}
	if err := tmpFile.Close(); err != nil {
		return &ExecResult{Error: fmt.Sprintf("close temp script: %v", err)}
	}

	stdinBytes, err := buildScriptPayload(flow)
	if err != nil {
		return &ExecResult{Error: fmt.Sprintf("marshal flow payload: %v", err)}
	}

	timeout := clampTimeout(p.TimeoutSec)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, interpPath, tmpPath)
	configureScriptCmd(cmd)
	cmd.Stdin = bytes.NewReader(stdinBytes)

	stdout := &limitedBuffer{limit: maxScriptOutputBytes}
	stderr := &limitedBuffer{limit: maxScriptOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()

	outStr := strings.TrimRight(stdout.String(), "\r\n")
	errStr := strings.TrimRight(stderr.String(), "\r\n")

	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			msg := fmt.Sprintf("script timed out after %s", timeout)
			if errStr != "" {
				msg += ": " + errStr
			}
			return &ExecResult{Output: outStr, Error: msg}
		}
		if ctx.Err() != nil {
			return &ExecResult{Output: outStr, Error: fmt.Sprintf("script cancelled: %v", ctx.Err())}
		}
		msg := runErr.Error()
		if errStr != "" {
			msg = errStr + " (" + msg + ")"
		}
		return &ExecResult{Output: outStr, Error: msg}
	}

	if errStr != "" {
		if outStr != "" {
			outStr += "\n[stderr]\n" + errStr
		} else {
			outStr = "[stderr]\n" + errStr
		}
	}
	return &ExecResult{Output: outStr}
}
