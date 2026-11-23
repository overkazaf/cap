package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

const maxExecutionLogs = 200

type Plugin struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Code        string `json:"code"`
	Enabled     bool   `json:"enabled"`
	Type        string `json:"type"` // "request_filter", "response_modifier", "analyzer"
	Runtime     string `json:"runtime,omitempty"`      // ""|"builtin"|"python3"|"node"|"sh"
	AutoRun     bool   `json:"auto_run,omitempty"`     // auto-execute on matching live flows
	HostPattern string `json:"host_pattern,omitempty"` // substring, glob '*', or /regex/
	PathPattern string `json:"path_pattern,omitempty"` // substring, glob '*', or /regex/
	Method      string `json:"method,omitempty"`       // "" = any, or GET/POST/...
	TimeoutSec  int    `json:"timeout_sec,omitempty"`  // default 10s, clamped 1..60s
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// ExecutionRecord captures one plugin execution (auto-run on live traffic or
// manual test run) for the bounded in-memory log and live GUI stream.
type ExecutionRecord struct {
	ID         string `json:"id"`
	PluginName string `json:"plugin_name"`
	Runtime    string `json:"runtime"`
	FlowID     string `json:"flow_id"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Output     string `json:"output"`
	Error      string `json:"error"`
	DurationMs int64  `json:"duration_ms"`
	Timestamp  string `json:"timestamp"`
	Trigger    string `json:"trigger"` // "auto" or "manual"
}

type Engine struct {
	dir      string
	plugins  map[string]*Plugin
	dirStamp string
	mu       sync.RWMutex

	logMu   sync.RWMutex
	logs    []ExecutionRecord
	execSeq atomic.Int64
}

var ErrEmptyName = errors.New("plugin: name is required")

func NewEngine(dir string) (*Engine, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("plugin: create directory: %w", err)
	}
	e := &Engine{dir: dir, plugins: make(map[string]*Plugin)}
	return e, e.loadAll()
}

// Dir returns the local directory where plugin *.json files are stored.
func (e *Engine) Dir() string {
	return e.dir
}

// Reload re-reads all *.json plugin files from e.dir under a write lock so
// locally created or edited plugins take effect without restarting cap.
func (e *Engine) Reload() error {
	stamp := computeDirStamp(e.dir)
	loaded, err := readPluginsDir(e.dir)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.plugins = loaded
	e.dirStamp = stamp
	e.mu.Unlock()
	return nil
}

func (e *Engine) loadAll() error {
	stamp := computeDirStamp(e.dir)
	loaded, err := readPluginsDir(e.dir)
	if err != nil {
		return err
	}
	e.plugins = loaded
	e.dirStamp = stamp
	return nil
}

// maybeReloadFromDisk performs a cheap directory stat fingerprint check and
// hot-reloads e.dir whenever local *.json files have been added, modified, or
// removed on disk.
func (e *Engine) maybeReloadFromDisk() {
	stamp := computeDirStamp(e.dir)
	e.mu.RLock()
	unchanged := stamp == e.dirStamp
	e.mu.RUnlock()
	if unchanged {
		return
	}
	loaded, err := readPluginsDir(e.dir)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.plugins = loaded
	e.dirStamp = stamp
	e.mu.Unlock()
}

func computeDirStamp(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", entry.Name(), info.Size(), info.ModTime().UnixNano())
	}
	return b.String()
}

func readPluginsDir(dir string) (map[string]*Plugin, error) {
	out := make(map[string]*Plugin)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, nil
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var p Plugin
		if json.Unmarshal(data, &p) == nil && strings.TrimSpace(p.Name) != "" {
			key := sanitizeName(p.Name)
			if existing, exists := out[key]; exists && existing.Name != p.Name {
				return nil, fmt.Errorf("plugin: %q collides with %q on disk", p.Name, existing.Name)
			}
			stored := p
			out[key] = &stored
		}
	}
	return out, nil
}

func (e *Engine) List() []*Plugin {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Plugin, 0, len(e.plugins))
	for key, p := range e.plugins {
		result = append(result, clonePlugin(p, key))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (e *Engine) Get(name string) (*Plugin, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	key := sanitizeName(name)
	p, ok := e.plugins[key]
	if !ok {
		return nil, fmt.Errorf("plugin %q not found", name)
	}
	return clonePlugin(p, key), nil
}

func (e *Engine) Save(p *Plugin) error {
	if p == nil {
		return errors.New("plugin: Save: plugin is nil")
	}
	if strings.TrimSpace(p.Name) == "" {
		return ErrEmptyName
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	key := sanitizeName(p.Name)
	if existing, exists := e.plugins[key]; exists && existing.Name != p.Name {
		return fmt.Errorf("plugin: %q collides with %q on disk", p.Name, existing.Name)
	}

	stored := clonePlugin(p, key)
	now := time.Now().Format(time.RFC3339)
	if stored.CreatedAt == "" {
		stored.CreatedAt = now
	}
	stored.UpdatedAt = now

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}

	filename := key + ".json"
	if err := os.WriteFile(filepath.Join(e.dir, filename), data, 0644); err != nil {
		return err
	}

	e.plugins[key] = stored
	e.dirStamp = computeDirStamp(e.dir)
	return nil
}

func (e *Engine) Delete(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := sanitizeName(name)
	filename := key + ".json"
	os.Remove(filepath.Join(e.dir, filename))
	delete(e.plugins, key)
	e.dirStamp = computeDirStamp(e.dir)
	return nil
}

func (e *Engine) Toggle(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := sanitizeName(name)
	p, ok := e.plugins[key]
	if !ok {
		return fmt.Errorf("plugin %q not found", name)
	}

	toggled := clonePlugin(p, key)
	toggled.Enabled = !toggled.Enabled
	toggled.UpdatedAt = time.Now().Format(time.RFC3339)
	data, err := json.MarshalIndent(toggled, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(e.dir, key+".json"), data, 0644); err != nil {
		return err
	}
	e.plugins[key] = toggled
	e.dirStamp = computeDirStamp(e.dir)
	return nil
}

type ExecResult struct {
	Output string `json:"output"`
	Error  string `json:"error"`
}

func (e *Engine) RunAnalyzer(name string, flow *types.Flow) *ExecResult {
	return e.RunAnalyzerContext(context.Background(), name, flow)
}

// RunAnalyzerContext executes a single named plugin (built-in or script
// runtime) against flow, recording EVERY execution (including disabled or
// missing plugin errors) in the engine's log buffer.
func (e *Engine) RunAnalyzerContext(ctx context.Context, name string, flow *types.Flow) *ExecResult {
	e.maybeReloadFromDisk()

	e.mu.RLock()
	key := sanitizeName(name)
	orig, ok := e.plugins[key]
	var p *Plugin
	if ok {
		p = clonePlugin(orig, key)
	}
	e.mu.RUnlock()

	if flow == nil {
		flow = &types.Flow{}
	}

	if !ok {
		errMsg := fmt.Sprintf("plugin %q not found", name)
		e.RecordExecution(ExecutionRecord{
			ID:         fmt.Sprintf("px-%d", e.execSeq.Add(1)),
			PluginName: name,
			Runtime:    RuntimeBuiltin,
			FlowID:     flow.ID,
			Method:     flow.Method,
			URL:        flow.URL,
			Status:     flow.Status,
			Error:      errMsg,
			Timestamp:  time.Now().Format(time.RFC3339),
			Trigger:    "manual",
		})
		return &ExecResult{Error: errMsg}
	}
	if !p.Enabled {
		errMsg := fmt.Sprintf("plugin %q is disabled", name)
		e.RecordExecution(ExecutionRecord{
			ID:         fmt.Sprintf("px-%d", e.execSeq.Add(1)),
			PluginName: p.Name,
			Runtime:    normalizeRuntime(p.Runtime),
			FlowID:     flow.ID,
			Method:     flow.Method,
			URL:        flow.URL,
			Status:     flow.Status,
			Error:      errMsg,
			Timestamp:  time.Now().Format(time.RFC3339),
			Trigger:    "manual",
		})
		return &ExecResult{Error: errMsg}
	}

	res, rec := e.executePlugin(ctx, p, flow, "manual")
	e.RecordExecution(rec)
	return res
}

// RunDraftContext executes an unsaved/in-memory Plugin draft against flow
// (even when p.Enabled is false), records a "manual" ExecutionRecord with a
// non-empty ID in the engine's log ring buffer, and returns both the ExecResult
// and the recorded ExecutionRecord.
func (e *Engine) RunDraftContext(ctx context.Context, p *Plugin, flow *types.Flow) (*ExecResult, ExecutionRecord) {
	if flow == nil {
		flow = &types.Flow{}
	}
	if p == nil {
		errMsg := "plugin draft is nil"
		rec := ExecutionRecord{
			ID:         fmt.Sprintf("px-%d", e.execSeq.Add(1)),
			PluginName: "draft",
			Runtime:    RuntimeBuiltin,
			FlowID:     flow.ID,
			Method:     flow.Method,
			URL:        flow.URL,
			Status:     flow.Status,
			Error:      errMsg,
			Timestamp:  time.Now().Format(time.RFC3339),
			Trigger:    "manual",
		}
		e.RecordExecution(rec)
		return &ExecResult{Error: errMsg}, rec
	}

	draft := clonePlugin(p, "draft")
	if strings.TrimSpace(draft.Name) == "" {
		draft.Name = "draft"
	}
	res, rec := e.executePlugin(ctx, draft, flow, "manual")
	e.RecordExecution(rec)
	return res, rec
}

// RunMatching finds all Enabled && AutoRun plugins whose filters match f,
// automatically reloading disk edits in e.dir if changed, executes each one
// respecting ctx, records every ExecutionRecord into the bounded log ring
// buffer, and returns the records in deterministic name order.
func (e *Engine) RunMatching(ctx context.Context, f *types.Flow) []ExecutionRecord {
	if f == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	e.maybeReloadFromDisk()

	e.mu.RLock()
	var matched []*Plugin
	for key, p := range e.plugins {
		if p.Enabled && p.AutoRun && MatchesFlow(p, f) {
			matched = append(matched, clonePlugin(p, key))
		}
	}
	e.mu.RUnlock()

	if len(matched) == 0 {
		return nil
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })

	records := make([]ExecutionRecord, 0, len(matched))
	for _, p := range matched {
		if ctx.Err() != nil {
			break
		}
		_, rec := e.executePlugin(ctx, p, f, "auto")
		e.RecordExecution(rec)
		records = append(records, rec)
	}
	return records
}

func (e *Engine) executePlugin(ctx context.Context, p *Plugin, flow *types.Flow, trigger string) (*ExecResult, ExecutionRecord) {
	if flow == nil {
		flow = &types.Flow{}
	}
	rt := normalizeRuntime(p.Runtime)
	start := time.Now()

	var res *ExecResult
	if rt == RuntimeBuiltin {
		res = runBuiltin(p, flow)
	} else {
		res = runScript(ctx, p, flow)
	}
	if res == nil {
		res = &ExecResult{}
	}

	rec := ExecutionRecord{
		ID:         fmt.Sprintf("px-%d", e.execSeq.Add(1)),
		PluginName: p.Name,
		Runtime:    rt,
		FlowID:     flow.ID,
		Method:     flow.Method,
		URL:        flow.URL,
		Status:     flow.Status,
		Output:     res.Output,
		Error:      res.Error,
		DurationMs: time.Since(start).Milliseconds(),
		Timestamp:  start.Format(time.RFC3339),
		Trigger:    trigger,
	}
	return res, rec
}

// RecordExecution appends rec into the engine's bounded ring buffer (capped at
// maxExecutionLogs entries).
func (e *Engine) RecordExecution(rec ExecutionRecord) {
	if rec.ID == "" {
		rec.ID = fmt.Sprintf("px-%d", e.execSeq.Add(1))
	}
	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().Format(time.RFC3339)
	}
	e.logMu.Lock()
	e.logs = append(e.logs, rec)
	if len(e.logs) > maxExecutionLogs {
		excess := len(e.logs) - maxExecutionLogs
		e.logs = append([]ExecutionRecord(nil), e.logs[excess:]...)
	}
	e.logMu.Unlock()
}

// Logs returns up to limit most recent ExecutionRecords (newest first).
// limit <= 0 returns all retained records.
func (e *Engine) Logs(limit int) []ExecutionRecord {
	e.logMu.RLock()
	defer e.logMu.RUnlock()

	n := len(e.logs)
	if n == 0 {
		return []ExecutionRecord{}
	}
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]ExecutionRecord, n)
	for i := 0; i < n; i++ {
		out[i] = e.logs[len(e.logs)-1-i]
	}
	return out
}

// ClearLogs empties the in-memory execution log buffer.
func (e *Engine) ClearLogs() {
	e.logMu.Lock()
	e.logs = nil
	e.logMu.Unlock()
}

func runBuiltin(p *Plugin, flow *types.Flow) *ExecResult {
	switch p.Type {
	case "request_filter":
		return runRequestFilter(p, flow)
	case "analyzer":
		return runAnalyzer(p, flow)
	case "response_modifier":
		return runResponseAnalysis(p, flow)
	default:
		flowJSON, _ := json.MarshalIndent(flow, "", "  ")
		return &ExecResult{Output: fmt.Sprintf("Plugin: %s\n%s", p.Name, string(flowJSON))}
	}
}

func clonePlugin(p *Plugin, name string) *Plugin {
	clone := *p
	if clone.Name == "" {
		clone.Name = name
	}
	return &clone
}

func runRequestFilter(p *Plugin, flow *types.Flow) *ExecResult {
	var lines []string
	lines = append(lines, fmt.Sprintf("[%s] %s %s → %d", flow.ID, flow.Method, flow.URL, flow.Status))

	if len(flow.ReqBody) > 0 {
		body := string(flow.ReqBody)
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		lines = append(lines, fmt.Sprintf("  Body (%d bytes): %s", len(flow.ReqBody), body))
	}

	for k, v := range flow.ReqHeaders {
		if strings.Contains(strings.ToLower(k), "auth") || strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "cookie") {
			lines = append(lines, fmt.Sprintf("  🔑 %s: %s", k, v))
		}
	}

	return &ExecResult{Output: strings.Join(lines, "\n")}
}

func runAnalyzer(p *Plugin, flow *types.Flow) *ExecResult {
	var findings []string

	// Check headers for sensitive data
	for k, v := range flow.ReqHeaders {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "api") && strings.Contains(kl, "key") {
			findings = append(findings, fmt.Sprintf("🔐 API Key in header: %s = %s", k, truncate(v, 30)))
		}
		if strings.Contains(kl, "authorization") {
			findings = append(findings, fmt.Sprintf("🔐 Auth header: %s = %s", k, truncate(v, 40)))
		}
		if strings.Contains(kl, "token") {
			findings = append(findings, fmt.Sprintf("🔐 Token in header: %s = %s", k, truncate(v, 30)))
		}
	}

	// Check URL for sensitive params
	if strings.Contains(flow.URL, "key=") || strings.Contains(flow.URL, "token=") || strings.Contains(flow.URL, "secret=") {
		findings = append(findings, fmt.Sprintf("⚠ Sensitive param in URL: %s", truncate(flow.URL, 80)))
	}

	// Check sign params
	if len(flow.SignParams) > 0 {
		findings = append(findings, fmt.Sprintf("🔍 Sign params detected: %s", strings.Join(flow.SignParams, ", ")))
	}

	// Check body for patterns
	body := string(flow.ReqBody)
	if strings.Contains(body, "password") || strings.Contains(body, "passwd") {
		findings = append(findings, "⚠ Password field in request body")
	}
	if strings.Contains(body, "credit") || strings.Contains(body, "card_number") {
		findings = append(findings, "🚨 Payment data in request body")
	}

	if len(findings) == 0 {
		return &ExecResult{Output: fmt.Sprintf("[%s] No sensitive data found", flow.ID)}
	}
	return &ExecResult{Output: fmt.Sprintf("[%s] %d finding(s):\n%s", flow.ID, len(findings), strings.Join(findings, "\n"))}
}

func runResponseAnalysis(p *Plugin, flow *types.Flow) *ExecResult {
	var lines []string
	lines = append(lines, fmt.Sprintf("[%s] Response: %d (%dms)", flow.ID, flow.Status, flow.LatencyMs))

	respBody := string(flow.RespBody)
	if len(respBody) > 0 {
		// Check for common response patterns
		if strings.Contains(respBody, "error") || strings.Contains(respBody, "Error") {
			lines = append(lines, "  ⚠ Response contains error")
		}
		if strings.Contains(respBody, "token") || strings.Contains(respBody, "jwt") {
			lines = append(lines, "  🔑 Response contains token/JWT")
		}
		if strings.Contains(respBody, "session") {
			lines = append(lines, "  🔑 Response contains session data")
		}
		lines = append(lines, fmt.Sprintf("  Size: %d bytes, Type: %s", len(flow.RespBody), flow.RespBodyType))
	}

	return &ExecResult{Output: strings.Join(lines, "\n")}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func sanitizeName(name string) string {
	r := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ".", "-")
	return strings.ToLower(r.Replace(name))
}

var ExamplePlugins = []Plugin{
	{
		Name:        "log-requests",
		Description: "Log all POST requests with their body",
		Type:        "request_filter",
		Runtime:     RuntimeBuiltin,
		Enabled:     false,
		Code: `// Plugin: log-requests
// Type: request_filter
// Runs for each captured request

function onRequest(flow) {
  if (flow.method !== "POST") return;

  console.log("[" + flow.id + "] POST " + flow.url);

  if (flow.req_body) {
    try {
      const body = JSON.parse(flow.req_body);
      console.log("  Body:", JSON.stringify(body, null, 2));
    } catch(e) {
      console.log("  Body (raw):", flow.req_body.substring(0, 200));
    }
  }

  // Return modified flow or null to keep original
  return null;
}`,
	},
	{
		Name:        "detect-api-keys",
		Description: "Flag requests that contain API keys or tokens in headers",
		Type:        "analyzer",
		Runtime:     RuntimeBuiltin,
		Enabled:     false,
		Code: `// Plugin: detect-api-keys
// Type: analyzer
// Scans request headers for sensitive data

const SENSITIVE_PATTERNS = [
  /api[_-]?key/i,
  /auth(orization)?/i,
  /token/i,
  /secret/i,
  /password/i,
  /x-api-key/i,
];

function analyze(flow) {
  const findings = [];

  for (const [key, value] of Object.entries(flow.req_headers || {})) {
    for (const pattern of SENSITIVE_PATTERNS) {
      if (pattern.test(key)) {
        findings.push({
          header: key,
          value: value.substring(0, 20) + "...",
          risk: "sensitive_header"
        });
      }
    }
  }

  return {
    flow_id: flow.id,
    findings: findings,
    summary: findings.length > 0
      ? findings.length + " sensitive header(s) found"
      : "No sensitive headers detected"
  };
}`,
	},
	{
		Name:        "sign-validator",
		Description: "Validate sign parameter by replaying with different timestamp",
		Type:        "analyzer",
		Runtime:     RuntimeBuiltin,
		Enabled:     false,
		Code: `// Plugin: sign-validator
// Type: analyzer
// Checks if sign changes when timestamp changes

function analyze(flow) {
  const url = new URL(flow.url);
  const params = Object.fromEntries(url.searchParams);

  const signKeys = Object.keys(params).filter(k =>
    /^(sign|signature|hash|hmac|digest)$/i.test(k)
  );

  const tsKeys = Object.keys(params).filter(k =>
    /^(ts|timestamp|time|_t|t)$/i.test(k)
  );

  if (signKeys.length === 0) {
    return { result: "no sign parameter found" };
  }

  return {
    sign_param: signKeys[0],
    sign_value: params[signKeys[0]],
    sign_length: params[signKeys[0]].length,
    ts_param: tsKeys[0] || "none",
    ts_value: tsKeys[0] ? params[tsKeys[0]] : "N/A",
    hint: "Compare sign values across requests with different timestamps"
  };
}`,
	},
	{
		Name:        "python-flow-inspector",
		Description: "Python 3 script reading captured flow JSON from stdin and logging API latency & payload keys",
		Type:        "analyzer",
		Runtime:     RuntimePython3,
		AutoRun:     false,
		PathPattern: "/api/*",
		TimeoutSec:  10,
		Enabled:     false,
		Code: `import json
import sys

flow = json.load(sys.stdin)
summary = {
    "flow_id": flow.get("id"),
    "method": flow.get("method"),
    "host": flow.get("host"),
    "path": flow.get("path"),
    "status": flow.get("status"),
    "latency_ms": flow.get("latency_ms"),
    "slow": (flow.get("latency_ms") or 0) >= 500,
}

resp_body = flow.get("resp_body") or ""
try:
    parsed = json.loads(resp_body)
    if isinstance(parsed, dict):
        summary["resp_keys"] = sorted(parsed.keys())[:20]
    elif isinstance(parsed, list):
        summary["resp_items"] = len(parsed)
except Exception:
    summary["resp_bytes"] = len(resp_body)

print(json.dumps(summary, ensure_ascii=False, indent=2))
`,
	},
	{
		Name:        "node-local-webhook",
		Description: "Node.js script forwarding a compact JSON flow summary to a local webhook endpoint",
		Type:        "analyzer",
		Runtime:     RuntimeNode,
		AutoRun:     false,
		Method:      "POST",
		PathPattern: "/api/*",
		TimeoutSec:  10,
		Enabled:     false,
		Code: `const fs = require("fs");
const http = require("http");

const flow = JSON.parse(fs.readFileSync(0, "utf8"));
const payload = JSON.stringify({
  id: flow.id,
  method: flow.method,
  url: flow.url,
  status: flow.status,
  latency_ms: flow.latency_ms,
});

// Replace with your local collector or webhook receiver:
const WEBHOOK_URL = process.env.CAP_WEBHOOK_URL || "http://127.0.0.1:9000/hook";
console.log("Prepared payload for " + WEBHOOK_URL + ":\n" + payload);

if (process.env.CAP_WEBHOOK_SEND === "1") {
  const u = new URL(WEBHOOK_URL);
  const req = http.request(
    {
      hostname: u.hostname,
      port: u.port || 80,
      path: u.pathname + u.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
      timeout: 3000,
    },
    (res) => console.log("Webhook status:", res.statusCode)
  );
  req.on("error", (err) => console.error("Webhook error:", err.message));
  req.write(payload);
  req.end();
}
`,
	},
}
