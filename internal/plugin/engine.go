package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

type Plugin struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Code        string `json:"code"`
	Enabled     bool   `json:"enabled"`
	Type        string `json:"type"` // "request_filter", "response_modifier", "analyzer"
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type Engine struct {
	dir     string
	plugins map[string]*Plugin
	mu      sync.RWMutex
}

func NewEngine(dir string) (*Engine, error) {
	os.MkdirAll(dir, 0755)
	e := &Engine{dir: dir, plugins: make(map[string]*Plugin)}
	return e, e.loadAll()
}

func (e *Engine) loadAll() error {
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(e.dir, entry.Name()))
		if err != nil {
			continue
		}
		var p Plugin
		if json.Unmarshal(data, &p) == nil && p.Name != "" {
			e.plugins[p.Name] = &p
		}
	}
	return nil
}

func (e *Engine) List() []*Plugin {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*Plugin, 0, len(e.plugins))
	for _, p := range e.plugins {
		result = append(result, p)
	}
	return result
}

func (e *Engine) Get(name string) (*Plugin, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin %q not found", name)
	}
	return p, nil
}

func (e *Engine) Save(p *Plugin) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().Format(time.RFC3339)
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}

	filename := sanitizeName(p.Name) + ".json"
	if err := os.WriteFile(filepath.Join(e.dir, filename), data, 0644); err != nil {
		return err
	}

	e.plugins[p.Name] = p
	return nil
}

func (e *Engine) Delete(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	filename := sanitizeName(name) + ".json"
	os.Remove(filepath.Join(e.dir, filename))
	delete(e.plugins, name)
	return nil
}

func (e *Engine) Toggle(name string) error {
	e.mu.Lock()
	p, ok := e.plugins[name]
	e.mu.Unlock()

	if !ok {
		return fmt.Errorf("plugin %q not found", name)
	}
	p.Enabled = !p.Enabled
	return e.Save(p)
}

type ExecResult struct {
	Output string `json:"output"`
	Error  string `json:"error"`
}

func (e *Engine) RunAnalyzer(name string, flow *types.Flow) *ExecResult {
	e.mu.RLock()
	p, ok := e.plugins[name]
	e.mu.RUnlock()

	if !ok {
		return &ExecResult{Error: fmt.Sprintf("plugin %q not found", name)}
	}
	if !p.Enabled {
		return &ExecResult{Error: fmt.Sprintf("plugin %q is disabled", name)}
	}

	flowJSON, _ := json.MarshalIndent(flow, "", "  ")
	return &ExecResult{
		Output: fmt.Sprintf("Plugin: %s\nType: %s\n\nFlow:\n%s\n\n[Plugin execution requires JS/Lua runtime - showing flow data for now]", p.Name, p.Type, string(flowJSON)),
	}
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
}
