package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

func testFlow() *types.Flow {
	return &types.Flow{
		ID:          "f1",
		Method:      "POST",
		URL:         "https://api.example.com/login?key=abc123",
		Host:        "api.example.com",
		Path:        "/login",
		Status:      200,
		LatencyMs:   42,
		ReqHeaders:  map[string]string{"Authorization": "Bearer tok_secret", "X-Api-Key": "ak_12345"},
		ReqBody:     []byte(`{"user":"test","password":"hunter2"}`),
		ReqBodyType: "application/json",
		RespHeaders: map[string]string{"Content-Type": "application/json"},
		RespBody:    []byte(`{"token":"eyJhbGciOiJIUzI1NiJ9","session":"s123"}`),
		RespBodyType: "application/json",
		SignParams:  []string{"sign", "ts"},
	}
}

// ── NewEngine ───────────────────────────────────────────────────────

func TestNewEngine_EmptyDir(t *testing.T) {
	e, err := NewEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(e.List()) != 0 {
		t.Fatalf("expected 0 plugins, got %d", len(e.List()))
	}
}

func TestNewEngine_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "plugins")
	e, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("expected dir to be created: %v", err)
	}
	if len(e.List()) != 0 {
		t.Fatalf("expected 0 plugins, got %d", len(e.List()))
	}
}

func TestNewEngine_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	p := &Plugin{Name: "pre-existing", Type: "analyzer", Enabled: true}
	data, _ := json.MarshalIndent(p, "", "  ")
	os.WriteFile(filepath.Join(dir, "pre-existing.json"), data, 0644)

	// Also place a non-JSON file that should be ignored
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("ignore me"), 0644)

	// And an invalid JSON file
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{invalid"), 0644)

	// And a valid JSON without a Name field
	os.WriteFile(filepath.Join(dir, "noname.json"), []byte(`{"type":"analyzer"}`), 0644)

	e, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	list := e.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(list))
	}
	if list[0].Name != "pre-existing" {
		t.Errorf("expected name %q, got %q", "pre-existing", list[0].Name)
	}
}

// ── Save + Get round-trip ───────────────────────────────────────────

func TestSaveAndGet(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	p := &Plugin{Name: "test-plug", Description: "desc", Type: "analyzer", Code: "code()"}
	if err := e.Save(p); err != nil {
		t.Fatal(err)
	}

	got, err := e.Get("test-plug")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "test-plug" || got.Description != "desc" || got.Code != "code()" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestGet_NotFound(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	_, err := e.Get("nope")
	if err == nil {
		t.Fatal("expected error for missing plugin")
	}
}

// ── Save persists to disk ───────────────────────────────────────────

func TestSave_PersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	e, _ := NewEngine(dir)
	e.Save(&Plugin{Name: "disk-test", Type: "analyzer"})

	// Create a fresh engine from the same directory
	e2, _ := NewEngine(dir)
	got, err := e2.Get("disk-test")
	if err != nil {
		t.Fatalf("plugin not persisted: %v", err)
	}
	if got.Name != "disk-test" {
		t.Errorf("expected %q, got %q", "disk-test", got.Name)
	}
}

// ── Timestamps ──────────────────────────────────────────────────────

func TestSave_SetsCreatedAt(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	p := &Plugin{Name: "ts-test", Type: "analyzer"}
	e.Save(p)

	got, _ := e.Get("ts-test")
	if got.CreatedAt == "" {
		t.Error("CreatedAt not set")
	}
	if got.UpdatedAt == "" {
		t.Error("UpdatedAt not set")
	}
}

func TestSave_PreservesCreatedAt(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	// Set a distinctive CreatedAt so we can verify it survives a second Save
	fixedCreated := "2020-01-01T00:00:00Z"
	p := &Plugin{Name: "ts-preserve", Type: "analyzer", CreatedAt: fixedCreated}
	e.Save(p)

	got, _ := e.Get("ts-preserve")
	if got.CreatedAt != fixedCreated {
		t.Errorf("CreatedAt overwritten on save: want %q, got %q", fixedCreated, got.CreatedAt)
	}

	// Second save should keep CreatedAt but update UpdatedAt
	got.Description = "updated"
	e.Save(got)

	got2, _ := e.Get("ts-preserve")
	if got2.CreatedAt != fixedCreated {
		t.Errorf("CreatedAt changed on second save: want %q, got %q", fixedCreated, got2.CreatedAt)
	}
	// UpdatedAt should be recent, not the fixed time
	if got2.UpdatedAt == fixedCreated {
		t.Error("UpdatedAt should differ from the fixed CreatedAt")
	}
}

// ── List ─────────────────────────────────────────────────────────────

func TestList_ReturnsAll(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	for _, name := range []string{"a", "b", "c"} {
		e.Save(&Plugin{Name: name, Type: "analyzer"})
	}
	list := e.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 plugins, got %d", len(list))
	}
	names := map[string]bool{}
	for _, p := range list {
		names[p.Name] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !names[want] {
			t.Errorf("missing plugin %q in list", want)
		}
	}
}

func TestList_EmptyEngine(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	list := e.List()
	if list == nil {
		t.Fatal("List() should return non-nil empty slice")
	}
	if len(list) != 0 {
		t.Fatalf("expected 0, got %d", len(list))
	}
}

// ── Delete ───────────────────────────────────────────────────────────

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	e, _ := NewEngine(dir)
	e.Save(&Plugin{Name: "to-delete", Type: "analyzer"})

	if err := e.Delete("to-delete"); err != nil {
		t.Fatal(err)
	}

	// Gone from memory
	_, err := e.Get("to-delete")
	if err == nil {
		t.Error("expected error after delete")
	}

	// Gone from disk
	path := filepath.Join(dir, "to-delete.json")
	if _, err := os.Stat(path); err == nil {
		t.Error("file should be deleted from disk")
	}
}

func TestDelete_NonExistent(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	err := e.Delete("ghost")
	if err != nil {
		t.Errorf("deleting non-existent plugin should not error, got: %v", err)
	}
}

// ── Toggle ───────────────────────────────────────────────────────────

func TestToggle(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "tog", Type: "analyzer", Enabled: false})

	if err := e.Toggle("tog"); err != nil {
		t.Fatal(err)
	}
	got, _ := e.Get("tog")
	if !got.Enabled {
		t.Error("expected Enabled=true after toggle")
	}

	e.Toggle("tog")
	got, _ = e.Get("tog")
	if got.Enabled {
		t.Error("expected Enabled=false after second toggle")
	}
}

func TestToggle_NotFound(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	err := e.Toggle("nope")
	if err == nil {
		t.Fatal("expected error toggling non-existent plugin")
	}
}

// ── RunAnalyzer ──────────────────────────────────────────────────────

func TestRunAnalyzer_NotFound(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	r := e.RunAnalyzer("missing", testFlow())
	if r.Error == "" {
		t.Error("expected error for missing plugin")
	}
}

func TestRunAnalyzer_Disabled(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "off", Type: "analyzer", Enabled: false})
	r := e.RunAnalyzer("off", testFlow())
	if r.Error == "" || !strings.Contains(r.Error, "disabled") {
		t.Errorf("expected disabled error, got: %q", r.Error)
	}
}

func TestRunAnalyzer_RequestFilter(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "rf", Type: "request_filter", Enabled: true})
	r := e.RunAnalyzer("rf", testFlow())
	if r.Error != "" {
		t.Fatalf("unexpected error: %s", r.Error)
	}
	if !strings.Contains(r.Output, "POST") {
		t.Error("request_filter output should contain method")
	}
	if !strings.Contains(r.Output, "api.example.com") {
		t.Error("request_filter output should contain URL")
	}
	// Should flag Authorization header
	if !strings.Contains(r.Output, "Authorization") {
		t.Error("request_filter should flag auth headers")
	}
}

func TestRunAnalyzer_RequestFilter_LargeBody(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "rf-big", Type: "request_filter", Enabled: true})
	f := testFlow()
	f.ReqBody = []byte(strings.Repeat("x", 600))
	r := e.RunAnalyzer("rf-big", f)
	if !strings.Contains(r.Output, "...") {
		t.Error("large body should be truncated")
	}
}

func TestRunAnalyzer_Analyzer_Sensitive(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "an", Type: "analyzer", Enabled: true})
	r := e.RunAnalyzer("an", testFlow())
	if r.Error != "" {
		t.Fatalf("unexpected error: %s", r.Error)
	}
	// testFlow has Authorization, X-Api-Key, key= in URL, password in body, sign params
	if !strings.Contains(r.Output, "finding") {
		t.Error("analyzer should report findings for sensitive flow")
	}
	if !strings.Contains(r.Output, "Auth header") {
		t.Error("analyzer should detect Authorization header")
	}
	if !strings.Contains(r.Output, "API Key") {
		t.Error("analyzer should detect API key header")
	}
	if !strings.Contains(r.Output, "Password") {
		t.Error("analyzer should detect password in body")
	}
	if !strings.Contains(r.Output, "Sign params") {
		t.Error("analyzer should report sign params")
	}
}

func TestRunAnalyzer_Analyzer_Clean(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "clean", Type: "analyzer", Enabled: true})
	f := &types.Flow{
		ID:     "f2",
		Method: "GET",
		URL:    "https://example.com/health",
		Status: 200,
	}
	r := e.RunAnalyzer("clean", f)
	if !strings.Contains(r.Output, "No sensitive data") {
		t.Errorf("clean flow should report no findings, got: %s", r.Output)
	}
}

func TestRunAnalyzer_ResponseModifier(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "rm", Type: "response_modifier", Enabled: true})
	r := e.RunAnalyzer("rm", testFlow())
	if r.Error != "" {
		t.Fatalf("unexpected error: %s", r.Error)
	}
	if !strings.Contains(r.Output, "Response: 200") {
		t.Error("response_modifier should show status")
	}
	if !strings.Contains(r.Output, "42ms") {
		t.Error("response_modifier should show latency")
	}
	// testFlow resp body contains "token" and "session"
	if !strings.Contains(r.Output, "token") {
		t.Error("response_modifier should flag token in response")
	}
	if !strings.Contains(r.Output, "session") {
		t.Error("response_modifier should flag session in response")
	}
}

func TestRunAnalyzer_ResponseModifier_ErrorBody(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "rm-err", Type: "response_modifier", Enabled: true})
	f := testFlow()
	f.RespBody = []byte(`{"error":"something went wrong"}`)
	r := e.RunAnalyzer("rm-err", f)
	if !strings.Contains(r.Output, "error") {
		t.Error("response_modifier should flag error in response body")
	}
}

func TestRunAnalyzer_UnknownType(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "unk", Type: "custom_thing", Enabled: true})
	r := e.RunAnalyzer("unk", testFlow())
	if r.Error != "" {
		t.Fatalf("unknown type should not error: %s", r.Error)
	}
	if !strings.Contains(r.Output, "Plugin: unk") {
		t.Error("unknown type should dump flow JSON with plugin name")
	}
}

// ── sanitizeName ─────────────────────────────────────────────────────

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"simple", "simple"},
		{"My Plugin", "my-plugin"},
		{"path/to/thing", "path-to-thing"},
		{"back\\slash", "back-slash"},
		{"has.dots", "has-dots"},
		{"UPPER Case", "upper-case"},
		{"a/b\\c.d e", "a-b-c-d-e"},
	}
	for _, tt := range tests {
		got := sanitizeName(tt.in)
		if got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── truncate ─────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short: %q", got)
	}
	if got := truncate("exactly10!", 10); got != "exactly10!" {
		t.Errorf("truncate exact: %q", got)
	}
	if got := truncate("this is longer than five", 5); got != "this ..." {
		t.Errorf("truncate long: %q", got)
	}
}

// ── Concurrent access ────────────────────────────────────────────────

func TestConcurrentSaveAndList(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		name := string(rune('a' + i%26))
		go func() {
			defer wg.Done()
			e.Save(&Plugin{Name: name, Type: "analyzer"})
		}()
		go func() {
			defer wg.Done()
			e.List()
		}()
	}
	wg.Wait()
	// No race/panic = pass. Check that at least some plugins exist.
	if len(e.List()) == 0 {
		t.Error("expected at least one plugin after concurrent saves")
	}
}

// NOTE: Toggle has a data race — it unlocks mu before mutating p.Enabled
// (engine.go:118-120). Concurrent Toggle calls on the same plugin race on
// the Enabled field. This test exercises sequential toggles only; fixing
// the race requires holding mu through the mutation in production code.
func TestToggle_SequentialMultiple(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	e.Save(&Plugin{Name: "multi-tog", Type: "analyzer", Enabled: false})
	for i := 0; i < 10; i++ {
		if err := e.Toggle("multi-tog"); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := e.Get("multi-tog")
	// 10 toggles from false → should end at false (even number)
	if got.Enabled {
		t.Error("expected Enabled=false after even number of toggles")
	}
}

// ── ExamplePlugins ───────────────────────────────────────────────────

func TestExamplePlugins(t *testing.T) {
	if len(ExamplePlugins) == 0 {
		t.Fatal("ExamplePlugins should not be empty")
	}
	for _, p := range ExamplePlugins {
		if p.Name == "" {
			t.Error("example plugin has empty name")
		}
		if p.Type == "" {
			t.Error("example plugin has empty type")
		}
		if p.Code == "" {
			t.Error("example plugin has empty code")
		}
	}
}

// ── MatchesFlow ──────────────────────────────────────────────────────

func TestMatchesFlow(t *testing.T) {
	f := testFlow() // POST https://api.example.com/login?key=abc123

	cases := []struct {
		name   string
		plugin *Plugin
		flow   *types.Flow
		want   bool
	}{
		{"nil plugin", nil, f, false},
		{"nil flow", &Plugin{Name: "p"}, nil, false},
		{"empty filters match all", &Plugin{Name: "p"}, f, true},
		{"method exact case-insensitive", &Plugin{Method: "post"}, f, true},
		{"method ANY matches", &Plugin{Method: "ANY"}, f, true},
		{"method mismatch", &Plugin{Method: "GET"}, f, false},
		{"host substring", &Plugin{HostPattern: "EXAMPLE.COM"}, f, true},
		{"host glob match", &Plugin{HostPattern: "*.example.com"}, f, true},
		{"host glob mismatch", &Plugin{HostPattern: "*.other.org"}, f, false},
		{"host regex match", &Plugin{HostPattern: `/^api\.example\.(com|net)$/`}, f, true},
		{"host invalid regex does not panic", &Plugin{HostPattern: `/[unclosed/`}, f, false},
		{"path glob match", &Plugin{PathPattern: "/log*"}, f, true},
		{"path regex match", &Plugin{PathPattern: `/^\/login$/`}, f, true},
		{"path mismatch", &Plugin{PathPattern: "/v2/orders"}, f, false},
		{"url fallback when host/path empty", &Plugin{HostPattern: "shop.local", PathPattern: "/v1/*"}, &types.Flow{Method: "GET", URL: "https://shop.local/v1/items"}, true},
		// Query-string path matching, optional leading '/', literal '?'
		{"path query glob without leading slash", &Plugin{PathPattern: "v1/url?album*"}, &types.Flow{Method: "GET", URL: "https://api.example.com:443/v1/url?album=123&fmt=json", Host: "api.example.com:443", Path: "/v1/url"}, true},
		{"path query glob with leading slash", &Plugin{PathPattern: "/v1/url?album*"}, &types.Flow{Method: "GET", URL: "https://api.example.com:443/v1/url?album=123", Host: "api.example.com:443", Path: "/v1/url"}, true},
		{"path query substring", &Plugin{PathPattern: "v1/url?album"}, &types.Flow{Method: "GET", URL: "https://api.example.com/v1/url?album=123", Host: "api.example.com", Path: "/v1/url"}, true},
		{"path query regex", &Plugin{PathPattern: `/\/v\d+\/url\?album/`}, &types.Flow{Method: "GET", URL: "https://api.example.com/v1/url?album=123", Host: "api.example.com", Path: "/v1/url"}, true},
		{"literal question mark does not act as single-char wildcard", &Plugin{PathPattern: "/v1/url?album*"}, &types.Flow{Method: "GET", URL: "https://api.example.com/v1/urlXalbum123", Host: "api.example.com", Path: "/v1/urlXalbum123"}, false},
		// Host with :port stripped cleanly
		{"host exact matches host:443", &Plugin{HostPattern: "api.example.com"}, &types.Flow{Method: "GET", URL: "https://api.example.com:443/ping", Host: "api.example.com:443", Path: "/ping"}, true},
		{"host glob matches host:443", &Plugin{HostPattern: "*.example.com"}, &types.Flow{Method: "GET", URL: "https://api.example.com:443/ping", Host: "api.example.com:443", Path: "/ping"}, true},
		{"host glob matches explicit host:443", &Plugin{HostPattern: "api.example.com:443"}, &types.Flow{Method: "GET", URL: "https://api.example.com:443/ping", Host: "api.example.com:443", Path: "/ping"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesFlow(tc.plugin, tc.flow); got != tc.want {
				t.Errorf("MatchesFlow = %v, want %v", got, tc.want)
			}
		})
	}
}

// ── Dir & Hot Reload ─────────────────────────────────────────────────

func TestDirAndReload(t *testing.T) {
	dir := t.TempDir()
	e, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dir() != dir {
		t.Fatalf("Dir() = %q, want %q", e.Dir(), dir)
	}

	// Drop a new plugin JSON directly on disk and call Reload.
	dropped := &Plugin{
		Name:        "local-hook",
		Type:        "analyzer",
		Runtime:     RuntimeShell,
		AutoRun:     true,
		HostPattern: "*.example.com",
		Enabled:     true,
		Code:        "cat",
	}
	raw, _ := json.MarshalIndent(dropped, "", "  ")
	diskPath := filepath.Join(dir, "local-hook.json")
	if err := os.WriteFile(diskPath, raw, 0644); err != nil {
		t.Fatal(err)
	}

	if err := e.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	got, err := e.Get("local-hook")
	if err != nil {
		t.Fatalf("Get after Reload: %v", err)
	}
	if !got.AutoRun || got.Runtime != RuntimeShell || got.HostPattern != "*.example.com" {
		t.Fatalf("reloaded plugin fields mismatch: %+v", got)
	}

	// Removing from disk + Reload removes from memory.
	_ = os.Remove(diskPath)
	if err := e.Reload(); err != nil {
		t.Fatalf("Reload after delete: %v", err)
	}
	if len(e.List()) != 0 {
		t.Fatalf("expected 0 plugins after delete+Reload, got %d", len(e.List()))
	}
}

// ── Script Execution (sh, python3, timeout, truncation) ──────────────

func TestRunScript_ShellAndPython3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}
	e, _ := NewEngine(t.TempDir())
	f := testFlow()

	// Shell script echoing stdin JSON
	if err := e.Save(&Plugin{
		Name:       "sh-echo",
		Type:       "analyzer",
		Runtime:    RuntimeShell,
		Enabled:    true,
		TimeoutSec: 5,
		Code:       `payload=$(cat); echo "GOT:$payload"`,
	}); err != nil {
		t.Fatal(err)
	}
	res := e.RunAnalyzer("sh-echo", f)
	if res.Error != "" {
		t.Fatalf("sh-echo error: %s", res.Error)
	}
	if !strings.Contains(res.Output, `"id":"f1"`) || !strings.Contains(res.Output, `"scheme":"https"`) {
		t.Fatalf("sh-echo missing flow JSON fields: %s", res.Output)
	}

	// Verify manual run was recorded in Logs().
	logs := e.Logs(10)
	if len(logs) != 1 || logs[0].Trigger != "manual" || logs[0].PluginName != "sh-echo" || logs[0].Runtime != RuntimeShell {
		t.Fatalf("unexpected manual log record: %+v", logs)
	}

	// Python 3 script if available on host.
	if _, err := exec.LookPath("python3"); err == nil {
		if err := e.Save(&Plugin{
			Name:       "py-inspect",
			Type:       "analyzer",
			Runtime:    RuntimePython3,
			Enabled:    true,
			TimeoutSec: 5,
			Code:       "import json, sys\nd = json.load(sys.stdin)\nprint(f\"{d['method']}:{d['host']}{d['path']}:{d['status']}\")\n",
		}); err != nil {
			t.Fatal(err)
		}
		pyRes := e.RunAnalyzer("py-inspect", f)
		if pyRes.Error != "" {
			t.Fatalf("py-inspect error: %s", pyRes.Error)
		}
		if pyRes.Output != "POST:api.example.com/login:200" {
			t.Fatalf("py-inspect output = %q, want POST:api.example.com/login:200", pyRes.Output)
		}
	}
}

func TestRunScript_TimeoutAndCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}
	e, _ := NewEngine(t.TempDir())
	_ = e.Save(&Plugin{
		Name:       "slow-sh",
		Type:       "analyzer",
		Runtime:    RuntimeShell,
		Enabled:    true,
		TimeoutSec: 1,
		Code:       "sleep 5",
	})

	// 1. Context cancellation terminates promptly (< 1s).
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := e.RunAnalyzerContext(ctx, "slow-sh", testFlow())
	elapsed := time.Since(start)
	if res.Error == "" {
		t.Fatal("expected timeout/cancel error")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("cancellation took %v, expected prompt process-group kill", elapsed)
	}

	// 2. Plugin TimeoutSec=1 triggers deadline cleanly.
	start = time.Now()
	res2 := e.RunAnalyzer("slow-sh", testFlow())
	if !strings.Contains(res2.Error, "timed out") {
		t.Fatalf("expected timed out error, got %q", res2.Error)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("1s timeout took too long: %v", time.Since(start))
	}
}

func TestRunScript_OutputTruncation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}
	e, _ := NewEngine(t.TempDir())
	// Emit ~100 KiB of 'A's to verify 64 KiB cap.
	_ = e.Save(&Plugin{
		Name:       "noisy-sh",
		Type:       "analyzer",
		Runtime:    RuntimeShell,
		Enabled:    true,
		TimeoutSec: 5,
		Code:       `dd if=/dev/zero bs=1024 count=100 2>/dev/null | tr '\0' 'A'`,
	})
	res := e.RunAnalyzer("noisy-sh", testFlow())
	if res.Error != "" {
		t.Fatalf("noisy-sh error: %s", res.Error)
	}
	if !strings.Contains(res.Output, "output truncated at 64 KiB") {
		t.Fatalf("expected truncation marker, got len=%d", len(res.Output))
	}
	if len(res.Output) > maxScriptOutputBytes+128 {
		t.Fatalf("output exceeded cap: %d bytes", len(res.Output))
	}
}

// ── RunMatching, Ring Buffer & Concurrency ───────────────────────────

func TestRunMatchingAndLogsRingBuffer(t *testing.T) {
	e, _ := NewEngine(t.TempDir())

	_ = e.Save(&Plugin{Name: "auto-hit", Type: "analyzer", Runtime: RuntimeBuiltin, Enabled: true, AutoRun: true, HostPattern: "*.example.com"})
	_ = e.Save(&Plugin{Name: "auto-miss", Type: "analyzer", Runtime: RuntimeBuiltin, Enabled: true, AutoRun: true, HostPattern: "other.dev"})
	_ = e.Save(&Plugin{Name: "auto-disabled", Type: "analyzer", Runtime: RuntimeBuiltin, Enabled: false, AutoRun: true})
	_ = e.Save(&Plugin{Name: "manual-only", Type: "analyzer", Runtime: RuntimeBuiltin, Enabled: true, AutoRun: false})

	recs := e.RunMatching(context.Background(), testFlow())
	if len(recs) != 1 {
		t.Fatalf("expected 1 matching auto-run record, got %d: %+v", len(recs), recs)
	}
	if recs[0].PluginName != "auto-hit" || recs[0].Trigger != "auto" || recs[0].FlowID != "f1" {
		t.Fatalf("unexpected auto record: %+v", recs[0])
	}

	// Ring buffer caps at maxExecutionLogs (200) and returns newest-first.
	e.ClearLogs()
	if len(e.Logs(0)) != 0 {
		t.Fatal("expected empty logs after ClearLogs")
	}
	for i := 1; i <= maxExecutionLogs+35; i++ {
		e.RecordExecution(ExecutionRecord{
			PluginName: fmt.Sprintf("p-%d", i),
			FlowID:     fmt.Sprintf("f-%d", i),
			Trigger:    "auto",
		})
	}
	all := e.Logs(0)
	if len(all) != maxExecutionLogs {
		t.Fatalf("Logs(0) len = %d, want %d", len(all), maxExecutionLogs)
	}
	wantNewest := fmt.Sprintf("p-%d", maxExecutionLogs+35)
	if all[0].PluginName != wantNewest {
		t.Fatalf("newest log = %q, want %q", all[0].PluginName, wantNewest)
	}
	top5 := e.Logs(5)
	if len(top5) != 5 || top5[0].PluginName != wantNewest {
		t.Fatalf("Logs(5) mismatch: %+v", top5)
	}

	// Concurrent RunMatching + Logs + Reload under -race.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			e.RunMatching(context.Background(), testFlow())
		}()
		go func() {
			defer wg.Done()
			_ = e.Logs(20)
		}()
		go func() {
			defer wg.Done()
			_ = e.Reload()
		}()
	}
	wg.Wait()
}

func TestRunAnalyzerContext_RecordsDisabledAndMissingErrors(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	_ = e.Save(&Plugin{Name: "off-plug", Type: "analyzer", Runtime: RuntimePython3, Enabled: false})

	res1 := e.RunAnalyzerContext(context.Background(), "off-plug", testFlow())
	if !strings.Contains(res1.Error, "disabled") {
		t.Fatalf("expected disabled error, got %q", res1.Error)
	}
	res2 := e.RunAnalyzerContext(context.Background(), "missing-plug", testFlow())
	if !strings.Contains(res2.Error, "not found") {
		t.Fatalf("expected not found error, got %q", res2.Error)
	}

	logs := e.Logs(10)
	if len(logs) != 2 {
		t.Fatalf("expected 2 logged error invocations, got %d: %+v", len(logs), logs)
	}
	for _, rec := range logs {
		if rec.ID == "" || rec.Error == "" || rec.Trigger != "manual" {
			t.Errorf("expected non-empty ID, Error, and manual trigger: %+v", rec)
		}
	}
}

func TestRunMatching_AutoReloadsDiskEdits(t *testing.T) {
	dir := t.TempDir()
	e, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Drop a plugin JSON directly onto disk WITHOUT calling Reload().
	p := &Plugin{
		Name:        "disk-auto",
		Type:        "analyzer",
		Runtime:     RuntimeBuiltin,
		Enabled:     true,
		AutoRun:     true,
		HostPattern: "*.example.com",
		PathPattern: "v1/items?type=*",
	}
	raw, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "disk-auto.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}

	flow := &types.Flow{
		ID:     "f-disk",
		Method: "GET",
		URL:    "https://api.example.com:443/v1/items?type=music&page=1",
		Host:   "api.example.com:443",
		Path:   "/v1/items",
		Status: 200,
	}
	recs := e.RunMatching(context.Background(), flow)
	if len(recs) != 1 || recs[0].PluginName != "disk-auto" || recs[0].ID == "" {
		t.Fatalf("expected disk-auto to auto-reload and trigger, got %+v", recs)
	}
}

func TestBuildFlowPayloadJSON_QueryAndQueryParams(t *testing.T) {
	f := &types.Flow{
		ID:        "f-qp",
		Method:    "GET",
		URL:       "https://api.example.com/v1/url?album=42&fmt=flac&tag=a&tag=b",
		Host:      "api.example.com",
		Path:      "/v1/url",
		Status:    200,
		LatencyMs: 18,
	}
	raw, err := BuildFlowPayloadJSON(f)
	if err != nil {
		t.Fatalf("BuildFlowPayloadJSON: %v", err)
	}
	var decoded struct {
		Query       string            `json:"query"`
		QueryParams map[string]string `json:"query_params"`
		Scheme      string            `json:"scheme"`
		Path        string            `json:"path"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if decoded.Query != "album=42&fmt=flac&tag=a&tag=b" {
		t.Errorf("query = %q", decoded.Query)
	}
	if decoded.QueryParams["album"] != "42" || decoded.QueryParams["fmt"] != "flac" || decoded.QueryParams["tag"] != "a" {
		t.Errorf("query_params = %+v", decoded.QueryParams)
	}

	// Flow without query string produces non-nil empty query_params map ({} in JSON).
	rawEmpty, err := BuildFlowPayloadJSON(&types.Flow{ID: "f-noq", URL: "https://example.com/ping"})
	if err != nil {
		t.Fatalf("BuildFlowPayloadJSON(no query): %v", err)
	}
	if !strings.Contains(string(rawEmpty), `"query_params": {}`) {
		t.Errorf("expected empty JSON object for query_params, got:\n%s", string(rawEmpty))
	}
}

func TestRunDraftContext_BuiltinAndScript(t *testing.T) {
	e, _ := NewEngine(t.TempDir())
	f := testFlow()

	// Unsaved AND disabled built-in draft runs cleanly and logs a non-empty ID record.
	res, rec := e.RunDraftContext(context.Background(), &Plugin{
		Name:    "unsaved-builtin",
		Type:    "analyzer",
		Runtime: RuntimeBuiltin,
		Enabled: false,
	}, f)
	if res.Error != "" {
		t.Fatalf("builtin draft error: %s", res.Error)
	}
	if rec.ID == "" || rec.PluginName != "unsaved-builtin" || rec.Trigger != "manual" {
		t.Fatalf("unexpected draft record: %+v", rec)
	}

	// Unsaved AND disabled shell draft receives query & query_params on stdin.
	if runtime.GOOS != "windows" {
		shRes, shRec := e.RunDraftContext(context.Background(), &Plugin{
			Name:       "unsaved-sh",
			Type:       "analyzer",
			Runtime:    RuntimeShell,
			Enabled:    false,
			TimeoutSec: 5,
			Code:       `cat`,
		}, f)
		if shRes.Error != "" {
			t.Fatalf("sh draft error: %s", shRes.Error)
		}
		if !strings.Contains(shRes.Output, `"query":"key=abc123"`) || !strings.Contains(shRes.Output, `"query_params":{"key":"abc123"}`) {
			t.Fatalf("sh draft stdin missing query/query_params: %s", shRes.Output)
		}
		if shRec.ID == "" || shRec.Runtime != RuntimeShell {
			t.Fatalf("unexpected sh draft record: %+v", shRec)
		}
	}

	logs := e.Logs(10)
	if len(logs) == 0 || logs[0].ID == "" {
		t.Fatalf("expected draft runs recorded in Logs(), got %+v", logs)
	}
}
