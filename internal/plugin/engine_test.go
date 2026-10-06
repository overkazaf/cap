package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
