package wailsgui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/plugin"
	"github.com/overkazaf/cap/internal/types"
)

func newTestPluginApp(t *testing.T) (*App, string) {
	t.Helper()
	pluginDir := filepath.Join(t.TempDir(), "plugins")
	eng, err := plugin.NewEngine(pluginDir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	pCtx, pCancel := context.WithCancel(context.Background())
	t.Cleanup(pCancel)

	flow := &types.Flow{
		ID:       "flow-plug-1",
		Method:   "POST",
		URL:      "https://api.example.com/v1/orders?debug=1",
		Host:     "api.example.com",
		Path:     "/v1/orders",
		Status:   201,
		RespBody: []byte(`{"order_id":"ord_123"}`),
	}
	app := &App{
		store:            &memFlowStore{flows: map[string]*types.Flow{flow.ID: flow}},
		certDir:          t.TempDir(),
		plugins:          eng,
		events:           NewEventBus(),
		settings:         map[string]string{},
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
		pluginSem:        make(chan struct{}, maxConcurrentAutoPlugins),
		pluginCtx:        pCtx,
		pluginCancel:     pCancel,
	}
	return app, pluginDir
}

func TestPluginDirReloadLogsAndEvents(t *testing.T) {
	app, pluginDir := newTestPluginApp(t)

	if got := app.GetPluginDir(); got != pluginDir {
		t.Fatalf("GetPluginDir() = %q, want %q", got, pluginDir)
	}

	// Drop a plugin JSON directly into the local plugin folder and verify ReloadPlugins picks it up
	dropped := plugin.Plugin{
		Name:        "local-auto-inspector",
		Description: "Inspects order endpoints via sh",
		Runtime:     plugin.RuntimeShell,
		Code:        `cat | grep -o 'ord_[0-9]*' || echo "no-order"`,
		Enabled:     true,
		Type:        "analyzer",
		AutoRun:     true,
		HostPattern: "*.example.com",
		PathPattern: "/v1/orders*",
		Method:      "POST",
		TimeoutSec:  5,
	}
	data, err := json.MarshalIndent(dropped, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, dropped.Name+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	list, err := app.ReloadPlugins()
	if err != nil {
		t.Fatalf("ReloadPlugins() error = %v", err)
	}
	found := false
	for _, p := range list {
		if p.Name == dropped.Name && p.AutoRun && p.Runtime == plugin.RuntimeShell {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ReloadPlugins() did not load dropped plugin %q: %+v", dropped.Name, list)
	}

	// Subscribe to EventPluginExecuted
	var mu sync.Mutex
	var events []plugin.ExecutionRecord
	app.events.SetEmitter(func(event string, data ...interface{}) {
		if event != EventPluginExecuted || len(data) == 0 {
			return
		}
		if rec, ok := data[0].(plugin.ExecutionRecord); ok {
			mu.Lock()
			events = append(events, rec)
			mu.Unlock()
		}
	})

	// 1. Manual RunPlugin must emit EventPluginExecuted with trigger="manual"
	res, err := app.RunPlugin(dropped.Name, "flow-plug-1")
	if err != nil {
		t.Fatalf("RunPlugin error = %v", err)
	}
	if res.Error != "" || !strings.Contains(res.Output, "ord_123") {
		t.Fatalf("unexpected RunPlugin result: %+v", res)
	}

	// 2. Auto-run on matching flow must emit EventPluginExecuted with trigger="auto"
	flow, _ := app.store.GetFlow("flow-plug-1")
	app.runAutoPlugins(flow)

	// 3. Auto-run on non-matching flow must NOT execute
	nonMatching := &types.Flow{
		ID:     "flow-other",
		Method: "GET",
		URL:    "https://other.invalid/health",
		Host:   "other.invalid",
		Path:   "/health",
	}
	app.runAutoPlugins(nonMatching)

	mu.Lock()
	gotEvents := append([]plugin.ExecutionRecord(nil), events...)
	mu.Unlock()

	if len(gotEvents) != 2 {
		t.Fatalf("got %d EventPluginExecuted events, want 2 (1 manual + 1 auto): %+v", len(gotEvents), gotEvents)
	}
	if gotEvents[0].Trigger != "manual" || gotEvents[1].Trigger != "auto" {
		t.Errorf("unexpected event triggers: [0]=%q [1]=%q", gotEvents[0].Trigger, gotEvents[1].Trigger)
	}

	// Verify GetPluginLogs & ClearPluginLogs
	logs := app.GetPluginLogs(10)
	if len(logs) != 2 {
		t.Fatalf("GetPluginLogs(10) = %d records, want 2", len(logs))
	}
	app.ClearPluginLogs()
	if after := app.GetPluginLogs(10); len(after) != 0 {
		t.Fatalf("GetPluginLogs after ClearPluginLogs = %d records, want 0", len(after))
	}
}

func TestAutoPluginsBoundedConcurrency(t *testing.T) {
	app, _ := newTestPluginApp(t)
	if err := app.SavePlugin(plugin.Plugin{
		Name:        "quick-sh",
		Runtime:     plugin.RuntimeShell,
		Code:        "echo ok",
		Enabled:     true,
		Type:        "analyzer",
		AutoRun:     true,
		HostPattern: "api.example.com",
		TimeoutSec:  5,
	}); err != nil {
		t.Fatal(err)
	}

	flow, _ := app.store.GetFlow("flow-plug-1")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			app.runAutoPlugins(flow)
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent runAutoPlugins timed out")
	}

	if logs := app.GetPluginLogs(20); len(logs) != 8 {
		t.Errorf("expected 8 execution logs, got %d", len(logs))
	}
}

func TestRunPluginEmitsNonEmptyIDOnDisabledOrMissingAndTestPluginMatch(t *testing.T) {
	app, _ := newTestPluginApp(t)

	if err := app.SavePlugin(plugin.Plugin{
		Name:        "disabled-plugin",
		Runtime:     plugin.RuntimeShell,
		Code:        "echo hi",
		Enabled:     false,
		Type:        "analyzer",
		HostPattern: "api.example.com",
		PathPattern: "/v1/orders*",
		Method:      "POST",
	}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var emitted []plugin.ExecutionRecord
	app.events.SetEmitter(func(event string, data ...interface{}) {
		if event != EventPluginExecuted || len(data) == 0 {
			return
		}
		if rec, ok := data[0].(plugin.ExecutionRecord); ok {
			mu.Lock()
			emitted = append(emitted, rec)
			mu.Unlock()
		}
	})

	// Run disabled plugin & missing plugin: both must emit non-empty ID & record in logs
	if _, err := app.RunPlugin("disabled-plugin", "flow-plug-1"); err != nil {
		t.Fatalf("RunPlugin(disabled) error = %v", err)
	}
	if _, err := app.RunPlugin("does-not-exist", "flow-plug-1"); err != nil {
		t.Fatalf("RunPlugin(missing) error = %v", err)
	}

	mu.Lock()
	got := append([]plugin.ExecutionRecord(nil), emitted...)
	mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("expected 2 EventPluginExecuted events, got %d: %+v", len(got), got)
	}
	for i, rec := range got {
		if rec.ID == "" {
			t.Errorf("event[%d] had empty ID: %+v", i, rec)
		}
		if rec.Trigger != "manual" {
			t.Errorf("event[%d].Trigger = %q, want manual", i, rec.Trigger)
		}
	}
	if logs := app.GetPluginLogs(10); len(logs) < 2 {
		t.Errorf("expected at least 2 recorded logs, got %d", len(logs))
	}

	// TestPluginMatch binding
	matched, err := app.TestPluginMatch(plugin.Plugin{
		Method:      "POST",
		HostPattern: "*.example.com",
		PathPattern: "/v1/orders*",
	}, "flow-plug-1")
	if err != nil || !matched {
		t.Errorf("TestPluginMatch(matching) = (%v, %v), want (true, nil)", matched, err)
	}

	notMatched, err := app.TestPluginMatch(plugin.Plugin{
		Method:      "GET",
		HostPattern: "api.example.com",
	}, "flow-plug-1")
	if err != nil || notMatched {
		t.Errorf("TestPluginMatch(non-matching) = (%v, %v), want (false, nil)", notMatched, err)
	}
}

func TestRunPluginDraftAndGetPluginFlowPayload(t *testing.T) {
	app, _ := newTestPluginApp(t)

	// 1. GetPluginFlowPayload returns valid indented JSON with query & query_params
	payloadStr, err := app.GetPluginFlowPayload("flow-plug-1")
	if err != nil {
		t.Fatalf("GetPluginFlowPayload error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		t.Fatalf("GetPluginFlowPayload returned invalid JSON: %v\n%s", err, payloadStr)
	}
	if payload["query"] != "debug=1" {
		t.Errorf("payload.query = %v, want %q", payload["query"], "debug=1")
	}
	qp, ok := payload["query_params"].(map[string]any)
	if !ok || qp["debug"] != "1" {
		t.Errorf("payload.query_params = %#v, want map with debug=1", payload["query_params"])
	}

	// 2. RunPluginDraft executes an unsaved, disabled draft and emits EventPluginExecuted with non-empty ID
	var mu sync.Mutex
	var emitted []plugin.ExecutionRecord
	app.events.SetEmitter(func(event string, data ...interface{}) {
		if event != EventPluginExecuted || len(data) == 0 {
			return
		}
		if rec, ok := data[0].(plugin.ExecutionRecord); ok {
			mu.Lock()
			emitted = append(emitted, rec)
			mu.Unlock()
		}
	})

	draft := plugin.Plugin{
		Name:       "unsaved-draft",
		Runtime:    plugin.RuntimeShell,
		Code:       `grep -Eo '"debug":[[:space:]]*"1"' || echo "miss"`,
		Enabled:    false, // drafts must run even when disabled
		Type:       "analyzer",
		TimeoutSec: 5,
	}
	res, err := app.RunPluginDraft(draft, "flow-plug-1")
	if err != nil {
		t.Fatalf("RunPluginDraft error = %v", err)
	}
	if res.Error != "" || !strings.Contains(res.Output, "debug") {
		t.Fatalf("unexpected RunPluginDraft result: %+v", res)
	}

	mu.Lock()
	got := append([]plugin.ExecutionRecord(nil), emitted...)
	mu.Unlock()
	if len(got) != 1 || got[0].ID == "" || got[0].Trigger != "manual" {
		t.Fatalf("expected 1 manual EventPluginExecuted with non-empty ID, got %+v", got)
	}
	if logs := app.GetPluginLogs(10); len(logs) != 1 || logs[0].ID == "" {
		t.Errorf("expected draft execution recorded in GetPluginLogs, got %+v", logs)
	}
}
