package wailsgui

import (
	"testing"

	"github.com/overkazaf/cap/internal/frida"
	captrace "github.com/overkazaf/cap/internal/trace"
)

func TestFridaGUIScriptsAndTraceCodegen(t *testing.T) {
	app := &App{
		certDir:          t.TempDir(),
		events:           NewEventBus(),
		settings:         map[string]string{},
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
	}

	// Scripts list includes built-ins
	scripts := app.ListFridaScripts()
	if len(scripts) < 6 {
		t.Fatalf("expected >= 6 built-in scripts, got %d", len(scripts))
	}

	// Save & delete custom script
	saved, err := app.SaveFridaScript(frida.Script{
		Name:        "GUI Custom Hook",
		Description: "Test custom hook",
		Category:    "custom",
		Code:        "console.log('hi');",
	})
	if err != nil {
		t.Fatalf("SaveFridaScript failed: %v", err)
	}
	if err := app.DeleteFridaScript(saved.ID); err != nil {
		t.Fatalf("DeleteFridaScript failed: %v", err)
	}

	// Idle session state
	st := app.GetFridaSessionState()
	if st == nil || st.Running || st.Status != frida.StatusIdle {
		t.Fatalf("unexpected idle session state: %+v", st)
	}

	// GenerateFridaHookFromTrace without prior trace returns clear error
	if _, err := app.GenerateFridaHookFromTrace(frida.DefaultHookGenOptions()); err == nil {
		t.Fatalf("expected error when no trace result exists")
	}

	// Seed a trace result and verify hook synthesis
	app.traceState = &DeepTraceState{
		Status: "done",
		Result: &captrace.TraceResult{
			FlowID:  "f99",
			Package: "com.acme.app",
			Method:  "POST",
			URL:     "https://api.acme.test/pay",
			JavaTrace: []captrace.JavaRef{
				{Class: "com.acme.app.PayClient", Method: "signOrder", MatchedTerm: "/pay"},
			},
			NativeTrace: []captrace.NativeRef{
				{SOFile: "lib/arm64-v8a/libpay.so", Function: "Java_com_acme_app_PayClient_sign"},
			},
		},
	}

	gen, err := app.GenerateFridaHookFromTrace(frida.DefaultHookGenOptions())
	if err != nil {
		t.Fatalf("GenerateFridaHookFromTrace failed: %v", err)
	}
	if gen.TargetPackage != "com.acme.app" || len(gen.JavaTargets) == 0 || len(gen.NativeTargets) == 0 {
		t.Fatalf("unexpected generated hook: %+v", gen)
	}

	// Focused targets helper
	focused, err := app.GenerateFridaHookForTargets("com.acme.app", "Single Module", []frida.HookTarget{
		{Kind: "java", ClassName: "com.acme.app.Crypto", MethodName: "*"},
	}, true)
	if err != nil {
		t.Fatalf("GenerateFridaHookForTargets failed: %v", err)
	}
	if len(focused.JavaTargets) != 1 {
		t.Fatalf("expected 1 java target, got %d", len(focused.JavaTargets))
	}
}
