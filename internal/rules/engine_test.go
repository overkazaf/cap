package rules_test

import (
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/rules"
)

func TestEngineAddRemove(t *testing.T) {
	e := rules.NewEngine()

	if got := e.ListRules(); len(got) != 0 {
		t.Fatalf("new engine should have no rules, got %d", len(got))
	}

	r1 := &rules.Rule{ID: "r1", Name: "one", Enabled: true}
	r2 := &rules.Rule{ID: "r2", Name: "two", Enabled: true}
	e.AddRule(r1)
	e.AddRule(r2)

	got := e.ListRules()
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2", len(got))
	}

	e.RemoveRule("r1")
	got = e.ListRules()
	if len(got) != 1 {
		t.Fatalf("got %d rules after remove, want 1", len(got))
	}
	if got[0].ID != "r2" {
		t.Errorf("remaining rule ID = %q, want r2", got[0].ID)
	}

	e.RemoveRule("does-not-exist")
	if len(e.ListRules()) != 1 {
		t.Error("removing a nonexistent rule should be a no-op")
	}
}

func TestEngineSetRules(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{ID: "old"})

	e.SetRules([]*rules.Rule{
		{ID: "a"},
		{ID: "b"},
	})

	got := e.ListRules()
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2", len(got))
	}
	ids := map[string]bool{got[0].ID: true, got[1].ID: true}
	if !ids["a"] || !ids["b"] {
		t.Errorf("SetRules did not replace the rule set, got ids %v", ids)
	}
}

func TestRulePriority(t *testing.T) {
	e := rules.NewEngine()
	e.SetRules([]*rules.Rule{
		{ID: "low", Enabled: true, Priority: 10, Match: rules.Matcher{Path: "/api"}, Action: rules.Action{Type: rules.ActionPassthrough}},
		{ID: "high", Enabled: true, Priority: 1, Match: rules.Matcher{Path: "/api"}, Action: rules.Action{Type: rules.ActionDrop}},
		{ID: "mid", Enabled: true, Priority: 5, Match: rules.Matcher{Path: "/api"}, Action: rules.Action{Type: rules.ActionMock}},
	})

	got := e.FindMatch("GET", "example.com", "/api/data", "http://example.com/api/data", nil, nil)
	if got == nil {
		t.Fatal("expected a match")
	}
	if got.ID != "high" {
		t.Errorf("matched rule = %q, want %q (lowest Priority value should win)", got.ID, "high")
	}
}

func TestFindMatchSkipsDisabledRules(t *testing.T) {
	e := rules.NewEngine()
	e.SetRules([]*rules.Rule{
		{ID: "disabled", Enabled: false, Priority: 1, Match: rules.Matcher{Path: "/api"}},
		{ID: "enabled", Enabled: true, Priority: 10, Match: rules.Matcher{Path: "/api"}},
	})

	got := e.FindMatch("GET", "example.com", "/api/data", "http://example.com/api/data", nil, nil)
	if got == nil {
		t.Fatal("expected a match")
	}
	if got.ID != "enabled" {
		t.Errorf("matched rule = %q, want %q (disabled rule must be skipped)", got.ID, "enabled")
	}
}

func TestFindMatchNoMatch(t *testing.T) {
	e := rules.NewEngine()
	e.AddRule(&rules.Rule{ID: "r1", Enabled: true, Match: rules.Matcher{Path: "/does-not-exist"}})

	if got := e.FindMatch("GET", "example.com", "/api", "http://example.com/api", nil, nil); got != nil {
		t.Errorf("expected no match, got rule %q", got.ID)
	}
}

func TestEngineBreakpointResolve(t *testing.T) {
	e := rules.NewEngine()
	bpID, pending := e.CreateBreakpoint(&rules.Rule{ID: "bp1", Name: "pause"}, "GET", "http://example.com/x", map[string]string{"A": "B"}, []byte("body"))

	if pending.RuleID != "bp1" {
		t.Errorf("pending.RuleID = %q, want bp1", pending.RuleID)
	}
	if pending.Method != "GET" {
		t.Errorf("pending.Method = %q, want GET", pending.Method)
	}
	if pending.Body != "body" {
		t.Errorf("pending.Body = %q, want %q", pending.Body, "body")
	}

	list := e.ListPendingBreakpoints()
	if len(list) != 1 || list[0].ID != bpID {
		t.Fatalf("ListPendingBreakpoints = %+v, want one entry with ID %q", list, bpID)
	}

	resolution := &rules.BreakpointResolution{Action: "forward"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := e.ResolveBreakpoint(bpID, resolution); err != nil {
			t.Errorf("ResolveBreakpoint: %v", err)
		}
	}()

	got, err := e.WaitForBreakpoint(bpID, time.Second)
	if err != nil {
		t.Fatalf("WaitForBreakpoint: %v", err)
	}
	if got.Action != "forward" {
		t.Errorf("resolution.Action = %q, want forward", got.Action)
	}
	<-done

	if list := e.ListPendingBreakpoints(); len(list) != 0 {
		t.Errorf("breakpoint should be removed from the pending list after resolution, got %+v", list)
	}
}

func TestEngineBreakpointTimeout(t *testing.T) {
	e := rules.NewEngine()
	bpID, _ := e.CreateBreakpoint(&rules.Rule{ID: "bp1"}, "GET", "http://example.com/x", nil, nil)

	_, err := e.WaitForBreakpoint(bpID, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}

	if list := e.ListPendingBreakpoints(); len(list) != 0 {
		t.Errorf("breakpoint should be removed from the pending list after timeout, got %+v", list)
	}
}

func TestResolveBreakpointUnknownID(t *testing.T) {
	e := rules.NewEngine()
	err := e.ResolveBreakpoint("does-not-exist", &rules.BreakpointResolution{Action: "forward"})
	if err == nil {
		t.Fatal("expected an error resolving an unknown breakpoint ID")
	}
}

func TestWaitForBreakpointUnknownID(t *testing.T) {
	e := rules.NewEngine()
	_, err := e.WaitForBreakpoint("does-not-exist", time.Second)
	if err == nil {
		t.Fatal("expected an error waiting on an unknown breakpoint ID")
	}
}

func TestResolveBreakpointTwiceFails(t *testing.T) {
	e := rules.NewEngine()
	bpID, _ := e.CreateBreakpoint(&rules.Rule{ID: "bp1"}, "GET", "http://example.com/x", nil, nil)

	if err := e.ResolveBreakpoint(bpID, &rules.BreakpointResolution{Action: "forward"}); err != nil {
		t.Fatalf("first ResolveBreakpoint: %v", err)
	}
	if err := e.ResolveBreakpoint(bpID, &rules.BreakpointResolution{Action: "forward"}); err == nil {
		t.Fatal("expected the second ResolveBreakpoint call to fail (already resolved)")
	}
}
