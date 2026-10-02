package compare_test

import (
	"testing"

	"github.com/overkazaf/cap/internal/compare"
	"github.com/overkazaf/cap/internal/types"
)

// baseFlow returns a fully-populated flow so tests can start from a known
// baseline and only override the fields they care about.
func baseFlow() *types.Flow {
	return &types.Flow{
		ID:     "flow-1",
		Method: "POST",
		URL:    "https://api.example.com/v1/login",
		Host:   "api.example.com",
		Path:   "/v1/login",
		ReqHeaders: map[string]string{
			"Authorization": "Bearer token-a",
			"Content-Type":  "application/json",
		},
		ReqBody: []byte(`{"user":"alice","active":true}`),
		Status:  200,
		RespHeaders: map[string]string{
			"Content-Type": "application/json",
		},
		RespBody:  []byte(`{"ok":true}`),
		LatencyMs: 100,
	}
}

// TestCompareIdentical compares a flow to itself and verifies every section
// of the Comparison reports no differences.
func TestCompareIdentical(t *testing.T) {
	flow := baseFlow()

	c := compare.Compare(flow, flow)

	if c.FlowA != flow.ID || c.FlowB != flow.ID {
		t.Errorf("FlowA/FlowB = %q/%q, want %q/%q", c.FlowA, c.FlowB, flow.ID, flow.ID)
	}
	if c.URL.Changed {
		t.Errorf("URL.Changed = true, want false (A=%q B=%q)", c.URL.A, c.URL.B)
	}
	if c.Method.Changed {
		t.Errorf("Method.Changed = true, want false")
	}
	if c.Status.Changed {
		t.Errorf("Status.Changed = true, want false")
	}
	if len(c.Headers.Added) != 0 || len(c.Headers.Removed) != 0 || len(c.Headers.Changed) != 0 {
		t.Errorf("Headers = %+v, want no added/removed/changed", c.Headers)
	}
	wantSame := len(flow.ReqHeaders) + len(flow.RespHeaders)
	if c.Headers.Same != wantSame {
		t.Errorf("Headers.Same = %d, want %d", c.Headers.Same, wantSame)
	}
	if c.ReqBody.Type != "identical" {
		t.Errorf("ReqBody.Type = %q, want %q", c.ReqBody.Type, "identical")
	}
	if c.RespBody.Type != "identical" {
		t.Errorf("RespBody.Type = %q, want %q", c.RespBody.Type, "identical")
	}
	if c.Latency.DiffMs != 0 {
		t.Errorf("Latency.DiffMs = %d, want 0", c.Latency.DiffMs)
	}
	if c.Latency.Percent != "0%" {
		t.Errorf("Latency.Percent = %q, want %q", c.Latency.Percent, "0%")
	}
	wantSummary := "no header diffs, body same, status same"
	if c.Summary != wantSummary {
		t.Errorf("Summary = %q, want %q", c.Summary, wantSummary)
	}
}

// TestCompareStatusDiff verifies that differing status codes are reported as
// a changed LineDiff with the codes formatted as strings.
func TestCompareStatusDiff(t *testing.T) {
	tests := []struct {
		name         string
		statusA      int
		statusB      int
		wantChanged  bool
		wantA, wantB string
	}{
		{"same status", 200, 200, false, "200", "200"},
		{"different status", 200, 404, true, "200", "404"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowA := baseFlow()
			flowA.Status = tt.statusA
			flowB := baseFlow()
			flowB.Status = tt.statusB

			c := compare.Compare(flowA, flowB)

			if c.Status.Changed != tt.wantChanged {
				t.Errorf("Status.Changed = %v, want %v", c.Status.Changed, tt.wantChanged)
			}
			if c.Status.A != tt.wantA || c.Status.B != tt.wantB {
				t.Errorf("Status = {A:%q B:%q}, want {A:%q B:%q}", c.Status.A, c.Status.B, tt.wantA, tt.wantB)
			}
		})
	}
}

// TestCompareHeadersDiff builds two flows whose request headers have an
// added, a removed, a changed and an identical key, and whose response
// headers add one more changed key, then verifies HeadersDiff reports all of
// it correctly merged across both request and response headers.
func TestCompareHeadersDiff(t *testing.T) {
	flowA := baseFlow()
	flowA.ReqHeaders = map[string]string{
		"Authorization": "Bearer token-a", // changed
		"X-Only-A":      "a-value",        // removed (absent from B)
		"X-Same":        "same-value",     // identical
	}
	flowA.RespHeaders = map[string]string{
		"Content-Type": "application/json", // identical
	}

	flowB := baseFlow()
	flowB.ReqHeaders = map[string]string{
		"Authorization": "Bearer token-b", // changed
		"X-Only-B":      "b-value",        // added (absent from A)
		"X-Same":        "same-value",     // identical
	}
	flowB.RespHeaders = map[string]string{
		"Content-Type": "application/json", // identical
	}

	c := compare.Compare(flowA, flowB)

	if len(c.Headers.Added) != 1 {
		t.Fatalf("len(Added) = %d, want 1 (%+v)", len(c.Headers.Added), c.Headers.Added)
	}
	if c.Headers.Added[0] != (compare.KV{Key: "X-Only-B", Value: "b-value"}) {
		t.Errorf("Added[0] = %+v, want {X-Only-B b-value}", c.Headers.Added[0])
	}

	if len(c.Headers.Removed) != 1 {
		t.Fatalf("len(Removed) = %d, want 1 (%+v)", len(c.Headers.Removed), c.Headers.Removed)
	}
	if c.Headers.Removed[0] != (compare.KV{Key: "X-Only-A", Value: "a-value"}) {
		t.Errorf("Removed[0] = %+v, want {X-Only-A a-value}", c.Headers.Removed[0])
	}

	if len(c.Headers.Changed) != 1 {
		t.Fatalf("len(Changed) = %d, want 1 (%+v)", len(c.Headers.Changed), c.Headers.Changed)
	}
	wantChange := compare.HeaderChange{Key: "Authorization", ValueA: "Bearer token-a", ValueB: "Bearer token-b"}
	if c.Headers.Changed[0] != wantChange {
		t.Errorf("Changed[0] = %+v, want %+v", c.Headers.Changed[0], wantChange)
	}

	// X-Same (request) and Content-Type (response) are identical in both.
	if c.Headers.Same != 2 {
		t.Errorf("Headers.Same = %d, want 2", c.Headers.Same)
	}
}

// TestCompareJSONBody verifies that two flows with structurally different
// JSON request bodies produce a key-path-level JSONDiff: added, removed and
// changed dot-paths, with nested objects flattened.
func TestCompareJSONBody(t *testing.T) {
	flowA := baseFlow()
	flowA.ReqBody = []byte(`{"user":{"name":"alice","age":30},"active":true}`)

	flowB := baseFlow()
	flowB.ReqBody = []byte(`{"user":{"name":"alice","age":31},"role":"admin"}`)
	// Response bodies stay identical so this test isolates request-body diffing.
	flowB.RespBody = flowA.RespBody

	c := compare.Compare(flowA, flowB)

	if c.ReqBody.Type != "json_diff" {
		t.Fatalf("ReqBody.Type = %q, want %q", c.ReqBody.Type, "json_diff")
	}
	if c.ReqBody.SizeA != len(flowA.ReqBody) || c.ReqBody.SizeB != len(flowB.ReqBody) {
		t.Errorf("ReqBody sizes = %d/%d, want %d/%d", c.ReqBody.SizeA, c.ReqBody.SizeB, len(flowA.ReqBody), len(flowB.ReqBody))
	}
	if c.ReqBody.JSONDiff == nil {
		t.Fatal("ReqBody.JSONDiff is nil")
	}

	jd := c.ReqBody.JSONDiff
	if !containsString(jd.Added, "role") {
		t.Errorf("JSONDiff.Added = %v, want it to contain %q", jd.Added, "role")
	}
	if !containsString(jd.Removed, "active") {
		t.Errorf("JSONDiff.Removed = %v, want it to contain %q", jd.Removed, "active")
	}
	wantChange := compare.JSONChange{Path: "user.age", ValueA: "30", ValueB: "31"}
	if !containsJSONChange(jd.Changed, wantChange) {
		t.Errorf("JSONDiff.Changed = %+v, want it to contain %+v", jd.Changed, wantChange)
	}
	// "user.name" is identical in both and must not appear anywhere in the diff.
	if containsString(jd.Added, "user.name") || containsString(jd.Removed, "user.name") {
		t.Errorf("JSONDiff unexpectedly mentions unchanged path user.name: %+v", jd)
	}

	if c.RespBody.Type != "identical" {
		t.Errorf("RespBody.Type = %q, want %q (bodies were set identical)", c.RespBody.Type, "identical")
	}
}

// TestCompareLatency verifies the absolute and percentage latency
// calculations, including the zero-baseline edge case.
func TestCompareLatency(t *testing.T) {
	tests := []struct {
		name        string
		latencyA    int64
		latencyB    int64
		wantDiffMs  int64
		wantPercent string
	}{
		{"25 percent slower", 100, 125, 25, "+25%"},
		{"25 percent faster", 200, 150, -50, "-25%"},
		{"unchanged", 80, 80, 0, "0%"},
		{"zero baseline, now positive", 0, 50, 50, "+inf%"},
		{"zero baseline, now negative", 0, -20, -20, "-inf%"},
		{"both zero", 0, 0, 0, "0%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowA := baseFlow()
			flowA.LatencyMs = tt.latencyA
			flowB := baseFlow()
			flowB.LatencyMs = tt.latencyB

			c := compare.Compare(flowA, flowB)

			if c.Latency.A != tt.latencyA || c.Latency.B != tt.latencyB {
				t.Errorf("Latency A/B = %d/%d, want %d/%d", c.Latency.A, c.Latency.B, tt.latencyA, tt.latencyB)
			}
			if c.Latency.DiffMs != tt.wantDiffMs {
				t.Errorf("Latency.DiffMs = %d, want %d", c.Latency.DiffMs, tt.wantDiffMs)
			}
			if c.Latency.Percent != tt.wantPercent {
				t.Errorf("Latency.Percent = %q, want %q", c.Latency.Percent, tt.wantPercent)
			}
		})
	}
}

// TestCompareSummary pins down the exact summary string format described by
// the package: "<N> header diffs, body <changed|same>, status <changed|same>".
func TestCompareSummary(t *testing.T) {
	flowA := baseFlow()
	flowA.Status = 200
	flowA.ReqHeaders = map[string]string{
		"A": "1", // changed below
		"B": "2", // removed below
		"C": "3", // identical
	}
	flowA.RespHeaders = nil
	flowA.ReqBody = []byte(`{"v":1}`)

	flowB := baseFlow()
	flowB.Status = 200 // same status
	flowB.ReqHeaders = map[string]string{
		"A": "1-changed", // changed
		"D": "4",         // added
		"C": "3",         // identical
	}
	flowB.RespHeaders = nil
	flowB.ReqBody = []byte(`{"v":2}`) // body changed

	c := compare.Compare(flowA, flowB)

	want := "3 header diffs, body changed, status same"
	if c.Summary != want {
		t.Errorf("Summary = %q, want %q", c.Summary, want)
	}
}

// TestCompareSummarySingularHeaderDiff checks the "1 header diff" singular
// wording, and that an otherwise-identical pair reports "no header diffs".
func TestCompareSummarySingularHeaderDiff(t *testing.T) {
	flowA := baseFlow()
	flowA.ReqHeaders = map[string]string{"X-Only-A": "v"}
	flowA.RespHeaders = nil

	flowB := baseFlow()
	flowB.ReqHeaders = nil // X-Only-A removed: exactly one header diff
	flowB.RespHeaders = nil

	c := compare.Compare(flowA, flowB)

	want := "1 header diff, body same, status same"
	if c.Summary != want {
		t.Errorf("Summary = %q, want %q", c.Summary, want)
	}
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func containsJSONChange(cs []compare.JSONChange, want compare.JSONChange) bool {
	for _, c := range cs {
		if c == want {
			return true
		}
	}
	return false
}
