package compare_test

import (
	"testing"

	"github.com/overkazaf/cap/internal/compare"
)

// TestCompareNilFlows verifies Compare never panics when given nil flows,
// instead treating a nil flow as an empty one so the result still reports
// what differs (everything the non-nil side has, in this case).
func TestCompareNilFlows(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		c := compare.Compare(nil, nil)
		if c == nil {
			t.Fatal("Compare(nil, nil) returned nil, want a non-nil zero-value Comparison")
		}
		if c.URL.Changed || c.Method.Changed || c.Status.Changed {
			t.Errorf("expected no changes between two nil flows, got %+v", c)
		}
		if c.ReqBody.Type != "identical" || c.RespBody.Type != "identical" {
			t.Errorf("expected identical empty bodies, got req=%q resp=%q", c.ReqBody.Type, c.RespBody.Type)
		}
	})

	t.Run("one nil", func(t *testing.T) {
		flowB := baseFlow()

		c := compare.Compare(nil, flowB)
		if c == nil {
			t.Fatal("Compare(nil, flow) returned nil")
		}
		if !c.URL.Changed {
			t.Errorf("URL.Changed = false, want true (A=%q B=%q)", c.URL.A, c.URL.B)
		}
		if c.URL.A != "" || c.URL.B != flowB.URL {
			t.Errorf("URL = {A:%q B:%q}, want {A:%q B:%q}", c.URL.A, c.URL.B, "", flowB.URL)
		}
	})
}
