package sequence_test

import (
	"testing"

	"github.com/overkazaf/cap/internal/sequence"
	"github.com/overkazaf/cap/internal/types"
)

// TestFromFlows exercises FromFlows's mapping of captured flows onto
// sequence steps, including the auto-detection of likely variable
// extractions (cookies and common token-shaped JSON fields) from each
// flow's response.
func TestFromFlows(t *testing.T) {
	flows := []*types.Flow{
		{
			ID:     "f1",
			Method: "POST",
			URL:    "https://api.example.com/login",
			ReqHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			ReqBody: []byte(`{"user":"alice","pass":"secret"}`),
			Status:  200,
			RespHeaders: map[string]string{
				"Set-Cookie":   "session=abc123; Path=/",
				"Content-Type": "application/json",
			},
			RespBody: []byte(`{"data":{"token":"tok-xyz"}}`),
		},
		{
			ID:     "f2",
			Method: "GET",
			URL:    "https://api.example.com/data",
			ReqHeaders: map[string]string{
				"Authorization": "Bearer {{token}}",
			},
			Status:   200,
			RespBody: []byte(`{"items":[1,2,3]}`),
		},
	}

	seq := sequence.FromFlows("login-flow", flows)

	t.Run("maps basic step fields", func(t *testing.T) {
		if seq == nil {
			t.Fatal("FromFlows returned nil")
		}
		if seq.Name != "login-flow" {
			t.Errorf("Name = %q, want %q", seq.Name, "login-flow")
		}
		if seq.CreatedAt.IsZero() {
			t.Error("CreatedAt should be set to a non-zero time")
		}
		if len(seq.Steps) != 2 {
			t.Fatalf("len(Steps) = %d, want 2", len(seq.Steps))
		}

		step0 := seq.Steps[0]
		if step0.FlowID != "f1" {
			t.Errorf("Steps[0].FlowID = %q, want %q", step0.FlowID, "f1")
		}
		if step0.Method != "POST" {
			t.Errorf("Steps[0].Method = %q, want POST", step0.Method)
		}
		if step0.URL != "https://api.example.com/login" {
			t.Errorf("Steps[0].URL = %q, want %q", step0.URL, "https://api.example.com/login")
		}
		if step0.Headers["Content-Type"] != "application/json" {
			t.Errorf("Steps[0].Headers[Content-Type] = %q, want application/json", step0.Headers["Content-Type"])
		}
		if string(step0.Body) != `{"user":"alice","pass":"secret"}` {
			t.Errorf("Steps[0].Body = %q, want original request body", step0.Body)
		}

		step1 := seq.Steps[1]
		if step1.FlowID != "f2" {
			t.Errorf("Steps[1].FlowID = %q, want %q", step1.FlowID, "f2")
		}
		if step1.Method != "GET" {
			t.Errorf("Steps[1].Method = %q, want GET", step1.Method)
		}
		if step1.Headers["Authorization"] != "Bearer {{token}}" {
			t.Errorf("Steps[1].Headers[Authorization] = %q, want %q", step1.Headers["Authorization"], "Bearer {{token}}")
		}
	})

	t.Run("auto-detects cookie extraction from Set-Cookie", func(t *testing.T) {
		step0 := seq.Steps[0]
		var found *sequence.Extraction
		for i := range step0.Extract {
			if step0.Extract[i].Source == "cookie" {
				found = &step0.Extract[i]
			}
		}
		if found == nil {
			t.Fatalf("Steps[0].Extract has no cookie extraction, got %+v", step0.Extract)
		}
		if found.Name == "" {
			t.Error("cookie extraction Name should not be empty")
		}
	})

	t.Run("auto-detects token field extraction from JSON body", func(t *testing.T) {
		step0 := seq.Steps[0]
		var found *sequence.Extraction
		for i := range step0.Extract {
			if step0.Extract[i].Source == "body_json" && step0.Extract[i].Name == "token" {
				found = &step0.Extract[i]
			}
		}
		if found == nil {
			t.Fatalf("Steps[0].Extract has no body_json token extraction, got %+v", step0.Extract)
		}
		if found.Path != "data.token" {
			t.Errorf("token extraction Path = %q, want %q", found.Path, "data.token")
		}
	})

	t.Run("no extraction added when response has nothing to detect", func(t *testing.T) {
		step1 := seq.Steps[1]
		if len(step1.Extract) != 0 {
			t.Errorf("Steps[1].Extract = %+v, want empty (no cookie/token in response)", step1.Extract)
		}
	})
}

// TestFromFlowsCaseInsensitiveCookieHeader checks that cookie
// auto-detection matches "Set-Cookie" regardless of how the captured flow
// happened to case the header name — flows captured by the proxy or
// imported from other tools won't reliably agree on casing.
func TestFromFlowsCaseInsensitiveCookieHeader(t *testing.T) {
	flows := []*types.Flow{
		{
			ID:     "f1",
			Method: "GET",
			URL:    "https://api.example.com/login",
			RespHeaders: map[string]string{
				"set-cookie": "session=abc123",
			},
		},
	}

	seq := sequence.FromFlows("lowercase-header", flows)

	found := false
	for _, ext := range seq.Steps[0].Extract {
		if ext.Source == "cookie" {
			found = true
		}
	}
	if !found {
		t.Errorf("Steps[0].Extract has no cookie extraction for a lowercase %q header, got %+v", "set-cookie", seq.Steps[0].Extract)
	}
}
