package compare_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/overkazaf/cap/internal/compare"
)

// TestCompareTextBodyDiff verifies that two differing non-JSON, UTF-8 bodies
// are classified as "text_diff" with a non-empty, line-oriented TextDiff.
func TestCompareTextBodyDiff(t *testing.T) {
	flowA := baseFlow()
	flowA.ReqHeaders["Content-Type"] = "text/plain"
	flowA.ReqBody = []byte("line one\nline two\nline three")

	flowB := baseFlow()
	flowB.ReqHeaders["Content-Type"] = "text/plain"
	flowB.ReqBody = []byte("line one\nCHANGED\nline three\nline four")

	c := compare.Compare(flowA, flowB)

	if c.ReqBody.Type != "text_diff" {
		t.Fatalf("ReqBody.Type = %q, want %q", c.ReqBody.Type, "text_diff")
	}
	if c.ReqBody.JSONDiff != nil {
		t.Errorf("ReqBody.JSONDiff = %+v, want nil for a text diff", c.ReqBody.JSONDiff)
	}
	if c.ReqBody.TextDiff == "" {
		t.Fatal("ReqBody.TextDiff is empty, want a non-empty diff")
	}
	if !strings.Contains(c.ReqBody.TextDiff, "CHANGED") {
		t.Errorf("ReqBody.TextDiff = %q, want it to mention the changed line", c.ReqBody.TextDiff)
	}
	if !strings.Contains(c.ReqBody.TextDiff, "line four") {
		t.Errorf("ReqBody.TextDiff = %q, want it to mention the added line", c.ReqBody.TextDiff)
	}
}

// TestCompareBinaryBodyDiff verifies that bodies containing non-text bytes
// fall back to a binary size comparison instead of a text or JSON diff, both
// for bytes that are invalid UTF-8 and for bytes that happen to be valid
// UTF-8 but contain a control byte (e.g. an embedded NUL).
func TestCompareBinaryBodyDiff(t *testing.T) {
	tests := []struct {
		name  string
		bodyA []byte
		bodyB []byte
		sizeA int
		sizeB int
	}{
		{
			name:  "invalid UTF-8",
			bodyA: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE},
			bodyB: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0xFC},
			sizeA: 5,
			sizeB: 7,
		},
		{
			name:  "valid UTF-8 with embedded NUL control byte",
			bodyA: []byte("abc\x00def"),
			bodyB: []byte("abc\x00xyz!"),
			sizeA: 7,
			sizeB: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowA := baseFlow()
			flowA.RespHeaders["Content-Type"] = "application/octet-stream"
			flowA.RespBody = tt.bodyA

			flowB := baseFlow()
			flowB.RespHeaders["Content-Type"] = "application/octet-stream"
			flowB.RespBody = tt.bodyB

			c := compare.Compare(flowA, flowB)

			if c.RespBody.Type != "binary_diff" {
				t.Fatalf("RespBody.Type = %q, want %q", c.RespBody.Type, "binary_diff")
			}
			if c.RespBody.SizeA != tt.sizeA || c.RespBody.SizeB != tt.sizeB {
				t.Errorf("RespBody sizes = %d/%d, want %d/%d", c.RespBody.SizeA, c.RespBody.SizeB, tt.sizeA, tt.sizeB)
			}
			if c.RespBody.JSONDiff != nil {
				t.Errorf("RespBody.JSONDiff = %+v, want nil for a binary diff", c.RespBody.JSONDiff)
			}
			if c.RespBody.TextDiff != "" {
				t.Errorf("RespBody.TextDiff = %q, want empty for a binary diff", c.RespBody.TextDiff)
			}
		})
	}
}

// TestCompareEmptyBodiesAreIdentical verifies that two empty (nil/zero-length)
// bodies are reported as identical rather than any diff type.
func TestCompareEmptyBodiesAreIdentical(t *testing.T) {
	flowA := baseFlow()
	flowA.ReqBody = nil
	flowB := baseFlow()
	flowB.ReqBody = []byte{}

	c := compare.Compare(flowA, flowB)

	if c.ReqBody.Type != "identical" {
		t.Errorf("ReqBody.Type = %q, want %q for two empty bodies", c.ReqBody.Type, "identical")
	}
	if c.ReqBody.SizeA != 0 || c.ReqBody.SizeB != 0 {
		t.Errorf("ReqBody sizes = %d/%d, want 0/0", c.ReqBody.SizeA, c.ReqBody.SizeB)
	}
}

// TestCompareTextBodyDiffTruncates verifies that a text diff with many
// differing lines is capped rather than growing unbounded, ending in "...".
func TestCompareTextBodyDiffTruncates(t *testing.T) {
	var linesA, linesB []string
	for i := 0; i < 25; i++ {
		linesA = append(linesA, fmt.Sprintf("a-line-%d", i))
		linesB = append(linesB, fmt.Sprintf("b-line-%d", i))
	}

	flowA := baseFlow()
	flowA.ReqBody = []byte(strings.Join(linesA, "\n"))
	flowB := baseFlow()
	flowB.ReqBody = []byte(strings.Join(linesB, "\n"))

	c := compare.Compare(flowA, flowB)

	if c.ReqBody.Type != "text_diff" {
		t.Fatalf("ReqBody.Type = %q, want %q", c.ReqBody.Type, "text_diff")
	}
	if !strings.HasSuffix(c.ReqBody.TextDiff, "...") {
		t.Errorf("TextDiff does not end with the truncation marker %q:\n%s", "...", c.ReqBody.TextDiff)
	}
}
