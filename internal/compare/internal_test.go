package compare

import (
	"encoding/json"
	"testing"
)

// TestFlattenJSON is a white-box test of the unexported flattenJSON helper,
// pinning down the exact dot-path flattening described in the package docs:
// {"a": {"b": 1}} flattens to {"a.b": "1"}.
func TestFlattenJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "nested object",
			input: `{"a": {"b": 1}}`,
			want:  map[string]string{"a.b": "1"},
		},
		{
			name:  "flat object",
			input: `{"x": 1, "y": "two", "z": true}`,
			want:  map[string]string{"x": "1", "y": "two", "z": "true"},
		},
		{
			name:  "null value",
			input: `{"a": null}`,
			want:  map[string]string{"a": "null"},
		},
		{
			name:  "array flattens with numeric indices",
			input: `{"items": [10, 20]}`,
			want:  map[string]string{"items.0": "10", "items.1": "20"},
		},
		{
			name:  "deeply nested",
			input: `{"a": {"b": {"c": "deep"}}}`,
			want:  map[string]string{"a.b.c": "deep"},
		},
		{
			name:  "decimal number",
			input: `{"a": 1.5}`,
			want:  map[string]string{"a": "1.5"},
		},
		{
			name:  "empty nested object and array",
			input: `{"meta": {}, "tags": []}`,
			want:  map[string]string{"meta": "{}", "tags": "[]"},
		},
		{
			name:  "top-level bare scalar",
			input: `"hello"`,
			want:  map[string]string{"$": "hello"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v any
			if err := json.Unmarshal([]byte(tt.input), &v); err != nil {
				t.Fatalf("json.Unmarshal(%q): %v", tt.input, err)
			}

			got := map[string]string{}
			flattenJSON("", v, got)

			if len(got) != len(tt.want) {
				t.Fatalf("flattenJSON(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for k, wantV := range tt.want {
				if gotV, ok := got[k]; !ok || gotV != wantV {
					t.Errorf("flattenJSON(%q)[%q] = %q, want %q", tt.input, k, gotV, wantV)
				}
			}
		})
	}
}
