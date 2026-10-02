package compare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxTextDiffLines caps how many differing-line entries textLineDiff emits,
// so comparing two large text bodies doesn't produce unbounded output.
const maxTextDiffLines = 40

// compareBody classifies and diffs a request or response body:
//
//   - Identical bytes (including both empty/nil) -> Type "identical".
//   - Otherwise, if both sides parse as JSON -> Type "json_diff", with a
//     key-path-level diff in JSONDiff (see diffJSONValues).
//   - Otherwise, if both sides look like text (valid UTF-8 without binary
//     control bytes) -> Type "text_diff", with a line-level summary in
//     TextDiff (see textLineDiff).
//   - Otherwise (at least one side is binary) -> Type "binary_diff", with
//     only the sizes compared.
func compareBody(a, b []byte) BodyDiff {
	bd := BodyDiff{SizeA: len(a), SizeB: len(b)}

	if bytes.Equal(a, b) {
		bd.Type = "identical"
		return bd
	}

	if valA, ok := parseJSON(a); ok {
		if valB, ok := parseJSON(b); ok {
			bd.Type = "json_diff"
			bd.JSONDiff = diffJSONValues(valA, valB)
			return bd
		}
	}

	if isTextBody(a) && isTextBody(b) {
		bd.Type = "text_diff"
		bd.TextDiff = textLineDiff(a, b)
		return bd
	}

	bd.Type = "binary_diff"
	return bd
}

// parseJSON attempts to decode data as a single JSON value. Empty input is
// treated as "not JSON" (rather than an error) so an empty body falls
// through to the text/binary path instead of masquerading as JSON.
func parseJSON(data []byte) (any, bool) {
	if len(data) == 0 {
		return nil, false
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, false
	}
	return v, true
}

// isTextBody reports whether data looks like text worth line-diffing: valid
// UTF-8 containing no control bytes other than tab, LF, VT, FF and CR. An
// empty body counts as text.
func isTextBody(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	for _, b := range data {
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			return false
		}
	}
	return true
}

// textLineDiff produces a compact, human-readable line-by-line diff between
// two text bodies, unified-diff-style: "-N: old" for a line only in (or
// different in) a, "+N: new" for a line only in (or different in) b, both
// 1-indexed. Output is capped at maxTextDiffLines entries.
func textLineDiff(a, b []byte) string {
	linesA := strings.Split(string(a), "\n")
	linesB := strings.Split(string(b), "\n")

	max := len(linesA)
	if len(linesB) > max {
		max = len(linesB)
	}

	var out []string
	for i := 0; i < max; i++ {
		hasA := i < len(linesA)
		hasB := i < len(linesB)
		var la, lb string
		if hasA {
			la = linesA[i]
		}
		if hasB {
			lb = linesB[i]
		}
		if hasA && hasB && la == lb {
			continue
		}
		if hasA {
			out = append(out, fmt.Sprintf("-%d: %s", i+1, la))
		}
		if hasB {
			out = append(out, fmt.Sprintf("+%d: %s", i+1, lb))
		}
		if len(out) >= maxTextDiffLines {
			out = append(out, "...")
			break
		}
	}
	return strings.Join(out, "\n")
}

// diffJSONValues flattens a and b (see flattenJSON) and compares the
// resulting flat maps by key, reporting paths added, removed, or changed.
func diffJSONValues(a, b any) *JSONDiff {
	flatA := map[string]string{}
	flattenJSON("", a, flatA)
	flatB := map[string]string{}
	flattenJSON("", b, flatB)

	added := []string{}
	removed := []string{}
	changed := []JSONChange{}

	for _, k := range unionStringKeys(flatA, flatB) {
		va, inA := flatA[k]
		vb, inB := flatB[k]
		switch {
		case inA && !inB:
			removed = append(removed, k)
		case !inA && inB:
			added = append(added, k)
		case va != vb:
			changed = append(changed, JSONChange{Path: k, ValueA: va, ValueB: vb})
		}
	}

	return &JSONDiff{Added: added, Removed: removed, Changed: changed}
}

// flattenJSON flattens an arbitrary decoded JSON value (as produced by
// encoding/json's default decoding into `any`) into dot-path keys mapped to
// their scalar string representation, e.g. {"a":{"b":1}} becomes
// {"a.b": "1"}. Arrays flatten with numeric index segments, e.g.
// {"a":[1,2]} becomes {"a.0": "1", "a.1": "2"}. prefix is the path built up
// so far and should be "" for the top-level call; out accumulates results
// and must be non-nil.
func flattenJSON(prefix string, value any, out map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		if len(v) == 0 {
			out[rootPath(prefix)] = "{}"
			return
		}
		for key, child := range v {
			flattenJSON(joinPath(prefix, key), child, out)
		}
	case []any:
		if len(v) == 0 {
			out[rootPath(prefix)] = "[]"
			return
		}
		for i, child := range v {
			flattenJSON(joinPath(prefix, strconv.Itoa(i)), child, out)
		}
	default:
		out[rootPath(prefix)] = jsonScalarString(v)
	}
}

// joinPath appends key to prefix with a "." separator, or returns key alone
// when prefix is empty (the top-level call).
func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// rootPath returns prefix, or "$" when prefix is empty — the edge case of
// the whole body being a bare scalar or an empty object/array rather than an
// object with named fields.
func rootPath(prefix string) string {
	if prefix == "" {
		return "$"
	}
	return prefix
}

// jsonScalarString renders a decoded JSON scalar — string, float64, bool, or
// nil, the only scalar types encoding/json produces when decoding into `any`
// — as the string stored in a JSONDiff value. Whole-number floats render
// without a trailing decimal point (1, not 1e+00 or 1.0), so
// {"a":{"b":1}} flattens to {"a.b": "1"} as documented.
func jsonScalarString(v any) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(val)
	case string:
		return val
	case float64:
		if val == math.Trunc(val) && !math.IsInf(val, 0) && math.Abs(val) < 1e15 {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'g', -1, 64)
	default:
		// Unreachable for values encoding/json decodes into `any`: those are
		// exactly the types handled above, plus map[string]any/[]any, which
		// flattenJSON handles itself before ever calling this function.
		return fmt.Sprintf("%v", val)
	}
}
