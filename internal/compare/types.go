// Package compare produces a structured, side-by-side diff of two captured
// flows. It powers cap's "compare" feature, which lets a reverse engineer
// line up two requests — e.g. the same endpoint hit before and after a
// client update, or a legitimate call next to a replayed/modified one — and
// see exactly what changed: URL, method, status, headers, bodies and
// latency.
//
// The package has no dependencies beyond the standard library and
// internal/types.
package compare

// Comparison is the structured result of comparing two flows. See Compare.
type Comparison struct {
	// FlowA and FlowB identify the two flows that were compared (their
	// types.Flow.ID), so a caller can tell which side is which without
	// holding on to the original *types.Flow values.
	FlowA string `json:"flow_a"`
	FlowB string `json:"flow_b"`

	URL    LineDiff `json:"url"`
	Method LineDiff `json:"method"`
	Status LineDiff `json:"status"`

	// Headers covers both request and response headers: Compare diffs each
	// set independently (request headers, then response headers) and merges
	// the two results here, since Comparison exposes a single Headers field.
	Headers HeadersDiff `json:"headers"`

	ReqBody  BodyDiff `json:"req_body"`
	RespBody BodyDiff `json:"resp_body"`

	Latency LatencyDiff `json:"latency"`

	// Summary is a short, human-readable description of the comparison,
	// e.g. "3 header diffs, body changed, status same". It is derived from
	// the fields above and is meant for a one-line display; inspect the
	// structured fields for details.
	Summary string `json:"summary"`
}

// LineDiff is a simple two-sided value comparison, used for fields that are
// either equal or not (URL, method, status).
type LineDiff struct {
	A       string `json:"a"`
	B       string `json:"b"`
	Changed bool   `json:"changed"`
}

// KV is a single header's key and value.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// HeaderChange describes a header key present on both sides with different
// values.
type HeaderChange struct {
	Key    string `json:"key"`
	ValueA string `json:"value_a"`
	ValueB string `json:"value_b"`
}

// HeadersDiff reports how a set of headers (or, for Comparison.Headers, two
// sets — request and response — merged together) differs between A and B.
// Added, Removed and Changed are sorted by key and are never nil (an empty
// slice, not null, when there is nothing to report), so callers can range
// over them unconditionally and the JSON encoding is always an array.
type HeadersDiff struct {
	Added   []KV           `json:"added"`   // present in B but not A
	Removed []KV           `json:"removed"` // present in A but not B
	Changed []HeaderChange `json:"changed"` // same key, different value
	Same    int            `json:"same"`    // count of headers identical in both
}

// JSONChange describes a flattened JSON dot-path present on both sides with
// a different scalar value. See JSONDiff.
type JSONChange struct {
	Path   string `json:"path"`
	ValueA string `json:"value_a"`
	ValueB string `json:"value_b"`
}

// JSONDiff reports how two JSON documents differ, at the level of flattened
// dot-path keys (see flattenJSON): Added and Removed list paths present on
// only one side, Changed lists paths present on both sides with a different
// scalar value. All three are sorted by path and never nil.
type JSONDiff struct {
	Added   []string     `json:"added"`   // paths present in B but not A
	Removed []string     `json:"removed"` // paths present in A but not B
	Changed []JSONChange `json:"changed"`
}

// BodyDiff classifies and, where possible, details how a request or
// response body differs between A and B.
type BodyDiff struct {
	// Type is one of "identical", "json_diff", "text_diff" or
	// "binary_diff" — see compareBody for exactly how each is chosen.
	Type  string `json:"type"`
	SizeA int    `json:"size_a"`
	SizeB int    `json:"size_b"`

	// JSONDiff is set only when Type is "json_diff".
	JSONDiff *JSONDiff `json:"json_diff,omitempty"`
	// TextDiff is set only when Type is "text_diff": a compact,
	// line-oriented summary of the differing lines.
	TextDiff string `json:"text_diff,omitempty"`
}

// LatencyDiff compares the LatencyMs of two flows.
type LatencyDiff struct {
	A      int64 `json:"a"`
	B      int64 `json:"b"`
	DiffMs int64 `json:"diff_ms"` // B - A; positive means B was slower

	// Percent is DiffMs expressed as a percentage of A, rounded to the
	// nearest whole percent and formatted with an explicit sign, e.g.
	// "+25%", "-10%", "0%". When A is 0 a ratio is undefined; Percent is
	// then "0%" if B is also 0, or "+inf%"/"-inf%" otherwise.
	Percent string `json:"percent"`
}
