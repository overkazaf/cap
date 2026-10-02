package compare

import (
	"sort"

	"github.com/overkazaf/cap/internal/types"
)

// compareHeaders diffs flowA's and flowB's headers, covering both the
// request and response header sets. Comparison exposes a single Headers
// field, so the two independent diffs (request headers, then response
// headers) are merged into one HeadersDiff: Added/Removed/Changed are
// concatenated (request-header entries first, each internally sorted by
// key) and Same is their combined count.
func compareHeaders(flowA, flowB *types.Flow) HeadersDiff {
	req := diffHeaderSet(flowA.ReqHeaders, flowB.ReqHeaders)
	resp := diffHeaderSet(flowA.RespHeaders, flowB.RespHeaders)

	return HeadersDiff{
		Added:   append(req.Added, resp.Added...),
		Removed: append(req.Removed, resp.Removed...),
		Changed: append(req.Changed, resp.Changed...),
		Same:    req.Same + resp.Same,
	}
}

// diffHeaderSet compares a single pair of header maps (e.g. just the request
// headers, or just the response headers), reporting keys present in only one
// side as added/removed and keys present in both with different values as
// changed. Results are sorted by key for deterministic output. The returned
// slices are always non-nil, freshly allocated and safe for the caller to
// append to.
func diffHeaderSet(a, b map[string]string) HeadersDiff {
	added := []KV{}
	removed := []KV{}
	changed := []HeaderChange{}
	same := 0

	for _, k := range unionStringKeys(a, b) {
		va, inA := a[k]
		vb, inB := b[k]
		switch {
		case inA && !inB:
			removed = append(removed, KV{Key: k, Value: va})
		case !inA && inB:
			added = append(added, KV{Key: k, Value: vb})
		case va == vb:
			same++
		default:
			changed = append(changed, HeaderChange{Key: k, ValueA: va, ValueB: vb})
		}
	}

	return HeadersDiff{Added: added, Removed: removed, Changed: changed, Same: same}
}

// unionStringKeys returns the sorted union of a's and b's keys. Sorting
// makes the result deterministic despite Go's randomized map iteration
// order, which matters both for stable output and for stable tests.
func unionStringKeys(a, b map[string]string) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		set[k] = struct{}{}
	}
	for k := range b {
		set[k] = struct{}{}
	}

	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
