package replay

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/overkazaf/cap/internal/types"
)

// ComputeDiff compares the responses of original and replayed, reporting
// status, header, body and latency differences. It never returns nil: if
// either argument is nil, it returns a zero-value Diff.
func ComputeDiff(original, replayed *types.Flow) *Diff {
	if original == nil || replayed == nil {
		return &Diff{}
	}

	diff := &Diff{
		HeadersDiff: diffHeaders(original.RespHeaders, replayed.RespHeaders),
		BodyDiff:    diffBody(original.RespBody, replayed.RespBody),
		LatencyDiff: absInt64(replayed.LatencyMs - original.LatencyMs),
	}
	if original.Status != replayed.Status {
		diff.StatusChanged = true
		diff.StatusDiff = fmt.Sprintf("%d → %d", original.Status, replayed.Status)
	}
	return diff
}

// diffHeaders reports headers present in exactly one of original/replayed as
// "added"/"removed", and headers present in both with different values as
// "changed". Results are sorted by key for deterministic output.
func diffHeaders(original, replayed map[string]string) []HeaderDiff {
	keySet := make(map[string]struct{}, len(original)+len(replayed))
	for k := range original {
		keySet[k] = struct{}{}
	}
	for k := range replayed {
		keySet[k] = struct{}{}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var diffs []HeaderDiff
	for _, k := range keys {
		ov, inOriginal := original[k]
		rv, inReplayed := replayed[k]
		switch {
		case inOriginal && !inReplayed:
			diffs = append(diffs, HeaderDiff{Key: k, Original: ov, Type: "removed"})
		case !inOriginal && inReplayed:
			diffs = append(diffs, HeaderDiff{Key: k, Replayed: rv, Type: "added"})
		case inOriginal && inReplayed && ov != rv:
			diffs = append(diffs, HeaderDiff{Key: k, Original: ov, Replayed: rv, Type: "changed"})
		}
	}
	return diffs
}

// diffBody compares two response bodies. If both parse as JSON, it reports
// which top-level keys were added, removed or changed; otherwise it falls
// back to a byte-length comparison.
func diffBody(original, replayed []byte) string {
	var originalVal, replayedVal any
	originalIsJSON := json.Unmarshal(original, &originalVal) == nil
	replayedIsJSON := json.Unmarshal(replayed, &replayedVal) == nil

	if originalIsJSON && replayedIsJSON {
		originalMap, origIsObject := originalVal.(map[string]any)
		replayedMap, replIsObject := replayedVal.(map[string]any)
		if origIsObject && replIsObject {
			return diffJSONKeys(originalMap, replayedMap)
		}
		if reflect.DeepEqual(originalVal, replayedVal) {
			return "identical"
		}
		return "JSON value changed"
	}

	switch {
	case len(original) == len(replayed) && string(original) == string(replayed):
		return "identical"
	case len(original) == len(replayed):
		return fmt.Sprintf("same length (%d bytes), content differs", len(original))
	default:
		return fmt.Sprintf("body length changed: %d → %d bytes", len(original), len(replayed))
	}
}

// diffJSONKeys compares two decoded JSON objects' top-level keys, reporting
// which were added, removed, or changed (by deep value comparison).
func diffJSONKeys(original, replayed map[string]any) string {
	var added, removed, changed []string
	for k, rv := range replayed {
		if ov, ok := original[k]; !ok {
			added = append(added, k)
		} else if !reflect.DeepEqual(ov, rv) {
			changed = append(changed, k)
		}
	}
	for k := range original {
		if _, ok := replayed[k]; !ok {
			removed = append(removed, k)
		}
	}
	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		return "identical"
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)

	var parts []string
	if len(added) > 0 {
		parts = append(parts, "added: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "removed: "+strings.Join(removed, ", "))
	}
	if len(changed) > 0 {
		parts = append(parts, "changed: "+strings.Join(changed, ", "))
	}
	return strings.Join(parts, "; ")
}

// absInt64 returns the absolute value of n.
func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
