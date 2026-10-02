package sqlite

import (
	"encoding/json"

	"github.com/overkazaf/cap/internal/types"
)

// marshalJSON encodes v (a map or slice field of types.Flow) as a JSON
// string for storage in a TEXT column. A nil map or slice encodes as the
// JSON literal "null", which round-trips back to nil on read.
func marshalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// unmarshalJSON decodes a TEXT column previously written by marshalJSON into
// dst. An empty string is tolerated as "null" so that rows without our usual
// defaults still scan cleanly.
func unmarshalJSON(s string, dst any) error {
	if s == "" {
		s = "null"
	}
	return json.Unmarshal([]byte(s), dst)
}

// marshalSourceRef encodes ref for the nullable source_ref column. A nil ref
// maps to SQL NULL (not the JSON literal "null"), so GetFlow round-trips an
// absent reference back to a nil *types.SourceRef rather than a non-nil
// pointer to a zero-value SourceRef.
func marshalSourceRef(ref *types.SourceRef) (any, error) {
	if ref == nil {
		return nil, nil
	}
	b, err := json.Marshal(ref)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// unmarshalSourceRef decodes a non-NULL source_ref column value.
func unmarshalSourceRef(s string) (*types.SourceRef, error) {
	var ref types.SourceRef
	if err := json.Unmarshal([]byte(s), &ref); err != nil {
		return nil, err
	}
	return &ref, nil
}
