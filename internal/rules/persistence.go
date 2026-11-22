package rules

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/overkazaf/cap/internal/fsutil"
)

const persistenceFormatVersion = 1

type persistedRules struct {
	Version int     `json:"version"`
	Rules   []*Rule `json:"rules"`
}

// LoadRules reads rules atomically-written by PersistRules. Unknown future
// versions are rejected rather than silently downgraded.
func LoadRules(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("rules: load: %w", err)
	}

	var persisted persistedRules
	if err := json.Unmarshal(data, &persisted); err != nil {
		return nil, fmt.Errorf("rules: decode %q: %w", path, err)
	}
	if persisted.Version > persistenceFormatVersion {
		return nil, fmt.Errorf("rules: %q uses unsupported format version %d", path, persisted.Version)
	}
	rules := make([]*Rule, len(persisted.Rules))
	copy(rules, persisted.Rules)
	return rules, nil
}

// PersistRules atomically replaces path with rules. Nil rules are preserved
// because Rule contains no interface or function fields.
func PersistRules(path string, rules []*Rule) error {
	persisted := persistedRules{
		Version: persistenceFormatVersion,
		Rules:   append([]*Rule(nil), rules...),
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("rules: encode: %w", err)
	}
	data = append(data, '\n')
	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return fmt.Errorf("rules: persist %q: %w", path, err)
	}
	return nil
}
