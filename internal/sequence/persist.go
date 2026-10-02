package sequence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Save writes seq to dir as "<sanitized-name>.json", creating dir if it
// doesn't already exist. A later Save with the same Name overwrites it.
func Save(seq *Sequence, dir string) error {
	if seq == nil {
		return errors.New("sequence: seq is nil")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("sequence: create dir %q: %w", dir, err)
	}

	data, err := json.MarshalIndent(seq, "", "  ")
	if err != nil {
		return fmt.Errorf("sequence: marshal %q: %w", seq.Name, err)
	}

	path := filepath.Join(dir, sanitizeName(seq.Name)+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("sequence: write %q: %w", path, err)
	}
	return nil
}

// Load reads back the Sequence previously saved under name in dir.
func Load(name, dir string) (*Sequence, error) {
	path := filepath.Join(dir, sanitizeName(name)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sequence: read %q: %w", path, err)
	}

	var seq Sequence
	if err := json.Unmarshal(data, &seq); err != nil {
		return nil, fmt.Errorf("sequence: unmarshal %q: %w", path, err)
	}
	return &seq, nil
}

// ListSaved returns the names of every sequence saved in dir, sorted
// alphabetically. A dir that doesn't exist yet (nothing saved there so far)
// yields an empty slice rather than an error.
func ListSaved(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("sequence: read dir %q: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	return names, nil
}

// sanitizeName maps a sequence name to a safe filename component, so names
// containing spaces, slashes, or other filesystem-unfriendly characters
// (which flow names or user-chosen sequence names might well contain)
// don't escape dir or fail to write.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "sequence"
	}
	return b.String()
}
