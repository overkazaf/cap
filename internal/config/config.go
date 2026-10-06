// Package config provides shared configuration defaults for cap.
// All components (proxy, CLI, GUI) should use these rather than
// duplicating path logic.
package config

import (
	"os"
	"path/filepath"
)

// DefaultDir returns cap's data directory, "~/.cap", falling back to
// a directory under the OS temp dir if the home directory can't be
// determined.
func DefaultDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cap")
	}
	return filepath.Join(os.TempDir(), "cap")
}

// DefaultDBPath returns the default flow database path, "~/.cap/flows.db".
func DefaultDBPath() string {
	return filepath.Join(DefaultDir(), "flows.db")
}
