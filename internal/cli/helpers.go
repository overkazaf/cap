package cli

import (
	"os"
	"path/filepath"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/store/sqlite"
)

// defaultCapDir returns cap's default data directory.
func defaultCapDir() string {
	return config.DefaultDir()
}

// defaultDBPath returns the default flow database path.
func defaultDBPath() string {
	return config.DefaultDBPath()
}

// openStore opens the SQLite-backed flow store at dbPath, defaulting to
// defaultDBPath() when dbPath is empty. The database's containing directory
// is created if it doesn't already exist.
func openStore(dbPath string) (*sqlite.SQLiteStore, error) {
	if dbPath == "" {
		dbPath = defaultDBPath()
	}

	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}

	return sqlite.New(dbPath)
}
