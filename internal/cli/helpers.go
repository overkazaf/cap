package cli

import (
	"os"
	"path/filepath"

	"github.com/overkazaf/cap/internal/store/sqlite"
)

// defaultCapDir returns cap's default data directory, "~/.cap", falling
// back to a directory under the OS temp dir if the home directory can't be
// determined. It is used as the default location for both the flow
// database and the MITM CA certificate, matching internal/proxy's own
// default (see proxy.Options.CertDir) so a bare `cap start` and
// `cap android connect` agree on where the CA lives.
func defaultCapDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cap")
	}
	return filepath.Join(os.TempDir(), "cap")
}

// defaultDBPath returns the default flow database path, "~/.cap/flows.db".
func defaultDBPath() string {
	return filepath.Join(defaultCapDir(), "flows.db")
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
