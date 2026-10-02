package sqlite

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestFileBackedPragmas is a white-box test (package sqlite, not sqlite_test)
// so it can read back the live PRAGMA state through the unexported *sql.DB.
// It verifies New() actually engages WAL mode and the requested
// busy_timeout for a real file-backed database. A ":memory:" database
// silently downgrades journal_mode=WAL to "memory" (there's no shared file
// to put a WAL on), so only a real file can exercise this path.
func TestFileBackedPragmas(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "flows.db")

	s, err := New(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode;").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}

	var timeout int
	if err := s.db.QueryRow("PRAGMA busy_timeout;").Scan(&timeout); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if timeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", timeout)
	}
}
