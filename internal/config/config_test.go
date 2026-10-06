package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultDir(t *testing.T) {
	dir := DefaultDir()
	if dir == "" {
		t.Fatal("DefaultDir() returned empty")
	}
	if !strings.HasSuffix(dir, filepath.Join(".cap")) {
		// Even in the tempdir fallback case, it should end with "cap"
		if !strings.HasSuffix(dir, "cap") {
			t.Errorf("DefaultDir() = %q, expected path ending in 'cap' or '.cap'", dir)
		}
	}
}

func TestDefaultDBPath(t *testing.T) {
	dbPath := DefaultDBPath()
	if !strings.HasSuffix(dbPath, "flows.db") {
		t.Errorf("DefaultDBPath() = %q, expected to end with flows.db", dbPath)
	}
	if !strings.Contains(dbPath, DefaultDir()) {
		t.Errorf("DefaultDBPath() = %q, expected to contain DefaultDir() = %q", dbPath, DefaultDir())
	}
}

func TestDefaultDirUsesHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}
	dir := DefaultDir()
	if dir != filepath.Join(home, ".cap") {
		t.Errorf("DefaultDir() = %q, want %q", dir, filepath.Join(home, ".cap"))
	}
}
