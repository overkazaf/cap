package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistAndLoadRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "rules.json")
	rules := []*Rule{
		{ID: "one", Name: "One", Enabled: true, Priority: 2},
		{ID: "two", Name: "Two", Priority: 1},
	}
	if err := PersistRules(path, rules); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 || loaded[0].ID != "one" || loaded[1].ID != "two" {
		t.Fatalf("loaded rules = %+v", loaded)
	}
}

func TestLoadRulesMissing(t *testing.T) {
	loaded, err := LoadRules(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Fatalf("loaded = %+v, want empty", loaded)
	}
}

func TestLoadRulesUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"rules":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(path); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestPersistRulesAtomicAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := PersistRules(path, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err == nil {
		for _, entry := range entries {
			if entry.Name() != filepath.Base(path) {
				t.Fatalf("temporary artifact %q leaked", entry.Name())
			}
		}
	}
	var payload struct {
		Version int `json:"version"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != 1 {
		t.Fatalf("version = %d, want 1", payload.Version)
	}
}
