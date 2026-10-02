package sequence_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/sequence"
)

// TestSaveLoad saves a Sequence to a temp directory and loads it back,
// checking that every field — including nested Steps, their Extract rules,
// and seeded Variables — round-trips unchanged.
func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()

	original := &sequence.Sequence{
		Name: "login-and-fetch",
		Steps: []sequence.Step{
			{
				FlowID: "f1",
				Method: "POST",
				URL:    "https://api.example.com/login",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: []byte(`{"user":"alice"}`),
				Extract: []sequence.Extraction{
					{Name: "token", Source: "body_json", Path: "data.token"},
					{Name: "cookie", Source: "cookie"},
				},
			},
			{
				FlowID: "f2",
				Method: "GET",
				URL:    "https://api.example.com/data",
				Headers: map[string]string{
					"Authorization": "Bearer {{token}}",
				},
			},
		},
		Variables: []sequence.Variable{
			{Name: "token", Value: ""},
		},
		CreatedAt: time.Now(),
	}

	if err := sequence.Save(original, dir); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	loaded, err := sequence.Load(original.Name, dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if loaded.Name != original.Name {
		t.Errorf("loaded.Name = %q, want %q", loaded.Name, original.Name)
	}
	// time.Time carries a monotonic reading that a JSON round-trip strips,
	// so compare wall-clock equality rather than reflect.DeepEqual-ing the
	// whole struct (which would spuriously fail on the monotonic field).
	if !loaded.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("loaded.CreatedAt = %v, want %v", loaded.CreatedAt, original.CreatedAt)
	}
	if !reflect.DeepEqual(loaded.Steps, original.Steps) {
		t.Errorf("loaded.Steps = %+v, want %+v", loaded.Steps, original.Steps)
	}
	if !reflect.DeepEqual(loaded.Variables, original.Variables) {
		t.Errorf("loaded.Variables = %+v, want %+v", loaded.Variables, original.Variables)
	}
}

// TestLoadMissing checks that loading a sequence that was never saved
// returns an error instead of a zero-value Sequence.
func TestLoadMissing(t *testing.T) {
	dir := t.TempDir()

	if _, err := sequence.Load("does-not-exist", dir); err == nil {
		t.Error("Load returned nil error for a sequence that was never saved")
	}
}

// TestLoadCorrupted checks that loading a file that isn't valid JSON
// returns an error instead of a zero-value or partially-populated Sequence.
func TestLoadCorrupted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("failed to write corrupted fixture: %v", err)
	}

	if _, err := sequence.Load("broken", dir); err == nil {
		t.Error("Load returned nil error for a corrupted file")
	}
}

// TestSaveLoadSanitizesName checks that a sequence name containing
// filesystem-unfriendly characters (spaces, slashes, ...) is still saved
// and loaded correctly, as a single file directly inside dir.
func TestSaveLoadSanitizesName(t *testing.T) {
	dir := t.TempDir()
	original := &sequence.Sequence{Name: "my seq/v2!", CreatedAt: time.Now()}

	if err := sequence.Save(original, dir); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	loaded, err := sequence.Load(original.Name, dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded.Name != original.Name {
		t.Errorf("loaded.Name = %q, want %q", loaded.Name, original.Name)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want exactly 1 saved file, got %v", len(entries), entries)
	}
}

// TestSaveLoadEmptyName checks that an empty sequence name — which
// sanitizes to no characters at all — still round-trips through a
// deterministic fallback filename rather than failing.
func TestSaveLoadEmptyName(t *testing.T) {
	dir := t.TempDir()
	original := &sequence.Sequence{Name: "", CreatedAt: time.Now()}

	if err := sequence.Save(original, dir); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	loaded, err := sequence.Load("", dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded.Name != "" {
		t.Errorf("loaded.Name = %q, want empty", loaded.Name)
	}
}

// TestListSaved checks that ListSaved reports every saved sequence's name,
// sorted, regardless of the order they were saved in.
func TestListSaved(t *testing.T) {
	dir := t.TempDir()

	toSave := []string{"seq-two", "seq-one", "seq-three"}
	for _, n := range toSave {
		seq := &sequence.Sequence{Name: n, CreatedAt: time.Now()}
		if err := sequence.Save(seq, dir); err != nil {
			t.Fatalf("Save(%q) returned error: %v", n, err)
		}
	}

	got, err := sequence.ListSaved(dir)
	if err != nil {
		t.Fatalf("ListSaved returned error: %v", err)
	}

	want := []string{"seq-one", "seq-three", "seq-two"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListSaved() = %v, want %v", got, want)
	}
}

// TestListSavedSkipsNonSequenceEntries checks that ListSaved reports only
// the ".json" files it saved itself, ignoring unrelated files and
// subdirectories that might also live in dir.
func TestListSavedSkipsNonSequenceEntries(t *testing.T) {
	dir := t.TempDir()

	if err := sequence.Save(&sequence.Sequence{Name: "real-one"}, dir); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("failed to write stray file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir.json"), 0o755); err != nil {
		t.Fatalf("failed to create stray subdirectory: %v", err)
	}

	got, err := sequence.ListSaved(dir)
	if err != nil {
		t.Fatalf("ListSaved returned error: %v", err)
	}

	want := []string{"real-one"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListSaved() = %v, want %v", got, want)
	}
}

// TestListSavedEmptyDir checks that listing a directory with nothing saved
// yet returns an empty (non-nil-error) result rather than failing — the
// natural state before any sequence has been saved.
func TestListSavedEmptyDir(t *testing.T) {
	dir := t.TempDir()

	got, err := sequence.ListSaved(dir)
	if err != nil {
		t.Fatalf("ListSaved returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ListSaved() = %v, want empty", got)
	}
}

// TestListSavedDirDoesNotExist checks that ListSaved tolerates a directory
// that has never been created at all (not merely empty), which is the
// state of a fresh install before any sequence has ever been saved there.
func TestListSavedDirDoesNotExist(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never-created")

	got, err := sequence.ListSaved(dir)
	if err != nil {
		t.Fatalf("ListSaved returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ListSaved() = %v, want empty", got)
	}
}

// TestSaveFailsWhenParentPathIsBlocked checks that Save surfaces an error
// (rather than panicking) when one of dir's parent path components already
// exists as a regular file, so the directory tree cannot be created.
func TestSaveFailsWhenParentPathIsBlocked(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("failed to write blocking file: %v", err)
	}
	dir := filepath.Join(blocker, "nested")

	if err := sequence.Save(&sequence.Sequence{Name: "whatever"}, dir); err == nil {
		t.Error("Save returned nil error when dir's parent is a file, want an error")
	}
}

// TestSaveFailsWhenTargetIsDirectory checks that Save surfaces an error
// when the destination filename is already occupied by a directory, rather
// than silently doing nothing or panicking.
func TestSaveFailsWhenTargetIsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "taken.json"), 0o755); err != nil {
		t.Fatalf("failed to create blocking directory: %v", err)
	}

	if err := sequence.Save(&sequence.Sequence{Name: "taken"}, dir); err == nil {
		t.Error("Save returned nil error when its target path is a directory, want an error")
	}
}
