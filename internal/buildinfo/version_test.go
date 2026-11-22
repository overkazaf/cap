package buildinfo

import "testing"

func TestVersion(t *testing.T) {
	if got := Version(); got == "" {
		t.Fatal("Version() returned an empty string")
	}
}
