package terminal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAllowlistEntries(t *testing.T) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	if strings.Contains(shell, "fish") {
		t.Skip("shell.Fields uses POSIX syntax")
	}
	allowlist, err := ParseAllowlistEntries([]string{"printf safe", "  printf   safe  "})
	if err != nil {
		t.Fatal(err)
	}
	if len(allowlist) != 1 {
		t.Fatalf("allowlist = %#v", allowlist)
	}
	token, ok := allowlist["printf safe"]
	if !ok || token == "" {
		t.Fatalf("allowlist = %#v", allowlist)
	}
}

func TestParseAllowlistEntriesRejectsMetacharacters(t *testing.T) {
	for _, command := range []string{"echo a; echo b", "echo a | cat", "echo a && echo b", "echo $HOME", "echo `id`", "echo\nid", "echo a\rid"} {
		if _, err := ParseAllowlistEntries([]string{command}); err == nil {
			t.Fatalf("expected error for %q", command)
		}
	}
}

func TestParseAllowlistEntriesRejectsMissingExecutable(t *testing.T) {
	if _, err := ParseAllowlistEntries([]string{"cap-definitely-missing --version"}); err == nil {
		t.Fatal("expected missing executable error")
	}
}

func TestParseAllowlistEntriesAbsoluteExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	allowlist, err := ParseAllowlistEntries([]string{path + " --version"})
	if err != nil {
		t.Fatal(err)
	}
	if len(allowlist) != 1 {
		t.Fatalf("allowlist = %#v", allowlist)
	}
}
