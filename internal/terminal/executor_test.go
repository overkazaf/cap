package terminal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestExecuteRequiresConfirmation(t *testing.T) {
	executor := New("")
	result := executor.Execute(context.Background(), Request{Command: "printf safe"})
	if result.Executed || !errors.Is(result.Err, ErrConfirmationRequired) || result.ConfirmationToken == "" {
		t.Fatalf("result = %+v", result)
	}
	if !strings.Contains(result.Err.Error(), "printf safe") {
		t.Fatalf("error should name the exact command: %v", result.Err)
	}
}

func TestExecuteWithConfirmation(t *testing.T) {
	executor := New("")
	first := executor.Execute(context.Background(), Request{Command: "printf safe"})
	second := executor.Execute(context.Background(), Request{
		Command:           "printf safe",
		Confirm:           true,
		ConfirmationToken: first.ConfirmationToken,
	})
	if !second.Executed || second.Output != "safe" || second.Err != nil {
		t.Fatalf("second = %+v", second)
	}
}

func TestConfirmationTokenOnlyAuthorizesExactCommand(t *testing.T) {
	executor := New("")
	first := executor.Execute(context.Background(), Request{Command: "printf safe"})
	replayed := executor.Execute(context.Background(), Request{
		Command:           "printf unsafe",
		Confirm:           true,
		ConfirmationToken: first.ConfirmationToken,
	})
	if replayed.Executed || !errors.Is(replayed.Err, ErrConfirmationRequired) {
		t.Fatalf("replayed = %+v", replayed)
	}
}

func TestExecuteAllowlisted(t *testing.T) {
	command := "printf safe"
	token := commandToken(command)
	executor := New("")
	result := executor.Execute(context.Background(), Request{
		Command:   command,
		Allowlist: map[string]string{command: token},
	})
	if !result.Executed || result.Output != "safe" || result.Err != nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecuteAllowlistCanonicalizesWhitespace(t *testing.T) {
	command := "printf safe"
	token := commandToken(command)
	executor := New("")
	result := executor.Execute(context.Background(), Request{
		Command:   "  printf   safe  ",
		Allowlist: map[string]string{command: token},
	})
	if !result.Executed || result.Output != "safe" {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecuteTimeout(t *testing.T) {
	executor := New("")
	first := executor.Execute(context.Background(), Request{Command: "sleep 1"})
	result := executor.Execute(context.Background(), Request{
		Command:           "sleep 1",
		Confirm:           true,
		ConfirmationToken: first.ConfirmationToken,
		Timeout:           20 * time.Millisecond,
	})
	if result.Executed || result.Err == nil || !strings.Contains(result.Err.Error(), "timed out") {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecutePreservesEnvironment(t *testing.T) {
	executor := New("")
	command := "printf $CAP_TEST_VALUE"
	first := executor.Execute(context.Background(), Request{Command: command})
	result := executor.Execute(context.Background(), Request{
		Command:           command,
		Confirm:           true,
		ConfirmationToken: first.ConfirmationToken,
		Env:               []string{"CAP_TEST_VALUE=inherited"},
	})
	if result.Output != "inherited" {
		t.Fatalf("output = %q", result.Output)
	}
}

func TestExecuteNilEnvironmentInheritsParent(t *testing.T) {
	t.Setenv("CAP_TEST_VALUE", "parent")
	executor := New("")
	command := "printf $CAP_TEST_VALUE"
	first := executor.Execute(context.Background(), Request{Command: command})
	result := executor.Execute(context.Background(), Request{
		Command:           command,
		Confirm:           true,
		ConfirmationToken: first.ConfirmationToken,
	})
	if result.Output != "parent" {
		t.Fatalf("output = %q", result.Output)
	}
}
