package terminal

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var shellMetacharacters = ";|&$\n\r`"

// ParseAllowlistEntries validates exact shell commands and returns their
// persisted {canonical-command: token} map. Every entry must start with an
// executable that exists on PATH (or an absolute path) and contain no shell
// metacharacters; arguments are still shell-parsed, so quoting must be valid.
func ParseAllowlistEntries(commands []string) (map[string]string, error) {
	allowlist := make(map[string]string, len(commands))
	for _, command := range commands {
		if strings.ContainsAny(command, shellMetacharacters) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidEntry, command)
		}
		canonical := canonicalCommand(command)
		if canonical == "" {
			continue
		}
		fields, err := splitShellFields(canonical)
		if err != nil || len(fields) == 0 {
			return nil, fmt.Errorf("%w: %q", ErrInvalidEntry, canonical)
		}
		if strings.Contains(fields[0], "/") {
			if info, err := os.Stat(fields[0]); err != nil || info.IsDir() {
				return nil, fmt.Errorf("%w: %q", ErrInvalidEntry, canonical)
			}
		} else if _, err := exec.LookPath(fields[0]); err != nil {
			return nil, fmt.Errorf("%w: %q", ErrInvalidEntry, canonical)
		}
		digest := sha256.Sum256([]byte(canonical))
		allowlist[canonical] = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	return allowlist, nil
}

func splitShellFields(input string) ([]string, error) {
	var fields []string
	var field strings.Builder
	var escaped, singleQuoted, doubleQuoted bool
	flush := func() {
		if field.Len() > 0 {
			fields = append(fields, field.String())
			field.Reset()
		}
	}

	for index := 0; index < len(input); index++ {
		char := input[index]
		if escaped {
			field.WriteByte(char)
			escaped = false
			continue
		}
		switch char {
		case '\\':
			escaped = true
		case '\'':
			if !doubleQuoted {
				singleQuoted = !singleQuoted
			} else {
				field.WriteByte(char)
			}
		case '"':
			if !singleQuoted {
				doubleQuoted = !doubleQuoted
			} else {
				field.WriteByte(char)
			}
		case ' ', '\t':
			if singleQuoted || doubleQuoted {
				field.WriteByte(char)
			} else {
				flush()
			}
		default:
			field.WriteByte(char)
		}
	}
	if escaped || singleQuoted || doubleQuoted {
		return nil, ErrInvalidEntry
	}
	flush()
	return fields, nil
}
