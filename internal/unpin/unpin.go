// Package unpin implements SSL/TLS certificate pinning bypass techniques
// for Android applications. Three strategies are provided — Frida-based
// runtime hooking, APK network-security-config patching, and a Magisk
// module for system-wide unpinning — each suited to different device
// states (rooted vs. non-root, Frida available vs. not, etc.).
package unpin

import (
	"fmt"
	"os/exec"
	"strings"
)

// Method identifies which unpinning strategy to use.
type Method int

const (
	MethodFrida  Method = iota // Runtime hooking via Frida
	MethodPatch                // APK network_security_config patching
	MethodMagisk               // Magisk module (system-wide)
)

func (m Method) String() string {
	switch m {
	case MethodFrida:
		return "frida"
	case MethodPatch:
		return "patch"
	case MethodMagisk:
		return "magisk"
	default:
		return "unknown"
	}
}

// Result carries the outcome of an unpinning operation.
type Result struct {
	Method  Method
	Success bool
	Message string
	Output  string // path to patched APK, deployed script, etc.
}

func adbCmd(serial string, args ...string) (string, error) {
	full := make([]string, 0, len(args)+2)
	if serial != "" {
		full = append(full, "-s", serial)
	}
	full = append(full, args...)
	out, err := exec.Command("adb", full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func adbShell(serial, cmd string) (string, error) {
	return adbCmd(serial, "shell", cmd)
}

func suShell(serial, cmd string) (string, error) {
	return adbShell(serial, fmt.Sprintf("su -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''")))
}

func which(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
