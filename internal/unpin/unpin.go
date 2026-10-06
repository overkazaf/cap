// Package unpin implements SSL/TLS certificate pinning bypass techniques
// for Android applications. Three strategies are provided — Frida-based
// runtime hooking, APK network-security-config patching, and a Magisk
// module for system-wide unpinning — each suited to different device
// states (rooted vs. non-root, Frida available vs. not, etc.).
package unpin

import (
	"os/exec"
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

func which(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
