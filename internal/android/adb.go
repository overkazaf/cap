// Package android implements one-command Android device setup for HTTP(S)
// traffic capture: discovering connected ADB devices, pointing the
// device-wide Wi-Fi proxy at cap, and installing cap's CA certificate into
// the device's trust store so intercepted HTTPS is trusted.
//
// All device interaction goes through the `adb` binary via os/exec — there
// is no direct ADB protocol implementation here.
package android

import (
	"fmt"
	"os/exec"
	"strings"
)

// Device is a single entry reported by `adb devices`.
type Device struct {
	Serial string
	State  string // "device", "unauthorized", "offline"
}

// SetupOptions configures Setup.
type SetupOptions struct {
	ProxyHost   string // host IP the device connects to (auto-detect if empty)
	ProxyPort   string // cap's proxy port
	Serial      string // specific device serial (empty = auto-detect first)
	CACertPath  string // path to CA cert file
	InstallCert bool   // whether to push cert
}

// ParseDeviceList parses the output of `adb devices`. The banner line
// ("List of devices attached"), blank lines, and ADB server/daemon status
// lines (which start with "*", e.g. "* daemon started successfully") are
// ignored. Every remaining well-formed "<serial>\t<state>" line is
// returned regardless of state, so callers can tell a ready "device" apart
// from "unauthorized" or "offline" entries.
func ParseDeviceList(output string) []Device {
	var devices []Device
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of") || strings.HasPrefix(line, "*") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		devices = append(devices, Device{Serial: fields[0], State: fields[1]})
	}
	return devices
}

// ParseProxySetting parses the value returned by
// `adb shell settings get global http_proxy`. Android reports an unset
// proxy as the literal string "null", and cap itself clears the proxy by
// writing ":0" (see Teardown); an empty string is also treated as unset.
// Any other value is expected to be "host:port".
func ParseProxySetting(setting string) (host, port string) {
	setting = strings.TrimSpace(setting)
	if setting == "" || setting == "null" || setting == ":0" {
		return "", ""
	}
	idx := strings.LastIndex(setting, ":")
	switch {
	case idx < 0:
		return setting, ""
	case idx == len(setting)-1:
		return setting[:idx], ""
	default:
		return setting[:idx], setting[idx+1:]
	}
}

// ListDevices runs `adb devices` and parses the result.
func ListDevices() ([]Device, error) {
	out, err := adbCmd("", "devices")
	if err != nil {
		return nil, fmt.Errorf("adb devices: %w", err)
	}
	return ParseDeviceList(out), nil
}

// GetDeviceSerial resolves which device to operate on. If preferred is
// non-empty, it must match a connected device, and that device must be in
// "device" state. Otherwise the first connected device in "device" state
// is used. A device present but unauthorized/offline produces a clear,
// actionable error rather than being silently skipped when explicitly
// requested.
func GetDeviceSerial(preferred string) (string, error) {
	devices, err := ListDevices()
	if err != nil {
		return "", err
	}
	if len(devices) == 0 {
		return "", fmt.Errorf("no Android device connected (check `adb devices`)")
	}

	if preferred != "" {
		for _, d := range devices {
			if d.Serial != preferred {
				continue
			}
			if d.State != "device" {
				return "", fmt.Errorf("device %s is %s, not ready (check `adb devices`)", d.Serial, d.State)
			}
			return d.Serial, nil
		}
		return "", fmt.Errorf("device %q not found (check `adb devices`)", preferred)
	}

	for _, d := range devices {
		if d.State == "device" {
			return d.Serial, nil
		}
	}
	return "", fmt.Errorf("no ready device found, connected: %+v", devices)
}

// adbCmd runs `adb [-s serial] args...` and returns combined stdout+stderr,
// trimmed of surrounding whitespace. serial may be empty to omit -s.
func adbCmd(serial string, args ...string) (string, error) {
	full := make([]string, 0, len(args)+2)
	if serial != "" {
		full = append(full, "-s", serial)
	}
	full = append(full, args...)

	out, err := exec.Command("adb", full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// adbShell runs `adb [-s serial] shell cmd`.
func adbShell(serial, cmd string) (string, error) {
	return adbCmd(serial, "shell", cmd)
}
