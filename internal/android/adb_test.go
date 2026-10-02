package android_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/overkazaf/cap/internal/android"
)

func TestParseDevices(t *testing.T) {
	t.Run("mixed states", func(t *testing.T) {
		output := "List of devices attached\n" +
			"emulator-5554\tdevice\n" +
			"192.168.1.100:5555\tdevice\n" +
			"ABCDEF123456\tunauthorized\n" +
			"0123456789AB\toffline\n"

		devices := android.ParseDeviceList(output)
		if len(devices) != 4 {
			t.Fatalf("expected 4 devices, got %d: %+v", len(devices), devices)
		}
		want := []android.Device{
			{Serial: "emulator-5554", State: "device"},
			{Serial: "192.168.1.100:5555", State: "device"},
			{Serial: "ABCDEF123456", State: "unauthorized"},
			{Serial: "0123456789AB", State: "offline"},
		}
		for i, w := range want {
			if devices[i] != w {
				t.Errorf("device %d = %+v, want %+v", i, devices[i], w)
			}
		}
	})

	t.Run("no devices attached", func(t *testing.T) {
		devices := android.ParseDeviceList("List of devices attached\n\n")
		if len(devices) != 0 {
			t.Fatalf("expected 0 devices, got %d: %+v", len(devices), devices)
		}
	})

	t.Run("ignores daemon startup noise", func(t *testing.T) {
		output := "* daemon not running; starting now at tcp:5037\n" +
			"* daemon started successfully\n" +
			"List of devices attached\n" +
			"emulator-5554\tdevice\n"

		devices := android.ParseDeviceList(output)
		if len(devices) != 1 || devices[0].Serial != "emulator-5554" || devices[0].State != "device" {
			t.Fatalf("expected [{emulator-5554 device}], got %+v", devices)
		}
	})

	t.Run("malformed lines are skipped", func(t *testing.T) {
		output := "List of devices attached\n" +
			"justaserial\n" +
			"emulator-5554\tdevice\n"

		devices := android.ParseDeviceList(output)
		if len(devices) != 1 || devices[0].Serial != "emulator-5554" {
			t.Fatalf("expected malformed line to be skipped, got %+v", devices)
		}
	})
}

func TestParseCurrentProxy(t *testing.T) {
	tests := []struct {
		input string
		host  string
		port  string
	}{
		{"192.168.1.2:8080", "192.168.1.2", "8080"},
		{":0", "", ""},
		{"null", "", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		h, p := android.ParseProxySetting(tt.input)
		if h != tt.host || p != tt.port {
			t.Errorf("ParseProxySetting(%q) = (%q, %q), want (%q, %q)", tt.input, h, p, tt.host, tt.port)
		}
	}
}

func TestCertHashFilename(t *testing.T) {
	certPath := filepath.Join("testdata", "test-ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Skip("no test cert available")
	}

	name := android.CertHashFilename(certPath)
	if name == "" {
		t.Fatal("expected non-empty hash filename for a valid cert")
	}
	if len(name) < 8 {
		t.Errorf("hash filename too short: %q", name)
	}

	// The Android trust store relies on this being stable across calls
	// (and reboots) for the same certificate.
	if again := android.CertHashFilename(certPath); again != name {
		t.Errorf("hash is not stable: %q vs %q", name, again)
	}
}

func TestCertHashFilenameInvalidInput(t *testing.T) {
	// No real ADB/device needed: these only exercise local file/PEM parsing.
	if got := android.CertHashFilename(filepath.Join("testdata", "does-not-exist.crt")); got != "" {
		t.Errorf("missing file: expected \"\", got %q", got)
	}

	garbage := filepath.Join(t.TempDir(), "not-a-cert.crt")
	if err := os.WriteFile(garbage, []byte("this is not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := android.CertHashFilename(garbage); got != "" {
		t.Errorf("garbage PEM: expected \"\", got %q", got)
	}
}

// TestListDevicesIntegration is the one ADB-dependent test in this package.
// It is skipped under -short (the mode this package's tests are expected to
// run under in CI/sandboxes without ADB or a device) and otherwise skips
// itself gracefully if the adb binary isn't on PATH.
func TestListDevicesIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ADB-dependent test in -short mode")
	}
	devices, err := android.ListDevices()
	if err != nil {
		t.Skipf("adb not available or errored: %v", err)
	}
	t.Logf("found %d connected device(s): %+v", len(devices), devices)
}
