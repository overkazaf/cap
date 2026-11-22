package wailsgui

import (
	"context"
	"strings"
	"testing"
)

func TestGetCACertInfo(t *testing.T) {
	app := &App{
		certDir:          t.TempDir(),
		events:           NewEventBus(),
		settings:         map[string]string{},
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
	}

	info, err := app.GetCACertInfo()
	if err != nil {
		t.Fatalf("GetCACertInfo failed: %v", err)
	}
	if !info.Exists {
		t.Fatalf("expected CA cert to exist")
	}
	if !strings.HasSuffix(info.Hash, ".0") || len(info.Hash) < 10 {
		t.Errorf("unexpected Android hash filename: %q", info.Hash)
	}
	if len(info.Fingerprint) != 95 || strings.Count(info.Fingerprint, ":") != 31 {
		t.Errorf("unexpected SHA-256 fingerprint: %q", info.Fingerprint)
	}
	if info.Subject != "Cap MITM CA" {
		t.Errorf("unexpected subject: %q, want %q", info.Subject, "Cap MITM CA")
	}
}

func TestDeviceLifecycleSafeWhenIdle(t *testing.T) {
	app := &App{
		certDir:          t.TempDir(),
		events:           NewEventBus(),
		settings:         map[string]string{},
		tlsErrors:        map[string]int{},
		connectedDevices: map[string]*connectedDeviceSession{},
		staleDevices:     map[string]bool{},
	}

	// Stopping idle proxy & shutting down should be race-free and panic-free.
	if err := app.StopProxy(); err != nil {
		t.Fatalf("StopProxy on idle app failed: %v", err)
	}
	app.stopDeviceMonitor()
	app.Shutdown(context.Background())
}
