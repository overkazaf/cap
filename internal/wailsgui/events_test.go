package wailsgui

import (
	"sync"
	"testing"
)

func TestEventBusEmitsWithLatestEmitter(t *testing.T) {
	bus := NewEventBus()

	var mu sync.Mutex
	var calls []string
	bus.SetEmitter(func(event string, data ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, event)
	})

	bus.Emit(EventProxyStarted)
	bus.SetEmitter(nil)
	bus.Emit(EventProxyStopped)

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0] != EventProxyStarted {
		t.Fatalf("calls = %v, want [%s]", calls, EventProxyStarted)
	}
}

func TestEventBusWithoutEmitter(t *testing.T) {
	NewEventBus().Emit(EventProxyFlow)
}
