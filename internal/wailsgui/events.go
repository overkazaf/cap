package wailsgui

import "sync"

const (
	EventProxyStarting = "proxy:starting"
	EventProxyStarted  = "proxy:started"
	EventProxyStopped  = "proxy:stopped"
	EventProxyError    = "proxy:error"
	EventProxyFlow     = "proxy:flow"
	EventProxyRate     = "proxy:rate"
	EventCaptureState  = "proxy:capture"
	EventTraceProgress       = "trace:progress"
	EventTraceDone           = "trace:done"
	EventTraceError          = "trace:error"
	EventPluginExecuted      = "plugin:executed"
	EventFridaLog            = "frida:log"
	EventFridaStatus         = "frida:status"
	EventFridaDeployProgress = "frida:deploy_progress"
)

type EventBus struct {
	mu      sync.RWMutex
	emitter func(event string, data ...interface{})
}

func NewEventBus() *EventBus {
	return &EventBus{}
}

func (b *EventBus) SetEmitter(emitter func(event string, data ...interface{})) {
	if emitter == nil {
		emitter = func(string, ...interface{}) {}
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.emitter = emitter
}

func (b *EventBus) Emit(event string, data ...interface{}) {
	b.mu.RLock()
	emitter := b.emitter
	b.mu.RUnlock()

	if emitter == nil {
		return
	}
	emitter(event, data...)
}
