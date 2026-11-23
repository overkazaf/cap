package wailsgui

import (
	"fmt"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/types"
)

// ==================== Proxy ====================

type FlowEvent struct {
	ID      string `json:"id"`
	Method  string `json:"method"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Latency int64  `json:"latency_ms"`
}

type ProxyEvent struct {
	State string `json:"state"`
	Addr  string `json:"address,omitempty"`
	Error string `json:"error,omitempty"`
}

type CaptureStateEvent struct {
	Paused bool `json:"paused"`
}

func (a *App) StartProxy(addr string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.isRunning {
		return fmt.Errorf("proxy already running")
	}
	if addr == "" {
		addr = "0.0.0.0:8080"
	}
	a.events.Emit(EventProxyStarting, ProxyEvent{State: "starting", Addr: addr})

	a.reqCount = 0
	a.byteCount = 0
	a.lastRateTS = time.Now()

	p, err := proxy.New(proxy.Options{
		Addr:                addr,
		CertDir:             a.certDir,
		RequestInterceptor:  a.rulesEngine.RequestHandler(),
		ResponseInterceptor: a.rulesEngine.ResponseHandler(),
		OnFlow: func(f *types.Flow) {
			if !a.shouldCapture(f.Host) {
				return
			}
			if err := a.store.SaveFlow(f); err != nil {
				a.events.Emit(EventProxyError, ProxyEvent{State: "flow_save_failed", Error: err.Error()})
				return
			}
			a.mu.Lock()
			a.flows = append([]*types.Flow{f}, a.flows...)
			a.reqCount++
			a.byteCount += int64(len(f.ReqBody) + len(f.RespBody))
			a.mu.Unlock()
			a.events.Emit(EventProxyFlow, FlowEvent{
				ID:      f.ID,
				Method:  f.Method,
				URL:     f.URL,
				Status:  f.Status,
				Latency: f.LatencyMs,
			})
			go a.runAutoPlugins(f)
		},
	})
	if err != nil {
		a.events.Emit(EventProxyError, ProxyEvent{State: "start_failed", Addr: addr, Error: err.Error()})
		return err
	}

	a.proxy = p
	a.isRunning = true
	a.isPaused = false
	a.events.Emit(EventProxyStarted, ProxyEvent{State: "started", Addr: p.Addr()})
	go p.Start()
	return nil
}

func (a *App) StopProxy() error {
	// Clean up any tracked connected Android devices BEFORE stopping the proxy
	// so devices are never left blackholed pointing at a closed proxy.
	a.teardownTrackedDevices("proxy_stopped")

	a.mu.Lock()
	if !a.isRunning || a.proxy == nil {
		a.mu.Unlock()
		return nil
	}
	p := a.proxy
	a.isRunning = false
	a.proxy = nil
	a.mu.Unlock()

	err := p.Stop()
	event := ProxyEvent{State: "stopped"}
	eventName := EventProxyStopped
	if err != nil {
		event.Error = err.Error()
		eventName = EventProxyError
	}
	a.events.Emit(eventName, event)
	return err
}

func (a *App) ProxyAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proxy != nil {
		return a.proxy.Addr()
	}
	return ""
}

func (a *App) IsProxyRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isRunning
}

// ==================== Capture Controls ====================

func (a *App) PauseCapture() {
	a.mu.Lock()
	a.isPaused = true
	a.mu.Unlock()
	a.events.Emit(EventCaptureState, CaptureStateEvent{Paused: true})
}

func (a *App) ResumeCapture() {
	a.mu.Lock()
	a.isPaused = false
	a.mu.Unlock()
	a.events.Emit(EventCaptureState, CaptureStateEvent{Paused: false})
}

func (a *App) IsPaused() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isPaused
}

type TrafficRate struct {
	ReqPerSec  float64 `json:"req_per_sec"`
	BytePerSec float64 `json:"byte_per_sec"`
	TotalReqs  int64   `json:"total_reqs"`
	TotalBytes int64   `json:"total_bytes"`
}

func (a *App) GetTrafficRate() TrafficRate {
	a.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(a.lastRateTS).Seconds()
	if elapsed >= 1.0 {
		a.rateReqPS = float64(a.reqCount-a.lastReqN) / elapsed
		a.rateBytPS = float64(a.byteCount-a.lastByteN) / elapsed
		a.lastReqN = a.reqCount
		a.lastByteN = a.byteCount
		a.lastRateTS = now
	}
	rate := TrafficRate{
		ReqPerSec:  a.rateReqPS,
		BytePerSec: a.rateBytPS,
		TotalReqs:  a.reqCount,
		TotalBytes: a.byteCount,
	}
	a.mu.Unlock()

	a.events.Emit(EventProxyRate, rate)
	return rate
}

func (a *App) SetDomainFilter(whitelist, blacklist []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.domainWhitelist = whitelist
	a.domainBlacklist = blacklist
}

func (a *App) GetDomainFilter() map[string][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string][]string{
		"whitelist": a.domainWhitelist,
		"blacklist": a.domainBlacklist,
	}
}

func (a *App) shouldCapture(host string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isPaused {
		return false
	}
	if len(a.domainWhitelist) > 0 {
		for _, d := range a.domainWhitelist {
			if strings.Contains(host, d) {
				return true
			}
		}
		return false
	}
	for _, d := range a.domainBlacklist {
		if strings.Contains(host, d) {
			return false
		}
	}
	return true
}

type TLSError struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

func (a *App) GetTLSErrors() []TLSError {
	a.tlsErrorsMu.Lock()
	defer a.tlsErrorsMu.Unlock()
	result := make([]TLSError, 0, len(a.tlsErrors))
	for host, count := range a.tlsErrors {
		result = append(result, TLSError{Host: host, Count: count})
	}
	return result
}

func (a *App) ClearTLSErrors() {
	a.tlsErrorsMu.Lock()
	a.tlsErrors = make(map[string]int)
	a.tlsErrorsMu.Unlock()
}
