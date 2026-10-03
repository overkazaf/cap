package rules

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultBreakpointTimeout is how long a paused breakpoint waits for
// resolution (see Engine.WaitForBreakpoint) before the goproxy handlers in
// handler.go give up and fail open: a request breakpoint forwards the
// original request unmodified, and a response breakpoint returns the
// original response unmodified.
const DefaultBreakpointTimeout = 60 * time.Second

// Engine holds a prioritized, mutable set of Rules and matches live traffic
// against them. It also brokers "breakpoint" rules, which pause a request or
// response until some external caller (typically a UI) resolves it via
// ResolveBreakpoint. Engine is safe for concurrent use.
type Engine struct {
	mu    sync.RWMutex
	rules []*Rule

	// bpMu guards bpSeq, breakpoints and pending below. breakpoints and
	// pending are keyed by breakpoint ID (not rule ID: the same rule may
	// have multiple in-flight breakpoints at once, one per matched
	// request).
	bpMu        sync.Mutex
	bpSeq       atomic.Int64
	breakpoints map[string]chan *BreakpointResolution
	pending     map[string]*PendingBreakpoint
}

// BreakpointResolution is how a paused breakpoint is resolved. Action picks
// what happens next; the remaining fields supply the (possibly edited) data
// for it:
//
//   - "forward": for a request breakpoint, Method/URL/Headers/Body (any of
//     which may be left zero to keep the request's original value) are
//     applied to the request before it continues upstream; Headers are
//     merged (set/overwritten) rather than replacing the whole header set.
//     For a response breakpoint, "forward" instead applies
//     Status/RespHeaders/RespBody to the response before it reaches the
//     client, with the same zero-value-keeps-original and merge semantics.
//   - "mock": for a request breakpoint only, short-circuits it, returning a
//     canned response built from Status/RespHeaders/RespBody instead of
//     forwarding to the upstream server.
//   - "drop": blocks the request (or, for a response breakpoint, discards
//     the real response), returning a 403 to the client.
type BreakpointResolution struct {
	Action string // "forward", "mock", "drop"

	// Modified request fields (Action == "forward" on a request
	// breakpoint).
	URL     string
	Method  string
	Headers map[string]string
	Body    []byte

	// Mock/modified response fields (Action == "mock" on a request
	// breakpoint, or Action == "forward" on a response breakpoint).
	Status      int
	RespHeaders map[string]string
	RespBody    []byte
}

// PendingBreakpoint is a snapshot of a paused request or response, suitable
// for display in a UI so a human can decide how to resolve it (see
// Engine.ListPendingBreakpoints and Engine.ResolveBreakpoint). It is
// immutable once created, so it's safe to read concurrently without
// synchronization. For a request breakpoint, Headers/Body are the
// request's; for a response breakpoint, they're the response's (Method/URL
// still describe the request that produced it, for context).
type PendingBreakpoint struct {
	ID        string            `json:"id"`
	RuleID    string            `json:"rule_id"`
	RuleName  string            `json:"rule_name"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Timestamp time.Time         `json:"timestamp"`
}

// NewEngine returns an Engine with no rules.
func NewEngine() *Engine {
	return &Engine{
		breakpoints: make(map[string]chan *BreakpointResolution),
		pending:     make(map[string]*PendingBreakpoint),
	}
}

// AddRule appends rule to the engine's rule set.
func (e *Engine) AddRule(rule *Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RemoveRule removes the rule with the given ID, if present. Removing an
// unknown ID is a no-op.
func (e *Engine) RemoveRule(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	kept := e.rules[:0]
	for _, r := range e.rules {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	e.rules = kept
}

// ListRules returns a snapshot of the engine's current rules. The returned
// slice is a copy, but the *Rule elements themselves are shared with the
// engine and should be treated as read-only.
func (e *Engine) ListRules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// SetRules replaces the entire rule set.
func (e *Engine) SetRules(newRules []*Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append([]*Rule(nil), newRules...)
}

// FindMatch returns the highest-priority (lowest Priority value) enabled
// rule whose Matcher matches the given request, or nil if none match. Ties
// are broken in favor of whichever matching rule appears earliest in the
// rule set.
func (e *Engine) FindMatch(method, host, path, fullURL string, headers map[string]string, body []byte) *Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var best *Rule
	for _, r := range e.rules {
		if !r.Enabled {
			continue
		}
		if !r.Match.Matches(method, host, path, fullURL, headers, body) {
			continue
		}
		if best == nil || r.Priority < best.Priority {
			best = r
		}
	}
	return best
}

// CreateBreakpoint registers a new paused breakpoint for rule, described by
// the given request/response snapshot (headers/body are the request's for a
// request-phase breakpoint, or the response's for a response-phase
// breakpoint — see PendingBreakpoint). It returns the breakpoint's ID and
// the PendingBreakpoint recorded for it, which stays visible via
// ListPendingBreakpoints until it's resolved or times out.
//
// The snapshot is built once, up front, rather than filled in by the caller
// after the fact, so that a concurrent ListPendingBreakpoints can never
// observe a half-written PendingBreakpoint.
func (e *Engine) CreateBreakpoint(rule *Rule, method, url string, headers map[string]string, body []byte) (string, *PendingBreakpoint) {
	id := fmt.Sprintf("bp%d", e.bpSeq.Add(1))
	pb := &PendingBreakpoint{
		ID:        id,
		RuleID:    rule.ID,
		RuleName:  rule.Name,
		Method:    method,
		URL:       url,
		Headers:   headers,
		Body:      string(body),
		Timestamp: time.Now(),
	}

	e.bpMu.Lock()
	e.breakpoints[id] = make(chan *BreakpointResolution, 1)
	e.pending[id] = pb
	e.bpMu.Unlock()

	return id, pb
}

// ResolveBreakpoint delivers resolution to the breakpoint identified by
// bpID, unblocking a concurrent (or future) call to WaitForBreakpoint for
// it. It returns an error if bpID is unknown: never created, already
// resolved, or already timed out.
func (e *Engine) ResolveBreakpoint(bpID string, resolution *BreakpointResolution) error {
	e.bpMu.Lock()
	ch, ok := e.breakpoints[bpID]
	e.bpMu.Unlock()
	if !ok {
		return fmt.Errorf("rules: no pending breakpoint %q", bpID)
	}

	select {
	case ch <- resolution:
		return nil
	default:
		return fmt.Errorf("rules: breakpoint %q already resolved", bpID)
	}
}

// WaitForBreakpoint blocks until bpID is resolved via ResolveBreakpoint or
// timeout elapses, whichever comes first, then removes it from the pending
// set. It returns an error if bpID is unknown or the wait times out.
func (e *Engine) WaitForBreakpoint(bpID string, timeout time.Duration) (*BreakpointResolution, error) {
	e.bpMu.Lock()
	ch, ok := e.breakpoints[bpID]
	e.bpMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("rules: no pending breakpoint %q", bpID)
	}

	select {
	case res := <-ch:
		e.removeBreakpoint(bpID)
		return res, nil
	case <-time.After(timeout):
		e.removeBreakpoint(bpID)
		return nil, fmt.Errorf("rules: breakpoint %q timed out after %s", bpID, timeout)
	}
}

func (e *Engine) removeBreakpoint(bpID string) {
	e.bpMu.Lock()
	delete(e.breakpoints, bpID)
	delete(e.pending, bpID)
	e.bpMu.Unlock()
}

// ListPendingBreakpoints returns a snapshot of all currently-paused
// breakpoints, in no particular order.
func (e *Engine) ListPendingBreakpoints() []*PendingBreakpoint {
	e.bpMu.Lock()
	defer e.bpMu.Unlock()
	out := make([]*PendingBreakpoint, 0, len(e.pending))
	for _, pb := range e.pending {
		out = append(out, pb)
	}
	return out
}
