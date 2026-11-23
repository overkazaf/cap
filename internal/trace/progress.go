package trace

import (
	"sync"
)

// Pipeline stage identifiers emitted by TraceContext in execution order.
const (
	StagePreflight     = "preflight"
	StageAPKPull       = "apk_pull"
	StageAPKInspect    = "apk_inspect"
	StageDEXSearch     = "dex_search"
	StageJadxDecompile = "jadx_decompile"
	StageJavaSearch    = "java_search"
	StageNative        = "native_analysis"
	StageGraphBuild    = "graph_build"
	StageDone          = "done"

	// TotalPipelineStages is the count of main pipeline stages (1..8).
	TotalPipelineStages = 8
)

// ProgressEvent describes a live state update during TraceContext execution.
// Callers (CLI progress renderers, Wails event emitters) receive events as
// stages start, stream intermediate progress (DEX files, jadx %, Java walk,
// native .so files), and finish.
type ProgressEvent struct {
	Stage         string      `json:"stage"`
	StageIndex    int         `json:"stage_index"`
	TotalStages   int         `json:"total_stages"`
	Percent       int         `json:"percent"`
	Status        string      `json:"status"` // "running", "ok", "skip", "error", "cancelled"
	Detail        string      `json:"detail"`
	DurationMs    int64       `json:"duration_ms"`
	DexMatches    int         `json:"dex_matches"`
	JavaMatches   int         `json:"java_matches"`
	NativeMatches int         `json:"native_matches"`
	GraphEdges    int         `json:"graph_edges"`
	Step          *StepResult `json:"step,omitempty"`
}

// ProgressCallback receives real-time ProgressEvent updates during TraceContext.
type ProgressCallback func(ProgressEvent)

// progressTracker ensures reported percentages are monotonic and snapshots
// live partial finding counts on every emitted ProgressEvent.
type progressTracker struct {
	mu      sync.Mutex
	cb      ProgressCallback
	lastPct int
	dex     int
	java    int
	native  int
	edges   int
}

func newProgressTracker(cb ProgressCallback) *progressTracker {
	return &progressTracker{cb: cb}
}

func (p *progressTracker) setCounts(dex, java, native, edges int) {
	p.mu.Lock()
	p.dex = dex
	p.java = java
	p.native = native
	p.edges = edges
	p.mu.Unlock()
}

func (p *progressTracker) emit(stage string, stageIdx, pct int, status, detail string, durationMs int64, step *StepResult) {
	p.mu.Lock()
	if pct < p.lastPct {
		pct = p.lastPct
	}
	if pct > 100 {
		pct = 100
	}
	p.lastPct = pct

	ev := ProgressEvent{
		Stage:         stage,
		StageIndex:    stageIdx,
		TotalStages:   TotalPipelineStages,
		Percent:       pct,
		Status:        status,
		Detail:        detail,
		DurationMs:    durationMs,
		DexMatches:    p.dex,
		JavaMatches:   p.java,
		NativeMatches: p.native,
		GraphEdges:    p.edges,
		Step:          step,
	}
	cb := p.cb
	p.mu.Unlock()

	if cb != nil {
		cb(ev)
	}
}
