package compare

import (
	"strconv"

	"github.com/overkazaf/cap/internal/types"
)

// Compare produces a structured, side-by-side diff of flowA and flowB: URL,
// method and status as simple line diffs; request and response headers
// diffed and merged into Comparison.Headers; request and response bodies
// each classified and diffed independently (see compareBody); and latency
// as an absolute and percentage change. It finishes with a short Summary
// string built from the other fields.
//
// Compare never panics and never returns nil: a nil flowA or flowB is
// treated as an empty flow (zero value), so comparing against a nil flow
// still produces a meaningful result — typically reporting every field on
// the non-nil side as "added".
func Compare(flowA, flowB *types.Flow) *Comparison {
	if flowA == nil {
		flowA = &types.Flow{}
	}
	if flowB == nil {
		flowB = &types.Flow{}
	}

	c := &Comparison{
		FlowA:    flowA.ID,
		FlowB:    flowB.ID,
		URL:      lineDiff(flowA.URL, flowB.URL),
		Method:   lineDiff(flowA.Method, flowB.Method),
		Status:   lineDiff(strconv.Itoa(flowA.Status), strconv.Itoa(flowB.Status)),
		Headers:  compareHeaders(flowA, flowB),
		ReqBody:  compareBody(flowA.ReqBody, flowB.ReqBody),
		RespBody: compareBody(flowA.RespBody, flowB.RespBody),
		Latency:  compareLatency(flowA.LatencyMs, flowB.LatencyMs),
	}
	c.Summary = summarize(c)
	return c
}

// lineDiff builds a LineDiff from two plain string values.
func lineDiff(a, b string) LineDiff {
	return LineDiff{A: a, B: b, Changed: a != b}
}
