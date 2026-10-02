// Package stats aggregates captured flows into summary statistics for
// dashboard display: per-host and per-status/method breakdowns, latency
// percentiles, the slowest/largest requests, error rate, and a per-minute
// request timeline.
package stats

import (
	"math"
	"sort"

	"github.com/overkazaf/cap/internal/types"
)

// topN is how many entries TopSlowest and TopLargest each retain.
const topN = 10

// errorStatusThreshold is the status code at and above which a flow counts
// toward ErrorRate (HTTP 4xx and 5xx).
const errorStatusThreshold = 400

// Summary is the aggregate computed by Compute over a set of flows.
type Summary struct {
	TotalFlows   int            `json:"total_flows"`
	TotalBytes   int64          `json:"total_bytes"`
	ByHost       []HostStat     `json:"by_host"`
	ByStatus     map[int]int    `json:"by_status"` // status_code -> count
	ByMethod     map[string]int `json:"by_method"` // method -> count
	AvgLatencyMs int64          `json:"avg_latency_ms"`
	P95LatencyMs int64          `json:"p95_latency_ms"`
	TopSlowest   []FlowStat     `json:"top_slowest"` // top 10 slowest
	TopLargest   []FlowStat     `json:"top_largest"` // top 10 largest response
	ErrorRate    float64        `json:"error_rate"`  // 4xx+5xx / total
	Timeline     []TimeSlot     `json:"timeline"`    // requests per minute
}

// HostStat summarizes all flows observed for a single Host.
type HostStat struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
	AvgMs int64  `json:"avg_ms"`
	Bytes int64  `json:"bytes"`
}

// FlowStat identifies one flow alongside a single metric value (latency or
// response size, depending on which top-N list it appears in).
type FlowStat struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Value  int64  `json:"value"` // latency or size
}

// TimeSlot is the request count for one calendar minute.
type TimeSlot struct {
	Minute string `json:"minute"` // "15:04"
	Count  int    `json:"count"`
}

// hostAccumulator collects running totals for one host while scanning
// flows, before being converted into a HostStat.
type hostAccumulator struct {
	count   int
	totalMs int64
	bytes   int64
}

// Compute aggregates flows into a Summary. It never panics, including on a
// nil or empty flows slice (nil entries within flows are skipped).
//
// ByHost is sorted by Count descending, TopSlowest and TopLargest by Value
// descending (capped at 10 entries each), and Timeline by Minute
// ascending. Ties preserve the input flows' relative order.
func Compute(flows []*types.Flow) *Summary {
	summary := &Summary{
		ByStatus: make(map[int]int),
		ByMethod: make(map[string]int),
	}

	hostOrder := make([]string, 0)
	hostAccs := make(map[string]*hostAccumulator)

	minuteOrder := make([]string, 0)
	minuteCounts := make(map[string]int)

	latencies := make([]int64, 0, len(flows))
	slowest := make([]FlowStat, 0, len(flows))
	largest := make([]FlowStat, 0, len(flows))

	var totalLatency int64
	var errorCount int
	var processed int

	for _, f := range flows {
		if f == nil {
			continue
		}
		processed++

		size := int64(len(f.ReqBody) + len(f.RespBody))
		summary.TotalBytes += size

		summary.ByStatus[f.Status]++
		summary.ByMethod[f.Method]++

		if f.Status >= errorStatusThreshold {
			errorCount++
		}

		acc, ok := hostAccs[f.Host]
		if !ok {
			acc = &hostAccumulator{}
			hostAccs[f.Host] = acc
			hostOrder = append(hostOrder, f.Host)
		}
		acc.count++
		acc.totalMs += f.LatencyMs
		acc.bytes += size

		latencies = append(latencies, f.LatencyMs)
		totalLatency += f.LatencyMs

		slowest = append(slowest, FlowStat{ID: f.ID, Method: f.Method, URL: f.URL, Value: f.LatencyMs})
		largest = append(largest, FlowStat{ID: f.ID, Method: f.Method, URL: f.URL, Value: int64(len(f.RespBody))})

		minute := f.Timestamp.Format("15:04")
		if _, ok := minuteCounts[minute]; !ok {
			minuteOrder = append(minuteOrder, minute)
		}
		minuteCounts[minute]++
	}

	summary.TotalFlows = processed
	if processed == 0 {
		return summary
	}

	summary.AvgLatencyMs = totalLatency / int64(processed)
	summary.ErrorRate = float64(errorCount) / float64(processed)
	summary.P95LatencyMs = percentile(latencies, 95)

	for _, host := range hostOrder {
		acc := hostAccs[host]
		summary.ByHost = append(summary.ByHost, HostStat{
			Host:  host,
			Count: acc.count,
			AvgMs: acc.totalMs / int64(acc.count),
			Bytes: acc.bytes,
		})
	}
	sort.SliceStable(summary.ByHost, func(i, j int) bool {
		return summary.ByHost[i].Count > summary.ByHost[j].Count
	})

	sort.SliceStable(slowest, func(i, j int) bool { return slowest[i].Value > slowest[j].Value })
	sort.SliceStable(largest, func(i, j int) bool { return largest[i].Value > largest[j].Value })
	summary.TopSlowest = capFlowStats(slowest, topN)
	summary.TopLargest = capFlowStats(largest, topN)

	for _, minute := range minuteOrder {
		summary.Timeline = append(summary.Timeline, TimeSlot{Minute: minute, Count: minuteCounts[minute]})
	}
	sort.Slice(summary.Timeline, func(i, j int) bool { return summary.Timeline[i].Minute < summary.Timeline[j].Minute })

	return summary
}

// capFlowStats truncates a descending-sorted slice to at most n entries.
func capFlowStats(stats []FlowStat, n int) []FlowStat {
	if len(stats) > n {
		return stats[:n]
	}
	return stats
}

// percentile returns the p-th percentile (0-100) of values using the
// nearest-rank method: values are sorted ascending and the
// ceil(p/100 * n)-th smallest (1-indexed) is returned. values must be
// non-empty.
func percentile(values []int64, p float64) int64 {
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	n := len(sorted)
	idx := int(math.Ceil(p/100*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}
