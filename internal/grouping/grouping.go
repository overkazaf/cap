// Package grouping clusters captured flows into a navigable API map: first
// by host, then by a shared path-segment prefix (e.g. "/api/v1"), then by
// exact method+path endpoint. It turns a flat, chronological capture log
// into something closer to a route table, which is what cap renders in its
// "API groups" view.
package grouping

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

// APIGroup is a cluster of endpoints that share a Host and a path-segment
// Prefix (e.g. Host "api.example.com", Prefix "/api/v1").
type APIGroup struct {
	Host      string     `json:"host"`
	Prefix    string     `json:"prefix"` // e.g. "/api/v1"
	Endpoints []Endpoint `json:"endpoints"`
	Count     int        `json:"count"` // sum of Endpoints[*].Count
}

// Endpoint aggregates every captured flow that shares an exact method and
// path within a group.
type Endpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Count  int    `json:"count"`
	AvgMs  int64  `json:"avg_ms"`
	LastID string `json:"last_id"` // ID of the most recently captured flow
}

// GroupFlows clusters flows into API groups in three passes:
//
//  1. Flows are bucketed by Host.
//  2. Within a host, paths are clustered by their first path segment (e.g.
//     "users" in "/users/1"), and each cluster's Prefix is set to the
//     longest path-segment prefix shared by every path assigned to it — so
//     "/api/v1/users" and "/api/v1/posts" land in one group with Prefix
//     "/api/v1", while a host mixing "/api/..." and "/health" traffic
//     yields two separate groups instead of one with a meaningless prefix.
//  3. Within each cluster, flows are aggregated by exact method+path into an
//     Endpoint: Count is the number of matching flows, AvgMs their rounded
//     mean latency, and LastID the ID of the most recently captured one (by
//     Timestamp, falling back to input order when timestamps are equal or
//     unset).
//
// The returned groups are sorted by Count descending, breaking ties by Host
// then Prefix for a stable, predictable order. nil entries in flows are
// skipped.
func GroupFlows(flows []*types.Flow) []APIGroup {
	clusters := make(map[clusterKey]*clusterAgg)

	for _, f := range flows {
		if f == nil {
			continue
		}

		ck := clusterKey{host: f.Host, firstSeg: firstSegment(f.Path)}
		c, ok := clusters[ck]
		if !ok {
			c = &clusterAgg{
				host:      f.Host,
				paths:     make(map[string]struct{}),
				endpoints: make(map[endpointKey]*endpointAgg),
			}
			clusters[ck] = c
		}
		c.paths[f.Path] = struct{}{}

		ek := endpointKey{method: f.Method, path: f.Path}
		e, ok := c.endpoints[ek]
		if !ok {
			e = &endpointAgg{}
			c.endpoints[ek] = e
		}
		e.count++
		e.latencySum += f.LatencyMs
		// A later-or-equal timestamp replaces the current "last" flow. Since
		// a zero Time is never After and never Before another zero Time,
		// flows with no timestamp at all simply keep overwriting it in
		// input order, which is the best available proxy for recency.
		if !e.hasLast || !f.Timestamp.Before(e.lastSeen) {
			e.lastID = f.ID
			e.lastSeen = f.Timestamp
			e.hasLast = true
		}
	}

	groups := make([]APIGroup, 0, len(clusters))
	for _, c := range clusters {
		groups = append(groups, c.toAPIGroup())
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		if groups[i].Host != groups[j].Host {
			return groups[i].Host < groups[j].Host
		}
		return groups[i].Prefix < groups[j].Prefix
	})

	return groups
}

// clusterKey identifies one (host, top-level path segment) cluster, the
// granularity at which GroupFlows decides whether two paths might share a
// prefix at all.
type clusterKey struct {
	host     string
	firstSeg string
}

// clusterAgg accumulates the flows belonging to one cluster while GroupFlows
// scans its input, before being reduced into a single APIGroup.
type clusterAgg struct {
	host      string
	paths     map[string]struct{} // distinct paths seen, input to the Prefix calc
	endpoints map[endpointKey]*endpointAgg
}

type endpointKey struct {
	method string
	path   string
}

type endpointAgg struct {
	count      int
	latencySum int64
	lastID     string
	lastSeen   time.Time
	hasLast    bool
}

// toAPIGroup reduces an accumulated cluster into its final, sorted form.
func (c *clusterAgg) toAPIGroup() APIGroup {
	endpoints := make([]Endpoint, 0, len(c.endpoints))
	total := 0
	for ek, e := range c.endpoints {
		endpoints = append(endpoints, Endpoint{
			Method: ek.method,
			Path:   ek.path,
			Count:  e.count,
			AvgMs:  avgLatency(e.latencySum, e.count),
			LastID: e.lastID,
		})
		total += e.count
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Count != endpoints[j].Count {
			return endpoints[i].Count > endpoints[j].Count
		}
		if endpoints[i].Path != endpoints[j].Path {
			return endpoints[i].Path < endpoints[j].Path
		}
		return endpoints[i].Method < endpoints[j].Method
	})

	return APIGroup{
		Host:      c.host,
		Prefix:    commonPrefix(c.paths),
		Endpoints: endpoints,
		Count:     total,
	}
}

func avgLatency(sum int64, count int) int64 {
	if count == 0 {
		return 0
	}
	return int64(math.Round(float64(sum) / float64(count)))
}

// firstSegment returns the first "/"-delimited, non-empty segment of path,
// or "" for a root path like "" or "/".
func firstSegment(path string) string {
	for _, seg := range strings.Split(path, "/") {
		if seg != "" {
			return seg
		}
	}
	return ""
}

// splitSegments splits a path into its non-empty segments, so
// "/api/v1/users/" becomes ["api", "v1", "users"] and "" or "/" becomes an
// empty slice.
func splitSegments(path string) []string {
	parts := strings.Split(path, "/")
	segs := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			segs = append(segs, p)
		}
	}
	return segs
}

// commonPrefix returns the "/"-joined longest path-segment prefix shared by
// every path in paths, e.g. {"/api/v1/users", "/api/v1/posts"} -> "/api/v1".
// A single path's "common prefix" is itself. An empty set, or a set whose
// members share no leading segment, returns "/".
func commonPrefix(paths map[string]struct{}) string {
	var common []string
	first := true
	for p := range paths {
		segs := splitSegments(p)
		if first {
			common = segs
			first = false
			continue
		}
		common = commonSegments(common, segs)
		if len(common) == 0 {
			break
		}
	}
	if len(common) == 0 {
		return "/"
	}
	return "/" + strings.Join(common, "/")
}

// commonSegments returns the longest shared leading run of a and b.
func commonSegments(a, b []string) []string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return a[:i]
}
