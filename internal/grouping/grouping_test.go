package grouping_test

import (
	"testing"

	"github.com/overkazaf/cap/internal/grouping"
	"github.com/overkazaf/cap/internal/types"
)

// TestGroupBasic sends 5 flows to 2 distinct hosts and checks that
// GroupFlows produces exactly one group per host, each carrying the right
// total flow count, with the busier host sorted first.
func TestGroupBasic(t *testing.T) {
	flows := []*types.Flow{
		{ID: "f1", Host: "api.example.com", Method: "GET", Path: "/users", Status: 200},
		{ID: "f2", Host: "api.example.com", Method: "GET", Path: "/users/1", Status: 200},
		{ID: "f3", Host: "api.example.com", Method: "POST", Path: "/users", Status: 201},
		{ID: "f4", Host: "cdn.example.com", Method: "GET", Path: "/assets/app.js", Status: 200},
		{ID: "f5", Host: "cdn.example.com", Method: "GET", Path: "/assets/logo.png", Status: 200},
	}

	groups := grouping.GroupFlows(flows)

	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2", len(groups))
	}

	byHost := make(map[string]grouping.APIGroup, len(groups))
	for _, g := range groups {
		byHost[g.Host] = g
	}

	api, ok := byHost["api.example.com"]
	if !ok {
		t.Fatal("missing group for host api.example.com")
	}
	if api.Count != 3 {
		t.Errorf("api.example.com group Count = %d, want 3", api.Count)
	}

	cdn, ok := byHost["cdn.example.com"]
	if !ok {
		t.Fatal("missing group for host cdn.example.com")
	}
	if cdn.Count != 2 {
		t.Errorf("cdn.example.com group Count = %d, want 2", cdn.Count)
	}

	// Groups are sorted by Count descending, so the 3-flow host comes first.
	if groups[0].Host != "api.example.com" {
		t.Errorf("groups[0].Host = %q, want api.example.com (highest count sorts first)", groups[0].Host)
	}
}

// TestGroupSamePath sends 3 POST requests to the exact same endpoint and
// checks that they collapse into a single Endpoint with the right count,
// average latency, and the ID of the last flow seen.
func TestGroupSamePath(t *testing.T) {
	flows := []*types.Flow{
		{ID: "f1", Host: "api.example.com", Method: "POST", Path: "/api/v1/login", Status: 200, LatencyMs: 100},
		{ID: "f2", Host: "api.example.com", Method: "POST", Path: "/api/v1/login", Status: 200, LatencyMs: 200},
		{ID: "f3", Host: "api.example.com", Method: "POST", Path: "/api/v1/login", Status: 200, LatencyMs: 300},
	}

	groups := grouping.GroupFlows(flows)

	if len(groups) != 1 {
		t.Fatalf("len(groups) = %d, want 1", len(groups))
	}
	g := groups[0]
	if g.Count != 3 {
		t.Errorf("group Count = %d, want 3", g.Count)
	}
	if len(g.Endpoints) != 1 {
		t.Fatalf("len(Endpoints) = %d, want 1", len(g.Endpoints))
	}

	ep := g.Endpoints[0]
	if ep.Method != "POST" || ep.Path != "/api/v1/login" {
		t.Errorf("endpoint = %s %s, want POST /api/v1/login", ep.Method, ep.Path)
	}
	if ep.Count != 3 {
		t.Errorf("Endpoint.Count = %d, want 3", ep.Count)
	}
	const wantAvg = (100 + 200 + 300) / 3
	if ep.AvgMs != wantAvg {
		t.Errorf("Endpoint.AvgMs = %d, want %d", ep.AvgMs, int64(wantAvg))
	}
	if ep.LastID != "f3" {
		t.Errorf("Endpoint.LastID = %q, want %q (last flow seen)", ep.LastID, "f3")
	}
}

// TestGroupPathPrefix checks that two endpoints sharing a versioned API
// prefix ("/api/v1/users" and "/api/v1/posts") are clustered into one group
// whose Prefix is the shared "/api/v1" segment rather than either full path.
func TestGroupPathPrefix(t *testing.T) {
	flows := []*types.Flow{
		{ID: "f1", Host: "api.example.com", Method: "GET", Path: "/api/v1/users", Status: 200},
		{ID: "f2", Host: "api.example.com", Method: "GET", Path: "/api/v1/posts", Status: 200},
	}

	groups := grouping.GroupFlows(flows)

	if len(groups) != 1 {
		t.Fatalf("len(groups) = %d, want 1", len(groups))
	}
	g := groups[0]
	if g.Prefix != "/api/v1" {
		t.Errorf("Prefix = %q, want %q", g.Prefix, "/api/v1")
	}
	if len(g.Endpoints) != 2 {
		t.Fatalf("len(Endpoints) = %d, want 2", len(g.Endpoints))
	}
}

// TestGroupDistinctPrefixesWithinHost checks that a single host whose
// traffic touches two unrelated top-level paths ("/api/..." and "/health")
// yields two separate groups for that host, not one group with an
// uninformative empty prefix.
func TestGroupDistinctPrefixesWithinHost(t *testing.T) {
	flows := []*types.Flow{
		{ID: "f1", Host: "api.example.com", Method: "GET", Path: "/api/v1/users"},
		{ID: "f2", Host: "api.example.com", Method: "GET", Path: "/health"},
	}

	groups := grouping.GroupFlows(flows)

	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2", len(groups))
	}
	for _, g := range groups {
		if g.Host != "api.example.com" {
			t.Errorf("group Host = %q, want api.example.com", g.Host)
		}
	}

	prefixes := map[string]bool{groups[0].Prefix: true, groups[1].Prefix: true}
	if !prefixes["/api/v1/users"] || !prefixes["/health"] {
		t.Errorf("group prefixes = %v, want {/api/v1/users, /health}", prefixes)
	}
}

// TestGroupEmpty checks that GroupFlows tolerates an empty or nil input
// without panicking, returning a non-nil empty slice.
func TestGroupEmpty(t *testing.T) {
	if got := grouping.GroupFlows(nil); len(got) != 0 {
		t.Errorf("GroupFlows(nil) = %v, want empty", got)
	}
	if got := grouping.GroupFlows([]*types.Flow{}); len(got) != 0 {
		t.Errorf("GroupFlows([]) = %v, want empty", got)
	}
}
