package stats_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/stats"
	"github.com/overkazaf/cap/internal/types"
)

func TestComputeBasic(t *testing.T) {
	flows := []*types.Flow{
		{ID: "f1", Method: "GET", Host: "api.example.com", Status: 200, LatencyMs: 100, ReqBody: make([]byte, 10), RespBody: make([]byte, 20)},
		{ID: "f2", Method: "POST", Host: "api.example.com", Status: 201, LatencyMs: 150, ReqBody: make([]byte, 5), RespBody: make([]byte, 15)},
		{ID: "f3", Method: "GET", Host: "api.example.com", Status: 404, LatencyMs: 50, RespBody: make([]byte, 30)},
		{ID: "f4", Method: "GET", Host: "cdn.example.com", Status: 200, LatencyMs: 20, RespBody: make([]byte, 1000)},
		{ID: "f5", Method: "GET", Host: "cdn.example.com", Status: 500, LatencyMs: 300, RespBody: make([]byte, 5)},
	}

	s := stats.Compute(flows)

	if s.TotalFlows != 5 {
		t.Errorf("TotalFlows = %d, want 5", s.TotalFlows)
	}
	if s.TotalBytes != 1085 {
		t.Errorf("TotalBytes = %d, want 1085", s.TotalBytes)
	}

	if len(s.ByHost) != 2 {
		t.Fatalf("len(ByHost) = %d, want 2", len(s.ByHost))
	}
	if s.ByHost[0].Host != "api.example.com" || s.ByHost[0].Count != 3 {
		t.Errorf("ByHost[0] = %+v, want api.example.com count=3 (sorted desc by count)", s.ByHost[0])
	}
	if s.ByHost[0].AvgMs != 100 {
		t.Errorf("ByHost[0].AvgMs = %d, want 100", s.ByHost[0].AvgMs)
	}
	if s.ByHost[0].Bytes != 80 {
		t.Errorf("ByHost[0].Bytes = %d, want 80", s.ByHost[0].Bytes)
	}
	if s.ByHost[1].Host != "cdn.example.com" || s.ByHost[1].Count != 2 {
		t.Errorf("ByHost[1] = %+v, want cdn.example.com count=2", s.ByHost[1])
	}
	if s.ByHost[1].AvgMs != 160 {
		t.Errorf("ByHost[1].AvgMs = %d, want 160", s.ByHost[1].AvgMs)
	}
	if s.ByHost[1].Bytes != 1005 {
		t.Errorf("ByHost[1].Bytes = %d, want 1005", s.ByHost[1].Bytes)
	}

	wantStatus := map[int]int{200: 2, 201: 1, 404: 1, 500: 1}
	for k, v := range wantStatus {
		if s.ByStatus[k] != v {
			t.Errorf("ByStatus[%d] = %d, want %d", k, s.ByStatus[k], v)
		}
	}

	wantMethod := map[string]int{"GET": 4, "POST": 1}
	for k, v := range wantMethod {
		if s.ByMethod[k] != v {
			t.Errorf("ByMethod[%q] = %d, want %d", k, s.ByMethod[k], v)
		}
	}

	if s.ErrorRate != 0.4 {
		t.Errorf("ErrorRate = %v, want 0.4", s.ErrorRate)
	}
}

func TestComputeLatency(t *testing.T) {
	var flows []*types.Flow
	for i := 1; i <= 20; i++ {
		flows = append(flows, &types.Flow{
			ID:        fmt.Sprintf("f%d", i),
			LatencyMs: int64(i * 10), // 10, 20, ..., 200
		})
	}

	s := stats.Compute(flows)

	if s.AvgLatencyMs != 105 {
		t.Errorf("AvgLatencyMs = %d, want 105", s.AvgLatencyMs)
	}
	// Nearest-rank P95 over 20 sorted values: ceil(0.95*20)=19th smallest (1-indexed) = 190.
	if s.P95LatencyMs != 190 {
		t.Errorf("P95LatencyMs = %d, want 190", s.P95LatencyMs)
	}
}

func TestComputeTopSlowest(t *testing.T) {
	var flows []*types.Flow
	for i := 1; i <= 15; i++ {
		flows = append(flows, &types.Flow{
			ID:        fmt.Sprintf("f%d", i),
			Method:    "GET",
			URL:       fmt.Sprintf("http://example.com/%d", i),
			LatencyMs: int64(i),
			RespBody:  make([]byte, i),
		})
	}

	s := stats.Compute(flows)

	if len(s.TopSlowest) != 10 {
		t.Fatalf("len(TopSlowest) = %d, want 10", len(s.TopSlowest))
	}
	for idx, want := range []int64{15, 14, 13, 12, 11, 10, 9, 8, 7, 6} {
		if s.TopSlowest[idx].Value != want {
			t.Errorf("TopSlowest[%d].Value = %d, want %d", idx, s.TopSlowest[idx].Value, want)
		}
	}

	if len(s.TopLargest) != 10 {
		t.Fatalf("len(TopLargest) = %d, want 10", len(s.TopLargest))
	}
	for idx, want := range []int64{15, 14, 13, 12, 11, 10, 9, 8, 7, 6} {
		if s.TopLargest[idx].Value != want {
			t.Errorf("TopLargest[%d].Value = %d, want %d", idx, s.TopLargest[idx].Value, want)
		}
	}
}

func TestComputeTimeline(t *testing.T) {
	mustParse := func(s string) time.Time {
		tm, err := time.Parse("15:04", s)
		if err != nil {
			t.Fatalf("time.Parse(%q): %v", s, err)
		}
		return tm
	}

	// Intentionally out of order to verify the result gets sorted by minute asc.
	flows := []*types.Flow{
		{ID: "f1", Timestamp: mustParse("10:02")},
		{ID: "f2", Timestamp: mustParse("10:00")},
		{ID: "f3", Timestamp: mustParse("10:01")},
		{ID: "f4", Timestamp: mustParse("10:00")},
		{ID: "f5", Timestamp: mustParse("10:01")},
		{ID: "f6", Timestamp: mustParse("10:01")},
	}

	s := stats.Compute(flows)

	if len(s.Timeline) != 3 {
		t.Fatalf("len(Timeline) = %d, want 3", len(s.Timeline))
	}
	want := []stats.TimeSlot{
		{Minute: "10:00", Count: 2},
		{Minute: "10:01", Count: 3},
		{Minute: "10:02", Count: 1},
	}
	for i, w := range want {
		if s.Timeline[i] != w {
			t.Errorf("Timeline[%d] = %+v, want %+v", i, s.Timeline[i], w)
		}
	}
}

func TestComputeEmpty(t *testing.T) {
	s := stats.Compute(nil)

	if s == nil {
		t.Fatal("Compute(nil) returned nil")
	}
	if s.TotalFlows != 0 {
		t.Errorf("TotalFlows = %d, want 0", s.TotalFlows)
	}
	if s.TotalBytes != 0 {
		t.Errorf("TotalBytes = %d, want 0", s.TotalBytes)
	}
	if len(s.ByHost) != 0 {
		t.Errorf("len(ByHost) = %d, want 0", len(s.ByHost))
	}
	if len(s.ByStatus) != 0 {
		t.Errorf("len(ByStatus) = %d, want 0", len(s.ByStatus))
	}
	if len(s.ByMethod) != 0 {
		t.Errorf("len(ByMethod) = %d, want 0", len(s.ByMethod))
	}
	if s.AvgLatencyMs != 0 {
		t.Errorf("AvgLatencyMs = %d, want 0", s.AvgLatencyMs)
	}
	if s.P95LatencyMs != 0 {
		t.Errorf("P95LatencyMs = %d, want 0", s.P95LatencyMs)
	}
	if s.ErrorRate != 0 {
		t.Errorf("ErrorRate = %v, want 0", s.ErrorRate)
	}
	if len(s.TopSlowest) != 0 {
		t.Errorf("len(TopSlowest) = %d, want 0", len(s.TopSlowest))
	}
	if len(s.TopLargest) != 0 {
		t.Errorf("len(TopLargest) = %d, want 0", len(s.TopLargest))
	}
	if len(s.Timeline) != 0 {
		t.Errorf("len(Timeline) = %d, want 0", len(s.Timeline))
	}

	// Also verify the empty (non-nil) slice form doesn't panic.
	s2 := stats.Compute([]*types.Flow{})
	if s2 == nil || s2.TotalFlows != 0 {
		t.Errorf("Compute([]*types.Flow{}) = %+v, want zero summary", s2)
	}
}
