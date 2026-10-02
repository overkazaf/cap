package sqlite_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/store/sqlite"
	"github.com/overkazaf/cap/internal/types"
)

// newTestStore returns an in-memory SQLiteStore that is closed automatically
// when the test completes.
func newTestStore(t *testing.T) *sqlite.SQLiteStore {
	t.Helper()
	s, err := sqlite.New(":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func ids(flows []*types.Flow) []string {
	out := make([]string, len(flows))
	for i, f := range flows {
		out[i] = f.ID
	}
	return out
}

func TestSaveAndGet(t *testing.T) {
	s := newTestStore(t)

	want := &types.Flow{
		ID:           "f1",
		Timestamp:    time.Now(),
		Method:       "POST",
		URL:          "https://api.example.com/login?x=1",
		Host:         "api.example.com",
		Path:         "/login",
		ReqHeaders:   map[string]string{"Content-Type": "application/json", "Authorization": "Bearer tok"},
		ReqBody:      []byte(`{"user":"test"}`),
		ReqBodyType:  "application/json",
		Status:       200,
		RespHeaders:  map[string]string{"Content-Type": "application/json"},
		RespBody:     []byte(`{"token":"abc"}`),
		RespBodyType: "application/json",
		LatencyMs:    150,
		Tags:         []string{"auth", "login"},
		SignParams:   []string{"sign", "ts"},
		SourceRef: &types.SourceRef{
			File:      "com/example/Api.java",
			Class:     "Api",
			Method:    "login",
			Line:      42,
			SignFunc:  "md5sign",
			Algorithm: "MD5",
		},
	}

	if err := s.SaveFlow(want); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	got, err := s.GetFlow("f1")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, want.Timestamp)
	}
	if got.Method != want.Method {
		t.Errorf("Method = %q, want %q", got.Method, want.Method)
	}
	if got.URL != want.URL {
		t.Errorf("URL = %q, want %q", got.URL, want.URL)
	}
	if got.Host != want.Host {
		t.Errorf("Host = %q, want %q", got.Host, want.Host)
	}
	if got.Path != want.Path {
		t.Errorf("Path = %q, want %q", got.Path, want.Path)
	}
	if !reflect.DeepEqual(got.ReqHeaders, want.ReqHeaders) {
		t.Errorf("ReqHeaders = %v, want %v", got.ReqHeaders, want.ReqHeaders)
	}
	if string(got.ReqBody) != string(want.ReqBody) {
		t.Errorf("ReqBody = %s, want %s", got.ReqBody, want.ReqBody)
	}
	if got.ReqBodyType != want.ReqBodyType {
		t.Errorf("ReqBodyType = %q, want %q", got.ReqBodyType, want.ReqBodyType)
	}
	if got.Status != want.Status {
		t.Errorf("Status = %d, want %d", got.Status, want.Status)
	}
	if !reflect.DeepEqual(got.RespHeaders, want.RespHeaders) {
		t.Errorf("RespHeaders = %v, want %v", got.RespHeaders, want.RespHeaders)
	}
	if string(got.RespBody) != string(want.RespBody) {
		t.Errorf("RespBody = %s, want %s", got.RespBody, want.RespBody)
	}
	if got.RespBodyType != want.RespBodyType {
		t.Errorf("RespBodyType = %q, want %q", got.RespBodyType, want.RespBodyType)
	}
	if got.LatencyMs != want.LatencyMs {
		t.Errorf("LatencyMs = %d, want %d", got.LatencyMs, want.LatencyMs)
	}
	if !reflect.DeepEqual(got.Tags, want.Tags) {
		t.Errorf("Tags = %v, want %v", got.Tags, want.Tags)
	}
	if !reflect.DeepEqual(got.SignParams, want.SignParams) {
		t.Errorf("SignParams = %v, want %v", got.SignParams, want.SignParams)
	}
	if !reflect.DeepEqual(got.SourceRef, want.SourceRef) {
		t.Errorf("SourceRef = %+v, want %+v", got.SourceRef, want.SourceRef)
	}
}

func TestGetFlowNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetFlow("missing"); err == nil {
		t.Fatal("GetFlow(missing): expected error, got nil")
	} else if !errors.Is(err, sqlite.ErrNotFound) {
		t.Errorf("GetFlow(missing) error = %v, want errors.Is match for sqlite.ErrNotFound", err)
	}
}

func TestListWithFilter(t *testing.T) {
	s := newTestStore(t)
	base := time.Now()
	flows := []*types.Flow{
		{ID: "f1", Method: "GET", URL: "https://a.com/api", Host: "a.com", Path: "/api", Status: 200, Timestamp: base},
		{ID: "f2", Method: "POST", URL: "https://b.com/login", Host: "b.com", Path: "/login", Status: 401, Timestamp: base.Add(time.Second)},
		{ID: "f3", Method: "GET", URL: "https://a.com/data", Host: "a.com", Path: "/data", Status: 200, Timestamp: base.Add(2 * time.Second)},
	}
	for _, f := range flows {
		if err := s.SaveFlow(f); err != nil {
			t.Fatalf("SaveFlow(%s): %v", f.ID, err)
		}
	}

	t.Run("by host", func(t *testing.T) {
		got, err := s.ListFlows(types.FlowFilter{Host: "a.com"})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2 (got %v)", len(got), ids(got))
		}
		// ORDER BY timestamp DESC: f3 (base+2s) then f1 (base).
		if got[0].ID != "f3" || got[1].ID != "f1" {
			t.Errorf("order = %v, want [f3 f1]", ids(got))
		}
	})

	t.Run("by method", func(t *testing.T) {
		got, err := s.ListFlows(types.FlowFilter{Method: "POST"})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(got) != 1 || got[0].ID != "f2" {
			t.Fatalf("got = %v, want [f2]", ids(got))
		}
	})

	t.Run("by status range", func(t *testing.T) {
		got, err := s.ListFlows(types.FlowFilter{StatusFrom: 400, StatusTo: 499})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(got) != 1 || got[0].ID != "f2" {
			t.Fatalf("got = %v, want [f2]", ids(got))
		}
	})

	t.Run("by path substring", func(t *testing.T) {
		got, err := s.ListFlows(types.FlowFilter{Path: "dat"})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(got) != 1 || got[0].ID != "f3" {
			t.Fatalf("got = %v, want [f3]", ids(got))
		}
	})

	t.Run("no filter returns all ordered desc", func(t *testing.T) {
		got, err := s.ListFlows(types.FlowFilter{})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		want := []string{"f3", "f2", "f1"}
		if !reflect.DeepEqual(ids(got), want) {
			t.Fatalf("order = %v, want %v", ids(got), want)
		}
	})

	t.Run("limit and offset paginate", func(t *testing.T) {
		page1, err := s.ListFlows(types.FlowFilter{Limit: 1})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(page1) != 1 || page1[0].ID != "f3" {
			t.Fatalf("page1 = %v, want [f3]", ids(page1))
		}

		page2, err := s.ListFlows(types.FlowFilter{Limit: 1, Offset: 1})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(page2) != 1 || page2[0].ID != "f2" {
			t.Fatalf("page2 = %v, want [f2]", ids(page2))
		}
	})
}

func TestListWithTagAndSearchFilter(t *testing.T) {
	s := newTestStore(t)
	flows := []*types.Flow{
		{ID: "f1", Method: "GET", URL: "https://a.com/api/login", Host: "a.com", Timestamp: time.Now(), Tags: []string{"auth"}, ReqBody: []byte(`{"user":"alice"}`)},
		{ID: "f2", Method: "GET", URL: "https://a.com/api/data", Host: "a.com", Timestamp: time.Now(), Tags: []string{"data"}, ReqBody: []byte(`{"q":"bob"}`)},
	}
	for _, f := range flows {
		if err := s.SaveFlow(f); err != nil {
			t.Fatalf("SaveFlow(%s): %v", f.ID, err)
		}
	}

	t.Run("by tag", func(t *testing.T) {
		got, err := s.ListFlows(types.FlowFilter{Tag: "auth"})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(got) != 1 || got[0].ID != "f1" {
			t.Fatalf("got = %v, want [f1]", ids(got))
		}
	})

	t.Run("search matches url", func(t *testing.T) {
		got, err := s.ListFlows(types.FlowFilter{Search: "login"})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(got) != 1 || got[0].ID != "f1" {
			t.Fatalf("got = %v, want [f1]", ids(got))
		}
	})

	t.Run("search matches req body", func(t *testing.T) {
		got, err := s.ListFlows(types.FlowFilter{Search: "bob"})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(got) != 1 || got[0].ID != "f2" {
			t.Fatalf("got = %v, want [f2]", ids(got))
		}
	})
}

func TestUpdateTags(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveFlow(&types.Flow{ID: "f1", Method: "GET", URL: "https://a.com", Timestamp: time.Now()}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	if err := s.UpdateTags("f1", []string{"auth", "encrypted"}); err != nil {
		t.Fatalf("UpdateTags: %v", err)
	}

	got, err := s.GetFlow("f1")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	want := []string{"auth", "encrypted"}
	if !reflect.DeepEqual(got.Tags, want) {
		t.Errorf("Tags = %v, want %v", got.Tags, want)
	}
}

func TestUpdateTagsNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpdateTags("missing", []string{"x"}); err == nil {
		t.Fatal("UpdateTags(missing): expected error, got nil")
	}
}

func TestUpdateSourceRef(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveFlow(&types.Flow{ID: "f1", Method: "GET", URL: "https://a.com", Timestamp: time.Now()}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	ref := &types.SourceRef{
		File:   "com/example/Api.java",
		Method: "login",
		Line:   42,
	}
	if err := s.UpdateSourceRef("f1", ref); err != nil {
		t.Fatalf("UpdateSourceRef: %v", err)
	}

	got, err := s.GetFlow("f1")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if got.SourceRef == nil {
		t.Fatal("SourceRef is nil")
	}
	if !reflect.DeepEqual(got.SourceRef, ref) {
		t.Errorf("SourceRef = %+v, want %+v", got.SourceRef, ref)
	}
}

func TestUpdateSourceRefNotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.UpdateSourceRef("missing", &types.SourceRef{File: "x.java"})
	if err == nil {
		t.Fatal("UpdateSourceRef(missing): expected error, got nil")
	}
}

func TestDeleteFlow(t *testing.T) {
	s := newTestStore(t)
	if err := s.SaveFlow(&types.Flow{ID: "f1", Method: "GET", URL: "https://a.com", Timestamp: time.Now()}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	if err := s.DeleteFlow("f1"); err != nil {
		t.Fatalf("DeleteFlow: %v", err)
	}

	if _, err := s.GetFlow("f1"); err == nil {
		t.Fatal("GetFlow after delete: expected error, got nil")
	}
}

func TestSaveFlowUpsert(t *testing.T) {
	s := newTestStore(t)
	f := &types.Flow{ID: "f1", Method: "GET", URL: "https://a.com", Status: 200, Timestamp: time.Now()}
	if err := s.SaveFlow(f); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	f.Status = 500
	f.Method = "POST"
	if err := s.SaveFlow(f); err != nil {
		t.Fatalf("SaveFlow (resave same ID): %v", err)
	}

	got, err := s.GetFlow("f1")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if got.Status != 500 || got.Method != "POST" {
		t.Errorf("got status=%d method=%s, want status=500 method=POST", got.Status, got.Method)
	}

	all, err := s.ListFlows(types.FlowFilter{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("len(all) = %d, want 1 (resaving the same ID must not duplicate rows)", len(all))
	}
}
