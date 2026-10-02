package replay_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/replay"
	"github.com/overkazaf/cap/internal/types"
)

// TestReplay starts a test server, builds a Flow that targets it, replays
// the flow unmodified, and checks both that the server received the request
// exactly as captured and that the response was captured into a new Flow.
func TestReplay(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	flow := &types.Flow{
		ID:     "f1",
		Method: "POST",
		URL:    server.URL + "/login",
		ReqHeaders: map[string]string{
			"Authorization": "Bearer secret-token",
			"Content-Type":  "application/json",
		},
		ReqBody:     []byte(`{"user":"alice"}`),
		ReqBodyType: "application/json",
	}

	result, err := replay.Replay(flow, replay.Options{})
	if err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("result.Error = %v, want nil", result.Error)
	}
	if result.Original != flow {
		t.Error("result.Original should be the exact flow passed in")
	}

	// The server must have received the request exactly as captured.
	if gotMethod != "POST" {
		t.Errorf("server saw method %q, want %q", gotMethod, "POST")
	}
	if gotPath != "/login" {
		t.Errorf("server saw path %q, want %q", gotPath, "/login")
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("server saw Authorization %q, want %q", gotAuth, "Bearer secret-token")
	}
	if string(gotBody) != `{"user":"alice"}` {
		t.Errorf("server saw body %q, want %q", gotBody, `{"user":"alice"}`)
	}

	// The response must be captured into Replayed.
	if result.Replayed == nil {
		t.Fatal("result.Replayed is nil")
	}
	if result.Replayed.Status != http.StatusOK {
		t.Errorf("Replayed.Status = %d, want %d", result.Replayed.Status, http.StatusOK)
	}
	if string(result.Replayed.RespBody) != `{"ok":true}` {
		t.Errorf("Replayed.RespBody = %q, want %q", result.Replayed.RespBody, `{"ok":true}`)
	}
	if result.Replayed.RespHeaders["Content-Type"] != "application/json" {
		t.Errorf("Replayed.RespHeaders[Content-Type] = %q, want %q",
			result.Replayed.RespHeaders["Content-Type"], "application/json")
	}
	if result.Diff == nil {
		t.Fatal("result.Diff is nil")
	}
}

// TestReplayModified checks that URL, method, header (both additions and
// removals) and body overrides are all applied before the request is sent,
// and that the replayed Flow reflects those modifications too.
func TestReplayModified(t *testing.T) {
	var gotMethod, gotPath, gotCustomHeader, gotAuth string
	var gotBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCustomHeader = r.Header.Get("X-Custom")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	flow := &types.Flow{
		ID:     "f1",
		Method: "GET",
		URL:    server.URL + "/original",
		ReqHeaders: map[string]string{
			"X-Custom":      "original-value",
			"Authorization": "Bearer original-token",
		},
		ReqBody: []byte("original body"),
	}

	mods := replay.Modifications{
		URL:        server.URL + "/modified",
		Method:     "PUT",
		SetHeaders: map[string]string{"X-Custom": "modified-value"},
		DelHeaders: []string{"Authorization"},
		Body:       []byte("modified body"),
	}

	result, err := replay.ReplayModified(flow, mods, replay.Options{})
	if err != nil {
		t.Fatalf("ReplayModified returned error: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("result.Error = %v, want nil", result.Error)
	}

	if gotMethod != "PUT" {
		t.Errorf("server saw method %q, want %q", gotMethod, "PUT")
	}
	if gotPath != "/modified" {
		t.Errorf("server saw path %q, want %q", gotPath, "/modified")
	}
	if gotCustomHeader != "modified-value" {
		t.Errorf("server saw X-Custom %q, want %q", gotCustomHeader, "modified-value")
	}
	if gotAuth != "" {
		t.Errorf("server saw Authorization %q, want it removed", gotAuth)
	}
	if string(gotBody) != "modified body" {
		t.Errorf("server saw body %q, want %q", gotBody, "modified body")
	}

	if result.Replayed == nil {
		t.Fatal("result.Replayed is nil")
	}
	if result.Replayed.Status != http.StatusCreated {
		t.Errorf("Replayed.Status = %d, want %d", result.Replayed.Status, http.StatusCreated)
	}
	// The request side of the replayed flow should reflect the
	// modifications too, not just what hit the wire.
	if result.Replayed.URL != mods.URL {
		t.Errorf("Replayed.URL = %q, want %q", result.Replayed.URL, mods.URL)
	}
	if result.Replayed.Method != "PUT" {
		t.Errorf("Replayed.Method = %q, want PUT", result.Replayed.Method)
	}
	if result.Replayed.ReqHeaders["X-Custom"] != "modified-value" {
		t.Errorf("Replayed.ReqHeaders[X-Custom] = %q, want modified-value", result.Replayed.ReqHeaders["X-Custom"])
	}
	if _, ok := result.Replayed.ReqHeaders["Authorization"]; ok {
		t.Error("Replayed.ReqHeaders should not contain the removed Authorization header")
	}
	if string(result.Replayed.ReqBody) != "modified body" {
		t.Errorf("Replayed.ReqBody = %q, want %q", result.Replayed.ReqBody, "modified body")
	}
}

// TestComputeDiff exercises ComputeDiff's status, header, body and latency
// comparisons directly, without going over the network.
func TestComputeDiff(t *testing.T) {
	t.Run("status change is flagged and formatted", func(t *testing.T) {
		diff := replay.ComputeDiff(&types.Flow{Status: 200}, &types.Flow{Status: 403})

		if !diff.StatusChanged {
			t.Error("StatusChanged = false, want true")
		}
		if diff.StatusDiff != "200 → 403" {
			t.Errorf("StatusDiff = %q, want %q", diff.StatusDiff, "200 → 403")
		}
	})

	t.Run("unchanged status is not flagged", func(t *testing.T) {
		diff := replay.ComputeDiff(&types.Flow{Status: 200}, &types.Flow{Status: 200})

		if diff.StatusChanged {
			t.Error("StatusChanged = true, want false for identical status")
		}
	})

	t.Run("headers added, removed and changed are all detected", func(t *testing.T) {
		original := &types.Flow{
			RespHeaders: map[string]string{
				"Content-Type": "application/json",
				"X-Removed":    "gone-in-replay",
				"X-Changed":    "old-value",
			},
		}
		replayed := &types.Flow{
			RespHeaders: map[string]string{
				"Content-Type": "application/json",
				"X-Added":      "new-in-replay",
				"X-Changed":    "new-value",
			},
		}

		diff := replay.ComputeDiff(original, replayed)

		byKey := make(map[string]replay.HeaderDiff, len(diff.HeadersDiff))
		for _, hd := range diff.HeadersDiff {
			byKey[hd.Key] = hd
		}

		if hd, ok := byKey["X-Removed"]; !ok || hd.Type != "removed" || hd.Original != "gone-in-replay" {
			t.Errorf("X-Removed diff = %+v, ok=%v, want Type=removed Original=gone-in-replay", hd, ok)
		}
		if hd, ok := byKey["X-Added"]; !ok || hd.Type != "added" || hd.Replayed != "new-in-replay" {
			t.Errorf("X-Added diff = %+v, ok=%v, want Type=added Replayed=new-in-replay", hd, ok)
		}
		if hd, ok := byKey["X-Changed"]; !ok || hd.Type != "changed" || hd.Original != "old-value" || hd.Replayed != "new-value" {
			t.Errorf("X-Changed diff = %+v, ok=%v, want Type=changed old-value->new-value", hd, ok)
		}
		if _, ok := byKey["Content-Type"]; ok {
			t.Error("Content-Type is unchanged and should not appear in HeadersDiff")
		}
		if len(diff.HeadersDiff) != 3 {
			t.Errorf("len(HeadersDiff) = %d, want 3", len(diff.HeadersDiff))
		}
	})

	t.Run("JSON bodies are compared structurally", func(t *testing.T) {
		original := &types.Flow{RespBody: []byte(`{"name":"alice","age":30,"deprecated":"x"}`)}
		replayed := &types.Flow{RespBody: []byte(`{"name":"alice","age":31,"active":true}`)}

		diff := replay.ComputeDiff(original, replayed)

		for _, want := range []string{"age", "active", "deprecated"} {
			if !strings.Contains(diff.BodyDiff, want) {
				t.Errorf("BodyDiff = %q, want it to mention key %q", diff.BodyDiff, want)
			}
		}
		if strings.Contains(diff.BodyDiff, "name") {
			t.Errorf("BodyDiff = %q, should not mention unchanged key %q", diff.BodyDiff, "name")
		}
	})

	t.Run("identical JSON bodies produce no diff", func(t *testing.T) {
		original := &types.Flow{RespBody: []byte(`{"name":"alice"}`)}
		replayed := &types.Flow{RespBody: []byte(`{"name": "alice"}`)} // different formatting, same structure

		diff := replay.ComputeDiff(original, replayed)

		if diff.BodyDiff != "identical" {
			t.Errorf("BodyDiff = %q, want %q for structurally identical JSON", diff.BodyDiff, "identical")
		}
	})

	t.Run("non-JSON bodies fall back to byte-length comparison", func(t *testing.T) {
		originalBody := []byte("short")
		replayedBody := []byte("a much longer plain-text body")

		diff := replay.ComputeDiff(
			&types.Flow{RespBody: originalBody},
			&types.Flow{RespBody: replayedBody},
		)

		wantOrigLen := fmt.Sprintf("%d", len(originalBody))
		wantReplLen := fmt.Sprintf("%d", len(replayedBody))
		if !strings.Contains(diff.BodyDiff, wantOrigLen) || !strings.Contains(diff.BodyDiff, wantReplLen) {
			t.Errorf("BodyDiff = %q, want it to mention lengths %s and %s", diff.BodyDiff, wantOrigLen, wantReplLen)
		}
	})

	t.Run("latency diff is the absolute difference in ms", func(t *testing.T) {
		diff := replay.ComputeDiff(&types.Flow{LatencyMs: 100}, &types.Flow{LatencyMs: 250})

		if diff.LatencyDiff != 150 {
			t.Errorf("LatencyDiff = %d, want 150", diff.LatencyDiff)
		}
	})
}

// TestReplayTimeout checks that a slow server causes Replay to fail with a
// timeout, rather than hang, once Options.Timeout is shorter than the
// server's response time.
func TestReplayTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	flow := &types.Flow{
		Method: "GET",
		URL:    server.URL,
	}

	result, err := replay.Replay(flow, replay.Options{Timeout: 30 * time.Millisecond})

	if err == nil {
		t.Fatal("Replay returned nil error, want a timeout error")
	}
	if result == nil {
		t.Fatal("Replay returned nil result, want a non-nil result carrying the error")
	}
	if result.Error == nil {
		t.Error("result.Error is nil, want the timeout error")
	}
	if result.Replayed != nil {
		t.Error("result.Replayed should be nil when the request times out")
	}
	if result.Original != flow {
		t.Error("result.Original should still be set to the original flow on failure")
	}
}
