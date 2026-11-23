package trace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/overkazaf/cap/internal/types"
)

func assertGraphIntegrity(t *testing.T, rep *TraceReport) {
	t.Helper()
	if rep == nil {
		t.Fatal("SynthesizeReport returned nil")
	}
	if len(rep.Graph.Nodes) == 0 {
		t.Fatal("Graph.Nodes is empty")
	}
	if len(rep.Graph.Nodes) > maxGraphNodes {
		t.Errorf("Graph.Nodes = %d, exceeds cap %d", len(rep.Graph.Nodes), maxGraphNodes)
	}
	nodeIDs := make(map[string]bool, len(rep.Graph.Nodes))
	modIDs := make(map[string]bool, len(rep.Modules))
	for _, m := range rep.Modules {
		modIDs[m.ID] = true
	}
	for _, n := range rep.Graph.Nodes {
		if n.ID == "" || n.Label == "" {
			t.Errorf("node missing ID or Label: %+v", n)
		}
		if nodeIDs[n.ID] {
			t.Errorf("duplicate node ID %q", n.ID)
		}
		nodeIDs[n.ID] = true
		if n.ModuleID != "" && !modIDs[n.ModuleID] {
			t.Errorf("node %q references unknown module_id %q", n.ID, n.ModuleID)
		}
	}
	if len(rep.Graph.Edges) == 0 {
		t.Fatal("Graph.Edges is empty")
	}
	for _, e := range rep.Graph.Edges {
		if !nodeIDs[e.From] {
			t.Errorf("edge %q has orphan From=%q", e.ID, e.From)
		}
		if !nodeIDs[e.To] {
			t.Errorf("edge %q has orphan To=%q", e.ID, e.To)
		}
	}
	if len(rep.Graph.Sequence) == 0 {
		t.Error("Graph.Sequence is empty")
	}
	for i, s := range rep.Graph.Sequence {
		if s.Order != i+1 {
			t.Errorf("sequence[%d].Order = %d, want %d", i, s.Order, i+1)
		}
		if s.From == "" || s.To == "" || s.Action == "" {
			t.Errorf("incomplete sequence step %+v", s)
		}
	}
}

func TestSynthesizeReport_WithoutJadxUsingDexXRefsAndNative(t *testing.T) {
	flow := &types.Flow{
		ID:         "f-dex-1",
		Method:     "POST",
		URL:        "https://api.acme-cloud.dev/v2/media/url?track_id=99182&sign=abcdef1234567890&ts=1730000000",
		Host:       "api.acme-cloud.dev",
		Path:       "/v2/media/url",
		Status:     200,
		LatencyMs:  88,
		ReqHeaders: map[string]string{"Authorization": "Bearer secret-token-1234567890", "X-Sign": "deadbeef99887766"},
		ReqBody:    []byte(`{"quality":"lossless"}`),
		RespBody:   []byte(`{"url":"https://cdn.acme-cloud.dev/track.flac"}`),
		SignParams: []string{"sign", "X-Sign"},
	}

	xref := &DexXRefResult{
		Methods: []DexMethodRef{
			{
				ClassName:    "com.acme.player.ui.PlayerViewModel",
				MethodName:   "loadTrack",
				Descriptor:   "(J)V",
				DexFile:      "classes.dex",
				MatchedTerms: []string{"track_id"},
				Callees:      []string{"com.acme.player.net.MediaApiClient.fetchTrackUrl"},
				Category:     "entry",
			},
			{
				ClassName:    "com.acme.player.net.MediaApiClient",
				MethodName:   "fetchTrackUrl",
				Descriptor:   "(Ljava/lang/String;)Ljava/lang/String;",
				DexFile:      "classes2.dex",
				MatchedTerms: []string{"/v2/media/url", "api.acme-cloud.dev"},
				Callers:      []string{"com.acme.player.ui.PlayerViewModel.loadTrack"},
				Callees:      []string{"com.acme.player.sec.RequestSigner.computeSign", "okhttp3.OkHttpClient.newCall"},
				Category:     "network",
			},
			{
				ClassName:    "com.acme.player.sec.RequestSigner",
				MethodName:   "computeSign",
				Descriptor:   "(Ljava/lang/String;)Ljava/lang/String;",
				DexFile:      "classes2.dex",
				MatchedTerms: []string{"sign", "X-Sign"},
				Callers:      []string{"com.acme.player.net.MediaApiClient.fetchTrackUrl"},
				IsNative:     true,
				LoadsLibrary: []string{"acmesign"},
				Category:     "crypto",
			},
		},
		NativeClasses: []DexClassSummary{
			{
				ClassName:     "com.acme.player.sec.RequestSigner",
				DexFile:       "classes2.dex",
				NativeMethods: []string{"computeSign"},
				Category:      "native",
			},
		},
		LoadLibraries: []string{"acmesign"},
		TotalClasses:  1200,
		TotalMethods:  9500,
	}

	res := &TraceResult{
		FlowID:   flow.ID,
		URL:      flow.URL,
		Method:   flow.Method,
		Package:  "com.acme.player",
		DexXRefs: xref.Methods,
		DexStrings: []DexMatch{
			{String: "https://api.acme-cloud.dev/v2/media/url", Offset: 0x1020, DexFile: "classes2.dex"},
		},
		APKInfo: &APKInfo{
			Package:     "com.acme.player",
			MinSDK:      "24",
			TargetSDK:   "34",
			HasNSConfig: true,
			Permissions: []string{"android.permission.INTERNET"},
			Activities:  []string{"com.acme.player.ui.MainActivity"},
			SOFiles:     []string{"lib/arm64-v8a/libacmesign.so"},
			DexCount:    4,
		},
		NativeTrace: []NativeRef{
			{
				SOFile:   "libacmesign.so",
				Function: "Java_com_acme_player_sec_RequestSigner_computeSign",
				Address:  "0x14a0",
				Calls:    []string{"HMAC_Init_ex", "SHA256_Final"},
				Strings:  []string{"X-Sign", "hmac-sha256"},
				Imports:  []string{"HMAC", "EVP_sha256"},
			},
		},
	}

	res.CallGraph = buildCallGraphWithXRefs(flow, res.JavaTrace, res.DexXRefs, res.NativeTrace)
	res.Mermaid = generateMermaid(res.CallGraph)
	rep := SynthesizeReport(flow, res, xref)

	assertGraphIntegrity(t, rep)

	if rep.Confidence != "high" || rep.ConfidenceScore < 70 {
		t.Errorf("expected high confidence (>=70) with DEX XRefs + Native + Params, got %s (%d)", rep.Confidence, rep.ConfidenceScore)
	}
	if len(rep.OriginChain) < 5 {
		t.Errorf("expected rich multi-layer origin chain (>=5 hops), got %d: %+v", len(rep.OriginChain), rep.OriginChain)
	}
	if len(rep.Modules) < 4 {
		t.Errorf("expected >=4 architectural modules, got %d: %+v", len(rep.Modules), rep.Modules)
	}
	if len(rep.ParamProvenance) == 0 {
		t.Fatal("expected ParamProvenance entries")
	}
	// Verify secret masking for Authorization & sign
	for _, qp := range rep.RequestAnatomy.QueryParams {
		if qp.Name == "sign" && strings.Contains(qp.SampleValue, "abcdef1234567890") {
			t.Errorf("expected sign query value to be masked, got %q", qp.SampleValue)
		}
	}
	// Verify sign param was traced to DEX/Native references
	foundSignRef := false
	for _, pt := range rep.ParamProvenance {
		if strings.EqualFold(pt.Name, "sign") && pt.HitCount > 0 {
			foundSignRef = true
			break
		}
	}
	if !foundSignRef {
		t.Errorf("expected 'sign' parameter provenance hits > 0, got %+v", rep.ParamProvenance)
	}
	// Verify SecurityPosture detected OkHttp, HMAC/SHA, and NSConfig
	if !rep.SecurityPosture.HasNSConfig || len(rep.SecurityPosture.NetworkStack) == 0 || len(rep.SecurityPosture.CryptoIndicators) == 0 {
		t.Errorf("incomplete SecurityPosture: %+v", rep.SecurityPosture)
	}
	// Verify CallGraph & Mermaid were enriched by DexXRefs even without jadx
	if len(res.CallGraph) < 4 {
		t.Errorf("expected enriched multi-hop CallGraph without jadx, got %d edges", len(res.CallGraph))
	}
	if !strings.Contains(rep.Markdown, "## Request Origin Chain") || !strings.Contains(rep.Markdown, "```mermaid") {
		t.Errorf("Markdown missing expected sections:\n%s", rep.Markdown)
	}

	// Ensure JSON serialization has no null slices
	rawJSON, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("json.Marshal(TraceReport) error = %v", err)
	}
	if !strings.Contains(string(rawJSON), `"origin_chain":[`) || !strings.Contains(string(rawJSON), `"sequence":[`) {
		t.Errorf("unexpected JSON structure: %s", string(rawJSON))
	}
}

func TestSynthesizeReport_WithJadxJavaTrace(t *testing.T) {
	flow := &types.Flow{
		ID:        "f-java-1",
		Method:    "GET",
		URL:       "https://api.example.com/v1/profile?uid=42",
		Host:      "api.example.com",
		Path:      "/v1/profile",
		Status:    200,
		LatencyMs: 45,
	}
	res := &TraceResult{
		FlowID:  flow.ID,
		URL:     flow.URL,
		Method:  flow.Method,
		Package: "com.example.shop",
		JavaTrace: []JavaRef{
			{
				File:          "com/example/shop/api/UserService.java",
				Class:         "com.example.shop.api.UserService",
				Method:        "getProfile",
				Line:          42,
				Snippet:       `@GET("/v1/profile") Call<User> getProfile(@Query("uid") String uid);`,
				Annotation:    "GET /v1/profile",
				MatchedTerm:   "/v1/profile",
				CallsNative:   true,
				NativeMethods: []string{"libshopsec.so", "signRequest"},
			},
		},
		NativeTrace: []NativeRef{
			{
				SOFile:   "libshopsec.so",
				Function: "Java_com_example_shop_api_UserService_signRequest",
				Address:  "0x800",
			},
		},
		APKInfo: &APKInfo{
			Package:   "com.example.shop",
			MinSDK:    "26",
			TargetSDK: "35",
			DexCount:  2,
			SOFiles:   []string{"lib/arm64-v8a/libshopsec.so"},
		},
	}

	rep := SynthesizeReport(flow, res, nil)
	assertGraphIntegrity(t, rep)
	if rep.Confidence != "high" {
		t.Errorf("expected high confidence with jadx + native, got %s (%d)", rep.Confidence, rep.ConfidenceScore)
	}
	if len(rep.Highlights) < 2 {
		t.Errorf("expected highlights, got %+v", rep.Highlights)
	}
}
