package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
	addr   net.Addr
}

func newPipeListener(addr net.Addr) *pipeListener {
	return &pipeListener{
		ch:     make(chan net.Conn, 16),
		closed: make(chan struct{}),
		addr:   addr,
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return l.addr }

func (l *pipeListener) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	select {
	case l.ch <- c2:
		return c1, nil
	case <-l.closed:
		_ = c1.Close()
		_ = c2.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = c1.Close()
		_ = c2.Close()
		return nil, ctx.Err()
	}
}

// startLocalHTTPTestServer starts a real local httptest.NewServer. When the
// host allows TCP loopback, attach is a no-op and traffic flows over real TCP.
// When an OS sandbox blocks loopback connect(2), attach routes the Client's
// Transport over an in-memory net.Pipe running a real HTTP/1.1 server for the
// same handler while keeping Client.httpClient.CheckRedirect untouched.
func startLocalHTTPTestServer(t *testing.T, handler http.Handler) (string, func(*Client)) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	probe, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
	if err == nil {
		_ = probe.Close()
		return srv.URL, func(*Client) {}
	}

	pl := newPipeListener(srv.Listener.Addr())
	pipeSrv := &http.Server{Handler: handler}
	go func() {
		_ = pipeSrv.Serve(pl)
	}()
	t.Cleanup(func() {
		_ = pipeSrv.Close()
		_ = pl.Close()
	})

	return srv.URL, func(c *Client) {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != addr {
				return nil, fmt.Errorf("unexpected dial target %q (want %q)", target, addr)
			}
			return pl.DialContext(ctx, network, target)
		}
		c.httpClient.Transport = tr
	}
}

func TestListProviderPresets(t *testing.T) {
	presets := ListProviderPresets()
	if len(presets) < 6 {
		t.Fatalf("expected at least 6 presets, got %d", len(presets))
	}
	wantIDs := map[string]bool{
		"openai":    false,
		"deepseek":  false,
		"anthropic": false,
		"gemini":    false,
		"qwen":      false,
		"ollama":    false,
	}
	for _, p := range presets {
		if _, ok := wantIDs[p.ID]; ok {
			wantIDs[p.ID] = true
		}
		if !IsValidProvider(p.Provider) {
			t.Errorf("preset %q has invalid provider %q", p.ID, p.Provider)
		}
		if _, err := ValidateBaseURL(p.BaseURL); err != nil {
			t.Errorf("preset %q has invalid BaseURL %q: %v", p.ID, p.BaseURL, err)
		}
		if p.DefaultModel == "" || len(p.SuggestedModels) == 0 {
			t.Errorf("preset %q missing model defaults", p.ID)
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Errorf("missing expected provider preset %q", id)
		}
	}
}

func TestConfigStorePermissionsKeyPreservationAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	store, err := NewConfigStore(dir)
	if err != nil {
		t.Fatalf("NewConfigStore: %v", err)
	}

	// Default settings check.
	pub0 := store.GetPublicConfig()
	if !pub0.RedactSecrets {
		t.Fatalf("RedactSecrets should default to true")
	}
	if pub0.MaxAutoRetries != DefaultMaxAutoRetries {
		t.Fatalf("MaxAutoRetries = %d, want %d", pub0.MaxAutoRetries, DefaultMaxAutoRetries)
	}

	// Upsert profile with real API key and sensitive ExtraHeader.
	rawKey := "sk-live-supersecret9876543210"
	pubProf, err := store.UpsertProfile(ProviderConfig{
		ID:          "openai-main",
		Name:        "OpenAI Main",
		Provider:    ProviderOpenAICompat,
		BaseURL:     "https://api.openai.com/v1/",
		APIKey:      rawKey,
		Model:       "gpt-4.1",
		Temperature: 0.2,
		ExtraHeaders: map[string]string{
			"X-Title":       "cap",
			"Authorization": "Bearer extra-secret-token-value",
		},
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpsertProfile: %v", err)
	}
	if !pubProf.HasAPIKey {
		t.Fatalf("expected HasAPIKey=true")
	}
	if strings.Contains(pubProf.APIKeyPreview, rawKey) || pubProf.APIKeyPreview == "" {
		t.Fatalf("bad APIKeyPreview: %q", pubProf.APIKeyPreview)
	}
	if pubProf.ExtraHeaders["Authorization"] != "[REDACTED]" {
		t.Fatalf("expected sensitive ExtraHeader redacted in public view, got %q", pubProf.ExtraHeaders["Authorization"])
	}

	// Public JSON snapshot must NEVER contain raw APIKey.
	pubBytes, err := json.Marshal(store.GetPublicConfig())
	if err != nil {
		t.Fatalf("marshal public config: %v", err)
	}
	if strings.Contains(string(pubBytes), rawKey) || strings.Contains(string(pubBytes), "extra-secret-token-value") {
		t.Fatalf("raw secret leaked into PublicAIConfig JSON: %s", string(pubBytes))
	}

	// Verify 0600 file permissions on <capDir>/ai.json.
	info, err := os.Stat(filepath.Join(dir, "ai.json"))
	if err != nil {
		t.Fatalf("stat ai.json: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ai.json permissions = %04o, want 0600", perm)
	}

	// Updating with empty APIKey preserves existing key.
	_, err = store.UpsertProfile(ProviderConfig{
		ID:       "openai-main",
		Name:     "OpenAI Renamed",
		Provider: ProviderOpenAICompat,
		BaseURL:  "https://api.openai.com/v1",
		APIKey:   "",
		Model:    "gpt-4o",
		Enabled:  true,
		ExtraHeaders: map[string]string{
			"X-Title":       "cap-v2",
			"Authorization": "[REDACTED]",
		},
	})
	if err != nil {
		t.Fatalf("UpsertProfile empty key update: %v", err)
	}
	saved, ok := store.GetProfile("openai-main")
	if !ok || saved.APIKey != rawKey {
		t.Fatalf("empty APIKey update did not preserve stored key: got %q", saved.APIKey)
	}
	if saved.ExtraHeaders["Authorization"] != "Bearer extra-secret-token-value" {
		t.Fatalf("redacted ExtraHeader round-trip did not preserve original header: got %q", saved.ExtraHeaders["Authorization"])
	}

	// Updating with masked APIKeyPreview also preserves existing key.
	_, err = store.UpsertProfile(ProviderConfig{
		ID:       "openai-main",
		Name:     "OpenAI Masked Echo",
		Provider: ProviderOpenAICompat,
		BaseURL:  "https://api.openai.com/v1",
		APIKey:   pubProf.APIKeyPreview,
		Model:    "gpt-4o",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("UpsertProfile masked key update: %v", err)
	}
	saved, _ = store.GetProfile("openai-main")
	if saved.APIKey != rawKey {
		t.Fatalf("masked APIKey update did not preserve stored key: got %q", saved.APIKey)
	}

	// Explicit ClearAPIKey clears stored key and never persists clear_api_key=true.
	pubCleared, err := store.UpsertProfile(ProviderConfig{
		ID:          "openai-main",
		Name:        "OpenAI Cleared",
		Provider:    ProviderOpenAICompat,
		BaseURL:     "https://api.openai.com/v1",
		ClearAPIKey: true,
		Model:       "gpt-4o",
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("UpsertProfile clear key: %v", err)
	}
	if pubCleared.HasAPIKey || pubCleared.APIKeyPreview != "" {
		t.Fatalf("expected cleared key in public view, got %+v", pubCleared)
	}
	saved, _ = store.GetProfile("openai-main")
	if saved.APIKey != "" || saved.ClearAPIKey {
		t.Fatalf("expected empty APIKey and ClearAPIKey=false, got %+v", saved)
	}

	// Add second profile, test SetActiveProfile, UpdateSettings clamping, DeleteProfile fallback.
	_, err = store.UpsertProfile(ProviderConfig{
		ID:       "ollama-local",
		Provider: ProviderOllama,
		BaseURL:  "http://127.0.0.1:11434",
		Model:    "qwen2.5-coder:14b",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("UpsertProfile ollama: %v", err)
	}
	if err := store.SetActiveProfile("ollama-local"); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}
	if err := store.UpdateSettings(AISettingsUpdate{
		AutoHealEnabled: boolPtr(true),
		MaxAutoRetries:  intPtr(99), // should clamp to 5
		RedactSecrets:   boolPtr(false),
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	// Reload from disk in a fresh ConfigStore instance.
	reloaded, err := NewConfigStore(dir)
	if err != nil {
		t.Fatalf("reload ConfigStore: %v", err)
	}
	rcfg := reloaded.GetPublicConfig()
	if rcfg.ActiveProfileID != "ollama-local" || !rcfg.AutoHealEnabled || rcfg.MaxAutoRetries != 5 || rcfg.RedactSecrets {
		t.Fatalf("reloaded config mismatch: %+v", rcfg)
	}

	// Delete active profile -> falls back to remaining enabled profile.
	if err := reloaded.DeleteProfile("ollama-local"); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	active, ok := reloaded.GetActiveProfile()
	if !ok || active.ID != "openai-main" {
		t.Fatalf("expected fallback active profile openai-main, got ok=%v id=%q", ok, active.ID)
	}

	// Concurrent reads/writes under -race.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = reloaded.GetPublicConfig()
				_, _ = reloaded.GetActiveProfile()
				_ = reloaded.UpdateSettings(AISettingsUpdate{MaxAutoRetries: intPtr((idx+j)%5 + 1)})
			}
		}(i)
	}
	wg.Wait()
}

func TestAllFourProviderProtocolsAndTestConnection(t *testing.T) {
	diagPayload := mustJSON(t, map[string]any{
		"root_cause":     "missing semicolon",
		"error_category": "syntax_error",
		"confidence":     0.95,
		"fix_kind":       "code_patch",
		"explanation":    "Added closing parenthesis.",
		"patched_code":   "console.log('ok');",
		"verify_hint":    "node --check",
	})

	t.Run("openai_compat", func(t *testing.T) {
		var mu sync.Mutex
		var gotPath, gotAuth, gotModel string
		baseURL, attach := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			gotModel, _ = req["model"].(string)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"role": "assistant", "content": diagPayload}},
				},
				"usage": map[string]any{"prompt_tokens": 111, "completion_tokens": 22},
			})
		}))

		client := NewClient()
		attach(client)
		prof := ProviderConfig{
			Provider: ProviderOpenAICompat,
			BaseURL:  baseURL + "/v1",
			APIKey:   "sk-openai-test-key-1234567890",
			Model:    "gpt-4.1",
		}
		resp, err := client.Complete(context.Background(), prof, "sys", "usr")
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		mu.Lock()
		path, auth, model := gotPath, gotAuth, gotModel
		mu.Unlock()
		if path != "/v1/chat/completions" {
			t.Fatalf("path = %q, want /v1/chat/completions", path)
		}
		if auth != "Bearer sk-openai-test-key-1234567890" {
			t.Fatalf("Authorization = %q", auth)
		}
		if model != "gpt-4.1" || resp.PromptTokens != 111 || resp.CompletionTokens != 22 {
			t.Fatalf("unexpected response metadata: model=%q resp=%+v", model, resp)
		}
		tc := client.TestConnection(context.Background(), prof)
		if !tc.OK || tc.Provider != ProviderOpenAICompat {
			t.Fatalf("TestConnection failed: %+v", tc)
		}
	})

	t.Run("anthropic", func(t *testing.T) {
		var mu sync.Mutex
		var gotPath, gotKey, gotVer, gotSystem string
		baseURL, attach := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			gotPath = r.URL.Path
			gotKey = r.Header.Get("x-api-key")
			gotVer = r.Header.Get("anthropic-version")
			gotSystem, _ = req["system"].(string)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": diagPayload},
				},
				"usage": map[string]any{"input_tokens": 200, "output_tokens": 45},
			})
		}))

		client := NewClient()
		attach(client)
		prof := ProviderConfig{
			Provider: ProviderAnthropic,
			BaseURL:  baseURL,
			APIKey:   "sk-ant-test-key-1234567890",
			Model:    "claude-sonnet-4-20250514",
		}
		resp, err := client.Complete(context.Background(), prof, "sys-anthropic", "usr")
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		mu.Lock()
		path, key, ver, sys := gotPath, gotKey, gotVer, gotSystem
		mu.Unlock()
		if path != "/v1/messages" {
			t.Fatalf("path = %q, want /v1/messages", path)
		}
		if key != "sk-ant-test-key-1234567890" || ver != "2023-06-01" {
			t.Fatalf("headers mismatch: key=%q ver=%q", key, ver)
		}
		if sys != "sys-anthropic" || resp.PromptTokens != 200 || resp.CompletionTokens != 45 {
			t.Fatalf("unexpected anthropic response: sys=%q resp=%+v", sys, resp)
		}
		tc := client.TestConnection(context.Background(), prof)
		if !tc.OK {
			t.Fatalf("TestConnection failed: %+v", tc)
		}
	})

	t.Run("gemini", func(t *testing.T) {
		var mu sync.Mutex
		var gotPath, gotQuery, gotKey string
		baseURL, attach := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotPath = r.URL.Path
			gotQuery = r.URL.RawQuery
			gotKey = r.Header.Get("x-goog-api-key")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"candidates": []map[string]any{
					{
						"content": map[string]any{
							"parts": []map[string]any{{"text": diagPayload}},
						},
					},
				},
				"usageMetadata": map[string]any{
					"promptTokenCount":     300,
					"candidatesTokenCount": 60,
				},
			})
		}))

		client := NewClient()
		attach(client)
		prof := ProviderConfig{
			Provider: ProviderGemini,
			BaseURL:  baseURL,
			APIKey:   "AIzaSyTestKey1234567890abcdefghijklmno",
			Model:    "gemini-2.5-pro",
		}
		resp, err := client.Complete(context.Background(), prof, "sys-gemini", "usr")
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		mu.Lock()
		path, query, key := gotPath, gotQuery, gotKey
		mu.Unlock()
		if path != "/v1beta/models/gemini-2.5-pro:generateContent" {
			t.Fatalf("path = %q, want /v1beta/models/gemini-2.5-pro:generateContent", path)
		}
		if query != "" {
			t.Fatalf("Gemini MUST NEVER send query params, got %q", query)
		}
		if key != "AIzaSyTestKey1234567890abcdefghijklmno" {
			t.Fatalf("x-goog-api-key header = %q", key)
		}
		if resp.PromptTokens != 300 || resp.CompletionTokens != 60 {
			t.Fatalf("unexpected gemini usage: %+v", resp)
		}
		tc := client.TestConnection(context.Background(), prof)
		if !tc.OK {
			t.Fatalf("TestConnection failed: %+v", tc)
		}

		// Reject path traversal / query smuggling in Gemini model name.
		badProf := prof
		badProf.Model = "gemini-2.5-pro?key=leak"
		if _, err := client.Complete(context.Background(), badProf, "sys", "usr"); err == nil {
			t.Fatalf("expected invalid Gemini model name error")
		}
	})

	t.Run("ollama", func(t *testing.T) {
		var mu sync.Mutex
		var gotPath string
		var gotStream any
		baseURL, attach := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			gotPath = r.URL.Path
			gotStream = req["stream"]
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message":           map[string]any{"role": "assistant", "content": diagPayload},
				"prompt_eval_count": 150,
				"eval_count":        33,
			})
		}))

		client := NewClient()
		attach(client)
		prof := ProviderConfig{
			Provider: ProviderOllama,
			BaseURL:  baseURL,
			Model:    "qwen2.5-coder:14b",
		}
		resp, err := client.Complete(context.Background(), prof, "sys-ollama", "usr")
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		mu.Lock()
		path, streamVal := gotPath, gotStream
		mu.Unlock()
		if path != "/api/chat" {
			t.Fatalf("path = %q, want /api/chat", path)
		}
		if streamBool, ok := streamVal.(bool); !ok || streamBool {
			t.Fatalf("ollama stream = %#v, want false", streamVal)
		}
		if resp.PromptTokens != 150 || resp.CompletionTokens != 33 {
			t.Fatalf("unexpected ollama usage: %+v", resp)
		}
		tc := client.TestConnection(context.Background(), prof)
		if !tc.OK {
			t.Fatalf("TestConnection failed: %+v", tc)
		}
	})
}

func TestClientSecurityValidationErrorRedactionAndLimits(t *testing.T) {
	// Invalid URL schemes / malformed URLs rejected.
	badURLs := []string{
		"",
		"file:///etc/passwd",
		"ftp://example.com/v1",
		"javascript:alert(1)",
		"https://",
		"https://user:pass@api.openai.com/v1",
		"https://api.openai.com/v1#frag",
	}
	for _, u := range badURLs {
		if _, err := ValidateBaseURL(u); err == nil {
			t.Errorf("ValidateBaseURL(%q) unexpectedly succeeded", u)
		}
	}

	// API key echoed by provider error response must be redacted from returned error.
	secretKey := "sk-super-secret-leak-check-99999"
	errURL, attachErr := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Invalid API key provided: " + secretKey,
			},
		})
	}))

	client := NewClient()
	attachErr(client)
	prof := ProviderConfig{
		Provider: ProviderOpenAICompat,
		BaseURL:  errURL + "/v1",
		APIKey:   secretKey,
		Model:    "gpt-4.1",
	}
	_, err := client.Complete(context.Background(), prof, "sys", "usr")
	if err == nil {
		t.Fatalf("expected HTTP 401 error")
	}
	if strings.Contains(err.Error(), secretKey) {
		t.Fatalf("API key leaked in error message: %s", err.Error())
	}
	tc := client.TestConnection(context.Background(), prof)
	if tc.OK || strings.Contains(tc.Error, secretKey) {
		t.Fatalf("TestConnection leaked secret or returned OK: %+v", tc)
	}

	// Redirect must be rejected.
	redirURL, attachRedir := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
	}))
	redirClient := NewClient()
	attachRedir(redirClient)
	prof.BaseURL = redirURL
	if _, err := redirClient.Complete(context.Background(), prof, "sys", "usr"); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection error, got: %v", err)
	}

	// Response body > 4 MiB must be rejected cleanly.
	bigURL, attachBig := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := strings.Repeat("a", 64*1024)
		for i := 0; i < 70; i++ { // ~4.4 MiB
			_, _ = io.WriteString(w, chunk)
		}
	}))
	bigClient := NewClient()
	attachBig(bigClient)
	prof.BaseURL = bigURL
	if _, err := bigClient.Complete(context.Background(), prof, "sys", "usr"); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected >4MiB response limit error, got: %v", err)
	}
}

func TestRedactSecretsAndCompressLogs(t *testing.T) {
	// 1. Line compression (head 40 + tail 120).
	var lines []string
	for i := 1; i <= 250; i++ {
		lines = append(lines, fmt.Sprintf("line-%03d: diagnostic payload", i))
	}
	compressed := CompressLogs(strings.Join(lines, "\n"))
	if !strings.Contains(compressed, "line-001:") || !strings.Contains(compressed, "line-040:") {
		t.Fatalf("compressed logs missing head lines")
	}
	if strings.Contains(compressed, "line-090:") {
		t.Fatalf("compressed logs failed to omit middle lines")
	}
	if !strings.Contains(compressed, "line-250:") || !strings.Contains(compressed, "lines omitted") {
		t.Fatalf("compressed logs missing tail or omission marker")
	}

	// 2. Hard 24 KiB cap with multibyte UTF-8 characters.
	hugeUTF8 := strings.Repeat("日志错误信息-中文测试-ABCDE-12345\n", 1500)
	capped := CompressLogs(hugeUTF8)
	if len(capped) > maxLogBytes {
		t.Fatalf("CompressLogs exceeded 24 KiB: len=%d > %d", len(capped), maxLogBytes)
	}
	if !utf8.ValidString(capped) {
		t.Fatalf("CompressLogs broke UTF-8 boundary")
	}

	// 3. Secret redaction across all required token/header/PEM/URL types.
	raw := strings.Join([]string{
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
		"Cookie: session_id=topsecretcookie123; theme=dark",
		"Set-Cookie: sid=anothersecret456; HttpOnly",
		"X-Api-Key: custom-header-api-secret",
		"proxy=http://alice:superpass123@10.0.0.5:8080/tunnel",
		"openai=sk-proj-1234567890abcdef123456",
		"gemini=AIzaSyA1234567890abcdefghijklmno12345",
		"github=ghp_1234567890abcdef1234567890abcdef",
		"basic=Basic dXNlcjpzZWNyZXRwYXNz",
		"url=https://api.example.com/v1/data?api_key=querysecret999&page=1",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretkeymaterial\n-----END RSA PRIVATE KEY-----",
	}, "\n")

	cleaned, count := RedactSecrets(raw)
	if count < 9 {
		t.Fatalf("expected >= 9 redactions, got %d\ncleaned:\n%s", count, cleaned)
	}
	leaks := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"topsecretcookie123",
		"anothersecret456",
		"custom-header-api-secret",
		"superpass123",
		"sk-proj-1234567890abcdef123456",
		"AIzaSyA1234567890abcdefghijklmno12345",
		"ghp_1234567890abcdef1234567890abcdef",
		"dXNlcjpzZWNyZXRwYXNz",
		"querysecret999",
		"MIIEowIBAAKCAQEAsecretkeymaterial",
	}
	for _, secret := range leaks {
		if strings.Contains(cleaned, secret) {
			t.Errorf("secret %q was NOT redacted:\n%s", secret, cleaned)
		}
	}
}

func TestBuildPreDiagnosis(t *testing.T) {
	// Unidbg pre-diagnosis delegates to repro.AnalyzeUnidbgLog.
	unidbgDiag := BuildPreDiagnosis(DiagnoseRequest{
		Scope: ScopeUnidbg,
		Logs: strings.Join([]string{
			"java.lang.UnsupportedOperationException: callObjectMethodV: android/content/Context->getPackageName()Ljava/lang/String;",
			"FileNotFoundException: /proc/self/cmdline",
			"__system_property_get key=ro.build.version.sdk",
			"library not found: libcrypto_custom.so",
		}, "\n"),
	})
	for _, want := range []string{"Deterministic Unidbg Analysis", "getPackageName", "/proc/self/cmdline", "ro.build.version.sdk", "libcrypto_custom.so"} {
		if !strings.Contains(unidbgDiag, want) {
			t.Errorf("Unidbg pre-diagnosis missing %q:\n%s", want, unidbgDiag)
		}
	}

	// Frida pre-diagnosis extracts overload & class mismatch hints.
	fridaDiag := BuildPreDiagnosis(DiagnoseRequest{
		Scope: ScopeFrida,
		Logs: `Error: sign(): has more than one overload, use .overload(<signature>) to choose from:
	.overload('java.lang.String')
	.overload('[B', 'int')
ClassNotFoundException: com.example.MissingSigner`,
	})
	for _, want := range []string{"Deterministic Frida Analysis", ".overload('java.lang.String')", ".overload('[B', 'int')", "com.example.MissingSigner"} {
		if !strings.Contains(fridaDiag, want) {
			t.Errorf("Frida pre-diagnosis missing %q:\n%s", want, fridaDiag)
		}
	}

	// Qiling pre-diagnosis extracts UC_ERR_* and faulting addresses.
	qilingDiag := BuildPreDiagnosis(DiagnoseRequest{
		Scope: ScopeQiling,
		Logs:  "unicorn.unicorn.UcError: Invalid memory read (UC_ERR_READ_UNMAPPED) at pc=0x40012000 accessing addr=0xdead0000\nFileNotFoundError: /rootfs/lib/libc.so.6",
	})
	for _, want := range []string{"Deterministic Qiling Analysis", "UC_ERR_READ_UNMAPPED", "0x40012000", "0xdead0000", "re_qiling_rootfs"} {
		if !strings.Contains(qilingDiag, want) {
			t.Errorf("Qiling pre-diagnosis missing %q:\n%s", want, qilingDiag)
		}
	}
}

func TestPromptsAndParseDiagnoseJSON(t *testing.T) {
	zhPrompt := BuildSystemPrompt(ScopeUnidbg, "zh-CN")
	enPrompt := BuildSystemPrompt(ScopeFrida, "en")
	if !strings.Contains(zhPrompt, "简体中文") || !strings.Contains(zhPrompt, "AbstractJni") {
		t.Fatalf("zh-CN unidbg prompt missing expected instructions")
	}
	if !strings.Contains(enPrompt, "English") || !strings.Contains(enPrompt, "Java.perform") {
		t.Fatalf("en frida prompt missing expected instructions")
	}

	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "raw JSON",
			raw:  `{"root_cause":"bad syntax","error_category":"syntax_error","confidence":0.9,"fix_kind":"code_patch","explanation":"fixed","patched_code":"function ok() { return 1; }"}`,
		},
		{
			name: "json markdown fence with commentary",
			raw: "Sure! Here is the diagnosis:\n```json\n" +
				`{"root_cause":"bad syntax","error_category":"syntax_error","confidence":0.9,"fix_kind":"code_patch","explanation":"fixed","patched_code":"function ok() { return { a: 1 }; }"}` +
				"\n```\nHope this helps!",
		},
		{
			name: "plain prose surrounding JSON with nested braces",
			raw:  `Analysis complete (note: avoid {bad}): {"root_cause":"bad syntax","error_category":"syntax_error","confidence":1.4,"fix_kind":"code_patch","explanation":"fixed","patched_code":"class A { void m() {} }"} Done.`,
		},
		{
			name: "UTF-8 BOM prefix",
			raw:  "\uFEFF" + `{"root_cause":"bad syntax","error_category":"syntax_error","confidence":0.8,"fix_kind":"explanation_only","explanation":"check logs"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseDiagnoseJSON(tc.raw)
			if err != nil {
				t.Fatalf("ParseDiagnoseJSON failed: %v", err)
			}
			if res.RootCause != "bad syntax" {
				t.Fatalf("RootCause = %q, want 'bad syntax'", res.RootCause)
			}
			if res.Confidence < 0 || res.Confidence > 1 {
				t.Fatalf("Confidence not clamped to [0,1]: %v", res.Confidence)
			}
		})
	}

	if _, err := ParseDiagnoseJSON("This is plain prose with no JSON at all."); err == nil {
		t.Fatalf("expected error on non-JSON text")
	}
}

func TestComputeUnifiedDiff(t *testing.T) {
	if diff := ComputeUnifiedDiff("a\nb\n", "a\nb\n"); diff != "" {
		t.Fatalf("expected empty diff for identical texts, got:\n%s", diff)
	}

	oldCode := "line1\nline2\nline3\nline4\nline5\n"
	newCode := "line1\nline2\nline3_fixed\nline4\nline5\nline6_added\n"
	diff := ComputeUnifiedDiff(oldCode, newCode)
	for _, want := range []string{"--- a/code", "+++ b/code", "@@ -", "-line3", "+line3_fixed", "+line6_added"} {
		if !strings.Contains(diff, want) {
			t.Errorf("unified diff missing %q:\n%s", want, diff)
		}
	}
}

func TestValidatePatchedCodeAndSanitizeConfigChanges(t *testing.T) {
	// Empty patch rejected.
	if v := ValidatePatchedCode("javascript", "var x = 1;", "   \n\t "); v.Passed {
		t.Fatalf("empty patch should fail validation")
	}

	// Destructive patterns blocked.
	destructiveSamples := []string{
		`os.system("rm -rf /")`,
		`exec("rm -fr /*")`,
		`subprocess.run(["mkfs.ext4", "/dev/sda1"])`,
		`dd if=/dev/zero of=/dev/disk0`,
		`:(){ :|:& };:`,
		`echo x > /dev/sda`,
	}
	for _, bad := range destructiveSamples {
		v := ValidatePatchedCode("python", "print(1)", bad)
		if v.Passed {
			t.Errorf("destructive sample unexpectedly passed: %q", bad)
		}
	}
	// Benign temp cleanup should NOT be falsely blocked.
	if v := ValidatePatchedCode("python", "print(1)", "cmd = \"rm -rf /tmp/cap-build\"\nprint(cmd)\n"); !v.Passed {
		t.Fatalf("benign /tmp cleanup falsely blocked: %+v", v)
	}

	// JavaScript valid & invalid (node --check on PATH + fallback helper).
	if v := ValidatePatchedCode("javascript", "const a = 1;", "const a = 2;\nconsole.log(a);\n"); !v.Passed {
		t.Fatalf("valid JS failed validation: %+v", v)
	}
	if v := ValidatePatchedCode("javascript", "const a = 1;", "function broken( { return 1; "); v.Passed {
		t.Fatalf("invalid JS unexpectedly passed validation: %+v", v)
	}
	if v := validateJSBalanced("const s = '{not a brace}'; /* ( */ function f() { return [1, 2]; }", nil); !v.Passed {
		t.Fatalf("validateJSBalanced failed on valid JS: %+v", v)
	}
	if v := validateJSBalanced("function f() { return [1, 2; }", nil); v.Passed {
		t.Fatalf("validateJSBalanced passed on unbalanced JS: %+v", v)
	}

	// Python valid & invalid (python3 -m py_compile + fallback helper).
	if v := ValidatePatchedCode("python", "x = 1", "def solve(x):\n    return x + 1\n"); !v.Passed {
		t.Fatalf("valid Python failed validation: %+v", v)
	}
	if v := ValidatePatchedCode("python", "x = 1", "def broken(:\n    pass\n"); v.Passed {
		t.Fatalf("invalid Python unexpectedly passed validation: %+v", v)
	}
	if v := validatePythonBalanced("x = '{ignored}' # (\ndef f():\n    return [1, (2, 3)]\n", nil); !v.Passed {
		t.Fatalf("validatePythonBalanced failed on valid Python: %+v", v)
	}
	if v := validatePythonBalanced("def f():\n    return (1, 2]\n", nil); v.Passed {
		t.Fatalf("validatePythonBalanced passed on unbalanced Python: %+v", v)
	}

	// Java structural validator.
	validJava := `package com.example;
// comment with { unmatched brace
public class MyStub {
    public String name() {
        String s = "unmatched { inside string";
        char brace = '{';
        return s + brace;
    }
}`
	if v := ValidatePatchedCode("java", "", validJava); !v.Passed {
		t.Fatalf("valid Java failed validation: %+v", v)
	}
	if v := ValidatePatchedCode("java", "", "public void orphanMethod() { int x = 1; }"); v.Passed {
		t.Fatalf("Java without class declaration unexpectedly passed: %+v", v)
	}
	if v := ValidatePatchedCode("java", "", "public class Broken { void f() { "); v.Passed {
		t.Fatalf("Java with unbalanced braces unexpectedly passed: %+v", v)
	}

	// SanitizeConfigChanges strict allowlist.
	sanitized := SanitizeConfigChanges(map[string]string{
		"re_r2_path":            "/usr/local/bin/r2",
		"re_java_path":          "/usr/bin/java",
		"re_mvn_path":           "/usr/local/bin/mvn",
		"re_unidbg_dir":         "/opt/unidbg",
		"re_python_path":        "/usr/bin/python3",
		"re_qiling_python_path": "/opt/ql/bin/python3",
		"re_angr_python_path":   "/opt/angr/bin/python3",
		"re_qiling_rootfs":      "/opt/rootfs/arm64_android",
		"frida_python_path":     "/opt/frida/bin/python3",
		"frida_cli_path":        "/opt/frida/bin/frida",
		"frida_default_port":    "27042",
		"gateway_addr":          "127.0.0.1:9000",
		"proxy_addr":            "127.0.0.1:8080",
		"evil_shell_cmd":        "rm -rf /",
		"api_key":               "sk-should-drop",
	})
	if len(sanitized) != 13 {
		t.Fatalf("expected all 13 allowlisted keys preserved and dangerous keys dropped, got %d: %+v", len(sanitized), sanitized)
	}
	if _, bad := sanitized["evil_shell_cmd"]; bad {
		t.Fatalf("non-allowlisted key survived sanitization")
	}
	badVals := SanitizeConfigChanges(map[string]string{
		"frida_default_port": "not-a-port",
		"re_python_path":     "/usr/bin/python3\nrm -rf /",
		"proxy_addr":         "127.0.0.1:8080 --inject",
	})
	if len(badVals) != 0 {
		t.Fatalf("invalid config values survived sanitization: %+v", badVals)
	}
}

func newTestManagerWithMockLLM(t *testing.T, handler func(call int, authHeader, systemPrompt, userPrompt string) string) *Manager {
	t.Helper()
	var calls atomic.Int32
	baseURL, attach := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var sys, usr string
		for _, m := range body.Messages {
			if m.Role == "system" {
				sys = m.Content
			} else if m.Role == "user" {
				usr = m.Content
			}
		}
		n := int(calls.Add(1))
		reply := handler(n, r.Header.Get("Authorization"), sys, usr)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": reply}},
			},
			"usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 25},
		})
	}))

	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	attach(mgr.client)
	if _, err := mgr.UpsertProfile(ProviderConfig{
		ID:       "mock-openai",
		Provider: ProviderOpenAICompat,
		BaseURL:  baseURL + "/v1",
		APIKey:   "sk-mock-secret-key-123456",
		Model:    "mock-model",
		Enabled:  true,
	}); err != nil {
		t.Fatalf("UpsertProfile: %v", err)
	}
	return mgr
}

func TestDiagnoseAndFixEndToEndRedactionPreDiagnosisAndMaskedTestConnection(t *testing.T) {
	var mu sync.Mutex
	var seenUserPrompt, seenAuth string
	mgr := newTestManagerWithMockLLM(t, func(_ int, auth, _, userPrompt string) string {
		mu.Lock()
		seenAuth = auth
		seenUserPrompt = userPrompt
		mu.Unlock()
		return "```json\n" + mustJSON(t, map[string]any{
			"root_cause":     "Missing Context.getPackageName JNI stub",
			"error_category": "missing_jni",
			"confidence":     0.92,
			"fix_kind":       "code_patch",
			"explanation":    "Added getPackageName case in callObjectMethodV.",
			"patched_code":   "public class SignRunner {\n    String pkg() { return \"com.demo.app\"; }\n}\n",
			"verify_hint":    "Re-run Unidbg",
		}) + "\n```"
	})

	// Manager.TestConnection with masked APIKeyPreview should resolve stored key.
	pub := mgr.GetPublicConfig()
	profPub := pub.Profiles[0]
	tc := mgr.TestConnection(context.Background(), ProviderConfig{
		ID:       profPub.ID,
		Provider: profPub.Provider,
		BaseURL:  profPub.BaseURL,
		APIKey:   profPub.APIKeyPreview,
		Model:    profPub.Model,
		Enabled:  true,
	})
	if !tc.OK {
		t.Fatalf("Manager.TestConnection with masked preview failed: %+v", tc)
	}
	mu.Lock()
	authAfterTest := seenAuth
	mu.Unlock()
	if authAfterTest != "Bearer sk-mock-secret-key-123456" {
		t.Fatalf("Manager.TestConnection did not reuse stored key; got Authorization=%q", authAfterTest)
	}
	if tc2 := mgr.TestProfileByID(context.Background(), profPub.ID); !tc2.OK {
		t.Fatalf("TestProfileByID failed: %+v", tc2)
	}

	res, err := mgr.DiagnoseAndFix(context.Background(), DiagnoseRequest{
		Scope:    ScopeUnidbg,
		Language: "java",
		Locale:   "zh-CN",
		Code:     "public class SignRunner {\n    String pkg() { return null; }\n}\n",
		Logs: strings.Join([]string{
			"Authorization: Bearer top-secret-bearer-token-999999",
			"java.lang.UnsupportedOperationException: callObjectMethodV: android/content/Context->getPackageName()Ljava/lang/String;",
		}, "\n"),
	})
	if err != nil {
		t.Fatalf("DiagnoseAndFix: %v", err)
	}
	mu.Lock()
	prompt := seenUserPrompt
	mu.Unlock()
	if strings.Contains(prompt, "top-secret-bearer-token-999999") {
		t.Fatalf("secret was sent to LLM prompt!")
	}
	if !strings.Contains(prompt, "Deterministic Unidbg Analysis") {
		t.Fatalf("pre-diagnosis was not included in LLM prompt:\n%s", prompt)
	}
	if res.RedactedCount < 1 || res.PreDiagnosis == "" {
		t.Fatalf("expected RedactedCount>=1 and non-empty PreDiagnosis: %+v", res)
	}
	if res.Validation == nil || !res.Validation.Passed {
		t.Fatalf("expected valid Java patch, got %+v", res.Validation)
	}
	if !strings.Contains(res.UnifiedDiff, "+    String pkg() { return \"com.demo.app\"; }") {
		t.Fatalf("unexpected UnifiedDiff:\n%s", res.UnifiedDiff)
	}
	if res.ProviderUsed != ProviderOpenAICompat || res.ModelUsed != "mock-model" {
		t.Fatalf("provider metadata mismatch: %+v", res)
	}
}

func TestRunAutoHealLoopAllExitPaths(t *testing.T) {
	t.Run("already_ok", func(t *testing.T) {
		var llmCalls atomic.Int32
		mgr := newTestManagerWithMockLLM(t, func(_ int, _, _, _ string) string {
			llmCalls.Add(1)
			return "{}"
		})
		var events []AutoHealEvent
		res, err := mgr.RunAutoHealLoop(
			context.Background(),
			DiagnoseRequest{Scope: ScopeFrida, Language: "javascript", Code: "console.log('hi');"},
			3,
			func(_ context.Context, _ string) (int, string, error) {
				return 0, "ok", nil
			},
			func(ev AutoHealEvent) { events = append(events, ev) },
		)
		if err != nil {
			t.Fatalf("RunAutoHealLoop: %v", err)
		}
		if !res.Healed || res.StopReason != StopReasonAlreadyOK || llmCalls.Load() != 0 {
			t.Fatalf("unexpected already_ok result: %+v llmCalls=%d", res, llmCalls.Load())
		}
		if len(events) < 2 {
			t.Fatalf("expected progress events, got %d", len(events))
		}
	})

	t.Run("healed_in_two_attempts", func(t *testing.T) {
		var secondPromptSawPrev atomic.Bool
		mgr := newTestManagerWithMockLLM(t, func(call int, _, _, userPrompt string) string {
			if call == 1 {
				return mustJSON(t, map[string]any{
					"root_cause":     "missing overload",
					"error_category": "overload_mismatch",
					"confidence":     0.85,
					"fix_kind":       "code_patch",
					"explanation":    "Added overload",
					"patched_code":   "const step = 1;\nconsole.log(step);\n",
				})
			}
			secondPromptSawPrev.Store(strings.Contains(userPrompt, "Previous Failed Repair Attempts"))
			return mustJSON(t, map[string]any{
				"root_cause":     "missing null check",
				"error_category": "runtime_error",
				"confidence":     0.95,
				"fix_kind":       "code_patch",
				"explanation":    "Added null check",
				"patched_code":   "const step = 2;\nconsole.log(step);\n",
			})
		})

		var events []AutoHealEvent
		res, err := mgr.RunAutoHealLoop(
			context.Background(),
			DiagnoseRequest{Scope: ScopeFrida, Language: "javascript", Code: "const step = 0;\n"},
			3,
			func(_ context.Context, code string) (int, string, error) {
				switch {
				case strings.Contains(code, "step = 0"):
					return 1, "Error: sign(): has more than one overload", nil
				case strings.Contains(code, "step = 1"):
					return 1, "TypeError: cannot read property 'length' of null", nil
				default:
					return 0, "hook attached OK", nil
				}
			},
			func(ev AutoHealEvent) { events = append(events, ev) },
		)
		if err != nil {
			t.Fatalf("RunAutoHealLoop: %v", err)
		}
		if !res.Healed || res.StopReason != StopReasonHealed || res.FinalExitCode != 0 {
			t.Fatalf("expected healed, got %+v", res)
		}
		if !secondPromptSawPrev.Load() {
			t.Fatalf("second attempt prompt did not include PreviousAttempts history")
		}
		if !strings.Contains(res.FinalCode, "step = 2") {
			t.Fatalf("FinalCode mismatch: %q", res.FinalCode)
		}
		if len(events) < 5 {
			t.Fatalf("expected multiple lifecycle events, got %d", len(events))
		}
	})

	t.Run("repeated_error", func(t *testing.T) {
		var llmCalls atomic.Int32
		mgr := newTestManagerWithMockLLM(t, func(call int, _, _, _ string) string {
			llmCalls.Add(1)
			return mustJSON(t, map[string]any{
				"root_cause":     "retry attempt",
				"error_category": "runtime_error",
				"confidence":     0.7,
				"fix_kind":       "code_patch",
				"explanation":    "Adjusted variable",
				"patched_code":   fmt.Sprintf("const attempt = %d;\n", call),
			})
		})

		runCount := 0
		res, err := mgr.RunAutoHealLoop(
			context.Background(),
			DiagnoseRequest{Scope: ScopeFrida, Language: "javascript", Code: "const attempt = 0;\n"},
			4,
			func(_ context.Context, _ string) (int, string, error) {
				runCount++
				// Same root error with different timestamps & PIDs -> same normalized fingerprint.
				return 1, fmt.Sprintf("2026-11-25T17:20:0%dZ pid=%d Error: unable to resolve symbol foo_sign", runCount, 1000+runCount), nil
			},
			nil,
		)
		if err != nil {
			t.Fatalf("RunAutoHealLoop: %v", err)
		}
		if res.Healed || res.StopReason != StopReasonRepeatedError {
			t.Fatalf("expected repeated_error, got %+v", res)
		}
		if llmCalls.Load() != 1 {
			t.Fatalf("expected stop after 1st repeated failure (no wasted retries), got %d LLM calls", llmCalls.Load())
		}
	})

	t.Run("validation_failed_syntax_and_destructive", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			lang string
			code string
		}{
			{"broken_js", "javascript", "function broken( { return ;"},
			{"destructive_py", "python", "import os\nos.system('rm -rf /')\n"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mgr := newTestManagerWithMockLLM(t, func(_ int, _, _, _ string) string {
					return mustJSON(t, map[string]any{
						"root_cause":     "bad patch",
						"error_category": "syntax_error",
						"confidence":     0.6,
						"fix_kind":       "code_patch",
						"explanation":    "Unsafe or invalid patch",
						"patched_code":   tc.code,
					})
				})

				runnerCalls := 0
				origCode := "console.log('start');\n"
				res, err := mgr.RunAutoHealLoop(
					context.Background(),
					DiagnoseRequest{Scope: ScopeFrida, Language: tc.lang, Code: origCode},
					3,
					func(_ context.Context, _ string) (int, string, error) {
						runnerCalls++
						return 1, "ReferenceError: foo is not defined", nil
					},
					nil,
				)
				if err != nil {
					t.Fatalf("RunAutoHealLoop: %v", err)
				}
				if res.Healed || res.StopReason != StopReasonValidationFailed {
					t.Fatalf("expected validation_failed, got %+v", res)
				}
				if runnerCalls != 1 {
					t.Fatalf("invalid patch must NEVER be executed; runnerCalls=%d", runnerCalls)
				}
				if res.FinalCode != origCode {
					t.Fatalf("FinalCode should remain uncorrupted original code, got %q", res.FinalCode)
				}
			})
		}
	})

	t.Run("unchanged_code", func(t *testing.T) {
		origCode := "console.log('same');\n"
		mgr := newTestManagerWithMockLLM(t, func(_ int, _, _, _ string) string {
			return mustJSON(t, map[string]any{
				"root_cause":     "no change",
				"error_category": "runtime_error",
				"confidence":     0.5,
				"fix_kind":       "code_patch",
				"explanation":    "Returned identical code",
				"patched_code":   origCode,
			})
		})
		res, err := mgr.RunAutoHealLoop(
			context.Background(),
			DiagnoseRequest{Scope: ScopeFrida, Language: "javascript", Code: origCode},
			3,
			func(_ context.Context, _ string) (int, string, error) {
				return 1, "Error: boom", nil
			},
			nil,
		)
		if err != nil {
			t.Fatalf("RunAutoHealLoop: %v", err)
		}
		if res.Healed || res.StopReason != StopReasonUnchangedCode {
			t.Fatalf("expected unchanged_code, got %+v", res)
		}
	})

	t.Run("non_patch_fix", func(t *testing.T) {
		mgr := newTestManagerWithMockLLM(t, func(_ int, _, _, _ string) string {
			return mustJSON(t, map[string]any{
				"root_cause":     "wrong qiling rootfs",
				"error_category": "config_error",
				"confidence":     0.9,
				"fix_kind":       "config_fix",
				"explanation":    "Update re_qiling_rootfs setting",
				"config_changes": map[string]string{
					"re_qiling_rootfs": "/opt/qiling/rootfs",
					"malicious_key":    "drop-me",
				},
			})
		})
		res, err := mgr.RunAutoHealLoop(
			context.Background(),
			DiagnoseRequest{Scope: ScopeQiling, Language: "python", Code: "print('hi')\n"},
			3,
			func(_ context.Context, _ string) (int, string, error) {
				return 1, "FileNotFoundError: /bad/rootfs", nil
			},
			nil,
		)
		if err != nil {
			t.Fatalf("RunAutoHealLoop: %v", err)
		}
		if res.Healed || res.StopReason != StopReasonNonPatchFix {
			t.Fatalf("expected non_patch_fix, got %+v", res)
		}
		lastDiag := res.Attempts[len(res.Attempts)-1].Diagnosis
		if lastDiag == nil || lastDiag.ConfigChanges["re_qiling_rootfs"] != "/opt/qiling/rootfs" || len(lastDiag.ConfigChanges) != 1 {
			t.Fatalf("expected sanitized config changes, got %+v", lastDiag)
		}
	})

	t.Run("max_retries", func(t *testing.T) {
		mgr := newTestManagerWithMockLLM(t, func(call int, _, _, _ string) string {
			return mustJSON(t, map[string]any{
				"root_cause":     fmt.Sprintf("step %d", call),
				"error_category": "runtime_error",
				"confidence":     0.8,
				"fix_kind":       "code_patch",
				"explanation":    "Patching next fault",
				"patched_code":   fmt.Sprintf("x = %d\nprint(x)\n", call),
			})
		})

		runNum := 0
		res, err := mgr.RunAutoHealLoop(
			context.Background(),
			DiagnoseRequest{Scope: ScopeQiling, Language: "python", Code: "x = 0\n"},
			2,
			func(_ context.Context, _ string) (int, string, error) {
				runNum++
				// Each attempt hits a distinct unmapped address -> progresses until max_retries.
				return 1, fmt.Sprintf("UC_ERR_READ_UNMAPPED at 0x%x000", runNum), nil
			},
			nil,
		)
		if err != nil {
			t.Fatalf("RunAutoHealLoop: %v", err)
		}
		if res.Healed || res.StopReason != StopReasonMaxRetries {
			t.Fatalf("expected max_retries, got %+v", res)
		}
		if runNum != 3 { // initial + 2 retries
			t.Fatalf("runNum = %d, want 3", runNum)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		mgr := newTestManagerWithMockLLM(t, func(_ int, _, _, _ string) string {
			return "{}"
		})

		// Pre-cancelled context.
		preCtx, preCancel := context.WithCancel(context.Background())
		preCancel()
		res, err := mgr.RunAutoHealLoop(
			preCtx,
			DiagnoseRequest{Scope: ScopeFrida, Language: "javascript", Code: "console.log(1);"},
			3,
			func(_ context.Context, _ string) (int, string, error) {
				t.Fatalf("runner should not execute when context is already cancelled")
				return 0, "", nil
			},
			nil,
		)
		if err != nil {
			t.Fatalf("RunAutoHealLoop: %v", err)
		}
		if res.Healed || res.StopReason != StopReasonCancelled {
			t.Fatalf("expected cancelled on pre-cancelled ctx, got %+v", res)
		}

		// Mid-flight cancellation during initial runner failure.
		midCtx, midCancel := context.WithCancel(context.Background())
		res2, err := mgr.RunAutoHealLoop(
			midCtx,
			DiagnoseRequest{Scope: ScopeFrida, Language: "javascript", Code: "console.log(1);"},
			3,
			func(_ context.Context, _ string) (int, string, error) {
				midCancel()
				return 1, "interrupted", errors.New("context canceled")
			},
			nil,
		)
		if err != nil {
			t.Fatalf("RunAutoHealLoop mid-cancel: %v", err)
		}
		if res2.Healed || res2.StopReason != StopReasonCancelled {
			t.Fatalf("expected cancelled on mid-flight cancel, got %+v", res2)
		}
	})
}

func TestAuditSecurityAndHardeningFixes(t *testing.T) {
	t.Run("sensitive_extra_headers_redaction_and_case_insensitive_restore", func(t *testing.T) {
		store, err := NewConfigStore(t.TempDir())
		if err != nil {
			t.Fatalf("NewConfigStore: %v", err)
		}
		pub, err := store.UpsertProfile(ProviderConfig{
			ID:       "azure-custom",
			Provider: ProviderOpenAICompat,
			BaseURL:  "https://azure.example.com/openai/deployments/gpt4",
			APIKey:   "sk-primary-1234567890abcdef",
			Model:    "gpt-4.1",
			Enabled:  true,
			ExtraHeaders: map[string]string{
				"api-key":         "azure-plain-secret-value-888",
				"x-goog-api-key":  "goog-custom-secret-777",
				"X-Custom-Token":  "tenant-tok-666",
				"X-Tenant-Note":   "proxy Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
				"X-Public-Header": "cap-agent",
			},
		})
		if err != nil {
			t.Fatalf("UpsertProfile: %v", err)
		}

		pubJSON := mustJSON(t, store.GetPublicConfig())
		for _, secret := range []string{
			"sk-primary-1234567890abcdef",
			"azure-plain-secret-value-888",
			"goog-custom-secret-777",
			"tenant-tok-666",
			"eyJhbGciOiJIUzI1NiJ9.abc.def",
		} {
			if strings.Contains(pubJSON, secret) {
				t.Fatalf("secret %q leaked in GetPublicConfig(): %s", secret, pubJSON)
			}
		}
		if pub.ExtraHeaders["api-key"] != "[REDACTED]" || pub.ExtraHeaders["x-goog-api-key"] != "[REDACTED]" || pub.ExtraHeaders["X-Custom-Token"] != "[REDACTED]" {
			t.Fatalf("expected sensitive headers redacted: %+v", pub.ExtraHeaders)
		}
		if pub.ExtraHeaders["X-Public-Header"] != "cap-agent" {
			t.Fatalf("non-sensitive header altered: %q", pub.ExtraHeaders["X-Public-Header"])
		}

		// Case-insensitive restore of [REDACTED] headers on UpsertProfile.
		_, err = store.UpsertProfile(ProviderConfig{
			ID:       "azure-custom",
			Provider: ProviderOpenAICompat,
			BaseURL:  "https://azure.example.com/openai/deployments/gpt4",
			Model:    "gpt-4.1",
			Enabled:  true,
			ExtraHeaders: map[string]string{
				"API-KEY":        "[REDACTED]",
				"X-Goog-Api-Key": "[REDACTED]",
				"x-custom-token": "[REDACTED]",
				"X-Tenant-Note":  pub.ExtraHeaders["X-Tenant-Note"],
			},
		})
		if err != nil {
			t.Fatalf("UpsertProfile case-insensitive restore: %v", err)
		}
		saved, ok := store.GetProfile("azure-custom")
		if !ok {
			t.Fatalf("profile missing")
		}
		if saved.ExtraHeaders["API-KEY"] != "azure-plain-secret-value-888" ||
			saved.ExtraHeaders["X-Goog-Api-Key"] != "goog-custom-secret-777" ||
			saved.ExtraHeaders["x-custom-token"] != "tenant-tok-666" ||
			saved.ExtraHeaders["X-Tenant-Note"] != "proxy Bearer eyJhbGciOiJIUzI1NiJ9.abc.def" {
			t.Fatalf("case-insensitive ExtraHeaders restore failed: %+v", saved.ExtraHeaders)
		}
	})

	t.Run("manager_test_connection_restores_redacted_headers_and_scrubs_errors", func(t *testing.T) {
		var mu sync.Mutex
		var gotAPIKeyHdr string
		var failMode atomic.Bool
		baseURL, attach := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get("api-key")
			mu.Lock()
			gotAPIKeyHdr = hdr
			mu.Unlock()
			if failMode.Load() {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{"message": "rejected custom credential: " + hdr},
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"role": "assistant", "content": "OK"}},
				},
			})
		}))

		mgr, err := NewManager(t.TempDir())
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		attach(mgr.client)
		_, err = mgr.UpsertProfile(ProviderConfig{
			ID:       "azure-prof",
			Provider: ProviderOpenAICompat,
			BaseURL:  baseURL + "/v1",
			Model:    "gpt-4.1",
			Enabled:  true,
			ExtraHeaders: map[string]string{
				"api-key": "non-sk-custom-tenant-secret-4242",
			},
		})
		if err != nil {
			t.Fatalf("UpsertProfile: %v", err)
		}

		pub := mgr.GetPublicConfig().Profiles[0]
		// Pass public [REDACTED] ExtraHeaders and nil ctx to verify both header restoration and nil ctx guard.
		var nilCtx context.Context
		res := mgr.TestConnection(nilCtx, ProviderConfig{
			ID:           pub.ID,
			Provider:     pub.Provider,
			BaseURL:      pub.BaseURL,
			Model:        pub.Model,
			ExtraHeaders: pub.ExtraHeaders,
			Enabled:      true,
		})
		if !res.OK {
			t.Fatalf("Manager.TestConnection failed: %+v", res)
		}
		mu.Lock()
		hdrSeen := gotAPIKeyHdr
		mu.Unlock()
		if hdrSeen != "non-sk-custom-tenant-secret-4242" {
			t.Fatalf("Manager.TestConnection did not restore [REDACTED] ExtraHeader, got %q", hdrSeen)
		}

		// When server echoes non-sk custom ExtraHeader secret in 403 error, it must be scrubbed.
		failMode.Store(true)
		errRes := mgr.TestConnection(context.Background(), ProviderConfig{
			ID:           pub.ID,
			Provider:     pub.Provider,
			BaseURL:      pub.BaseURL,
			Model:        pub.Model,
			ExtraHeaders: pub.ExtraHeaders,
			Enabled:      true,
		})
		if errRes.OK {
			t.Fatalf("expected HTTP 403 failure")
		}
		if strings.Contains(errRes.Error, "non-sk-custom-tenant-secret-4242") {
			t.Fatalf("custom sensitive ExtraHeader value leaked in error: %s", errRes.Error)
		}
	})

	t.Run("pem_spanning_line_40_truncated_pem_and_extra_headers_redaction", func(t *testing.T) {
		var lines []string
		for i := 1; i <= 38; i++ {
			lines = append(lines, fmt.Sprintf("head-line-%02d", i))
		}
		// PEM block starts at line 39 and spans past line 40 into omitted middle!
		lines = append(lines, "-----BEGIN RSA PRIVATE KEY-----")
		lines = append(lines, "MIIEowIBAAKCAQEAline40SecretChunkOne")
		lines = append(lines, "MIIEowIBAAKCAQEAline41SecretChunkTwo")
		lines = append(lines, "MIIEowIBAAKCAQEAline42SecretChunkThree")
		lines = append(lines, "-----END RSA PRIVATE KEY-----")
		for i := 1; i <= 180; i++ {
			lines = append(lines, fmt.Sprintf("body-line-%03d", i))
		}
		lines = append(lines, "api-key: azure-log-secret-111")
		lines = append(lines, "x-access-token: access-tok-secret-222")
		lines = append(lines, "x-session-token: session-tok-secret-333")

		cleaned, count := RedactAndCompressLogs(strings.Join(lines, "\n"), true)
		if count < 4 {
			t.Fatalf("expected >=4 redactions, got %d", count)
		}
		for _, leak := range []string{
			"MIIEowIBAAKCAQEAline40SecretChunkOne",
			"MIIEowIBAAKCAQEAline41SecretChunkTwo",
			"azure-log-secret-111",
			"access-tok-secret-222",
			"session-tok-secret-333",
		} {
			if strings.Contains(cleaned, leak) {
				t.Fatalf("secret %q leaked after RedactAndCompressLogs:\n%s", leak, cleaned)
			}
		}

		// Direct RedactSecrets call on an already-truncated PEM block without END marker.
		trunc := "INFO loading key\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\nMIIEvQIBADANBgkqhkiG9w0BAQEFSecondLine\n... [truncated] ...\nINFO still here"
		redTrunc, tc := RedactSecrets(trunc)
		if tc < 1 || strings.Contains(redTrunc, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw") || strings.Contains(redTrunc, "MIIEvQIBADANBgkqhkiG9w0BAQEFSecondLine") {
			t.Fatalf("truncated PEM key was not redacted (count=%d):\n%s", tc, redTrunc)
		}
		if !strings.Contains(redTrunc, "INFO still here") {
			t.Fatalf("truncated PEM redaction swallowed trailing log line:\n%s", redTrunc)
		}
	})

	t.Run("destructive_command_hints_filtered", func(t *testing.T) {
		raw := mustJSON(t, map[string]any{
			"root_cause":     "missing tool",
			"error_category": "missing_dependency",
			"confidence":     0.9,
			"fix_kind":       "command_hint",
			"explanation":    "Install frida-tools",
			"command_hints": []string{
				"pip3 install frida-tools",
				"rm -rf /",
				"mkfs.ext4 /dev/sda1",
				"dd if=/dev/zero of=/dev/sda",
				":(){ :|:& };:",
				"frida --version",
			},
		})
		res, err := ParseDiagnoseJSON(raw)
		if err != nil {
			t.Fatalf("ParseDiagnoseJSON: %v", err)
		}
		if len(res.CommandHints) != 2 || res.CommandHints[0] != "pip3 install frida-tools" || res.CommandHints[1] != "frida --version" {
			t.Fatalf("unexpected filtered CommandHints: %+v", res.CommandHints)
		}
	})

	t.Run("scope_inferred_language_validation_and_nil_ctx_and_empty_openai_content", func(t *testing.T) {
		// 1. Scope-inferred validation catches invalid JS when req.Language == "".
		mgr := newTestManagerWithMockLLM(t, func(_ int, _, _, _ string) string {
			return mustJSON(t, map[string]any{
				"root_cause":     "syntax bug",
				"error_category": "syntax_error",
				"confidence":     0.8,
				"fix_kind":       "code_patch",
				"explanation":    "Broken JS returned",
				"patched_code":   "function bad( { return ;",
			})
		})
		var nilCtx context.Context
		res, err := mgr.DiagnoseAndFix(nilCtx, DiagnoseRequest{
			Scope: ScopeFrida,
			// Intentionally empty Language -> must infer "javascript" and fail validation!
			Code: "console.log(1);",
			Logs: "Error: boom",
		})
		if err != nil {
			t.Fatalf("DiagnoseAndFix with nil ctx: %v", err)
		}
		if res.Validation == nil || res.Validation.Passed || res.Validation.Validator == "basic" {
			t.Fatalf("expected JS validator failure for ScopeFrida with empty Language, got %+v", res.Validation)
		}

		// RunAutoHealLoop with nil ctx should not panic.
		healRes, err := mgr.RunAutoHealLoop(nilCtx, DiagnoseRequest{Scope: ScopeFrida, Code: "console.log(1);"}, 1, func(_ context.Context, _ string) (int, string, error) {
			return 0, "ok", nil
		}, nil)
		if err != nil || !healRes.Healed || healRes.StopReason != StopReasonAlreadyOK {
			t.Fatalf("RunAutoHealLoop nil ctx unexpected result: %+v err=%v", healRes, err)
		}

		// 2. Empty/whitespace openai_compat choices[0].message.content rejected.
		emptyURL, attachEmpty := startLocalHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"role": "assistant", "content": "   \n\t  "}},
				},
			})
		}))
		c := NewClient()
		attachEmpty(c)
		if _, err := c.Complete(nilCtx, ProviderConfig{
			Provider: ProviderOpenAICompat,
			BaseURL:  emptyURL + "/v1",
			Model:    "gpt-4.1",
		}, "sys", "usr"); err == nil || !strings.Contains(err.Error(), "empty message content") {
			t.Fatalf("expected empty message content error for openai_compat, got: %v", err)
		}
	})
}
