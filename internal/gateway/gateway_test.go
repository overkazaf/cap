package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/types"
)

// newLoopbackForwardProxy creates a lightweight loopback HTTP forward proxy
// server for testing ProxyPool health checks, routing, sticky proxies, and failover.
func newLoopbackForwardProxy(t *testing.T, label string, hitCount *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hitCount != nil {
			hitCount.Add(1)
		}
		targetURL := r.RequestURI
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + r.Host + r.RequestURI
		}
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		for k, vals := range r.Header {
			for _, v := range vals {
				outReq.Header.Add(k, v)
			}
		}
		outReq.Header.Set("X-Via-Proxy", label)

		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
}

func TestProxyPoolStrategiesAndFiltering(t *testing.T) {
	pool := NewProxyPool(ProxyPoolConfig{Strategy: StrategyRoundRobin})

	_, err := pool.Add(ProxyNode{
		ID:        "p1",
		Name:      "Proxy One",
		URL:       "127.0.0.1:8001",
		Region:    "us",
		Tags:      []string{"residential", "fast"},
		Enabled:   true,
		Healthy:   true,
		LatencyMs: 80,
	})
	if err != nil {
		t.Fatalf("Add p1: %v", err)
	}
	_, err = pool.Add(ProxyNode{
		ID:        "p2",
		Name:      "Proxy Two",
		URL:       "http://user:pass@127.0.0.1:8002",
		Region:    "us",
		Tags:      []string{"residential"},
		Enabled:   true,
		Healthy:   true,
		LatencyMs: 25,
	})
	if err != nil {
		t.Fatalf("Add p2: %v", err)
	}
	_, err = pool.Add(ProxyNode{
		ID:        "p3",
		Name:      "Proxy Three",
		URL:       "socks5://127.0.0.1:1080",
		Region:    "jp",
		Tags:      []string{"datacenter"},
		Enabled:   true,
		Healthy:   true,
		LatencyMs: 12,
	})
	if err != nil {
		t.Fatalf("Add p3: %v", err)
	}
	_, err = pool.Add(ProxyNode{
		ID:        "p4-down",
		Name:      "Proxy Down",
		URL:       "http://127.0.0.1:8004",
		Region:    "us",
		Tags:      []string{"residential"},
		Enabled:   true,
		Healthy:   false,
		LastError: "connection refused",
	})
	if err != nil {
		t.Fatalf("Add p4-down: %v", err)
	}

	// Round-robin over us/residential (p1, p2; p4-down must be skipped)
	seen := make([]string, 0, 4)
	for range 4 {
		n, err := pool.Select(ProxySelectOptions{Tags: []string{"residential"}, Region: "us"})
		if err != nil {
			t.Fatalf("Select round_robin: %v", err)
		}
		if n.ID == "p4-down" {
			t.Fatalf("selected unhealthy proxy p4-down")
		}
		seen = append(seen, n.ID)
	}
	if seen[0] != "p1" || seen[1] != "p2" || seen[2] != "p1" || seen[3] != "p2" {
		t.Fatalf("round_robin sequence = %v, want [p1 p2 p1 p2]", seen)
	}

	// Least latency
	n, err := pool.Select(ProxySelectOptions{Strategy: StrategyLeastLatency})
	if err != nil {
		t.Fatalf("Select least_latency: %v", err)
	}
	if n.ID != "p3" {
		t.Fatalf("least_latency picked %s (lat=%d), want p3", n.ID, n.LatencyMs)
	}

	// Random strategy
	for range 10 {
		n, err := pool.Select(ProxySelectOptions{Strategy: StrategyRandom, Region: "us"})
		if err != nil {
			t.Fatalf("Select random: %v", err)
		}
		if n.ID != "p1" && n.ID != "p2" {
			t.Fatalf("random picked unexpected proxy %s", n.ID)
		}
	}

	// Sticky device strategy
	n, err = pool.Select(ProxySelectOptions{Strategy: StrategyStickyDevice, StickyProxyID: "p2"})
	if err != nil {
		t.Fatalf("Select sticky_device: %v", err)
	}
	if n.ID != "p2" {
		t.Fatalf("sticky_device picked %s, want p2", n.ID)
	}

	// Sticky proxy excluded during failover -> falls back to other healthy node
	n, err = pool.Select(ProxySelectOptions{
		Strategy:      StrategyStickyDevice,
		StickyProxyID: "p2",
		Region:        "us",
		ExcludeIDs:    map[string]bool{"p2": true},
	})
	if err != nil {
		t.Fatalf("Select sticky failover: %v", err)
	}
	if n.ID != "p1" {
		t.Fatalf("sticky failover picked %s, want p1", n.ID)
	}

	// Transport builder supports HTTP, HTTPS, SOCKS5 with credentials
	for _, tc := range []ProxyNode{
		{URL: "http://127.0.0.1:8080", Username: "u", Password: "p"},
		{URL: "https://127.0.0.1:8443"},
		{URL: "socks5://alice:secret@127.0.0.1:1080"},
		{URL: "socks5h://127.0.0.1:1080", Username: "bob", Password: "pw"},
	} {
		tr, err := BuildProxyTransport(&tc)
		if err != nil {
			t.Fatalf("BuildProxyTransport(%s): %v", tc.URL, err)
		}
		tr.CloseIdleConnections()
	}
	if _, err := BuildProxyTransport(&ProxyNode{URL: "ftp://127.0.0.1:21"}); err == nil {
		t.Fatalf("expected error for unsupported scheme ftp")
	}
}

func TestProxyPoolDynamicProviderAndHealthCheck(t *testing.T) {
	// Start an upstream target and a working loopback HTTP proxy
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	var proxyHits atomic.Int64
	goodProxy := newLoopbackForwardProxy(t, "good", &proxyHits)
	defer goodProxy.Close()

	// Dead port for unhealthy check
	deadProxy := httptest.NewServer(http.NotFoundHandler())
	deadURL := deadProxy.URL
	deadProxy.Close()

	// Lines format provider
	linesProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "# comment line\n%s\n%s\n10.0.0.5:8888:user1:pass1\n", goodProxy.URL, deadURL)
	}))
	defer linesProvider.Close()

	pool := NewProxyPool(ProxyPoolConfig{
		ProviderURL:    linesProvider.URL,
		ProviderFormat: ProviderFormatLines,
		HealthCheckURL: target.URL,
	})
	added, total, err := pool.FetchFromProvider(context.Background())
	if err != nil {
		t.Fatalf("FetchFromProvider (lines): %v", err)
	}
	if added != 3 || total != 3 {
		t.Fatalf("lines provider got added=%d total=%d, want 3/3", added, total)
	}
	// Fetching again should deduplicate
	added2, total2, err := pool.FetchFromProvider(context.Background())
	if err != nil {
		t.Fatalf("FetchFromProvider dedup: %v", err)
	}
	if added2 != 0 || total2 != 3 {
		t.Fatalf("dedup got added=%d total=%d, want 0/3", added2, total2)
	}

	// JSON format provider with nested path
	jsonProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"code": 0,
			"data": {
				"list": [
					{"ip": "10.0.0.10", "port": 3128, "protocol": "http", "region": "sg", "tags": ["mobile"]},
					"socks5://10.0.0.11:1080"
				]
			}
		}`))
	}))
	defer jsonProvider.Close()

	addedJSON, totalJSON, err := pool.FetchFromProviderURL(context.Background(), jsonProvider.URL, ProviderFormatJSON, "data.list")
	if err != nil {
		t.Fatalf("FetchFromProviderURL (json): %v", err)
	}
	if addedJSON != 2 || totalJSON != 5 {
		t.Fatalf("json provider got added=%d total=%d, want 2/5", addedJSON, totalJSON)
	}

	// Verify health check marks goodProxy healthy and deadProxy unhealthy
	var goodID, deadID string
	for _, n := range pool.List() {
		if n.URL == goodProxy.URL {
			goodID = n.ID
		}
		if n.URL == deadURL {
			deadID = n.ID
		}
	}
	if goodID == "" || deadID == "" {
		t.Fatalf("missing good/dead proxy IDs in pool: %+v", pool.List())
	}

	checkedGood, err := pool.CheckNode(context.Background(), goodID, target.URL)
	if err != nil {
		t.Fatalf("CheckNode good failed: %v", err)
	}
	if !checkedGood.Healthy || checkedGood.LatencyMs <= 0 || proxyHits.Load() < 1 {
		t.Fatalf("expected healthy good proxy with positive latency, got %+v (hits=%d)", checkedGood, proxyHits.Load())
	}

	checkedDead, err := pool.CheckNode(context.Background(), deadID, target.URL)
	if err == nil {
		t.Fatalf("expected error checking dead proxy")
	}
	if checkedDead.Healthy || checkedDead.FailCount < 1 || checkedDead.LastError == "" {
		t.Fatalf("expected unhealthy dead proxy state, got %+v", checkedDead)
	}
}

func TestDevicePoolPresetsTemplatesStickyAndADBSync(t *testing.T) {
	presets := BuiltinDevicePresets()
	if len(presets) < 4 {
		t.Fatalf("expected >= 4 built-in presets, got %d", len(presets))
	}

	pool := NewDevicePool()
	dev1, err := pool.CreateFromPreset("pixel-8-pro", "Pixel Lab 1", []string{"vip"})
	if err != nil {
		t.Fatalf("CreateFromPreset pixel-8-pro: %v", err)
	}
	dev1.StickyProxyID = "proxy-us-1"
	dev1.ProxyRegion = "us"
	dev1.Tokens = map[string]string{"access": "tok-abc"}
	dev1.Cookies = map[string]string{"sid": "cookie-123"}
	dev1.AuthHeaders = map[string]string{"X-Auth": "bearer-xyz"}
	dev1, err = pool.Upsert(*dev1)
	if err != nil {
		t.Fatalf("Upsert dev1: %v", err)
	}

	dev2, err := pool.CreateFromPreset("xiaomi-14", "Xiaomi Lab 2", []string{"vip"})
	if err != nil {
		t.Fatalf("CreateFromPreset xiaomi-14: %v", err)
	}
	if dev1.Fingerprint.OAID == "" || dev1.Fingerprint.AndroidID == "" || dev1.Fingerprint.OAID == dev2.Fingerprint.OAID {
		t.Fatalf("expected unique non-empty OAID/AndroidID per virtual device")
	}

	// Sticky proxy lookup
	pid, region := pool.StickyProxyFor(dev1)
	if pid != "proxy-us-1" || region != "us" {
		t.Fatalf("StickyProxyFor = (%q, %q), want (proxy-us-1, us)", pid, region)
	}

	// Tag filtering & round-robin acquisition
	a1, err := pool.Acquire([]string{"vip"}, "")
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}
	a2, err := pool.Acquire([]string{"vip"}, "")
	if err != nil {
		t.Fatalf("Acquire 2: %v", err)
	}
	if a1.ID == a2.ID {
		t.Fatalf("expected round-robin across two vip devices, got %s twice", a1.ID)
	}

	// Template rendering covering input.*, device.*, env.*, timestamp, nonce
	rendered := RenderTemplate(
		"https://api.example.com/u/{{input.uid}}?oaid={{device.oaid}}&model={{device.model}}&tok={{device.token.access}}&ck={{device.cookie.sid}}&hdr={{device.header.x-auth}}&env={{env.CAP_TEST_ENV}}&ts={{timestamp}}&n={{nonce}}",
		TemplateContext{
			Input:     map[string]string{"uid": "42"},
			Device:    dev1,
			Env:       map[string]string{"CAP_TEST_ENV": "staging"},
			Timestamp: 1700000000,
			Nonce:     "deadbeef",
		},
	)
	for _, want := range []string{
		"/u/42?",
		"oaid=" + dev1.Fingerprint.OAID,
		"model=Pixel 8 Pro",
		"tok=tok-abc",
		"ck=cookie-123",
		"hdr=bearer-xyz",
		"env=staging",
		"ts=1700000000",
		"n=deadbeef",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered template %q missing %q", rendered, want)
		}
	}

	keys := ExtractTemplateInputKeys("https://a.com/{{input.id}}?q={{ input.keyword }}", `{"uid":"{{input.id}}","page":"{{input.page}}"}`)
	if strings.Join(keys, ",") != "id,keyword,page" {
		t.Fatalf("ExtractTemplateInputKeys = %v, want [id keyword page]", keys)
	}

	// Mocked ADB sync
	origList := adbListDevicesFunc
	origShell := adbShellFunc
	defer func() {
		adbListDevicesFunc = origList
		adbShellFunc = origShell
	}()
	adbListDevicesFunc = func() ([]android.Device, error) {
		return []android.Device{
			{Serial: "emulator-5554", State: "device"},
			{Serial: "offline-9999", State: "offline"},
		}, nil
	}
	adbShellFunc = func(serial, cmd string) (string, error) {
		return strings.Join([]string{
			"MODEL=Pixel 8",
			"BRAND=google",
			"RELEASE=14",
			"SDK=34",
			"LOCALE=en-US",
			"TZ=America/Los_Angeles",
			"ANDROID_ID=a1b2c3d4e5f60708",
			"SCREEN=Physical size: 1080x2400",
		}, "\n"), nil
	}

	synced, err := pool.SyncADBDevices(context.Background())
	if err != nil {
		t.Fatalf("SyncADBDevices: %v", err)
	}
	if len(synced) != 1 || synced[0].Kind != DeviceKindPhysical || synced[0].ADBSerial != "emulator-5554" || synced[0].Fingerprint.AndroidID != "a1b2c3d4e5f60708" {
		t.Fatalf("unexpected synced ADB device: %+v", synced)
	}
}

func TestSignersBuiltinHMACHTTPAndScript(t *testing.T) {
	// 1. Built-in HMAC-SHA256 & MD5
	hmacSigner := &SignerProvider{
		ID:            "s-hmac",
		Name:          "HMAC Signer",
		Kind:          SignerKindBuiltinHMAC,
		Enabled:       true,
		HMACAlgorithm: "hmac-sha256",
		HMACSecret:    "topsecret",
		InjectTarget:  InjectTargetQuery,
		InjectField:   "sign",
	}
	out, err := ExecuteSigner(context.Background(), hmacSigner, SignerInput{
		Method: "POST",
		Query:  map[string]string{"b": "2", "a": "1"},
		Body:   `{"c":"3"}`,
	})
	if err != nil {
		t.Fatalf("ExecuteSigner builtin_hmac: %v", err)
	}
	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write([]byte("a=1&b=2&c=3"))
	wantHMAC := hex.EncodeToString(mac.Sum(nil))
	if out.Sign != wantHMAC {
		t.Fatalf("hmac sign = %s, want %s", out.Sign, wantHMAC)
	}

	md5Signer := &SignerProvider{
		ID:            "s-md5",
		Name:          "MD5 Signer",
		Kind:          SignerKindBuiltinHMAC,
		Enabled:       true,
		HMACAlgorithm: "md5",
		HMACSecret:    "salt",
		InjectTarget:  InjectTargetHeader,
		InjectField:   "X-MD5-Sign",
	}
	md5Out, err := ExecuteSigner(context.Background(), md5Signer, SignerInput{
		Query: map[string]string{"k": "v"},
	})
	if err != nil {
		t.Fatalf("ExecuteSigner md5: %v", err)
	}
	wantMD5Sum := md5.Sum([]byte("k=vsalt"))
	if md5Out.Sign != hex.EncodeToString(wantMD5Sum[:]) {
		t.Fatalf("md5 sign = %s, want %x", md5Out.Sign, wantMD5Sum)
	}

	// Verify ApplySignature for header + body_json
	baseURL, _ := url.Parse("https://api.example.com/v1/order?k=v")
	uAfter, hAfter, bodyAfter, err := ApplySignature(md5Signer, md5Out, baseURL, map[string]string{}, `{"item":1}`)
	if err != nil {
		t.Fatalf("ApplySignature header: %v", err)
	}
	if hAfter["X-MD5-Sign"] != md5Out.Sign || uAfter.Query().Get("k") != "v" || bodyAfter != `{"item":1}` {
		t.Fatalf("unexpected header injection result: url=%s hdrs=%v body=%s", uAfter, hAfter, bodyAfter)
	}

	// 2. HTTP / Unidbg HTTP signer via loopback httptest
	unidbgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Signer-Token") != "unidbg-tok" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		var in SignerInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 0,
			"data": map[string]any{
				"x_gorgon": "8404" + in.Query["uid"],
				"x_khronos": fmt.Sprintf("%d", in.Timestamp),
			},
		})
	}))
	defer unidbgSrv.Close()

	httpSigner := &SignerProvider{
		ID:          "s-unidbg",
		Name:        "Unidbg Signer",
		Kind:        SignerKindUnidbgHTTP,
		Enabled:     true,
		EndpointURL: unidbgSrv.URL,
		HTTPMethod:  "POST",
		Headers:     map[string]string{"X-Signer-Token": "unidbg-tok"},
		OutputMapping: map[string]string{
			"x_gorgon":  "header:X-Gorgon",
			"x_khronos": "query:khronos",
		},
	}
	unidbgOut, err := ExecuteSigner(context.Background(), httpSigner, SignerInput{
		Method:    "GET",
		Query:     map[string]string{"uid": "9001"},
		Timestamp: 1712345678,
	})
	if err != nil {
		t.Fatalf("ExecuteSigner unidbg_http: %v", err)
	}
	u2, h2, _, err := ApplySignature(httpSigner, unidbgOut, baseURL, map[string]string{}, "")
	if err != nil {
		t.Fatalf("ApplySignature unidbg_http: %v", err)
	}
	if h2["X-Gorgon"] != "84049001" || u2.Query().Get("khronos") != "1712345678" {
		t.Fatalf("unidbg mapping failed: hdrs=%v query=%v", h2, u2.Query())
	}

	// 3. Script signer via `sh` (also test timeout cancellation on unix)
	if runtime.GOOS != "windows" {
		shSigner := &SignerProvider{
			ID:           "s-sh",
			Name:         "Shell Signer",
			Kind:         SignerKindScript,
			Enabled:      true,
			Runtime:      "sh",
			ScriptCode:   `payload=$(cat); printf '{"sign":"sh-sig-ok","headers":{"X-Shell":"yes"},"params":{"from_sh":"1"}}\n'`,
			InjectTarget: InjectTargetBodyJSON,
			InjectField:  "signature",
		}
		shOut, err := ExecuteSigner(context.Background(), shSigner, SignerInput{Method: "POST", Body: `{"a":1}`})
		if err != nil {
			t.Fatalf("ExecuteSigner sh: %v", err)
		}
		if shOut.Sign != "sh-sig-ok" || shOut.Headers["X-Shell"] != "yes" || shOut.Params["from_sh"] != "1" {
			t.Fatalf("unexpected sh signer output: %+v", shOut)
		}
		u3, h3, body3, err := ApplySignature(shSigner, shOut, baseURL, map[string]string{}, `{"a":1}`)
		if err != nil {
			t.Fatalf("ApplySignature sh: %v", err)
		}
		if u3.Query().Get("from_sh") != "1" || h3["X-Shell"] != "yes" || !strings.Contains(body3, `"signature":"sh-sig-ok"`) {
			t.Fatalf("unexpected applied sh signature: url=%s hdrs=%v body=%s", u3, h3, body3)
		}

		// Verify timeout kills slow subprocess cleanly
		slowSigner := &SignerProvider{
			ID:         "s-slow",
			Name:       "Slow Signer",
			Kind:       SignerKindScript,
			Enabled:    true,
			Runtime:    "sh",
			TimeoutSec: 1,
			ScriptCode: `sleep 10`,
		}
		start := time.Now()
		_, err = ExecuteSigner(context.Background(), slowSigner, SignerInput{})
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("expected timeout error from slow script, got %v", err)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("slow script took too long to terminate: %s", time.Since(start))
		}
	}
}

func TestGatewayEndToEndHTTPAuthRateLimitOpenAPIFailoverAndRaw(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	// Upstream echo server inspecting rendered URL, device headers, proxy header, and signature
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Echo", "true")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method":    r.Method,
			"path":      r.URL.Path,
			"query":     r.URL.Query(),
			"ua":        r.Header.Get("User-Agent"),
			"oaid_hdr":  r.Header.Get("X-Device-OAID"),
			"via_proxy": r.Header.Get("X-Via-Proxy"),
			"cookie":    r.Header.Get("Cookie"),
			"body":      string(body),
		})
	}))
	defer upstream.Close()

	// Dead proxy (pinned as sticky to test failover!) + healthy proxy
	deadProxySrv := httptest.NewServer(http.NotFoundHandler())
	deadProxyURL := deadProxySrv.URL
	deadProxySrv.Close()

	var proxyHits atomic.Int64
	goodProxySrv := newLoopbackForwardProxy(t, "proxy-good", &proxyHits)
	defer goodProxySrv.Close()

	if err := mgr.UpdateProxyConfig(ProxyPoolConfig{
		Strategy:        StrategyStickyDevice,
		FailoverRetries: 2,
	}); err != nil {
		t.Fatalf("UpdateProxyConfig: %v", err)
	}
	deadNode, err := mgr.SaveProxy(ProxyNode{
		ID:      "p-dead",
		Name:    "Dead Proxy",
		URL:     deadProxyURL,
		Tags:    []string{"pool-a"},
		Enabled: true,
		Healthy: true, // Initially marked healthy so attempt 0 hits it and fails over!
	})
	if err != nil {
		t.Fatalf("SaveProxy dead: %v", err)
	}
	goodNode, err := mgr.SaveProxy(ProxyNode{
		ID:      "p-good",
		Name:    "Good Proxy",
		URL:     goodProxySrv.URL,
		Tags:    []string{"pool-a"},
		Enabled: true,
		Healthy: true,
	})
	if err != nil {
		t.Fatalf("SaveProxy good: %v", err)
	}

	// Create virtual device bound to deadNode initially (to verify failover!)
	dev, err := mgr.CreateDeviceFromPreset("pixel-8-pro", "Pixel Primary", []string{"prod"})
	if err != nil {
		t.Fatalf("CreateDeviceFromPreset: %v", err)
	}
	dev.StickyProxyID = deadNode.ID
	dev.Cookies = map[string]string{"session": "s-999"}
	dev, err = mgr.SaveDevice(*dev)
	if err != nil {
		t.Fatalf("SaveDevice: %v", err)
	}

	// Add HMAC signer
	signer, err := mgr.SaveSigner(SignerProvider{
		ID:            "hmac-main",
		Name:          "Main HMAC",
		Kind:          SignerKindBuiltinHMAC,
		Enabled:       true,
		HMACAlgorithm: "hmac-sha256",
		HMACSecret:    "gw-secret",
		InjectTarget:  InjectTargetQuery,
		InjectField:   "sig",
	})
	if err != nil {
		t.Fatalf("SaveSigner: %v", err)
	}

	// Add ServiceRoute
	route, err := mgr.SaveRoute(ServiceRoute{
		Slug:           "user-detail",
		Name:           "Get User Detail",
		Description:    "Fetch user profile with device fingerprint, proxy failover, and HMAC signing",
		Enabled:        true,
		UpstreamMethod: "GET",
		UpstreamURL:    upstream.URL + "/v1/users/{{input.uid}}",
		StaticHeaders:  map[string]string{"X-Device-OAID": "{{device.oaid}}"},
		StaticQuery:    map[string]string{"brand": "{{device.brand}}"},
		SignerID:       signer.ID,
		DeviceTags:     []string{"prod"},
		ProxyTags:      []string{"pool-a"},
		RequireProxy:   true,
		RequireDevice:  true,
		RateLimitRPS:   2,
		TimeoutSec:     10,
	})
	if err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}

	// Enable API Key auth
	if err := mgr.UpdateConfig(GatewayConfig{
		ListenAddr:  "127.0.0.1:0",
		RequireAuth: true,
		APIKeys:     []string{"secret-api-key-123"},
		CORSOrigins: []string{"*"},
		MaxLogs:     50,
	}); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	// Track live invocation & status callbacks
	var (
		cbMu        sync.Mutex
		invocations []InvocationRecord
		statuses    []GatewayStatus
	)
	mgr.SetCallbacks(
		func(rec InvocationRecord) {
			cbMu.Lock()
			invocations = append(invocations, rec)
			cbMu.Unlock()
		},
		func(st GatewayStatus) {
			cbMu.Lock()
			statuses = append(statuses, st)
			cbMu.Unlock()
		},
	)

	if err := mgr.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !mgr.IsRunning() {
		t.Fatalf("expected IsRunning() == true")
	}
	baseURL := "http://" + mgr.ListenAddr()

	// 1. GET /health
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	var health map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || health["ok"] != true {
		t.Fatalf("/health = %d %+v", resp.StatusCode, health)
	}

	// 2. GET /openapi.json (OpenAPI 3.0.3)
	resp, err = http.Get(baseURL + "/openapi.json")
	if err != nil {
		t.Fatalf("GET /openapi.json: %v", err)
	}
	var spec map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
		t.Fatalf("decode /openapi.json: %v", err)
	}
	resp.Body.Close()
	if spec["openapi"] != "3.0.3" {
		t.Fatalf("openapi version = %v, want 3.0.3", spec["openapi"])
	}
	paths, _ := spec["paths"].(map[string]any)
	if _, ok := paths["/gw/"+route.Slug]; !ok {
		t.Fatalf("openapi paths missing /gw/%s: %+v", route.Slug, paths)
	}

	// 3. Unauthorized call without API key -> 401
	resp, err = http.Get(baseURL + "/gw/" + route.Slug + "?uid=77")
	if err != nil {
		t.Fatalf("GET unauthorized: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without API key, got %d", resp.StatusCode)
	}

	// 4. Authorized call via X-API-Key -> succeeds via failover from p-dead to p-good!
	req1, _ := http.NewRequest(http.MethodGet, baseURL+"/gw/"+route.Slug+"?uid=77", nil)
	req1.Header.Set("X-API-Key", "secret-api-key-123")
	resp, err = http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("GET authorized 1: %v", err)
	}
	var env TestInvokeResult
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !env.OK || env.Status != 200 {
		t.Fatalf("expected 200 ok envelope, got http=%d env=%+v", resp.StatusCode, env)
	}
	if env.ProxyID != goodNode.ID || env.Retries != 1 {
		t.Fatalf("expected failover to %s with 1 retry, got proxy=%s retries=%d", goodNode.ID, env.ProxyID, env.Retries)
	}
	if env.DeviceID != dev.ID {
		t.Fatalf("expected device %s, got %s", dev.ID, env.DeviceID)
	}
	dataMap, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected parsed JSON data map, got %T", env.Data)
	}
	if dataMap["path"] != "/v1/users/77" {
		t.Fatalf("upstream path = %v, want /v1/users/77", dataMap["path"])
	}
	if dataMap["oaid_hdr"] != dev.Fingerprint.OAID {
		t.Fatalf("upstream oaid_hdr = %v, want %s", dataMap["oaid_hdr"], dev.Fingerprint.OAID)
	}
	if dataMap["ua"] != dev.Fingerprint.UserAgent {
		t.Fatalf("upstream UA = %v, want device UA %s", dataMap["ua"], dev.Fingerprint.UserAgent)
	}
	if dataMap["via_proxy"] != "proxy-good" {
		t.Fatalf("upstream via_proxy = %v, want proxy-good", dataMap["via_proxy"])
	}
	if dataMap["cookie"] != "session=s-999" {
		t.Fatalf("upstream cookie = %v, want session=s-999", dataMap["cookie"])
	}
	qMap, _ := dataMap["query"].(map[string]any)
	if sigVals, ok := qMap["sig"].([]any); !ok || len(sigVals) == 0 || sigVals[0] == "" {
		t.Fatalf("expected signed 'sig' query param on upstream, got %+v", qMap)
	}

	// 5. Second immediate call using Authorization: Bearer & ?raw=1 passthrough (consumes 2nd burst token)
	req2, _ := http.NewRequest(http.MethodGet, baseURL+"/gw/"+route.Slug+"?uid=88&raw=1", nil)
	req2.Header.Set("Authorization", "Bearer secret-api-key-123")
	resp, err = http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET raw=1: %v", err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Upstream-Echo") != "true" {
		t.Fatalf("raw passthrough failed: status=%d hdr=%q body=%s", resp.StatusCode, resp.Header.Get("X-Upstream-Echo"), string(rawBody))
	}
	if !bytes.Contains(rawBody, []byte(`/v1/users/88`)) {
		t.Fatalf("raw body missing /v1/users/88: %s", string(rawBody))
	}

	// 6. Third immediate call exceeds RateLimitRPS=2 -> 429 Too Many Requests
	req3, _ := http.NewRequest(http.MethodGet, baseURL+"/gw/"+route.Slug+"?uid=99", nil)
	req3.Header.Set("X-API-Key", "secret-api-key-123")
	resp, err = http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("GET rate limited: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 rate limit exceeded, got %d", resp.StatusCode)
	}

	// 7. Direct InvokeRoute (in-process GUI/CLI test helper)
	directRes, err := mgr.InvokeRoute(context.Background(), route.Slug, TestInvokeRequest{
		Input: map[string]string{"uid": "555"},
	})
	if err != nil || !directRes.OK {
		t.Fatalf("InvokeRoute failed: res=%+v err=%v", directRes, err)
	}

	// 8. Telemetry, Logs, and Callbacks
	stats := mgr.Stats()
	if stats.TotalRequests != 3 || stats.SuccessRequests != 3 || stats.AuthFailures != 1 || stats.RateLimited != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	logs := mgr.ListLogs(10)
	if len(logs) != 3 {
		t.Fatalf("expected 3 invocation logs, got %d", len(logs))
	}
	cbMu.Lock()
	gotInvokes := len(invocations)
	gotStatuses := len(statuses)
	cbMu.Unlock()
	if gotInvokes != 3 || gotStatuses < 1 {
		t.Fatalf("expected 3 invoke callbacks and >=1 status callback, got %d / %d", gotInvokes, gotStatuses)
	}

	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if mgr.IsRunning() {
		t.Fatalf("expected IsRunning() == false after Stop")
	}
}

func TestPublishFlowAsRouteAndPersistenceRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	flow := &types.Flow{
		ID:     "flow-42",
		Method: "POST",
		URL:    "https://api.shop.example/v2/orders?region=cn&lang=zh",
		Host:   "api.shop.example",
		Path:   "/v2/orders",
		ReqHeaders: map[string]string{
			"Host":            "api.shop.example",
			"Content-Length":  "18",
			"Accept-Encoding": "gzip",
			"X-App-Version":   "9.4.1",
			"Content-Type":    "application/json",
		},
		ReqBody: []byte(`{"item_id":"1001"}`),
	}

	route, err := mgr.PublishFlowAsRoute(flow, "create-order", "Create Order API")
	if err != nil {
		t.Fatalf("PublishFlowAsRoute: %v", err)
	}
	if route.Slug != "create-order" || route.SourceFlowID != "flow-42" {
		t.Fatalf("unexpected route metadata: %+v", route)
	}
	if route.UpstreamURL != "https://api.shop.example/v2/orders" {
		t.Fatalf("expected query stripped from UpstreamURL, got %q", route.UpstreamURL)
	}
	if route.StaticQuery["region"] != "cn" || route.StaticQuery["lang"] != "zh" {
		t.Fatalf("expected StaticQuery extracted, got %+v", route.StaticQuery)
	}
	if _, hasHost := route.StaticHeaders["Host"]; hasHost {
		t.Fatalf("expected hop-by-hop/auto Host header stripped")
	}
	if route.StaticHeaders["X-App-Version"] != "9.4.1" || route.BodyTemplate != `{"item_id":"1001"}` {
		t.Fatalf("expected custom header and body preserved: %+v", route)
	}

	// Save config, proxy, device, signer and verify full disk reload roundtrip
	if err := mgr.UpdateConfig(GatewayConfig{
		ListenAddr:  "127.0.0.1:9191",
		RequireAuth: true,
		APIKeys:     []string{"k1"},
		MaxLogs:     100,
	}); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}
	if _, err := mgr.SaveProxy(ProxyNode{ID: "px1", Name: "PX1", URL: "socks5://127.0.0.1:1080", Enabled: true, Healthy: true}); err != nil {
		t.Fatalf("SaveProxy: %v", err)
	}
	if _, err := mgr.CreateDeviceFromPreset("samsung-s24", "S24 Persist", []string{"persist"}); err != nil {
		t.Fatalf("CreateDeviceFromPreset: %v", err)
	}
	if _, err := mgr.SaveSigner(SignerProvider{ID: "sg1", Name: "SG1", Kind: SignerKindBuiltinHMAC, Enabled: true, HMACAlgorithm: "sha256", HMACSecret: "s"}); err != nil {
		t.Fatalf("SaveSigner: %v", err)
	}
	_ = mgr.Shutdown()

	// Re-open Manager from the same directory
	mgr2, err := NewManager(tmpDir)
	if err != nil {
		t.Fatalf("NewManager reload: %v", err)
	}
	defer func() { _ = mgr2.Shutdown() }()

	if cfg := mgr2.GetConfig(); cfg.ListenAddr != "127.0.0.1:9191" || !cfg.RequireAuth || len(cfg.APIKeys) != 1 || cfg.APIKeys[0] != "k1" {
		t.Fatalf("reloaded config mismatch: %+v", cfg)
	}
	if proxies := mgr2.ListProxies(); len(proxies) != 1 || proxies[0].ID != "px1" {
		t.Fatalf("reloaded proxies mismatch: %+v", proxies)
	}
	if devs := mgr2.ListDevices(); len(devs) != 1 || devs[0].Name != "S24 Persist" {
		t.Fatalf("reloaded devices mismatch: %+v", devs)
	}
	if signers := mgr2.ListSigners(); len(signers) != 1 || signers[0].ID != "sg1" {
		t.Fatalf("reloaded signers mismatch: %+v", signers)
	}
	reloadedRoute, ok := mgr2.GetRouteBySlug("create-order")
	if !ok || reloadedRoute.SourceFlowID != "flow-42" || reloadedRoute.StaticQuery["region"] != "cn" {
		t.Fatalf("reloaded route mismatch: ok=%v route=%+v", ok, reloadedRoute)
	}
}

func TestReadOnlyFilesystemGracefulInit(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("read-only chmod test requires non-root unix")
	}
	roDir := filepath.Join(t.TempDir(), "ro")
	if err := os.MkdirAll(roDir, 0o555); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}
	defer func() { _ = os.Chmod(roDir, 0o755) }()

	mgr, err := NewManager(roDir)
	if err != nil {
		t.Fatalf("NewManager on read-only dir should degrade gracefully, got error: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	// In-memory operations still work even if disk write returns error
	if _, err := mgr.SaveProxy(ProxyNode{Name: "mem-proxy", URL: "http://127.0.0.1:8080", Enabled: true}); err == nil {
		t.Fatalf("expected persistence error on read-only dir")
	}
	if len(mgr.ListProxies()) != 1 {
		t.Fatalf("expected in-memory proxy to still exist after failed persist")
	}
	if errors.Is(err, os.ErrPermission) {
		// fine
	}
}

func TestGatewayCORSPOSTBodyMetricsCheckAllAndFridaRPC(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	// Upstream echoes POST JSON body
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	// Concurrent CheckAllProxies across 1 good + 1 dead proxy
	goodProxy := newLoopbackForwardProxy(t, "chk", nil)
	defer goodProxy.Close()
	deadSrv := httptest.NewServer(http.NotFoundHandler())
	deadURL := deadSrv.URL
	deadSrv.Close()

	_, _ = mgr.SaveProxy(ProxyNode{ID: "chk-good", Name: "Good", URL: goodProxy.URL, Enabled: true})
	_, _ = mgr.SaveProxy(ProxyNode{ID: "chk-dead", Name: "Dead", URL: deadURL, Enabled: true})
	checked := mgr.CheckAllProxies(context.Background(), upstream.URL)
	if len(checked) != 2 {
		t.Fatalf("CheckAllProxies len = %d, want 2", len(checked))
	}
	goodAfter, _ := mgr.GetProxy("chk-good")
	deadAfter, _ := mgr.GetProxy("chk-dead")
	if !goodAfter.Healthy || deadAfter.Healthy {
		t.Fatalf("unexpected health after CheckAll: good=%v dead=%v", goodAfter.Healthy, deadAfter.Healthy)
	}
	// Remove proxies so POST test runs direct cleanly
	_ = mgr.DeleteProxy("chk-good")
	_ = mgr.DeleteProxy("chk-dead")

	// Validate frida_rpc provider validation and generated Python driver script
	fridaProvider := &SignerProvider{
		Name:         "Frida Sign",
		Kind:         SignerKindFridaRPC,
		Enabled:      true,
		FridaSerial:  "emulator-5554",
		FridaPackage: "com.demo.app",
		FridaExport:  "signRequest",
		ScriptCode:   `rpc.exports = { signRequest: function(p) { return { sign: "ok" }; } };`,
	}
	if err := ValidateSigner(fridaProvider); err != nil {
		t.Fatalf("ValidateSigner frida_rpc: %v", err)
	}
	pyDriver := buildFridaRPCDriverScript(fridaProvider)
	if !strings.Contains(pyDriver, "script.exports_sync") || !strings.Contains(pyDriver, `"signRequest"`) || !strings.Contains(pyDriver, `"com.demo.app"`) {
		t.Fatalf("unexpected frida_rpc driver script: %s", pyDriver)
	}
	if err := ValidateSigner(&SignerProvider{Name: "Bad Frida", Kind: SignerKindFridaRPC}); err == nil {
		t.Fatalf("expected validation error for incomplete frida_rpc signer")
	}

	// Verify sha1 & sha256 builtin signers
	for _, algo := range []string{"sha1", "sha256"} {
		out, err := ExecuteSigner(context.Background(), &SignerProvider{
			Name:          algo,
			Kind:          SignerKindBuiltinHMAC,
			Enabled:       true,
			HMACAlgorithm: algo,
			HMACSecret:    "k",
		}, SignerInput{Query: map[string]string{"x": "1"}})
		if err != nil || out.Sign == "" {
			t.Fatalf("builtin %s failed: out=%+v err=%v", algo, out, err)
		}
	}

	// Configure restricted CORS + POST route + disabled route
	_ = mgr.UpdateConfig(GatewayConfig{
		ListenAddr:  "127.0.0.1:0",
		RequireAuth: false,
		CORSOrigins: []string{"https://app.local"},
	})
	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:           "search",
		Name:           "Search POST",
		Enabled:        true,
		UpstreamMethod: "POST",
		UpstreamURL:    upstream.URL + "/search",
		BodyTemplate:   `{"q":"{{input.keyword}}","limit":"{{input.limit}}"}`,
	})
	if err != nil {
		t.Fatalf("SaveRoute search: %v", err)
	}
	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:           "disabled-api",
		Name:           "Disabled",
		Enabled:        false,
		UpstreamMethod: "GET",
		UpstreamURL:    upstream.URL + "/off",
	})
	if err != nil {
		t.Fatalf("SaveRoute disabled-api: %v", err)
	}

	gwSrv := httptest.NewServer(mgr.Handler())
	defer gwSrv.Close()

	// CORS preflight
	optReq, _ := http.NewRequest(http.MethodOptions, gwSrv.URL+"/gw/search", nil)
	optReq.Header.Set("Origin", "https://app.local")
	optResp, err := gwSrv.Client().Do(optReq)
	if err != nil {
		t.Fatalf("OPTIONS preflight: %v", err)
	}
	optResp.Body.Close()
	if optResp.StatusCode != http.StatusNoContent || optResp.Header.Get("Access-Control-Allow-Origin") != "https://app.local" {
		t.Fatalf("unexpected CORS preflight response: %d origin=%q", optResp.StatusCode, optResp.Header.Get("Access-Control-Allow-Origin"))
	}

	// POST /gw/search with JSON input feeding BodyTemplate
	postResp, err := gwSrv.Client().Post(gwSrv.URL+"/gw/search", "application/json", strings.NewReader(`{"keyword":"shoes","limit":"20"}`))
	if err != nil {
		t.Fatalf("POST /gw/search: %v", err)
	}
	var env TestInvokeResult
	_ = json.NewDecoder(postResp.Body).Decode(&env)
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusOK || !env.OK {
		t.Fatalf("POST /gw/search failed: status=%d env=%+v", postResp.StatusCode, env)
	}
	dm, _ := env.Data.(map[string]any)
	if dm["q"] != "shoes" || dm["limit"] != "20" {
		t.Fatalf("unexpected rendered POST body echo: %+v", dm)
	}

	// Disabled route -> 503; unknown route -> 404
	disResp, err := gwSrv.Client().Get(gwSrv.URL + "/gw/disabled-api")
	if err != nil {
		t.Fatalf("GET disabled: %v", err)
	}
	disResp.Body.Close()
	if disResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("disabled route status = %d, want 503", disResp.StatusCode)
	}
	nfResp, err := gwSrv.Client().Get(gwSrv.URL + "/gw/no-such-route")
	if err != nil {
		t.Fatalf("GET unknown: %v", err)
	}
	nfResp.Body.Close()
	if nfResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want 404", nfResp.StatusCode)
	}

	// GET /metrics
	metResp, err := gwSrv.Client().Get(gwSrv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	var stats GatewayStats
	_ = json.NewDecoder(metResp.Body).Decode(&stats)
	metResp.Body.Close()
	if metResp.StatusCode != http.StatusOK || stats.TotalRequests != 1 || stats.RouteTotal != 2 || stats.RouteEnabled != 1 {
		t.Fatalf("unexpected /metrics response: status=%d stats=%+v", metResp.StatusCode, stats)
	}

	// Verify OpenAPI spec only includes enabled routes (search, NOT disabled-api)
	spec := mgr.OpenAPISpec()
	paths, _ := spec["paths"].(map[string]any)
	if _, ok := paths["/gw/search"]; !ok {
		t.Fatalf("OpenAPI missing /gw/search")
	}
	if _, ok := paths["/gw/disabled-api"]; ok {
		t.Fatalf("OpenAPI should exclude disabled route /gw/disabled-api")
	}
}

func TestCredentialRedactionAcrossProxyUpstreamAndSigner(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	// 1. Proxy Upsert extracts embedded credentials from URL into Username/Password
	//    and scrubs them from node.URL so display & transport deduplication work cleanly.
	deadSrv := httptest.NewServer(http.NotFoundHandler())
	deadHost := strings.TrimPrefix(deadSrv.URL, "http://")
	deadSrv.Close()

	secretPass := "S3cr3tPr0xyPass!"
	savedProxy, err := mgr.SaveProxy(ProxyNode{
		ID:      "p-auth-dead",
		Name:    "Auth Dead Proxy",
		URL:     "http://alice:" + secretPass + "@" + deadHost,
		Enabled: true,
		Healthy: true,
	})
	if err != nil {
		t.Fatalf("SaveProxy: %v", err)
	}
	if strings.Contains(savedProxy.URL, secretPass) || strings.Contains(savedProxy.URL, "alice") {
		t.Fatalf("expected credentials stripped from node.URL, got %q", savedProxy.URL)
	}
	if savedProxy.Username != "alice" || savedProxy.Password != secretPass {
		t.Fatalf("expected extracted credentials alice/%s, got %q/%q", secretPass, savedProxy.Username, savedProxy.Password)
	}

	// 2. CheckNode error and ProxyNode.LastError must redact credentials.
	checked, checkErr := mgr.CheckProxy(context.Background(), savedProxy.ID, "http://127.0.0.1:1/health")
	if checkErr == nil {
		t.Fatalf("expected CheckProxy failure against dead proxy")
	}
	if strings.Contains(checkErr.Error(), secretPass) || strings.Contains(checked.LastError, secretPass) {
		t.Fatalf("proxy password leaked in check error=%q last_error=%q", checkErr.Error(), checked.LastError)
	}

	// 3. Upstream failure through password proxy + upstream userinfo must redact URL & error.
	upstreamPass := "Upstr3amP@ss!"
	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:           "cred-upstream",
		Name:           "Cred Upstream",
		Enabled:        true,
		UpstreamMethod: "GET",
		UpstreamURL:    "http://bob:" + upstreamPass + "@" + deadHost + "/api",
		RequireProxy:   false,
	})
	if err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	// Re-mark proxy healthy so pipeline uses it and fails
	savedProxy.Healthy = true
	_, _ = mgr.SaveProxy(*savedProxy)

	res, invErr := mgr.InvokeRoute(context.Background(), "cred-upstream", TestInvokeRequest{})
	if invErr == nil || res == nil || res.OK {
		t.Fatalf("expected failed invocation against dead proxy/upstream")
	}
	for _, field := range []string{res.UpstreamURL, res.Error, invErr.Error()} {
		if strings.Contains(field, secretPass) || strings.Contains(field, upstreamPass) {
			t.Fatalf("credential leaked in result/error: %q", field)
		}
	}
	logs := mgr.ListLogs(5)
	if len(logs) == 0 {
		t.Fatalf("expected invocation log entry")
	}
	if strings.Contains(logs[0].UpstreamURL, upstreamPass) || strings.Contains(logs[0].Error, secretPass) || strings.Contains(logs[0].Error, upstreamPass) {
		t.Fatalf("credential leaked in InvocationRecord: %+v", logs[0])
	}

	// 4. HTTP signer failure with embedded credentials in EndpointURL must redact credentials.
	signerPass := "Sign3rSecret!"
	_, sigErr := ExecuteSigner(context.Background(), &SignerProvider{
		Name:        "Auth HTTP Signer",
		Kind:        SignerKindHTTP,
		Enabled:     true,
		EndpointURL: "http://svc:" + signerPass + "@" + deadHost + "/sign",
	}, SignerInput{Method: "GET"})
	if sigErr == nil {
		t.Fatalf("expected HTTP signer failure against dead host")
	}
	if strings.Contains(sigErr.Error(), signerPass) {
		t.Fatalf("signer credential leaked in error: %q", sigErr.Error())
	}
}

func TestTemplateInjectionAndSSRFHardening(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	// 1. Disallowed URL schemes rejected in SaveRoute, CheckNode, FetchFromProviderURL
	for _, badURL := range []string{"file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO", "ftp://example.com/a", "javascript:alert(1)"} {
		if _, err := mgr.SaveRoute(ServiceRoute{Slug: "bad", Name: "Bad", UpstreamURL: badURL}); err == nil {
			t.Fatalf("SaveRoute should reject disallowed scheme %q", badURL)
		}
	}
	if _, _, err := mgr.ProxyPool().FetchFromProviderURL(context.Background(), "file:///etc/passwd", ProviderFormatLines, ""); err == nil {
		t.Fatalf("FetchFromProviderURL should reject file:// scheme")
	}
	px, _ := mgr.SaveProxy(ProxyNode{ID: "px-scheme", Name: "PX", URL: "http://127.0.0.1:8080", Enabled: true})
	if _, err := mgr.ProxyPool().CheckNode(context.Background(), px.ID, "file:///etc/passwd"); err == nil {
		t.Fatalf("CheckNode should reject file:// scheme")
	}

	// 2. RenderURLTemplate escapes path traversal, query & fragment injection
	u, err := RenderURLTemplate("https://api.example.com/v1/users/{{input.uid}}?tag={{input.tag}}", TemplateContext{
		Input: map[string]string{
			"uid": "../../admin?role=super#frag",
			"tag": "a&admin=1#x",
		},
	})
	if err != nil {
		t.Fatalf("RenderURLTemplate path/query escape: %v", err)
	}
	if u.Host != "api.example.com" || u.Fragment != "" {
		t.Fatalf("unexpected host/fragment after escaping: %s", u.String())
	}
	if u.Query().Get("role") != "" || u.Query().Get("admin") != "" || u.Query().Get("tag") != "a&admin=1#x" {
		t.Fatalf("query smuggling occurred: %s", u.String())
	}
	if !strings.Contains(u.EscapedPath(), "%2F") || strings.Contains(u.EscapedPath(), "/admin") {
		t.Fatalf("path traversal not properly escaped: %s", u.EscapedPath())
	}

	// ".." segment alone must also be percent-encoded
	uDot, err := RenderURLTemplate("https://api.example.com/v1/{{input.seg}}/info", TemplateContext{
		Input: map[string]string{"seg": ".."},
	})
	if err != nil {
		t.Fatalf("RenderURLTemplate dotdot: %v", err)
	}
	if !strings.Contains(uDot.EscapedPath(), "%2E%2E") {
		t.Fatalf("expected '..' percent-encoded, got %s", uDot.EscapedPath())
	}

	// Host hijack attempts in templated subdomain must be rejected
	for _, evilSub := range []string{"169.254.169.254#", "evil.com@", "evil.com/path?", "a b"} {
		if _, err := RenderURLTemplate("https://{{input.sub}}.example.com/v1", TemplateContext{
			Input: map[string]string{"sub": evilSub},
		}); err == nil {
			t.Fatalf("RenderURLTemplate should reject host hijack input %q", evilSub)
		}
	}

	// 3. RenderJSONTemplate blocks JSON structure injection inside and outside strings
	injectedBody := RenderJSONTemplate(
		`{"q":"{{input.keyword}}","count":{{input.count}},"raw_val":{{input.evil_unquoted}}}`,
		TemplateContext{
			Input: map[string]string{
				"keyword":       `shoes","admin":true,"x":"`,
				"count":         "42",
				"evil_unquoted": `1,"admin":true`,
			},
		},
	)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(injectedBody), &decoded); err != nil {
		t.Fatalf("RenderJSONTemplate produced invalid JSON: %v (body=%s)", err, injectedBody)
	}
	if _, injected := decoded["admin"]; injected {
		t.Fatalf("JSON structure injection succeeded: %s", injectedBody)
	}
	if decoded["q"] != `shoes","admin":true,"x":"` || decoded["count"] != float64(42) || decoded["raw_val"] != `1,"admin":true` {
		t.Fatalf("unexpected safely escaped JSON values: %+v", decoded)
	}

	// 4. {{env.*}} only exposes CAP_GW_* from host os.Getenv (arbitrary host secrets blocked)
	t.Setenv("CAP_GW_PUBLIC_REGION", "us-east")
	t.Setenv("SUPER_SECRET_HOST_TOKEN", "do-not-leak")
	gotEnv := RenderTemplate("r={{env.CAP_GW_PUBLIC_REGION}}&s={{env.SUPER_SECRET_HOST_TOKEN}}", TemplateContext{})
	if gotEnv != "r=us-east&s=" {
		t.Fatalf("unexpected env expansion: %q (want r=us-east&s=)", gotEnv)
	}
}

func TestSignerHeaderCaseOverrideFridaEscapingOpenAPIAndAutoRefreshRace(t *testing.T) {
	// 1. ApplySignature overrides existing headers case-insensitively (no duplicate keys)
	u, _ := url.Parse("https://api.example.com/v1")
	existing := map[string]string{
		"x-sign":   "old-lowercase-value",
		"x-gorgon": "old-gorgon",
	}
	provider := &SignerProvider{
		InjectTarget:  InjectTargetHeader,
		InjectField:   "X-Sign",
		OutputMapping: map[string]string{"g": "header:X-Gorgon"},
	}
	sigOut := &SignerOutput{
		Sign:    "new-fresh-sig",
		Headers: map[string]string{"X-Extra": "1"},
		Raw:     map[string]any{"g": "new-gorgon"},
	}
	_, hdrs, _, err := ApplySignature(provider, sigOut, u, existing, "")
	if err != nil {
		t.Fatalf("ApplySignature: %v", err)
	}
	if _, dup := hdrs["x-sign"]; dup {
		t.Fatalf("expected lowercase x-sign removed when X-Sign injected, got %+v", hdrs)
	}
	if _, dup := hdrs["x-gorgon"]; dup {
		t.Fatalf("expected lowercase x-gorgon removed when X-Gorgon mapped, got %+v", hdrs)
	}
	if hdrs["X-Sign"] != "new-fresh-sig" || hdrs["X-Gorgon"] != "new-gorgon" {
		t.Fatalf("unexpected headers after case-insensitive override: %+v", hdrs)
	}

	// 2. buildFridaRPCDriverScript escapes quotes/backslashes cleanly and yields valid Python syntax
	trickyFrida := &SignerProvider{
		FridaSerial:  `emu'1"\test`,
		FridaPackage: `com.app."evil"'pkg`,
		FridaExport:  `sign'Req"\n`,
		ScriptCode:   "", // exercises fallback JS error message generation too
	}
	pyScript := buildFridaRPCDriverScript(trickyFrida)
	if pyPath, err := exec.LookPath("python3"); err == nil {
		tmpPy := filepath.Join(t.TempDir(), "frida_driver.py")
		if err := os.WriteFile(tmpPy, []byte(pyScript), 0o600); err != nil {
			t.Fatalf("write temp py: %v", err)
		}
		if out, err := exec.Command(pyPath, "-m", "py_compile", tmpPy).CombinedOutput(); err != nil {
			t.Fatalf("generated Frida RPC python failed py_compile: %v\n%s\nscript:\n%s", err, string(out), pyScript)
		}
	}

	// 3. OpenAPI 3.0.3 validity: normalized ":9090" server URL, no duplicate "raw" param, no requestBody on GET
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	_ = mgr.UpdateConfig(GatewayConfig{ListenAddr: ":9090"})
	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:           "get-with-raw-and-body",
		Name:           "GET Edge Case",
		Enabled:        true,
		UpstreamMethod: "GET",
		UpstreamURL:    "https://api.example.com/items?raw={{input.raw}}&id={{input.id}}",
		BodyTemplate:   `{"ignored_for_openapi_get":true}`,
	})
	if err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}

	spec := mgr.OpenAPISpec()
	servers, _ := spec["servers"].([]map[string]any)
	if len(servers) == 0 || servers[0]["url"] != "http://127.0.0.1:9090" {
		t.Fatalf("OpenAPI server URL = %+v, want http://127.0.0.1:9090", servers)
	}
	paths, _ := spec["paths"].(map[string]any)
	pathItem, _ := paths["/gw/get-with-raw-and-body"].(map[string]any)
	getOp, _ := pathItem["get"].(map[string]any)
	if _, hasReqBody := getOp["requestBody"]; hasReqBody {
		t.Fatalf("OpenAPI GET operation must not include requestBody")
	}
	params, _ := getOp["parameters"].([]map[string]any)
	rawCount := 0
	for _, p := range params {
		if name, _ := p["name"].(string); strings.EqualFold(name, "raw") {
			rawCount++
		}
	}
	if rawCount != 1 {
		t.Fatalf("expected exactly 1 'raw' query parameter in OpenAPI, got %d (%+v)", rawCount, params)
	}

	// 4. Concurrent StartAutoRefresh / StopAutoRefresh race test
	pool := NewProxyPool(ProxyPoolConfig{
		ProviderURL:        "http://127.0.0.1:1/proxies",
		RefreshIntervalSec: 60,
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool.StartAutoRefresh(context.Background())
		}()
	}
	wg.Wait()
	pool.StopAutoRefresh()
}
