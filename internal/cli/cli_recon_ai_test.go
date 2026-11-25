package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/overkazaf/cap/internal/ai"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/recon"
)

func TestRootHelpIncludesReconAndAI(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	orig := i18n.Lang()
	defer i18n.SetLang(string(orig))
	i18n.SetLang("en")

	out, err := execCLI(t, "", "--help")
	if err != nil {
		t.Fatalf("cap --help failed: %v", err)
	}
	for _, want := range []string{"recon", "ai"} {
		if !strings.Contains(out, want) {
			t.Errorf("cap --help missing command %q:\n%s", want, out)
		}
	}
}

func TestCLIReconSubcommands(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	capDir := filepath.Join(homeDir, ".cap")
	if err := os.MkdirAll(capDir, 0o755); err != nil {
		t.Fatalf("mkdir .cap: %v", err)
	}

	// 1. status loads saved recon_* paths from ~/.cap/settings.json
	fakeNmap := filepath.Join(t.TempDir(), "mock-nmap")
	if err := os.WriteFile(fakeNmap, []byte("#!/bin/sh\necho 'Nmap version 7.94'\n"), 0o755); err != nil {
		t.Fatalf("write mock-nmap: %v", err)
	}
	settingsJSON, _ := json.Marshal(map[string]string{
		"recon_nmap_path":      fakeNmap,
		"recon_subfinder_path": "/nonexistent/subfinder",
		"recon_whois_path":     "/nonexistent/whois",
		"recon_dig_path":       "/nonexistent/dig",
	})
	if err := os.WriteFile(filepath.Join(capDir, "settings.json"), settingsJSON, 0o644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	out, err := execCLI(t, "", "recon", "status", "--json")
	if err != nil {
		t.Fatalf("cap recon status --json: %v\n%s", err, out)
	}
	var tc recon.ToolchainInfo
	if err := json.Unmarshal([]byte(out), &tc); err != nil {
		t.Fatalf("unmarshal toolchain info: %v\n%s", err, out)
	}
	if !tc.Nmap.Ready || tc.Nmap.Path != fakeNmap || tc.Nmap.Version != "7.94" {
		t.Fatalf("expected saved recon_nmap_path loaded and ready, got %+v", tc.Nmap)
	}
	out, err = execCLI(t, "", "recon", "status")
	if err != nil || !strings.Contains(out, "nmap") {
		t.Fatalf("cap recon status text failed: err=%v out=%s", err, out)
	}

	// 2. domain (loopback)
	out, err = execCLI(t, "", "recon", "domain", "127.0.0.1", "--json")
	if err != nil {
		t.Fatalf("cap recon domain --json: %v\n%s", err, out)
	}
	var domRep recon.DomainReport
	if err := json.Unmarshal([]byte(out), &domRep); err != nil || domRep.Target != "127.0.0.1" {
		t.Fatalf("unexpected domain report: err=%v rep=%+v", err, domRep)
	}

	// 3. site (--no-discovery --insecure --json and text)
	siteSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.26.0")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>CLI Recon Site</title></head><body>hi</body></html>"))
	}))
	defer siteSrv.Close()

	out, err = execCLI(t, "", "recon", "site", siteSrv.URL, "--no-discovery", "--insecure", "--json")
	if err != nil {
		t.Fatalf("cap recon site --json: %v\n%s", err, out)
	}
	var siteProf recon.SiteProfile
	if err := json.Unmarshal([]byte(out), &siteProf); err != nil || siteProf.Title != "CLI Recon Site" {
		t.Fatalf("unexpected site profile: err=%v prof=%+v", err, siteProf)
	}
	out, err = execCLI(t, "", "recon", "site", siteSrv.URL, "--no-discovery")
	if err != nil || !strings.Contains(out, "CLI Recon Site") {
		t.Fatalf("cap recon site text failed: err=%v out=%s", err, out)
	}

	// 4. tls (--port --json and text)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()
	parsedTLS, _ := url.Parse(tlsSrv.URL)
	tlsHost, tlsPort, _ := net.SplitHostPort(parsedTLS.Host)

	out, err = execCLI(t, "", "recon", "tls", tlsHost, "--port", tlsPort, "--json")
	if err != nil {
		t.Fatalf("cap recon tls --json: %v\n%s", err, out)
	}
	var tlsRep recon.TLSInspectReport
	if err := json.Unmarshal([]byte(out), &tlsRep); err != nil || tlsRep.Leaf == nil {
		t.Fatalf("unexpected tls report: err=%v rep=%+v", err, tlsRep)
	}
	out, err = execCLI(t, "", "recon", "tls", tlsHost, "--port", tlsPort)
	if err != nil || !strings.Contains(out, "TLS") {
		t.Fatalf("cap recon tls text failed: err=%v out=%s", err, out)
	}

	// 5. subdomains (--no-ct/--no-subfinder/--no-dns/--json)
	if _, err := execCLI(t, "", "recon", "subdomains", "example.test", "--no-ct", "--no-subfinder", "--no-dns"); err == nil {
		t.Fatal("expected error when all subdomain sources are disabled")
	}
	ctSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name_value":"app.example.test"},{"name_value":"gw.example.test"}]`))
	}))
	defer ctSrv.Close()

	out, err = execCLI(t, "", "recon", "subdomains", "example.test", "--no-subfinder", "--no-dns", "--ct-endpoint", ctSrv.URL+"/?q=%s", "--json")
	if err != nil {
		t.Fatalf("cap recon subdomains --json: %v\n%s", err, out)
	}
	var subRep recon.SubdomainReport
	if err := json.Unmarshal([]byte(out), &subRep); err != nil || subRep.TotalCount != 2 {
		t.Fatalf("unexpected subdomain report: err=%v rep=%+v", err, subRep)
	}

	// 6. ports (--engine native --preset custom --ports --service-version --timeout-ms --json)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: CapTest\r\n\r\n"))
			_ = c.Close()
		}
	}()
	openPort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	out, err = execCLI(t, "", "recon", "ports", "127.0.0.1",
		"--engine", "native",
		"--preset", "custom",
		"--ports", openPort,
		"--service-version",
		"--timeout-ms", "500",
		"--json")
	if err != nil {
		t.Fatalf("cap recon ports --json: %v\n%s", err, out)
	}
	var psRes recon.PortScanResult
	if err := json.Unmarshal([]byte(out), &psRes); err != nil || psRes.OpenCount != 1 {
		t.Fatalf("unexpected portscan result: err=%v res=%+v", err, psRes)
	}
	out, err = execCLI(t, "", "recon", "ports", "127.0.0.1", "--engine", "native", "--ports", openPort, "--timeout-ms", "500")
	if err != nil || !strings.Contains(out, openPort) {
		t.Fatalf("cap recon ports text failed: err=%v out=%s", err, out)
	}

	// 7. history (--json, --show <id>, --clear)
	out, err = execCLI(t, "", "recon", "history", "--json")
	if err != nil {
		t.Fatalf("cap recon history --json: %v\n%s", err, out)
	}
	var entries []recon.ReconHistoryEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil || len(entries) < 3 {
		t.Fatalf("expected persisted recon history entries, err=%v len=%d", err, len(entries))
	}

	out, err = execCLI(t, "", "recon", "history", "--show", entries[0].ID, "--json")
	if err != nil {
		t.Fatalf("cap recon history --show: %v\n%s", err, out)
	}
	var shown recon.ReconHistoryEntry
	if err := json.Unmarshal([]byte(out), &shown); err != nil || shown.ID != entries[0].ID {
		t.Fatalf("unexpected history --show output: err=%v entry=%+v", err, shown)
	}

	out, err = execCLI(t, "", "recon", "history", "--clear", "--json")
	if err != nil {
		t.Fatalf("cap recon history --clear: %v\n%s", err, out)
	}
	out, err = execCLI(t, "", "recon", "history", "--json")
	if err != nil {
		t.Fatalf("cap recon history after clear: %v\n%s", err, out)
	}
	var remaining []recon.ReconHistoryEntry
	if err := json.Unmarshal([]byte(out), &remaining); err != nil || len(remaining) != 0 {
		t.Fatalf("expected 0 history entries after clear, err=%v len=%d", err, len(remaining))
	}
}

func TestCLIAISubcommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// 1. status & presets
	out, err := execCLI(t, "", "ai", "status", "--json")
	if err != nil {
		t.Fatalf("cap ai status --json: %v\n%s", err, out)
	}
	var initCfg ai.PublicAIConfig
	if err := json.Unmarshal([]byte(out), &initCfg); err != nil || !initCfg.RedactSecrets {
		t.Fatalf("unexpected initial AI status: err=%v cfg=%+v", err, initCfg)
	}

	out, err = execCLI(t, "", "ai", "presets", "--json")
	if err != nil {
		t.Fatalf("cap ai presets --json: %v\n%s", err, out)
	}
	var presets []ai.ProviderPreset
	if err := json.Unmarshal([]byte(out), &presets); err != nil || len(presets) < 5 {
		t.Fatalf("unexpected AI presets: err=%v len=%d", err, len(presets))
	}
	if out, err = execCLI(t, "", "ai", "presets"); err != nil || !strings.Contains(out, "ollama") {
		t.Fatalf("cap ai presets text failed: err=%v out=%s", err, out)
	}

	// Mock OpenAI-compatible provider server
	var mockMode atomic.Int32 // 0=valid fix, 1=bad syntax, 2=destructive rm -rf /
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		userMsg := ""
		for _, m := range body.Messages {
			if m.Role == "user" {
				userMsg = m.Content
			}
		}

		content := "OK"
		if strings.Contains(userMsg, "bad_var") {
			patched := "value = 42\nprint(value)\n"
			switch mockMode.Load() {
			case 1:
				patched = "def broken(:\n"
			case 2:
				patched = "import os\nos.system('rm -rf /')\n"
			}
			diagPayload := map[string]any{
				"root_cause":     "Undefined variable bad_var",
				"error_category": "runtime",
				"confidence":     0.94,
				"fix_kind":       ai.FixKindCodePatch,
				"explanation":    "Defined value = 42 and printed it",
				"patched_code":   patched,
				"verify_hint":    "python3 script.py",
			}
			raw, _ := json.Marshal(diagPayload)
			content = string(raw)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": content}},
			},
			"usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 18},
		})
	}))
	defer mockSrv.Close()

	// 2. profiles --add (--api-key-env & --api-key), --activate, list, --delete
	t.Setenv("CAP_CLI_AI_KEY", "sk-cli-secret-abcdef123456")
	out, err = execCLI(t, "", "ai", "profiles",
		"--add", "Primary Mock",
		"--provider", "openai_compat",
		"--base-url", mockSrv.URL,
		"--model", "gpt-4.1",
		"--api-key-env", "CAP_CLI_AI_KEY",
		"--json")
	if err != nil {
		t.Fatalf("cap ai profiles --add (env): %v\n%s", err, out)
	}
	if strings.Contains(out, "sk-cli-secret-abcdef123456") {
		t.Fatalf("raw API key must never appear in CLI output:\n%s", out)
	}
	var prof1 ai.PublicProviderConfig
	if err := json.Unmarshal([]byte(out), &prof1); err != nil || !prof1.HasAPIKey || prof1.Name != "Primary Mock" {
		t.Fatalf("unexpected profile 1: err=%v prof=%+v", err, prof1)
	}

	out, err = execCLI(t, "", "ai", "profiles",
		"--add",
		"--provider", "deepseek",
		"--base-url", mockSrv.URL,
		"--api-key", "sk-second-secret-999999999",
		"--json")
	if err != nil {
		t.Fatalf("cap ai profiles --add (preset): %v\n%s", err, out)
	}
	var prof2 ai.PublicProviderConfig
	if err := json.Unmarshal([]byte(out), &prof2); err != nil || prof2.Provider != ai.ProviderOpenAICompat {
		t.Fatalf("unexpected profile 2: err=%v prof=%+v", err, prof2)
	}

	if out, err = execCLI(t, "", "ai", "profiles", "--activate", prof2.ID); err != nil || !strings.Contains(out, prof2.ID) {
		t.Fatalf("cap ai profiles --activate failed: err=%v out=%s", err, out)
	}
	if out, err = execCLI(t, "", "ai", "profiles"); err != nil || !strings.Contains(out, prof1.ID) || !strings.Contains(out, prof2.ID) {
		t.Fatalf("cap ai profiles list failed: err=%v out=%s", err, out)
	}

	// 3. test (--profile and default active)
	out, err = execCLI(t, "", "ai", "test", "--profile", prof1.ID, "--json")
	if err != nil {
		t.Fatalf("cap ai test --profile --json: %v\n%s", err, out)
	}
	var testRes ai.TestConnectionResult
	if err := json.Unmarshal([]byte(out), &testRes); err != nil || !testRes.OK {
		t.Fatalf("unexpected test result: err=%v res=%+v", err, testRes)
	}
	if out, err = execCLI(t, "", "ai", "test"); err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("cap ai test default active failed: err=%v out=%s", err, out)
	}

	// 4. diagnose (--scope, --file, --error, --log-file, --locale, --json)
	workDir := t.TempDir()
	scriptPath := filepath.Join(workDir, "emulate.py")
	origCode := "print(bad_var)\n"
	if err := os.WriteFile(scriptPath, []byte(origCode), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	logPath := filepath.Join(workDir, "run.log")
	if err := os.WriteFile(logPath, []byte("NameError: name 'bad_var' is not defined\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	out, err = execCLI(t, "", "ai", "diagnose",
		"--scope", "qiling",
		"--file", scriptPath,
		"--error", "NameError: name 'bad_var' is not defined",
		"--log-file", logPath,
		"--locale", "en",
		"--json")
	if err != nil {
		t.Fatalf("cap ai diagnose --json: %v\n%s", err, out)
	}
	var diagRes ai.DiagnoseResult
	if err := json.Unmarshal([]byte(out), &diagRes); err != nil || diagRes.FixKind != ai.FixKindCodePatch || diagRes.Validation == nil || !diagRes.Validation.Passed {
		t.Fatalf("unexpected diagnose result: err=%v res=%+v", err, diagRes)
	}

	// 5. fix (default prints unified diff without modifying file)
	out, err = execCLI(t, "", "ai", "fix",
		"--scope", "qiling",
		"--file", scriptPath,
		"--log-file", logPath)
	if err != nil {
		t.Fatalf("cap ai fix dry-run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "-print(bad_var)") || !strings.Contains(out, "+value = 42") {
		t.Fatalf("expected unified diff in cap ai fix output:\n%s", out)
	}
	if raw, _ := os.ReadFile(scriptPath); string(raw) != origCode {
		t.Fatalf("dry-run fix must not modify file, got %q", string(raw))
	}
	if _, err := os.Stat(scriptPath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("dry-run fix must not create .bak file")
	}

	// 6. fix --apply rejects unvalidated syntax error AND destructive patch (rm -rf /) without touching file
	mockMode.Store(1)
	if _, err := execCLI(t, "", "ai", "fix", "--scope", "qiling", "--file", scriptPath, "--log-file", logPath, "--apply"); err == nil {
		t.Fatal("expected cap ai fix --apply to fail when syntax validation fails")
	}
	if raw, _ := os.ReadFile(scriptPath); string(raw) != origCode {
		t.Fatalf("failed syntax validation must leave file unchanged, got %q", string(raw))
	}

	mockMode.Store(2)
	if _, err := execCLI(t, "", "ai", "fix", "--scope", "qiling", "--file", scriptPath, "--log-file", logPath, "--apply"); err == nil {
		t.Fatal("expected cap ai fix --apply to reject destructive rm -rf / patch")
	}
	if raw, _ := os.ReadFile(scriptPath); string(raw) != origCode {
		t.Fatalf("destructive patch rejection must leave file unchanged, got %q", string(raw))
	}
	if _, err := os.Stat(scriptPath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("rejected destructive patch must not create .bak file")
	}
	mockMode.Store(0)

	// 7. fix --apply writes validated PatchedCode + creates .bak backup
	out, err = execCLI(t, "", "ai", "fix",
		"--scope", "qiling",
		"--file", scriptPath,
		"--log-file", logPath,
		"--apply",
		"--json")
	if err != nil {
		t.Fatalf("cap ai fix --apply --json: %v\n%s", err, out)
	}
	var fixOut struct {
		ai.DiagnoseResult
		Applied    bool   `json:"applied"`
		BackupPath string `json:"backup_path"`
	}
	if err := json.Unmarshal([]byte(out), &fixOut); err != nil || !fixOut.Applied || fixOut.BackupPath != scriptPath+".bak" {
		t.Fatalf("unexpected fix --apply output: err=%v out=%s", err, out)
	}
	if raw, err := os.ReadFile(scriptPath); err != nil || string(raw) != "value = 42\nprint(value)\n" {
		t.Fatalf("patched file content mismatch: err=%v got=%q", err, string(raw))
	}
	if bak, err := os.ReadFile(scriptPath + ".bak"); err != nil || string(bak) != origCode {
		t.Fatalf("backup file content mismatch: err=%v got=%q", err, string(bak))
	}

	// 8. profiles --delete
	if out, err = execCLI(t, "", "ai", "profiles", "--delete", prof2.ID); err != nil || !strings.Contains(out, prof2.ID) {
		t.Fatalf("cap ai profiles --delete failed: err=%v out=%s", err, out)
	}
}
