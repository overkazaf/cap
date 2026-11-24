package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/store/sqlite"
	"github.com/overkazaf/cap/internal/tui"
	"github.com/overkazaf/cap/internal/types"
)

func seedTestDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "flows.db")
	st, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer st.Close()

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	flows := []*types.Flow{
		{
			ID:           "f1",
			Timestamp:    now,
			Method:       "GET",
			URL:          "https://api.example.com/v1/users",
			Host:         "api.example.com",
			Path:         "/v1/users",
			ReqHeaders:   map[string]string{"Accept": "application/json"},
			Status:       200,
			RespHeaders:  map[string]string{"Content-Type": "application/json"},
			RespBody:     []byte(`{"ok":true}`),
			RespBodyType: "application/json",
			LatencyMs:    45,
		},
		{
			ID:           "f2",
			Timestamp:    now.Add(time.Second),
			Method:       "POST",
			URL:          "https://api.example.com/v1/login",
			Host:         "api.example.com",
			Path:         "/v1/login",
			ReqHeaders:   map[string]string{"Content-Type": "application/json"},
			ReqBody:      []byte(`{"user":"alice"}`),
			ReqBodyType:  "application/json",
			Status:       401,
			RespHeaders:  map[string]string{"Content-Type": "application/json"},
			RespBody:     []byte(`{"error":"unauthorized"}`),
			RespBodyType: "application/json",
			LatencyMs:    512,
		},
	}
	for _, f := range flows {
		if err := st.SaveFlow(f); err != nil {
			t.Fatalf("SaveFlow %s: %v", f.ID, err)
		}
	}
	return dbPath
}

func TestRootHelpAndSubcommands(t *testing.T) {
	orig := i18n.Lang()
	defer i18n.SetLang(string(orig))
	i18n.SetLang("en")

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap --help failed: %v", err)
	}
	text := out.String()
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("non-TTY cap --help must not emit ANSI escapes:\n%s", text)
	}
	for _, want := range []string{"CAPTURE & INSPECTION", "DEVICE & SSL UNPINNING", "start", "tui", "gui", "flows", "export", "android", "unpin", "cap start --tui", "© 2026 0xaf (@overkazaf)", "https://github.com/overkazaf/cap"} {
		if !strings.Contains(text, want) {
			t.Errorf("cap --help missing %q", want)
		}
	}

	// Localized Chinese root help via --lang zh
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--lang", "zh", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap --lang zh --help failed: %v", err)
	}
	zhText := out.String()
	for _, want := range []string{"抓包与流量检视", "设备管理与 SSL 绕过", "快速开始", "© 2026 0xaf (@overkazaf)", "https://github.com/overkazaf/cap"} {
		if !strings.Contains(zhText, want) {
			t.Errorf("cap --lang zh --help missing %q:\n%s", want, zhText)
		}
	}
}

func TestFlowsCommandJSONAndPlainTable(t *testing.T) {
	dbPath := seedTestDB(t)

	// 1. --format json (pure JSON, zero ANSI)
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"flows", "-d", dbPath, "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap flows --format json failed: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("JSON output must never contain ANSI escapes")
	}
	var decoded []*types.Flow
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON from cap flows: %v\n%s", err, out.String())
	}
	if len(decoded) != 2 || decoded[0].ID != "f2" {
		t.Fatalf("unexpected decoded flows: %+v", decoded)
	}

	// 2. --json shorthand with --method filter
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"flows", "-d", dbPath, "--method", "POST", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap flows --json failed: %v", err)
	}
	decoded = nil
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON from --json shorthand: %v", err)
	}
	if len(decoded) != 1 || decoded[0].ID != "f2" {
		t.Fatalf("expected only f2, got %+v", decoded)
	}

	// 3. Non-TTY table stays plain, uncolored, parseable
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"flows", "-d", dbPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap flows table failed: %v", err)
	}
	tbl := out.String()
	if strings.Contains(tbl, "\x1b[") {
		t.Fatalf("non-TTY table must not contain ANSI escapes:\n%s", tbl)
	}
	if !strings.Contains(tbl, "ID") || !strings.Contains(tbl, "f2") || !strings.Contains(tbl, "/v1/login") {
		t.Fatalf("unexpected plain table output:\n%s", tbl)
	}

	// 4. Styled TTY table renders cleanly with header & tip
	var styledBuf bytes.Buffer
	st, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	allFlows, _ := st.ListFlows(types.FlowFilter{})
	if err := writeFlowsStyledTable(&styledBuf, allFlows, types.FlowFilter{}); err != nil {
		t.Fatalf("writeFlowsStyledTable: %v", err)
	}
	styledText := tui.StripANSI(styledBuf.String())
	if !strings.Contains(styledText, "CAP") || !strings.Contains(styledText, "f2") || !strings.Contains(styledText, "cap tui") {
		t.Fatalf("unexpected styled table output:\n%s", styledText)
	}
}

func TestExportCommandPureOutput(t *testing.T) {
	dbPath := seedTestDB(t)

	// Code export must remain pure runnable snippet with zero ANSI,
	// and its local --lang flag must not collide with root's persistent --lang!
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"export", "-d", dbPath, "--flow", "f2", "--lang", "curl"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap export --lang curl failed: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("single-lang export must not contain ANSI escapes")
	}
	if !strings.Contains(out.String(), "curl") || !strings.Contains(out.String(), "https://api.example.com/v1/login") {
		t.Fatalf("unexpected curl output:\n%s", out.String())
	}

	// Invalid root --lang flag fails cleanly.
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--lang", "klingon", "flows", "-d", dbPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid root --lang value")
	}

	// Agent JSONL export must be clean JSONL.
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"export", "-d", dbPath, "-f", "agent"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap export agent failed: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("agent export must not contain ANSI escapes")
	}
	if !strings.Contains(out.String(), "api.example.com") {
		t.Fatalf("unexpected agent export output:\n%s", out.String())
	}
}

func TestStartStreamFormattingAndBanner(t *testing.T) {
	orig := i18n.Lang()
	defer i18n.SetLang(string(orig))
	i18n.SetLang("en")

	f := &types.Flow{
		ID:        "f9",
		Timestamp: time.Date(2026, 11, 22, 15, 4, 5, 0, time.UTC),
		Method:    "POST",
		URL:       "https://api.example.com/v1/orders",
		Host:      "api.example.com",
		Path:      "/v1/orders",
		Status:    201,
		RespBody:  []byte(`{"id":99}`),
		LatencyMs: 85,
	}

	// Non-TTY plain line matches classic format with zero ANSI.
	plain := formatStreamFlowLine(f, false, cliTheme(false), 100)
	wantPlain := "[f9] POST https://api.example.com/v1/orders → 201 (85ms)"
	if plain != wantPlain {
		t.Fatalf("plain stream line = %q, want %q", plain, wantPlain)
	}

	// Styled TTY line contains method, status, latency, size, target.
	th := tui.NewTheme(tui.ThemeDark, false, true)
	styled := formatStreamFlowLine(f, true, th, 110)
	if !strings.Contains(styled, "\x1b[") {
		t.Fatal("expected ANSI escapes in styled stream line")
	}
	stripped := tui.StripANSI(styled)
	for _, token := range []string{"f9", "POST", "201", "85ms", "9 B", "api.example.com/v1/orders"} {
		if !strings.Contains(stripped, token) {
			t.Errorf("styled stream line missing %q: %q", token, stripped)
		}
	}

	// Banner in both modes.
	var plainBuf, styledBuf bytes.Buffer
	printStartBanner(&plainBuf, false, cliTheme(false), 100, "127.0.0.1:8080", "/tmp/flows.db", "/tmp/ca.crt", true, "")
	if strings.Contains(plainBuf.String(), "\x1b[") || !strings.Contains(plainBuf.String(), "cap: listening on") {
		t.Fatalf("unexpected plain banner:\n%s", plainBuf.String())
	}

	printStartBanner(&styledBuf, true, th, 100, "127.0.0.1:8080", "/tmp/flows.db", "/tmp/ca.crt", true, "emulator-5554 (10.0.2.2:8080)")
	sb := tui.StripANSI(styledBuf.String())
	for _, want := range []string{"CAP", "MITM Proxy", "http://127.0.0.1:8080", "cap start --tui", "emulator-5554"} {
		if !strings.Contains(sb, want) {
			t.Errorf("styled banner missing %q:\n%s", want, sb)
		}
	}

	// Localized Chinese banner.
	i18n.SetLang("zh")
	var zhBuf bytes.Buffer
	printStartBanner(&zhBuf, true, th, 100, "127.0.0.1:8080", "/tmp/flows.db", "/tmp/ca.crt", true, "")
	zhBanner := tui.StripANSI(zhBuf.String())
	for _, want := range []string{"MITM 代理", "实时", "自动清理"} {
		if !strings.Contains(zhBanner, want) {
			t.Errorf("ZH styled banner missing %q:\n%s", want, zhBanner)
		}
	}
}

func TestTUICommandRejectsNonTTY(t *testing.T) {
	origLang := i18n.Lang()
	defer i18n.SetLang(string(origLang))
	i18n.SetLang("en")

	orig := isTTYCheck
	isTTYCheck = func(*os.File) bool { return false }
	defer func() { isTTYCheck = orig }()

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"tui", "-d", filepath.Join(t.TempDir(), "flows.db")})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("expected interactive terminal error in non-TTY, got: %v", err)
	}
}

func TestUnpinScriptRemainsRawJS(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"unpin", "script"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap unpin script failed: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("cap unpin script must never emit ANSI escapes")
	}
	if len(out.String()) < 100 {
		t.Fatalf("expected non-empty Frida JS script, got %d bytes", out.Len())
	}
}

func TestAndroidCLIFlagsAndStatusRendering(t *testing.T) {
	origLang := i18n.Lang()
	defer i18n.SetLang(string(origLang))
	i18n.SetLang("en")

	// Verify `cap android connect --help` exposes --no-companion and `cap android cert` exists.
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"android", "connect", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("android connect --help failed: %v", err)
	}
	if !strings.Contains(out.String(), "--no-companion") {
		t.Fatalf("expected --no-companion flag in android connect --help:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"android", "cert", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("android cert --help failed: %v", err)
	}
	if !strings.Contains(out.String(), "--check") || !strings.Contains(out.String(), "--remove") {
		t.Fatalf("expected --check and --remove in android cert --help:\n%s", out.String())
	}

	// Render DeviceStatus in plain, styled EN, and styled ZH modes.
	st := &android.DeviceStatus{
		Serial:         "emulator-5554",
		Model:          "Pixel 8",
		AndroidVersion: "14",
		SDK:            "34",
		Rooted:         true,
		ProxyAddress:   "192.168.1.5:8080",
		CertStatus: android.CertStatus{
			Installed: true,
			Store:     "system",
			Hash:      "9a5ba575.0",
		},
		CompanionStatus: android.CompanionStatus{
			Installed:         true,
			Version:           "1.0.0",
			HasSecureSettings: true,
			WatchdogRunning:   true,
		},
	}

	var plainBuf bytes.Buffer
	renderAndroidStatus(&plainBuf, false, cliTheme(false), st)
	if strings.Contains(plainBuf.String(), "\x1b[") {
		t.Fatal("non-TTY android status must not emit ANSI escapes")
	}
	for _, want := range []string{"emulator-5554", "192.168.1.5:8080", "store=system", "watchdog=true"} {
		if !strings.Contains(plainBuf.String(), want) {
			t.Errorf("plain android status missing %q:\n%s", want, plainBuf.String())
		}
	}

	th := tui.NewTheme(tui.ThemeDark, false, true)
	var enBuf bytes.Buffer
	renderAndroidStatus(&enBuf, true, th, st)
	enText := tui.StripANSI(enBuf.String())
	for _, want := range []string{"System Trusted", "Watchdog Active", "WRITE_SECURE_SETTINGS ✓"} {
		if !strings.Contains(enText, want) {
			t.Errorf("EN android status missing %q:\n%s", want, enText)
		}
	}

	i18n.SetLang("zh")
	var zhBuf bytes.Buffer
	renderAndroidStatus(&zhBuf, true, th, st)
	zhText := tui.StripANSI(zhBuf.String())
	for _, want := range []string{"Android 设备状态", "系统信任区", "看门狗运行中"} {
		if !strings.Contains(zhText, want) {
			t.Errorf("ZH android status missing %q:\n%s", want, zhText)
		}
	}
}

func TestFridaCLICommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Verify `cap frida --help` lists all expected subcommands
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"frida", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap frida --help failed: %v", err)
	}
	for _, sub := range []string{"status", "deploy", "start", "stop", "ps", "scripts", "run"} {
		if !strings.Contains(out.String(), sub) {
			t.Errorf("cap frida --help missing subcommand %q", sub)
		}
	}

	// Verify `cap frida scripts --json` emits valid machine-readable JSON without ANSI
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"frida", "scripts", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap frida scripts --json failed: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("cap frida scripts --json must not contain ANSI escapes")
	}
	if !strings.Contains(out.String(), "builtin:ssl-unpin-universal") {
		t.Fatalf("expected built-in SSL unpin script in JSON output:\n%s", out.String())
	}

	// Verify `cap frida scripts --show builtin:crypto-sign-tracer` prints raw JS
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"frida", "scripts", "--show", "builtin:crypto-sign-tracer"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap frida scripts --show failed: %v", err)
	}
	if !strings.Contains(out.String(), "MessageDigest") {
		t.Fatalf("expected MessageDigest hook in crypto-sign-tracer output")
	}
}

func TestREAndDeobfCLICommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// 1. cap re --help & projects --json & gen
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"re", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap re --help failed: %v", err)
	}
	for _, sub := range []string{"status", "analyze", "r2", "projects", "gen"} {
		if !strings.Contains(out.String(), sub) {
			t.Errorf("cap re --help missing subcommand %q", sub)
		}
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"re", "projects", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap re projects --json failed: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("cap re projects --json must not contain ANSI escapes")
	}
	var projects []map[string]any
	if err := json.Unmarshal(out.Bytes(), &projects); err != nil || len(projects) == 0 {
		t.Fatalf("invalid JSON from cap re projects: err=%v len=%d", err, len(projects))
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"re", "gen", "--engine", "unidbg", "--class", "com/acme/Sign", "--method", "calc"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap re gen failed: %v", err)
	}
	if !strings.Contains(out.String(), "com/acme/Sign") {
		t.Fatalf("cap re gen output missing target class:\n%s", out.String())
	}

	// 2. cap deobf --help, stealth, unpack, ollvm, vmp, vmp-trace
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"deobf", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap deobf --help failed: %v", err)
	}
	for _, sub := range []string{"scan", "stealth", "unpack", "ollvm", "vmp", "vmp-trace"} {
		if !strings.Contains(out.String(), sub) {
			t.Errorf("cap deobf --help missing subcommand %q", sub)
		}
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"deobf", "stealth", "--pkg", "com.acme.app"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap deobf stealth failed: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[") || len(out.String()) < 100 {
		t.Fatalf("unexpected cap deobf stealth output (len=%d)", out.Len())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"deobf", "ollvm", "--so", "./libsec.so", "--addr", "0x1000"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap deobf ollvm failed: %v", err)
	}
	if !strings.Contains(out.String(), "import angr") {
		t.Fatalf("expected angr script from cap deobf ollvm")
	}

	vmpFile := filepath.Join(t.TempDir(), "vmp.log")
	vmpTrace := `[CAP_VMP] {"pc":"0x7000001000","insn":"br x8","target":"0x7000002000"}` + "\n" +
		`[CAP_VMP] {"pc":"0x7000002000","insn":"add x0, x0, #1"}` + "\n"
	if err := os.WriteFile(vmpFile, []byte(vmpTrace), 0o644); err != nil {
		t.Fatalf("write vmp trace: %v", err)
	}
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"deobf", "vmp-trace", vmpFile, "--base", "0x7000000000", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap deobf vmp-trace failed: %v", err)
	}
	var vmpOut map[string]any
	if err := json.Unmarshal(out.Bytes(), &vmpOut); err != nil {
		t.Fatalf("invalid JSON from cap deobf vmp-trace: %v", err)
	}
}

func TestExecTraceAndGatewayCLICommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// 1. cap exectrace workflow: import -> list -> taint -> diff -> collect -> export
	traceDir := t.TempDir()
	traceAFile := filepath.Join(traceDir, "a.log")
	traceBFile := filepath.Join(traceDir, "b.log")
	traceAContent := "[12:00:00 001][libsign.so 0x1000] [e0 03 01 aa] 0x40001000: \"mov x0, x1\" x1=0x11 => x0=0x11\n" +
		"[12:00:00 002][libsign.so 0x1004] [02 00 03 ca] 0x40001004: \"eor x2, x0, x3\" x0=0x11 x3=0xff => x2=0xee\n"
	traceBContent := "[12:00:00 001][libsign.so 0x1000] [e0 03 01 aa] 0x50001000: \"mov x0, x1\" x1=0x11 => x0=0x11\n" +
		"[12:00:00 002][libsign.so 0x1008] [02 00 03 ca] 0x50001008: \"sub x2, x0, x3\" x0=0x11 x3=0x01 => x2=0x10\n"
	if err := os.WriteFile(traceAFile, []byte(traceAContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(traceBFile, []byte(traceBContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"exectrace", "import", traceAFile, "--name", "run-a", "--base", "0x40000000", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exectrace import A failed: %v", err)
	}
	var sessA struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out.Bytes(), &sessA); err != nil || sessA.ID == "" {
		t.Fatalf("failed to decode imported session A: err=%v raw=%s", err, out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"exectrace", "import", traceBFile, "--name", "run-b", "--base", "0x50000000", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exectrace import B failed: %v", err)
	}
	var sessB struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out.Bytes(), &sessB); err != nil || sessB.ID == "" {
		t.Fatalf("failed to decode imported session B: err=%v raw=%s", err, out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"exectrace", "list", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exectrace list failed: %v", err)
	}
	if !strings.Contains(out.String(), sessA.ID) || !strings.Contains(out.String(), sessB.ID) {
		t.Fatalf("exectrace list missing imported sessions:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"exectrace", "taint", "--session", sessA.ID, "--direction", "forward", "--seq", "1", "--reg", "x0", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exectrace taint failed: %v", err)
	}
	if !strings.Contains(out.String(), "tainted_steps") {
		t.Fatalf("unexpected taint JSON:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"exectrace", "diff", sessA.ID, sessB.ID, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exectrace diff failed: %v", err)
	}
	if !strings.Contains(out.String(), "first_divergence") {
		t.Fatalf("unexpected diff JSON:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"exectrace", "collect", "--kind", "stalker", "--module", "libsign.so"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exectrace collect failed: %v", err)
	}
	if !strings.Contains(out.String(), "libsign.so") {
		t.Fatalf("unexpected collect output:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"exectrace", "export", sessA.ID, "--format", "tenet"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("exectrace export failed: %v", err)
	}
	if !strings.Contains(out.String(), "pc=0x40001000") {
		t.Fatalf("unexpected tenet export:\n%s", out.String())
	}

	// 2. cap gateway workflow: status, publish, routes, proxies, devices, signers, openapi
	dbPath := seedTestDB(t)

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"gateway", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap gateway --help failed: %v", err)
	}
	for _, sub := range []string{"start", "status", "routes", "publish", "proxies", "devices", "signers", "openapi"} {
		if !strings.Contains(out.String(), sub) {
			t.Errorf("cap gateway --help missing subcommand %q", sub)
		}
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"gateway", "publish", "-d", dbPath, "--flow", "f1", "--slug", "list-users", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap gateway publish failed: %v", err)
	}
	if !strings.Contains(out.String(), `"slug": "list-users"`) {
		t.Fatalf("unexpected publish output:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"gateway", "routes", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap gateway routes failed: %v", err)
	}
	if !strings.Contains(out.String(), "list-users") {
		t.Fatalf("expected published route in cap gateway routes:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"gateway", "proxies", "--add", "socks5://127.0.0.1:1080", "--region", "US"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap gateway proxies --add failed: %v", err)
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"gateway", "devices", "--presets", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap gateway devices --presets failed: %v", err)
	}
	if !strings.Contains(out.String(), "fingerprint") {
		t.Fatalf("unexpected device presets JSON:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"gateway", "status", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap gateway status failed: %v", err)
	}
	if !strings.Contains(out.String(), `"route_total": 1`) {
		t.Fatalf("unexpected gateway status JSON:\n%s", out.String())
	}

	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"gateway", "openapi"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap gateway openapi failed: %v", err)
	}
	if !strings.Contains(out.String(), `"openapi": "3.0.3"`) || !strings.Contains(out.String(), "/gw/list-users") {
		t.Fatalf("unexpected OpenAPI output:\n%s", out.String())
	}
}
