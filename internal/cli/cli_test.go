package cli

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/gateway"
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
	for _, sub := range []string{"status", "run", "analyze", "r2", "projects", "gen"} {
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

	// Regression: cap gateway signers --test parses Path & Query from --url
	gwMgr, err := gateway.NewManager(config.DefaultDir())
	if err != nil {
		t.Fatalf("gateway.NewManager: %v", err)
	}
	savedSigner, err := gwMgr.SaveSigner(gateway.SignerProvider{
		Name:          "Order HMAC",
		Kind:          gateway.SignerKindBuiltinHMAC,
		Enabled:       true,
		HMACAlgorithm: "hmac-sha256",
		HMACSecret:    "s3cr3t",
	})
	if err != nil {
		t.Fatalf("SaveSigner: %v", err)
	}
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"gateway", "signers", "--test", savedSigner.ID, "--url", "https://api.example.com/v1/order?b=2&a=1"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap gateway signers --test failed: %v", err)
	}
	var sigOut struct {
		Sign string         `json:"sign"`
		Raw  map[string]any `json:"raw"`
	}
	if err := json.Unmarshal(out.Bytes(), &sigOut); err != nil {
		t.Fatalf("decode signer test JSON: %v\n%s", err, out.String())
	}
	if sigOut.Sign == "" || sigOut.Raw["canonical"] != "a=1&b=2" {
		t.Fatalf("expected canonical query a=1&b=2, got sign=%q raw=%+v", sigOut.Sign, sigOut.Raw)
	}
}

func TestDeobfStealthScanAutoTailoring(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Build a minimal ARM64 ELF64 containing an inline `svc #0` (0xd4000001) in .text
	const ehdrSize, shdrSize = 64, 64
	shstrtab := []byte("\x00.shstrtab\x00.text\x00")
	textData := []byte{
		0xa8, 0x0e, 0x80, 0xd2, // mov x8, #117 (ptrace)
		0x01, 0x00, 0x00, 0xd4, // svc #0
		0xc0, 0x03, 0x5f, 0xd6, // ret
	}
	shstrOff := uint64(ehdrSize)
	textOff := shstrOff + uint64(len(shstrtab))
	shoff := (textOff + uint64(len(textData)) + 7) &^ 7

	var buf bytes.Buffer
	hdr := make([]byte, ehdrSize)
	copy(hdr[0:4], []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = 2 // 64-bit
	hdr[5] = 1 // little-endian
	hdr[6] = 1
	binary.LittleEndian.PutUint16(hdr[16:18], 3)   // ET_DYN
	binary.LittleEndian.PutUint16(hdr[18:20], 183) // EM_AARCH64
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	binary.LittleEndian.PutUint64(hdr[40:48], shoff)
	binary.LittleEndian.PutUint16(hdr[52:54], ehdrSize)
	binary.LittleEndian.PutUint16(hdr[58:60], shdrSize)
	binary.LittleEndian.PutUint16(hdr[60:62], 3)
	binary.LittleEndian.PutUint16(hdr[62:64], 1)
	buf.Write(hdr)
	buf.Write(shstrtab)
	buf.Write(textData)
	for uint64(buf.Len()) < shoff {
		buf.WriteByte(0)
	}
	writeShdr := func(nameOff, shType uint32, flags, addr, off, size uint64) {
		s := make([]byte, shdrSize)
		binary.LittleEndian.PutUint32(s[0:4], nameOff)
		binary.LittleEndian.PutUint32(s[4:8], shType)
		binary.LittleEndian.PutUint64(s[8:16], flags)
		binary.LittleEndian.PutUint64(s[16:24], addr)
		binary.LittleEndian.PutUint64(s[24:32], off)
		binary.LittleEndian.PutUint64(s[32:40], size)
		buf.Write(s)
	}
	writeShdr(0, 0, 0, 0, 0, 0)
	writeShdr(1, 3, 0, 0, shstrOff, uint64(len(shstrtab)))
	writeShdr(11, 1, 0x6, 0x1000, textOff, uint64(len(textData)))

	elfPath := filepath.Join(t.TempDir(), "libsvc.so")
	if err := os.WriteFile(elfPath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write svc elf: %v", err)
	}

	// Auto-tailor via --scan should enable PatchInlineSVC and omit BypassTimingAndInotify
	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"deobf", "stealth", "--scan", elfPath, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap deobf stealth --scan failed: %v", err)
	}
	var sc struct {
		Modules []string `json:"modules"`
	}
	if err := json.Unmarshal(out.Bytes(), &sc); err != nil {
		t.Fatalf("decode stealth JSON: %v", err)
	}
	joined := strings.Join(sc.Modules, ",")
	if !strings.Contains(joined, "PatchInlineSVC") {
		t.Fatalf("expected --scan to auto-enable PatchInlineSVC, got modules=%v", sc.Modules)
	}
	if strings.Contains(joined, "BypassTimingAndInotify") {
		t.Fatalf("expected --scan to omit unused BypassTimingAndInotify, got modules=%v", sc.Modules)
	}

	// Explicit --patch-svc=false overrides the report-derived default
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"deobf", "stealth", "--scan", elfPath, "--patch-svc=false", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap deobf stealth --scan --patch-svc=false failed: %v", err)
	}
	sc.Modules = nil
	if err := json.Unmarshal(out.Bytes(), &sc); err != nil {
		t.Fatalf("decode stealth override JSON: %v", err)
	}
	if strings.Contains(strings.Join(sc.Modules, ","), "PatchInlineSVC") {
		t.Fatalf("expected explicit --patch-svc=false to disable PatchInlineSVC, got modules=%v", sc.Modules)
	}
}

func TestREStatusReadsSettingsAndRERunExecutes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	capDir := filepath.Join(home, ".cap")
	binDir := filepath.Join(home, "bin")
	rootfsDir := filepath.Join(home, "rootfs")
	for _, d := range []string{capDir, binDir, rootfsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	writeStub := func(name, body string) string {
		p := filepath.Join(binDir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fakeR2 := writeStub("r2", `echo "radare2 5.9.4"`)
	fakeJava := writeStub("java", `echo 'openjdk version "17.0.7"' >&2`)
	_ = writeStub("javac", `echo 'javac 17.0.7'`)
	fakeMvn := writeStub("mvn", `echo "Apache Maven 3.9.6"`)
	pyQiling := writeStub("py-qiling", `
if [ "$1" = "-c" ]; then
  echo "PY=3.12.5"
  echo "QILING=1.4.6"
  echo "ANGR="
  exit 0
fi
echo "rootfs=$CAP_RE_ROOTFS"
echo '[CAP_RE] {"kind":"smoke","engine":"qiling","ok":true}'
`)
	pyAngr := writeStub("py-angr", `
if [ "$1" = "-c" ]; then
  echo "PY=3.10.4"
  echo "QILING="
  echo "ANGR=9.2.144"
  exit 0
fi
echo '[CAP_RE] {"kind":"solution","solution_utf8":"CAP!"}'
`)

	settingsPayload, _ := json.Marshal(map[string]string{
		"re_r2_path":            fakeR2,
		"re_java_path":          fakeJava,
		"re_mvn_path":           fakeMvn,
		"re_qiling_python_path": pyQiling,
		"re_angr_python_path":   pyAngr,
		"re_qiling_rootfs":      rootfsDir,
	})
	if err := os.WriteFile(filepath.Join(capDir, "settings.json"), settingsPayload, 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. cap re status --json loads saved ~/.cap/settings.json
	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"re", "status", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap re status --json failed: %v", err)
	}
	var tc struct {
		R2Ready      bool   `json:"r2_ready"`
		QilingReady  bool   `json:"qiling_ready"`
		AngrReady    bool   `json:"angr_ready"`
		QilingRootFS string `json:"qiling_rootfs"`
		Qiling       struct {
			Path string `json:"path"`
		} `json:"qiling"`
		Angr struct {
			Path string `json:"path"`
		} `json:"angr"`
	}
	if err := json.Unmarshal(out.Bytes(), &tc); err != nil {
		t.Fatalf("decode cap re status JSON: %v\n%s", err, out.String())
	}
	if !tc.R2Ready || !tc.QilingReady || !tc.AngrReady || tc.Qiling.Path != pyQiling || tc.Angr.Path != pyAngr || tc.QilingRootFS != rootfsDir {
		t.Fatalf("cap re status did not apply saved settings: %+v", tc)
	}

	// 2. cap re status plain text prints javac, qiling_rootfs, and separate Python paths
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"re", "status"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap re status plain failed: %v", err)
	}
	plain := out.String()
	for _, want := range []string{"javac:", "qiling_rootfs:", "qiling_python:", "angr_python:", pyQiling, pyAngr} {
		if !strings.Contains(plain, want) {
			t.Errorf("cap re status plain output missing %q:\n%s", want, plain)
		}
	}

	// 3. cap re run --engine angr --file <script> --json
	angrScript := filepath.Join(home, "solve.py")
	if err := os.WriteFile(angrScript, []byte("print('solve')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"re", "run", "--engine", "angr", "--file", angrScript, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap re run angr --json failed: %v", err)
	}
	var runState struct {
		Status  string `json:"status"`
		Results []struct {
			Kind    string         `json:"kind"`
			Payload map[string]any `json:"payload"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out.Bytes(), &runState); err != nil {
		t.Fatalf("decode cap re run JSON: %v\n%s", err, out.String())
	}
	if runState.Status != "done" || len(runState.Results) != 1 || runState.Results[0].Payload["solution_utf8"] != "CAP!" {
		t.Fatalf("unexpected cap re run angr state: %+v", runState)
	}

	// 4. cap re run --engine qiling --file <script> (streaming text output)
	qScript := filepath.Join(home, "emu.py")
	if err := os.WriteFile(qScript, []byte("print('emu')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	cmd = NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"re", "run", "--engine", "qiling", "--file", qScript, "--timeout", "10"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cap re run qiling failed: %v", err)
	}
	if !strings.Contains(out.String(), "rootfs="+rootfsDir) || !strings.Contains(out.String(), "Structured [CAP_RE] Results (1):") {
		t.Fatalf("unexpected cap re run qiling output:\n%s", out.String())
	}
}
