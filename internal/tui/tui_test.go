package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/types"
)

func sampleFlows() []*types.Flow {
	now := time.Date(2026, 11, 22, 14, 30, 0, 0, time.UTC)
	return []*types.Flow{
		{
			ID:           "f3",
			Timestamp:    now,
			Method:       "POST",
			URL:          "https://api.example.com/v1/订单/checkout?ref=1",
			Host:         "api.example.com",
			Path:         "/v1/订单/checkout",
			ReqHeaders:   map[string]string{"Content-Type": "application/json", "Authorization": "Bearer secret"},
			ReqBody:      []byte(`{"item":"测试商品","qty":2,"active":true,"coupon":null}`),
			ReqBodyType:  "application/json",
			Status:       500,
			RespHeaders:  map[string]string{"Content-Type": "application/json", "X-Request-Id": "req-500"},
			RespBody:     []byte(`{"error":"internal_failure","code":500,"retryable":false}`),
			RespBodyType: "application/json",
			LatencyMs:    1240,
			Tags:         []string{"checkout", "critical"},
			SignParams:   []string{"X-Sig", "ts"},
			SourceRef: &types.SourceRef{
				File:      "CheckoutClient.java",
				Class:     "com.example.CheckoutClient",
				Method:    "submitOrder",
				Line:      88,
				Algorithm: "HMAC-SHA256",
			},
		},
		{
			ID:           "f2",
			Timestamp:    now.Add(-5 * time.Second),
			Method:       "GET",
			URL:          "https://cdn.example.com/assets/logo.bin",
			Host:         "cdn.example.com",
			Path:         "/assets/logo.bin",
			ReqHeaders:   map[string]string{"Accept": "*/*"},
			Status:       200,
			RespHeaders:  map[string]string{"Content-Type": "application/octet-stream"},
			RespBody:     []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0xff, 0xfe},
			RespBodyType: "application/octet-stream",
			LatencyMs:    42,
			Tags:         []string{"asset"},
		},
		{
			ID:           "f1",
			Timestamp:    now.Add(-10 * time.Second),
			Method:       "DELETE",
			URL:          "https://auth.example.com/session\x1b[31mINJECT",
			Host:         "auth.example.com",
			Path:         "/session\x1b[31mINJECT",
			ReqHeaders:   map[string]string{"User-Agent": "cap-test/1.0"},
			Status:       403,
			RespHeaders:  map[string]string{"Content-Type": "text/plain"},
			RespBody:     []byte("forbidden\r\nline2"),
			RespBodyType: "text/plain",
			LatencyMs:    480,
			Tags:         []string{"auth"},
		},
	}
}

func TestUnicodeWidthAndTruncation(t *testing.T) {
	if got := DisplayWidth("hello"); got != 5 {
		t.Fatalf("DisplayWidth(hello) = %d, want 5", got)
	}
	// CJK ideographs occupy 2 terminal cells each.
	if got := DisplayWidth("测试商品"); got != 8 {
		t.Fatalf("DisplayWidth(测试商品) = %d, want 8", got)
	}
	// ANSI sequences must contribute 0 visual width.
	styled := "\x1b[1m\x1b[38;2;56;189;248mGET\x1b[0m"
	if got := DisplayWidth(styled); got != 3 {
		t.Fatalf("DisplayWidth(styled GET) = %d, want 3", got)
	}

	// Truncating wide characters must never exceed maxWidth.
	trunc := Truncate("测试商品名称", 7)
	if w := DisplayWidth(trunc); w > 7 {
		t.Fatalf("Truncate wide text produced width %d > 7 (%q)", w, trunc)
	}
	if !strings.HasSuffix(trunc, "…") {
		t.Fatalf("expected ellipsis on truncated string, got %q", trunc)
	}

	// SanitizeInline must neutralize raw ANSI escape injections and newlines.
	clean := SanitizeInline("ok\x1b[31mRED\nNEXT\tTAB")
	if strings.Contains(clean, "\x1b") || strings.Contains(clean, "\n") || strings.Contains(clean, "\t") {
		t.Fatalf("SanitizeInline failed to strip unsafe characters: %q", clean)
	}
	if clean != "okRED NEXT TAB" {
		t.Fatalf("SanitizeInline = %q, want %q", clean, "okRED NEXT TAB")
	}

	// ClampANSI preserves reset when clamping mid-sequence.
	clamped := ClampANSI("\x1b[32mabcdefghij\x1b[0m", 5)
	if DisplayWidth(clamped) != 5 {
		t.Fatalf("ClampANSI width = %d, want 5", DisplayWidth(clamped))
	}
	if !strings.HasSuffix(clamped, ansiReset) {
		t.Fatalf("ClampANSI missing trailing reset: %q", clamped)
	}
}

func TestJSONHighlightingAndBinaryHexDump(t *testing.T) {
	th := NewTheme(ThemeDark, false, true)
	raw := []byte(`{"user":"alice:1","count":42,"ok":true,"empty":null}`)

	lines, ok := HighlightJSON(raw, th)
	if !ok {
		t.Fatal("HighlightJSON failed on valid JSON")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "\x1b[") {
		t.Fatal("expected ANSI color codes in highlighted JSON")
	}
	plain := StripANSI(joined)
	if !strings.Contains(plain, `"user": "alice:1"`) || !strings.Contains(plain, `"count": 42`) {
		t.Fatalf("unexpected pretty JSON content:\n%s", plain)
	}

	// NoColor mode produces zero ANSI escapes.
	thNoColor := NewTheme(ThemeDark, true, false)
	ncLines, ok := HighlightJSON(raw, thNoColor)
	if !ok {
		t.Fatal("HighlightJSON NoColor failed")
	}
	if strings.Contains(strings.Join(ncLines, "\n"), "\x1b") {
		t.Fatal("expected zero ANSI escapes in NoColor mode")
	}

	// Invalid JSON returns ok=false.
	if _, ok := HighlightJSON([]byte("not json"), th); ok {
		t.Fatal("expected ok=false for non-JSON input")
	}

	// Binary detection and hex dump.
	bin := []byte{0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02, 0xff}
	if !IsBinary(bin) {
		t.Fatal("expected IsBinary=true for PNG/null bytes")
	}
	if IsBinary([]byte("hello world\n")) {
		t.Fatal("expected IsBinary=false for UTF-8 text")
	}
	bodyLines := FormatBodyLines(bin, "image/png", thNoColor)
	joinedBin := strings.Join(bodyLines, "\n")
	if !strings.Contains(joinedBin, "00000000") || !strings.Contains(joinedBin, "89 50 4e 47") {
		t.Fatalf("expected hex dump lines, got:\n%s", joinedBin)
	}
}

func TestFilterQueryMatching(t *testing.T) {
	flows := sampleFlows()

	cases := []struct {
		name       string
		query      string
		method     string
		errorsOnly bool
		wantIDs    []string
	}{
		{"empty", "", "", false, []string{"f3", "f2", "f1"}},
		{"method predicate", "m:POST", "", false, []string{"f3"}},
		{"status 5xx", "s:5xx", "", false, []string{"f3"}},
		{"status >=400", "s:>=400", "", false, []string{"f3", "f1"}},
		{"host predicate", "h:cdn.example", "", false, []string{"f2"}},
		{"tag predicate", "t:auth", "", false, []string{"f1"}},
		{"negation", "!m:GET !m:DELETE", "", false, []string{"f3"}},
		{"body substring", "internal_failure", "", false, []string{"f3"}},
		{"quick errors only", "", "", true, []string{"f3", "f1"}},
		{"quick method", "", "GET", false, []string{"f2"}},
		{"combined AND", "h:example.com s:4xx", "", false, []string{"f1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fq := ParseFilter(tc.query)
			var got []string
			for _, f := range flows {
				if fq.Matches(f, tc.method, tc.errorsOnly) {
					got = append(got, f.ID)
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.wantIDs, ",") {
				t.Fatalf("got IDs %v, want %v", got, tc.wantIDs)
			}
		})
	}
}

func TestParseKey(t *testing.T) {
	cases := []struct {
		in   []byte
		kind KeyKind
		r    rune
		n    int
	}{
		{[]byte{'j'}, KeyRune, 'j', 1},
		{[]byte("测"), KeyRune, '测', 3},
		{[]byte{0x03}, KeyCtrlC, 0, 1},
		{[]byte{0x04}, KeyCtrlD, 0, 1},
		{[]byte{0x15}, KeyCtrlU, 0, 1},
		{[]byte{'\t'}, KeyTab, 0, 1},
		{[]byte("\x1b[Z"), KeyShiftTab, 0, 3},
		{[]byte("\x1b[A"), KeyUp, 0, 3},
		{[]byte("\x1b[B"), KeyDown, 0, 3},
		{[]byte("\x1bOA"), KeyUp, 0, 3},
		{[]byte("\x1b[5~"), KeyPgUp, 0, 4},
		{[]byte("\x1b[6~"), KeyPgDn, 0, 4},
		{[]byte("\x1b"), KeyEsc, 0, 1},
	}

	for _, tc := range cases {
		ev, n := ParseKey(tc.in)
		if ev.Kind != tc.kind || ev.Rune != tc.r || n != tc.n {
			t.Errorf("ParseKey(%q) = (%+v, %d), want (kind=%v rune=%q n=%d)", tc.in, ev, n, tc.kind, tc.r, tc.n)
		}
	}
}

func TestStateReducerInteractions(t *testing.T) {
	s := NewState(StateOptions{
		Width:      130,
		Height:     36,
		Live:       true,
		ListenAddr: "127.0.0.1:8080",
		Flows:      sampleFlows(),
	})

	if s.SelectedFlow().ID != "f3" {
		t.Fatalf("initial selected = %s, want f3", s.SelectedFlow().ID)
	}
	if s.ErrorCount != 2 {
		t.Fatalf("ErrorCount = %d, want 2", s.ErrorCount)
	}

	// Move down disables AutoFollow and selects f2.
	s.Update(KeyEvent{Kind: KeyRune, Rune: 'j'})
	if s.SelectedFlow().ID != "f2" {
		t.Fatalf("after j selected = %s, want f2", s.SelectedFlow().ID)
	}
	if s.AutoFollow {
		t.Fatal("expected AutoFollow to turn off after scrolling down")
	}

	// Live flow arrives while AutoFollow is off: selection stays pinned on f2!
	liveFlow := &types.Flow{ID: "f4", Method: "GET", Host: "live.dev", Path: "/ping", Status: 200, LatencyMs: 12}
	s.AddFlow(liveFlow)
	if s.SelectedFlow().ID != "f2" {
		t.Fatalf("expected selection to stay on f2 while AutoFollow=false, got %s", s.SelectedFlow().ID)
	}

	// Toggle AutoFollow back ON snaps to newest flow (f4).
	s.Update(KeyEvent{Kind: KeyRune, Rune: 'f'})
	if !s.AutoFollow || s.SelectedFlow().ID != "f4" {
		t.Fatalf("after f: AutoFollow=%v selected=%s, want true & f4", s.AutoFollow, s.SelectedFlow().ID)
	}

	// Pause live capture drops incoming flows cleanly and tracks count.
	s.Update(KeyEvent{Kind: KeyRune, Rune: 'p'})
	if !s.Paused {
		t.Fatal("expected Paused=true")
	}
	s.AddFlow(&types.Flow{ID: "f5", Method: "GET", Status: 200})
	if s.PausedDropped != 1 || len(s.Flows) != 4 {
		t.Fatalf("expected paused drop count=1 len=4, got drop=%d len=%d", s.PausedDropped, len(s.Flows))
	}
	s.Update(KeyEvent{Kind: KeyRune, Rune: 'p'})
	if s.Paused || s.PausedDropped != 0 {
		t.Fatal("expected resume to reset Paused and PausedDropped")
	}

	// Filter input mode: live filtering + Esc restores backup.
	s.Update(KeyEvent{Kind: KeyRune, Rune: '/'})
	if s.Mode != ModeFilterInput {
		t.Fatal("expected ModeFilterInput")
	}
	for _, r := range "s:5xx" {
		s.Update(KeyEvent{Kind: KeyRune, Rune: r})
	}
	if len(s.Filtered) != 1 || s.Filtered[0].ID != "f3" {
		t.Fatalf("live filter s:5xx gave %d matches", len(s.Filtered))
	}
	// Confirm with Enter.
	s.Update(KeyEvent{Kind: KeyEnter})
	if s.Mode != ModeNormal || s.FilterApplied != "s:5xx" {
		t.Fatalf("after Enter: mode=%v filter=%q", s.Mode, s.FilterApplied)
	}
	// Clear with 'c'.
	s.Update(KeyEvent{Kind: KeyRune, Rune: 'c'})
	if len(s.Filtered) != 4 {
		t.Fatalf("after clear: len(Filtered) = %d, want 4", len(s.Filtered))
	}

	// Tabs, codegen language cycling, theme toggle, zoom, help, replay, copy, quit.
	s.Update(KeyEvent{Kind: KeyRune, Rune: '6'})
	if s.Tab != TabExport || s.ExportLang() != "curl" {
		t.Fatalf("expected TabExport curl, got tab=%v lang=%s", s.Tab, s.ExportLang())
	}
	s.Update(KeyEvent{Kind: KeyRune, Rune: 'l'})
	if s.ExportLang() != "python" {
		t.Fatalf("expected python after 'l', got %s", s.ExportLang())
	}

	cmd := s.Update(KeyEvent{Kind: KeyRune, Rune: 'y'})
	if cmd.Type != CmdCopySnippet || cmd.Lang != "python" {
		t.Fatalf("expected CmdCopySnippet(python), got %+v", cmd)
	}

	cmd = s.Update(KeyEvent{Kind: KeyRune, Rune: 'r'})
	if cmd.Type != CmdReplay || !s.Replaying {
		t.Fatalf("expected CmdReplay with Replaying=true, got %+v", cmd)
	}

	s.Update(KeyEvent{Kind: KeyRune, Rune: 't'})
	if s.ThemeName != ThemeLight {
		t.Fatalf("expected ThemeLight after 't', got %s", s.ThemeName)
	}

	// 'L' live-toggles EN <-> ZH with localized toast.
	origLang := i18n.Lang()
	defer i18n.SetLang(string(origLang))
	s.Locale = i18n.EN
	s.Update(KeyEvent{Kind: KeyRune, Rune: 'L'})
	if s.Locale != i18n.ZH {
		t.Fatalf("expected Locale ZH after 'L', got %s", s.Locale)
	}
	if !strings.Contains(s.Toast, "简体中文") {
		t.Fatalf("expected Chinese toast after switching to ZH, got %q", s.Toast)
	}
	s.Update(KeyEvent{Kind: KeyRune, Rune: 'L'})
	if s.Locale != i18n.EN {
		t.Fatalf("expected Locale EN after second 'L', got %s", s.Locale)
	}
	if !strings.Contains(s.Toast, "English") {
		t.Fatalf("expected English toast after switching to EN, got %q", s.Toast)
	}

	s.Update(KeyEvent{Kind: KeyRune, Rune: 'z'})
	if !s.Zoom {
		t.Fatal("expected Zoom=true")
	}

	s.Update(KeyEvent{Kind: KeyRune, Rune: '?'})
	if s.Mode != ModeHelp {
		t.Fatal("expected ModeHelp")
	}
	s.Update(KeyEvent{Kind: KeyEsc})
	if s.Mode != ModeNormal {
		t.Fatal("expected Esc to close ModeHelp")
	}

	cmd = s.Update(KeyEvent{Kind: KeyRune, Rune: 'q'})
	if cmd.Type != CmdQuit {
		t.Fatalf("expected CmdQuit, got %+v", cmd)
	}
}

func TestRenderScreenDimensionsAndModes(t *testing.T) {
	now := time.Now()
	layouts := []struct {
		name      string
		w, h      int
		zoom      bool
		focus     FocusPane
		mode      Mode
		noColor   bool
		light     bool
		emptyFlow bool
	}{
		{"wide-dark", 140, 38, false, PaneList, ModeNormal, false, false, false},
		{"wide-light", 130, 34, false, PaneDetail, ModeNormal, false, true, false},
		{"narrow-stacked", 84, 28, false, PaneList, ModeNormal, false, false, false},
		{"zoom-list", 120, 30, true, PaneList, ModeNormal, false, false, false},
		{"zoom-detail", 120, 30, true, PaneDetail, ModeNormal, false, false, false},
		{"help-modal", 120, 34, false, PaneList, ModeHelp, false, false, false},
		{"filter-bar", 100, 30, false, PaneList, ModeFilterInput, false, false, false},
		{"nocolor-mode", 120, 30, false, PaneList, ModeNormal, true, false, false},
		{"empty-live", 110, 26, false, PaneList, ModeNormal, false, false, true},
		{"tiny-terminal", 30, 8, false, PaneList, ModeNormal, false, false, false},
	}

	for _, tc := range layouts {
		for _, loc := range []i18n.Locale{i18n.EN, i18n.ZH} {
			t.Run(tc.name+"/"+string(loc), func(t *testing.T) {
				var flows []*types.Flow
				if !tc.emptyFlow {
					flows = sampleFlows()
				}
				s := NewState(StateOptions{
					Width:      tc.w,
					Height:     tc.h,
					Version:    "1.2.3",
					Locale:     loc,
					Live:       true,
					ListenAddr: "127.0.0.1:8080",
					DBPath:     "/tmp/flows.db",
					LightTheme: tc.light,
					NoColor:    tc.noColor,
					TrueColor:  true,
					Flows:      flows,
				})
				s.Zoom = tc.zoom
				s.Focus = tc.focus
				s.Mode = tc.mode
				if tc.mode == ModeFilterInput {
					s.FilterInput = "m:POST"
				}

				for tab := DetailTab(0); tab < tabCount; tab++ {
					s.Tab = tab
					lines := RenderScreen(s, now)
					if len(lines) != tc.h {
						t.Fatalf("tab %v: got %d lines, want %d", tab, len(lines), tc.h)
					}
					for rowIdx, line := range lines {
						if tc.noColor && strings.Contains(line, "\x1b") {
							t.Fatalf("tab %v row %d: unexpected ANSI escape in NoColor mode", tab, rowIdx)
						}
						if dw := DisplayWidth(line); dw != tc.w {
							t.Fatalf("tab %v row %d: DisplayWidth=%d, want %d\nplain=%q", tab, rowIdx, dw, tc.w, StripANSI(line))
						}
					}
					if loc == i18n.ZH && tc.name == "wide-dark" && tab == TabOverview {
						joined := StripANSI(strings.Join(lines, "\n"))
						for _, want := range []string{"实时", "流量列表", "详情检视", "中文"} {
							if !strings.Contains(joined, want) {
								t.Errorf("ZH render missing expected text %q", want)
							}
						}
					}
					if tc.name == "help-modal" && tab == TabOverview {
						joined := StripANSI(strings.Join(lines, "\n"))
						if !strings.Contains(joined, "© 2026 0xaf (@overkazaf)") || !strings.Contains(joined, "github.com/overkazaf/cap") {
							t.Errorf("%s help modal missing copyright footer", loc)
						}
						if loc == i18n.ZH && (!strings.Contains(joined, "CAP 快捷键指南") || !strings.Contains(joined, "切换界面语言")) {
							t.Errorf("ZH help modal missing localized strings")
						}
					}
				}
			})
		}
	}
}

func TestDoubleBufferedRendererDiffing(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf)
	s := NewState(StateOptions{
		Width:   110,
		Height:  28,
		Flows:   sampleFlows(),
		NoColor: true,
	})
	now := time.Now()

	// First draw writes full synchronized frame.
	if err := r.Draw(s, now); err != nil {
		t.Fatalf("first Draw error: %v", err)
	}
	firstOut := buf.String()
	if !strings.HasPrefix(firstOut, "\x1b[?2026h") || !strings.HasSuffix(firstOut, "\x1b[?2026l") {
		t.Fatal("expected synchronized output wrapper")
	}

	// Second identical draw should emit zero bytes!
	buf.Reset()
	if err := r.Draw(s, now); err != nil {
		t.Fatalf("second Draw error: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected 0 bytes for unchanged frame, got %d", buf.Len())
	}

	// Changing toast should only repaint the status line (much smaller than full frame).
	s.SetToast(ToastSuccess, "Copied cURL", 3*time.Second)
	buf.Reset()
	if err := r.Draw(s, now); err != nil {
		t.Fatalf("third Draw error: %v", err)
	}
	if buf.Len() == 0 || buf.Len() >= len(firstOut) {
		t.Fatalf("expected compact diff repaint, got %d bytes vs full %d", buf.Len(), len(firstOut))
	}
	if !strings.Contains(buf.String(), "Copied cURL") {
		t.Fatalf("expected toast text in diff output, got %q", buf.String())
	}
}
