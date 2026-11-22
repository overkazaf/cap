package tui

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/types"
)

const (
	minTerminalWidth  = 40
	minTerminalHeight = 10
	wideLayoutWidth   = 110
)

// Renderer performs double-buffered, flicker-free ANSI rendering by diffing
// lines against the previous frame and flushing updates in a single write
// wrapped with Synchronized Output (DEC private mode 2026).
type Renderer struct {
	out       io.Writer
	prevLines []string
	prevW     int
	prevH     int
}

// NewRenderer creates a Renderer targeting out.
func NewRenderer(out io.Writer) *Renderer {
	return &Renderer{out: out}
}

// Invalidate forces the next Draw call to repaint every row from scratch.
func (r *Renderer) Invalidate() {
	r.prevLines = nil
}

// Draw renders State to the terminal, writing only modified rows when the
// terminal dimensions haven't changed.
func (r *Renderer) Draw(s *State, now time.Time) error {
	lines := RenderScreen(s, now)
	fullRepaint := r.prevLines == nil || r.prevW != s.Width || r.prevH != s.Height || len(r.prevLines) != len(lines)

	var buf bytes.Buffer
	buf.Grow(s.Width * s.Height * 2)
	// Synchronized Output start (supported by Ghostty, iTerm2, Kitty, WezTerm, VSCode; safely ignored elsewhere).
	buf.WriteString("\x1b[?2026h")

	if fullRepaint {
		buf.WriteString("\x1b[H")
		for i, line := range lines {
			fmt.Fprintf(&buf, "\x1b[%d;1H%s\x1b[K", i+1, line)
		}
	} else {
		for i, line := range lines {
			if line != r.prevLines[i] {
				fmt.Fprintf(&buf, "\x1b[%d;1H%s\x1b[K", i+1, line)
			}
		}
	}

	buf.WriteString("\x1b[?2026l")

	r.prevLines = lines
	r.prevW = s.Width
	r.prevH = s.Height

	if buf.Len() == len("\x1b[?2026h\x1b[?2026l") {
		return nil
	}
	_, err := r.out.Write(buf.Bytes())
	return err
}

// RenderScreen computes the exact s.Height lines of width s.Width for the
// current State. It is completely side-effect-free (except updating cached
// viewport row counts) and can be directly asserted in unit tests.
func RenderScreen(s *State, now time.Time) []string {
	th := s.Theme()
	w, h := s.Width, s.Height
	if w < 1 {
		w = 80
	}
	if h < 1 {
		h = 24
	}

	if w < minTerminalWidth || h < minTerminalHeight {
		return renderTooSmall(s, w, h, th)
	}

	showFilterBar := s.Mode == ModeFilterInput || strings.TrimSpace(s.FilterApplied) != ""
	headerLine := renderHeader(s, th, w)
	statusLine := renderStatusBar(s, th, w, now)

	topRows := 1
	var filterLine string
	if showFilterBar {
		filterLine = renderFilterBar(s, th, w)
		topRows = 2
	}

	bodyHeight := h - topRows - 1
	if bodyHeight < 4 {
		bodyHeight = 4
	}

	var bodyLines []string
	if s.Zoom {
		if s.Focus == PaneList {
			bodyLines = renderFlowListPane(s, th, w, bodyHeight)
		} else {
			bodyLines = renderInspectorPane(s, th, w, bodyHeight)
		}
	} else if w >= wideLayoutWidth {
		leftW := (w * 47) / 100
		if leftW < 44 {
			leftW = 44
		}
		rightW := w - leftW
		leftLines := renderFlowListPane(s, th, leftW, bodyHeight)
		rightLines := renderInspectorPane(s, th, rightW, bodyHeight)
		bodyLines = make([]string, bodyHeight)
		for i := 0; i < bodyHeight; i++ {
			bodyLines[i] = leftLines[i] + rightLines[i]
		}
	} else {
		topH := (bodyHeight * 44) / 100
		if topH < 5 {
			topH = 5
		}
		botH := bodyHeight - topH
		if botH < 5 {
			botH = 5
			topH = bodyHeight - botH
		}
		topLines := renderFlowListPane(s, th, w, topH)
		botLines := renderInspectorPane(s, th, w, botH)
		bodyLines = append(topLines, botLines...)
	}

	screen := make([]string, 0, h)
	screen = append(screen, headerLine)
	if showFilterBar {
		screen = append(screen, filterLine)
	}
	screen = append(screen, bodyLines...)
	screen = append(screen, statusLine)

	// Guarantee exact height.
	for len(screen) < h {
		screen = append(screen, strings.Repeat(" ", w))
	}
	if len(screen) > h {
		screen = screen[:h]
	}

	if s.Mode == ModeHelp {
		screen = overlayHelpModal(s, screen, w, h, th)
	}

	return screen
}

func renderTooSmall(s *State, w, h int, th Theme) []string {
	lines := make([]string, h)
	msg := s.tr("tui.too_small", w, h, minTerminalWidth, minTerminalHeight)
	mid := h / 2
	for i := 0; i < h; i++ {
		if i == mid {
			lines[i] = PadRight(th.Bold(th.Warn, Truncate(msg, w)), w)
		} else {
			lines[i] = strings.Repeat(" ", w)
		}
	}
	return lines
}

func renderHeader(s *State, th Theme, width int) string {
	bg := th.BgCode(th.HeaderBg)

	var left strings.Builder
	left.WriteString(th.Pill(th.BrandFg, th.BrandBg, true, " CAP "))
	if s.Version != "" && width >= 96 {
		left.WriteString(" ")
		left.WriteString(th.Fg(th.FgMuted, s.Version))
	}
	left.WriteString("  ")

	if s.Live {
		if s.Paused {
			left.WriteString(th.Bold(th.Paused, "⏸ "+s.tr("tui.mode.paused")))
		} else {
			left.WriteString(th.Bold(th.Live, "● "+s.tr("tui.mode.live")))
		}
		if s.ListenAddr != "" {
			left.WriteString(" ")
			left.WriteString(th.Fg(th.FgSecondary, SanitizeInline(s.ListenAddr)))
		}
	} else {
		left.WriteString(th.Bold(th.Info, "○ "+s.tr("tui.mode.store")))
	}

	left.WriteString("  ")
	if s.HasActiveFilter() {
		left.WriteString(th.Bold(th.FgPrimary, fmt.Sprintf("%d", len(s.Filtered))))
		left.WriteString(th.Fg(th.FgMuted, fmt.Sprintf("/%d %s", len(s.Flows), s.tr("tui.header.flows"))))
	} else {
		left.WriteString(th.Bold(th.FgPrimary, fmt.Sprintf("%d", len(s.Flows))))
		left.WriteString(th.Fg(th.FgMuted, " "+s.tr("tui.header.flows")))
	}

	if s.ErrorCount > 0 {
		left.WriteString("  ")
		left.WriteString(th.Bold(th.Danger, "▲ "+s.tr("tui.header.err", s.ErrorCount)))
	}

	if s.MethodFilter != "" {
		left.WriteString("  ")
		left.WriteString(th.Pill(th.MethodColor(s.MethodFilter), th.ChipBg, true, " m:"+s.MethodFilter+" "))
	}
	if s.ErrorsOnly {
		left.WriteString("  ")
		left.WriteString(th.Pill(th.Danger, th.ChipBg, true, " 4xx/5xx "))
	}

	var right strings.Builder
	if s.DBPath != "" && width >= 88 {
		right.WriteString(th.Fg(th.FgMuted, Truncate(filepath.Base(s.DBPath), 20)))
		right.WriteString("  ")
	}
	right.WriteString(th.Pill(th.Accent, th.ChipBg, true, " "+s.Locale.ShortLabel()+" "))
	right.WriteString(" ")
	if s.ThemeName == ThemeLight {
		right.WriteString(th.Fg(th.FgSecondary, "☀ "+s.tr("common.light")+" "))
	} else {
		right.WriteString(th.Fg(th.FgSecondary, "◐ "+s.tr("common.dark")+" "))
	}

	leftStr := left.String()
	rightStr := right.String()
	leftW := DisplayWidth(leftStr)
	rightW := DisplayWidth(rightStr)

	if leftW+rightW+2 <= width {
		gap := strings.Repeat(" ", width-leftW-rightW)
		return FillLine(leftStr+gap+rightStr, width, bg)
	}
	return FillLine(leftStr, width, bg)
}

func renderFilterBar(s *State, th Theme, width int) string {
	bg := th.BgCode(th.FilterBg)
	var b strings.Builder

	label := " / " + s.tr("tui.filter.label") + " "
	if s.Mode == ModeFilterInput {
		b.WriteString(th.Pill(th.BrandFg, th.BrandBg, true, label))
		b.WriteString(" ")
		b.WriteString(th.Fg(th.FgPrimary, SanitizeInline(s.FilterInput)))
		b.WriteString(th.Bold(th.Accent, "█"))
	} else {
		b.WriteString(th.Pill(th.Accent, th.ChipBg, true, label))
		b.WriteString(" ")
		b.WriteString(th.Fg(th.FgPrimary, SanitizeInline(s.FilterApplied)))
	}

	matchKey := "tui.filter.matches"
	if len(s.Filtered) == 1 {
		matchKey = "tui.filter.match"
	}
	right := th.Fg(th.FgMuted, s.tr(matchKey, len(s.Filtered)))
	if s.Mode == ModeFilterInput && width >= 95 {
		right = th.Fg(th.FgMuted, s.tr("tui.filter.syntax")+"   ") + right
	}
	right += " "

	leftStr := b.String()
	leftW := DisplayWidth(leftStr)
	rightW := DisplayWidth(right)
	if leftW+rightW+2 <= width {
		return FillLine(leftStr+strings.Repeat(" ", width-leftW-rightW)+right, width, bg)
	}
	return FillLine(leftStr, width, bg)
}

func renderFlowListPane(s *State, th Theme, width, height int) []string {
	focused := s.Focus == PaneList
	innerW := width - 2
	innerH := height - 2
	if innerW < 10 {
		innerW = 10
	}
	if innerH < 1 {
		innerH = 1
	}

	hasColHeader := innerH >= 2
	visibleRows := innerH
	if hasColHeader {
		visibleRows = innerH - 1
	}
	s.listVisibleRows = visibleRows
	s.ensureListVisible()

	title := s.tr("tui.pane.flows", len(s.Filtered))
	if s.HasActiveFilter() {
		title = s.tr("tui.pane.flows_filt", len(s.Filtered), len(s.Flows))
	}
	var badges []string
	if s.AutoFollow {
		badges = append(badges, th.Bold(th.Live, s.tr("tui.badge.follow")))
	}
	if s.Zoom && focused {
		badges = append(badges, th.Bold(th.Accent, s.tr("tui.badge.zoom")))
	}
	titleExtra := ""
	if len(badges) > 0 {
		titleExtra = " " + strings.Join(badges, " ")
	}

	borderColor := th.BorderMuted
	if focused {
		borderColor = th.BorderFocus
	}

	lines := make([]string, 0, height)
	lines = append(lines, renderBoxTop(width, title, titleExtra, focused, borderColor, th))

	if hasColHeader {
		hdr := renderFlowHeaderRow(s, innerW, th)
		lines = append(lines, th.Fg(borderColor, "│")+PadRight(hdr, innerW)+th.Fg(borderColor, "│"))
	}

	if len(s.Filtered) == 0 {
		emptyRows := renderEmptyFlowList(s, th, innerW, visibleRows)
		for _, row := range emptyRows {
			lines = append(lines, th.Fg(borderColor, "│")+PadRight(row, innerW)+th.Fg(borderColor, "│"))
		}
	} else {
		needScroll := len(s.Filtered) > visibleRows
		rowW := innerW
		if needScroll {
			rowW = innerW - 1
		}
		for i := 0; i < visibleRows; i++ {
			idx := s.ListOffset + i
			var rowContent string
			if idx < len(s.Filtered) {
				f := s.Filtered[idx]
				selected := idx == s.SelectedIdx
				rowContent = renderFlowRow(f, selected, focused, rowW, th)
			} else {
				rowContent = strings.Repeat(" ", rowW)
			}
			scrollChar := ""
			if needScroll {
				scrollChar = renderScrollCell(i, visibleRows, s.ListOffset, len(s.Filtered), th)
			}
			lines = append(lines, th.Fg(borderColor, "│")+rowContent+scrollChar+th.Fg(borderColor, "│"))
		}
	}

	lines = append(lines, renderBoxBottom(width, borderColor, th))
	return lines
}

type colLayout struct {
	idW     int
	methodW int
	statusW int
	hostW   int
	pathW   int
	sizeW   int
	latW    int
	showID  bool
	showSz  bool
}

func computeFlowCols(w int) colLayout {
	avail := w - 2
	if avail < 20 {
		avail = 20
	}
	c := colLayout{
		idW:     5,
		methodW: 6,
		statusW: 4,
		sizeW:   7,
		latW:    6,
		showID:  w >= 54,
		showSz:  w >= 66,
	}

	fixed := c.methodW + 1 + c.statusW + 1 + c.latW + 1
	if c.showID {
		fixed += c.idW + 1
	}
	if c.showSz {
		fixed += c.sizeW + 1
	}

	rem := avail - fixed
	if rem < 10 {
		rem = 10
	}
	c.hostW = (rem * 38) / 100
	if c.hostW < 10 {
		c.hostW = 10
	}
	if c.hostW > 28 {
		c.hostW = 28
	}
	c.pathW = rem - c.hostW - 1
	if c.pathW < 6 {
		c.pathW = 6
	}
	return c
}

func renderFlowHeaderRow(s *State, width int, th Theme) string {
	c := computeFlowCols(width)
	var b strings.Builder
	b.WriteString("  ")
	if c.showID {
		b.WriteString(PadRight("#", c.idW))
		b.WriteByte(' ')
	}
	b.WriteString(PadRight(s.tr("tui.col.method"), c.methodW))
	b.WriteByte(' ')
	b.WriteString(PadRight(s.tr("tui.col.status"), c.statusW))
	b.WriteByte(' ')
	b.WriteString(PadRight(s.tr("tui.col.host"), c.hostW))
	b.WriteByte(' ')
	b.WriteString(PadRight(s.tr("tui.col.path"), c.pathW))
	b.WriteByte(' ')
	if c.showSz {
		b.WriteString(PadLeft(s.tr("tui.col.size"), c.sizeW))
		b.WriteByte(' ')
	}
	b.WriteString(PadLeft(s.tr("tui.col.time"), c.latW))
	return th.Dim(th.FgMuted, PadRight(b.String(), width))
}

func renderFlowRow(f *types.Flow, selected, paneFocused bool, width int, th Theme) string {
	c := computeFlowCols(width)
	var b strings.Builder

	if selected {
		if paneFocused {
			b.WriteString(th.Bold(th.Accent, "▸ "))
		} else {
			b.WriteString(th.Fg(th.FgMuted, "▸ "))
		}
	} else {
		b.WriteString("  ")
	}

	if c.showID {
		b.WriteString(th.Fg(th.FgMuted, PadRight(Truncate(SanitizeInline(f.ID), c.idW), c.idW)))
		b.WriteByte(' ')
	}

	method := Truncate(strings.ToUpper(SanitizeInline(f.Method)), c.methodW)
	b.WriteString(th.Bold(th.MethodColor(f.Method), PadRight(method, c.methodW)))
	b.WriteByte(' ')

	statusStr := "---"
	if f.Status > 0 {
		statusStr = fmt.Sprintf("%3d", f.Status)
	}
	b.WriteString(th.Bold(th.StatusColor(f.Status), PadRight(statusStr, c.statusW)))
	b.WriteByte(' ')

	host := Truncate(SanitizeInline(f.Host), c.hostW)
	b.WriteString(th.Fg(th.FgSecondary, PadRight(host, c.hostW)))
	b.WriteByte(' ')

	pathVal := f.Path
	if pathVal == "" {
		pathVal = "/"
	}
	path := Truncate(SanitizeInline(pathVal), c.pathW)
	if selected {
		b.WriteString(th.Bold(th.FgPrimary, PadRight(path, c.pathW)))
	} else {
		b.WriteString(th.Fg(th.FgPrimary, PadRight(path, c.pathW)))
	}
	b.WriteByte(' ')

	if c.showSz {
		sz := FormatBytes(len(f.RespBody))
		b.WriteString(th.Fg(th.FgMuted, PadLeft(Truncate(sz, c.sizeW), c.sizeW)))
		b.WriteByte(' ')
	}

	latColor := th.FgMuted
	if f.LatencyMs >= 1000 {
		latColor = th.Danger
	} else if f.LatencyMs >= 400 {
		latColor = th.Warn
	}
	b.WriteString(th.Fg(latColor, PadLeft(Truncate(FormatLatency(f.LatencyMs), c.latW), c.latW)))

	if selected {
		return FillLine(b.String(), width, th.BgCode(th.SelectedBg))
	}
	return PadRight(b.String(), width)
}

func renderEmptyFlowList(s *State, th Theme, width, rows int) []string {
	out := make([]string, rows)
	for i := range out {
		out[i] = strings.Repeat(" ", width)
	}
	if rows < 2 {
		return out
	}

	var msgs []string
	if s.HasActiveFilter() && len(s.Flows) > 0 {
		msgs = []string{
			th.Bold(th.Warn, s.tr("tui.empty.filter.title")),
			th.Fg(th.FgMuted, s.tr("tui.empty.filter.hint")),
		}
	} else if s.Live {
		addr := s.ListenAddr
		if addr == "" {
			addr = "127.0.0.1:8080"
		}
		msgs = []string{
			th.Bold(th.Live, "● "+s.tr("tui.empty.live.title")),
			th.Fg(th.FgSecondary, s.tr("tui.empty.live.proxy", addr)),
			th.Fg(th.FgMuted, s.tr("tui.empty.live.try", addr)),
		}
	} else {
		msgs = []string{
			th.Bold(th.FgSecondary, s.tr("tui.empty.store.title")),
			th.Fg(th.FgMuted, s.tr("tui.empty.store.hint")),
		}
	}

	startRow := (rows - len(msgs)) / 2
	if startRow < 0 {
		startRow = 0
	}
	for i, m := range msgs {
		r := startRow + i
		if r >= rows {
			break
		}
		mw := DisplayWidth(m)
		pad := (width - mw) / 2
		if pad < 1 {
			pad = 1
		}
		out[r] = PadRight(strings.Repeat(" ", pad)+m, width)
	}
	return out
}

func renderInspectorPane(s *State, th Theme, width, height int) []string {
	focused := s.Focus == PaneDetail
	innerW := width - 2
	innerH := height - 2
	if innerW < 10 {
		innerW = 10
	}
	if innerH < 1 {
		innerH = 1
	}

	borderColor := th.BorderMuted
	if focused {
		borderColor = th.BorderFocus
	}

	title := s.tr("tui.pane.inspector")
	if f := s.SelectedFlow(); f != nil {
		title = s.tr("tui.pane.insp_flow", SanitizeInline(f.ID))
	}
	titleExtra := ""
	if s.Zoom && focused {
		titleExtra = " " + th.Bold(th.Accent, s.tr("tui.badge.zoom"))
	}

	hasTabBar := innerH >= 2
	contentH := innerH
	if hasTabBar {
		contentH = innerH - 1
	}
	s.detailVisibleRows = contentH

	contentW := innerW - 2
	if contentW < 8 {
		contentW = 8
	}

	allLines := buildInspectorLines(s, th, contentW)
	s.DetailTotalLines = len(allLines)
	s.clampDetailScroll()

	lines := make([]string, 0, height)
	lines = append(lines, renderBoxTop(width, title, titleExtra, focused, borderColor, th))

	if hasTabBar {
		tabBar := renderTabBar(s.Tab, s.Locale, innerW, th)
		lines = append(lines, th.Fg(borderColor, "│")+PadRight(tabBar, innerW)+th.Fg(borderColor, "│"))
	}

	needScroll := len(allLines) > contentH
	for i := 0; i < contentH; i++ {
		idx := s.DetailScroll + i
		bodyLine := ""
		if idx < len(allLines) {
			bodyLine = " " + allLines[idx]
		}
		scrollCell := " "
		if needScroll {
			scrollCell = renderScrollCell(i, contentH, s.DetailScroll, len(allLines), th)
		}
		lines = append(lines, th.Fg(borderColor, "│")+PadRight(bodyLine, innerW-1)+scrollCell+th.Fg(borderColor, "│"))
	}

	lines = append(lines, renderBoxBottom(width, borderColor, th))
	return lines
}

func renderTabBar(active DetailTab, loc i18n.Locale, width int, th Theme) string {
	var b strings.Builder
	b.WriteByte(' ')
	for t := DetailTab(0); t < tabCount; t++ {
		label := fmt.Sprintf(" %d %s ", int(t)+1, t.Title(loc))
		if width < 64 {
			label = " " + t.ShortTitle(loc) + " "
		}
		if t == active {
			b.WriteString(th.Pill(th.FgPrimary, th.TabActiveBg, true, label))
		} else {
			b.WriteString(th.Fg(th.FgMuted, label))
		}
	}
	return FillLine(b.String(), width, th.BgCode(th.HeaderBg))
}

func buildInspectorLines(s *State, th Theme, width int) []string {
	f := s.SelectedFlow()
	if f == nil {
		return []string{
			"",
			th.Fg(th.FgMuted, s.tr("tui.empty.select")),
		}
	}

	switch s.Tab {
	case TabOverview:
		return buildOverviewTab(s, f, th, width)
	case TabRequest:
		return buildRequestTab(s, f, th, width)
	case TabResponse:
		return buildResponseTab(s, f, th, width)
	case TabHeaders:
		return buildHeadersTab(s, f, th, width)
	case TabTiming:
		return buildTimingTab(s, f, th, width)
	case TabExport:
		return buildExportTab(s, f, s.ExportLang(), th, width)
	default:
		return buildOverviewTab(s, f, th, width)
	}
}

func buildOverviewTab(s *State, f *types.Flow, th Theme, width int) []string {
	var lines []string

	methodBadge := th.Pill(th.FgInverse, th.MethodColor(f.Method), true, " "+SanitizeInline(f.Method)+" ")
	statusBadge := th.Pill(th.FgInverse, th.StatusColor(f.Status), true, fmt.Sprintf(" %d ", f.Status))
	summary := fmt.Sprintf("%s %s  %s  %s",
		methodBadge,
		statusBadge,
		th.Bold(th.FgPrimary, FormatLatency(f.LatencyMs)),
		th.Fg(th.FgSecondary, fmt.Sprintf("↑%s  ↓%s", FormatBytes(len(f.ReqBody)), FormatBytes(len(f.RespBody)))),
	)
	lines = append(lines, summary)
	lines = append(lines, "")

	lines = append(lines, th.Bold(th.Accent, s.tr("tui.insp.endpoint")))
	for _, uline := range WrapText(f.URL, width) {
		lines = append(lines, th.Fg(th.FgPrimary, uline))
	}
	lines = append(lines, "")

	lines = append(lines, th.Bold(th.Accent, s.tr("tui.insp.summary")))
	kv := func(k, v string) {
		lines = append(lines, th.Fg(th.FgMuted, PadRight(k, 14))+th.Fg(th.FgPrimary, SanitizeInline(v)))
	}
	kv(s.tr("tui.insp.flow_id"), f.ID)
	kv(s.tr("tui.insp.host"), f.Host)
	kv(s.tr("tui.insp.path"), f.Path)
	if !f.Timestamp.IsZero() {
		kv(s.tr("tui.insp.captured"), f.Timestamp.Local().Format("2006-01-02 15:04:05.000"))
	}
	if f.ReqBodyType != "" {
		kv(s.tr("tui.insp.req_type"), f.ReqBodyType)
	}
	if f.RespBodyType != "" {
		kv(s.tr("tui.insp.resp_type"), f.RespBodyType)
	}
	if len(f.Tags) > 0 {
		kv(s.tr("tui.insp.tags"), strings.Join(f.Tags, ", "))
	}
	if len(f.SignParams) > 0 {
		kv(s.tr("tui.insp.sign_params"), strings.Join(f.SignParams, ", "))
	}
	if f.SourceRef != nil {
		loc := f.SourceRef.File
		if f.SourceRef.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.SourceRef.Line)
		}
		kv(s.tr("tui.insp.source_ref"), loc)
		if f.SourceRef.Algorithm != "" {
			kv(s.tr("tui.insp.algorithm"), f.SourceRef.Algorithm)
		}
	}

	lines = append(lines, "")
	lines = append(lines, th.Bold(th.Accent, s.tr("tui.insp.resp_preview", FormatBytes(len(f.RespBody)))))
	preview := FormatBodyLinesLocale(f.RespBody, f.RespBodyType, th, s.Locale)
	maxPrev := 16
	if len(preview) > maxPrev {
		lines = append(lines, preview[:maxPrev]...)
		lines = append(lines, th.Fg(th.FgMuted, s.tr("tui.insp.more_lines", len(preview)-maxPrev)))
	} else {
		lines = append(lines, preview...)
	}

	return lines
}

func buildRequestTab(s *State, f *types.Flow, th Theme, width int) []string {
	var lines []string
	lines = append(lines, th.Bold(th.MethodColor(f.Method), SanitizeInline(f.Method))+" "+th.Fg(th.FgPrimary, Truncate(SanitizeInline(f.URL), max(10, width-10))))
	meta := s.tr("tui.insp.req_meta", contentTypeOrDefault(f.ReqBodyType), FormatBytes(len(f.ReqBody)), len(f.ReqHeaders))
	lines = append(lines, th.Fg(th.FgMuted, meta))
	lines = append(lines, th.Fg(th.BorderMuted, strings.Repeat("─", min(width, 72))))
	lines = append(lines, FormatBodyLinesLocale(f.ReqBody, f.ReqBodyType, th, s.Locale)...)
	return lines
}

func buildResponseTab(s *State, f *types.Flow, th Theme, width int) []string {
	var lines []string
	lines = append(lines, th.Bold(th.StatusColor(f.Status), fmt.Sprintf("HTTP %d", f.Status))+"  "+
		th.Fg(th.FgSecondary, FormatLatency(f.LatencyMs))+"  "+
		th.Fg(th.FgMuted, FormatBytes(len(f.RespBody))))
	meta := s.tr("tui.insp.resp_meta", contentTypeOrDefault(f.RespBodyType), len(f.RespHeaders))
	lines = append(lines, th.Fg(th.FgMuted, meta))
	lines = append(lines, th.Fg(th.BorderMuted, strings.Repeat("─", min(width, 72))))
	lines = append(lines, FormatBodyLinesLocale(f.RespBody, f.RespBodyType, th, s.Locale)...)
	return lines
}

func buildHeadersTab(s *State, f *types.Flow, th Theme, width int) []string {
	var lines []string
	lines = append(lines, th.Bold(th.Accent, s.tr("tui.insp.req_headers", len(f.ReqHeaders))))
	lines = append(lines, formatHeaderMap(s.Locale, f.ReqHeaders, th, width)...)
	lines = append(lines, "")
	lines = append(lines, th.Bold(th.Accent, s.tr("tui.insp.resp_headers", len(f.RespHeaders))))
	lines = append(lines, formatHeaderMap(s.Locale, f.RespHeaders, th, width)...)
	return lines
}

func formatHeaderMap(loc i18n.Locale, hdrs map[string]string, th Theme, width int) []string {
	if len(hdrs) == 0 {
		return []string{th.Fg(th.FgMuted, "  "+i18n.TLocale(loc, "common.none"))}
	}
	keys := make([]string, 0, len(hdrs))
	maxK := 0
	for k := range hdrs {
		keys = append(keys, k)
		if w := DisplayWidth(k); w > maxK {
			maxK = w
		}
	}
	sort.Strings(keys)
	if maxK > 26 {
		maxK = 26
	}
	if maxK < 12 {
		maxK = 12
	}

	valW := width - maxK - 4
	if valW < 12 {
		valW = 12
	}

	var lines []string
	for _, k := range keys {
		cleanK := Truncate(SanitizeInline(k), maxK)
		wrapped := WrapText(hdrs[k], valW)
		for i, chunk := range wrapped {
			if i == 0 {
				lines = append(lines, "  "+th.Fg(th.JSONKey, PadRight(cleanK, maxK))+"  "+th.Fg(th.FgPrimary, chunk))
			} else {
				lines = append(lines, "  "+strings.Repeat(" ", maxK)+"  "+th.Fg(th.FgPrimary, chunk))
			}
		}
	}
	return lines
}

func buildTimingTab(s *State, f *types.Flow, th Theme, width int) []string {
	var lines []string
	barW := min(32, max(12, width-24))

	lines = append(lines, th.Bold(th.Accent, s.tr("tui.insp.latency_prof")))
	latClass := s.tr("tui.insp.lat_fast")
	latColor := th.Success
	if f.LatencyMs >= 1000 {
		latClass = s.tr("tui.insp.lat_slow")
		latColor = th.Danger
	} else if f.LatencyMs >= 350 {
		latClass = s.tr("tui.insp.lat_moderate")
		latColor = th.Warn
	}
	ratio := float64(f.LatencyMs) / 1500.0
	if ratio > 1.0 {
		ratio = 1.0
	}
	filled := int(ratio * float64(barW))
	if f.LatencyMs > 0 && filled == 0 {
		filled = 1
	}
	bar := th.Fg(latColor, strings.Repeat("█", filled)) + th.Fg(th.BorderMuted, strings.Repeat("░", barW-filled))
	lines = append(lines, fmt.Sprintf("  %s %s  %s (%s)", PadRight(s.tr("tui.insp.lat_total"), 8), bar, th.Bold(latColor, FormatLatency(f.LatencyMs)), th.Fg(th.FgMuted, latClass)))
	lines = append(lines, "")

	lines = append(lines, th.Bold(th.Accent, s.tr("tui.insp.payload")))
	reqSz := len(f.ReqBody)
	respSz := len(f.RespBody)
	totalSz := reqSz + respSz
	drawSizeBar := func(label string, sz int, col ColorSpec) string {
		fill := 0
		if totalSz > 0 {
			fill = int((float64(sz) / float64(totalSz)) * float64(barW))
			if sz > 0 && fill == 0 {
				fill = 1
			}
		}
		b := th.Fg(col, strings.Repeat("█", fill)) + th.Fg(th.BorderMuted, strings.Repeat("░", barW-fill))
		return fmt.Sprintf("  %s %s  %s", PadRight(label, 8), b, th.Fg(th.FgPrimary, FormatBytes(sz)))
	}
	lines = append(lines, drawSizeBar(s.tr("tui.insp.payload_req"), reqSz, th.MethodPOST))
	lines = append(lines, drawSizeBar(s.tr("tui.insp.payload_resp"), respSz, th.MethodGET))
	lines = append(lines, fmt.Sprintf("  %s %s", PadRight(s.tr("tui.insp.payload_total"), 8), th.Bold(th.FgPrimary, FormatBytes(totalSz))))
	lines = append(lines, "")

	lines = append(lines, th.Bold(th.Accent, s.tr("tui.insp.metadata")))
	addKV := func(k, v string) {
		lines = append(lines, "  "+th.Fg(th.FgMuted, PadRight(k, 14))+th.Fg(th.FgPrimary, SanitizeInline(v)))
	}
	addKV(s.tr("tui.insp.flow_id"), f.ID)
	if !f.Timestamp.IsZero() {
		addKV(s.tr("tui.insp.local_time"), f.Timestamp.Local().Format(time.RFC3339))
		addKV(s.tr("tui.insp.utc_time"), f.Timestamp.UTC().Format(time.RFC3339))
	}
	addKV(s.tr("tui.insp.host"), f.Host)
	addKV(s.tr("tui.insp.method"), f.Method)
	addKV(s.tr("tui.insp.status"), fmt.Sprintf("%d", f.Status))
	addKV(s.tr("tui.insp.req_hdr_count"), fmt.Sprintf("%d", len(f.ReqHeaders)))
	addKV(s.tr("tui.insp.resp_hdr_count"), fmt.Sprintf("%d", len(f.RespHeaders)))
	if len(f.Tags) > 0 {
		addKV(s.tr("tui.insp.tags"), strings.Join(f.Tags, ", "))
	}
	if len(f.SignParams) > 0 {
		addKV(s.tr("tui.insp.sign_params"), strings.Join(f.SignParams, ", "))
	}
	return lines
}

func buildExportTab(s *State, f *types.Flow, lang string, th Theme, width int) []string {
	var lines []string

	var bar strings.Builder
	for _, l := range codegen.Languages() {
		label := " " + strings.ToUpper(l) + " "
		if l == lang {
			bar.WriteString(th.Pill(th.BrandFg, th.BrandBg, true, label))
		} else {
			bar.WriteString(th.Fg(th.FgMuted, label))
		}
		bar.WriteByte(' ')
	}
	lines = append(lines, bar.String())
	lines = append(lines, th.Fg(th.FgMuted, s.tr("tui.insp.export_hint")))
	lines = append(lines, th.Fg(th.BorderMuted, strings.Repeat("─", min(width, 72))))

	code, err := codegen.Generate(f, lang)
	if err != nil {
		lines = append(lines, th.Fg(th.Danger, s.tr("tui.insp.codegen_err", err.Error())))
		return lines
	}
	code = strings.ReplaceAll(code, "\r\n", "\n")
	code = strings.ReplaceAll(code, "\t", "  ")
	for _, line := range strings.Split(strings.TrimRight(code, "\n"), "\n") {
		lines = append(lines, th.Fg(th.FgPrimary, SanitizeInline(line)))
	}
	return lines
}

func renderStatusBar(s *State, th Theme, width int, now time.Time) string {
	bg := th.BgCode(th.StatusBarBg)

	if msg, kind, ok := s.ActiveToast(now); ok {
		icon := "●"
		col := th.Info
		switch kind {
		case ToastSuccess:
			icon = "✓"
			col = th.Success
		case ToastWarn:
			icon = "▲"
			col = th.Warn
		case ToastError:
			icon = "✗"
			col = th.Danger
		}
		toastStr := " " + th.Bold(col, icon+" "+SanitizeInline(msg))
		return FillLine(toastStr, width, bg)
	}

	type hint struct{ key, desc string }
	var hints []hint
	switch s.Mode {
	case ModeFilterInput:
		hints = []hint{
			{"Enter", s.tr("tui.hint.apply")},
			{"Esc", s.tr("tui.hint.cancel")},
			{"Ctrl+U", s.tr("tui.hint.clear")},
			{"Ctrl+W", s.tr("tui.hint.del_word")},
		}
	case ModeHelp:
		hints = []hint{
			{"?/Esc/q", s.tr("tui.hint.close")},
		}
	default:
		hints = []hint{
			{"↑↓/jk", s.tr("tui.hint.nav")},
			{"/", s.tr("tui.hint.filter")},
			{"1-6", s.tr("tui.hint.tabs")},
			{"Tab", s.tr("tui.hint.focus")},
			{"z", s.tr("tui.hint.zoom")},
			{"r", s.tr("tui.hint.replay")},
			{"y", s.tr("tui.hint.copy")},
			{"f", s.tr("tui.hint.follow")},
			{"L", s.tr("tui.hint.lang")},
			{"t", s.tr("tui.hint.theme")},
			{"?", s.tr("tui.hint.help")},
			{"q", s.tr("tui.hint.quit")},
		}
	}

	var b strings.Builder
	b.WriteByte(' ')
	used := 1
	for _, h := range hints {
		chip := th.Pill(th.Accent, th.ChipBg, true, " "+h.key+" ") + th.Fg(th.FgMuted, " "+h.desc+"  ")
		cw := DisplayWidth(chip)
		if used+cw > width {
			break
		}
		b.WriteString(chip)
		used += cw
	}

	return FillLine(b.String(), width, bg)
}

func renderBoxTop(width int, title, extra string, focused bool, borderColor ColorSpec, th Theme) string {
	if width < 4 {
		return strings.Repeat("─", width)
	}
	titleStyled := th.Fg(th.FgSecondary, title)
	if focused {
		titleStyled = th.Bold(th.Accent, title)
	}
	prefix := th.Fg(borderColor, "╭─ ") + titleStyled + extra + th.Fg(borderColor, " ")
	prefixW := DisplayWidth(prefix)
	rem := width - prefixW - 1
	if rem < 0 {
		return ClampANSI(prefix, width-1) + th.Fg(borderColor, "╮")
	}
	return prefix + th.Fg(borderColor, strings.Repeat("─", rem)+"╮")
}

func renderBoxBottom(width int, borderColor ColorSpec, th Theme) string {
	if width < 2 {
		return strings.Repeat("─", width)
	}
	return th.Fg(borderColor, "╰"+strings.Repeat("─", width-2)+"╯")
}

func renderScrollCell(row, visible, offset, total int, th Theme) string {
	if total <= visible || visible <= 0 {
		return " "
	}
	thumbSize := (visible * visible) / total
	if thumbSize < 1 {
		thumbSize = 1
	}
	maxOffset := total - visible
	thumbPos := 0
	if maxOffset > 0 {
		thumbPos = (offset * (visible - thumbSize)) / maxOffset
	}
	if row >= thumbPos && row < thumbPos+thumbSize {
		return th.Fg(th.Accent, "┃")
	}
	return th.Fg(th.BorderMuted, "│")
}

func overlayHelpModal(s *State, screen []string, w, h int, th Theme) []string {
	entries := []struct{ section, key, desc string }{
		{s.tr("tui.help.sec.nav"), "", ""},
		{"", "j / k / ↑ / ↓", s.tr("tui.help.nav.move")},
		{"", "g / G / Home / End", s.tr("tui.help.nav.jump")},
		{"", "PgUp / PgDn / Ctrl+U / Ctrl+D", s.tr("tui.help.nav.page")},
		{"", "Tab / Enter", s.tr("tui.help.nav.focus")},
		{"", "z", s.tr("tui.help.nav.zoom")},
		{s.tr("tui.help.sec.inspect"), "", ""},
		{"", "1 - 6 / [ / ]", s.tr("tui.help.insp.tabs")},
		{"", "l", s.tr("tui.help.insp.codegen")},
		{"", "/", s.tr("tui.help.insp.filter")},
		{"", "m / e / c", s.tr("tui.help.insp.quick")},
		{s.tr("tui.help.sec.actions"), "", ""},
		{"", "r", s.tr("tui.help.act.replay")},
		{"", "y / x", s.tr("tui.help.act.copy")},
		{"", "f / p", s.tr("tui.help.act.live")},
		{"", "R / d", s.tr("tui.help.act.store")},
		{"", "L", s.tr("tui.help.act.lang")},
		{"", "t / ? / q", s.tr("tui.help.act.misc")},
	}

	modalW := min(w-4, 74)
	if modalW < 36 {
		modalW = w - 2
	}
	modalH := min(h-2, len(entries)+4)
	if modalH < 8 {
		return screen
	}

	top := (h - modalH) / 2
	left := (w - modalW) / 2
	bg := th.BgCode(th.ModalBg)
	innerW := modalW - 2

	modalLines := make([]string, 0, modalH)
	modalLines = append(modalLines, renderBoxTop(modalW, s.tr("tui.help.title"), "", true, th.BorderFocus, th))

	maxEntries := modalH - 3
	for i := 0; i < maxEntries && i < len(entries); i++ {
		e := entries[i]
		var content string
		if e.section != "" {
			content = " " + th.Bold(th.Accent, e.section)
		} else {
			keyW := min(30, innerW/2)
			content = "  " + th.Bold(th.FgPrimary, PadRight(Truncate(e.key, keyW), keyW)) + " " + th.Fg(th.FgSecondary, Truncate(e.desc, max(4, innerW-keyW-3)))
		}
		modalLines = append(modalLines, th.Fg(th.BorderFocus, "│")+FillLine(content, innerW, bg)+th.Fg(th.BorderFocus, "│"))
	}

	footer := FillLine(" "+th.Fg(th.FgMuted, s.tr("tui.help.footer")), innerW, bg)
	modalLines = append(modalLines, th.Fg(th.BorderFocus, "│")+footer+th.Fg(th.BorderFocus, "│"))
	modalLines = append(modalLines, renderBoxBottom(modalW, th.BorderFocus, th))

	out := make([]string, len(screen))
	copy(out, screen)
	padLeft := strings.Repeat(" ", max(0, left))
	padRight := strings.Repeat(" ", max(0, w-left-modalW))
	for i, ml := range modalLines {
		row := top + i
		if row >= 0 && row < len(out) {
			out[row] = padLeft + ml + padRight
		}
	}
	return out
}
