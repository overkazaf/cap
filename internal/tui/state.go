package tui

import (
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/types"
)

// Mode represents the active keyboard interaction mode.
type Mode int

const (
	ModeNormal Mode = iota
	ModeFilterInput
	ModeHelp
)

// FocusPane identifies which split-pane currently holds focus.
type FocusPane int

const (
	PaneList FocusPane = iota
	PaneDetail
)

// DetailTab identifies the active tab inside the Flow Inspector pane.
type DetailTab int

const (
	TabOverview DetailTab = iota
	TabRequest
	TabResponse
	TabHeaders
	TabTiming
	TabExport
	tabCount
)

// Title returns the localized display label for a DetailTab.
func (t DetailTab) Title(loc i18n.Locale) string {
	switch t {
	case TabOverview:
		return i18n.TLocale(loc, "tui.tab.overview")
	case TabRequest:
		return i18n.TLocale(loc, "tui.tab.request")
	case TabResponse:
		return i18n.TLocale(loc, "tui.tab.response")
	case TabHeaders:
		return i18n.TLocale(loc, "tui.tab.headers")
	case TabTiming:
		return i18n.TLocale(loc, "tui.tab.timing")
	case TabExport:
		return i18n.TLocale(loc, "tui.tab.export")
	default:
		return i18n.TLocale(loc, "tui.tab.overview")
	}
}

// ShortTitle returns the compact localized tab label for narrow terminals.
func (t DetailTab) ShortTitle(loc i18n.Locale) string {
	switch t {
	case TabOverview:
		return i18n.TLocale(loc, "tui.tab.short.overview")
	case TabRequest:
		return i18n.TLocale(loc, "tui.tab.short.request")
	case TabResponse:
		return i18n.TLocale(loc, "tui.tab.short.response")
	case TabHeaders:
		return i18n.TLocale(loc, "tui.tab.short.headers")
	case TabTiming:
		return i18n.TLocale(loc, "tui.tab.short.timing")
	case TabExport:
		return i18n.TLocale(loc, "tui.tab.short.export")
	default:
		return i18n.TLocale(loc, "tui.tab.short.overview")
	}
}

// ToastKind classifies a transient status bar notification.
type ToastKind int

const (
	ToastInfo ToastKind = iota
	ToastSuccess
	ToastWarn
	ToastError
)

// CommandType represents an asynchronous or I/O side effect requested by State.Update.
type CommandType int

const (
	CmdNone CommandType = iota
	CmdQuit
	CmdRedrawFull
	CmdReplay
	CmdCopySnippet
	CmdExportFlow
	CmdDeleteFlow
	CmdReloadStore
)

// Command carries a side effect from the pure state reducer to the runtime loop.
type Command struct {
	Type CommandType
	Flow *types.Flow
	Lang string
}

var methodCycle = []string{"", "GET", "POST", "PUT", "PATCH", "DELETE"}

const maxInMemoryFlows = 5000

// State holds the complete UI state for the interactive TUI. All mutations go
// through methods on State so the reducer is deterministic and unit-testable.
type State struct {
	Width   int
	Height  int
	Version string
	Locale  i18n.Locale

	// Source / runtime status
	Live          bool
	ListenAddr    string
	DBPath        string
	Paused        bool
	AutoFollow    bool
	TotalCaptured int
	PausedDropped int
	Replaying     bool

	// Theme & rendering options
	ThemeName ThemeName
	NoColor   bool
	TrueColor bool

	// Data & filtering
	Flows         []*types.Flow
	Filtered      []*types.Flow
	ErrorCount    int
	FilterInput   string
	FilterApplied string
	FilterBackup  string
	MethodFilter  string
	ErrorsOnly    bool

	// Selection & viewport
	SelectedIdx      int
	ListOffset       int
	DetailScroll     int
	DetailTotalLines int
	Focus            FocusPane
	Zoom             bool
	Tab              DetailTab
	ExportLangIdx    int
	Mode             Mode

	// Transient toast notification
	Toast       string
	ToastKind   ToastKind
	ToastExpiry time.Time

	// Cached layout dimensions updated during render / resize
	listVisibleRows   int
	detailVisibleRows int
}

// StateOptions initializes a new TUI State.
type StateOptions struct {
	Width         int
	Height        int
	Version       string
	Locale        i18n.Locale
	Live          bool
	ListenAddr    string
	DBPath        string
	InitialFilter string
	LightTheme    bool
	NoColor       bool
	TrueColor     bool
	Flows         []*types.Flow
}

// NewState constructs a ready-to-render TUI State.
func NewState(opts StateOptions) *State {
	if opts.Width <= 0 {
		opts.Width = 120
	}
	if opts.Height <= 0 {
		opts.Height = 36
	}
	loc := opts.Locale
	if loc == "" {
		loc = i18n.Lang()
	} else {
		loc = i18n.Normalize(string(loc))
	}
	themeName := ThemeDark
	if opts.LightTheme {
		themeName = ThemeLight
	}
	s := &State{
		Width:             opts.Width,
		Height:            opts.Height,
		Version:           opts.Version,
		Locale:            loc,
		Live:              opts.Live,
		ListenAddr:        opts.ListenAddr,
		DBPath:            opts.DBPath,
		AutoFollow:        opts.Live,
		ThemeName:         themeName,
		NoColor:           opts.NoColor,
		TrueColor:         opts.TrueColor,
		FilterInput:       opts.InitialFilter,
		FilterApplied:     opts.InitialFilter,
		listVisibleRows:   10,
		detailVisibleRows: 10,
	}
	s.SetFlows(opts.Flows)
	return s
}

func (s *State) tr(key string, args ...any) string {
	return i18n.TLocale(s.Locale, key, args...)
}

// Theme returns the active Theme for rendering.
func (s *State) Theme() Theme {
	return NewTheme(s.ThemeName, s.NoColor, s.TrueColor)
}

// ExportLang returns the currently selected codegen language for TabExport.
func (s *State) ExportLang() string {
	langs := codegen.Languages()
	if len(langs) == 0 {
		return "curl"
	}
	idx := s.ExportLangIdx % len(langs)
	if idx < 0 {
		idx += len(langs)
	}
	return langs[idx]
}

// SelectedFlow returns the currently highlighted flow, or nil when empty.
func (s *State) SelectedFlow() *types.Flow {
	if s.SelectedIdx < 0 || s.SelectedIdx >= len(s.Filtered) {
		return nil
	}
	return s.Filtered[s.SelectedIdx]
}

// SetFlows replaces the master flow list (newest first) and recomputes filters.
func (s *State) SetFlows(flows []*types.Flow) {
	selectedID := ""
	if cur := s.SelectedFlow(); cur != nil {
		selectedID = cur.ID
	}

	copied := make([]*types.Flow, 0, len(flows))
	errCount := 0
	for _, f := range flows {
		if f == nil {
			continue
		}
		copied = append(copied, f)
		if f.Status >= 400 {
			errCount++
		}
	}
	if len(copied) > maxInMemoryFlows {
		copied = copied[:maxInMemoryFlows]
	}
	s.Flows = copied
	s.ErrorCount = errCount
	s.applyFilter(selectedID)
}

// AddFlow ingests a newly captured or replayed flow at the top of the list.
func (s *State) AddFlow(f *types.Flow) {
	if f == nil {
		return
	}
	if s.Paused {
		s.PausedDropped++
		return
	}

	selectedID := ""
	if !s.AutoFollow {
		if cur := s.SelectedFlow(); cur != nil {
			selectedID = cur.ID
		}
	}

	s.Flows = append([]*types.Flow{f}, s.Flows...)
	if len(s.Flows) > maxInMemoryFlows {
		s.Flows = s.Flows[:maxInMemoryFlows]
	}
	s.TotalCaptured++
	if f.Status >= 400 {
		s.ErrorCount++
	}

	if s.AutoFollow {
		s.applyFilter("")
		s.SelectedIdx = 0
		s.ListOffset = 0
		s.DetailScroll = 0
	} else {
		s.applyFilter(selectedID)
	}
}

// RemoveFlow removes a flow by ID from in-memory state.
func (s *State) RemoveFlow(id string) {
	next := make([]*types.Flow, 0, len(s.Flows))
	errCount := 0
	for _, f := range s.Flows {
		if f.ID == id {
			continue
		}
		next = append(next, f)
		if f.Status >= 400 {
			errCount++
		}
	}
	s.Flows = next
	s.ErrorCount = errCount
	s.applyFilter("")
	s.DetailScroll = 0
}

// Resize updates terminal dimensions and clamps scroll offsets.
func (s *State) Resize(width, height int) {
	if width > 0 {
		s.Width = width
	}
	if height > 0 {
		s.Height = height
	}
	s.ensureListVisible()
	s.clampDetailScroll()
}

// SetToast displays a transient message in the bottom status bar.
func (s *State) SetToast(kind ToastKind, msg string, ttl time.Duration) {
	s.Toast = msg
	s.ToastKind = kind
	if ttl <= 0 {
		ttl = 3500 * time.Millisecond
	}
	s.ToastExpiry = time.Now().Add(ttl)
}

// ActiveToast returns the toast message and kind if not yet expired.
func (s *State) ActiveToast(now time.Time) (string, ToastKind, bool) {
	if s.Toast == "" {
		return "", ToastInfo, false
	}
	if !s.ToastExpiry.IsZero() && now.After(s.ToastExpiry) {
		return "", ToastInfo, false
	}
	return s.Toast, s.ToastKind, true
}

// HasActiveFilter reports whether any filter constraint is currently active.
func (s *State) HasActiveFilter() bool {
	return strings.TrimSpace(s.FilterApplied) != "" || s.MethodFilter != "" || s.ErrorsOnly
}

func (s *State) applyFilter(preserveID string) {
	query := ParseFilter(s.FilterApplied)
	filtered := make([]*types.Flow, 0, len(s.Flows))
	for _, f := range s.Flows {
		if query.Matches(f, s.MethodFilter, s.ErrorsOnly) {
			filtered = append(filtered, f)
		}
	}
	s.Filtered = filtered

	if len(s.Filtered) == 0 {
		s.SelectedIdx = 0
		s.ListOffset = 0
		return
	}

	if preserveID != "" {
		for i, f := range s.Filtered {
			if f.ID == preserveID {
				s.SelectedIdx = i
				s.ensureListVisible()
				return
			}
		}
	}

	if s.SelectedIdx >= len(s.Filtered) {
		s.SelectedIdx = len(s.Filtered) - 1
	}
	if s.SelectedIdx < 0 {
		s.SelectedIdx = 0
	}
	s.ensureListVisible()
}

func (s *State) ensureListVisible() {
	rows := s.listVisibleRows
	if rows < 1 {
		rows = 1
	}
	if s.SelectedIdx < s.ListOffset {
		s.ListOffset = s.SelectedIdx
	}
	if s.SelectedIdx >= s.ListOffset+rows {
		s.ListOffset = s.SelectedIdx - rows + 1
	}
	maxOffset := len(s.Filtered) - rows
	if maxOffset < 0 {
		maxOffset = 0
	}
	if s.ListOffset > maxOffset {
		s.ListOffset = maxOffset
	}
	if s.ListOffset < 0 {
		s.ListOffset = 0
	}
}

func (s *State) clampDetailScroll() {
	rows := s.detailVisibleRows
	if rows < 1 {
		rows = 1
	}
	maxScroll := s.DetailTotalLines - rows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if s.DetailScroll > maxScroll {
		s.DetailScroll = maxScroll
	}
	if s.DetailScroll < 0 {
		s.DetailScroll = 0
	}
}

// Update processes a single KeyEvent and returns an optional side-effect Command.
func (s *State) Update(ev KeyEvent) Command {
	if ev.Kind == KeyCtrlC {
		return Command{Type: CmdQuit}
	}
	if ev.Kind == KeyCtrlL {
		return Command{Type: CmdRedrawFull}
	}

	switch s.Mode {
	case ModeHelp:
		return s.updateHelp(ev)
	case ModeFilterInput:
		return s.updateFilterInput(ev)
	default:
		return s.updateNormal(ev)
	}
}

func (s *State) updateHelp(ev KeyEvent) Command {
	if ev.Kind == KeyEsc || ev.Kind == KeyEnter || (ev.Kind == KeyRune && (ev.Rune == '?' || ev.Rune == 'q')) {
		s.Mode = ModeNormal
	}
	return Command{Type: CmdNone}
}

func (s *State) updateFilterInput(ev KeyEvent) Command {
	switch ev.Kind {
	case KeyEsc:
		s.FilterInput = s.FilterBackup
		s.FilterApplied = s.FilterBackup
		s.Mode = ModeNormal
		s.applyFilter("")
		s.DetailScroll = 0
	case KeyEnter:
		s.FilterApplied = strings.TrimSpace(s.FilterInput)
		s.Mode = ModeNormal
		s.applyFilter("")
		s.DetailScroll = 0
		if s.FilterApplied != "" {
			s.SetToast(ToastInfo, s.tr("tui.toast.filter_applied", s.FilterApplied, len(s.Filtered)), 2500*time.Millisecond)
		}
	case KeyBackspace:
		runes := []rune(s.FilterInput)
		if len(runes) > 0 {
			s.FilterInput = string(runes[:len(runes)-1])
			s.FilterApplied = s.FilterInput
			s.applyFilter("")
			s.DetailScroll = 0
		}
	case KeyCtrlU:
		s.FilterInput = ""
		s.FilterApplied = ""
		s.applyFilter("")
		s.DetailScroll = 0
	case KeyCtrlW:
		trimmed := strings.TrimRight(s.FilterInput, " ")
		if idx := strings.LastIndex(trimmed, " "); idx >= 0 {
			s.FilterInput = trimmed[:idx+1]
		} else {
			s.FilterInput = ""
		}
		s.FilterApplied = s.FilterInput
		s.applyFilter("")
		s.DetailScroll = 0
	case KeyRune:
		s.FilterInput += string(ev.Rune)
		s.FilterApplied = s.FilterInput
		s.applyFilter("")
		s.DetailScroll = 0
	}
	return Command{Type: CmdNone}
}

func (s *State) updateNormal(ev KeyEvent) Command {
	pageStep := s.detailVisibleRows / 2
	if pageStep < 5 {
		pageStep = 5
	}
	listPage := s.listVisibleRows / 2
	if listPage < 5 {
		listPage = 5
	}

	switch ev.Kind {
	case KeyTab, KeyShiftTab:
		if s.Focus == PaneList {
			s.Focus = PaneDetail
		} else {
			s.Focus = PaneList
		}
		return Command{Type: CmdNone}

	case KeyEnter:
		if s.Focus == PaneList && s.SelectedFlow() != nil {
			s.Focus = PaneDetail
		}
		return Command{Type: CmdNone}

	case KeyEsc:
		if s.Zoom {
			s.Zoom = false
			return Command{Type: CmdNone}
		}
		if s.Focus == PaneDetail {
			s.Focus = PaneList
			return Command{Type: CmdNone}
		}
		if s.HasActiveFilter() {
			s.clearFilters()
		}
		return Command{Type: CmdNone}

	case KeyDown:
		if s.Focus == PaneList {
			s.moveSelection(1)
		} else {
			s.scrollDetail(1)
		}
		return Command{Type: CmdNone}

	case KeyUp:
		if s.Focus == PaneList {
			s.moveSelection(-1)
		} else {
			s.scrollDetail(-1)
		}
		return Command{Type: CmdNone}

	case KeyHome:
		if s.Focus == PaneList {
			s.selectIndex(0)
		} else {
			s.DetailScroll = 0
		}
		return Command{Type: CmdNone}

	case KeyEnd:
		if s.Focus == PaneList {
			s.selectIndex(len(s.Filtered) - 1)
		} else {
			s.DetailScroll = s.DetailTotalLines
			s.clampDetailScroll()
		}
		return Command{Type: CmdNone}

	case KeyPgDn, KeyCtrlD:
		if s.Focus == PaneList && ev.Kind == KeyPgDn {
			s.moveSelection(listPage)
		} else {
			s.scrollDetail(pageStep)
		}
		return Command{Type: CmdNone}

	case KeyPgUp, KeyCtrlU:
		if s.Focus == PaneList && ev.Kind == KeyPgUp {
			s.moveSelection(-listPage)
		} else {
			s.scrollDetail(-pageStep)
		}
		return Command{Type: CmdNone}

	case KeyLeft:
		s.prevTab()
		return Command{Type: CmdNone}

	case KeyRight:
		s.nextTab()
		return Command{Type: CmdNone}

	case KeyRune:
		return s.handleRune(ev.Rune)
	}

	return Command{Type: CmdNone}
}

func (s *State) handleRune(r rune) Command {
	switch r {
	case 'q':
		return Command{Type: CmdQuit}
	case '?':
		s.Mode = ModeHelp
	case '/':
		s.FilterBackup = s.FilterApplied
		s.FilterInput = s.FilterApplied
		s.Mode = ModeFilterInput
	case 'j':
		if s.Focus == PaneList {
			s.moveSelection(1)
		} else {
			s.scrollDetail(1)
		}
	case 'k':
		if s.Focus == PaneList {
			s.moveSelection(-1)
		} else {
			s.scrollDetail(-1)
		}
	case 'J':
		s.scrollDetail(3)
	case 'K':
		s.scrollDetail(-3)
	case 'g':
		if s.Focus == PaneList {
			s.selectIndex(0)
		} else {
			s.DetailScroll = 0
		}
	case 'G':
		if s.Focus == PaneList {
			s.selectIndex(len(s.Filtered) - 1)
		} else {
			s.DetailScroll = s.DetailTotalLines
			s.clampDetailScroll()
		}
	case 'z':
		s.Zoom = !s.Zoom
	case '1':
		s.setTab(TabOverview)
	case '2':
		s.setTab(TabRequest)
	case '3':
		s.setTab(TabResponse)
	case '4':
		s.setTab(TabHeaders)
	case '5':
		s.setTab(TabTiming)
	case '6':
		s.setTab(TabExport)
	case '[':
		s.prevTab()
	case ']':
		s.nextTab()
	case 'l':
		if s.Tab == TabExport {
			langs := codegen.Languages()
			if len(langs) > 0 {
				s.ExportLangIdx = (s.ExportLangIdx + 1) % len(langs)
				s.DetailScroll = 0
				s.SetToast(ToastInfo, s.tr("tui.toast.codegen_lang", strings.ToUpper(s.ExportLang())), 2000*time.Millisecond)
			}
		} else {
			s.nextTab()
		}
	case 'L':
		if s.Locale == i18n.ZH {
			s.Locale = i18n.EN
		} else {
			s.Locale = i18n.ZH
		}
		i18n.SetLang(string(s.Locale))
		s.SetToast(ToastSuccess, s.tr("tui.toast.lang_switched", s.Locale.NativeName()), 2400*time.Millisecond)
	case 'h':
		if s.Tab != TabExport {
			s.prevTab()
		}
	case 'm':
		s.cycleMethodFilter()
	case 'e':
		s.ErrorsOnly = !s.ErrorsOnly
		s.applyFilter("")
		s.DetailScroll = 0
		if s.ErrorsOnly {
			s.SetToast(ToastWarn, s.tr("tui.toast.errors_on", len(s.Filtered)), 2500*time.Millisecond)
		} else {
			s.SetToast(ToastInfo, s.tr("tui.toast.errors_off"), 2000*time.Millisecond)
		}
	case 'c':
		s.clearFilters()
	case 'f':
		s.AutoFollow = !s.AutoFollow
		if s.AutoFollow {
			s.SelectedIdx = 0
			s.ListOffset = 0
			s.DetailScroll = 0
			s.SetToast(ToastSuccess, s.tr("tui.toast.follow_on"), 2200*time.Millisecond)
		} else {
			s.SetToast(ToastInfo, s.tr("tui.toast.follow_off"), 2000*time.Millisecond)
		}
	case 'p':
		if s.Live {
			s.Paused = !s.Paused
			if s.Paused {
				s.SetToast(ToastWarn, s.tr("tui.toast.paused"), 2500*time.Millisecond)
			} else {
				msg := s.tr("tui.toast.resumed")
				if s.PausedDropped > 0 {
					msg = s.tr("tui.toast.resumed_dropped", s.PausedDropped)
					s.PausedDropped = 0
				}
				s.SetToast(ToastSuccess, msg, 2500*time.Millisecond)
			}
		} else {
			s.SetToast(ToastInfo, s.tr("tui.toast.pause_live_only"), 2000*time.Millisecond)
		}
	case 't':
		if s.ThemeName == ThemeDark {
			s.ThemeName = ThemeLight
			s.SetToast(ToastInfo, s.tr("tui.toast.theme_light"), 2000*time.Millisecond)
		} else {
			s.ThemeName = ThemeDark
			s.SetToast(ToastInfo, s.tr("tui.toast.theme_dark"), 2000*time.Millisecond)
		}
	case 'r':
		if f := s.SelectedFlow(); f != nil {
			if s.Replaying {
				s.SetToast(ToastWarn, s.tr("tui.toast.replay_busy"), 2000*time.Millisecond)
				return Command{Type: CmdNone}
			}
			s.Replaying = true
			s.SetToast(ToastInfo, s.tr("tui.toast.replaying", f.Method, Truncate(f.Path, 30)), 5000*time.Millisecond)
			return Command{Type: CmdReplay, Flow: f}
		}
	case 'y':
		if f := s.SelectedFlow(); f != nil {
			lang := "curl"
			if s.Tab == TabExport {
				lang = s.ExportLang()
			}
			return Command{Type: CmdCopySnippet, Flow: f, Lang: lang}
		}
	case 'x':
		if f := s.SelectedFlow(); f != nil {
			lang := "curl"
			if s.Tab == TabExport {
				lang = s.ExportLang()
			}
			return Command{Type: CmdExportFlow, Flow: f, Lang: lang}
		}
	case 'd':
		if f := s.SelectedFlow(); f != nil {
			return Command{Type: CmdDeleteFlow, Flow: f}
		}
	case 'R':
		return Command{Type: CmdReloadStore}
	}
	return Command{Type: CmdNone}
}

func (s *State) moveSelection(delta int) {
	if len(s.Filtered) == 0 {
		return
	}
	next := s.SelectedIdx + delta
	if next < 0 {
		next = 0
	}
	if next >= len(s.Filtered) {
		next = len(s.Filtered) - 1
	}
	if next != s.SelectedIdx {
		s.SelectedIdx = next
		s.DetailScroll = 0
		if next > 0 && s.AutoFollow {
			s.AutoFollow = false
		}
	}
	s.ensureListVisible()
}

func (s *State) selectIndex(idx int) {
	if len(s.Filtered) == 0 {
		return
	}
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s.Filtered) {
		idx = len(s.Filtered) - 1
	}
	if idx != s.SelectedIdx {
		s.SelectedIdx = idx
		s.DetailScroll = 0
		if idx > 0 && s.AutoFollow {
			s.AutoFollow = false
		}
	}
	s.ensureListVisible()
}

func (s *State) scrollDetail(delta int) {
	s.DetailScroll += delta
	s.clampDetailScroll()
}

func (s *State) setTab(tab DetailTab) {
	if s.Tab != tab {
		s.Tab = tab
		s.DetailScroll = 0
	}
}

func (s *State) nextTab() {
	s.Tab = (s.Tab + 1) % tabCount
	s.DetailScroll = 0
}

func (s *State) prevTab() {
	s.Tab = (s.Tab - 1 + tabCount) % tabCount
	s.DetailScroll = 0
}

func (s *State) cycleMethodFilter() {
	cur := 0
	for i, m := range methodCycle {
		if m == s.MethodFilter {
			cur = i
			break
		}
	}
	s.MethodFilter = methodCycle[(cur+1)%len(methodCycle)]
	s.applyFilter("")
	s.DetailScroll = 0
	if s.MethodFilter == "" {
		s.SetToast(ToastInfo, s.tr("tui.toast.method_cleared"), 2000*time.Millisecond)
	} else {
		s.SetToast(ToastInfo, s.tr("tui.toast.method_set", s.MethodFilter, len(s.Filtered)), 2200*time.Millisecond)
	}
}

func (s *State) clearFilters() {
	s.FilterInput = ""
	s.FilterApplied = ""
	s.MethodFilter = ""
	s.ErrorsOnly = false
	s.applyFilter("")
	s.DetailScroll = 0
	s.SetToast(ToastInfo, s.tr("tui.toast.filters_cleared"), 2000*time.Millisecond)
}
