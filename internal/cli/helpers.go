package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/store/sqlite"
	"github.com/overkazaf/cap/internal/tui"
)

// isTTYCheck is overridable in tests to exercise both TTY and non-TTY output.
var isTTYCheck = func(f *os.File) bool {
	if f == nil {
		return false
	}
	return tui.IsTTY(f.Fd())
}

// termWidthCheck is overridable in tests for deterministic layout assertions.
var termWidthCheck = func(f *os.File) int {
	if f == nil {
		return 100
	}
	w, _ := tui.TerminalSize(f.Fd())
	if w <= 0 {
		return 100
	}
	return w
}

// defaultCapDir returns cap's default data directory.
func defaultCapDir() string {
	return config.DefaultDir()
}

// defaultDBPath returns the default flow database path.
func defaultDBPath() string {
	return config.DefaultDBPath()
}

// openStore opens the SQLite-backed flow store at dbPath, defaulting to
// defaultDBPath() when dbPath is empty. The database's containing directory
// is created if it doesn't already exist.
func openStore(dbPath string) (*sqlite.SQLiteStore, error) {
	if dbPath == "" {
		dbPath = defaultDBPath()
	}

	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}

	return sqlite.New(dbPath)
}

// isStyledWriter reports whether w is an interactive terminal where styled
// commercial CLI output should be rendered.
func isStyledWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isTTYCheck(f)
}

// cliTheme returns the shared Obsidian Dark theme configured for CLI output.
// When styled is false or NO_COLOR is set, all ANSI color sequences are omitted.
func cliTheme(styled bool) tui.Theme {
	noColor := !styled || tui.DetectNoColor()
	return tui.NewTheme(tui.ThemeDark, noColor, tui.DetectTrueColor())
}

// cliWidth returns the best-effort terminal column width for w.
func cliWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		return termWidthCheck(f)
	}
	return 100
}

// printSectionHeader writes a refined commercial CLI header bar on TTYs.
func printSectionHeader(w io.Writer, th tui.Theme, title, subtitle string) {
	badge := th.Pill(th.BrandFg, th.BrandBg, true, " CAP ")
	line := badge + " " + th.Bold(th.FgPrimary, title)
	if subtitle != "" {
		line += "  " + th.Fg(th.FgMuted, "·  "+subtitle)
	}
	fmt.Fprintln(w, line)
	ruleW := min(cliWidth(w), 88)
	if ruleW < 30 {
		ruleW = 30
	}
	fmt.Fprintln(w, th.Fg(th.BorderMuted, strings.Repeat("─", ruleW)))
}

// printHint writes a subtle next-step tip line.
func printHint(w io.Writer, th tui.Theme, text string) {
	fmt.Fprintln(w, th.Fg(th.FgMuted, "  ▸ "+text))
}

// printSuccessBadge writes a green checkmark status line.
func printSuccessBadge(w io.Writer, th tui.Theme, text string) {
	fmt.Fprintln(w, th.Bold(th.Success, "✓")+" "+th.Fg(th.FgPrimary, text))
}

// printInfoBadge writes a cyan dot status line.
func printInfoBadge(w io.Writer, th tui.Theme, text string) {
	fmt.Fprintln(w, th.Bold(th.Info, "●")+" "+th.Fg(th.FgSecondary, text))
}
