package tui

import (
	"fmt"
	"os"
	"strings"
)

// ThemeName identifies the active TUI color palette.
type ThemeName string

const (
	ThemeDark  ThemeName = "dark"
	ThemeLight ThemeName = "light"
)

// ColorSpec holds both 24-bit RGB and 256-color fallback values so the TUI
// renders crisply across TrueColor terminals (Ghostty, iTerm2, Kitty, VSCode)
// as well as 256-color terminals (macOS Terminal.app, tmux).
type ColorSpec struct {
	R, G, B uint8
	ANSI256 uint8
}

func (c ColorSpec) fg(trueColor bool) string {
	if trueColor {
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", c.R, c.G, c.B)
	}
	return fmt.Sprintf("\x1b[38;5;%dm", c.ANSI256)
}

func (c ColorSpec) bg(trueColor bool) string {
	if trueColor {
		return fmt.Sprintf("\x1b[48;2;%d;%d;%dm", c.R, c.G, c.B)
	}
	return fmt.Sprintf("\x1b[48;5;%dm", c.ANSI256)
}

// Theme defines all semantic colors used across the TUI and styled CLI views.
type Theme struct {
	Name      ThemeName
	NoColor   bool
	TrueColor bool

	// Brand & Accent
	BrandBg ColorSpec
	BrandFg ColorSpec
	Accent  ColorSpec

	// Surfaces
	HeaderBg    ColorSpec
	StatusBarBg ColorSpec
	SelectedBg  ColorSpec
	FilterBg    ColorSpec
	ChipBg      ColorSpec
	ModalBg     ColorSpec
	TabActiveBg ColorSpec

	// Text hierarchy
	FgPrimary   ColorSpec
	FgSecondary ColorSpec
	FgMuted     ColorSpec
	FgInverse   ColorSpec

	// Borders
	BorderMuted ColorSpec
	BorderFocus ColorSpec

	// Semantic states
	Live    ColorSpec
	Paused  ColorSpec
	Success ColorSpec
	Warn    ColorSpec
	Danger  ColorSpec
	Info    ColorSpec

	// HTTP Methods
	MethodGET    ColorSpec
	MethodPOST   ColorSpec
	MethodPUT    ColorSpec
	MethodPATCH  ColorSpec
	MethodDELETE ColorSpec
	MethodWS     ColorSpec
	MethodOTHER  ColorSpec

	// HTTP Status classes
	Status2xx   ColorSpec
	Status3xx   ColorSpec
	Status4xx   ColorSpec
	Status5xx   ColorSpec
	StatusOther ColorSpec

	// JSON / Code syntax highlighting
	JSONKey    ColorSpec
	JSONString ColorSpec
	JSONNumber ColorSpec
	JSONBool   ColorSpec
	JSONPunct  ColorSpec
}

// DetectTrueColor reports whether the current terminal advertises 24-bit color.
func DetectTrueColor() bool {
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	if ct == "truecolor" || ct == "24bit" {
		return true
	}
	term := strings.ToLower(os.Getenv("TERM"))
	if strings.Contains(term, "direct") || strings.Contains(term, "ghostty") || strings.Contains(term, "kitty") {
		return true
	}
	tp := strings.ToLower(os.Getenv("TERM_PROGRAM"))
	return tp == "iterm.app" || tp == "vscode" || tp == "wezterm" || tp == "ghostty"
}

// DetectNoColor reports whether ANSI colors should be disabled based on
// standard environment conventions (NO_COLOR, TERM=dumb).
func DetectNoColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return true
	}
	return strings.EqualFold(os.Getenv("TERM"), "dumb")
}

// NewTheme builds the requested theme with TrueColor/NoColor flags applied.
func NewTheme(name ThemeName, noColor bool, trueColor bool) Theme {
	if name == ThemeLight {
		t := lightTheme()
		t.NoColor = noColor
		t.TrueColor = trueColor
		return t
	}
	t := darkTheme()
	t.NoColor = noColor
	t.TrueColor = trueColor
	return t
}

// darkTheme is the Obsidian commercial dark theme aligned with the desktop GUI.
func darkTheme() Theme {
	return Theme{
		Name: ThemeDark,

		BrandBg: ColorSpec{56, 189, 248, 81},  // Sky/Cyan #38BDF8
		BrandFg: ColorSpec{11, 12, 16, 233},   // Obsidian #0B0C10
		Accent:  ColorSpec{56, 189, 248, 81},  // Sky/Cyan #38BDF8

		HeaderBg:    ColorSpec{19, 21, 28, 234},  // Panel #13151C
		StatusBarBg: ColorSpec{19, 21, 28, 234},  // Panel #13151C
		SelectedBg:  ColorSpec{30, 38, 56, 237},  // Selected #1E2638
		FilterBg:    ColorSpec{24, 27, 38, 235},  // Elevated
		ChipBg:      ColorSpec{34, 39, 54, 238},  // Chip
		ModalBg:     ColorSpec{19, 21, 28, 234},  // Panel #13151C
		TabActiveBg: ColorSpec{30, 38, 56, 237},  // Selected #1E2638

		FgPrimary:   ColorSpec{236, 238, 244, 255}, // #ECEEF4
		FgSecondary: ColorSpec{184, 192, 208, 250},
		FgMuted:     ColorSpec{118, 127, 146, 244}, // #767F92
		FgInverse:   ColorSpec{11, 12, 16, 233},    // #0B0C10

		BorderMuted: ColorSpec{42, 47, 61, 238},  // #2A2F3D
		BorderFocus: ColorSpec{56, 189, 248, 81}, // #38BDF8

		Live:    ColorSpec{52, 211, 153, 79},   // Emerald #34D399
		Paused:  ColorSpec{251, 191, 36, 221},  // Amber #FBBF24
		Success: ColorSpec{52, 211, 153, 79},   // Emerald #34D399
		Warn:    ColorSpec{251, 191, 36, 221},  // Amber #FBBF24
		Danger:  ColorSpec{248, 113, 113, 203}, // Red #F87171
		Info:    ColorSpec{56, 189, 248, 81},   // Sky #38BDF8

		MethodGET:    ColorSpec{52, 211, 153, 79},   // Emerald #34D399
		MethodPOST:   ColorSpec{56, 189, 248, 81},   // Sky #38BDF8
		MethodPUT:    ColorSpec{251, 146, 60, 215},  // Orange #FB923C
		MethodPATCH:  ColorSpec{192, 132, 252, 177}, // Purple #C084FC
		MethodDELETE: ColorSpec{248, 113, 113, 203}, // Red #F87171
		MethodWS:     ColorSpec{45, 212, 191, 80},   // Teal #2DD4BF
		MethodOTHER:  ColorSpec{148, 163, 184, 247}, // Slate #94A3B8

		Status2xx:   ColorSpec{52, 211, 153, 79},   // Emerald #34D399
		Status3xx:   ColorSpec{96, 165, 250, 75},   // Blue #60A5FA
		Status4xx:   ColorSpec{251, 191, 36, 221},  // Amber #FBBF24
		Status5xx:   ColorSpec{248, 113, 113, 203}, // Red #F87171
		StatusOther: ColorSpec{148, 163, 184, 247},

		JSONKey:    ColorSpec{56, 189, 248, 81},
		JSONString: ColorSpec{52, 211, 153, 79},
		JSONNumber: ColorSpec{251, 191, 36, 221},
		JSONBool:   ColorSpec{192, 132, 252, 177},
		JSONPunct:  ColorSpec{118, 127, 146, 244},
	}
}

// lightTheme is the Crisp Porcelain light theme aligned with the desktop GUI.
func lightTheme() Theme {
	return Theme{
		Name: ThemeLight,

		BrandBg: ColorSpec{2, 132, 199, 32},    // Sky #0284C7
		BrandFg: ColorSpec{255, 255, 255, 231}, // White
		Accent:  ColorSpec{2, 132, 199, 32},    // Sky #0284C7

		HeaderBg:    ColorSpec{246, 247, 249, 255}, // App #F6F7F9
		StatusBarBg: ColorSpec{246, 247, 249, 255}, // App #F6F7F9
		SelectedBg:  ColorSpec{227, 239, 252, 195}, // Selected #E3EFFC
		FilterBg:    ColorSpec{255, 255, 255, 231}, // Panel #FFFFFF
		ChipBg:      ColorSpec{226, 232, 240, 253},
		ModalBg:     ColorSpec{255, 255, 255, 231}, // Panel #FFFFFF
		TabActiveBg: ColorSpec{227, 239, 252, 195}, // Selected #E3EFFC

		FgPrimary:   ColorSpec{15, 23, 42, 234},   // #0F172A
		FgSecondary: ColorSpec{51, 65, 85, 239},   // #334155
		FgMuted:     ColorSpec{100, 116, 139, 244}, // #64748B
		FgInverse:   ColorSpec{255, 255, 255, 231},

		BorderMuted: ColorSpec{203, 213, 225, 251}, // #CBD5E1
		BorderFocus: ColorSpec{2, 132, 199, 32},    // #0284C7

		Live:    ColorSpec{5, 150, 105, 29},
		Paused:  ColorSpec{217, 119, 6, 172},
		Success: ColorSpec{5, 150, 105, 29},
		Warn:    ColorSpec{217, 119, 6, 172},
		Danger:  ColorSpec{220, 38, 38, 160},
		Info:    ColorSpec{2, 132, 199, 32},

		MethodGET:    ColorSpec{5, 150, 105, 29},
		MethodPOST:   ColorSpec{2, 132, 199, 32},
		MethodPUT:    ColorSpec{234, 88, 12, 166},
		MethodPATCH:  ColorSpec{147, 51, 234, 92},
		MethodDELETE: ColorSpec{220, 38, 38, 160},
		MethodWS:     ColorSpec{13, 148, 136, 30},
		MethodOTHER:  ColorSpec{100, 116, 139, 244},

		Status2xx:   ColorSpec{5, 150, 105, 29},
		Status3xx:   ColorSpec{37, 99, 235, 27},
		Status4xx:   ColorSpec{217, 119, 6, 172},
		Status5xx:   ColorSpec{220, 38, 38, 160},
		StatusOther: ColorSpec{100, 116, 139, 244},

		JSONKey:    ColorSpec{2, 132, 199, 32},
		JSONString: ColorSpec{5, 150, 105, 29},
		JSONNumber: ColorSpec{217, 119, 6, 172},
		JSONBool:   ColorSpec{147, 51, 234, 92},
		JSONPunct:  ColorSpec{100, 116, 139, 244},
	}
}

const ansiReset = "\x1b[0m"
const ansiBold = "\x1b[1m"
const ansiDim = "\x1b[2m"

// Fg colors text with foreground c.
func (t Theme) Fg(c ColorSpec, text string) string {
	if t.NoColor || text == "" {
		return text
	}
	return c.fg(t.TrueColor) + text + ansiReset
}

// Bold colors text with foreground c and bold weight.
func (t Theme) Bold(c ColorSpec, text string) string {
	if t.NoColor || text == "" {
		return text
	}
	return ansiBold + c.fg(t.TrueColor) + text + ansiReset
}

// Dim renders muted/dimmed text.
func (t Theme) Dim(c ColorSpec, text string) string {
	if t.NoColor || text == "" {
		return text
	}
	return ansiDim + c.fg(t.TrueColor) + text + ansiReset
}

// Pill renders text with both foreground and background colors (optionally bold).
func (t Theme) Pill(fg, bg ColorSpec, bold bool, text string) string {
	if t.NoColor || text == "" {
		return text
	}
	var b strings.Builder
	if bold {
		b.WriteString(ansiBold)
	}
	b.WriteString(fg.fg(t.TrueColor))
	b.WriteString(bg.bg(t.TrueColor))
	b.WriteString(text)
	b.WriteString(ansiReset)
	return b.String()
}

// BgCode returns the raw ANSI background escape sequence (or "" when NoColor).
func (t Theme) BgCode(c ColorSpec) string {
	if t.NoColor {
		return ""
	}
	return c.bg(t.TrueColor)
}

// FgCode returns the raw ANSI foreground escape sequence (or "" when NoColor).
func (t Theme) FgCode(c ColorSpec) string {
	if t.NoColor {
		return ""
	}
	return c.fg(t.TrueColor)
}

// MethodColor returns the semantic color for an HTTP method.
func (t Theme) MethodColor(method string) ColorSpec {
	switch strings.ToUpper(method) {
	case "GET":
		return t.MethodGET
	case "POST":
		return t.MethodPOST
	case "PUT":
		return t.MethodPUT
	case "PATCH":
		return t.MethodPATCH
	case "DELETE":
		return t.MethodDELETE
	case "WS", "WSS", "WEBSOCKET":
		return t.MethodWS
	default:
		return t.MethodOTHER
	}
}

// StatusColor returns the semantic color for an HTTP status code.
func (t Theme) StatusColor(status int) ColorSpec {
	switch {
	case status >= 200 && status < 300:
		return t.Status2xx
	case status >= 300 && status < 400:
		return t.Status3xx
	case status >= 400 && status < 500:
		return t.Status4xx
	case status >= 500 && status < 600:
		return t.Status5xx
	default:
		return t.StatusOther
	}
}
