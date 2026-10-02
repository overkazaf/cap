package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type ThemeStyle int

const (
	ThemeDark ThemeStyle = iota
	ThemeLight
	ThemeMocha
	ThemeNord
)

var ThemeNames = []string{"Dark", "Light", "Mocha", "Nord"}

type capTheme struct {
	fyne.Theme
	style ThemeStyle
}

func newCapTheme() *capTheme {
	return &capTheme{Theme: theme.DefaultTheme(), style: ThemeDark}
}

func (t *capTheme) SetStyle(s ThemeStyle) {
	t.style = s
}

func (t *capTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	p := themePalettes[t.style]

	switch name {
	case theme.ColorNameForeground:
		return p.fg
	case theme.ColorNameBackground:
		return p.bg
	case theme.ColorNameButton:
		return p.button
	case theme.ColorNameDisabled:
		return p.disabled
	case theme.ColorNameDisabledButton:
		return p.disabledBtn
	case theme.ColorNamePlaceHolder:
		return p.placeholder
	case theme.ColorNamePrimary:
		return p.primary
	case theme.ColorNameFocus:
		return p.primary
	case theme.ColorNameSeparator:
		return p.separator
	case theme.ColorNameInputBackground:
		return p.inputBg
	case theme.ColorNameHeaderBackground:
		return p.headerBg
	case theme.ColorNameHover:
		return p.hover
	case theme.ColorNameSelection:
		return p.selection
	case theme.ColorNameSuccess:
		return p.success
	case theme.ColorNameError:
		return p.danger
	case theme.ColorNameWarning:
		return p.warning
	}

	return t.Theme.Color(name, variant)
}

func (t *capTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 13
	case theme.SizeNameSubHeadingText:
		return 15
	case theme.SizeNameHeadingText:
		return 18
	case theme.SizeNameCaptionText:
		return 11
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 4
	case theme.SizeNameLineSpacing:
		return 4
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius:
		return 6
	case theme.SizeNameSelectionRadius:
		return 4
	}
	return t.Theme.Size(name)
}

type palette struct {
	fg, bg, button, disabled, disabledBtn, placeholder color.Color
	primary, separator, inputBg, headerBg               color.Color
	hover, selection, success, danger, warning           color.Color
}

var themePalettes = map[ThemeStyle]palette{
	ThemeDark: {
		fg:          c(0xE4, 0xE4, 0xE7), // zinc-200
		bg:          c(0x18, 0x18, 0x1B), // zinc-900
		button:      c(0x27, 0x27, 0x2A), // zinc-800
		disabled:    c(0x71, 0x71, 0x7A), // zinc-500
		disabledBtn: c(0x27, 0x27, 0x2A),
		placeholder: c(0xA1, 0xA1, 0xAA), // zinc-400
		primary:     c(0x38, 0xBD, 0xF8), // sky-400
		separator:   c(0x2D, 0x2D, 0x30), // subtle line
		inputBg:     c(0x1F, 0x1F, 0x23),
		headerBg:    c(0x1C, 0x1C, 0x1F),
		hover:       ca(0x38, 0xBD, 0xF8, 0x1A), // sky-400/10%
		selection:   ca(0x38, 0xBD, 0xF8, 0x33), // sky-400/20%
		success:     c(0x22, 0xC5, 0x5E), // green-500
		danger:      c(0xEF, 0x44, 0x44), // red-500
		warning:     c(0xF5, 0x9E, 0x0B), // amber-500
	},
	ThemeLight: {
		fg:          c(0x18, 0x18, 0x1B), // zinc-900
		bg:          c(0xFA, 0xFA, 0xFA), // zinc-50
		button:      c(0xF4, 0xF4, 0xF5), // zinc-100
		disabled:    c(0xA1, 0xA1, 0xAA), // zinc-400
		disabledBtn: c(0xE4, 0xE4, 0xE7),
		placeholder: c(0x71, 0x71, 0x7A), // zinc-500
		primary:     c(0x0E, 0xA5, 0xE9), // sky-500
		separator:   c(0xE4, 0xE4, 0xE7), // zinc-200
		inputBg:     c(0xFF, 0xFF, 0xFF),
		headerBg:    c(0xF4, 0xF4, 0xF5),
		hover:       ca(0x0E, 0xA5, 0xE9, 0x14),
		selection:   ca(0x0E, 0xA5, 0xE9, 0x28),
		success:     c(0x16, 0xA3, 0x4A), // green-600
		danger:      c(0xDC, 0x26, 0x26), // red-600
		warning:     c(0xD9, 0x77, 0x06), // amber-600
	},
	ThemeMocha: {
		fg:          c(0xCD, 0xD6, 0xF4), // text
		bg:          c(0x1E, 0x1E, 0x2E), // base
		button:      c(0x31, 0x32, 0x44), // surface0
		disabled:    c(0x7F, 0x84, 0x9C), // overlay1
		disabledBtn: c(0x31, 0x32, 0x44),
		placeholder: c(0x93, 0x99, 0xB2), // overlay2
		primary:     c(0x89, 0xB4, 0xFA), // blue
		separator:   c(0x2B, 0x2B, 0x3C),
		inputBg:     c(0x24, 0x24, 0x36), // mantle
		headerBg:    c(0x18, 0x18, 0x25), // crust
		hover:       ca(0x89, 0xB4, 0xFA, 0x1A),
		selection:   ca(0x89, 0xB4, 0xFA, 0x33),
		success:     c(0xA6, 0xE3, 0xA1), // green
		danger:      c(0xF3, 0x8B, 0xA8), // red
		warning:     c(0xFA, 0xB3, 0x87), // peach
	},
	ThemeNord: {
		fg:          c(0xEC, 0xEF, 0xF4), // snow storm 3
		bg:          c(0x2E, 0x34, 0x40), // polar night 0
		button:      c(0x3B, 0x42, 0x52), // nord1
		disabled:    c(0x7B, 0x88, 0x9C),
		disabledBtn: c(0x3B, 0x42, 0x52),
		placeholder: c(0x9B, 0xA4, 0xB5),
		primary:     c(0x88, 0xC0, 0xD0), // frost 2
		separator:   c(0x3B, 0x42, 0x52),
		inputBg:     c(0x35, 0x3B, 0x49),
		headerBg:    c(0x2A, 0x2F, 0x3A),
		hover:       ca(0x88, 0xC0, 0xD0, 0x1A),
		selection:   ca(0x88, 0xC0, 0xD0, 0x33),
		success:     c(0xA3, 0xBE, 0x8C), // aurora green
		danger:      c(0xBF, 0x61, 0x6A), // aurora red
		warning:     c(0xEB, 0xCB, 0x8B), // aurora yellow
	},
}

func c(r, g, b uint8) color.Color {
	return color.NRGBA{R: r, G: g, B: b, A: 255}
}

func ca(r, g, b, a uint8) color.Color {
	return color.NRGBA{R: r, G: g, B: b, A: a}
}
