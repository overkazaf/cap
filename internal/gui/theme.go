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
	case theme.ColorNamePlaceHolder:
		return p.placeholder
	case theme.ColorNamePrimary:
		return p.primary
	case theme.ColorNameSeparator:
		return p.separator
	case theme.ColorNameInputBackground:
		return p.inputBg
	case theme.ColorNameHeaderBackground:
		return p.headerBg
	}

	return t.Theme.Color(name, variant)
}

func (t *capTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 14
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameHeadingText:
		return 20
	}
	return t.Theme.Size(name)
}

type palette struct {
	fg, bg, button, disabled, placeholder, primary, separator, inputBg, headerBg color.Color
}

var themePalettes = map[ThemeStyle]palette{
	ThemeDark: {
		fg:          color.NRGBA{R: 230, G: 230, B: 230, A: 255},
		bg:          color.NRGBA{R: 30, G: 30, B: 35, A: 255},
		button:      color.NRGBA{R: 55, G: 55, B: 65, A: 255},
		disabled:    color.NRGBA{R: 120, G: 120, B: 130, A: 255},
		placeholder: color.NRGBA{R: 140, G: 140, B: 150, A: 255},
		primary:     color.NRGBA{R: 80, G: 160, B: 255, A: 255},
		separator:   color.NRGBA{R: 60, G: 60, B: 70, A: 255},
		inputBg:     color.NRGBA{R: 40, G: 40, B: 48, A: 255},
		headerBg:    color.NRGBA{R: 35, G: 35, B: 42, A: 255},
	},
	ThemeLight: {
		fg:          color.NRGBA{R: 20, G: 20, B: 25, A: 255},
		bg:          color.NRGBA{R: 248, G: 248, B: 250, A: 255},
		button:      color.NRGBA{R: 225, G: 225, B: 230, A: 255},
		disabled:    color.NRGBA{R: 130, G: 130, B: 140, A: 255},
		placeholder: color.NRGBA{R: 100, G: 100, B: 110, A: 255},
		primary:     color.NRGBA{R: 40, G: 120, B: 220, A: 255},
		separator:   color.NRGBA{R: 210, G: 210, B: 215, A: 255},
		inputBg:     color.NRGBA{R: 255, G: 255, B: 255, A: 255},
		headerBg:    color.NRGBA{R: 240, G: 240, B: 245, A: 255},
	},
	ThemeMocha: {
		fg:          color.NRGBA{R: 205, G: 214, B: 244, A: 255}, // Catppuccin text
		bg:          color.NRGBA{R: 30, G: 30, B: 46, A: 255},    // base
		button:      color.NRGBA{R: 49, G: 50, B: 68, A: 255},    // surface0
		disabled:    color.NRGBA{R: 127, G: 132, B: 156, A: 255}, // overlay1
		placeholder: color.NRGBA{R: 147, G: 153, B: 178, A: 255}, // overlay2
		primary:     color.NRGBA{R: 137, G: 180, B: 250, A: 255}, // blue
		separator:   color.NRGBA{R: 69, G: 71, B: 90, A: 255},    // surface1
		inputBg:     color.NRGBA{R: 36, G: 36, B: 54, A: 255},    // mantle
		headerBg:    color.NRGBA{R: 24, G: 24, B: 37, A: 255},    // crust
	},
	ThemeNord: {
		fg:          color.NRGBA{R: 216, G: 222, B: 233, A: 255}, // snow storm
		bg:          color.NRGBA{R: 46, G: 52, B: 64, A: 255},    // polar night
		button:      color.NRGBA{R: 59, G: 66, B: 82, A: 255},    // nord1
		disabled:    color.NRGBA{R: 127, G: 140, B: 160, A: 255},
		placeholder: color.NRGBA{R: 150, G: 160, B: 175, A: 255},
		primary:     color.NRGBA{R: 136, G: 192, B: 208, A: 255}, // frost
		separator:   color.NRGBA{R: 67, G: 76, B: 94, A: 255},    // nord2
		inputBg:     color.NRGBA{R: 53, G: 59, B: 72, A: 255},
		headerBg:    color.NRGBA{R: 40, G: 45, B: 56, A: 255},
	},
}
