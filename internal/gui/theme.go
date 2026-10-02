package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type capTheme struct {
	fyne.Theme
}

func newCapTheme() fyne.Theme {
	return &capTheme{Theme: theme.DefaultTheme()}
}

func (t *capTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameForeground:
		if variant == theme.VariantLight {
			return color.NRGBA{R: 20, G: 20, B: 20, A: 255}
		}
		return color.NRGBA{R: 240, G: 240, B: 240, A: 255}

	case theme.ColorNameDisabled:
		if variant == theme.VariantLight {
			return color.NRGBA{R: 80, G: 80, B: 80, A: 255}
		}
		return color.NRGBA{R: 160, G: 160, B: 160, A: 255}

	case theme.ColorNamePlaceHolder:
		if variant == theme.VariantLight {
			return color.NRGBA{R: 100, G: 100, B: 100, A: 255}
		}
		return color.NRGBA{R: 150, G: 150, B: 150, A: 255}
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
