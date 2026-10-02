package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/overkazaf/cap/internal/store"
)

func Run(st store.Store) {
	a := app.New()
	capTheme := newCapTheme()
	a.Settings().SetTheme(capTheme)

	w := a.NewWindow("cap")
	w.Resize(fyne.NewSize(1400, 900))

	state := NewAppState(st)

	themeSelect := widget.NewSelect(ThemeNames, func(name string) {
		for i, n := range ThemeNames {
			if n == name {
				capTheme.SetStyle(ThemeStyle(i))
				a.Settings().SetTheme(capTheme)
				break
			}
		}
	})
	themeSelect.SetSelected("Dark")

	toolbar := container.NewHBox(
		widget.NewLabelWithStyle("cap", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		widget.NewSeparator(),
		layout.NewSpacer(),
		widget.NewLabel("Theme"),
		themeSelect,
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Capture", NewCaptureTab(state, w)),
		container.NewTabItem("Flows", NewFlowsTab(state, w)),
		container.NewTabItem("Terminal", NewTerminalTab(state, w)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	content := container.NewBorder(
		container.NewVBox(toolbar, widget.NewSeparator()),
		nil, nil, nil,
		tabs,
	)

	w.SetContent(content)
	w.ShowAndRun()
}
