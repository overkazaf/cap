package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"

	"github.com/overkazaf/cap/internal/store"
)

func Run(st store.Store) {
	a := app.New()
	a.Settings().SetTheme(newCapTheme())
	w := a.NewWindow("Cap - Packet Capture for Reverse Engineering")
	w.Resize(fyne.NewSize(1200, 800))

	state := NewAppState(st)

	tabs := container.NewAppTabs(
		container.NewTabItem("Proxy", NewProxyTab(state, w)),
		container.NewTabItem("Flows", NewFlowsTab(state, w)),
		container.NewTabItem("Export", NewExportTab(state, w)),
		container.NewTabItem("Android", NewAndroidTab(state, w)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	w.SetContent(tabs)
	w.ShowAndRun()
}
