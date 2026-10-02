package gui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type termTab struct {
	session    *TermSession
	console    *widget.Entry
	tab        *container.TabItem
	inputStart int // byte offset where current input begins
}

func (tt *termTab) appendOutput(text string) {
	tt.console.SetText(tt.console.Text + text + "\n")
	tt.inputStart = len(tt.console.Text)
	lines := strings.Split(tt.console.Text, "\n")
	tt.console.CursorRow = len(lines) - 1
	tt.console.CursorColumn = len(lines[len(lines)-1])
}

func (tt *termTab) handleSubmit(text string) {
	input := ""
	if len(text) > tt.inputStart {
		input = text[tt.inputStart:]
	}
	input = strings.TrimRight(input, "\n")
	if input == "" {
		tt.session.Write("")
		return
	}
	tt.session.Write(input)
}

func NewTerminalTab(state *AppState, w fyne.Window) fyne.CanvasObject {
	tabs := container.NewDocTabs()
	tabIndex := 0
	var terms []*termTab

	addNewTerm := func() {
		tabIndex++
		label := fmt.Sprintf("sh-%d", tabIndex)

		console := widget.NewMultiLineEntry()
		console.TextStyle = fyne.TextStyle{Monospace: true}
		console.Wrapping = fyne.TextWrapBreak

		session, err := NewTermSession()
		if err != nil {
			console.SetText(fmt.Sprintf("$ [failed: %v]\n", err))
			console.Disable()
			tab := container.NewTabItem(label, console)
			tabs.Append(tab)
			tabs.Select(tab)
			return
		}

		tt := &termTab{
			session: session,
			console: console,
		}

		session.OnOutput = func(line string) {
			fyne.Do(func() {
				tt.appendOutput(line)
			})
		}

		session.OnExit = func() {
			fyne.Do(func() {
				tt.appendOutput("[session ended]")
				console.Disable()
			})
		}

		console.OnSubmitted = func(text string) {
			tt.handleSubmit(text)
		}

		tab := container.NewTabItem(label, console)
		tt.tab = tab

		terms = append(terms, tt)
		tabs.Append(tab)
		tabs.Select(tab)
	}

	tabs.CloseIntercept = func(item *container.TabItem) {
		for i, tt := range terms {
			if tt.tab == item {
				tt.session.Close()
				terms = append(terms[:i], terms[i+1:]...)
				break
			}
		}
		tabs.Remove(item)
	}

	newTabBtn := widget.NewButtonWithIcon("New Shell", theme.ContentAddIcon(), func() {
		addNewTerm()
	})
	newTabBtn.Importance = widget.HighImportance

	toolbar := container.NewHBox(
		widget.NewLabelWithStyle("TERMINAL", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		newTabBtn,
	)

	addNewTerm()

	return container.NewBorder(
		container.NewVBox(toolbar, widget.NewSeparator()),
		nil, nil, nil,
		tabs,
	)
}
