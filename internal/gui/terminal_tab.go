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
	session *TermSession
	output  *widget.Entry
	input   *widget.Entry
	tab     *container.TabItem
}

func NewTerminalTab(state *AppState, w fyne.Window) fyne.CanvasObject {
	tabs := container.NewDocTabs()
	tabIndex := 0
	var terms []*termTab

	addNewTerm := func() {
		tabIndex++
		label := fmt.Sprintf("Shell %d", tabIndex)

		output := widget.NewMultiLineEntry()
		output.TextStyle = fyne.TextStyle{Monospace: true}
		output.Wrapping = fyne.TextWrapBreak
		output.Disable()

		input := widget.NewEntry()
		input.SetPlaceHolder("cap$ type command and press Enter...")
		input.TextStyle = fyne.TextStyle{Monospace: true}

		session, err := NewTermSession()
		if err != nil {
			output.SetText(fmt.Sprintf("[failed to start shell: %v]", err))
			tab := container.NewTabItem(label, container.NewBorder(nil, input, nil, nil, output))
			tabs.Append(tab)
			tabs.Select(tab)
			return
		}

		tt := &termTab{
			session: session,
			output:  output,
			input:   input,
		}

		session.OnOutput = func(line string) {
			fyne.Do(func() {
				if output.Text == "" {
					output.SetText(line)
				} else {
					output.SetText(output.Text + "\n" + line)
				}
				lines := strings.Split(output.Text, "\n")
				output.CursorRow = len(lines) - 1
			})
		}

		session.OnExit = func() {
			fyne.Do(func() {
				output.SetText(output.Text + "\n[session ended]")
				input.SetPlaceHolder("[session ended]")
				input.Disable()
			})
		}

		input.OnSubmitted = func(text string) {
			text = strings.TrimSpace(text)
			if text == "" {
				return
			}
			input.SetText("")
			session.Write(text)
		}

		tab := container.NewTabItem(label,
			container.NewBorder(nil, input, nil, nil, output),
		)
		tt.tab = tab

		terms = append(terms, tt)
		tabs.Append(tab)
		tabs.Select(tab)

		input.FocusGained()
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
		widget.NewLabelWithStyle("Terminal", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		newTabBtn,
	)

	// Start with one shell tab
	addNewTerm()

	return container.NewBorder(
		container.NewVBox(toolbar, widget.NewSeparator()),
		nil, nil, nil,
		tabs,
	)
}
