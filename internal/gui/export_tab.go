package gui

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/overkazaf/cap/internal/export/agent"
	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/types"
)

// agentJSONLLabel is the radio option that exports every captured flow as
// compact agent/LLM-friendly JSONL via the agent package, rather than
// rendering a single flow through codegen.
const agentJSONLLabel = "Agent JSONL"

// languageOptions lists the radio button labels in display order.
// agentJSONLLabel is included here but has no entry in languageKeys since it
// is handled separately from codegen.Generate.
var languageOptions = []string{"cURL", "Python", "Go", "Java", "JavaScript", agentJSONLLabel}

// languageKeys maps a radio label to the language identifier codegen.Generate
// expects (see codegen.Languages).
var languageKeys = map[string]string{
	"cURL":       "curl",
	"Python":     "python",
	"Go":         "go",
	"Java":       "java",
	"JavaScript": "js",
}

// NewExportTab builds the Export tab: pick a captured flow and a target
// language, render a runnable code snippet (or, for "Agent JSONL", a compact
// JSONL dump of every captured flow), and copy the result to the clipboard.
func NewExportTab(state *AppState, w fyne.Window) fyne.CanvasObject {
	var (
		flowByLabel  map[string]*types.Flow
		selectedFlow *types.Flow
	)

	// Code output area. Disabled gives it a read-only feel (typing and
	// pasting are blocked) while still allowing the user to select text and
	// copy it manually via the right-click menu, in addition to the Copy
	// button below.
	output := widget.NewMultiLineEntry()
	output.TextStyle = fyne.TextStyle{Monospace: true}
	output.PlaceHolder = "Generated code will appear here..."
	output.Disable()

	status := widget.NewLabel("")
	showError := func(err error) {
		status.Importance = widget.DangerImportance
		status.SetText(err.Error())
	}
	showStatus := func(format string, args ...any) {
		status.Importance = widget.MediumImportance
		status.SetText(fmt.Sprintf(format, args...))
	}

	// Flow selector. flowByLabel maps each dropdown entry back to its Flow;
	// labels are unique because every one is prefixed with its (unique) flow
	// ID, e.g. "f1 - POST /api/login 200".
	flowSelect := widget.NewSelect(nil, func(label string) {
		selectedFlow = flowByLabel[label]
	})
	flowSelect.PlaceHolder = "Select a flow..."

	refreshFlows := func() {
		flows := state.GetFlows()
		labels := make([]string, 0, len(flows))
		byLabel := make(map[string]*types.Flow, len(flows))
		for _, f := range flows {
			if f == nil {
				continue
			}
			label := flowLabel(f)
			labels = append(labels, label)
			byLabel[label] = f
		}
		flowByLabel = byLabel

		flowSelect.SetOptions(labels)
		if f, ok := byLabel[flowSelect.Selected]; ok {
			// Keep the current selection (now possibly backed by a fresher
			// *Flow instance) if it's still present in the new flow list.
			selectedFlow = f
		} else {
			selectedFlow = nil
			flowSelect.ClearSelected()
		}
	}

	// Chain any previously-registered OnFlowsChanged hook rather than
	// clobbering it, and dispatch onto the Fyne main loop: AddFlow/ClearFlows
	// (and therefore OnFlowsChanged) are expected to be driven by a capture
	// loop draining AppState.FlowCh on its own goroutine, and Fyne widgets
	// must only be mutated from the main thread.
	prevOnFlowsChanged := state.OnFlowsChanged
	state.OnFlowsChanged = func() {
		if prevOnFlowsChanged != nil {
			prevOnFlowsChanged()
		}
		fyne.Do(refreshFlows)
	}
	refreshFlows()

	// Language selector.
	selectedLang := languageOptions[0]
	langRadio := widget.NewRadioGroup(languageOptions, func(label string) {
		selectedLang = label
	})
	langRadio.Horizontal = true
	langRadio.SetSelected(selectedLang)

	generateBtn := widget.NewButton("Generate", func() {
		if selectedLang == agentJSONLLabel {
			// Agent JSONL always exports every captured flow, regardless of
			// which flow (if any) is selected in the dropdown above.
			flows := state.GetFlows()
			if len(flows) == 0 {
				showError(fmt.Errorf("no captured flows to export"))
				return
			}
			out, err := agent.Format(flows, agent.FormatOptions{})
			if err != nil {
				showError(fmt.Errorf("format agent JSONL: %w", err))
				return
			}
			output.SetText(string(out))
			showStatus("Exported %d flow(s) as Agent JSONL", len(flows))
			return
		}

		if selectedFlow == nil {
			showError(fmt.Errorf("select a flow to export first"))
			return
		}

		lang, ok := languageKeys[selectedLang]
		if !ok {
			showError(fmt.Errorf("select a language first"))
			return
		}

		code, err := codegen.Generate(selectedFlow, lang)
		if err != nil {
			showError(fmt.Errorf("generate %s: %w", selectedLang, err))
			return
		}
		output.SetText(code)
		showStatus("Generated %s for flow %s", selectedLang, selectedFlow.ID)
	})
	generateBtn.Importance = widget.HighImportance

	copyBtn := widget.NewButton("Copy", func() {
		if output.Text == "" {
			return
		}
		w.Clipboard().SetContent(output.Text)
		showStatus("Copied to clipboard")
	})

	top := container.NewVBox(
		container.NewBorder(nil, nil, widget.NewLabel("Flow:"), nil, flowSelect),
		widget.NewSeparator(),
		widget.NewLabel("Language:"),
		langRadio,
		generateBtn,
	)
	bottom := container.NewBorder(nil, nil, nil, copyBtn, status)

	return container.NewBorder(top, bottom, nil, nil, output)
}

// flowLabel renders a one-line, human-readable description of a flow for the
// flow picker, e.g. "f1 - POST /api/login 200". It is prefixed with the
// flow's ID so every label is guaranteed unique.
func flowLabel(f *types.Flow) string {
	loc := f.Path
	if loc == "" {
		loc = f.URL
	}
	return fmt.Sprintf("%s - %s %s %d", f.ID, f.Method, loc, f.Status)
}
