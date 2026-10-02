package gui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/overkazaf/cap/internal/export/agent"
	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/types"
)

const (
	colID = iota
	colMethod
	colStatus
	colHost
	colPath
	colURL
	colLatency
	flowColumnCount
)

const maxBodyPreview = 256 * 1024

var flowColumnHeaders = [flowColumnCount]string{
	colID:      "ID",
	colMethod:  "Method",
	colStatus:  "Status",
	colHost:    "Host",
	colPath:    "Path",
	colURL:     "URL",
	colLatency: "Latency",
}

type flowsTab struct {
	state  *AppState
	window fyne.Window

	table *widget.Table
	flows []*types.Flow // full snapshot
	shown []*types.Flow // filtered view

	filterHost   *widget.Entry
	filterMethod *widget.Select
	filterSearch *widget.Entry

	selectedID  string
	selectedRow int

	detail          fyne.CanvasObject
	overviewForm    *widget.Form
	reqHeadersForm  *widget.Form
	respHeadersForm *widget.Form
	reqBody         *widget.Label
	respBody        *widget.Label

	exportLang   *widget.Select
	exportOutput *widget.Entry
}

func NewFlowsTab(state *AppState, w fyne.Window) fyne.CanvasObject {
	ft := &flowsTab{state: state, window: w}

	// --- Filter bar ---
	ft.filterHost = widget.NewEntry()
	ft.filterHost.SetPlaceHolder("Filter host...")
	ft.filterHost.OnChanged = func(_ string) { ft.applyFilter() }

	ft.filterMethod = widget.NewSelect([]string{"ALL", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}, nil)
	ft.filterMethod.SetSelected("ALL")

	ft.filterSearch = widget.NewEntry()
	ft.filterSearch.SetPlaceHolder("Search URL/body...")

	clearFilter := widget.NewButtonWithIcon("", theme.ContentClearIcon(), func() {
		ft.filterHost.SetText("")
		ft.filterMethod.SetSelected("ALL")
		ft.filterSearch.SetText("")
	})

	filterBar := container.New(layout.NewFormLayout(),
		widget.NewLabel("Host:"), ft.filterHost,
		widget.NewLabel("Method:"), ft.filterMethod,
		widget.NewLabel("Search:"), container.NewBorder(nil, nil, nil, clearFilter, ft.filterSearch),
	)

	// --- Table ---
	ft.table = widget.NewTable(
		func() (int, int) { return len(ft.shown), flowColumnCount },
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.Truncation = fyne.TextTruncateEllipsis
			return l
		},
		ft.updateCell,
	)
	ft.table.ShowHeaderRow = true
	ft.table.CreateHeader = func() fyne.CanvasObject {
		return widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	}
	ft.table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		text := ""
		if id.Col >= 0 && id.Col < flowColumnCount {
			text = flowColumnHeaders[id.Col]
		}
		o.(*widget.Label).SetText(text)
	}
	ft.table.SetColumnWidth(colID, 60)
	ft.table.SetColumnWidth(colMethod, 65)
	ft.table.SetColumnWidth(colStatus, 55)
	ft.table.SetColumnWidth(colHost, 150)
	ft.table.SetColumnWidth(colPath, 180)
	ft.table.SetColumnWidth(colURL, 300)
	ft.table.SetColumnWidth(colLatency, 70)
	ft.table.OnSelected = ft.onSelected

	// Wire filter callbacks now that table exists
	ft.filterHost.OnChanged = func(_ string) { ft.applyFilter() }
	ft.filterMethod.OnChanged = func(_ string) { ft.applyFilter() }
	ft.filterSearch.OnChanged = func(_ string) { ft.applyFilter() }

	// --- Detail + Export panel ---
	ft.buildDetailPanel()
	ft.showEmptyDetail()
	ft.refresh()

	prev := state.OnFlowsChanged
	state.OnFlowsChanged = func() {
		if prev != nil {
			prev()
		}
		fyne.Do(func() { ft.refresh() })
	}

	// --- Layout ---
	leftTop := container.NewVBox(
		widget.NewLabelWithStyle("Flows", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		filterBar,
		widget.NewSeparator(),
	)
	leftPanel := container.NewBorder(leftTop, nil, nil, nil, ft.table)

	split := container.NewHSplit(leftPanel, ft.detail)
	split.SetOffset(0.55)
	return split
}

func (ft *flowsTab) applyFilter() {
	host := strings.ToLower(strings.TrimSpace(ft.filterHost.Text))
	method := ft.filterMethod.Selected
	search := strings.ToLower(strings.TrimSpace(ft.filterSearch.Text))

	if host == "" && (method == "" || method == "ALL") && search == "" {
		ft.shown = ft.flows
	} else {
		var filtered []*types.Flow
		for _, f := range ft.flows {
			if host != "" && !strings.Contains(strings.ToLower(f.Host), host) {
				continue
			}
			if method != "" && method != "ALL" && !strings.EqualFold(f.Method, method) {
				continue
			}
			if search != "" {
				haystack := strings.ToLower(f.URL) + strings.ToLower(string(f.ReqBody))
				if !strings.Contains(haystack, search) {
					continue
				}
			}
			filtered = append(filtered, f)
		}
		ft.shown = filtered
	}
	ft.table.Refresh()
}

func (ft *flowsTab) refresh() {
	ft.flows = ft.state.GetFlows()
	ft.applyFilter()

	if ft.selectedID == "" {
		return
	}
	for i, f := range ft.shown {
		if f.ID == ft.selectedID {
			if i != ft.selectedRow {
				ft.table.UnselectAll()
				ft.selectedRow = i
			}
			ft.showDetail(f)
			return
		}
	}
	ft.table.UnselectAll()
	ft.showEmptyDetail()
}

func (ft *flowsTab) onSelected(id widget.TableCellID) {
	if id.Row < 0 || id.Row >= len(ft.shown) {
		return
	}
	ft.selectedRow = id.Row
	ft.showDetail(ft.shown[id.Row])
}

func (ft *flowsTab) updateCell(id widget.TableCellID, o fyne.CanvasObject) {
	label := o.(*widget.Label)
	if id.Row < 0 || id.Row >= len(ft.shown) {
		label.Importance = widget.MediumImportance
		label.SetText("")
		return
	}

	f := ft.shown[id.Row]
	label.Importance = widget.MediumImportance

	var text string
	switch id.Col {
	case colID:
		text = f.ID
	case colMethod:
		text = f.Method
	case colStatus:
		text = statusText(f.Status)
		label.Importance = statusImportance(f.Status)
	case colHost:
		text = f.Host
	case colPath:
		text = f.Path
	case colURL:
		text = f.URL
	case colLatency:
		text = fmt.Sprintf("%dms", f.LatencyMs)
	}
	label.SetText(text)
}

func (ft *flowsTab) buildDetailPanel() {
	ft.overviewForm = widget.NewForm()
	ft.reqHeadersForm = widget.NewForm()
	ft.respHeadersForm = widget.NewForm()
	ft.reqBody = newBodyLabel()
	ft.respBody = newBodyLabel()

	detailTabs := container.NewAppTabs(
		container.NewTabItem("Req Headers", container.NewVScroll(ft.reqHeadersForm)),
		container.NewTabItem("Req Body", container.NewVScroll(ft.reqBody)),
		container.NewTabItem("Resp Headers", container.NewVScroll(ft.respHeadersForm)),
		container.NewTabItem("Resp Body", container.NewVScroll(ft.respBody)),
	)

	// --- Export section (inline) ---
	langs := []string{"cURL", "Python", "Go", "Java", "JavaScript", "Agent JSONL"}
	ft.exportLang = widget.NewSelect(langs, nil)
	ft.exportLang.SetSelected("cURL")

	ft.exportOutput = widget.NewMultiLineEntry()
	ft.exportOutput.TextStyle = fyne.TextStyle{Monospace: true}
	ft.exportOutput.Wrapping = fyne.TextWrapBreak

	generateBtn := widget.NewButtonWithIcon("Generate", theme.MediaPlayIcon(), func() {
		ft.generateExport()
	})
	generateBtn.Importance = widget.HighImportance

	copyBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		if ft.exportOutput.Text != "" {
			ft.window.Clipboard().SetContent(ft.exportOutput.Text)
		}
	})

	exportBar := container.NewHBox(
		widget.NewLabel("Export:"),
		ft.exportLang,
		generateBtn,
		copyBtn,
	)

	exportSection := container.NewBorder(exportBar, nil, nil, nil, ft.exportOutput)

	// Detail: overview on top, tabs in middle, export at bottom (split)
	topDetail := container.NewVBox(ft.overviewForm, widget.NewSeparator())
	bottomSplit := container.NewVSplit(detailTabs, exportSection)
	bottomSplit.SetOffset(0.55)

	ft.detail = container.NewBorder(topDetail, nil, nil, nil, bottomSplit)
}

func (ft *flowsTab) generateExport() {
	langLabel := ft.exportLang.Selected
	langKeys := map[string]string{
		"cURL": "curl", "Python": "python", "Go": "go",
		"Java": "java", "JavaScript": "js",
	}

	if langLabel == "Agent JSONL" {
		flows := ft.state.GetFlows()
		if len(flows) == 0 {
			ft.exportOutput.SetText("(no flows captured)")
			return
		}
		out, err := agent.Format(flows, agent.FormatOptions{})
		if err != nil {
			ft.exportOutput.SetText(fmt.Sprintf("Error: %v", err))
			return
		}
		ft.exportOutput.SetText(string(out))
		return
	}

	if ft.selectedID == "" {
		ft.exportOutput.SetText("(select a flow first)")
		return
	}
	f := ft.state.GetFlow(ft.selectedID)
	if f == nil {
		ft.exportOutput.SetText("(flow not found)")
		return
	}
	key := langKeys[langLabel]
	out, err := codegen.Generate(f, key)
	if err != nil {
		ft.exportOutput.SetText(fmt.Sprintf("Error: %v", err))
		return
	}
	ft.exportOutput.SetText(out)
}

func (ft *flowsTab) showDetail(f *types.Flow) {
	ft.selectedID = f.ID

	ft.overviewForm.Items = overviewItems(f)
	ft.overviewForm.Refresh()

	ft.reqHeadersForm.Items = headerItems(f.ReqHeaders)
	ft.reqHeadersForm.Refresh()
	ft.reqBody.SetText(formatBody(f.ReqBody, f.ReqBodyType))

	ft.respHeadersForm.Items = headerItems(f.RespHeaders)
	ft.respHeadersForm.Refresh()
	ft.respBody.SetText(formatBody(f.RespBody, f.RespBodyType))

	// auto-generate export for selected flow
	ft.generateExport()
}

func (ft *flowsTab) showEmptyDetail() {
	ft.selectedID = ""
	ft.selectedRow = -1

	ft.overviewForm.Items = []*widget.FormItem{
		widget.NewFormItem("", newWrappingLabel("Select a flow to see details and export code.")),
	}
	ft.overviewForm.Refresh()

	ft.reqHeadersForm.Items = emptyFormItems()
	ft.reqHeadersForm.Refresh()
	ft.reqBody.SetText("")

	ft.respHeadersForm.Items = emptyFormItems()
	ft.respHeadersForm.Refresh()
	ft.respBody.SetText("")

	ft.exportOutput.SetText("")
}

func emptyFormItems() []*widget.FormItem {
	return []*widget.FormItem{widget.NewFormItem("", newWrappingLabel("-"))}
}

func overviewItems(f *types.Flow) []*widget.FormItem {
	items := []*widget.FormItem{
		widget.NewFormItem("Method", newWrappingLabel(f.Method)),
		widget.NewFormItem("URL", newWrappingLabel(f.URL)),
		widget.NewFormItem("Status", newStatusLabel(f.Status)),
		widget.NewFormItem("Latency", newWrappingLabel(fmt.Sprintf("%d ms", f.LatencyMs))),
		widget.NewFormItem("Time", newWrappingLabel(f.Timestamp.Format("2006-01-02 15:04:05.000"))),
	}
	if len(f.Tags) > 0 {
		items = append(items, widget.NewFormItem("Tags", newWrappingLabel(strings.Join(f.Tags, ", "))))
	}
	if len(f.SignParams) > 0 {
		items = append(items, widget.NewFormItem("Sign Params", newWrappingLabel(strings.Join(f.SignParams, ", "))))
	}
	if f.SourceRef != nil {
		items = append(items, sourceRefItems(f.SourceRef)...)
	}
	return items
}

func sourceRefItems(ref *types.SourceRef) []*widget.FormItem {
	loc := ref.File
	if ref.Line > 0 {
		loc = fmt.Sprintf("%s:%d", ref.File, ref.Line)
	}
	items := []*widget.FormItem{
		widget.NewFormItem("Source File", newWrappingLabel(loc)),
	}
	if ref.Class != "" {
		items = append(items, widget.NewFormItem("Source Class", newWrappingLabel(ref.Class)))
	}
	if ref.Method != "" {
		items = append(items, widget.NewFormItem("Source Method", newWrappingLabel(ref.Method)))
	}
	if ref.SignFunc != "" {
		items = append(items, widget.NewFormItem("Sign Func", newWrappingLabel(ref.SignFunc)))
	}
	if ref.Algorithm != "" {
		items = append(items, widget.NewFormItem("Algorithm", newWrappingLabel(ref.Algorithm)))
	}
	return items
}

func headerItems(h map[string]string) []*widget.FormItem {
	if len(h) == 0 {
		return []*widget.FormItem{widget.NewFormItem("", newWrappingLabel("(no headers)"))}
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	items := make([]*widget.FormItem, 0, len(keys))
	for _, k := range keys {
		items = append(items, widget.NewFormItem(k, newWrappingLabel(h[k])))
	}
	return items
}

func formatBody(body []byte, contentType string) string {
	if len(body) == 0 {
		return "(empty body)"
	}

	truncated := false
	if len(body) > maxBodyPreview {
		body = body[:maxBodyPreview]
		truncated = true
	}

	text := string(body)
	if strings.Contains(strings.ToLower(contentType), "json") {
		var buf bytes.Buffer
		if err := json.Indent(&buf, body, "", "  "); err == nil {
			text = buf.String()
		}
	}
	if truncated {
		text += "\n\n... (truncated)"
	}
	return text
}

func statusText(status int) string {
	if status <= 0 {
		return "-"
	}
	return strconv.Itoa(status)
}

func statusImportance(status int) widget.Importance {
	switch {
	case status >= 500:
		return widget.DangerImportance
	case status >= 400:
		return widget.WarningImportance
	default:
		return widget.MediumImportance
	}
}

func newStatusLabel(status int) *widget.Label {
	l := widget.NewLabel(statusText(status))
	l.Importance = statusImportance(status)
	return l
}

func newWrappingLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Wrapping = fyne.TextWrapBreak
	l.Selectable = true
	return l
}

func newBodyLabel() *widget.Label {
	l := widget.NewLabel("")
	l.Wrapping = fyne.TextWrapBreak
	l.TextStyle = fyne.TextStyle{Monospace: true}
	l.Selectable = true
	return l
}
