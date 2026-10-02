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
	"fyne.io/fyne/v2/widget"

	"github.com/overkazaf/cap/internal/types"
)

// Flow table column indices.
const (
	colID = iota
	colMethod
	colStatus
	colHost
	colPath
	colLatency
	flowColumnCount
)

// maxBodyPreview caps how many raw bytes of a request/response body are
// rendered in the detail panel, so a large (e.g. binary) payload can't
// freeze the UI thread with an enormous label.
const maxBodyPreview = 256 * 1024

var flowColumnHeaders = [flowColumnCount]string{
	colID:      "ID",
	colMethod:  "Method",
	colStatus:  "Status",
	colHost:    "Host",
	colPath:    "Path",
	colLatency: "Latency",
}

// flowsTab owns the widgets and in-memory state backing the Flows list tab:
// a table of captured flows on the left, and a detail panel for whichever
// flow is currently selected on the right.
type flowsTab struct {
	state *AppState

	table *widget.Table

	// flows is a snapshot of state.GetFlows(), rebuilt on every refresh.
	// It is only ever read or written from the Fyne UI goroutine: the
	// initial build happens before the window is shown, and later updates
	// are marshalled onto the UI goroutine via fyne.Do in the
	// OnFlowsChanged handler.
	flows []*types.Flow

	selectedID  string // ID of the flow shown in the detail panel, "" if none
	selectedRow int    // row currently highlighted in the table for selectedID

	detail          fyne.CanvasObject
	overviewForm    *widget.Form
	reqHeadersForm  *widget.Form
	respHeadersForm *widget.Form
	reqBody         *widget.Label
	respBody        *widget.Label
}

// NewFlowsTab builds the Flows list tab: an HSplit with a table of captured
// flows on the left (60%) and a detail panel for the selected flow on the
// right (40%). The table refreshes automatically whenever
// state.OnFlowsChanged fires.
func NewFlowsTab(state *AppState, w fyne.Window) fyne.CanvasObject {
	ft := &flowsTab{state: state}

	ft.table = widget.NewTable(
		func() (int, int) { return len(ft.flows), flowColumnCount },
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
	ft.table.SetColumnWidth(colID, 70)
	ft.table.SetColumnWidth(colMethod, 70)
	ft.table.SetColumnWidth(colStatus, 60)
	ft.table.SetColumnWidth(colHost, 160)
	ft.table.SetColumnWidth(colPath, 220)
	ft.table.SetColumnWidth(colLatency, 80)
	ft.table.OnSelected = ft.onSelected

	ft.buildDetailPanel()
	ft.showEmptyDetail()
	ft.refresh()

	// Chain onto any callback that may already be registered rather than
	// clobbering it, and hop onto the Fyne UI goroutine since flows can
	// arrive from the proxy's own capture goroutine.
	prev := state.OnFlowsChanged
	state.OnFlowsChanged = func() {
		if prev != nil {
			prev()
		}
		fyne.Do(func() { ft.refresh() })
	}

	split := container.NewHSplit(ft.table, ft.detail)
	split.SetOffset(0.6)
	return split
}

// refresh reloads the flow snapshot from state and updates both the table
// and, if the previously selected flow still exists, the detail panel.
//
// New flows are prepended by AppState, so the row index of an already
// selected flow shifts every time a new one arrives. Table.Select would
// fix the highlight but also scrolls to it, which would fight the user's
// scroll position during live capture; so instead, when the index has
// drifted, the stale highlight is simply cleared with UnselectAll (which
// does not scroll) rather than left pointing at the wrong row.
func (ft *flowsTab) refresh() {
	ft.flows = ft.state.GetFlows()
	ft.table.Refresh()

	if ft.selectedID == "" {
		return
	}
	for i, f := range ft.flows {
		if f.ID == ft.selectedID {
			if i != ft.selectedRow {
				ft.table.UnselectAll()
				ft.selectedRow = i
			}
			ft.showDetail(f)
			return
		}
	}
	// The previously selected flow is gone (e.g. ClearFlows) - reset.
	ft.table.UnselectAll()
	ft.showEmptyDetail()
}

func (ft *flowsTab) onSelected(id widget.TableCellID) {
	if id.Row < 0 || id.Row >= len(ft.flows) {
		return
	}
	ft.selectedRow = id.Row
	ft.showDetail(ft.flows[id.Row])
}

func (ft *flowsTab) updateCell(id widget.TableCellID, o fyne.CanvasObject) {
	label := o.(*widget.Label)
	if id.Row < 0 || id.Row >= len(ft.flows) {
		label.Importance = widget.MediumImportance
		label.SetText("")
		return
	}

	f := ft.flows[id.Row]
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
	case colLatency:
		text = fmt.Sprintf("%d ms", f.LatencyMs)
	}
	label.SetText(text)
}

// buildDetailPanel constructs the right-hand detail widgets: a summary form
// at the top, plus tabs for request/response headers and bodies below it.
func (ft *flowsTab) buildDetailPanel() {
	ft.overviewForm = widget.NewForm()
	ft.reqHeadersForm = widget.NewForm()
	ft.respHeadersForm = widget.NewForm()
	ft.reqBody = newBodyLabel()
	ft.respBody = newBodyLabel()

	tabs := container.NewAppTabs(
		container.NewTabItem("Request Headers", container.NewVScroll(ft.reqHeadersForm)),
		container.NewTabItem("Request Body", container.NewVScroll(ft.reqBody)),
		container.NewTabItem("Response Headers", container.NewVScroll(ft.respHeadersForm)),
		container.NewTabItem("Response Body", container.NewVScroll(ft.respBody)),
	)

	ft.detail = container.NewBorder(ft.overviewForm, nil, nil, nil, tabs)
}

// showDetail populates the detail panel with the given flow.
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
}

// showEmptyDetail resets the detail panel to its no-selection placeholder.
func (ft *flowsTab) showEmptyDetail() {
	ft.selectedID = ""
	ft.selectedRow = -1

	ft.overviewForm.Items = []*widget.FormItem{
		widget.NewFormItem("", newWrappingLabel("Select a flow on the left to see its details.")),
	}
	ft.overviewForm.Refresh()

	ft.reqHeadersForm.Items = emptyFormItems()
	ft.reqHeadersForm.Refresh()
	ft.reqBody.SetText("")

	ft.respHeadersForm.Items = emptyFormItems()
	ft.respHeadersForm.Refresh()
	ft.respBody.SetText("")
}

func emptyFormItems() []*widget.FormItem {
	return []*widget.FormItem{widget.NewFormItem("", newWrappingLabel("-"))}
}

// overviewItems builds the summary rows shown above the detail tabs: core
// flow metadata, plus tags, sign params and source reference when present.
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

// sourceRefItems renders the optional static-analysis source reference
// attached to a flow: which file/class/method produced the request, and how
// it was signed, if known.
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

// headerItems renders an HTTP header map as sorted key/value form rows, so
// the display order is stable across refreshes.
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

// formatBody renders a request/response body for display: pretty-printed if
// it looks like JSON, truncated if it's unreasonably large, and a
// placeholder if empty.
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
		text += "\n\n... (truncated, body exceeds preview limit)"
	}
	return text
}

// statusText renders a flow's HTTP status, or "-" if no response was ever
// recorded for it.
func statusText(status int) string {
	if status <= 0 {
		return "-"
	}
	return strconv.Itoa(status)
}

// statusImportance color-codes an HTTP status: 5xx red (danger), 4xx orange
// (warning), everything else - including no response yet - normal.
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

// newWrappingLabel builds a selectable label that wraps long values (header
// values, URLs, source file paths, etc.) instead of overflowing the panel.
func newWrappingLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Wrapping = fyne.TextWrapBreak
	l.Selectable = true
	return l
}

// newBodyLabel builds a selectable, monospace, wrapping label used to
// display request/response bodies.
func newBodyLabel() *widget.Label {
	l := widget.NewLabel("")
	l.Wrapping = fyne.TextWrapBreak
	l.TextStyle = fyne.TextStyle{Monospace: true}
	l.Selectable = true
	return l
}
