package gui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/types"
)

// defaultProxyAddr pre-fills the listen-address field when the tab is built.
const defaultProxyAddr = "127.0.0.1:8080"

// NewProxyTab builds the "Proxy" tab: address/cert-dir configuration, a
// start/stop/clear control row, a status bar, and a live-scrolling log of
// every flow captured by the running proxy.
func NewProxyTab(state *AppState, w fyne.Window) fyne.CanvasObject {
	certDir := DefaultCertDir()

	certDirDisplay := certDir
	if _, _, err := proxy.EnsureCA(certDir); err != nil {
		// Surface the problem in the config section rather than failing tab
		// construction outright — the user can still see/edit the address
		// and will get the same error again (via the Start button) once
		// they've fixed e.g. a permissions issue.
		certDirDisplay = fmt.Sprintf("%s (warning: %v)", certDir, err)
	}

	// --- Config section --------------------------------------------------

	addrEntry := widget.NewEntry()
	addrEntry.SetText(defaultProxyAddr)
	addrEntry.SetPlaceHolder(defaultProxyAddr)

	certDirLabel := widget.NewLabel(certDirDisplay)
	certDirLabel.Wrapping = fyne.TextWrapBreak

	configForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Address:"), addrEntry,
		widget.NewLabel("Cert dir:"), certDirLabel,
	)

	// --- Live flow log -----------------------------------------------------

	logContent := widget.NewLabel("")
	logContent.Wrapping = fyne.TextWrapWord
	logScroll := container.NewVScroll(logContent)
	logScroll.SetMinSize(fyne.NewSize(0, 320))

	var logLines []string
	appendLog := func(line string) {
		logLines = append(logLines, line)
		logContent.SetText(strings.Join(logLines, "\n"))
		logScroll.ScrollToBottom()
	}

	// --- Status bar & control buttons ---------------------------------

	statusLabel := widget.NewLabel("Stopped")
	setStatus := func(text string, importance widget.Importance) {
		statusLabel.Text = text
		statusLabel.Importance = importance
		statusLabel.Refresh()
	}

	var toggleBtn *widget.Button

	// setStoppedUI resets all widgets (and AppState) to the "not running"
	// state. Safe to call from the main goroutine only — callers from a
	// background goroutine must wrap the call in fyne.Do.
	setStoppedUI := func(status string) {
		state.IsRunning = false
		state.Proxy = nil

		addrEntry.Enable()
		toggleBtn.SetText("Start")
		toggleBtn.SetIcon(theme.MediaPlayIcon())
		toggleBtn.Importance = widget.SuccessImportance
		toggleBtn.Refresh()

		setStatus(status, widget.MediumImportance)
	}

	// setRunningUI mirrors setStoppedUI for the "running" state. Same
	// main-goroutine-only contract.
	setRunningUI := func(addr string) {
		state.IsRunning = true

		addrEntry.Disable()
		toggleBtn.SetText("Stop")
		toggleBtn.SetIcon(theme.MediaStopIcon())
		toggleBtn.Importance = widget.DangerImportance
		toggleBtn.Refresh()

		setStatus(fmt.Sprintf("Running on %s", addr), widget.SuccessImportance)
	}

	startProxy := func() {
		addr := strings.TrimSpace(addrEntry.Text)
		if addr == "" {
			addr = defaultProxyAddr
		}

		p, err := proxy.New(proxy.Options{
			Addr:    addr,
			CertDir: certDir,
			OnFlow: func(f *types.Flow) {
				// OnFlow runs on whichever goroutine is handling that
				// in-flight request, never the UI goroutine, and may be
				// called concurrently for multiple requests — so every
				// widget mutation below is funneled through fyne.Do.
				// Store.SaveFlow itself touches no UI and is documented
				// (via Options.OnFlow) to be safe to call concurrently,
				// so it runs directly on the caller's goroutine.
				saveErr := state.Store.SaveFlow(f)
				fyne.Do(func() {
					appendLog(formatFlowLine(f))
					if saveErr != nil {
						appendLog(fmt.Sprintf("[%s] store error: %v", f.ID, saveErr))
					}
					state.AddFlow(f)
				})
			},
		})
		if err != nil {
			setStatus(fmt.Sprintf("Error: %v", err), widget.DangerImportance)
			appendLog(fmt.Sprintf("--- failed to start proxy: %v ---", err))
			return
		}

		state.Proxy = p
		setRunningUI(p.Addr())
		appendLog(fmt.Sprintf("--- proxy started on %s ---", p.Addr()))

		// Start blocks until Stop is called (or the listener fails), so it
		// must run on its own goroutine. Any widget touch from in here
		// goes through fyne.Do since this isn't the UI goroutine.
		go func() {
			if err := p.Start(); err != nil {
				fyne.Do(func() {
					appendLog(fmt.Sprintf("--- proxy error: %v ---", err))
					setStoppedUI(fmt.Sprintf("Error: %v", err))
				})
			}
		}()
	}

	stopProxy := func() {
		p := state.Proxy
		if p == nil {
			return
		}
		if err := p.Stop(); err != nil {
			appendLog(fmt.Sprintf("--- error stopping proxy: %v ---", err))
		}
		appendLog("--- proxy stopped ---")
		setStoppedUI("Stopped")
	}

	toggleBtn = widget.NewButtonWithIcon("Start", theme.MediaPlayIcon(), func() {
		if state.IsRunning {
			stopProxy()
		} else {
			startProxy()
		}
	})
	toggleBtn.Importance = widget.SuccessImportance

	clearBtn := widget.NewButtonWithIcon("Clear", theme.ContentClearIcon(), func() {
		logLines = nil
		logContent.SetText("")
	})

	controls := container.NewHBox(toggleBtn, clearBtn)

	// --- Layout ------------------------------------------------------------

	top := container.NewVBox(
		widget.NewLabelWithStyle("Proxy Control", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		configForm,
		controls,
		widget.NewSeparator(),
		statusLabel,
		widget.NewSeparator(),
	)

	return container.NewBorder(top, nil, nil, nil, logScroll)
}

// formatFlowLine renders a single captured flow as one line of the live log,
// e.g. "[f1] POST https://api.com/login → 200 (120ms)".
func formatFlowLine(f *types.Flow) string {
	return fmt.Sprintf("[%s] %s %s → %d (%dms)", f.ID, f.Method, f.URL, f.Status, f.LatencyMs)
}

// defaultCertDir returns the directory holding cap's MITM CA
