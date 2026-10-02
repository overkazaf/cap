package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/types"
)

const defaultAddr = "0.0.0.0:8080"

func NewCaptureTab(state *AppState, w fyne.Window) fyne.CanvasObject {
	certDir := DefaultCertDir()
	proxy.EnsureCA(certDir)

	// --- Log ---
	logContent := widget.NewLabel("")
	logContent.Wrapping = fyne.TextWrapWord
	logContent.TextStyle = fyne.TextStyle{Monospace: true}
	logScroll := container.NewVScroll(logContent)

	var logLines []string
	appendLog := func(format string, args ...any) {
		line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
		logLines = append(logLines, line)
		if len(logLines) > 500 {
			logLines = logLines[len(logLines)-500:]
		}
		logContent.SetText(strings.Join(logLines, "\n"))
		logScroll.ScrollToBottom()
	}

	// ==================== Proxy ====================
	addrEntry := widget.NewEntry()
	addrEntry.SetText(defaultAddr)
	addrEntry.TextStyle = fyne.TextStyle{Monospace: true}

	statusLabel := widget.NewLabel("Stopped")
	statusLabel.TextStyle = fyne.TextStyle{Monospace: true}

	var toggleBtn *widget.Button

	startProxy := func() {
		addr := strings.TrimSpace(addrEntry.Text)
		if addr == "" {
			addr = defaultAddr
		}
		p, err := proxy.New(proxy.Options{
			Addr:    addr,
			CertDir: certDir,
			OnFlow: func(f *types.Flow) {
				saveErr := state.Store.SaveFlow(f)
				fyne.Do(func() {
					appendLog("[%s] %s %s → %d (%dms)", f.ID, f.Method, f.URL, f.Status, f.LatencyMs)
					if saveErr != nil {
						appendLog("  store: %v", saveErr)
					}
					state.AddFlow(f)
				})
			},
		})
		if err != nil {
			appendLog("Error: %v", err)
			return
		}
		state.Proxy = p
		state.IsRunning = true
		addrEntry.Disable()
		toggleBtn.SetText("Stop")
		toggleBtn.SetIcon(theme.MediaStopIcon())
		toggleBtn.Importance = widget.DangerImportance
		toggleBtn.Refresh()
		statusLabel.SetText(fmt.Sprintf("Running on %s", p.Addr()))
		statusLabel.Importance = widget.SuccessImportance
		statusLabel.Refresh()
		appendLog("Proxy started on %s", p.Addr())
		go func() {
			if err := p.Start(); err != nil {
				fyne.Do(func() { appendLog("Proxy error: %v", err) })
			}
		}()
	}

	stopProxy := func() {
		if state.Proxy != nil {
			state.Proxy.Stop()
		}
		state.IsRunning = false
		state.Proxy = nil
		addrEntry.Enable()
		toggleBtn.SetText("Start")
		toggleBtn.SetIcon(theme.MediaPlayIcon())
		toggleBtn.Importance = widget.SuccessImportance
		toggleBtn.Refresh()
		statusLabel.SetText("Stopped")
		statusLabel.Importance = widget.MediumImportance
		statusLabel.Refresh()
		appendLog("Proxy stopped")
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

	proxySection := container.NewVBox(
		container.New(layout.NewFormLayout(),
			widget.NewLabelWithStyle("Listen", fyne.TextAlignTrailing, fyne.TextStyle{Bold: true}),
			addrEntry,
		),
		container.NewHBox(toggleBtn, clearBtn, layout.NewSpacer(), statusLabel),
	)

	// ==================== Android ====================
	var devices []android.Device
	deviceSelect := widget.NewSelect(nil, nil)
	deviceSelect.PlaceHolder = "No device — click Refresh"

	deviceStatus := widget.NewLabel("")
	deviceStatus.TextStyle = fyne.TextStyle{Monospace: true}

	selectedDevice := func() (android.Device, bool) {
		idx := deviceSelect.SelectedIndex()
		if idx < 0 || idx >= len(devices) {
			return android.Device{}, false
		}
		return devices[idx], true
	}
	deviceSelect.OnChanged = func(string) {
		if d, ok := selectedDevice(); ok {
			deviceStatus.SetText(d.Serial)
		}
	}

	portEntry := widget.NewEntry()
	portEntry.SetText("8080")
	portEntry.TextStyle = fyne.TextStyle{Monospace: true}
	certCheck := widget.NewCheck("CA cert", nil)
	certCheck.SetChecked(true)

	refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), nil)
	connectBtn := widget.NewButtonWithIcon("Connect", theme.MediaPlayIcon(), nil)
	disconnectBtn := widget.NewButtonWithIcon("Disconnect", theme.MediaStopIcon(), nil)

	adbBtns := []*widget.Button{refreshBtn, connectBtn, disconnectBtn}
	setBusy := func(busy bool) {
		for _, b := range adbBtns {
			if busy {
				b.Disable()
			} else {
				b.Enable()
			}
		}
	}

	refreshBtn.OnTapped = func() {
		setBusy(true)
		appendLog("Scanning devices...")
		go func() {
			list, err := android.ListDevices()
			fyne.Do(func() {
				setBusy(false)
				if err != nil {
					appendLog("Scan failed: %v", err)
					return
				}
				devices = list
				opts := make([]string, len(list))
				for i, d := range list {
					opts[i] = fmt.Sprintf("%s (%s)", d.Serial, d.State)
				}
				deviceSelect.SetOptions(opts)
				if len(list) > 0 {
					deviceSelect.SetSelectedIndex(0)
				}
				appendLog("Found %d device(s)", len(list))
			})
		}()
	}

	connectBtn.OnTapped = func() {
		dev, ok := selectedDevice()
		if !ok {
			appendLog("Select a device first")
			return
		}
		port := strings.TrimSpace(portEntry.Text)
		if port == "" {
			port = "8080"
		}
		setBusy(true)
		appendLog("Connecting %s...", dev.Serial)
		go func() {
			var certPath string
			var err error
			if certCheck.Checked {
				certPath, _, err = proxy.EnsureCA(certDir)
			}
			if err == nil {
				err = android.Setup(android.SetupOptions{
					ProxyPort:   port,
					Serial:      dev.Serial,
					CACertPath:  certPath,
					InstallCert: certCheck.Checked,
				})
			}
			fyne.Do(func() {
				setBusy(false)
				if err != nil {
					appendLog("Failed: %v", err)
				} else {
					appendLog("Connected %s on :%s", dev.Serial, port)
					deviceStatus.SetText(dev.Serial + " connected")
				}
			})
		}()
	}

	disconnectBtn.OnTapped = func() {
		dev, ok := selectedDevice()
		if !ok {
			appendLog("Select a device first")
			return
		}
		setBusy(true)
		go func() {
			err := android.Teardown(dev.Serial)
			fyne.Do(func() {
				setBusy(false)
				if err != nil {
					appendLog("Failed: %v", err)
				} else {
					appendLog("Disconnected %s", dev.Serial)
				}
			})
		}()
	}

	androidSection := container.NewVBox(
		container.NewBorder(nil, nil, nil, refreshBtn, deviceSelect),
		container.NewHBox(
			widget.NewLabelWithStyle("Port", fyne.TextAlignTrailing, fyne.TextStyle{Bold: true}),
			portEntry,
			certCheck,
			layout.NewSpacer(),
			connectBtn,
			disconnectBtn,
		),
		deviceStatus,
	)

	// ==================== Layout ====================
	topPanel := container.NewVBox(
		widget.NewLabelWithStyle("PROXY", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		proxySection,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("ANDROID", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		androidSection,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("LOG", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
	)

	return container.NewBorder(topPanel, nil, nil, nil, logScroll)
}
