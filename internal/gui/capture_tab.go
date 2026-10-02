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

	// --- Shared log ---
	logContent := widget.NewLabel("")
	logContent.Wrapping = fyne.TextWrapWord
	logScroll := container.NewVScroll(logContent)

	var logLines []string
	appendLog := func(format string, args ...any) {
		line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
		logLines = append(logLines, line)
		logContent.SetText(strings.Join(logLines, "\n"))
		logScroll.ScrollToBottom()
	}

	// ==================== Proxy Section ====================
	addrEntry := widget.NewEntry()
	addrEntry.SetText(defaultAddr)

	statusLabel := widget.NewLabel("Proxy: Stopped")
	statusLabel.Importance = widget.MediumImportance

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
						appendLog("  store error: %v", saveErr)
					}
					state.AddFlow(f)
				})
			},
		})
		if err != nil {
			appendLog("Start failed: %v", err)
			return
		}
		state.Proxy = p
		state.IsRunning = true
		addrEntry.Disable()
		toggleBtn.SetText("Stop")
		toggleBtn.SetIcon(theme.MediaStopIcon())
		toggleBtn.Importance = widget.DangerImportance
		toggleBtn.Refresh()
		statusLabel.SetText(fmt.Sprintf("Proxy: Running on %s", p.Addr()))
		statusLabel.Importance = widget.SuccessImportance
		statusLabel.Refresh()
		appendLog("Proxy started on %s", p.Addr())

		go func() {
			if err := p.Start(); err != nil {
				fyne.Do(func() {
					appendLog("Proxy error: %v", err)
				})
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
		statusLabel.SetText("Proxy: Stopped")
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

	clearBtn := widget.NewButtonWithIcon("Clear Log", theme.ContentClearIcon(), func() {
		logLines = nil
		logContent.SetText("")
	})

	proxyRow := container.New(layout.NewFormLayout(),
		widget.NewLabel("Listen:"), addrEntry,
	)
	proxyControls := container.NewHBox(toggleBtn, clearBtn, layout.NewSpacer(), statusLabel)

	// ==================== Android Section ====================
	var devices []android.Device
	deviceSelect := widget.NewSelect(nil, nil)
	deviceSelect.PlaceHolder = "Click Refresh"

	deviceStatus := widget.NewLabel("")

	selectedDevice := func() (android.Device, bool) {
		idx := deviceSelect.SelectedIndex()
		if idx < 0 || idx >= len(devices) {
			return android.Device{}, false
		}
		return devices[idx], true
	}

	deviceSelect.OnChanged = func(string) {
		d, ok := selectedDevice()
		if !ok {
			return
		}
		deviceStatus.SetText(d.Serial + " — " + d.State)
	}

	proxyPortEntry := widget.NewEntry()
	proxyPortEntry.SetText("8080")
	installCertCheck := widget.NewCheck("Install CA cert", nil)
	installCertCheck.SetChecked(true)

	refreshBtn := widget.NewButton("Refresh", nil)
	connectBtn := widget.NewButton("Connect", nil)
	disconnectBtn := widget.NewButton("Disconnect", nil)

	adbButtons := []*widget.Button{refreshBtn, connectBtn, disconnectBtn}
	setBusy := func(busy bool) {
		for _, b := range adbButtons {
			if busy {
				b.Disable()
			} else {
				b.Enable()
			}
		}
	}

	refreshBtn.OnTapped = func() {
		setBusy(true)
		appendLog("Scanning ADB devices...")
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
		port := strings.TrimSpace(proxyPortEntry.Text)
		if port == "" {
			port = "8080"
		}
		setBusy(true)
		appendLog("Connecting %s (port %s)...", dev.Serial, port)
		go func() {
			var certPath string
			var err error
			if installCertCheck.Checked {
				certPath, _, err = proxy.EnsureCA(certDir)
			}
			if err == nil {
				err = android.Setup(android.SetupOptions{
					ProxyPort:   port,
					Serial:      dev.Serial,
					CACertPath:  certPath,
					InstallCert: installCertCheck.Checked,
				})
			}
			fyne.Do(func() {
				setBusy(false)
				if err != nil {
					appendLog("Connect failed: %v", err)
				} else {
					appendLog("Connected %s on port %s", dev.Serial, port)
					deviceStatus.SetText(dev.Serial + " — connected")
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
					appendLog("Disconnect failed: %v", err)
				} else {
					appendLog("Disconnected %s", dev.Serial)
					deviceStatus.SetText(dev.Serial + " — disconnected")
				}
			})
		}()
	}

	deviceRow := container.NewBorder(nil, nil, nil, refreshBtn, deviceSelect)
	androidConfig := container.NewHBox(
		widget.NewLabel("Port:"), proxyPortEntry,
		installCertCheck,
		connectBtn, disconnectBtn,
	)

	// ==================== Combined Layout ====================
	proxyCard := widget.NewCard("Proxy", "", container.NewVBox(proxyRow, proxyControls))
	androidCard := widget.NewCard("Android Device", "", container.NewVBox(deviceRow, deviceStatus, androidConfig))

	top := container.NewVBox(proxyCard, androidCard, widget.NewSeparator())
	return container.NewBorder(top, nil, nil, nil, logScroll)
}
