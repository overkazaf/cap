package gui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/proxy"
)

// defaultCertDir returns "~/.cap", the directory cap stores its generated
// MITM CA certificate in. This mirrors internal/cli's own default so a
// certificate installed via the GUI's Connect button is the same one a
// `cap android connect` / `cap start` would use.
func defaultCertDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cap")
	}
	return ".cap"
}

// NewAndroidTab builds the Android device management tab: discover ADB
// devices, configure the proxy connection, and connect/disconnect/check
// status — the GUI equivalent of `cap android connect|disconnect|status`.
func NewAndroidTab(state *AppState, w fyne.Window) fyne.CanvasObject {
	// devices mirrors deviceSelect.Options 1:1 (same order, refreshed
	// together). Both are only ever touched on the Fyne UI goroutine —
	// directly inside widget callbacks, or inside fyne.Do from background
	// goroutines — so no extra locking is needed.
	var devices []android.Device

	// --- Log output ---------------------------------------------------

	logOutput := widget.NewMultiLineEntry()
	logOutput.Wrapping = fyne.TextWrapWord
	logOutput.Disable()

	appendLog := func(format string, args ...any) {
		line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
		if logOutput.Text == "" {
			logOutput.SetText(line)
		} else {
			logOutput.Append("\n" + line)
		}
		// Best-effort: move the cursor to the new last line so the entry's
		// view follows the latest output.
		lines := strings.Split(logOutput.Text, "\n")
		logOutput.CursorRow = len(lines) - 1
		logOutput.CursorColumn = len(lines[len(lines)-1])
	}

	// --- Device section -------------------------------------------------

	statusLabel := widget.NewLabel("No device selected.")

	deviceSelect := widget.NewSelect(nil, nil)
	deviceSelect.PlaceHolder = "No devices — click Refresh Devices"

	// selectedDevice resolves the Select's current choice back to the
	// android.Device it was built from.
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
			statusLabel.SetText("No device selected.")
			return
		}
		statusLabel.SetText(fmt.Sprintf("%s — %s", d.Serial, d.State))
	}

	// --- Config section ---------------------------------------------------

	proxyHostEntry := widget.NewEntry()
	proxyHostEntry.SetPlaceHolder("auto")

	proxyPortEntry := widget.NewEntry()
	proxyPortEntry.SetText("8080")

	installCertCheck := widget.NewCheck("Install CA certificate on device", nil)
	installCertCheck.SetChecked(true)

	// --- Action buttons ---------------------------------------------------

	refreshBtn := widget.NewButton("Refresh Devices", nil)
	connectBtn := widget.NewButton("Connect", nil)
	disconnectBtn := widget.NewButton("Disconnect", nil)
	statusBtn := widget.NewButton("Status", nil)

	actionButtons := []*widget.Button{refreshBtn, connectBtn, disconnectBtn, statusBtn}
	// setBusy disables every action while a background adb/proxy operation
	// is in flight, so the user can't kick off overlapping commands.
	setBusy := func(busy bool) {
		for _, b := range actionButtons {
			if busy {
				b.Disable()
			} else {
				b.Enable()
			}
		}
	}

	refreshBtn.OnTapped = func() {
		setBusy(true)
		appendLog("Scanning for ADB devices...")

		go func() {
			list, err := android.ListDevices()

			fyne.Do(func() {
				setBusy(false)
				if err != nil {
					appendLog("Refresh failed: %v", err)
					return
				}

				devices = list
				options := make([]string, len(list))
				for i, d := range list {
					options[i] = fmt.Sprintf("%s (%s)", d.Serial, d.State)
				}
				deviceSelect.SetOptions(options)

				if len(list) == 0 {
					deviceSelect.ClearSelected()
					appendLog("No devices found — check `adb devices` and that USB debugging is enabled.")
					return
				}
				deviceSelect.SetSelectedIndex(0)
				appendLog("Found %d device(s).", len(list))
			})
		}()
	}

	connectBtn.OnTapped = func() {
		dev, ok := selectedDevice()
		if !ok {
			appendLog("Select a device first (click Refresh Devices).")
			return
		}

		host := strings.TrimSpace(proxyHostEntry.Text)
		port := strings.TrimSpace(proxyPortEntry.Text)
		if port == "" {
			port = "8080"
		}
		installCert := installCertCheck.Checked

		setBusy(true)
		if host == "" {
			appendLog("Connecting %s (auto-detecting host IP, port %s)...", dev.Serial, port)
		} else {
			appendLog("Connecting %s to %s:%s...", dev.Serial, host, port)
		}

		go func() {
			var certPath string
			var err error
			if installCert {
				certPath, _, err = proxy.EnsureCA(defaultCertDir())
				if err != nil {
					fyne.Do(func() {
						setBusy(false)
						appendLog("Connect failed: generate CA certificate: %v", err)
					})
					return
				}
			}

			err = android.Setup(android.SetupOptions{
				ProxyHost:   host,
				ProxyPort:   port,
				Serial:      dev.Serial,
				CACertPath:  certPath,
				InstallCert: installCert,
			})

			fyne.Do(func() {
				setBusy(false)
				if err != nil {
					appendLog("Connect failed: %v", err)
					return
				}
				appendLog("Connected %s — proxy configured on port %s.", dev.Serial, port)
				if installCert {
					appendLog("CA certificate installed on %s (from %s).", dev.Serial, certPath)
				}
				statusLabel.SetText(fmt.Sprintf("%s — connected", dev.Serial))
			})
		}()
	}

	disconnectBtn.OnTapped = func() {
		dev, ok := selectedDevice()
		if !ok {
			appendLog("Select a device first (click Refresh Devices).")
			return
		}

		setBusy(true)
		appendLog("Disconnecting %s...", dev.Serial)

		go func() {
			err := android.Teardown(dev.Serial)

			fyne.Do(func() {
				setBusy(false)
				if err != nil {
					appendLog("Disconnect failed: %v", err)
					return
				}
				appendLog("Disconnected %s — proxy cleared.", dev.Serial)
				statusLabel.SetText(fmt.Sprintf("%s — disconnected", dev.Serial))
			})
		}()
	}

	statusBtn.OnTapped = func() {
		dev, ok := selectedDevice()
		if !ok {
			appendLog("Select a device first (click Refresh Devices).")
			return
		}

		setBusy(true)
		appendLog("Checking status of %s...", dev.Serial)

		go func() {
			list, err := android.ListDevices()

			fyne.Do(func() {
				setBusy(false)
				if err != nil {
					appendLog("Status check failed: %v", err)
					return
				}
				for _, d := range list {
					if d.Serial != dev.Serial {
						continue
					}
					appendLog("Device %s: state=%s", d.Serial, d.State)
					statusLabel.SetText(fmt.Sprintf("%s — %s", d.Serial, d.State))
					return
				}
				appendLog("Device %s is no longer connected.", dev.Serial)
				statusLabel.SetText(fmt.Sprintf("%s — disconnected", dev.Serial))
			})
		}()
	}

	// --- Layout -------------------------------------------------------

	deviceRow := container.NewBorder(nil, nil, nil, refreshBtn, deviceSelect)
	deviceCard := widget.NewCard("Device", "", container.NewVBox(deviceRow, statusLabel))

	configForm := widget.NewForm(
		widget.NewFormItem("Proxy host", proxyHostEntry),
		widget.NewFormItem("Proxy port", proxyPortEntry),
	)
	configCard := widget.NewCard("Proxy Configuration", "", container.NewVBox(configForm, installCertCheck))

	actionsCard := widget.NewCard("Actions", "", container.NewHBox(connectBtn, disconnectBtn, statusBtn))

	logCard := widget.NewCard("Log", "", logOutput)

	top := container.NewVBox(deviceCard, configCard, actionsCard)
	return container.NewBorder(top, nil, nil, nil, logCard)
}
