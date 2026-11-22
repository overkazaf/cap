package wailsgui

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/screen"
	captrace "github.com/overkazaf/cap/internal/trace"
)

// ==================== Android ====================

const (
	EventDeviceStatus       = "device:status"
	EventDeviceDisconnected = "device:disconnected"
)

type DeviceInfo struct {
	Serial string `json:"serial"`
	State  string `json:"state"`
}

type DeviceConnectionStatus struct {
	Serial           string                  `json:"serial"`
	ADBState         string                  `json:"adb_state"` // "device", "offline", "unauthorized", "disconnected"
	Connected        bool                    `json:"connected"`
	ProxyAddress     string                  `json:"proxy_address"`
	VPNActive        bool                    `json:"vpn_active"`
	Mode             string                  `json:"mode"` // "proxy", "vpn", "none"
	Rooted           bool                    `json:"rooted"`
	Model            string                  `json:"model"`
	AndroidVersion   string                  `json:"android_version"`
	CertStatus       android.CertStatus      `json:"cert_status"`
	Companion        android.CompanionStatus `json:"companion"`
	CompanionWarning string                  `json:"companion_warning,omitempty"`
}

type DeviceDisconnectedEvent struct {
	Serial          string `json:"serial"`
	Reason          string `json:"reason"` // "adb_disconnected", "proxy_stopped", "user_disconnect", "app_shutdown", "reconnect_cleanup"
	CompanionActive bool   `json:"companion_active"`
	ProxyCleaned    bool   `json:"proxy_cleaned"`
	Message         string `json:"message"`
}

type CACertInfo struct {
	Path        string `json:"path"`
	Hash        string `json:"hash"`
	Exists      bool   `json:"exists"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject,omitempty"`
}

type connectedDeviceSession struct {
	Serial          string
	ProxyAddress    string
	Mode            string
	CompanionActive bool
	ConnectedAt     time.Time
}

func (a *App) ListDevices() ([]DeviceInfo, error) {
	devs, err := android.ListDevices()
	if err != nil {
		return nil, err
	}
	result := make([]DeviceInfo, len(devs))
	for i, d := range devs {
		result[i] = DeviceInfo{Serial: d.Serial, State: d.State}
	}
	return result, nil
}

// ConnectDevice preserves the legacy Wails signature and delegates to
// ConnectDeviceAdvanced with Wi-Fi proxy mode and Companion Guard enabled.
func (a *App) ConnectDevice(serial, port string, installCert bool) error {
	_, err := a.ConnectDeviceAdvanced(serial, port, installCert, false, true)
	return err
}

// ConnectDeviceAdvanced connects an Android device with full control over CA
// certificate installation, VPN/iptables vs Wi-Fi proxy mode, and the Cap Guard
// Companion APK watchdog, returning live connection status.
func (a *App) ConnectDeviceAdvanced(serial, port string, installCert, vpnMode, installCompanion bool) (*DeviceConnectionStatus, error) {
	if port == "" {
		port = "8080"
	}

	certPath, _, err := proxy.EnsureCA(a.certDir)
	if err != nil && installCert {
		return nil, err
	}

	res, err := android.SetupDetailed(android.SetupOptions{
		ProxyPort:   port,
		Serial:      serial,
		CACertPath:  certPath,
		InstallCert: installCert,
		VPN:         vpnMode,
		NoCompanion: !installCompanion,
	})
	if err != nil {
		return nil, err
	}

	proxyAddr := res.ProxyHost + ":" + res.ProxyPort
	companionActive := res.CompanionStatus.Installed && res.CompanionStatus.WatchdogRunning

	a.deviceMu.Lock()
	if a.connectedDevices == nil {
		a.connectedDevices = make(map[string]*connectedDeviceSession)
	}
	if a.staleDevices == nil {
		a.staleDevices = make(map[string]bool)
	}
	delete(a.staleDevices, res.Serial)
	a.connectedDevices[res.Serial] = &connectedDeviceSession{
		Serial:          res.Serial,
		ProxyAddress:    proxyAddr,
		Mode:            res.Mode,
		CompanionActive: companionActive,
		ConnectedAt:     time.Now(),
	}
	a.deviceMu.Unlock()
	a.ensureDeviceMonitor()

	status, stErr := a.GetDeviceConnectionStatus(res.Serial)
	if stErr != nil {
		status = &DeviceConnectionStatus{
			Serial:           res.Serial,
			ADBState:         "device",
			Connected:        true,
			ProxyAddress:     proxyAddr,
			VPNActive:        res.Mode == "vpn",
			Mode:             res.Mode,
			Rooted:           res.Rooted,
			CertStatus:       res.CertStatus,
			Companion:        res.CompanionStatus,
			CompanionWarning: res.CompanionWarning,
		}
	} else if res.CompanionWarning != "" {
		status.CompanionWarning = res.CompanionWarning
	}

	a.events.Emit(EventDeviceStatus, status)
	return status, nil
}

func (a *App) DisconnectDevice(serial string) error {
	resolved := serial
	if r, err := android.GetDeviceSerial(serial); err == nil {
		resolved = r
	}

	var companionActive bool
	a.deviceMu.Lock()
	if sess, ok := a.connectedDevices[resolved]; ok {
		companionActive = sess.CompanionActive
		delete(a.connectedDevices, resolved)
	}
	delete(a.staleDevices, resolved)
	a.deviceMu.Unlock()

	err := android.Teardown(resolved)
	cleaned := err == nil
	a.events.Emit(EventDeviceDisconnected, DeviceDisconnectedEvent{
		Serial:          resolved,
		Reason:          "user_disconnect",
		CompanionActive: companionActive,
		ProxyCleaned:    cleaned,
		Message:         "Device disconnected and proxy cleared",
	})
	if st, stErr := a.GetDeviceConnectionStatus(resolved); stErr == nil {
		a.events.Emit(EventDeviceStatus, st)
	}
	return err
}

// GetDeviceConnectionStatus inspects the device's live ADB state, proxy/VPN
// routing, CA certificate store status, and Companion Guard watchdog status.
func (a *App) GetDeviceConnectionStatus(serial string) (*DeviceConnectionStatus, error) {
	devices, err := android.ListDevices()
	if err != nil {
		return nil, err
	}

	targetSerial := serial
	adbState := "disconnected"
	if targetSerial == "" {
		for _, d := range devices {
			if d.State == "device" {
				targetSerial = d.Serial
				adbState = d.State
				break
			}
		}
		if targetSerial == "" && len(devices) > 0 {
			targetSerial = devices[0].Serial
			adbState = devices[0].State
		}
	} else {
		for _, d := range devices {
			if d.Serial == targetSerial {
				adbState = d.State
				break
			}
		}
	}

	if targetSerial == "" || adbState != "device" {
		return &DeviceConnectionStatus{
			Serial:    targetSerial,
			ADBState:  adbState,
			Connected: false,
			Mode:      "none",
			CertStatus: android.CertStatus{
				Store: "none",
			},
		}, nil
	}

	certPath := filepath.Join(a.certDir, "cap-ca.crt")
	if _, statErr := os.Stat(certPath); statErr != nil {
		certPath, _, _ = proxy.EnsureCA(a.certDir)
	}

	st, err := android.GetDeviceStatus(targetSerial, certPath)
	if err != nil {
		return nil, err
	}

	mode := "none"
	connected := false
	if st.VPNActive {
		mode = "vpn"
		connected = true
	} else if st.ProxyAddress != "" {
		mode = "proxy"
		connected = true
	}

	return &DeviceConnectionStatus{
		Serial:         st.Serial,
		ADBState:       st.State,
		Connected:      connected,
		ProxyAddress:   st.ProxyAddress,
		VPNActive:      st.VPNActive,
		Mode:           mode,
		Rooted:         st.Rooted,
		Model:          st.Model,
		AndroidVersion: st.AndroidVersion,
		CertStatus:     st.CertStatus,
		Companion:      st.CompanionStatus,
	}, nil
}

// InstallDeviceCert installs cap's CA certificate on the selected Android
// device and returns the structured installation result.
func (a *App) InstallDeviceCert(serial string) (*android.CertInstallResult, error) {
	certPath, _, err := proxy.EnsureCA(a.certDir)
	if err != nil {
		return nil, err
	}
	res, err := android.InstallCACert(serial, certPath)
	if err != nil {
		return &res, err
	}
	if st, stErr := a.GetDeviceConnectionStatus(serial); stErr == nil {
		a.events.Emit(EventDeviceStatus, st)
	}
	return &res, nil
}

// InstallCompanionAPK installs (or upgrades) the embedded Cap Guard Companion
// APK on the selected device and grants required permissions.
func (a *App) InstallCompanionAPK(serial string) (*android.CompanionStatus, error) {
	resolved, err := android.GetDeviceSerial(serial)
	if err != nil {
		return nil, err
	}
	if err := android.InstallCompanion(resolved); err != nil {
		st := android.GetCompanionStatus(resolved)
		st.Error = err.Error()
		return &st, err
	}
	st := android.GetCompanionStatus(resolved)
	if connSt, stErr := a.GetDeviceConnectionStatus(resolved); stErr == nil {
		a.events.Emit(EventDeviceStatus, connSt)
	}
	return &st, nil
}

// GetCACertInfo returns local CA certificate metadata (path, Android hash
// filename, existence, SHA-256 fingerprint, and subject).
func (a *App) GetCACertInfo() (*CACertInfo, error) {
	certPath, _, err := proxy.EnsureCA(a.certDir)
	if err != nil {
		p := filepath.Join(a.certDir, "cap-ca.crt")
		return &CACertInfo{Path: p, Exists: false}, err
	}
	_, statErr := os.Stat(certPath)
	exists := statErr == nil
	info := &CACertInfo{
		Path:   certPath,
		Exists: exists,
	}
	if exists {
		info.Hash = android.CertHashFilename(certPath)
		info.Fingerprint = android.CertSHA256Fingerprint(certPath)
		info.Subject = android.CertSubject(certPath)
	}
	return info, nil
}

// teardownTrackedDevices cleans up all devices actively tracked by App (e.g.
// when StopProxy is called) so no phone is left pointing at a stopped proxy.
func (a *App) teardownTrackedDevices(reason string) {
	a.deviceMu.Lock()
	sessions := make([]*connectedDeviceSession, 0, len(a.connectedDevices))
	for serial, sess := range a.connectedDevices {
		sessions = append(sessions, sess)
		delete(a.connectedDevices, serial)
	}
	a.deviceMu.Unlock()

	for _, sess := range sessions {
		err := android.Teardown(sess.Serial)
		cleaned := err == nil
		if !cleaned {
			// Device may currently be unplugged; mark stale so reconnect auto-cleans it.
			a.deviceMu.Lock()
			if a.staleDevices == nil {
				a.staleDevices = make(map[string]bool)
			}
			a.staleDevices[sess.Serial] = true
			a.deviceMu.Unlock()
			a.ensureDeviceMonitor()
		}
		a.events.Emit(EventDeviceDisconnected, DeviceDisconnectedEvent{
			Serial:          sess.Serial,
			Reason:          reason,
			CompanionActive: sess.CompanionActive,
			ProxyCleaned:    cleaned,
			Message:         "Proxy stopped — device proxy cleared",
		})
		if st, stErr := a.GetDeviceConnectionStatus(sess.Serial); stErr == nil {
			a.events.Emit(EventDeviceStatus, st)
		}
	}
}

// teardownAllDevices tears down all tracked devices plus any currently attached
// ADB devices during App.Shutdown.
func (a *App) teardownAllDevices(reason string) {
	seen := make(map[string]bool)

	a.deviceMu.Lock()
	tracked := make([]string, 0, len(a.connectedDevices))
	for serial := range a.connectedDevices {
		tracked = append(tracked, serial)
		seen[serial] = true
		delete(a.connectedDevices, serial)
	}
	a.staleDevices = make(map[string]bool)
	a.deviceMu.Unlock()

	for _, serial := range tracked {
		_ = android.Teardown(serial)
	}

	devices, _ := android.ListDevices()
	for _, d := range devices {
		if d.State != "device" || seen[d.Serial] {
			continue
		}
		_ = android.Teardown(d.Serial)
	}
	_ = reason
}

func (a *App) ensureDeviceMonitor() {
	a.deviceMu.Lock()
	if a.monitorRunning {
		a.deviceMu.Unlock()
		return
	}
	stopCh := make(chan struct{})
	a.monitorStop = stopCh
	a.monitorRunning = true
	a.deviceMu.Unlock()

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if !a.pollConnectedDevices() {
					a.deviceMu.Lock()
					if a.monitorStop == stopCh {
						a.monitorRunning = false
						a.monitorStop = nil
					}
					a.deviceMu.Unlock()
					return
				}
			}
		}
	}()
}

func (a *App) stopDeviceMonitor() {
	a.deviceMu.Lock()
	stopCh := a.monitorStop
	a.monitorStop = nil
	a.monitorRunning = false
	a.deviceMu.Unlock()
	if stopCh != nil {
		close(stopCh)
	}
}

// pollConnectedDevices checks ADB presence for tracked/stale devices and returns
// false when there is nothing left to monitor.
func (a *App) pollConnectedDevices() bool {
	a.deviceMu.Lock()
	if len(a.connectedDevices) == 0 && len(a.staleDevices) == 0 {
		a.deviceMu.Unlock()
		return false
	}
	connectedCopy := make(map[string]*connectedDeviceSession, len(a.connectedDevices))
	for k, v := range a.connectedDevices {
		connectedCopy[k] = v
	}
	staleCopy := make([]string, 0, len(a.staleDevices))
	for k := range a.staleDevices {
		staleCopy = append(staleCopy, k)
	}
	a.deviceMu.Unlock()

	devices, err := android.ListDevices()
	if err != nil {
		return true
	}
	stateBySerial := make(map[string]string, len(devices))
	for _, d := range devices {
		stateBySerial[d.Serial] = d.State
	}

	// Detect unexpected ADB disconnects for active sessions
	for serial, sess := range connectedCopy {
		st, present := stateBySerial[serial]
		if !present || st != "device" {
			adbState := "disconnected"
			if present {
				adbState = st
			}
			a.deviceMu.Lock()
			delete(a.connectedDevices, serial)
			if a.staleDevices == nil {
				a.staleDevices = make(map[string]bool)
			}
			a.staleDevices[serial] = true
			a.deviceMu.Unlock()

			msg := "Android device disconnected over ADB"
			if sess.CompanionActive {
				msg = "Android device disconnected — Cap Guard on device will automatically clear proxy and restore network"
			}
			a.events.Emit(EventDeviceDisconnected, DeviceDisconnectedEvent{
				Serial:          serial,
				Reason:          "adb_disconnected",
				CompanionActive: sess.CompanionActive,
				ProxyCleaned:    false,
				Message:         msg,
			})
			a.events.Emit(EventDeviceStatus, &DeviceConnectionStatus{
				Serial:    serial,
				ADBState:  adbState,
				Connected: false,
				Mode:      "none",
				CertStatus: android.CertStatus{
					Store: "none",
				},
			})
		}
	}

	// Auto-clean stale proxy if a previously disconnected device reconnects while proxy is stopped
	for _, serial := range staleCopy {
		if stateBySerial[serial] != "device" {
			continue
		}
		a.deviceMu.Lock()
		delete(a.staleDevices, serial)
		a.deviceMu.Unlock()

		if a.IsProxyRunning() {
			continue
		}
		proxySetting, _ := android.AdbShell(serial, "settings get global http_proxy")
		host, _ := android.ParseProxySetting(proxySetting)
		psOut, _ := android.AdbShell(serial, "pidof cap-redir 2>/dev/null || true")
		if host != "" || strings.TrimSpace(psOut) != "" {
			if err := android.Teardown(serial); err == nil {
				a.events.Emit(EventDeviceDisconnected, DeviceDisconnectedEvent{
					Serial:       serial,
					Reason:       "reconnect_cleanup",
					ProxyCleaned: true,
					Message:      "Stale proxy detected on reconnected device and cleared automatically",
				})
				if connSt, stErr := a.GetDeviceConnectionStatus(serial); stErr == nil {
					a.events.Emit(EventDeviceStatus, connSt)
				}
			}
		}
	}

	a.deviceMu.Lock()
	keepRunning := len(a.connectedDevices) > 0 || len(a.staleDevices) > 0
	a.deviceMu.Unlock()
	return keepRunning
}

func (a *App) ConnectWiFiADB(ipPort string) (string, error) {
	if ipPort == "" {
		return "", fmt.Errorf("IP:PORT required")
	}
	return android.AdbCmd("", "connect", ipPort)
}

func (a *App) DisconnectWiFiADB(ipPort string) (string, error) {
	return android.AdbCmd("", "disconnect", ipPort)
}

type AppInfo struct {
	Package string `json:"package"`
	Name    string `json:"name"`
}

func (a *App) ListApps(serial string) ([]AppInfo, error) {
	out, err := android.AdbShell(serial, "pm list packages -3")
	if err != nil {
		return nil, err
	}
	var apps []AppInfo
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			pkg := strings.TrimPrefix(line, "package:")
			apps = append(apps, AppInfo{Package: pkg, Name: pkg})
		}
	}
	return apps, nil
}

func (a *App) LaunchApp(serial, packageName string) error {
	_, err := android.AdbShell(serial, fmt.Sprintf("monkey -p %s -c android.intent.category.LAUNCHER 1", packageName))
	return err
}

// ==================== Device Environment ====================

type DeviceEnv struct {
	Model       string `json:"model"`
	Brand       string `json:"brand"`
	Android     string `json:"android"`
	SDK         string `json:"sdk"`
	CPU         string `json:"cpu"`
	RAM         string `json:"ram"`
	Screen      string `json:"screen"`
	Kernel      string `json:"kernel"`
	Battery     string `json:"battery"`
	Rooted      bool   `json:"rooted"`
	RootMethod  string `json:"root_method"`
	Magisk      string `json:"magisk"`
	MagiskVer   string `json:"magisk_ver"`
	KernelSU    bool   `json:"kernelsu"`
	KernelSUVer string `json:"kernelsu_ver"`
	Zygisk      bool   `json:"zygisk"`
	LSPosed     bool   `json:"lsposed"`
	LSPosedVer  string `json:"lsposed_ver"`
	SELinux     string `json:"selinux"`
	Integrity   string `json:"integrity"`
	Fingerprint string `json:"fingerprint"`
}

func (a *App) GetDeviceEnv(serial string) (*DeviceEnv, error) {
	prop := func(key string) string {
		out, _ := android.AdbShell(serial, "getprop "+key)
		return out
	}

	shell := func(cmd string) string {
		out, _ := android.AdbShell(serial, cmd)
		return out
	}

	suShell := func(cmd string) string {
		out, _ := android.SuShell(serial, cmd)
		return out
	}

	env := &DeviceEnv{
		Model:       prop("ro.product.model"),
		Brand:       prop("ro.product.brand"),
		Android:     prop("ro.build.version.release"),
		SDK:         prop("ro.build.version.sdk"),
		CPU:         prop("ro.product.cpu.abi"),
		Kernel:      shell("uname -r"),
		Fingerprint: prop("ro.build.fingerprint"),
	}

	// Screen
	env.Screen = shell("wm size")
	if idx := strings.Index(env.Screen, ": "); idx >= 0 {
		env.Screen = env.Screen[idx+2:]
	}

	// RAM
	memInfo := shell("cat /proc/meminfo | head -1")
	if strings.Contains(memInfo, "MemTotal") {
		parts := strings.Fields(memInfo)
		if len(parts) >= 2 {
			kb := 0
			fmt.Sscanf(parts[1], "%d", &kb)
			env.RAM = fmt.Sprintf("%.1f GB", float64(kb)/1048576.0)
		}
	}

	// Battery
	battInfo := shell("dumpsys battery | grep level")
	if strings.Contains(battInfo, "level") {
		parts := strings.Split(battInfo, ":")
		if len(parts) >= 2 {
			env.Battery = strings.TrimSpace(parts[1]) + "%"
		}
	}

	// Root check
	rootCheck := shell("su -c id")
	env.Rooted = strings.Contains(rootCheck, "uid=0")
	if env.Rooted {
		env.RootMethod = "su"
	}

	// Magisk
	magiskVer := suShell("magisk -v")
	if magiskVer != "" && !strings.Contains(magiskVer, "not found") && !strings.Contains(magiskVer, "error") {
		env.Magisk = "installed"
		env.MagiskVer = magiskVer
		env.RootMethod = "Magisk"
	} else {
		magiskDir := suShell("ls /data/adb/magisk/")
		if magiskDir != "" && !strings.Contains(magiskDir, "No such") {
			env.Magisk = "installed"
			env.RootMethod = "Magisk"
		} else {
			env.Magisk = "not found"
		}
	}

	// KernelSU
	ksuVer := shell("ksud --version 2>/dev/null")
	if ksuVer != "" && !strings.Contains(ksuVer, "not found") {
		env.KernelSU = true
		env.KernelSUVer = ksuVer
		if env.RootMethod == "su" {
			env.RootMethod = "KernelSU"
		}
	} else {
		ksuDir := suShell("ls /data/adb/ksu/ 2>/dev/null")
		if ksuDir != "" && !strings.Contains(ksuDir, "No such") {
			env.KernelSU = true
			env.RootMethod = "KernelSU"
		} else {
			ksuModule := shell("ls /data/adb/modules/.kernelsu 2>/dev/null")
			if ksuModule != "" && !strings.Contains(ksuModule, "No such") {
				env.KernelSU = true
			}
		}
	}

	// Zygisk
	zygiskProp := prop("persist.magisk.zygisk")
	if zygiskProp == "1" {
		env.Zygisk = true
	} else {
		zygiskCheck := suShell("ls /data/adb/modules/zygisksu 2>/dev/null || ls /data/adb/modules/zygisk* 2>/dev/null")
		env.Zygisk = zygiskCheck != "" && !strings.Contains(zygiskCheck, "No such")
	}

	// LSPosed
	lsposedCheck := shell("pm list packages 2>/dev/null | grep lspd")
	if strings.Contains(lsposedCheck, "lspd") {
		env.LSPosed = true
	} else {
		lspdDir := suShell("ls /data/adb/lspd/ 2>/dev/null || ls /data/adb/modules/lsposed* 2>/dev/null")
		env.LSPosed = lspdDir != "" && !strings.Contains(lspdDir, "No such")
	}
	if env.LSPosed {
		env.LSPosedVer = suShell("cat /data/adb/lspd/manager/version 2>/dev/null")
	}

	// SELinux
	env.SELinux = shell("getenforce")

	// Google Play Integrity (basic check)
	gmsVer := shell("dumpsys package com.google.android.gms 2>/dev/null | grep versionName | head -1")
	if strings.Contains(gmsVer, "versionName") {
		parts := strings.Split(gmsVer, "=")
		if len(parts) >= 2 {
			env.Integrity = "GMS " + strings.TrimSpace(parts[1])
		}
	}
	integrityCheck := prop("ro.boot.verifiedbootstate")
	if integrityCheck != "" {
		env.Integrity += " | boot=" + integrityCheck
	}

	return env, nil
}

// ==================== RE Tools ====================

type AppDetail struct {
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	TargetSDK   string   `json:"target_sdk"`
	MinSDK      string   `json:"min_sdk"`
	Permissions []string `json:"permissions"`
	Activities  []string `json:"activities"`
	Services    []string `json:"services"`
	Receivers   []string `json:"receivers"`
	NativeLibs  []string `json:"native_libs"`
	APKPath     string   `json:"apk_path"`
	DataDir     string   `json:"data_dir"`
	UID         string   `json:"uid"`
	Debuggable  bool     `json:"debuggable"`
}

func (a *App) InspectApp(serial, pkg string) (*AppDetail, error) {
	shell := func(cmd string) string {
		out, _ := android.AdbShell(serial, cmd)
		return out
	}

	dump := shell(fmt.Sprintf("dumpsys package %s", pkg))
	detail := &AppDetail{Package: pkg}

	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "versionName=") {
			detail.Version = strings.TrimPrefix(line, "versionName=")
		} else if strings.HasPrefix(line, "targetSdk=") {
			detail.TargetSDK = strings.TrimPrefix(line, "targetSdk=")
		} else if strings.HasPrefix(line, "minSdk=") {
			detail.MinSDK = strings.TrimPrefix(line, "minSdk=")
		} else if strings.HasPrefix(line, "codePath=") {
			detail.APKPath = strings.TrimPrefix(line, "codePath=")
		} else if strings.HasPrefix(line, "dataDir=") {
			detail.DataDir = strings.TrimPrefix(line, "dataDir=")
		} else if strings.HasPrefix(line, "userId=") {
			detail.UID = strings.TrimPrefix(line, "userId=")
		} else if strings.Contains(line, "android.permission.") {
			perm := line
			if idx := strings.Index(perm, "android.permission."); idx >= 0 {
				perm = perm[idx:]
				if spIdx := strings.IndexAny(perm, " :"); spIdx > 0 {
					perm = perm[:spIdx]
				}
				detail.Permissions = append(detail.Permissions, perm)
			}
		} else if strings.Contains(line, "flags=") && strings.Contains(line, "DEBUGGABLE") {
			detail.Debuggable = true
		}
	}

	// Activities
	actDump := shell(fmt.Sprintf("cmd package query-activities --brief %s 2>/dev/null || dumpsys package %s | grep -A1 'Activity Resolver'", pkg, pkg))
	for _, line := range strings.Split(actDump, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, pkg) && strings.Contains(line, "/") {
			detail.Activities = append(detail.Activities, line)
		}
	}

	// Services
	svcDump := shell(fmt.Sprintf("dumpsys package %s | grep '%s' | grep -i service", pkg, pkg))
	for _, line := range strings.Split(svcDump, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, pkg) && len(line) > 5 {
			detail.Services = append(detail.Services, line)
		}
	}

	// Native libs
	libDump := shell(fmt.Sprintf("ls %s/lib/arm64/ 2>/dev/null || ls %s/lib/arm/ 2>/dev/null", detail.APKPath, detail.APKPath))
	for _, line := range strings.Split(libDump, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, ".so") {
			detail.NativeLibs = append(detail.NativeLibs, line)
		}
	}

	return detail, nil
}

type ProcessInfo struct {
	PID  string `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
}

func (a *App) ListProcesses(serial string) ([]ProcessInfo, error) {
	out, err := android.AdbShell(serial, "ps -A -o PID,USER,NAME 2>/dev/null || ps")
	if err != nil {
		return nil, err
	}
	var procs []ProcessInfo
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && fields[0] != "PID" {
			procs = append(procs, ProcessInfo{PID: fields[0], User: fields[1], Name: fields[2]})
		}
	}
	return procs, nil
}

func (a *App) PullAPK(serial, pkg string) (string, error) {
	pathOut, _ := android.AdbShell(serial, fmt.Sprintf("pm path %s", pkg))
	apkPath := ""
	for _, line := range strings.Split(pathOut, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "package:") {
			apkPath = strings.TrimPrefix(strings.TrimSpace(line), "package:")
			break
		}
	}
	if apkPath == "" {
		return "", fmt.Errorf("package %s not found", pkg)
	}

	localDir := filepath.Join(a.certDir, "apks")
	os.MkdirAll(localDir, 0755)
	localPath := filepath.Join(localDir, pkg+".apk")

	if _, err := android.AdbCmd(serial, "pull", apkPath, localPath); err != nil {
		return "", err
	}
	return localPath, nil
}

func (a *App) CheckFrida(serial string) map[string]string {
	result := map[string]string{"status": "not running"}

	psOut, _ := android.AdbShell(serial, "ps -A 2>/dev/null | grep frida || ps | grep frida")
	if strings.Contains(psOut, "frida") {
		result["status"] = "running"
		for _, line := range strings.Split(psOut, "\n") {
			if strings.Contains(line, "frida") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					result["pid"] = fields[1]
				}
				break
			}
		}
	}

	binOut, _ := android.AdbShell(serial, "ls /data/local/tmp/frida-server* 2>/dev/null")
	if binOut != "" && !strings.Contains(binOut, "No such") {
		result["binary"] = binOut
	}

	return result
}

func (a *App) StartFrida(serial string) (string, error) {
	return android.SuShell(serial, "nohup /data/local/tmp/frida-server -D > /dev/null 2>&1 &")
}

func (a *App) RunLogcat(serial, filter string, lines int) (string, error) {
	if lines <= 0 {
		lines = 100
	}
	cmd := fmt.Sprintf("logcat -d -t %d", lines)
	if filter != "" {
		cmd += " -s " + filter
	}
	return android.AdbShell(serial, cmd)
}

// ==================== Deep Trace ====================

func (a *App) DeepTrace(flowID, packageName string) (*captrace.TraceResult, error) {
	f, err := a.store.GetFlow(flowID)
	if err != nil {
		return nil, err
	}

	devices, _ := android.ListDevices()
	serial := ""
	if len(devices) > 0 {
		serial = devices[0].Serial
	}

	return captrace.Trace(f, captrace.Options{
		Serial:    serial,
		OutputDir: filepath.Join(a.certDir, "trace", packageName),
		Package:   packageName,
	}, nil)
}

func (a *App) GetTraceMermaid(flowID, packageName string) (string, error) {
	result, err := a.DeepTrace(flowID, packageName)
	if err != nil {
		return "", err
	}
	return result.Mermaid, nil
}

// ==================== Device Screen ====================

func (a *App) CaptureScreen(serial string) (string, error) {
	return a.CaptureScreenScaled(serial, 50)
}

func (a *App) CaptureScrcpy(serial string) (string, error) {
	data, err := screen.Capture(screen.Options{
		Serial:  serial,
		Engine:  screen.EngineScrcpy,
		MaxSize: 540,
		Quality: 70,
	})
	if err != nil {
		return "", err
	}
	return "data:image/jpeg;base64," + base64Encode(data), nil
}

func (a *App) DeployScrcpy(serial string) (string, error) {
	cacheDir, _ := screen.DefaultCacheDir()
	if err := screen.DeployScrcpyServer(serial, cacheDir); err != nil {
		return "", err
	}
	return "scrcpy-server deployed", nil
}

func (a *App) IsScrcpyReady(serial string) bool {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return false
	}
	return screen.IsScrcpyDeployed(serial)
}

func (a *App) CaptureScreenScaled(serial string, quality int) (string, error) {
	maxSize := 540
	if quality > 80 {
		maxSize = 720
	} else if quality > 60 {
		maxSize = 540
	} else if quality > 40 {
		maxSize = 400
	} else {
		maxSize = 320
	}

	jpegData, err := screen.FastCapture(serial, maxSize, quality)
	if err != nil {
		out, fallbackErr := android.AdbCmd(serial, "exec-out", "screencap", "-p")
		if fallbackErr != nil {
			return "", fmt.Errorf("screencap: %w (fast: %v)", fallbackErr, err)
		}
		return "data:image/png;base64," + base64Encode([]byte(out)), nil
	}

	return "data:image/jpeg;base64," + base64Encode(jpegData), nil
}

func (a *App) DeviceTap(serial string, x, y int) error {
	_, err := android.AdbShell(serial, fmt.Sprintf("input tap %d %d", x, y))
	return err
}

func (a *App) DeviceSwipe(serial string, x1, y1, x2, y2, duration int) error {
	_, err := android.AdbShell(serial, fmt.Sprintf("input swipe %d %d %d %d %d", x1, y1, x2, y2, duration))
	return err
}

func (a *App) DeviceBack(serial string) error {
	_, err := android.AdbShell(serial, "input keyevent 4")
	return err
}

func (a *App) DeviceHome(serial string) error {
	_, err := android.AdbShell(serial, "input keyevent 3")
	return err
}

func (a *App) GetScreenSize(serial string) ([]int, error) {
	out, err := android.AdbShell(serial, "wm size")
	if err != nil {
		return nil, err
	}
	s := out
	parts := strings.Split(s, ": ")
	if len(parts) < 2 {
		return []int{1080, 2400}, nil
	}
	dims := strings.Split(parts[len(parts)-1], "x")
	if len(dims) < 2 {
		return []int{1080, 2400}, nil
	}
	w := 1080
	h := 2400
	fmt.Sscanf(dims[0], "%d", &w)
	fmt.Sscanf(dims[1], "%d", &h)
	return []int{w, h}, nil
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
