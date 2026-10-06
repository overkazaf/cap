package wailsgui

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/screen"
	captrace "github.com/overkazaf/cap/internal/trace"
)

// ==================== Android ====================

type DeviceInfo struct {
	Serial string `json:"serial"`
	State  string `json:"state"`
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

func (a *App) ConnectDevice(serial, port string, installCert bool) error {
	if port == "" {
		port = "8080"
	}
	var certPath string
	if installCert {
		var err error
		certPath, _, err = proxy.EnsureCA(a.certDir)
		if err != nil {
			return err
		}
	}
	return android.Setup(android.SetupOptions{
		ProxyPort:   port,
		Serial:      serial,
		CACertPath:  certPath,
		InstallCert: installCert,
	})
}

func (a *App) DisconnectDevice(serial string) error {
	return android.Teardown(serial)
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
