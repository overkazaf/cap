package android

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const redirPortStateFile = "/data/local/tmp/cap-redir.port"

// SetupResult provides structured details about a completed Android setup.
type SetupResult struct {
	Serial           string             `json:"serial"`
	ProxyHost        string             `json:"proxy_host"`
	ProxyPort        string             `json:"proxy_port"`
	Mode             string             `json:"mode"` // "proxy" or "vpn"
	RedirPort        string             `json:"redir_port,omitempty"`
	Rooted           bool               `json:"rooted"`
	CertResult       *CertInstallResult `json:"cert_result,omitempty"`
	CertStatus       CertStatus         `json:"cert_status"`
	CompanionStatus  CompanionStatus    `json:"companion_status"`
	CompanionWarning string             `json:"companion_warning,omitempty"`
}

// DeviceStatus summarizes live inspection state for an attached Android device.
type DeviceStatus struct {
	Serial          string          `json:"serial"`
	State           string          `json:"state"`
	Model           string          `json:"model"`
	Brand           string          `json:"brand"`
	AndroidVersion  string          `json:"android_version"`
	SDK             string          `json:"sdk"`
	Rooted          bool            `json:"rooted"`
	ProxyHost       string          `json:"proxy_host"`
	ProxyPort       string          `json:"proxy_port"`
	ProxyAddress    string          `json:"proxy_address"`
	VPNActive       bool            `json:"vpn_active"`
	RedirPort       string          `json:"redir_port,omitempty"`
	CertStatus      CertStatus      `json:"cert_status"`
	CompanionStatus CompanionStatus `json:"companion_status"`
}

// Setup configures an Android device to route HTTP(S) traffic through
// cap's proxy. In normal mode it sets the global Wi-Fi proxy; in VPN
// mode it pushes the cap-redir binary and sets up iptables REDIRECT.
// Unless opts.NoCompanion is set, it also deploys and starts the Cap Guard
// Companion APK watchdog so proxy settings auto-clear on disconnect.
func Setup(opts SetupOptions) error {
	_, err := SetupDetailed(opts)
	return err
}

// SetupDetailed performs full Android device setup and returns structured
// diagnostics covering CA cert, Companion Guard, and proxy/VPN mode.
func SetupDetailed(opts SetupOptions) (*SetupResult, error) {
	serial, err := GetDeviceSerial(opts.Serial)
	if err != nil {
		return nil, err
	}

	host := opts.ProxyHost
	if host == "" {
		host, err = detectHostIP()
		if err != nil {
			return nil, fmt.Errorf("auto-detect host IP: %w (pass ProxyHost explicitly)", err)
		}
	}

	port := opts.ProxyPort
	if port == "" {
		port = "8080"
	}
	redirPort := opts.RedirPort
	if redirPort == "" {
		redirPort = "9999"
	}

	mode := "proxy"
	if opts.VPN {
		mode = "vpn"
	}

	res := &SetupResult{
		Serial:    serial,
		ProxyHost: host,
		ProxyPort: port,
		Mode:      mode,
		Rooted:    IsRooted(serial),
	}
	if opts.VPN {
		res.RedirPort = redirPort
	}

	// Step 1: Ensure Companion Guard APK (best-effort by default so cert KeyChain flow & watchdog work)
	companionReady := false
	if !opts.NoCompanion {
		if err := InstallCompanion(serial); err != nil {
			res.CompanionWarning = fmt.Sprintf("companion install skipped: %v", err)
		} else {
			companionReady = true
		}
	}

	// Step 2: Install & verify CA cert if requested
	if opts.InstallCert {
		if opts.CACertPath == "" {
			return nil, fmt.Errorf("InstallCert is true but CACertPath is empty")
		}
		certRes, err := InstallCACert(serial, opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("install CA cert: %w", err)
		}
		res.CertResult = &certRes
		res.CertStatus = CheckCertStatus(serial, opts.CACertPath)
		fmt.Printf("device %s: CA certificate %s (%s)\n", serial, certRes.Method, certRes.Store)
	} else if opts.CACertPath != "" {
		res.CertStatus = CheckCertStatus(serial, opts.CACertPath)
	}

	// Step 3: Configure traffic routing (VPN/iptables or global Wi-Fi proxy)
	if opts.VPN {
		// Ensure global http_proxy doesn't conflict with transparent redirect
		_, _ = clearGlobalProxySettings(serial)
		if err := setupVPN(serial, host, port, opts.RedirBinary, redirPort); err != nil {
			return nil, err
		}
	} else {
		// Clear stale auxiliary proxy keys before setting global http_proxy
		_, _ = AdbShell(serial, "settings delete global global_http_proxy_host 2>/dev/null; settings delete global global_http_proxy_port 2>/dev/null; settings delete global global_http_proxy_exclusion_list 2>/dev/null; true")
		proxySetting := fmt.Sprintf("%s:%s", host, port)
		if _, err := AdbShell(serial, "settings put global http_proxy "+proxySetting); err != nil {
			return nil, fmt.Errorf("set proxy on %s: %w", serial, err)
		}
		fmt.Printf("device %s: proxy set to %s\n", serial, proxySetting)
	}

	// Step 4: Start Companion Guard watchdog pointing at host:port
	if !opts.NoCompanion && companionReady {
		if err := StartCompanionGuardWithConfig(serial, host, port, mode, redirPort, opts.HeartbeatMs, opts.MissThreshold); err != nil {
			res.CompanionWarning = fmt.Sprintf("companion watchdog failed to start: %v", err)
		}
	}
	res.CompanionStatus = GetCompanionStatus(serial)

	return res, nil
}

// setupVPN pushes the embedded cap-redir binary to the device and sets up
// iptables to redirect all HTTP/HTTPS traffic through it.
func setupVPN(serial, proxyHost, proxyPort, _ string, redirPort string) error {
	if redirPort == "" {
		redirPort = "9999"
	}

	if !IsRooted(serial) {
		return fmt.Errorf("VPN mode requires a rooted device")
	}

	// Write embedded binary to temp file, then push to device
	tmpFile, err := os.CreateTemp("", "cap-redir-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(capRedirBinary); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write cap-redir: %w", err)
	}
	tmpFile.Close()

	remoteBin := "/data/local/tmp/cap-redir"
	if _, err := AdbCmd(serial, "push", tmpFile.Name(), remoteBin); err != nil {
		return fmt.Errorf("push cap-redir: %w", err)
	}
	if _, err := SuShell(serial, "chmod 755 "+remoteBin); err != nil {
		return fmt.Errorf("chmod cap-redir: %w", err)
	}

	// Kill any existing cap-redir
	_, _ = SuShell(serial, "pkill -f cap-redir 2>/dev/null || true")

	proxyAddr := fmt.Sprintf("%s:%s", proxyHost, proxyPort)

	// Start cap-redir in background and record active redirPort for reliable Teardown
	startCmd := fmt.Sprintf(
		"echo %s > %s; nohup %s -proxy %s -listen :%s > /data/local/tmp/cap-redir.log 2>&1 &",
		shellQuote(redirPort), redirPortStateFile, remoteBin, proxyAddr, redirPort,
	)
	if _, err := SuShell(serial, startCmd); err != nil {
		return fmt.Errorf("start cap-redir: %w", err)
	}
	fmt.Printf("device %s: cap-redir started (proxy=%s, listen=:%s)\n", serial, proxyAddr, redirPort)

	// Set up iptables (deduplicating any pre-existing rules first)
	script := fmt.Sprintf(`
while iptables -t nat -D OUTPUT -p tcp --dport 80  -j REDIRECT --to-port %s 2>/dev/null; do :; done
while iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port %s 2>/dev/null; do :; done
iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-port %s
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port %s
echo OK
`, redirPort, redirPort, redirPort, redirPort)

	out, err := SuShellMountMaster(serial, script)
	if err != nil || !strings.Contains(out, "OK") {
		return fmt.Errorf("iptables setup failed: %s %v", out, err)
	}
	fmt.Printf("device %s: iptables REDIRECT → :%s (VPN mode active)\n", serial, redirPort)
	return nil
}

// BuildTeardownProxyCommands returns the ordered shell commands used to clear
// all Android global proxy settings reliably across Android 7–15.
func BuildTeardownProxyCommands() []string {
	return []string{
		"settings put global http_proxy :0",
		"settings delete global global_http_proxy_host",
		"settings delete global global_http_proxy_port",
		"settings delete global global_http_proxy_exclusion_list",
		"settings delete global http_proxy",
	}
}

// BuildTeardownIptablesScript constructs the root shell script that kills
// cap-redir and deletes all duplicate iptables REDIRECT rules for every
// specified port plus default port 9999.
func BuildTeardownIptablesScript(ports ...string) string {
	seen := make(map[string]bool)
	ordered := make([]string, 0, len(ports)+1)
	for _, p := range append(ports, "9999") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		ordered = append(ordered, p)
	}

	var b strings.Builder
	b.WriteString("pkill -f cap-redir 2>/dev/null || true\n")
	b.WriteString("rm -f " + redirPortStateFile + " 2>/dev/null || true\n")
	for _, p := range ordered {
		fmt.Fprintf(&b, "while iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-port %s 2>/dev/null; do :; done\n", p)
		fmt.Fprintf(&b, "while iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port %s 2>/dev/null; do :; done\n", p)
	}
	b.WriteString("echo OK")
	return b.String()
}

func clearGlobalProxySettings(serial string) (string, error) {
	cmds := BuildTeardownProxyCommands()
	var firstErr error
	for _, c := range cmds {
		if _, err := AdbShell(serial, c); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Verify http_proxy is actually cleared
	cur, err := AdbShell(serial, "settings get global http_proxy")
	if err == nil {
		if host, _ := ParseProxySetting(cur); host != "" {
			// Retry explicit :0 reset
			_, _ = AdbShell(serial, "settings put global http_proxy :0")
			cur, _ = AdbShell(serial, "settings get global http_proxy")
		}
	}
	return cur, firstErr
}

// Teardown stops Companion Guard, clears all Android global proxy settings,
// removes any VPN/iptables REDIRECT rules & cap-redir process, and verifies
// that global http_proxy is cleared.
func Teardown(serial string) error {
	serial, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}

	// 1. Stop Companion Guard cleanly (dismisses ongoing notification & stops watchdog)
	_ = StopCompanionGuard(serial)

	// 2. Clear all global proxy settings
	cur, clearErr := clearGlobalProxySettings(serial)

	// 3. Clean up VPN mode (read recorded redirPort + always clean 9999)
	recordedPort, _ := AdbShell(serial, "cat "+redirPortStateFile+" 2>/dev/null || true")
	iptablesScript := BuildTeardownIptablesScript(recordedPort)
	_, _ = SuShellMountMaster(serial, iptablesScript)

	// 4. Verify global proxy is actually cleared
	if host, _ := ParseProxySetting(cur); host != "" {
		return fmt.Errorf("proxy on %s remained set to %q after teardown (%v)", serial, cur, clearErr)
	}
	if clearErr != nil && strings.TrimSpace(cur) == "" {
		// If clearing failed and we couldn't even read back settings, surface the error.
		if _, checkErr := AdbShell(serial, "settings get global http_proxy"); checkErr != nil {
			return fmt.Errorf("clear proxy on %s: %w", serial, clearErr)
		}
	}

	fmt.Printf("device %s: proxy, companion guard, and VPN mode cleared\n", serial)
	return nil
}

// GetDeviceStatus inspects a connected Android device and returns structured
// proxy, VPN, CA certificate, and Companion Guard status.
func GetDeviceStatus(serial, certPath string) (*DeviceStatus, error) {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return nil, err
	}
	serial = resolved

	model, _ := AdbShell(serial, "getprop ro.product.model")
	brand, _ := AdbShell(serial, "getprop ro.product.brand")
	release, _ := AdbShell(serial, "getprop ro.build.version.release")
	sdk, _ := AdbShell(serial, "getprop ro.build.version.sdk")
	proxySetting, _ := AdbShell(serial, "settings get global http_proxy")
	host, port := ParseProxySetting(proxySetting)
	proxyAddr := ""
	if host != "" {
		if port != "" {
			proxyAddr = host + ":" + port
		} else {
			proxyAddr = host
		}
	}

	rooted := IsRooted(serial)

	vpnActive := false
	redirPort := ""
	psOut, _ := AdbShell(serial, "pidof cap-redir 2>/dev/null || ps -A 2>/dev/null | grep cap-redir")
	if strings.TrimSpace(psOut) != "" && !strings.Contains(psOut, "not found") {
		vpnActive = true
		pOut, _ := AdbShell(serial, "cat "+redirPortStateFile+" 2>/dev/null || true")
		redirPort = strings.TrimSpace(pOut)
		if redirPort == "" {
			redirPort = "9999"
		}
	}

	var certStatus CertStatus
	if certPath != "" {
		certStatus = CheckCertStatus(serial, certPath)
	}
	companion := GetCompanionStatus(serial)

	return &DeviceStatus{
		Serial:          serial,
		State:           "device",
		Model:           model,
		Brand:           brand,
		AndroidVersion:  release,
		SDK:             sdk,
		Rooted:          rooted,
		ProxyHost:       host,
		ProxyPort:       port,
		ProxyAddress:    proxyAddr,
		VPNActive:       vpnActive,
		RedirPort:       redirPort,
		CertStatus:      certStatus,
		CompanionStatus: companion,
	}, nil
}

// Status prints the resolved device's identity, Android version, root
// status, current proxy/VPN configuration, CA cert status, and Companion Guard status.
func Status(serial string) error {
	certPath := defaultLocalCertPath()
	st, err := GetDeviceStatus(serial, certPath)
	if err != nil {
		return err
	}

	fmt.Printf("Device:    %s (%s)\n", st.Serial, st.Model)
	fmt.Printf("Android:   %s (SDK %s)\n", st.AndroidVersion, st.SDK)
	fmt.Printf("Rooted:    %v\n", st.Rooted)
	if st.ProxyAddress == "" {
		fmt.Println("Proxy:     (not set)")
	} else {
		fmt.Printf("Proxy:     %s\n", st.ProxyAddress)
	}
	if st.VPNActive {
		fmt.Printf("VPN Mode:  active (cap-redir :%s)\n", st.RedirPort)
	} else {
		fmt.Println("VPN Mode:  inactive")
	}
	if certPath != "" {
		fmt.Printf("CA Cert:   %s (installed=%v, hash=%s)\n", st.CertStatus.Store, st.CertStatus.Installed, st.CertStatus.Hash)
	}
	fmt.Printf("Companion: installed=%v version=%s secure_settings=%v watchdog=%v\n",
		st.CompanionStatus.Installed,
		st.CompanionStatus.Version,
		st.CompanionStatus.HasSecureSettings,
		st.CompanionStatus.WatchdogRunning,
	)
	return nil
}

func defaultLocalCertPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(home, ".cap", "cap-ca.crt")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// detectHostIP returns the first non-loopback IPv4 address among this
// host's network interfaces — a best-effort default for "the IP an
// Android device on the same network can reach this machine at". Callers
// on multi-homed hosts (VPNs, multiple NICs) should pass ProxyHost
// explicitly instead of relying on this.
func detectHostIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	return "", fmt.Errorf("no non-loopback IPv4 network interface found")
}
