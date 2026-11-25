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

	// Step 4: Start Companion Guard watchdog pointing at host:port & sync CA cert metadata
	if !opts.NoCompanion && companionReady {
		if opts.CACertPath != "" {
			_ = SyncCompanionCert(serial, opts.CACertPath)
		}
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

// GetDeviceStatus inspects a connected Android device in a single batched
// `adb shell` invocation (plus at most one `su` probe if rooted and cert
// wasn't already found in system/APEX) and returns structured proxy, VPN,
// CA certificate, and Companion Guard status.
func GetDeviceStatus(serial, certPath string) (*DeviceStatus, error) {
	resolved, err := GetDeviceSerial(serial)
	if err != nil {
		return nil, err
	}
	serial = resolved

	hashName := ""
	if certPath != "" {
		hashName = CertHashFilename(certPath)
	}

	var b strings.Builder
	b.WriteString(`echo "===CAP_META==="; `)
	b.WriteString(`echo "MODEL=$(getprop ro.product.model)"; `)
	b.WriteString(`echo "BRAND=$(getprop ro.product.brand)"; `)
	b.WriteString(`echo "RELEASE=$(getprop ro.build.version.release)"; `)
	b.WriteString(`echo "SDK=$(getprop ro.build.version.sdk)"; `)
	b.WriteString(`echo "PROXY=$(settings get global http_proxy 2>/dev/null)"; `)
	b.WriteString(`echo "ROOT=$(su -c id 2>/dev/null || true)"; `)
	b.WriteString(`echo "REDIR_PID=$(pidof cap-redir 2>/dev/null || (ps -A 2>/dev/null | grep cap-redir | grep -v grep) || true)"; `)
	b.WriteString(`echo "REDIR_PORT=$(cat ` + redirPortStateFile + ` 2>/dev/null || true)"; `)
	b.WriteString(`echo "===CAP_CERT==="; `)
	if hashName != "" {
		fmt.Fprintf(&b,
			`[ -d /apex/com.android.conscrypt/cacerts ] && echo HAS_APEX_DIR; `+
				`[ -f /apex/com.android.conscrypt/cacerts/%s ] && echo APEX; `+
				`[ -f /system/etc/security/cacerts/%s ] && echo SYSTEM; `+
				`[ -f /data/misc/user/0/cacerts-added/%s ] && echo USER; `+
				`[ -f /data/adb/modules/cap-cert/system/etc/security/cacerts/%s ] && echo MAGISK; `,
			hashName, hashName, hashName, hashName,
		)
	}
	fmt.Fprintf(&b,
		`echo "===CAP_PKG==="; dumpsys package %s 2>/dev/null; `+
			`echo "===CAP_SVC==="; dumpsys activity services %s 2>/dev/null; `+
			`echo "===CAP_WL==="; dumpsys deviceidle whitelist 2>/dev/null; true`,
		CompanionPackage, CompanionService,
	)

	out, err := AdbShell(serial, b.String())
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, err
	}

	st := ParseBatchedDeviceStatusOutput(serial, hashName, certPath != "", out)

	// Unprivileged adb shell cannot read /data/adb/modules or /data/misc/user/0/cacerts-added
	// (Permission denied on Android 10–15) and may sit in an isolated mount namespace.
	// Probe via root whenever not yet confirmed installed (including legacy_system_only!).
	if hashName != "" && !st.CertStatus.Installed && st.Rooted {
		suOut, _ := SuShellMountMaster(serial, buildRootCertProbeCmd(hashName))
		if strings.TrimSpace(suOut) != "" {
			certSec := extractSection(out, "===CAP_CERT===", "===CAP_PKG===")
			st.CertStatus = ParseCertCheckOutput(hashName, certSec+"\n"+suOut)
		}
	}

	// Zero-root fallback: when still not confirmed installed and Companion Guard is
	// present, query Android's live AndroidCAStore via CertStatusReceiver so non-rooted
	// User CA installs are detected accurately on Android 10–15.
	if hashName != "" && !st.CertStatus.Installed && st.CompanionStatus.Installed {
		if compStatus, ok := CheckCertViaCompanion(serial, certPath); ok && compStatus.Installed {
			st.CertStatus = compStatus
		}
	}

	return st, nil
}

// ParseBatchedDeviceStatusOutput parses the sectioned output emitted by
// GetDeviceStatus's single batched `adb shell` call into a *DeviceStatus.
func ParseBatchedDeviceStatusOutput(serial, hashName string, wantCert bool, output string) *DeviceStatus {
	metaSec := extractSection(output, "===CAP_META===", "===CAP_CERT===")
	certSec := extractSection(output, "===CAP_CERT===", "===CAP_PKG===")

	meta := make(map[string]string, 8)
	for _, line := range strings.Split(metaSec, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.IndexByte(line, '='); idx > 0 {
			meta[line[:idx]] = strings.TrimSpace(line[idx+1:])
		}
	}

	host, port := ParseProxySetting(meta["PROXY"])
	proxyAddr := ""
	if host != "" {
		if port != "" {
			proxyAddr = host + ":" + port
		} else {
			proxyAddr = host
		}
	}

	rooted := strings.Contains(meta["ROOT"], "uid=0")

	vpnActive := false
	redirPort := ""
	pidOut := meta["REDIR_PID"]
	if pidOut != "" && !strings.Contains(pidOut, "not found") {
		vpnActive = true
		redirPort = meta["REDIR_PORT"]
		if redirPort == "" {
			redirPort = "9999"
		}
	}

	var certStatus CertStatus
	if wantCert {
		if hashName == "" {
			certStatus = CertStatus{
				Installed: false,
				Store:     "none",
				Details:   "local CA certificate file not found or invalid",
			}
		} else {
			certStatus = ParseCertCheckOutput(hashName, certSec)
		}
	}

	companion := ParseBatchedCompanionOutput(output)

	return &DeviceStatus{
		Serial:          serial,
		State:           "device",
		Model:           meta["MODEL"],
		Brand:           meta["BRAND"],
		AndroidVersion:  meta["RELEASE"],
		SDK:             meta["SDK"],
		Rooted:          rooted,
		ProxyHost:       host,
		ProxyPort:       port,
		ProxyAddress:    proxyAddr,
		VPNActive:       vpnActive,
		RedirPort:       redirPort,
		CertStatus:      certStatus,
		CompanionStatus: companion,
	}
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

// hostIPCandidate represents a single IPv4 address bound to a network
// interface, used by selectBestHostIP for deterministic LAN interface ranking.
type hostIPCandidate struct {
	ifaceName string
	ip        net.IP
	up        bool
	loopback  bool
}

// DetectHostIP returns the best LAN IPv4 address on this host that an Android
// device on the same Wi-Fi network can reach, skipping down, loopback,
// link-local, and virtual/VPN tunnel interfaces (utun, awdl, llw, bridge,
// docker, veth, 169.254.*, 198.18.*).
func DetectHostIP() (string, error) {
	return detectHostIP()
}

// LocalHostIPv4s returns all active non-loopback IPv4 addresses on this host.
func LocalHostIPv4s() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []string
	seen := make(map[string]bool)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			s := ip4.String()
			if !seen[s] {
				seen[s] = true
				ips = append(ips, s)
			}
		}
	}
	return ips
}

func detectHostIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var candidates []hostIPCandidate
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		up := iface.Flags&net.FlagUp != 0
		loopback := iface.Flags&net.FlagLoopback != 0
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			candidates = append(candidates, hostIPCandidate{
				ifaceName: iface.Name,
				ip:        ip4,
				up:        up,
				loopback:  loopback,
			})
		}
	}
	if best := selectBestHostIP(candidates); best != "" {
		return best, nil
	}
	return "", fmt.Errorf("no non-loopback IPv4 network interface found")
}

func selectBestHostIP(candidates []hostIPCandidate) string {
	bestScore := -1
	bestIP := ""
	for _, c := range candidates {
		score := scoreHostIPCandidate(c)
		if score > bestScore {
			bestScore = score
			bestIP = c.ip.String()
		}
	}
	return bestIP
}

func scoreHostIPCandidate(c hostIPCandidate) int {
	if !c.up || c.loopback || c.ip == nil {
		return -1
	}
	ip4 := c.ip.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsLinkLocalMulticast() {
		return -1
	}
	// Skip 198.18.0.0/15 (RFC 2544 benchmark / Clash & Surge fake-IP TUN range)
	if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
		return -1
	}

	name := strings.ToLower(c.ifaceName)
	virtual := isVirtualInterfaceName(name)
	private := isRFC1918(ip4)

	if virtual {
		// Keep virtual non-link-local IPv4 only as a very last fallback
		if private {
			return 10
		}
		return 5
	}

	score := 50
	if private {
		score += 40
	}
	switch {
	case name == "en0" || name == "wlan0":
		score += 30
	case name == "en1" || name == "eth0" || strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wlp"):
		score += 20
	case strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth"):
		score += 10
	}
	return score
}

func isVirtualInterfaceName(name string) bool {
	prefixes := []string{
		"utun", "awdl", "llw", "bridge", "docker", "veth",
		"lo", "vmnet", "vboxnet", "tailscale", "tun", "tap",
		"anpi", "ap", "gif", "stf", "ipsec", "feth", "pktap",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func isRFC1918(ip4 net.IP) bool {
	return ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168)
}
