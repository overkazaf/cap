package android

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Setup configures an Android device to route HTTP(S) traffic through
// cap's proxy. In normal mode it sets the global Wi-Fi proxy; in VPN
// mode it pushes the cap-redir binary and sets up iptables REDIRECT.
func Setup(opts SetupOptions) error {
	serial, err := GetDeviceSerial(opts.Serial)
	if err != nil {
		return err
	}

	host := opts.ProxyHost
	if host == "" {
		host, err = detectHostIP()
		if err != nil {
			return fmt.Errorf("auto-detect host IP: %w (pass ProxyHost explicitly)", err)
		}
	}

	if opts.InstallCert {
		if opts.CACertPath == "" {
			return fmt.Errorf("InstallCert is true but CACertPath is empty")
		}
		if err := installCACert(serial, opts.CACertPath); err != nil {
			return fmt.Errorf("install CA cert: %w", err)
		}
		fmt.Printf("device %s: CA certificate installed\n", serial)
	}

	if opts.VPN {
		return setupVPN(serial, host, opts.ProxyPort, opts.RedirBinary, opts.RedirPort)
	}

	proxySetting := fmt.Sprintf("%s:%s", host, opts.ProxyPort)
	if _, err := AdbShell(serial, "settings put global http_proxy "+proxySetting); err != nil {
		return fmt.Errorf("set proxy on %s: %w", serial, err)
	}
	fmt.Printf("device %s: proxy set to %s\n", serial, proxySetting)
	return nil
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
	SuShell(serial, "pkill -f cap-redir 2>/dev/null || true")

	proxyAddr := fmt.Sprintf("%s:%s", proxyHost, proxyPort)

	// Start cap-redir in background
	startCmd := fmt.Sprintf("nohup %s -proxy %s -listen :%s > /data/local/tmp/cap-redir.log 2>&1 &",
		remoteBin, proxyAddr, redirPort)
	if _, err := SuShell(serial, startCmd); err != nil {
		return fmt.Errorf("start cap-redir: %w", err)
	}
	fmt.Printf("device %s: cap-redir started (proxy=%s, listen=:%s)\n", serial, proxyAddr, redirPort)

	// Set up iptables
	script := fmt.Sprintf(`
iptables -t nat -D OUTPUT -p tcp --dport 80  -j REDIRECT --to-port %s 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port %s 2>/dev/null || true
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

// Teardown clears both normal proxy and VPN mode, restoring connectivity.
func Teardown(serial string) error {
	serial, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}

	// Clear system proxy
	if _, err := AdbShell(serial, "settings put global http_proxy :0"); err != nil {
		return fmt.Errorf("clear proxy on %s: %w", serial, err)
	}

	// Clean up VPN mode (safe to run even if not in VPN mode)
	SuShell(serial, "pkill -f cap-redir 2>/dev/null || true")
	SuShell(serial, "iptables -t nat -D OUTPUT -p tcp --dport 80  -j REDIRECT --to-port 9999 2>/dev/null || true")
	SuShell(serial, "iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 9999 2>/dev/null || true")

	fmt.Printf("device %s: proxy and VPN mode cleared\n", serial)
	return nil
}

// Status prints the resolved device's identity, Android version, root
// status, and current proxy configuration.
func Status(serial string) error {
	serial, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}

	model, _ := AdbShell(serial, "getprop ro.product.model")
	release, _ := AdbShell(serial, "getprop ro.build.version.release")
	proxySetting, _ := AdbShell(serial, "settings get global http_proxy")
	host, port := ParseProxySetting(proxySetting)

	fmt.Printf("Device:  %s (%s)\n", serial, model)
	fmt.Printf("Android: %s\n", release)
	fmt.Printf("Rooted:  %v\n", IsRooted(serial))
	if host == "" {
		fmt.Println("Proxy:   (not set)")
	} else {
		fmt.Printf("Proxy:   %s:%s\n", host, port)
	}
	return nil
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
