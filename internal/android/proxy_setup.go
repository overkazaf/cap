package android

import (
	"fmt"
	"net"
)

// Setup configures an Android device to route HTTP(S) traffic through
// cap's proxy:
//
//  1. Resolve which device to use (opts.Serial, or auto-detect).
//  2. Auto-detect this host's LAN IPv4 address if opts.ProxyHost is empty.
//  3. Point the device's global Wi-Fi proxy at host:port.
//  4. If opts.InstallCert is set, push and install opts.CACertPath so the
//     device trusts cap's MITM certificate.
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

	proxySetting := fmt.Sprintf("%s:%s", host, opts.ProxyPort)
	if _, err := adbShell(serial, "settings put global http_proxy "+proxySetting); err != nil {
		return fmt.Errorf("set proxy on %s: %w", serial, err)
	}
	fmt.Printf("device %s: proxy set to %s\n", serial, proxySetting)

	if opts.InstallCert {
		if opts.CACertPath == "" {
			return fmt.Errorf("InstallCert is true but CACertPath is empty")
		}
		if err := installCACert(serial, opts.CACertPath); err != nil {
			return fmt.Errorf("install CA cert: %w", err)
		}
		fmt.Printf("device %s: CA certificate installed\n", serial)
	}

	return nil
}

// Teardown clears the device's Wi-Fi proxy, restoring normal connectivity.
// It does not remove any CA certificate installed by Setup: on rooted
// devices the system cert can be removed by re-running the rooted install
// steps in reverse, but on non-root devices a user-added cert can only be
// removed from the device's Settings > Security UI, so cap leaves it in
// place rather than attempting a partial, surprising cleanup.
func Teardown(serial string) error {
	serial, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}
	if _, err := adbShell(serial, "settings put global http_proxy :0"); err != nil {
		return fmt.Errorf("clear proxy on %s: %w", serial, err)
	}
	fmt.Printf("device %s: proxy cleared\n", serial)
	return nil
}

// Status prints the resolved device's identity, Android version, root
// status, and current proxy configuration.
func Status(serial string) error {
	serial, err := GetDeviceSerial(serial)
	if err != nil {
		return err
	}

	model, _ := adbShell(serial, "getprop ro.product.model")
	release, _ := adbShell(serial, "getprop ro.build.version.release")
	proxySetting, _ := adbShell(serial, "settings get global http_proxy")
	host, port := ParseProxySetting(proxySetting)

	fmt.Printf("Device:  %s (%s)\n", serial, model)
	fmt.Printf("Android: %s\n", release)
	fmt.Printf("Rooted:  %v\n", isRooted(serial))
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
