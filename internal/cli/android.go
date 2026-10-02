package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/proxy"
)

// newAndroidCmd builds `cap android` and its connect/disconnect/status
// subcommands for one-command Android device traffic capture setup.
func newAndroidCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "android",
		Short: "Android device management",
		Long:  "Configure an Android device (over ADB) to route HTTP(S) traffic through cap's proxy and trust its MITM certificate.",
	}

	cmd.AddCommand(
		newAndroidConnectCmd(),
		newAndroidDisconnectCmd(),
		newAndroidStatusCmd(),
	)

	return cmd
}

// newAndroidConnectCmd builds `cap android connect`: point the device's
// Wi-Fi proxy at cap and, unless --no-cert is set, install cap's CA
// certificate so intercepted HTTPS is trusted.
func newAndroidConnectCmd() *cobra.Command {
	var serial, proxyHost, proxyPort string
	var noCert bool

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Point an Android device's proxy at cap",
		RunE: func(cmd *cobra.Command, args []string) error {
			var certFile string
			if !noCert {
				var err error
				certFile, _, err = proxy.EnsureCA(defaultCapDir())
				if err != nil {
					return fmt.Errorf("ensure CA certificate: %w", err)
				}
			}

			return android.Setup(android.SetupOptions{
				ProxyHost:   proxyHost,
				ProxyPort:   proxyPort,
				Serial:      serial,
				CACertPath:  certFile,
				InstallCert: !noCert,
			})
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")
	cmd.Flags().StringVar(&proxyHost, "proxy-host", "", "host IP the device should connect to (auto-detect if omitted)")
	cmd.Flags().StringVarP(&proxyPort, "proxy-port", "p", "8080", "cap's proxy port")
	cmd.Flags().BoolVar(&noCert, "no-cert", false, "skip installing cap's CA certificate on the device")

	return cmd
}

// newAndroidDisconnectCmd builds `cap android disconnect`: clear the
// device's proxy setting.
func newAndroidDisconnectCmd() *cobra.Command {
	var serial string

	cmd := &cobra.Command{
		Use:   "disconnect",
		Short: "Clear the proxy configured on an Android device",
		RunE: func(cmd *cobra.Command, args []string) error {
			return android.Teardown(serial)
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")

	return cmd
}

// newAndroidStatusCmd builds `cap android status`: print the device's
// identity, root status, and current proxy configuration.
func newAndroidStatusCmd() *cobra.Command {
	var serial string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show an Android device's identity and proxy configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return android.Status(serial)
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")

	return cmd
}
