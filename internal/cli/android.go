package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/tui"
)

// newAndroidCmd builds `cap android` and its connect/disconnect/status/cert
// subcommands for one-command Android device traffic capture setup.
func newAndroidCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "android",
		Short: "Android device management",
		Long:  "Configure an Android device (over ADB) to route HTTP(S) traffic through cap's proxy, install its MITM CA certificate, and deploy the Cap Companion Guard watchdog.",
	}

	cmd.AddCommand(
		newAndroidConnectCmd(),
		newAndroidDisconnectCmd(),
		newAndroidStatusCmd(),
		newAndroidCertCmd(),
	)

	return cmd
}

// newAndroidConnectCmd builds `cap android connect`: point the device's
// Wi-Fi proxy (or VPN iptables redirect) at cap, install the CA certificate,
// and deploy the Companion Guard watchdog so phone network auto-restores on exit.
func newAndroidConnectCmd() *cobra.Command {
	var serial, proxyHost, proxyPort string
	var noCert, vpn, noCompanion bool

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Point an Android device's proxy at cap",
		Long: "Connect an Android device to cap's proxy.\n\n" +
			"By default, sets the system-wide Wi-Fi proxy, installs cap's CA certificate,\n" +
			"and deploys the embedded Cap Companion Guard APK watchdog so the phone's\n" +
			"network auto-restores if USB disconnects or cap exits. Use --no-companion to\n" +
			"skip the Companion Guard APK, or --vpn for root iptables transparent redirect.",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			styled := isStyledWriter(out)
			th := cliTheme(styled)

			mode := i18n.T("cli.android.mode.wifi")
			if vpn {
				mode = i18n.T("cli.android.mode.vpn")
			}
			if styled {
				printSectionHeader(out, th, i18n.T("cli.android.connect.title"), fmt.Sprintf("%s · :%s", mode, proxyPort))
			}

			var certFile string
			if !noCert {
				var err error
				certFile, _, err = proxy.EnsureCA(defaultCapDir())
				if err != nil {
					return fmt.Errorf("ensure CA certificate: %w", err)
				}
			} else {
				certFile = filepath.Join(defaultCapDir(), "ca.crt")
			}

			res, err := android.SetupDetailed(android.SetupOptions{
				ProxyHost:   proxyHost,
				ProxyPort:   proxyPort,
				Serial:      serial,
				CACertPath:  certFile,
				InstallCert: !noCert,
				VPN:         vpn,
				NoCompanion: noCompanion,
			})
			if err != nil {
				return err
			}

			renderAndroidSetupResult(out, styled, th, res)
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")
	cmd.Flags().StringVar(&proxyHost, "proxy-host", "", "host IP the device should connect to (auto-detect if omitted)")
	cmd.Flags().StringVarP(&proxyPort, "proxy-port", "p", "8080", "cap's proxy port")
	cmd.Flags().BoolVar(&noCert, "no-cert", false, "skip installing cap's CA certificate on the device")
	cmd.Flags().BoolVar(&vpn, "vpn", false, "use iptables redirect instead of system proxy (requires root)")
	cmd.Flags().BoolVar(&noCompanion, "no-companion", false, "skip installing and starting the Cap Companion Guard APK watchdog")

	return cmd
}

// newAndroidDisconnectCmd builds `cap android disconnect`: stop Companion Guard
// and clear all Android proxy & VPN redirect settings cleanly.
func newAndroidDisconnectCmd() *cobra.Command {
	var serial string

	cmd := &cobra.Command{
		Use:   "disconnect",
		Short: "Clear proxy, VPN redirect, and Companion Guard on an Android device",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			styled := isStyledWriter(out)
			th := cliTheme(styled)

			if styled {
				printSectionHeader(out, th, i18n.T("cli.android.disconnect.title"), i18n.T("cli.android.disconnect.sub"))
			}
			if err := android.Teardown(serial); err != nil {
				return err
			}
			if styled {
				fmt.Fprintln(out)
				printSuccessBadge(out, th, i18n.T("cli.android.disconnect.ok"))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")

	return cmd
}

// newAndroidStatusCmd builds `cap android status`: inspect device identity,
// root status, proxy/VPN configuration, CA cert store, and Companion Guard state.
func newAndroidStatusCmd() *cobra.Command {
	var serial string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show Android device identity, proxy, CA cert, and Companion Guard status",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			certPath := filepath.Join(defaultCapDir(), "ca.crt")

			st, err := android.GetDeviceStatus(serial, certPath)
			if err != nil {
				return err
			}

			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			renderAndroidStatus(out, styled, th, st)
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output device status as JSON")

	return cmd
}

// newAndroidCertCmd builds `cap android cert`: install, verify, or remove
// cap's MITM CA certificate on a connected Android device.
func newAndroidCertCmd() *cobra.Command {
	var serial string
	var checkOnly bool
	var remove bool

	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Install, verify, or remove cap's CA certificate on an Android device",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			styled := isStyledWriter(out)
			th := cliTheme(styled)

			if styled {
				printSectionHeader(out, th, i18n.T("cli.android.cert.title"), i18n.T("cli.android.cert.sub"))
			}

			certFile, _, err := proxy.EnsureCA(defaultCapDir())
			if err != nil {
				return fmt.Errorf("ensure CA certificate: %w", err)
			}

			resolvedSerial, err := android.GetDeviceSerial(serial)
			if err != nil {
				return err
			}

			if checkOnly {
				cs := android.CheckCertStatus(resolvedSerial, certFile)
				renderCertStatusLine(out, styled, th, cs)
				return nil
			}

			if remove {
				if err := android.RemoveCACert(resolvedSerial, certFile); err != nil {
					return err
				}
				if styled {
					printSuccessBadge(out, th, fmt.Sprintf("CA certificate removed on %s", resolvedSerial))
				} else {
					fmt.Fprintf(out, "device %s: CA certificate removed\n", resolvedSerial)
				}
				return nil
			}

			res, err := android.InstallCACert(resolvedSerial, certFile)
			if err != nil {
				return err
			}
			if styled {
				printSuccessBadge(out, th, i18n.T("cli.android.cert.ok", res.Method))
				if res.Message != "" {
					printHint(out, th, res.Message)
				}
			} else {
				fmt.Fprintf(out, "device %s: CA cert %s (store=%s, hash=%s)\n", resolvedSerial, res.Method, res.Store, res.Hash)
				if res.Message != "" {
					fmt.Fprintln(out, res.Message)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")
	cmd.Flags().BoolVar(&checkOnly, "check", false, "only check current CA certificate status on device")
	cmd.Flags().BoolVar(&remove, "remove", false, "remove installed CA certificate (rooted devices)")

	return cmd
}

func renderAndroidSetupResult(out io.Writer, styled bool, th tui.Theme, res *android.SetupResult) {
	if res == nil {
		return
	}
	if !styled {
		fmt.Fprintf(out, "Device:    %s (mode=%s, proxy=%s:%s)\n", res.Serial, res.Mode, res.ProxyHost, res.ProxyPort)
		fmt.Fprintf(out, "CA Cert:   store=%s installed=%v hash=%s\n", res.CertStatus.Store, res.CertStatus.Installed, res.CertStatus.Hash)
		fmt.Fprintf(out, "Companion: installed=%v watchdog=%v secure_settings=%v\n",
			res.CompanionStatus.Installed, res.CompanionStatus.WatchdogRunning, res.CompanionStatus.HasSecureSettings)
		if res.CompanionWarning != "" {
			fmt.Fprintf(out, "Warning:   %s\n", res.CompanionWarning)
		}
		if res.CertResult != nil && res.CertResult.Message != "" {
			fmt.Fprintln(out, res.CertResult.Message)
		}
		return
	}

	fmt.Fprintln(out)
	kv := func(label, val string) {
		fmt.Fprintf(out, "  %s %s\n", th.Fg(th.FgMuted, tui.PadRight(label, 12)), val)
	}
	kv(i18n.T("cli.android.lbl.device"), th.Bold(th.FgPrimary, res.Serial))
	kv(i18n.T("cli.android.lbl.proxy"), th.Bold(th.Info, fmt.Sprintf("%s:%s", res.ProxyHost, res.ProxyPort))+" "+th.Fg(th.FgMuted, "("+res.Mode+")"))
	kv(i18n.T("cli.android.lbl.cert"), formatCertStatusBadge(th, res.CertStatus))
	kv(i18n.T("cli.android.lbl.companion"), formatCompanionBadge(th, res.CompanionStatus))

	if res.CompanionWarning != "" {
		fmt.Fprintln(out, "  "+th.Fg(th.Warn, "▲ "+res.CompanionWarning))
	}
	if res.CertResult != nil && (res.CertResult.NeedsManual || res.CertResult.NeedsReboot) && res.CertResult.Message != "" {
		fmt.Fprintln(out, "  "+th.Fg(th.Warn, "▲ "+res.CertResult.Message))
	}

	fmt.Fprintln(out)
	printSuccessBadge(out, th, i18n.T("cli.android.connect.ok"))
	printHint(out, th, i18n.T("cli.android.connect.hint", res.ProxyPort))
}

func renderAndroidStatus(out io.Writer, styled bool, th tui.Theme, st *android.DeviceStatus) {
	if st == nil {
		return
	}
	if !styled {
		fmt.Fprintf(out, "Device:    %s (%s)\n", st.Serial, st.Model)
		fmt.Fprintf(out, "Android:   %s (SDK %s)\n", st.AndroidVersion, st.SDK)
		fmt.Fprintf(out, "Rooted:    %v\n", st.Rooted)
		if st.ProxyAddress == "" {
			fmt.Fprintln(out, "Proxy:     (not set)")
		} else {
			fmt.Fprintf(out, "Proxy:     %s\n", st.ProxyAddress)
		}
		if st.VPNActive {
			fmt.Fprintf(out, "VPN Mode:  active (redir=:%s)\n", st.RedirPort)
		}
		fmt.Fprintf(out, "CA Cert:   store=%s installed=%v hash=%s\n", st.CertStatus.Store, st.CertStatus.Installed, st.CertStatus.Hash)
		fmt.Fprintf(out, "Companion: installed=%v version=%s watchdog=%v secure_settings=%v\n",
			st.CompanionStatus.Installed, st.CompanionStatus.Version, st.CompanionStatus.WatchdogRunning, st.CompanionStatus.HasSecureSettings)
		return
	}

	printSectionHeader(out, th, i18n.T("cli.android.status.title"), i18n.T("cli.android.status.sub"))
	kv := func(label, val string) {
		fmt.Fprintf(out, "  %s %s\n", th.Fg(th.FgMuted, tui.PadRight(label, 12)), val)
	}

	devVal := th.Bold(th.FgPrimary, st.Serial)
	if st.Model != "" {
		devVal += " " + th.Fg(th.FgSecondary, "("+st.Model+")")
	}
	kv(i18n.T("cli.android.lbl.device"), devVal)

	verVal := st.AndroidVersion
	if st.SDK != "" {
		verVal += fmt.Sprintf(" (API %s)", st.SDK)
	}
	kv(i18n.T("cli.android.lbl.android"), th.Fg(th.FgPrimary, verVal))

	rootBadge := th.Fg(th.FgMuted, "false")
	if st.Rooted {
		rootBadge = th.Bold(th.Success, "true")
	}
	kv(i18n.T("cli.android.lbl.rooted"), rootBadge)

	if st.ProxyAddress == "" {
		proxyVal := th.Fg(th.FgMuted, i18n.T("cli.android.proxy.not_set"))
		if st.VPNActive {
			proxyVal = th.Bold(th.Live, "● VPN :"+st.RedirPort)
		}
		kv(i18n.T("cli.android.lbl.proxy"), proxyVal)
	} else {
		proxyVal := th.Bold(th.Info, st.ProxyAddress)
		if st.VPNActive {
			proxyVal += " " + th.Fg(th.Live, "(VPN :"+st.RedirPort+")")
		}
		kv(i18n.T("cli.android.lbl.proxy"), proxyVal)
	}

	kv(i18n.T("cli.android.lbl.cert"), formatCertStatusBadge(th, st.CertStatus))
	kv(i18n.T("cli.android.lbl.companion"), formatCompanionBadge(th, st.CompanionStatus))
}

func renderCertStatusLine(out io.Writer, styled bool, th tui.Theme, cs android.CertStatus) {
	if !styled {
		fmt.Fprintf(out, "CA Cert: store=%s installed=%v hash=%s method=%s\n", cs.Store, cs.Installed, cs.Hash, cs.Method)
		if cs.Details != "" {
			fmt.Fprintln(out, cs.Details)
		}
		return
	}
	fmt.Fprintf(out, "  %s %s\n", th.Fg(th.FgMuted, tui.PadRight(i18n.T("cli.android.lbl.cert"), 12)), formatCertStatusBadge(th, cs))
	if cs.Details != "" {
		printHint(out, th, cs.Details)
	}
}

func formatCertStatusBadge(th tui.Theme, cs android.CertStatus) string {
	var badge string
	switch cs.Store {
	case "system":
		badge = th.Bold(th.Success, "✓ "+i18n.T("cli.android.cert.system"))
	case "user":
		badge = th.Bold(th.Warn, "● "+i18n.T("cli.android.cert.user"))
	default:
		badge = th.Fg(th.Danger, "✗ "+i18n.T("cli.android.cert.none"))
	}
	if cs.Hash != "" {
		badge += " " + th.Fg(th.FgMuted, "("+cs.Hash+")")
	}
	return badge
}

func formatCompanionBadge(th tui.Theme, cs android.CompanionStatus) string {
	if !cs.Installed {
		return th.Fg(th.FgMuted, "○ "+i18n.T("cli.android.guard.missing"))
	}
	var badge string
	if cs.WatchdogRunning {
		badge = th.Bold(th.Live, "● "+i18n.T("cli.android.guard.active"))
	} else {
		badge = th.Fg(th.Info, "○ "+i18n.T("cli.android.guard.idle"))
	}
	if cs.Version != "" {
		badge += " " + th.Fg(th.FgMuted, "v"+cs.Version)
	}
	if cs.HasSecureSettings {
		badge += "  " + th.Fg(th.Success, i18n.T("cli.android.guard.perm_ok"))
	} else {
		badge += "  " + th.Fg(th.Warn, i18n.T("cli.android.guard.perm_no"))
	}
	return badge
}
