package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/tlskit"
	"github.com/overkazaf/cap/internal/tui"
)

func newTLSKitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tls",
		Short: "Modern TLS / mTLS diagnostics, JA3 profiles, APK cert scan & proxy compat scripts",
		Long: `Modern TLS, mutual TLS (mTLS), JA3 fingerprint profiles, and local-proxy diagnostic tools:

  profiles          — List curated TLS / HTTP2 client profiles and their JA3 hashes
  ja3               — Compute deterministic JA3 summary for a TLS profile ID
  scan-apk          — Scan an APK archive in pure Go for certificates, keystores, and pins
  validate-mtls     — Validate a PEM client certificate & private key pair for mTLS
  flutter           — Generate a local-proxy Flutter diagnostic Frida script
  cronet            — Generate a Cronet / OkHttp HTTP/2 local-proxy compatibility script
  mtls-observer     — Generate a strictly diagnostic mTLS KeyStore/SSLContext observer script
  curl-impersonate  — Detect host curl-impersonate binaries on PATH

Examples:
  cap tls profiles --json
  cap tls ja3 chrome_131
  cap tls scan-apk ./target.apk --json
  cap tls validate-mtls --cert ./client.pem --key ./client.key --json
  cap tls flutter --offset 0x5a1230 --proxy 127.0.0.1:8080 -o flutter_debug.js
  cap tls cronet -o cronet_h2.js
  cap tls mtls-observer -o mtls_observer.js
  cap tls curl-impersonate --json`,
	}

	cmd.AddCommand(
		newTLSProfilesCmd(),
		newTLSJA3Cmd(),
		newTLSScanAPKCmd(),
		newTLSValidateMTLSCmd(),
		newTLSFlutterCmd(),
		newTLSCronetCmd(),
		newTLSMTLSObserverCmd(),
		newTLSCurlImpersonateCmd(),
	)
	return cmd
}

func writeTLSCompatScriptOutput(cmd *cobra.Command, sc *tlskit.GeneratedCompatScript, outFile string, jsonOut bool) error {
	out := cmd.OutOrStdout()
	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(sc.Code), 0o644); err != nil {
			return fmt.Errorf("write script %s: %w", outFile, err)
		}
		fmt.Fprintf(out, "Saved %s (%s) to %s\n", sc.Name, sc.Kind, outFile)
		return nil
	}
	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(sc)
	}
	fmt.Fprint(out, sc.Code)
	if !strings.HasSuffix(sc.Code, "\n") {
		fmt.Fprintln(out)
	}
	return nil
}

func newTLSProfilesCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List all curated TLS / HTTP2 client fingerprint profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			profiles := tlskit.ListTLSProfiles()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(profiles)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.tls.profiles.title"), fmt.Sprintf("%d profile(s)", len(profiles)))
			}
			fmt.Fprintf(out, "%-16s %-22s %-10s %-14s %s\n", "ID", "NAME", "PLATFORM", "ALPN", "JA3 HASH")
			for _, p := range profiles {
				ja3Hash := ""
				if p.JA3 != nil {
					ja3Hash = p.JA3.JA3Hash
				}
				fmt.Fprintf(out, "%-16s %-22s %-10s %-14s %s\n",
					p.ID, tui.Truncate(p.Name, 22), tui.Truncate(p.Platform, 10),
					tui.Truncate(strings.Join(p.ALPN, ","), 14), ja3Hash)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output TLSProfileSpec JSON")
	return cmd
}

func newTLSJA3Cmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "ja3 [profile]",
		Short: "Compute deterministic JA3 fingerprint summary for a TLS profile",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			profileID := "go_default"
			if len(args) == 1 {
				profileID = args[0]
			}
			summary := tlskit.ComputeProfileJA3Summary(profileID)
			if summary == nil {
				return fmt.Errorf("unknown TLS profile %q (run 'cap tls profiles' to list valid IDs)", profileID)
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(summary)
			}
			fmt.Fprintf(out, "Profile: %s\n", summary.ProfileID)
			fmt.Fprintf(out, "JA3 MD5: %s\n", summary.JA3Hash)
			fmt.Fprintf(out, "JA3 Raw: %s\n", summary.JA3String)
			fmt.Fprintf(out, "Details: tls_version=0x%04x  ciphers=%d  curves=%d\n",
				summary.TLSVersion, summary.CipherCount, summary.CurveCount)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JA3Summary JSON")
	return cmd
}

func newTLSScanAPKCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "scan-apk <apk>",
		Short: "Scan an APK archive for X.509 certificates, keystores, and network_security_config pins",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			report, err := tlskit.ScanAPKForCertificates(args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.tls.scan.title"), report.APKPath)
			}
			fmt.Fprintf(out, "APK:        %s (entries=%d, bytes=%d, truncated=%v)\n",
				report.APKPath, report.EntriesScanned, report.TotalBytesRead, report.Truncated)
			fmt.Fprintf(out, "Indicators: pinning=%v  mtls=%v\n", report.HasPinning, report.HasMTLSIndicators)
			fmt.Fprintf(out, "Findings:   certs=%d  keystores=%d  net_sec_configs=%d  pins=%d\n",
				len(report.Certificates), len(report.Keystores),
				len(report.NetworkSecurityConfigs), len(report.Pins))
			if len(report.Certificates) > 0 {
				fmt.Fprintln(out, "\nCertificates:")
				for _, c := range report.Certificates {
					fmt.Fprintf(out, "  - [%s] %s  subject=%q  expired=%v\n",
						c.Format, c.SourcePath, c.Subject, c.Expired)
				}
			}
			if len(report.Keystores) > 0 {
				fmt.Fprintln(out, "\nKeystores:")
				for _, ks := range report.Keystores {
					fmt.Fprintf(out, "  - [%s] %s (%d bytes, verified=%v)\n",
						ks.Format, ks.Path, ks.SizeBytes, ks.MagicVerified)
				}
			}
			if len(report.Pins) > 0 {
				fmt.Fprintln(out, "\nPublic Key Pins:")
				for _, pin := range report.Pins {
					fmt.Fprintf(out, "  - %s:%s  domains=%s\n", pin.Digest, pin.Value, strings.Join(pin.Domains, ","))
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output APKCertScanReport JSON")
	return cmd
}

func newTLSValidateMTLSCmd() *cobra.Command {
	var (
		certPath string
		keyPath  string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "validate-mtls",
		Short: "Validate a PEM client certificate and private key pair for mutual TLS",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			res, err := tlskit.ValidateMTLSKeyPair(certPath, keyPath)
			if jsonOut && res != nil {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				_ = enc.Encode(res)
				return err
			}
			if err != nil {
				return err
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.tls.mtls.title"), certPath)
			}
			fmt.Fprintf(out, "Valid:        %v  KeyPairMatch: %v  ClientAuthEKU: %v\n",
				res.Valid, res.KeyPairMatch, res.HasClientAuthEKU)
			fmt.Fprintf(out, "Chain Length: %d  Expired: %v  NotYetValid: %v  ExpiresInDays: %d\n",
				res.ChainLength, res.Expired, res.NotYetValid, res.ExpiresInDays)
			if res.Leaf != nil {
				fmt.Fprintf(out, "Leaf Subject: %s\n", res.Leaf.Subject)
				fmt.Fprintf(out, "Leaf Issuer:  %s\n", res.Leaf.Issuer)
				fmt.Fprintf(out, "SHA-256:      %s\n", res.Leaf.SHA256Fingerprint)
			}
			for _, w := range res.Warnings {
				fmt.Fprintf(out, "Warning:      %s\n", w)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&certPath, "cert", "", "path to PEM client certificate file")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to PEM private key file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output MTLSValidationResult JSON")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func parseProxyHostPort(raw string) (string, int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, nil
	}
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if strings.Contains(s, ":") {
		host, portStr, err := net.SplitHostPort(s)
		if err != nil {
			return "", 0, fmt.Errorf("invalid --proxy %q (expected host:port): %w", raw, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid proxy port %q in %q", portStr, raw)
		}
		return host, port, nil
	}
	return s, 8080, nil
}

func newTLSFlutterCmd() *cobra.Command {
	var (
		opts    tlskit.FlutterDebugOptions
		proxy   string
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "flutter",
		Short: "Generate a local-proxy Flutter diagnostic Frida script",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(proxy) != "" {
				host, port, err := parseProxyHostPort(proxy)
				if err != nil {
					return err
				}
				opts.ProxyHost = host
				opts.ProxyPort = port
			}
			sc := tlskit.GenerateFlutterProxyDebugScript(opts)
			return writeTLSCompatScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&opts.OffsetHex, "offset", "", "optional local debug symbol hex offset (e.g. 0x5a1230)")
	cmd.Flags().StringVar(&proxy, "proxy", "127.0.0.1:8080", "local MITM proxy host:port")
	cmd.Flags().StringVar(&opts.PackageName, "pkg", "", "target app package or bundle ID")
	cmd.Flags().StringVar(&opts.Platform, "platform", "android", "target platform: android or ios")
	cmd.Flags().StringVar(&opts.ModuleName, "module", "", "Flutter module name (default libflutter.so / Flutter)")
	cmd.Flags().StringVar(&opts.VerifySymbol, "symbol", "", "optional BoringSSL verification symbol name")
	cmd.Flags().BoolVar(&opts.ForceAllowLocalVerify, "force-local-verify", false, "opt-in local dev override for your own build")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write Frida JS script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedCompatScript JSON")
	return cmd
}

func newTLSCronetCmd() *cobra.Command {
	var (
		opts    = tlskit.DefaultCronetOptions()
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "cronet",
		Short: "Generate a Cronet / OkHttp HTTP/2 local-proxy compatibility Frida script",
		RunE: func(cmd *cobra.Command, args []string) error {
			sc := tlskit.GenerateCronetHTTP2Script(opts)
			return writeTLSCompatScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&opts.PackageName, "pkg", "", "target Android package name")
	cmd.Flags().BoolVar(&opts.DisableQUIC, "disable-quic", true, "disable QUIC in CronetEngine$Builder for HTTP/2 fallback")
	cmd.Flags().BoolVar(&opts.ConfigureOkHttpProtocols, "okhttp", true, "configure OkHttp HTTP/2 + HTTP/1.1 protocols")
	cmd.Flags().BoolVar(&opts.LogAltSvcHeaders, "log-alt-svc", true, "log Alt-Svc response headers")
	cmd.Flags().StringVar(&opts.ProxyHint, "proxy-hint", "", "optional local proxy hint (e.g. 127.0.0.1:8080)")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write Frida JS script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedCompatScript JSON")
	return cmd
}

func newTLSMTLSObserverCmd() *cobra.Command {
	var (
		opts    = tlskit.DefaultMTLSObserverOptions()
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "mtls-observer",
		Short: "Generate a strictly diagnostic mTLS KeyStore/SSLContext observer Frida script",
		RunE: func(cmd *cobra.Command, args []string) error {
			sc := tlskit.GenerateMTLSObserverScript(opts)
			return writeTLSCompatScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&opts.PackageName, "pkg", "", "target Android package name")
	cmd.Flags().BoolVar(&opts.ObserveKeyStore, "keystore", true, "observe KeyStore types and alias names")
	cmd.Flags().BoolVar(&opts.ObserveKeyManager, "keymanager", true, "observe KeyManagerFactory algorithms")
	cmd.Flags().BoolVar(&opts.ObserveSSLContext, "sslcontext", true, "observe SSLContext protocols")
	cmd.Flags().BoolVar(&opts.ObserveCertificates, "certs", true, "observe peer/client X.509 certificate metadata")
	cmd.Flags().IntVar(&opts.MaxAliasesPerStore, "max-aliases", 32, "maximum aliases logged per KeyStore")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write Frida JS script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedCompatScript JSON")
	return cmd
}

func newTLSCurlImpersonateCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "curl-impersonate",
		Short: "Detect optional curl-impersonate binaries installed on PATH",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			info := tlskit.DetectCurlImpersonate()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			fmt.Fprintf(out, "Available: %v\n", info.Available)
			if info.PrimaryBinary != "" {
				fmt.Fprintf(out, "Primary:   %s\n", info.PrimaryBinary)
			}
			for _, b := range info.Binaries {
				fmt.Fprintf(out, "  - %-26s [%s] %s\n", b.Name, b.Family, b.Path)
			}
			if !info.Available && info.InstallHint != "" {
				fmt.Fprintf(out, "Hint:      %s\n", info.InstallHint)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output CurlImpersonateInfo JSON")
	return cmd
}
