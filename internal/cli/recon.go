package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/recon"
	"github.com/overkazaf/cap/internal/tui"
)

func loadSavedReconToolchainConfig() recon.ToolchainConfig {
	settingsPath := filepath.Join(config.DefaultDir(), "settings.json")
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		return recon.ToolchainConfig{}
	}
	var settings map[string]string
	if err := json.Unmarshal(raw, &settings); err != nil {
		return recon.ToolchainConfig{}
	}
	return recon.ToolchainConfig{
		NmapPath:      strings.TrimSpace(settings["recon_nmap_path"]),
		SubfinderPath: strings.TrimSpace(settings["recon_subfinder_path"]),
		WhoisPath:     strings.TrimSpace(settings["recon_whois_path"]),
		DigPath:       strings.TrimSpace(settings["recon_dig_path"]),
	}
}

func mergeReconToolchainConfig(base, override recon.ToolchainConfig) recon.ToolchainConfig {
	pick := func(o, b string) string {
		if s := strings.TrimSpace(o); s != "" {
			return s
		}
		return strings.TrimSpace(b)
	}
	return recon.ToolchainConfig{
		NmapPath:      pick(override.NmapPath, base.NmapPath),
		SubfinderPath: pick(override.SubfinderPath, base.SubfinderPath),
		WhoisPath:     pick(override.WhoisPath, base.WhoisPath),
		DigPath:       pick(override.DigPath, base.DigPath),
	}
}

func openReconManager() (*recon.Manager, error) {
	mgr, err := recon.NewManager(config.DefaultDir())
	if err != nil {
		return nil, err
	}
	mgr.SetToolchainConfig(loadSavedReconToolchainConfig())
	return mgr, nil
}

func cmdBaseContext(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

func newReconCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Site reconnaissance, domain intelligence, TLS audit, subdomains & port scanning",
		Long: `Authorized site reconnaissance, asset inventory, security header auditing,
live TLS certificate inspection, subdomain discovery, and TCP/Nmap port scanning:

  status      — Inspect host recon toolchain readiness (nmap, subfinder, whois, dig)
  domain      — Resolve DNS records, CDN/WAF hints, WHOIS metadata, and TLS for a domain
  site        — Fingerprint HTTP stack, audit security headers, and probe standard discovery paths
  tls         — Inspect live TLS handshake, cipher suite, and X.509 certificate chain
  subdomains  — Discover subdomains via CT logs, subfinder, and wildcard-guarded common DNS
  ports       — Run authorized TCP/Nmap port and service scan (quick, top100, web, service, custom)
  history     — List, inspect, or clear persisted recon scan history

Examples:
  cap recon status --json
  cap recon domain example.com
  cap recon site https://example.com --no-discovery --json
  cap recon tls example.com --port 443
  cap recon subdomains example.com --no-subfinder
  cap recon ports 127.0.0.1 --engine native --preset web
  cap recon ports 127.0.0.1 --engine native --ports 80,443,8080 --service-version
  cap recon history --json`,
	}

	cmd.AddCommand(
		newReconStatusCmd(),
		newReconDomainCmd(),
		newReconSiteCmd(),
		newReconTLSCmd(),
		newReconSubdomainsCmd(),
		newReconPortsCmd(),
		newReconHistoryCmd(),
	)
	return cmd
}

func newReconStatusCmd() *cobra.Command {
	var (
		cfg     recon.ToolchainConfig
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Inspect host recon toolchain readiness (nmap, subfinder, whois, dig)",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			effective := mergeReconToolchainConfig(loadSavedReconToolchainConfig(), cfg)
			info := recon.DetectToolchain(effective)

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.recon.status.title"), "")
			}

			tools := []recon.ToolStatus{info.Nmap, info.Subfinder, info.Whois, info.Dig}
			for _, ts := range tools {
				state := "missing"
				if ts.Ready {
					state = "ready"
				}
				detail := ts.Path
				if ts.Version != "" {
					if detail != "" {
						detail += " (" + ts.Version + ")"
					} else {
						detail = ts.Version
					}
				}
				if !ts.Ready && ts.Issue != "" {
					detail = ts.Issue
				}
				fmt.Fprintf(out, "  %-11s %-8s %s\n", ts.Name, state, detail)
			}
			fmt.Fprintln(out, "\n  Pure-Go engines (DNS, HTTP fingerprint, TLS inspect, CT logs, native TCP scan) are always available.")
			return nil
		},
	}

	cmd.Flags().StringVar(&cfg.NmapPath, "nmap", "", "custom nmap binary path")
	cmd.Flags().StringVar(&cfg.SubfinderPath, "subfinder", "", "custom subfinder binary path")
	cmd.Flags().StringVar(&cfg.WhoisPath, "whois", "", "custom whois binary path")
	cmd.Flags().StringVar(&cfg.DigPath, "dig", "", "custom dig binary path")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newReconDomainCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "domain <target>",
		Short: "Analyze DNS records, CDN/WAF hints, WHOIS, and TLS for a domain or IP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openReconManager()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmdBaseContext(cmd), 60*time.Second)
			defer cancel()

			report, err := mgr.AnalyzeDomain(ctx, args[0])
			if err != nil {
				return err
			}
			_, _ = mgr.SaveHistory(recon.ReconHistoryEntry{
				Kind:         recon.JobKindDomain,
				Target:       report.Target,
				Summary:      fmt.Sprintf("IPv4:%d IPv6:%d CDN:%d", len(report.IPv4), len(report.IPv6), len(report.CDNProviders)),
				Status:       recon.StatusDone,
				ElapsedMs:    report.ElapsedMs,
				DomainReport: report,
			})

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.recon.domain.title"), report.Target)
			}
			fmt.Fprintf(out, "Target:      %s (root: %s · %dms)\n", report.Target, report.RootDomain, report.ElapsedMs)
			if len(report.IPv4) > 0 {
				fmt.Fprintf(out, "IPv4:        %s\n", strings.Join(report.IPv4, ", "))
			}
			if len(report.IPv6) > 0 {
				fmt.Fprintf(out, "IPv6:        %s\n", strings.Join(report.IPv6, ", "))
			}
			if report.DNSRecords.CNAME != "" {
				fmt.Fprintf(out, "CNAME:       %s\n", report.DNSRecords.CNAME)
			}
			if len(report.DNSRecords.NS) > 0 {
				fmt.Fprintf(out, "NS:          %s\n", strings.Join(report.DNSRecords.NS, ", "))
			}
			if len(report.DNSRecords.MX) > 0 {
				mxs := make([]string, 0, len(report.DNSRecords.MX))
				for _, mx := range report.DNSRecords.MX {
					mxs = append(mxs, fmt.Sprintf("%s(%d)", mx.Host, mx.Pref))
				}
				fmt.Fprintf(out, "MX:          %s\n", strings.Join(mxs, ", "))
			}
			if len(report.CDNProviders) > 0 {
				fmt.Fprintf(out, "CDN:         %s\n", strings.Join(report.CDNProviders, ", "))
			}
			if len(report.WAFHints) > 0 {
				fmt.Fprintf(out, "WAF Hints:   %s\n", strings.Join(report.WAFHints, ", "))
			}
			if report.Whois != nil && (report.Whois.Registrar != "" || report.Whois.ExpiryDate != "") {
				fmt.Fprintf(out, "WHOIS:       registrar=%s created=%s expires=%s\n",
					report.Whois.Registrar, report.Whois.CreationDate, report.Whois.ExpiryDate)
			}
			if report.TLS != nil {
				fmt.Fprintf(out, "TLS:         %s · %s · verified=%v\n",
					report.TLS.TLSVersion, report.TLS.CipherSuite, report.TLS.Verified)
			}
			for _, w := range report.Warnings {
				fmt.Fprintf(out, "Warning:     %s\n", w)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newReconSiteCmd() *cobra.Command {
	var (
		noDiscovery bool
		insecure    bool
		jsonOut     bool
	)

	cmd := &cobra.Command{
		Use:   "site <url>",
		Short: "Fingerprint HTTP technologies, audit security headers, and probe discovery paths",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openReconManager()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmdBaseContext(cmd), 45*time.Second)
			defer cancel()

			opts := recon.SiteProbeOptions{
				SkipDiscovery:      noDiscovery,
				InsecureSkipVerify: insecure,
			}
			profile, err := mgr.ProbeSite(ctx, args[0], opts)
			if err != nil {
				return err
			}
			_, _ = mgr.SaveHistory(recon.ReconHistoryEntry{
				Kind:        recon.JobKindSite,
				Target:      profile.TargetURL,
				Summary:     fmt.Sprintf("HTTP %d · %d tech · score %d/100", profile.StatusCode, len(profile.Technologies), profile.SecurityScore),
				Status:      recon.StatusDone,
				ElapsedMs:   profile.ElapsedMs,
				SiteProfile: profile,
			})

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(profile)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.recon.site.title"), profile.TargetURL)
			}
			fmt.Fprintf(out, "URL:            %s -> %s\n", profile.TargetURL, profile.FinalURL)
			fmt.Fprintf(out, "Status:         %d (%s · %dms)\n", profile.StatusCode, profile.Protocol, profile.ElapsedMs)
			if profile.Title != "" {
				fmt.Fprintf(out, "Title:          %s\n", profile.Title)
			}
			if profile.Server != "" {
				fmt.Fprintf(out, "Server:         %s\n", profile.Server)
			}
			fmt.Fprintf(out, "Security Score: %d/100\n", profile.SecurityScore)

			if len(profile.Technologies) > 0 {
				fmt.Fprintf(out, "\nTechnologies (%d):\n", len(profile.Technologies))
				for _, t := range profile.Technologies {
					ver := ""
					if t.Version != "" {
						ver = " " + t.Version
					}
					fmt.Fprintf(out, "  %-22s %-12s %-8s %s\n", t.Name+ver, t.Category, t.Confidence, t.Evidence)
				}
			}
			if len(profile.SecurityHeaders) > 0 {
				fmt.Fprintf(out, "\nSecurity Headers (%d):\n", len(profile.SecurityHeaders))
				for _, h := range profile.SecurityHeaders {
					fmt.Fprintf(out, "  %-30s %-6s (%d/%d)\n", h.Header, strings.ToUpper(h.Status), h.Score, h.Weight)
				}
			}
			if profile.RobotsRules != nil && profile.RobotsRules.Found {
				fmt.Fprintf(out, "\nrobots.txt:     found (allow=%d disallow=%d sitemaps=%d)\n",
					len(profile.RobotsRules.Allow), len(profile.RobotsRules.Disallow), len(profile.RobotsRules.Sitemaps))
			}
			for _, wk := range profile.WellKnownPaths {
				if wk.Found {
					fmt.Fprintf(out, "well-known:     %s (%d %s)\n", wk.Path, wk.StatusCode, wk.ContentType)
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&noDiscovery, "no-discovery", false, "skip robots.txt, sitemap, favicon, and .well-known probes")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification during HTTP probe")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newReconTLSCmd() *cobra.Command {
	var (
		port    int
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "tls <host>",
		Short: "Inspect live TLS handshake, cipher suite, and certificate chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openReconManager()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmdBaseContext(cmd), 20*time.Second)
			defer cancel()

			report, err := mgr.InspectTLS(ctx, args[0], port)
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
				printSectionHeader(out, th, i18n.T("cli.recon.tls.title"), fmt.Sprintf("%s:%d", report.Host, report.Port))
			}
			fmt.Fprintf(out, "Endpoint:    %s:%d (%dms)\n", report.Host, report.Port, report.ElapsedMs)
			fmt.Fprintf(out, "Protocol:    %s · %s\n", report.TLSVersion, report.CipherSuite)
			if report.ALPN != "" {
				fmt.Fprintf(out, "ALPN:        %s\n", report.ALPN)
			}
			fmt.Fprintf(out, "Verified:    %v", report.Verified)
			if report.VerifyError != "" {
				fmt.Fprintf(out, " (%s)", report.VerifyError)
			}
			fmt.Fprintln(out)
			if report.Leaf != nil {
				fmt.Fprintf(out, "Subject:     %s\n", report.Leaf.Subject)
				fmt.Fprintf(out, "Issuer:      %s\n", report.Leaf.Issuer)
				fmt.Fprintf(out, "Validity:    %s -> %s (%d days remaining, expired=%v)\n",
					report.Leaf.NotBefore, report.Leaf.NotAfter, report.Leaf.DaysUntilExpiry, report.Leaf.Expired)
				fmt.Fprintf(out, "Key:         %s %d-bit (self-signed=%v)\n",
					report.Leaf.PubKeyAlgo, report.Leaf.PubKeyBits, report.Leaf.SelfSigned)
				if len(report.Leaf.SANs) > 0 {
					fmt.Fprintf(out, "SANs:        %s\n", strings.Join(report.Leaf.SANs, ", "))
				}
				fmt.Fprintf(out, "SHA256:      %s\n", report.Leaf.SHA256Fingerprint)
			}
			fmt.Fprintf(out, "Chain Len:   %d\n", len(report.Chain))
			return nil
		},
	}

	cmd.Flags().IntVar(&port, "port", 443, "TCP port for TLS inspection")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newReconSubdomainsCmd() *cobra.Command {
	var (
		noCT        bool
		noSubfinder bool
		noDNS       bool
		resolveDNS  bool
		ctEndpoint  string
		jsonOut     bool
	)

	cmd := &cobra.Command{
		Use:   "subdomains <domain>",
		Short: "Discover subdomains via passive CT logs, subfinder, and wildcard-guarded DNS",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if noCT && noSubfinder && noDNS {
				return fmt.Errorf("at least one subdomain discovery source must remain enabled")
			}

			mgr, err := openReconManager()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmdBaseContext(cmd), 90*time.Second)
			defer cancel()

			req := recon.SubdomainRequest{
				Domain:       args[0],
				UseCTLog:     !noCT,
				UseSubfinder: !noSubfinder,
				UseCommonDNS: !noDNS,
				ResolveDNS:   resolveDNS,
				CTEndpoint:   strings.TrimSpace(ctEndpoint),
			}
			report, err := mgr.EnumerateSubdomains(ctx, req)
			if err != nil {
				return err
			}
			_, _ = mgr.SaveHistory(recon.ReconHistoryEntry{
				Kind:            recon.JobKindSubdomain,
				Target:          report.Domain,
				Summary:         fmt.Sprintf("%d subdomain(s) via %s", report.TotalCount, strings.Join(report.SourcesUsed, ",")),
				Status:          recon.StatusDone,
				ElapsedMs:       report.ElapsedMs,
				SubdomainReport: report,
			})

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.recon.subdomains.title"), report.Domain)
			}
			fmt.Fprintf(out, "Domain:    %s (%d found in %dms)\n", report.Domain, report.TotalCount, report.ElapsedMs)
			fmt.Fprintf(out, "Sources:   %s\n", strings.Join(report.SourcesUsed, ", "))
			if report.WildcardDetected {
				fmt.Fprintf(out, "Wildcard:  detected (%s)\n", strings.Join(report.WildcardIPs, ", "))
			}
			if len(report.Subdomains) == 0 {
				fmt.Fprintln(out, "No subdomains discovered.")
			} else {
				fmt.Fprintf(out, "\n%-38s %-20s %s\n", "HOSTNAME", "SOURCES", "IPS / CNAME")
				for _, s := range report.Subdomains {
					extra := strings.Join(s.IPs, ",")
					if s.CNAME != "" {
						if extra != "" {
							extra += " -> " + s.CNAME
						} else {
							extra = s.CNAME
						}
					}
					fmt.Fprintf(out, "%-38s %-20s %s\n",
						tui.Truncate(s.Hostname, 38),
						tui.Truncate(strings.Join(s.Sources, ","), 20),
						extra)
				}
			}
			for _, w := range report.Warnings {
				fmt.Fprintf(out, "Warning:   %s\n", w)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&noCT, "no-ct", false, "disable passive Certificate Transparency (crt.sh) lookup")
	cmd.Flags().BoolVar(&noSubfinder, "no-subfinder", false, "disable external subfinder binary")
	cmd.Flags().BoolVar(&noDNS, "no-dns", false, "disable wildcard-guarded common DNS subdomain probing")
	cmd.Flags().BoolVar(&resolveDNS, "resolve", false, "resolve discovered hostnames to IP/CNAME records")
	cmd.Flags().StringVar(&ctEndpoint, "ct-endpoint", "", "custom CT log query URL template")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newReconPortsCmd() *cobra.Command {
	var (
		engine         string
		preset         string
		portsSpec      string
		serviceVersion bool
		timeoutMs      int
		jsonOut        bool
	)

	cmd := &cobra.Command{
		Use:   "ports <target>",
		Short: "Run an authorized Nmap or pure-Go TCP port & service scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openReconManager()
			if err != nil {
				return err
			}

			effectivePreset := strings.TrimSpace(preset)
			if strings.TrimSpace(portsSpec) != "" && !cmd.Flags().Changed("preset") {
				effectivePreset = recon.PresetCustom
			}

			req := recon.PortScanRequest{
				Target:         args[0],
				Engine:         strings.TrimSpace(engine),
				Preset:         effectivePreset,
				PortsSpec:      strings.TrimSpace(portsSpec),
				ServiceVersion: serviceVersion,
				TimeoutMs:      timeoutMs,
			}

			ctx, cancel := context.WithTimeout(cmdBaseContext(cmd), 180*time.Second)
			defer cancel()

			res, err := mgr.RunPortScan(ctx, req, nil)
			if err != nil {
				return err
			}
			_, _ = mgr.SaveHistory(recon.ReconHistoryEntry{
				Kind:           recon.JobKindPortScan,
				Target:         res.Target,
				Summary:        fmt.Sprintf("%s · %d open / %d scanned", res.Engine, res.OpenCount, res.TotalScanned),
				Status:         recon.StatusDone,
				ElapsedMs:      res.ElapsedMs,
				PortScanResult: res,
			})

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.recon.ports.title"), res.Target)
			}
			fmt.Fprintf(out, "Target:   %s (engine=%s preset=%s · %d open / %d scanned in %dms)\n",
				res.Target, res.Engine, res.Preset, res.OpenCount, res.TotalScanned, res.ElapsedMs)
			if res.Command != "" {
				fmt.Fprintf(out, "Command:  %s\n", res.Command)
			}
			for _, host := range res.Hosts {
				fmt.Fprintf(out, "\nHost %s (%s):\n", host.Address, host.State)
				if len(host.Ports) == 0 {
					fmt.Fprintln(out, "  (no open ports)")
					continue
				}
				fmt.Fprintf(out, "  %-8s %-6s %-10s %-14s %s\n", "PORT", "PROTO", "STATE", "SERVICE", "DETAIL")
				for _, p := range host.Ports {
					detail := strings.TrimSpace(strings.Join([]string{p.Product, p.Version, p.ExtraInfo, p.Banner}, " "))
					fmt.Fprintf(out, "  %-8d %-6s %-10s %-14s %s\n",
						p.Port, p.Protocol, p.State, p.Service, tui.Truncate(detail, 60))
				}
			}
			for _, w := range res.Warnings {
				fmt.Fprintf(out, "Warning:  %s\n", w)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&engine, "engine", recon.PortScanEngineAuto, "scan engine: auto, nmap, native")
	cmd.Flags().StringVar(&preset, "preset", recon.PresetQuick, "port preset: quick, top100, web, service, custom")
	cmd.Flags().StringVar(&portsSpec, "ports", "", "custom port list/ranges (e.g. 80,443,8000-8080)")
	cmd.Flags().BoolVar(&serviceVersion, "service-version", false, "enable service/version detection (-sV / banner probe)")
	cmd.Flags().IntVar(&timeoutMs, "timeout-ms", recon.DefaultPortTimeout, "per-port connect timeout in milliseconds (native engine)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newReconHistoryCmd() *cobra.Command {
	var (
		showID   string
		clearAll bool
		deleteID string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "history",
		Short: "List, inspect, or clear persisted recon scan history",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openReconManager()
			if err != nil {
				return err
			}

			if clearAll {
				if err := mgr.ClearHistory(); err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]any{"cleared": true})
				}
				fmt.Fprintln(out, "Cleared all recon history entries.")
				return nil
			}

			if strings.TrimSpace(deleteID) != "" {
				if err := mgr.DeleteHistory(deleteID); err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]any{"deleted": deleteID})
				}
				fmt.Fprintf(out, "Deleted recon history entry %s.\n", deleteID)
				return nil
			}

			if strings.TrimSpace(showID) != "" {
				entry, ok := mgr.GetHistory(showID)
				if !ok {
					return fmt.Errorf("recon history entry %q not found", showID)
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(entry)
				}
				styled := isStyledWriter(out)
				th := cliTheme(styled)
				if styled {
					printSectionHeader(out, th, i18n.T("cli.recon.history.title"), entry.ID)
				}
				fmt.Fprintf(out, "ID:       %s\n", entry.ID)
				fmt.Fprintf(out, "Kind:     %s\n", entry.Kind)
				fmt.Fprintf(out, "Target:   %s\n", entry.Target)
				fmt.Fprintf(out, "Status:   %s (%dms)\n", entry.Status, entry.ElapsedMs)
				fmt.Fprintf(out, "Summary:  %s\n", entry.Summary)
				fmt.Fprintf(out, "Created:  %s\n", entry.CreatedAt)
				return nil
			}

			entries := mgr.ListHistory()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(entries)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.recon.history.title"), fmt.Sprintf("%d", len(entries)))
			}
			if len(entries) == 0 {
				fmt.Fprintln(out, "No recon history entries.")
				return nil
			}
			fmt.Fprintf(out, "%-28s %-10s %-24s %-8s %s\n", "ID", "KIND", "TARGET", "STATUS", "SUMMARY")
			for _, e := range entries {
				fmt.Fprintf(out, "%-28s %-10s %-24s %-8s %s\n",
					tui.Truncate(e.ID, 28),
					e.Kind,
					tui.Truncate(e.Target, 24),
					e.Status,
					tui.Truncate(e.Summary, 40))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&showID, "show", "", "show details for a single recon history entry ID")
	cmd.Flags().BoolVar(&clearAll, "clear", false, "delete all persisted recon history entries")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete a single recon history entry by ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}
