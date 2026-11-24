package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/gateway"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/tui"
)

func openGatewayManager() (*gateway.Manager, error) {
	return gateway.NewManager(config.DefaultDir())
}

func newGatewayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Serviceization & Open API Gateway (routes, proxy pool, device pool, signers)",
		Long: `Turn reverse-engineered mobile APIs into callable Open API endpoints backed by
Proxy IP Pools, Virtual/ADB Device Pools, and Pluggable Signer Providers:

  start    — Run the embedded Open API Gateway HTTP server
  status   — Show gateway configuration and resource pool counts
  routes   — List, test, or delete published service routes
  publish  — Publish a captured flow from SQLite as a gateway ServiceRoute
  proxies  — List, add, import, fetch, or health-check Proxy IP Pool nodes
  devices  — List, create from presets, or sync ADB devices in the Device Pool
  signers  — List, test, or delete configured Signer Providers
  openapi  — Export the OpenAPI 3.0.3 JSON specification for enabled routes

Examples:
  cap gateway start -a 127.0.0.1:9090
  cap gateway publish --flow f1 --slug user-profile
  cap gateway routes --json
  cap gateway proxies --add socks5://user:pass@1.2.3.4:1080 --region US
  cap gateway devices --presets
  cap gateway openapi -o openapi.json`,
	}

	cmd.AddCommand(
		newGatewayStartCmd(),
		newGatewayStatusCmd(),
		newGatewayRoutesCmd(),
		newGatewayPublishCmd(),
		newGatewayProxiesCmd(),
		newGatewayDevicesCmd(),
		newGatewaySignersCmd(),
		newGatewayOpenAPICmd(),
	)
	return cmd
}

func newGatewayStartCmd() *cobra.Command {
	var (
		addr        string
		requireAuth bool
		apiKeys     []string
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the embedded Open API Gateway HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			defer func() { _ = mgr.Shutdown() }()

			cfg := mgr.GetConfig()
			changed := false
			if strings.TrimSpace(addr) != "" {
				cfg.ListenAddr = strings.TrimSpace(addr)
				changed = true
			}
			if cmd.Flags().Changed("require-auth") {
				cfg.RequireAuth = requireAuth
				changed = true
			}
			if len(apiKeys) > 0 {
				cfg.APIKeys = apiKeys
				cfg.RequireAuth = true
				changed = true
			}
			if changed {
				_ = mgr.UpdateConfig(cfg)
			}

			var outMu sync.Mutex
			mgr.SetCallbacks(
				func(rec gateway.InvocationRecord) {
					outMu.Lock()
					defer outMu.Unlock()
					fmt.Fprintf(out, "[%s] /gw/%s -> %d (%dms, proxy=%s, device=%s)\n",
						rec.Method, rec.RouteSlug, rec.StatusCode, rec.LatencyMs, rec.ProxyName, rec.DeviceName)
				},
				nil,
			)

			if err := mgr.Start(cfg.ListenAddr); err != nil {
				return err
			}
			st := mgr.Stats()

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			outMu.Lock()
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.title"), st.ListenAddr)
			}
			fmt.Fprintf(out, "Listening: http://%s\n", st.ListenAddr)
			fmt.Fprintf(out, "Endpoints: /health · /metrics · /openapi.json · /gw/{slug}\n")
			fmt.Fprintf(out, "Pools:     routes=%d/%d  proxies=%d/%d  devices=%d/%d  signers=%d\n",
				st.RouteEnabled, st.RouteTotal, st.ProxyHealthy, st.ProxyTotal,
				st.DeviceEnabled, st.DeviceTotal, st.SignerTotal)
			outMu.Unlock()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			defer signal.Stop(sigCh)
			<-sigCh
			outMu.Lock()
			fmt.Fprintln(out, "\nShutting down Open API Gateway...")
			outMu.Unlock()
			return mgr.Shutdown()
		},
	}

	cmd.Flags().StringVarP(&addr, "addr", "a", "", "listen address (default from gateway config or 127.0.0.1:9090)")
	cmd.Flags().BoolVar(&requireAuth, "require-auth", false, "require API key authentication")
	cmd.Flags().StringSliceVar(&apiKeys, "api-key", nil, "API key(s) accepted via X-API-Key / Bearer token")
	return cmd
}

func newGatewayStatusCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Inspect gateway configuration and pool counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			stats := mgr.Stats()
			cfg := mgr.GetConfig()

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"config": cfg,
					"stats":  stats,
					"dir":    mgr.Dir(),
				})
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.status.title"), cfg.ListenAddr)
			}
			fmt.Fprintf(out, "Listen Addr:  %s\n", cfg.ListenAddr)
			fmt.Fprintf(out, "Auth:         require_auth=%v (%d key(s))\n", cfg.RequireAuth, len(cfg.APIKeys))
			fmt.Fprintf(out, "Routes:       %d enabled / %d total\n", stats.RouteEnabled, stats.RouteTotal)
			fmt.Fprintf(out, "Proxies:      %d healthy / %d total\n", stats.ProxyHealthy, stats.ProxyTotal)
			fmt.Fprintf(out, "Devices:      %d enabled / %d total\n", stats.DeviceEnabled, stats.DeviceTotal)
			fmt.Fprintf(out, "Signers:      %d total\n", stats.SignerTotal)
			fmt.Fprintf(out, "Storage Dir:  %s\n", mgr.Dir())
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newGatewayRoutesCmd() *cobra.Command {
	var (
		testSlug string
		inputs   []string
		body     string
		rawMode  bool
		deleteID string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "routes",
		Short: "List, test, or delete published gateway service routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			if deleteID != "" {
				if err := mgr.DeleteRoute(deleteID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Deleted route %s\n", deleteID)
				return nil
			}
			if testSlug != "" {
				inMap := make(map[string]string, len(inputs))
				for _, kv := range inputs {
					k, v, ok := strings.Cut(kv, "=")
					if ok && strings.TrimSpace(k) != "" {
						inMap[strings.TrimSpace(k)] = v
					}
				}
				res, invokeErr := mgr.InvokeRoute(context.Background(), testSlug, gateway.TestInvokeRequest{
					RouteSlug: testSlug,
					Input:     inMap,
					Body:      body,
					Raw:       rawMode,
				})
				if res != nil && jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					_ = enc.Encode(res)
					return invokeErr
				}
				if invokeErr != nil {
					return invokeErr
				}
				if rawMode {
					fmt.Fprintln(out, res.Body)
					return nil
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			routes := mgr.ListRoutes()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(routes)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.routes.title"), fmt.Sprintf("%d", len(routes)))
			}
			if len(routes) == 0 {
				fmt.Fprintln(out, "No published service routes. Use 'cap gateway publish --flow <id>' to create one.")
				return nil
			}
			fmt.Fprintf(out, "%-24s %-8s %-7s %s\n", "SLUG", "METHOD", "ENABLED", "UPSTREAM URL")
			for _, r := range routes {
				fmt.Fprintf(out, "%-24s %-8s %-7v %s\n",
					tui.Truncate(r.Slug, 24), r.UpstreamMethod, r.Enabled, r.UpstreamURL)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&testSlug, "test", "", "invoke a route by slug directly")
	cmd.Flags().StringSliceVar(&inputs, "input", nil, "template inputs as key=value (repeatable, used with --test)")
	cmd.Flags().StringVar(&body, "body", "", "request body (used with --test)")
	cmd.Flags().BoolVar(&rawMode, "raw", false, "print raw upstream body (used with --test)")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete a route by ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newGatewayPublishCmd() *cobra.Command {
	var (
		flowID  string
		slug    string
		name    string
		dbPath  string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish a captured flow as an Open API Gateway ServiceRoute",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			st, err := openStore(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()

			f, err := st.GetFlow(flowID)
			if err != nil {
				return err
			}
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			route, err := mgr.PublishFlowAsRoute(f, slug, name)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(route)
			}
			fmt.Fprintf(out, "Published flow %s as /gw/%s (id=%s, %s %s)\n",
				f.ID, route.Slug, route.ID, route.UpstreamMethod, route.UpstreamURL)
			return nil
		},
	}

	cmd.Flags().StringVar(&flowID, "flow", "", "captured flow ID to publish")
	cmd.Flags().StringVar(&slug, "slug", "", "custom gateway route slug (auto-derived if empty)")
	cmd.Flags().StringVar(&name, "name", "", "display name for the route")
	cmd.Flags().StringVarP(&dbPath, "db", "d", "", "SQLite flow database path")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("flow")
	return cmd
}

func newGatewayProxiesCmd() *cobra.Command {
	var (
		addURL      string
		region      string
		tags        []string
		importFile  string
		checkAll    bool
		fetchURL    string
		fetchFormat string
		jsonPath    string
		deleteID    string
		jsonOut     bool
	)

	cmd := &cobra.Command{
		Use:   "proxies",
		Short: "Manage the gateway Proxy IP Pool",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			if deleteID != "" {
				if err := mgr.DeleteProxy(deleteID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Deleted proxy %s\n", deleteID)
				return nil
			}
			if addURL != "" {
				saved, err := mgr.SaveProxy(gateway.ProxyNode{
					URL:     addURL,
					Region:  region,
					Tags:    tags,
					Enabled: true,
				})
				if err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(saved)
				}
				fmt.Fprintf(out, "Added proxy %s (%s)\n", saved.ID, saved.URL)
				return nil
			}
			if importFile != "" {
				raw, err := os.ReadFile(importFile)
				if err != nil {
					return fmt.Errorf("read proxy list %s: %w", importFile, err)
				}
				parsed := gateway.ParseProxyLines(string(raw))
				added := 0
				for _, node := range parsed {
					if region != "" && node.Region == "" {
						node.Region = region
					}
					if len(tags) > 0 {
						node.Tags = append(node.Tags, tags...)
					}
					node.Enabled = true
					if _, saveErr := mgr.SaveProxy(node); saveErr != nil {
						return saveErr
					}
					added++
				}
				fmt.Fprintf(out, "Imported %d proxy node(s)\n", added)
				return nil
			}
			if fetchURL != "" {
				cfg := mgr.GetProxyConfig()
				cfg.ProviderURL = fetchURL
				cfg.ProviderFormat = fetchFormat
				cfg.ProviderJSONPath = jsonPath
				_ = mgr.UpdateProxyConfig(cfg)
				added, total, err := mgr.FetchProxiesFromProvider(context.Background())
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "Fetched %d new proxy node(s) (pool total: %d)\n", added, total)
				return nil
			}
			if checkAll {
				nodes := mgr.CheckAllProxies(context.Background(), "")
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(nodes)
				}
				for _, n := range nodes {
					fmt.Fprintf(out, "%-20s %-30s healthy=%-5v latency=%dms %s\n",
						tui.Truncate(n.ID, 20), n.URL, n.Healthy, n.LatencyMs, n.LastError)
				}
				return nil
			}

			nodes := mgr.ListProxies()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(nodes)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.proxies.title"), fmt.Sprintf("%d", len(nodes)))
			}
			if len(nodes) == 0 {
				fmt.Fprintln(out, "No proxy nodes configured. Use 'cap gateway proxies --add <url>' to add one.")
				return nil
			}
			fmt.Fprintf(out, "%-22s %-30s %-8s %-8s %s\n", "ID", "URL", "REGION", "HEALTHY", "LATENCY")
			for _, n := range nodes {
				fmt.Fprintf(out, "%-22s %-30s %-8s %-8v %dms\n",
					tui.Truncate(n.ID, 22), tui.Truncate(n.URL, 30), n.Region, n.Healthy, n.LatencyMs)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addURL, "add", "", "add a proxy URL (http://, https://, socks5://)")
	cmd.Flags().StringVar(&region, "region", "", "optional region label for added/imported proxies")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "optional tags for added/imported proxies")
	cmd.Flags().StringVar(&importFile, "import", "", "bulk-import proxies from a text file")
	cmd.Flags().BoolVar(&checkAll, "check", false, "run health checks across all enabled proxies")
	cmd.Flags().StringVar(&fetchURL, "fetch", "", "fetch dynamic proxies from provider URL")
	cmd.Flags().StringVar(&fetchFormat, "format", "", "provider format: lines or json")
	cmd.Flags().StringVar(&jsonPath, "json-path", "", "dot-separated JSON path for JSON proxy providers")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete a proxy node by ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newGatewayDevicesCmd() *cobra.Command {
	var (
		listPresets bool
		fromPreset  string
		customName  string
		syncADB     bool
		deleteID    string
		jsonOut     bool
	)

	cmd := &cobra.Command{
		Use:   "devices",
		Short: "Manage the gateway Device Pool and virtual fingerprint profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if listPresets {
				presets := gateway.BuiltinDevicePresets()
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(presets)
				}
				fmt.Fprintf(out, "%-24s %-24s %-10s %s\n", "PRESET ID", "NAME", "BRAND", "MODEL / OS")
				for _, p := range presets {
					fmt.Fprintf(out, "%-24s %-24s %-10s %s (Android %s / SDK %d)\n",
						p.ID, p.Name, p.Fingerprint.Brand, p.Fingerprint.Model, p.Fingerprint.OSVersion, p.Fingerprint.SDK)
				}
				return nil
			}

			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			if deleteID != "" {
				if err := mgr.DeleteDevice(deleteID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Deleted device %s\n", deleteID)
				return nil
			}
			if fromPreset != "" {
				dev, err := mgr.CreateDeviceFromPreset(fromPreset, customName, nil)
				if err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(dev)
				}
				fmt.Fprintf(out, "Created virtual device %s (%s · %s)\n", dev.ID, dev.Name, dev.Fingerprint.Model)
				return nil
			}
			if syncADB {
				devs, err := mgr.SyncADBDevices(context.Background())
				if err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(devs)
				}
				fmt.Fprintf(out, "Synced %d physical ADB device(s)\n", len(devs))
				return nil
			}

			devs := mgr.ListDevices()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(devs)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.devices.title"), fmt.Sprintf("%d", len(devs)))
			}
			if len(devs) == 0 {
				fmt.Fprintln(out, "No devices in pool. Use 'cap gateway devices --presets' or '--from-preset <id>'.")
				return nil
			}
			fmt.Fprintf(out, "%-24s %-10s %-18s %-8s %s\n", "ID", "KIND", "MODEL", "ENABLED", "NAME")
			for _, d := range devs {
				fmt.Fprintf(out, "%-24s %-10s %-18s %-8v %s\n",
					tui.Truncate(d.ID, 24), d.Kind, tui.Truncate(d.Fingerprint.Model, 18), d.Enabled, d.Name)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&listPresets, "presets", false, "list built-in virtual Android device presets")
	cmd.Flags().StringVar(&fromPreset, "from-preset", "", "create a virtual device profile from a preset ID")
	cmd.Flags().StringVar(&customName, "name", "", "custom name when creating from preset")
	cmd.Flags().BoolVar(&syncADB, "sync-adb", false, "sync connected physical ADB devices into the pool")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete a device profile by ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newGatewaySignersCmd() *cobra.Command {
	var (
		testID   string
		testURL  string
		method   string
		body     string
		deleteID string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "signers",
		Short: "List, test, or delete configured gateway Signer Providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			if deleteID != "" {
				if err := mgr.DeleteSigner(deleteID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Deleted signer %s\n", deleteID)
				return nil
			}
			if testID != "" {
				parsedURL, err := url.Parse(strings.TrimSpace(testURL))
				if err != nil {
					return fmt.Errorf("invalid --url %q: %w", testURL, err)
				}
				flatQuery := make(map[string]string)
				for k, vals := range parsedURL.Query() {
					if len(vals) > 0 {
						flatQuery[k] = vals[0]
					}
				}
				res, err := mgr.TestSigner(context.Background(), testID, gateway.SignerInput{
					Method: method,
					URL:    parsedURL.String(),
					Path:   parsedURL.Path,
					Query:  flatQuery,
					Body:   body,
				})
				if err != nil {
					return err
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			signers := mgr.ListSigners()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(signers)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.signers.title"), fmt.Sprintf("%d", len(signers)))
			}
			if len(signers) == 0 {
				fmt.Fprintln(out, "No signer providers configured.")
				return nil
			}
			fmt.Fprintf(out, "%-24s %-14s %-8s %s\n", "ID", "KIND", "ENABLED", "NAME")
			for _, s := range signers {
				fmt.Fprintf(out, "%-24s %-14s %-8v %s\n",
					tui.Truncate(s.ID, 24), s.Kind, s.Enabled, s.Name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&testID, "test", "", "execute a saved signer by ID against sample input")
	cmd.Flags().StringVar(&testURL, "url", "https://api.example.com/v1/test", "sample URL for --test")
	cmd.Flags().StringVar(&method, "method", "GET", "sample HTTP method for --test")
	cmd.Flags().StringVar(&body, "body", "", "sample request body for --test")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete a signer provider by ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newGatewayOpenAPICmd() *cobra.Command {
	var outFile string

	cmd := &cobra.Command{
		Use:   "openapi",
		Short: "Export the OpenAPI 3.0.3 JSON specification for enabled gateway routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			spec, err := mgr.OpenAPISpecJSON()
			if err != nil {
				return err
			}
			if outFile != "" {
				if err := os.WriteFile(outFile, spec, 0o644); err != nil {
					return fmt.Errorf("write OpenAPI spec %s: %w", outFile, err)
				}
				fmt.Fprintf(out, "Wrote OpenAPI 3.0.3 spec to %s\n", outFile)
				return nil
			}
			fmt.Fprintln(out, string(spec))
			return nil
		},
	}

	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write OpenAPI JSON to file")
	return cmd
}
