package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
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
		Short: "Serviceization & Open API Gateway (routes, pools, accounts, workers, circuits)",
		Long: `Turn reverse-engineered mobile APIs into callable Open API endpoints backed by
Proxy IP Pools, Virtual/ADB Device Pools, Account Pools, Managed Signer Workers,
and Pluggable Signer Providers:

  start          — Run the embedded Open API Gateway HTTP server
  serve          — Headless production gateway server (default 0.0.0.0:9090 + Managed Workers)
  status         — Show gateway configuration and resource pool counts
  routes         — List, test, or delete published service routes
  publish        — Publish a captured flow from SQLite as a gateway ServiceRoute
  proxies        — List, add, import, fetch, or health-check Proxy IP Pool nodes
  devices        — List, create from presets, or sync ADB devices in the Device Pool
  signers        — List, test, or delete configured Signer Providers
  accounts       — Manage the gateway Account / Session Pool
  workers        — Manage local supervised Signer Worker Process Pools
  circuits       — Inspect/reset per-route circuit breakers or clear route caches
  prometheus     — Export live gateway telemetry in Prometheus exposition format
  export-docker  — Generate production Dockerfile and docker-compose.yml for headless serve
  openapi        — Export the OpenAPI 3.0.3 JSON specification for enabled routes

Examples:
  cap gateway start -a 127.0.0.1:9090
  cap gateway serve --addr 0.0.0.0:9090
  cap gateway publish --flow f1 --slug user-profile
  cap gateway routes --json
  cap gateway proxies --add socks5://user:pass@1.2.3.4:1080 --region US
  cap gateway accounts --add "VIP-1" --token "tok_abc" --tags vip
  cap gateway workers --status --json
  cap gateway circuits --reset user-profile
  cap gateway prometheus
  cap gateway export-docker --addr 0.0.0.0:9090 --out-dir ./deploy`,
	}

	cmd.AddCommand(
		newGatewayStartCmd(),
		newGatewayServeCmd(),
		newGatewayStatusCmd(),
		newGatewayRoutesCmd(),
		newGatewayPublishCmd(),
		newGatewayProxiesCmd(),
		newGatewayDevicesCmd(),
		newGatewaySignersCmd(),
		newGatewayAccountsCmd(),
		newGatewayWorkersCmd(),
		newGatewayCircuitsCmd(),
		newGatewayPrometheusCmd(),
		newGatewayExportDockerCmd(),
		newGatewayOpenAPICmd(),
	)
	return cmd
}

func runGatewayServer(cmd *cobra.Command, addr string, requireAuth bool, apiKeys []string, startWorkers bool) error {
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

	if startWorkers {
		for _, w := range mgr.ListWorkers() {
			if !w.Enabled {
				continue
			}
			if startErr := mgr.StartWorker(w.ID); startErr != nil {
				outMu.Lock()
				fmt.Fprintf(out, "Warning: failed to start managed worker %s (%s): %v\n", w.Name, w.ID, startErr)
				outMu.Unlock()
			}
		}
	}

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
	fmt.Fprintf(out, "Endpoints: /health · /metrics · /metrics/prometheus · /openapi.json · /gw/{slug}\n")
	fmt.Fprintf(out, "Pools:     routes=%d/%d  proxies=%d/%d  devices=%d/%d  accounts=%d/%d  workers=%d/%d  signers=%d\n",
		st.RouteEnabled, st.RouteTotal, st.ProxyHealthy, st.ProxyTotal,
		st.DeviceEnabled, st.DeviceTotal, st.ActiveAccounts, st.TotalAccounts,
		st.HealthyWorkers, st.TotalWorkers, st.SignerTotal)
	outMu.Unlock()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ctx := cmd.Context()
	if ctx != nil {
		select {
		case <-sigCh:
		case <-ctx.Done():
		}
	} else {
		<-sigCh
	}

	outMu.Lock()
	fmt.Fprintln(out, "\nShutting down Open API Gateway...")
	outMu.Unlock()
	return mgr.Shutdown()
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
			return runGatewayServer(cmd, addr, requireAuth, apiKeys, false)
		},
	}

	cmd.Flags().StringVarP(&addr, "addr", "a", "", "listen address (default from gateway config or 127.0.0.1:9090)")
	cmd.Flags().BoolVar(&requireAuth, "require-auth", false, "require API key authentication")
	cmd.Flags().StringSliceVar(&apiKeys, "api-key", nil, "API key(s) accepted via X-API-Key / Bearer token")
	return cmd
}

func newGatewayServeCmd() *cobra.Command {
	var (
		addr         string
		requireAuth  bool
		apiKeys      []string
		startWorkers bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the Open API Gateway headlessly in production mode (HTTP server + Managed Workers)",
		RunE: func(cmd *cobra.Command, args []string) error {
			listenAddr := strings.TrimSpace(addr)
			if !cmd.Flags().Changed("addr") {
				if envAddr := strings.TrimSpace(os.Getenv("CAP_GW_LISTEN_ADDR")); envAddr != "" {
					listenAddr = envAddr
				}
			}
			if listenAddr == "" {
				listenAddr = "0.0.0.0:9090"
			}
			return runGatewayServer(cmd, listenAddr, requireAuth, apiKeys, startWorkers)
		},
	}

	cmd.Flags().StringVarP(&addr, "addr", "a", "0.0.0.0:9090", "listen address (defaults to CAP_GW_LISTEN_ADDR or 0.0.0.0:9090)")
	cmd.Flags().BoolVar(&requireAuth, "require-auth", false, "require API key authentication")
	cmd.Flags().StringSliceVar(&apiKeys, "api-key", nil, "API key(s) accepted via X-API-Key / Bearer token")
	cmd.Flags().BoolVar(&startWorkers, "start-workers", true, "auto-start enabled Managed Signer Workers on startup")
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
			fmt.Fprintf(out, "Accounts:     %d active / %d total\n", stats.ActiveAccounts, stats.TotalAccounts)
			fmt.Fprintf(out, "Workers:      %d healthy / %d total\n", stats.HealthyWorkers, stats.TotalWorkers)
			fmt.Fprintf(out, "Signers:      %d total\n", stats.SignerTotal)
			fmt.Fprintf(out, "Cache/Circ:   hits=%d  misses=%d  open_circuits=%d\n", stats.CacheHits, stats.CacheMisses, stats.OpenCircuits)
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

func newGatewayAccountsCmd() *cobra.Command {
	var (
		addName       string
		username      string
		token         string
		refreshToken  string
		cookie        string
		tags          []string
		stickyDevice  string
		expiresAt     string
		strategy      string
		deleteID      string
		markHealthyID string
		jsonOut       bool
	)

	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "Manage the gateway Account / Session Pool",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			if deleteID != "" {
				if err := mgr.DeleteAccount(deleteID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Deleted account %s\n", deleteID)
				return nil
			}
			if markHealthyID != "" {
				if err := mgr.AccountPool().MarkHealthy(markHealthyID); err != nil {
					return err
				}
				if jsonOut {
					acc, _ := mgr.GetAccount(markHealthyID)
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(acc)
				}
				fmt.Fprintf(out, "Marked account %s healthy\n", markHealthyID)
				return nil
			}
			if strings.TrimSpace(strategy) != "" {
				cfg := mgr.GetAccountConfig()
				cfg.Strategy = strings.TrimSpace(strategy)
				if err := mgr.UpdateAccountConfig(cfg); err != nil {
					return err
				}
				if addName == "" {
					if jsonOut {
						enc := json.NewEncoder(out)
						enc.SetIndent("", "  ")
						return enc.Encode(mgr.GetAccountConfig())
					}
					fmt.Fprintf(out, "Updated account pool strategy to %s\n", mgr.GetAccountConfig().Strategy)
					return nil
				}
			}
			if addName != "" {
				saved, err := mgr.SaveAccount(gateway.AccountProfile{
					Name:           addName,
					Username:       username,
					Token:          token,
					RefreshToken:   refreshToken,
					Cookie:         cookie,
					Tags:           tags,
					StickyDeviceID: stickyDevice,
					ExpiresAt:      expiresAt,
					Enabled:        true,
					Status:         gateway.AccountStatusActive,
				})
				if err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(saved)
				}
				fmt.Fprintf(out, "Added account %s (%s · status=%s)\n", saved.ID, saved.Name, saved.Status)
				return nil
			}

			accounts := mgr.ListAccounts()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(accounts)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.accounts.title"), fmt.Sprintf("%d", len(accounts)))
			}
			if len(accounts) == 0 {
				fmt.Fprintln(out, "No accounts in pool. Use 'cap gateway accounts --add <name> --token <tok>' to add one.")
				return nil
			}
			fmt.Fprintf(out, "%-24s %-18s %-11s %-7s %-6s %-6s %s\n", "ID", "NAME", "STATUS", "ENABLED", "USES", "FAILS", "TAGS")
			for _, a := range accounts {
				fmt.Fprintf(out, "%-24s %-18s %-11s %-7v %-6d %-6d %s\n",
					tui.Truncate(a.ID, 24), tui.Truncate(a.Name, 18), a.Status, a.Enabled,
					a.UseCount, a.FailCount, strings.Join(a.Tags, ","))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addName, "add", "", "add an account profile with the given display name")
	cmd.Flags().StringVar(&username, "username", "", "optional username for --add")
	cmd.Flags().StringVar(&token, "token", "", "primary bearer/session token for --add")
	cmd.Flags().StringVar(&refreshToken, "refresh-token", "", "optional refresh token for --add")
	cmd.Flags().StringVar(&cookie, "cookie", "", "optional Cookie header value for --add")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "optional tags for --add")
	cmd.Flags().StringVar(&stickyDevice, "sticky-device", "", "optional sticky device ID for --add")
	cmd.Flags().StringVar(&expiresAt, "expires-at", "", "optional RFC3339 expiry timestamp for --add")
	cmd.Flags().StringVar(&strategy, "strategy", "", "update pool rotation strategy (round_robin, least_used, sticky_device)")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete an account profile by ID")
	cmd.Flags().StringVar(&markHealthyID, "mark-healthy", "", "mark an account active and clear errors/expiry by ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newGatewayWorkersCmd() *cobra.Command {
	var (
		addName     string
		kind        string
		command     string
		cmdArgs     []string
		workDir     string
		basePort    int
		instances   int
		healthPath  string
		signPath    string
		autoRestart bool
		startID     string
		stopID      string
		restartID   string
		deleteID    string
		showStatus  bool
		jsonOut     bool
	)

	cmd := &cobra.Command{
		Use:   "workers",
		Short: "Manage local supervised Signer Worker Process Pools",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			if deleteID != "" {
				if err := mgr.DeleteWorker(deleteID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Deleted worker pool %s\n", deleteID)
				return nil
			}
			if startID != "" {
				if err := mgr.StartWorker(startID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Started worker pool %s\n", startID)
				return nil
			}
			if stopID != "" {
				if err := mgr.StopWorker(stopID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Stopped worker pool %s\n", stopID)
				return nil
			}
			if restartID != "" {
				if err := mgr.RestartWorker(restartID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Restarted worker pool %s\n", restartID)
				return nil
			}
			if addName != "" {
				saved, err := mgr.SaveWorker(gateway.ManagedWorkerSpec{
					Name:        addName,
					Kind:        kind,
					Command:     command,
					Args:        cmdArgs,
					WorkDir:     workDir,
					BasePort:    basePort,
					Instances:   instances,
					HealthPath:  healthPath,
					SignPath:    signPath,
					AutoRestart: autoRestart,
					Enabled:     true,
				})
				if err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(saved)
				}
				fmt.Fprintf(out, "Added worker pool %s (%s · kind=%s · base_port=%d · instances=%d)\n",
					saved.ID, saved.Name, saved.Kind, saved.BasePort, saved.Instances)
				return nil
			}
			if showStatus {
				statuses := mgr.ListWorkerStatuses()
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(statuses)
				}
				styled := isStyledWriter(out)
				th := cliTheme(styled)
				if styled {
					printSectionHeader(out, th, i18n.T("cli.gateway.workers.title"), fmt.Sprintf("%d", len(statuses)))
				}
				if len(statuses) == 0 {
					fmt.Fprintln(out, "No managed worker pools configured.")
					return nil
				}
				fmt.Fprintf(out, "%-24s %-14s %-8s %-10s %s\n", "ID", "KIND", "RUNNING", "HEALTHY", "NAME")
				for _, s := range statuses {
					fmt.Fprintf(out, "%-24s %-14s %-8v %d/%-8d %s\n",
						tui.Truncate(s.Spec.ID, 24), s.Spec.Kind, s.Running,
						s.HealthyInstances, s.TotalInstances, s.Spec.Name)
				}
				return nil
			}

			workers := mgr.ListWorkers()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(workers)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.workers.title"), fmt.Sprintf("%d", len(workers)))
			}
			if len(workers) == 0 {
				fmt.Fprintln(out, "No managed worker pools configured. Use 'cap gateway workers --add <name> --cmd <bin> --base-port <port>'.")
				return nil
			}
			fmt.Fprintf(out, "%-24s %-14s %-6s %-5s %-8s %s\n", "ID", "KIND", "PORT", "INST", "ENABLED", "NAME")
			for _, w := range workers {
				fmt.Fprintf(out, "%-24s %-14s %-6d %-5d %-8v %s\n",
					tui.Truncate(w.ID, 24), w.Kind, w.BasePort, w.Instances, w.Enabled, w.Name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addName, "add", "", "add a managed worker pool with the given name")
	cmd.Flags().StringVar(&kind, "kind", gateway.WorkerKindScriptHTTP, "worker kind: unidbg_http, qiling_http, script_http, custom")
	cmd.Flags().StringVar(&command, "cmd", "", "executable command for --add")
	cmd.Flags().StringArrayVar(&cmdArgs, "args", nil, "command arguments for --add (repeatable)")
	cmd.Flags().StringVar(&workDir, "work-dir", "", "working directory for --add")
	cmd.Flags().IntVar(&basePort, "base-port", 18900, "base loopback port for --add")
	cmd.Flags().IntVar(&instances, "instances", 1, "number of worker instances (1..8) for --add")
	cmd.Flags().StringVar(&healthPath, "health-path", gateway.DefaultWorkerHealthPath, "health check path for --add")
	cmd.Flags().StringVar(&signPath, "sign-path", gateway.DefaultWorkerSignPath, "signing endpoint path for --add")
	cmd.Flags().BoolVar(&autoRestart, "auto-restart", true, "auto-restart crashed instances for --add")
	cmd.Flags().StringVar(&startID, "start", "", "start a managed worker pool by ID")
	cmd.Flags().StringVar(&stopID, "stop", "", "stop a managed worker pool by ID")
	cmd.Flags().StringVar(&restartID, "restart", "", "restart a managed worker pool by ID")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete a managed worker pool by ID")
	cmd.Flags().BoolVar(&showStatus, "status", false, "show live runtime status snapshots for all worker pools")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newGatewayCircuitsCmd() *cobra.Command {
	var (
		resetSlug      string
		clearCacheSlug string
		jsonOut        bool
	)

	cmd := &cobra.Command{
		Use:   "circuits",
		Short: "Inspect or reset per-route circuit breakers and clear route response caches",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}

			acted := false
			if cmd.Flags().Changed("reset") {
				slug := strings.TrimSpace(resetSlug)
				if slug == "all" || slug == "*" {
					slug = ""
				}
				mgr.ResetCircuit(slug)
				acted = true
				if !jsonOut {
					if slug == "" {
						fmt.Fprintln(out, "Reset circuit breaker state for all routes")
					} else {
						fmt.Fprintf(out, "Reset circuit breaker for route %s\n", slug)
					}
				}
			}
			if cmd.Flags().Changed("clear-cache") {
				slug := strings.TrimSpace(clearCacheSlug)
				if slug == "all" || slug == "*" {
					slug = ""
				}
				mgr.ClearRouteCache(slug)
				acted = true
				if !jsonOut {
					if slug == "" {
						fmt.Fprintln(out, "Cleared response cache for all routes")
					} else {
						fmt.Fprintf(out, "Cleared response cache for route %s\n", slug)
					}
				}
			}
			if acted && !jsonOut {
				return nil
			}

			states := mgr.CircuitStates()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(states)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.gateway.circuits.title"), fmt.Sprintf("%d", len(states)))
			}
			if len(states) == 0 {
				fmt.Fprintln(out, "No circuit-protected routes tracked.")
				return nil
			}
			slugs := make([]string, 0, len(states))
			for slug := range states {
				slugs = append(slugs, slug)
			}
			sort.Strings(slugs)
			fmt.Fprintf(out, "%-24s %-10s %-10s %-10s %s\n", "ROUTE", "STATE", "FAILS/THR", "COOLDOWN", "TRIPS")
			for _, slug := range slugs {
				s := states[slug]
				fmt.Fprintf(out, "%-24s %-10s %d/%-8d %-10s %d\n",
					tui.Truncate(s.RouteSlug, 24), s.State, s.ConsecutiveFailures, s.Threshold,
					fmt.Sprintf("%ds", s.CooldownSec), s.TripCount)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&resetSlug, "reset", "", "reset circuit breaker for route slug (use 'all' for all routes)")
	cmd.Flags().StringVar(&clearCacheSlug, "clear-cache", "", "clear TTL response cache for route slug (use 'all' for all routes)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newGatewayPrometheusCmd() *cobra.Command {
	var outFile string

	cmd := &cobra.Command{
		Use:   "prometheus",
		Short: "Export gateway telemetry in Prometheus text exposition format",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			metrics := mgr.PrometheusMetrics()
			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(metrics), 0o644); err != nil {
					return fmt.Errorf("write Prometheus metrics %s: %w", outFile, err)
				}
				fmt.Fprintf(out, "Wrote Prometheus metrics to %s\n", outFile)
				return nil
			}
			fmt.Fprint(out, metrics)
			if !strings.HasSuffix(metrics, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write Prometheus exposition text to file")
	return cmd
}

func newGatewayExportDockerCmd() *cobra.Command {
	var (
		addr    string
		outDir  string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "export-docker",
		Short: "Export Dockerfile and docker-compose.yml for headless 'cap gateway serve' deployment",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openGatewayManager()
			if err != nil {
				return err
			}
			bundle := mgr.ExportDockerBundle(addr)
			if strings.TrimSpace(outDir) != "" {
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					return fmt.Errorf("create output dir %s: %w", outDir, err)
				}
				dfPath := filepath.Join(outDir, "Dockerfile")
				dcPath := filepath.Join(outDir, "docker-compose.yml")
				if err := os.WriteFile(dfPath, []byte(bundle.Dockerfile), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", dfPath, err)
				}
				if err := os.WriteFile(dcPath, []byte(bundle.DockerCompose), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", dcPath, err)
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]any{
						"listen_addr":    bundle.ListenAddr,
						"dockerfile":     dfPath,
						"docker_compose": dcPath,
					})
				}
				fmt.Fprintf(out, "Exported Docker deployment bundle (listen=%s) to %s:\n  - %s\n  - %s\n",
					bundle.ListenAddr, outDir, dfPath, dcPath)
				return nil
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(bundle)
			}
			fmt.Fprintf(out, "# === Dockerfile (listen=%s) ===\n%s\n# === docker-compose.yml ===\n%s",
				bundle.ListenAddr, bundle.Dockerfile, bundle.DockerCompose)
			return nil
		},
	}

	cmd.Flags().StringVarP(&addr, "addr", "a", "0.0.0.0:9090", "listen address configured in container")
	cmd.Flags().StringVarP(&outDir, "out-dir", "o", "", "directory to write Dockerfile and docker-compose.yml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}
