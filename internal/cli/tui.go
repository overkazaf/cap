package cli

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/buildinfo"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/tui"
	"github.com/overkazaf/cap/internal/types"
)

type tuiLaunchOptions struct {
	Live           bool
	Addr           string
	DBPath         string
	CertDir        string
	AutoDisconnect bool
	DeviceSerial   string
	Filter         string
	LightTheme     bool
	NoColor        bool
	Lang           string
}

// newTUICmd builds `cap tui`: launch the interactive full-screen terminal UI
// for inspecting stored flows or running a live MITM capture session.
func newTUICmd() *cobra.Command {
	var opts tuiLaunchOptions

	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive full-screen TUI",
		Long: "Launch cap's commercial-grade interactive terminal UI.\n\n" +
			"By default, opens the SQLite flow database for fast keyboard-driven\n" +
			"browsing, JSON/hex inspection, replay, and code generation. Pass --live\n" +
			"to start the MITM proxy inside the TUI and watch flows arrive in real time.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.DBPath, "db", "d", "", `database path (default "~/.cap/flows.db")`)
	cmd.Flags().BoolVar(&opts.Live, "live", false, "start live MITM proxy capture inside the TUI")
	cmd.Flags().StringVarP(&opts.Addr, "addr", "a", "127.0.0.1:8080", "proxy listen address (used with --live)")
	cmd.Flags().StringVar(&opts.CertDir, "cert-dir", "", `CA cert directory (default "~/.cap")`)
	cmd.Flags().BoolVar(&opts.AutoDisconnect, "auto-disconnect", false, "clear Android device proxy on exit (used with --live)")
	cmd.Flags().StringVar(&opts.DeviceSerial, "device", "", "Android device serial for auto-disconnect")
	cmd.Flags().StringVarP(&opts.Filter, "filter", "f", "", "initial filter query (e.g. 'm:POST s:4xx')")
	cmd.Flags().BoolVar(&opts.LightTheme, "light", false, "start with the Porcelain Light theme")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "disable ANSI colors")

	return cmd
}

func runTUI(opts tuiLaunchOptions) error {
	if opts.Lang != "" {
		loc, ok := i18n.ParseLocale(opts.Lang)
		if !ok {
			return fmt.Errorf("%s", i18n.T("cli.err.invalid_lang", opts.Lang))
		}
		i18n.SetLang(string(loc))
	}

	if !isTTYCheck(os.Stdin) || !isTTYCheck(os.Stdout) {
		return fmt.Errorf("%s", i18n.T("cli.tui.need_tty"))
	}

	st, err := openStore(opts.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	resolvedDB := opts.DBPath
	if resolvedDB == "" {
		resolvedDB = defaultDBPath()
	}

	var (
		p            *proxy.Proxy
		flowCh       chan *types.Flow
		serveErr     chan error
		onShutdown   func()
		listenAddr   string
		capturedLive atomic.Int64
	)

	if opts.Live {
		certDir := opts.CertDir
		if certDir == "" {
			certDir = defaultCapDir()
		}
		if _, _, err := proxy.EnsureCA(certDir); err != nil {
			return fmt.Errorf("ensure CA certificate: %w", err)
		}

		flowCh = make(chan *types.Flow, 256)
		p, err = proxy.New(proxy.Options{
			Addr:    opts.Addr,
			CertDir: certDir,
			OnFlow: func(f *types.Flow) {
				_ = st.SaveFlow(f)
				capturedLive.Add(1)
				select {
				case flowCh <- f:
				default:
					// Never block proxy forwarding if UI channel is momentarily saturated.
				}
			},
		})
		if err != nil {
			return fmt.Errorf("create proxy: %w", err)
		}
		listenAddr = p.Addr()

		onShutdown, _ = detectAndroidCleanupSilent(opts.DeviceSerial, listenAddr)
		if onShutdown == nil && opts.AutoDisconnect {
			serial := opts.DeviceSerial
			onShutdown = func() {
				_ = android.Teardown(serial)
			}
		}

		serveErr = make(chan error, 1)
		go func() {
			serveErr <- p.Start()
		}()
	}

	app := tui.NewApp(tui.Config{
		Store:         st,
		Version:       buildinfo.Version(),
		Lang:          string(i18n.Lang()),
		Live:          opts.Live,
		ListenAddr:    listenAddr,
		DBPath:        resolvedDB,
		InitialFilter: opts.Filter,
		LightTheme:    opts.LightTheme,
		NoColor:       opts.NoColor,
		FlowStream:    flowCh,
		In:            os.Stdin,
		Out:           os.Stdout,
	})

	runErr := app.Run()

	if p != nil {
		_ = p.Stop()
		<-serveErr
		if onShutdown != nil {
			onShutdown()
		}
		if runErr == nil {
			th := cliTheme(isStyledWriter(os.Stdout) && !opts.NoColor)
			printInfoBadge(os.Stdout, th, i18n.T("cli.tui.ended", capturedLive.Load(), resolvedDB))
		}
	}

	return runErr
}

// detectAndroidCleanupSilent checks whether an attached Android device has its
// Wi-Fi proxy pointing at cap's port OR has the Cap Companion Guard watchdog
// active. When matched, it returns a teardown hook (stopping Companion Guard
// and clearing proxy/VPN rules) without printing to stdout so alt-screen TUI
// startup stays spotless.
func detectAndroidCleanupSilent(serial, listenAddr string) (func(), string) {
	devices, err := android.ListDevices()
	if err != nil || len(devices) == 0 {
		return nil, ""
	}
	resolvedSerial, err := android.GetDeviceSerial(serial)
	if err != nil {
		return nil, ""
	}

	_, listenPort, _ := strings.Cut(listenAddr, ":")
	proxySetting, _ := android.AdbShell(resolvedSerial, "settings get global http_proxy")
	host, port := android.ParseProxySetting(proxySetting)
	proxyMatched := host != "" && port == listenPort

	comp := android.GetCompanionStatus(resolvedSerial)
	if !proxyMatched && !comp.WatchdogRunning {
		return nil, ""
	}

	var info string
	if proxyMatched {
		info = fmt.Sprintf("%s (%s:%s)", resolvedSerial, host, port)
	} else {
		info = fmt.Sprintf("%s (Guard active)", resolvedSerial)
	}
	if comp.WatchdogRunning && proxyMatched {
		info += " · Guard ✓"
	}
	return func() {
		if err := android.Teardown(resolvedSerial); err != nil {
			fmt.Fprintf(os.Stderr, "cap: auto-disconnect: %v\n", err)
		}
	}, info
}
