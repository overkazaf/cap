package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/buildinfo"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/store/sqlite"
	"github.com/overkazaf/cap/internal/tui"
	"github.com/overkazaf/cap/internal/types"
)

// newStartCmd builds `cap start`: run the MITM proxy, saving every captured
// flow to the SQLite store and printing a one-line summary as it arrives
// (or launching the interactive full-screen TUI with --tui).
func newStartCmd() *cobra.Command {
	var addr string
	var dbPath string
	var certDir string
	var autoDisconnect bool
	var deviceSerial string
	var launchTUI bool
	var lightTheme bool
	var noColor bool

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the MITM proxy and capture traffic",
		Long: "Start cap's MITM proxy. Every intercepted HTTP(S) request/response pair is\n" +
			"saved to the flow database and summarized on stdout as it's captured.\n\n" +
			"Pass --tui to launch the full-screen interactive terminal workbench with live\n" +
			"traffic streaming, filtering, JSON/hex inspection, and one-key replay.\n\n" +
			"Use --auto-disconnect to automatically clear the Android device's proxy\n" +
			"when cap shuts down, so the phone can access the internet normally.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if launchTUI {
				return runTUI(tuiLaunchOptions{
					Live:           true,
					Addr:           addr,
					DBPath:         dbPath,
					CertDir:        certDir,
					AutoDisconnect: autoDisconnect,
					DeviceSerial:   deviceSerial,
					LightTheme:     lightTheme,
					NoColor:        noColor,
				})
			}

			if certDir == "" {
				certDir = defaultCapDir()
			}

			certFile, _, err := proxy.EnsureCA(certDir)
			if err != nil {
				return fmt.Errorf("ensure CA certificate: %w", err)
			}

			st, err := openStore(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			out := cmd.OutOrStdout()
			styled := isStyledWriter(out) && !noColor
			th := cliTheme(styled)
			width := cliWidth(out)

			var flowCount atomic.Int64
			var printMu sync.Mutex

			p, err := proxy.New(proxy.Options{
				Addr:    addr,
				CertDir: certDir,
				OnFlow:  onFlowFormatted(st, out, styled, th, width, &flowCount, &printMu),
			})
			if err != nil {
				return fmt.Errorf("create proxy: %w", err)
			}

			resolvedDB := dbPath
			if resolvedDB == "" {
				resolvedDB = defaultDBPath()
			}

			onShutdown, detectedDevice := detectAndroidCleanupSilent(deviceSerial, p.Addr())
			if onShutdown == nil && autoDisconnect {
				onShutdown = func() {
					if err := android.Teardown(deviceSerial); err != nil {
						fmt.Fprintf(os.Stderr, "cap: auto-disconnect: %v\n", err)
					}
				}
			}

			printStartBanner(out, styled, th, width, p.Addr(), resolvedDB, certFile, onShutdown != nil, detectedDevice)

			err = runProxyUntilSignal(p, out, styled, th, &flowCount, onShutdown)
			return err
		},
	}

	cmd.Flags().StringVarP(&addr, "addr", "a", "127.0.0.1:8080", "proxy listen address")
	cmd.Flags().StringVarP(&dbPath, "db", "d", "", `database path (default "~/.cap/flows.db")`)
	cmd.Flags().StringVar(&certDir, "cert-dir", "", `CA cert directory (default "~/.cap")`)
	cmd.Flags().BoolVar(&autoDisconnect, "auto-disconnect", false, "clear device proxy on shutdown (auto-detected if device proxy points at cap)")
	cmd.Flags().StringVar(&deviceSerial, "device", "", "device serial for auto-disconnect (auto-detect if omitted)")
	cmd.Flags().BoolVar(&launchTUI, "tui", false, "run live capture inside the interactive full-screen TUI")
	cmd.Flags().BoolVar(&lightTheme, "light", false, "use Porcelain Light theme (with --tui)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable ANSI colors")

	return cmd
}

func printStartBanner(w io.Writer, styled bool, th tui.Theme, termW int, listenAddr, dbPath, certFile string, autoClean bool, detectedDevice string) {
	if !styled {
		fmt.Fprintf(w, "cap: listening on      %s\n", listenAddr)
		fmt.Fprintf(w, "cap: database          %s\n", dbPath)
		fmt.Fprintf(w, "cap: CA certificate    %s\n", certFile)
		if detectedDevice != "" {
			fmt.Fprintf(w, "cap: detected device   %s\n", detectedDevice)
		}
		if autoClean {
			fmt.Fprintln(w, "cap: auto-disconnect   enabled")
		}
		fmt.Fprintln(w, "cap: press Ctrl+C to stop")
		fmt.Fprintln(w)
		return
	}

	boxW := min(max(termW, 60), 86)
	innerW := boxW - 2
	border := th.BorderFocus

	title := th.Pill(th.BrandFg, th.BrandBg, true, " CAP ") + " " + th.Bold(th.FgPrimary, i18n.T("cli.start.title")) + " " + th.Fg(th.FgMuted, "v"+buildinfo.Version())
	topPrefix := th.Fg(border, "╭─ ") + title + th.Fg(border, " ")
	rem := boxW - tui.DisplayWidth(topPrefix) - 1
	if rem < 0 {
		rem = 0
	}
	fmt.Fprintln(w, topPrefix+th.Fg(border, strings.Repeat("─", rem)+"╮"))

	row := func(label, val string) {
		content := "  " + th.Fg(th.FgMuted, tui.PadRight(label, 16)) + val
		fmt.Fprintln(w, th.Fg(border, "│")+tui.PadRight(content, innerW)+th.Fg(border, "│"))
	}

	row(i18n.T("cli.start.status"), th.Bold(th.Live, "● "+i18n.T("tui.mode.live"))+"  "+th.Bold(th.FgPrimary, "http://"+listenAddr))
	row(i18n.T("cli.start.database"), th.Fg(th.FgSecondary, tui.Truncate(dbPath, innerW-20)))
	row(i18n.T("cli.start.ca_cert"), th.Fg(th.FgSecondary, tui.Truncate(certFile, innerW-20)))
	if detectedDevice != "" {
		row(i18n.T("cli.start.android_dev"), th.Fg(th.Info, tui.Truncate(detectedDevice, innerW-20)))
	}
	if autoClean {
		row(i18n.T("cli.start.auto_clean"), th.Fg(th.Success, i18n.T("common.enabled"))+" "+th.Fg(th.FgMuted, i18n.T("cli.start.auto_clean_msg")))
	}
	tip := "  " + th.Fg(th.FgMuted, i18n.T("cli.start.tip_pre")) + th.Fg(th.Accent, "cap start --tui") + th.Fg(th.FgMuted, i18n.T("cli.start.tip_mid")) + th.Fg(th.FgSecondary, "Ctrl+C") + th.Fg(th.FgMuted, i18n.T("cli.start.tip_post"))
	fmt.Fprintln(w, th.Fg(border, "│")+tui.PadRight(tip, innerW)+th.Fg(border, "│"))
	fmt.Fprintln(w, th.Fg(border, "╰"+strings.Repeat("─", innerW)+"╯"))
	fmt.Fprintln(w)

	// Column header for live traffic stream (CJK-width aware).
	hdr := fmt.Sprintf("  %s  %s  %s  %s  %s  %s  %s",
		tui.PadRight(i18n.T("cli.start.col.time"), 8),
		tui.PadRight(i18n.T("cli.start.col.id"), 5),
		tui.PadRight(i18n.T("cli.start.col.method"), 7),
		tui.PadRight(i18n.T("cli.start.col.sts"), 4),
		tui.PadLeft(i18n.T("cli.start.col.latency"), 7),
		tui.PadLeft(i18n.T("cli.start.col.size"), 8),
		i18n.T("cli.start.col.target"),
	)
	fmt.Fprintln(w, th.Dim(th.FgMuted, hdr))
	fmt.Fprintln(w, th.Fg(th.BorderMuted, "  "+strings.Repeat("─", min(max(termW-4, 56), 100))))
}

// formatStreamFlowLine formats a single captured flow for `cap start`.
// In styled TTY mode it emits an aligned, color-coded commercial log line;
// in non-TTY/piped mode it emits the classic parseable plain line.
func formatStreamFlowLine(f *types.Flow, styled bool, th tui.Theme, termW int) string {
	if !styled {
		return fmt.Sprintf("[%s] %s %s → %d (%dms)", f.ID, f.Method, f.URL, f.Status, f.LatencyMs)
	}

	ts := f.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	timeStr := th.Fg(th.FgMuted, ts.Local().Format("15:04:05"))
	idStr := th.Fg(th.FgMuted, tui.PadRight(tui.Truncate(tui.SanitizeInline(f.ID), 5), 5))
	methodStr := th.Bold(th.MethodColor(f.Method), tui.PadRight(tui.Truncate(strings.ToUpper(f.Method), 7), 7))
	statusStr := th.Bold(th.StatusColor(f.Status), fmt.Sprintf("%3d", f.Status))

	latColor := th.FgMuted
	if f.LatencyMs >= 1000 {
		latColor = th.Danger
	} else if f.LatencyMs >= 400 {
		latColor = th.Warn
	}
	latStr := th.Fg(latColor, tui.PadLeft(tui.FormatLatency(f.LatencyMs), 7))
	sizeStr := th.Fg(th.FgMuted, tui.PadLeft(tui.FormatBytes(len(f.RespBody)), 8))

	// Fixed prefix takes ~50 cells; give remaining width to host + path.
	targetMax := termW - 52
	if targetMax < 24 {
		targetMax = 24
	}
	host := tui.SanitizeInline(f.Host)
	path := tui.SanitizeInline(f.Path)
	if path == "" {
		path = "/"
	}
	target := host + path
	if tui.DisplayWidth(target) > targetMax {
		target = tui.Truncate(target, targetMax)
		return fmt.Sprintf("  %s  %s  %s  %s  %s  %s  %s",
			timeStr, idStr, methodStr, statusStr, latStr, sizeStr, th.Fg(th.FgPrimary, target))
	}
	return fmt.Sprintf("  %s  %s  %s  %s  %s  %s  %s%s",
		timeStr, idStr, methodStr, statusStr, latStr, sizeStr,
		th.Fg(th.FgSecondary, host), th.Fg(th.FgPrimary, path))
}

func onFlowFormatted(st *sqlite.SQLiteStore, out io.Writer, styled bool, th tui.Theme, width int, counter *atomic.Int64, mu *sync.Mutex) func(*types.Flow) {
	return func(f *types.Flow) {
		if err := st.SaveFlow(f); err != nil {
			fmt.Fprintf(os.Stderr, "cap: save flow %s: %v\n", f.ID, err)
		}
		counter.Add(1)
		line := formatStreamFlowLine(f, styled, th, width)
		mu.Lock()
		fmt.Fprintln(out, line)
		mu.Unlock()
	}
}

// onFlow returns a proxy.Options.OnFlow callback that persists each captured
// flow to st and prints a one-line summary. Kept for backward compatibility.
func onFlow(st *sqlite.SQLiteStore) func(*types.Flow) {
	return func(f *types.Flow) {
		if err := st.SaveFlow(f); err != nil {
			fmt.Fprintf(os.Stderr, "cap: save flow %s: %v\n", f.ID, err)
		}
		fmt.Printf("[%s] %s %s → %d (%dms)\n", f.ID, f.Method, f.URL, f.Status, f.LatencyMs)
	}
}

// runProxyUntilSignal starts p and blocks until either it stops on its own
// (returning its error, if any) or SIGINT/SIGTERM requests a graceful
// shutdown. If onShutdown is non-nil it is called after stopping the proxy
// (e.g. to clear the Android device's Wi-Fi proxy).
func runProxyUntilSignal(p *proxy.Proxy, out io.Writer, styled bool, th tui.Theme, counter *atomic.Int64, onShutdown func()) error {
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- p.Start()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	select {
	case err := <-serveErr:
		if onShutdown != nil {
			onShutdown()
		}
		if err != nil {
			return fmt.Errorf("proxy stopped: %w", err)
		}
		return nil
	case <-sig:
		if styled {
			fmt.Fprintln(out)
			printInfoBadge(out, th, i18n.T("cli.start.stopped", counter.Load()))
		} else {
			fmt.Fprintln(out, "\ncap: shutting down...")
		}
		if err := p.Stop(); err != nil {
			return fmt.Errorf("stop proxy: %w", err)
		}
		<-serveErr
		if onShutdown != nil {
			onShutdown()
		}
		return nil
	}
}
