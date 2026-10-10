package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/android"
	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/store/sqlite"
	"github.com/overkazaf/cap/internal/types"
)

// newStartCmd builds `cap start`: run the MITM proxy, saving every captured
// flow to the SQLite store and printing a one-line summary as it arrives.
func newStartCmd() *cobra.Command {
	var addr string
	var dbPath string
	var certDir string
	var autoDisconnect bool
	var deviceSerial string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the MITM proxy and capture traffic",
		Long: "Start cap's MITM proxy. Every intercepted HTTP(S) request/response pair is\n" +
			"saved to the flow database and summarized on stdout as it's captured.\n\n" +
			"Use --auto-disconnect to automatically clear the Android device's proxy\n" +
			"when cap shuts down, so the phone can access the internet normally.",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			p, err := proxy.New(proxy.Options{
				Addr:    addr,
				CertDir: certDir,
				OnFlow:  onFlow(st),
			})
			if err != nil {
				return fmt.Errorf("create proxy: %w", err)
			}

			resolvedDB := dbPath
			if resolvedDB == "" {
				resolvedDB = defaultDBPath()
			}

			fmt.Printf("cap: listening on      %s\n", p.Addr())
			fmt.Printf("cap: database          %s\n", resolvedDB)
			fmt.Printf("cap: CA certificate    %s\n", certFile)
			if autoDisconnect {
				fmt.Println("cap: auto-disconnect   enabled")
			}
			fmt.Println("cap: press Ctrl+C to stop")
			fmt.Println()

			var onShutdown func()
			if autoDisconnect {
				onShutdown = func() {
					if err := android.Teardown(deviceSerial); err != nil {
						fmt.Fprintf(os.Stderr, "cap: auto-disconnect: %v\n", err)
					}
				}
			}

			return runProxyUntilSignal(p, onShutdown)
		},
	}

	cmd.Flags().StringVarP(&addr, "addr", "a", "127.0.0.1:8080", "proxy listen address")
	cmd.Flags().StringVarP(&dbPath, "db", "d", "", `database path (default "~/.cap/flows.db")`)
	cmd.Flags().StringVar(&certDir, "cert-dir", "", `CA cert directory (default "~/.cap")`)
	cmd.Flags().BoolVar(&autoDisconnect, "auto-disconnect", false, "clear device proxy on shutdown")
	cmd.Flags().StringVar(&deviceSerial, "device", "", "device serial for auto-disconnect (auto-detect if omitted)")

	return cmd
}

// onFlow returns a proxy.Options.OnFlow callback that persists each captured
// flow to st and prints a one-line summary, e.g.:
//
//	[f1] POST https://api.com/login → 200 (120ms)
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
func runProxyUntilSignal(p *proxy.Proxy, onShutdown func()) error {
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
		fmt.Println("\ncap: shutting down...")
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
