package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/frida"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/tui"
)

func newFridaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "frida",
		Short: "Manage Frida server, scripts, and live instrumentation sessions",
		Long: `Full Frida dynamic instrumentation workflow for Android reverse engineering:

  status   — Inspect host Python/Frida toolchain & device frida-server status
  deploy   — Auto-download (matching ABI/version) or push local frida-server
  start    — Start frida-server on device (with optional custom port & forward)
  stop     — Stop running frida-server on device
  ps       — List applications & running processes on device
  scripts  — List built-in & custom scripts (~/.cap/frida-scripts/) or print one
  run      — Spawn or attach to an app with live structured hook output

Examples:
  cap frida status
  cap frida deploy --start --name hluda-srv
  cap frida ps
  cap frida scripts --show builtin:crypto-sign-tracer
  cap frida run --pkg com.example.app --spawn --script builtin:ssl-unpin-universal`,
	}

	cmd.AddCommand(
		newFridaStatusCmd(),
		newFridaDeployCmd(),
		newFridaStartCmd(),
		newFridaStopCmd(),
		newFridaPSCmd(),
		newFridaScriptsCmd(),
		newFridaRunCmd(),
	)

	return cmd
}

func newFridaStatusCmd() *cobra.Command {
	var (
		serial  string
		port    int
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Inspect host Frida toolchain and device frida-server status",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			tc := frida.DetectToolchain(frida.ToolchainConfig{})
			hostVer := tc.FridaVersion
			if hostVer == "" {
				hostVer = tc.FridaCLIVersion
			}
			srv, _ := frida.CheckServer(serial, port, hostVer)

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"toolchain": tc,
					"server":    srv,
				})
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.frida.status.title"), tc.Driver)
			}

			fmt.Fprintf(out, "  %s  %s\n", th.Bold(th.FgMuted, tui.PadRight("Driver", 14)), th.Bold(th.FgPrimary, tc.Driver))
			if tc.PythonPath != "" {
				pyStatus := tc.PythonPath + " (" + tc.PythonVersion + ")"
				if tc.FridaModuleOK {
					pyStatus += " · frida " + tc.FridaVersion
				} else {
					pyStatus += " · frida module missing"
				}
				fmt.Fprintf(out, "  %s  %s\n", th.Fg(th.FgMuted, tui.PadRight("Python", 14)), pyStatus)
			}
			if tc.FridaCLIPath != "" {
				cliState := tc.FridaCLIPath
				if tc.FridaCLIOK {
					cliState += " (v" + tc.FridaCLIVersion + ")"
				} else {
					cliState += " (broken/unhealthy)"
				}
				fmt.Fprintf(out, "  %s  %s\n", th.Fg(th.FgMuted, tui.PadRight("Frida CLI", 14)), cliState)
			}
			for _, iss := range tc.Issues {
				fmt.Fprintf(out, "  %s  %s\n", th.Fg(th.Warn, tui.PadRight("Notice", 14)), iss)
			}

			fmt.Fprintln(out)
			if srv == nil || !srv.Connected {
				msg := "no Android device connected"
				if srv != nil && srv.Error != "" {
					msg = srv.Error
				}
				fmt.Fprintf(out, "  %s  %s\n", th.Fg(th.FgMuted, tui.PadRight("Device", 14)), th.Fg(th.Warn, msg))
				return nil
			}

			stateStr := "stopped"
			if srv.Running {
				stateStr = fmt.Sprintf("running (PID %s · port %d)", srv.PID, srv.Port)
			} else if srv.BinaryPath == "" {
				stateStr = "not deployed"
			}
			fmt.Fprintf(out, "  %s  %s (%s / %s)\n", th.Fg(th.FgMuted, tui.PadRight("Device", 14)), srv.Serial, srv.DeviceABI, srv.FridaArch)
			fmt.Fprintf(out, "  %s  %s\n", th.Fg(th.FgMuted, tui.PadRight("Server", 14)), stateStr)
			if srv.BinaryPath != "" {
				fmt.Fprintf(out, "  %s  %s (v%s · %s)\n", th.Fg(th.FgMuted, tui.PadRight("Binary", 14)), srv.BinaryPath, srv.ServerVersion, srv.VersionMatch)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial (auto-detect if omitted)")
	cmd.Flags().IntVarP(&port, "port", "p", frida.DefaultPort, "frida-server port")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newFridaDeployCmd() *cobra.Command {
	var (
		serial     string
		version    string
		localBin   string
		remoteName string
		port       int
		autoStart  bool
		forward    bool
	)

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Download or push frida-server to Android device",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if version == "" && localBin == "" {
				tc := frida.DetectToolchain(frida.ToolchainConfig{})
				if tc.FridaVersion != "" {
					version = tc.FridaVersion
				} else if tc.FridaCLIVersion != "" {
					version = tc.FridaCLIVersion
				}
			}
			res, err := frida.DeployServer(context.Background(), frida.DeployOptions{
				Serial:          serial,
				Version:         version,
				LocalBinaryPath: localBin,
				RemoteName:      remoteName,
				Port:            port,
				AutoStart:       autoStart,
				ForwardPort:     forward,
				OnProgress: func(ev frida.DeployProgressEvent) {
					fmt.Fprintf(out, "[%3d%%] [%s] %s\n", ev.Percent, ev.Stage, ev.Detail)
				},
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(out, res.Message)
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial")
	cmd.Flags().StringVar(&version, "version", "", "Frida release version (default: match local frida or latest)")
	cmd.Flags().StringVar(&localBin, "binary", "", "local frida-server binary (raw or .xz) for offline deploy")
	cmd.Flags().StringVar(&remoteName, "name", frida.DefaultRemoteName, "remote filename on device (supports stealth rename)")
	cmd.Flags().IntVarP(&port, "port", "p", frida.DefaultPort, "frida-server listen port")
	cmd.Flags().BoolVar(&autoStart, "start", false, "start frida-server immediately after deploy")
	cmd.Flags().BoolVar(&forward, "forward", true, "configure adb port forwarding")
	return cmd
}

func newFridaStartCmd() *cobra.Command {
	var (
		serial     string
		binaryPath string
		port       int
		forward    bool
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start frida-server on the Android device",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := frida.StartServer(frida.StartServerOptions{
				Serial:      serial,
				BinaryPath:  binaryPath,
				Port:        port,
				ForwardPort: forward,
			})
			if err != nil {
				return err
			}
			if st.Running {
				fmt.Fprintf(cmd.OutOrStdout(), "frida-server running on %s (PID %s, port %d)\n", st.Serial, st.PID, st.Port)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "frida-server start command sent to %s\n", st.Serial)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "remote path to frida-server binary")
	cmd.Flags().IntVarP(&port, "port", "p", frida.DefaultPort, "listen port")
	cmd.Flags().BoolVar(&forward, "forward", true, "setup adb forward tcp:<port>")
	return cmd
}

func newFridaStopCmd() *cobra.Command {
	var (
		serial     string
		binaryName string
		port       int
	)

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop running frida-server on the Android device",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := frida.StopServer(serial, binaryName, port, "")
			if err != nil {
				return err
			}
			if st.Running {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: frida-server still appears running (PID %s)\n", st.PID)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "frida-server stopped on %s\n", st.Serial)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial")
	cmd.Flags().StringVar(&binaryName, "name", "", "custom stealth binary name to stop")
	cmd.Flags().IntVarP(&port, "port", "p", frida.DefaultPort, "port to remove adb forward")
	return cmd
}

func newFridaPSCmd() *cobra.Command {
	var (
		serial     string
		remoteHost string
		jsonOut    bool
	)

	cmd := &cobra.Command{
		Use:   "ps",
		Short: "List apps and running processes on device",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			tc := frida.DetectToolchain(frida.ToolchainConfig{})
			entries, err := frida.ListProcesses(context.Background(), serial, remoteHost, tc)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(entries)
			}
			fmt.Fprintf(out, "%-7s %-28s %s\n", "PID", "NAME", "IDENTIFIER")
			for _, e := range entries {
				pidStr := "-"
				if e.PID > 0 {
					pidStr = fmt.Sprintf("%d", e.PID)
				}
				fmt.Fprintf(out, "%-7s %-28s %s\n", pidStr, tui.Truncate(e.Name, 28), e.Identifier)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial")
	cmd.Flags().StringVarP(&remoteHost, "host", "H", "", "remote frida-server host:port")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newFridaScriptsCmd() *cobra.Command {
	var (
		showID  string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "scripts",
		Short: "List built-in & custom Frida scripts or print script source",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			store, err := frida.NewScriptStore(filepath.Join(config.DefaultDir(), "frida-scripts"))
			if err != nil {
				return err
			}
			if showID != "" {
				sc, ok := store.Get(showID)
				if !ok {
					return fmt.Errorf("script %q not found", showID)
				}
				fmt.Fprint(out, sc.Code)
				return nil
			}
			list := store.List()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(list)
			}
			fmt.Fprintf(out, "%-32s %-12s %s\n", "ID", "CATEGORY", "NAME")
			for _, sc := range list {
				fmt.Fprintf(out, "%-32s %-12s %s\n", sc.ID, sc.Category, sc.Name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&showID, "show", "", "print full JS source of the specified script ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newFridaRunCmd() *cobra.Command {
	var (
		serial     string
		pkg        string
		spawn      bool
		scriptRef  string
		port       int
		remoteHost string
		pythonPath string
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a Frida script against an Android app with live structured output",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := frida.NewManager(config.DefaultDir())
			if err != nil {
				return err
			}
			if pythonPath != "" {
				mgr.SetToolchainConfig(frida.ToolchainConfig{PythonPath: pythonPath})
			}

			var scriptCode, scriptName string
			if scriptRef == "" {
				scriptRef = "builtin:ssl-unpin-universal"
			}
			if sc, ok := mgr.Scripts().Get(scriptRef); ok {
				scriptCode = sc.Code
				scriptName = sc.Name
			} else if raw, readErr := os.ReadFile(scriptRef); readErr == nil {
				scriptCode = string(raw)
				scriptName = filepath.Base(scriptRef)
			} else {
				return fmt.Errorf("script %q not found in library or on disk", scriptRef)
			}

			mode := frida.ModeAttach
			if spawn {
				mode = frida.ModeSpawn
			}

			doneCh := make(chan struct{})
			mgr.SetCallbacks(
				func(ev frida.LogEvent) {
					fmt.Fprintf(out, "[%s] [%s] %s\n", strings.ToUpper(ev.Level), ev.Category, ev.Message)
				},
				func(st *frida.SessionState) {
					if st != nil && !st.Running && (st.Status == frida.StatusStopped || st.Status == frida.StatusError) {
						select {
						case <-doneCh:
						default:
							close(doneCh)
						}
					}
				},
			)

			if _, err := mgr.StartSession(frida.SessionConfig{
				Serial:     serial,
				Target:     pkg,
				Mode:       mode,
				ScriptCode: scriptCode,
				ScriptName: scriptName,
				Port:       port,
				RemoteHost: remoteHost,
				NoPause:    true,
			}); err != nil {
				return err
			}

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			defer signal.Stop(sigCh)

			select {
			case <-sigCh:
				fmt.Fprintln(out, "\nDetaching Frida session...")
				_ = mgr.StopSession()
			case <-doneCh:
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&serial, "serial", "s", "", "device serial")
	cmd.Flags().StringVar(&pkg, "pkg", "", "target app package name or PID")
	cmd.Flags().BoolVarP(&spawn, "spawn", "f", false, "spawn the app (vs. attach)")
	cmd.Flags().StringVarP(&scriptRef, "script", "l", "builtin:ssl-unpin-universal", "script ID from `cap frida scripts` or local .js file path")
	cmd.Flags().IntVarP(&port, "port", "p", frida.DefaultPort, "frida-server port")
	cmd.Flags().StringVarP(&remoteHost, "host", "H", "", "remote frida-server host:port")
	cmd.Flags().StringVar(&pythonPath, "python", "", "custom python3 binary path with frida installed")
	_ = cmd.MarkFlagRequired("pkg")
	return cmd
}
