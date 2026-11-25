package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/retools"
	"github.com/overkazaf/cap/internal/tui"
)

func loadSavedREToolchainConfig() retools.ToolchainConfig {
	settingsPath := filepath.Join(config.DefaultDir(), "settings.json")
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		return retools.ToolchainConfig{}
	}
	var settings map[string]string
	if err := json.Unmarshal(raw, &settings); err != nil {
		return retools.ToolchainConfig{}
	}
	return retools.ToolchainConfig{
		R2Path:           strings.TrimSpace(settings["re_r2_path"]),
		JavaPath:         strings.TrimSpace(settings["re_java_path"]),
		MvnPath:          strings.TrimSpace(settings["re_mvn_path"]),
		UnidbgDir:        strings.TrimSpace(settings["re_unidbg_dir"]),
		PythonPath:       strings.TrimSpace(settings["re_python_path"]),
		QilingPythonPath: strings.TrimSpace(settings["re_qiling_python_path"]),
		AngrPythonPath:   strings.TrimSpace(settings["re_angr_python_path"]),
		QilingRootFS:     strings.TrimSpace(settings["re_qiling_rootfs"]),
	}
}

func mergeREToolchainConfig(base, override retools.ToolchainConfig) retools.ToolchainConfig {
	pick := func(o, b string) string {
		if s := strings.TrimSpace(o); s != "" {
			return s
		}
		return strings.TrimSpace(b)
	}
	return retools.ToolchainConfig{
		R2Path:           pick(override.R2Path, base.R2Path),
		JavaPath:         pick(override.JavaPath, base.JavaPath),
		MvnPath:          pick(override.MvnPath, base.MvnPath),
		UnidbgDir:        pick(override.UnidbgDir, base.UnidbgDir),
		PythonPath:       pick(override.PythonPath, base.PythonPath),
		QilingPythonPath: pick(override.QilingPythonPath, base.QilingPythonPath),
		AngrPythonPath:   pick(override.AngrPythonPath, base.AngrPythonPath),
		QilingRootFS:     pick(override.QilingRootFS, base.QilingRootFS),
	}
}

func newRECmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "re",
		Short: "Native binary analysis and emulation (radare2, Unidbg, Qiling, angr)",
		Long: `Native reverse-engineering & algorithm emulation toolkit:

  status    — Inspect host radare2, Java/Maven/Unidbg, and Python/Qiling/angr readiness
  run       — Execute a Unidbg, Qiling, angr, or radare2 job from file or project ID
  analyze   — Statically analyze an ELF or Mach-O binary (radare2 or pure-Go fallback)
  r2        — Run a sanitized read-only radare2 command on a binary
  projects  — List built-in & custom RE projects or print project source code
  gen       — Synthesize a runnable Unidbg, Qiling, angr, or radare2 harness

Examples:
  cap re status
  cap re run --engine unidbg --file ./SignerHarness.java
  cap re run --engine qiling --file ./emulate.py --binary ./libsign.so
  cap re run --engine angr --file ./solve.py --json
  cap re analyze ./libnative-lib.so --json
  cap re r2 ./libnative-lib.so "afl"
  cap re projects --engine unidbg
  cap re gen --engine unidbg --apk app.apk --so libsign.so --class com/acme/Signer --method sign`,
	}

	cmd.AddCommand(
		newREStatusCmd(),
		newRERunCmd(),
		newREAnalyzeCmd(),
		newRER2Cmd(),
		newREProjectsCmd(),
		newREGenCmd(),
	)
	return cmd
}

func newREStatusCmd() *cobra.Command {
	var (
		cfg     retools.ToolchainConfig
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Inspect host RE toolchain readiness (radare2, Java/Unidbg, Python/Qiling/angr)",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			effective := mergeREToolchainConfig(loadSavedREToolchainConfig(), cfg)
			info := retools.DetectToolchain(effective)

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.re.status.title"), "")
			}

			tools := []retools.ToolStatus{
				info.R2, info.Java, info.Mvn, info.Unidbg, info.Python, info.Qiling, info.Angr,
			}
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
				fmt.Fprintf(out, "  %-10s %-8s %s\n", ts.Name, state, detail)
			}
			fmt.Fprintln(out)
			if info.JavacPath != "" {
				fmt.Fprintf(out, "  %-14s %s\n", "javac:", info.JavacPath)
			}
			if info.JavaHome != "" {
				fmt.Fprintf(out, "  %-14s %s\n", "java_home:", info.JavaHome)
			}
			if info.UnidbgMode != "" {
				fmt.Fprintf(out, "  %-14s %s\n", "unidbg_mode:", info.UnidbgMode)
			}
			if info.QilingRootFS != "" {
				fmt.Fprintf(out, "  %-14s %s\n", "qiling_rootfs:", info.QilingRootFS)
			}
			if info.Qiling.Path != "" {
				fmt.Fprintf(out, "  %-14s %s\n", "qiling_python:", info.Qiling.Path)
			}
			if info.Angr.Path != "" {
				fmt.Fprintf(out, "  %-14s %s\n", "angr_python:", info.Angr.Path)
			}
			fmt.Fprintf(out, "\n  Engines: r2=%v  unidbg=%v  qiling=%v  angr=%v\n",
				info.R2Ready, info.UnidbgReady, info.QilingReady, info.AngrReady)
			return nil
		},
	}

	cmd.Flags().StringVar(&cfg.R2Path, "r2", "", "custom radare2 binary path")
	cmd.Flags().StringVar(&cfg.JavaPath, "java", "", "custom java binary path")
	cmd.Flags().StringVar(&cfg.MvnPath, "mvn", "", "custom maven binary path")
	cmd.Flags().StringVar(&cfg.UnidbgDir, "unidbg-dir", "", "path to Unidbg directory or JARs")
	cmd.Flags().StringVar(&cfg.PythonPath, "python", "", "custom python3 binary path")
	cmd.Flags().StringVar(&cfg.QilingPythonPath, "qiling-python", "", "custom python3 binary path for Qiling")
	cmd.Flags().StringVar(&cfg.AngrPythonPath, "angr-python", "", "custom python3 binary path for angr")
	cmd.Flags().StringVar(&cfg.QilingRootFS, "rootfs", "", "Qiling rootfs directory")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newRERunCmd() *cobra.Command {
	var (
		engine     string
		filePath   string
		projectID  string
		binaryPath string
		apkPath    string
		rootfs     string
		timeoutSec int
		extraArgs  []string
		jsonOut    bool
		tcOverride retools.ToolchainConfig
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a Unidbg, Qiling, angr, or radare2 job from file or saved project",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			capDir := config.DefaultDir()

			mgr, err := retools.NewManager(capDir)
			if err != nil {
				return err
			}
			defer mgr.Shutdown()

			effectiveTC := mergeREToolchainConfig(loadSavedREToolchainConfig(), tcOverride)
			if strings.TrimSpace(rootfs) != "" {
				effectiveTC.QilingRootFS = strings.TrimSpace(rootfs)
			}
			mgr.SetToolchainConfig(effectiveTC)

			req := retools.RunJobRequest{
				ProjectID:  strings.TrimSpace(projectID),
				Engine:     strings.TrimSpace(engine),
				BinaryPath: strings.TrimSpace(binaryPath),
				APKPath:    strings.TrimSpace(apkPath),
				RootFS:     strings.TrimSpace(rootfs),
				TimeoutSec: timeoutSec,
				Args:       extraArgs,
			}

			if fp := strings.TrimSpace(filePath); fp != "" {
				raw, err := os.ReadFile(fp)
				if err != nil {
					return fmt.Errorf("read script file %s: %w", fp, err)
				}
				req.Code = string(raw)
				req.ProjectName = filepath.Base(fp)
				if req.Engine == "" {
					switch strings.ToLower(filepath.Ext(fp)) {
					case ".java":
						req.Engine = retools.EngineUnidbg
					case ".r2":
						req.Engine = retools.EngineRadare2
					}
				}
			}

			if req.Code == "" && req.ProjectID == "" {
				return fmt.Errorf("either --file or --project is required")
			}

			var outMu sync.Mutex
			if !jsonOut {
				styled := isStyledWriter(out)
				th := cliTheme(styled)
				if styled {
					printSectionHeader(out, th, i18n.T("cli.re.run.title"), req.Engine)
				}
				mgr.SetCallbacks(func(ev retools.JobLogEvent) {
					outMu.Lock()
					defer outMu.Unlock()
					switch ev.Stream {
					case "result":
						fmt.Fprintf(out, "[result] %s\n", ev.Message)
					case "stderr":
						fmt.Fprintf(out, "[stderr] %s\n", ev.Message)
					case "system":
						fmt.Fprintf(out, "[system] %s\n", ev.Message)
					default:
						fmt.Fprintf(out, "%s\n", ev.Message)
					}
				}, nil)
			}

			if _, err := mgr.StartJob(req); err != nil {
				return err
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			state, waitErr := mgr.WaitJob(ctx)
			if waitErr != nil {
				_ = mgr.CancelJob()
				return waitErr
			}

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(state); err != nil {
					return err
				}
			} else if len(state.Results) > 0 {
				outMu.Lock()
				fmt.Fprintf(out, "\nStructured [CAP_RE] Results (%d):\n", len(state.Results))
				for i, res := range state.Results {
					payloadJSON, _ := json.Marshal(res.Payload)
					fmt.Fprintf(out, "  %d. [%s] %s (%s)\n", i+1, res.Kind, res.Summary, string(payloadJSON))
				}
				outMu.Unlock()
			}

			if state.Status != retools.StatusDone {
				return fmt.Errorf("RE job %s (exit %d): %s", state.Status, state.ExitCode, state.Error)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&engine, "engine", "e", "", "target engine: unidbg, qiling, angr, radare2")
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "path to harness source file (.java, .py, .r2)")
	cmd.Flags().StringVarP(&projectID, "project", "p", "", "RE project ID to run")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "target binary / .so path (CAP_RE_BINARY)")
	cmd.Flags().StringVar(&apkPath, "apk", "", "target APK path (CAP_RE_APK)")
	cmd.Flags().StringVar(&rootfs, "rootfs", "", "Qiling rootfs directory (CAP_RE_ROOTFS)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 0, "execution timeout in seconds (0 = unlimited)")
	cmd.Flags().StringArrayVar(&extraArgs, "arg", nil, "argument passed to target harness (repeatable)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output final JobState JSON")
	cmd.Flags().StringVar(&tcOverride.R2Path, "r2", "", "override radare2 binary path")
	cmd.Flags().StringVar(&tcOverride.JavaPath, "java", "", "override java binary path")
	cmd.Flags().StringVar(&tcOverride.MvnPath, "mvn", "", "override maven binary path")
	cmd.Flags().StringVar(&tcOverride.UnidbgDir, "unidbg-dir", "", "override Unidbg directory or JARs")
	cmd.Flags().StringVar(&tcOverride.PythonPath, "python", "", "override default python3 binary path")
	cmd.Flags().StringVar(&tcOverride.QilingPythonPath, "qiling-python", "", "override python3 path for Qiling")
	cmd.Flags().StringVar(&tcOverride.AngrPythonPath, "angr-python", "", "override python3 path for angr")
	return cmd
}

func newREAnalyzeCmd() *cobra.Command {
	var (
		r2Path   string
		funcName string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "analyze <file>",
		Short: "Analyze an ELF or Mach-O binary (functions, exports, imports, strings, mitigations)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			binPath := args[0]
			effectiveR2 := strings.TrimSpace(r2Path)
			if effectiveR2 == "" {
				effectiveR2 = loadSavedREToolchainConfig().R2Path
			}

			if strings.TrimSpace(funcName) != "" {
				detail, err := retools.InspectFunction(context.Background(), binPath, funcName, effectiveR2)
				if err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(detail)
				}
				fmt.Fprintf(out, "Function: %s (%s, size=%d, engine=%s)\n", detail.Name, detail.Addr, detail.Size, detail.Engine)
				if detail.Disasm != "" {
					fmt.Fprintf(out, "\n--- Disassembly ---\n%s\n", detail.Disasm)
				}
				if detail.PseudoC != "" {
					fmt.Fprintf(out, "\n--- Pseudo-C (%s) ---\n%s\n", detail.PseudoCEngine, detail.PseudoC)
				}
				return nil
			}

			res, err := retools.AnalyzeBinary(context.Background(), binPath, effectiveR2)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.re.analyze.title"), res.FileName)
			}
			fmt.Fprintf(out, "File:        %s (%d bytes)\n", res.FileName, res.FileSize)
			fmt.Fprintf(out, "Format/Arch: %s / %s (%d-bit %s) · engine=%s\n", res.Format, res.Arch, res.Bits, res.Endian, res.Engine)
			fmt.Fprintf(out, "Mitigations: PIE=%v NX=%v Canary=%v RELRO=%s Stripped=%v\n",
				res.Mitigations.PIE, res.Mitigations.NX, res.Mitigations.Canary, res.Mitigations.RELRO, res.Mitigations.Stripped)
			fmt.Fprintf(out, "Counts:      functions=%d exports=%d imports=%d strings=%d xrefs=%d\n",
				len(res.Functions), len(res.Exports), len(res.Imports), len(res.Strings), len(res.XRefs))
			if len(res.Exports) > 0 {
				fmt.Fprintln(out, "\nTop Exports:")
				limit := min(len(res.Exports), 15)
				for _, sym := range res.Exports[:limit] {
					tag := ""
					if sym.IsJNI {
						tag = " [JNI]"
					}
					fmt.Fprintf(out, "  %-14s %s%s\n", sym.Addr, sym.Name, tag)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&r2Path, "r2", "", "custom radare2 binary path")
	cmd.Flags().StringVar(&funcName, "func", "", "inspect a specific function by name or hex address")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newRER2Cmd() *cobra.Command {
	var (
		r2Path  string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "r2 <file> <cmd>",
		Short: "Run a sanitized read-only radare2 command on a binary",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			effectiveR2 := strings.TrimSpace(r2Path)
			if effectiveR2 == "" {
				effectiveR2 = loadSavedREToolchainConfig().R2Path
			}
			res, err := retools.RunR2Command(context.Background(), args[0], args[1], effectiveR2)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			fmt.Fprint(out, res.Output)
			if !strings.HasSuffix(res.Output, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&r2Path, "r2", "", "custom radare2 binary path")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newREProjectsCmd() *cobra.Command {
	var (
		engine  string
		showID  string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "projects",
		Short: "List built-in & saved RE projects or print project code",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			store, err := retools.NewProjectStore(filepath.Join(config.DefaultDir(), "re-projects"))
			if err != nil {
				return err
			}
			if showID != "" {
				proj, ok := store.Get(showID)
				if !ok {
					return fmt.Errorf("RE project %q not found", showID)
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(proj)
				}
				fmt.Fprint(out, proj.Code)
				if !strings.HasSuffix(proj.Code, "\n") {
					fmt.Fprintln(out)
				}
				return nil
			}

			projects := store.ListByEngine(engine)
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(projects)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.re.projects.title"), fmt.Sprintf("%d", len(projects)))
			}
			fmt.Fprintf(out, "%-32s %-10s %s\n", "ID", "ENGINE", "NAME")
			for _, p := range projects {
				fmt.Fprintf(out, "%-32s %-10s %s\n", tui.Truncate(p.ID, 32), p.Engine, p.Name)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&engine, "engine", "e", "", "filter by engine: unidbg, qiling, angr, radare2")
	cmd.Flags().StringVar(&showID, "show", "", "print source code of the specified project ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newREGenCmd() *cobra.Command {
	var (
		engine  string
		opts    retools.GenerateOptions
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Synthesize a Unidbg, Qiling, angr, or radare2 harness",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			harness, err := retools.GenerateFromTrace(nil, engine, opts)
			if err != nil {
				return err
			}
			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(harness.Code), 0o644); err != nil {
					return fmt.Errorf("write harness %s: %w", outFile, err)
				}
				fmt.Fprintf(out, "Saved %s harness (%s) to %s\n", harness.Engine, harness.FileName, outFile)
				return nil
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(harness)
			}
			fmt.Fprint(out, harness.Code)
			if !strings.HasSuffix(harness.Code, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&engine, "engine", "e", retools.EngineUnidbg, "target engine: unidbg, qiling, angr, radare2")
	cmd.Flags().StringVar(&opts.PackageName, "pkg", "", "Android package name")
	cmd.Flags().StringVar(&opts.APKPath, "apk", "", "path to target APK file")
	cmd.Flags().StringVar(&opts.BinaryPath, "binary", "", "path to target binary / .so file")
	cmd.Flags().StringVar(&opts.SOFile, "so", "", "target shared library name or path")
	cmd.Flags().StringVar(&opts.TargetClass, "class", "", "Java class path (e.g. com/acme/Signer)")
	cmd.Flags().StringVar(&opts.TargetMethod, "method", "", "Java native method name")
	cmd.Flags().StringVar(&opts.TargetSymbol, "symbol", "", "native exported symbol name")
	cmd.Flags().StringVar(&opts.TargetAddr, "addr", "", "target function hex address")
	cmd.Flags().StringVar(&opts.FindAddr, "find", "", "angr target find hex address")
	cmd.Flags().StringVar(&opts.AvoidAddr, "avoid", "", "angr avoid hex address")
	cmd.Flags().StringVar(&opts.Arch, "arch", "", "target architecture: arm64, arm, x86_64, x86")
	cmd.Flags().StringVar(&opts.RootFS, "rootfs", "", "Qiling rootfs directory")
	cmd.Flags().BoolVar(&opts.HTTPServerMode, "http-server", false, "generate Unidbg embedded HTTP signer server")
	cmd.Flags().IntVar(&opts.HTTPPort, "port", 8899, "Unidbg HTTP signer port")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write generated harness to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output full GeneratedHarness JSON")
	return cmd
}
