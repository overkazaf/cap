package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/repro"
	"github.com/overkazaf/cap/internal/tui"
)

func newReproCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repro",
		Short: "Professional RE extensions (Unidbg auto-stub, JADX/JNI linker, IDA/Ghidra symbols, iOS)",
		Long: `Professional reverse-engineering workbench extensions:

  autostub      — Diagnose Unidbg exception logs and generate Java AbstractJni/IOResolver stubs
  env-snapshot  — Generate a Frida Android runtime environment snapshot script for Unidbg
  jadx          — Decompile an APK/DEX workspace, search/read classes, and link Java <-> JNI .so
  symbols       — Convert & export SymbolBundle JSON to IDAPython, Ghidra Python, or normalized JSON
  ios           — Statically inspect a Mach-O, Fat Mach-O, or .ipa archive
  ios-harness   — Generate a Unidbg DarwinEmulatorBuilder iOS Java harness
  ios-stealth   — Generate an authorized Frida iOS stealth diagnostic script

Examples:
  cap repro autostub --file ./unidbg.log --json
  cap repro env-snapshot --pkg com.acme.app -o snapshot.js
  cap repro jadx ./target.apk --link-so ./libsign.so --json
  cap repro symbols --in ./symbols.json --format ida -o apply_ida.py
  cap repro ios ./Target.ipa --json
  cap repro ios-harness --binary ./Target --objc-class Signer --objc-selector sign:
  cap repro ios-stealth --bundle-id com.acme.ios -o ios_stealth.js`,
	}

	cmd.AddCommand(
		newReproAutoStubCmd(),
		newReproEnvSnapshotCmd(),
		newReproJadxCmd(),
		newReproSymbolsCmd(),
		newReproIOSCmd(),
		newReproIOSHarnessCmd(),
		newReproIOSStealthCmd(),
	)
	return cmd
}

func writeReproScriptOutput(cmd *cobra.Command, sc *repro.GeneratedToolScript, outFile string, jsonOut bool) error {
	out := cmd.OutOrStdout()
	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(sc.Code), 0o644); err != nil {
			return fmt.Errorf("write script %s: %w", outFile, err)
		}
		fmt.Fprintf(out, "Saved %s (%s) to %s\n", sc.Name, sc.Engine, outFile)
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

func newReproAutoStubCmd() *cobra.Command {
	var (
		filePath  string
		fromStdin bool
		outFile   string
		jsonOut   bool
	)

	cmd := &cobra.Command{
		Use:   "autostub [file]",
		Short: "Diagnose Unidbg runtime logs and synthesize Java AbstractJni/IOResolver/SysProp stubs",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if filePath == "" && len(args) == 1 {
				filePath = args[0]
			}

			var (
				raw []byte
				err error
			)
			switch {
			case fromStdin || filePath == "-":
				raw, err = io.ReadAll(cmd.InOrStdin())
			case strings.TrimSpace(filePath) != "":
				raw, err = os.ReadFile(filePath)
			default:
				return fmt.Errorf("either --file <log> or --stdin is required")
			}
			if err != nil {
				return fmt.Errorf("read Unidbg log: %w", err)
			}

			diag := repro.AnalyzeUnidbgLog(string(raw))
			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(diag.CombinedJavaSnippet), 0o644); err != nil {
					return fmt.Errorf("write Java stub snippet %s: %w", outFile, err)
				}
				if !jsonOut {
					fmt.Fprintf(out, "Saved Unidbg Java stub snippet to %s\n", outFile)
					return nil
				}
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(diag)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.repro.autostub.title"), fmt.Sprintf("%d issue(s)", diag.TotalErrors))
			}
			fmt.Fprintf(out, "Summary:   %s\n", diag.Summary)
			fmt.Fprintf(out, "Detected:  jni=%d  classes=%d  files=%d  sys_props=%d  libraries=%d\n",
				len(diag.MissingJNI), len(diag.MissingClasses), len(diag.MissingFiles),
				len(diag.MissingSysProps), len(diag.MissingLibraries))
			if len(diag.MissingJNI) > 0 {
				fmt.Fprintln(out, "\nMissing JNI Callbacks:")
				for _, item := range diag.MissingJNI {
					smart := ""
					if item.SmartMatch {
						smart = " [smart]"
					}
					fmt.Fprintf(out, "  - [%s] %s (x%d)%s\n", item.Callback, item.Signature, item.Count, smart)
				}
			}
			if len(diag.MissingFiles) > 0 {
				fmt.Fprintln(out, "\nMissing Files:")
				for _, f := range diag.MissingFiles {
					fmt.Fprintf(out, "  - %s (x%d)\n", f.Path, f.Count)
				}
			}
			if len(diag.MissingSysProps) > 0 {
				fmt.Fprintln(out, "\nMissing System Properties:")
				for _, sp := range diag.MissingSysProps {
					fmt.Fprintf(out, "  - %s -> %q (x%d)\n", sp.Key, sp.SuggestedValue, sp.Count)
				}
			}
			if len(diag.MissingLibraries) > 0 {
				fmt.Fprintln(out, "\nMissing Libraries:")
				for _, lib := range diag.MissingLibraries {
					fmt.Fprintf(out, "  - %s (x%d)\n", lib.Name, lib.Count)
				}
			}
			if strings.TrimSpace(diag.CombinedJavaSnippet) != "" {
				fmt.Fprintf(out, "\n--- Generated Java Stub ---\n%s\n", strings.TrimRight(diag.CombinedJavaSnippet, "\n"))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&filePath, "file", "f", "", "path to Unidbg stderr/stdout log file (or - for stdin)")
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read Unidbg log from stdin")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write combined Java stub snippet to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output UnidbgStubDiagnosis JSON")
	return cmd
}

func newReproEnvSnapshotCmd() *cobra.Command {
	var (
		pkg     string
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "env-snapshot",
		Short: "Generate a Frida Android runtime environment snapshot script for Unidbg",
		RunE: func(cmd *cobra.Command, args []string) error {
			sc := repro.GenerateFridaEnvSnapshotScript(pkg)
			return writeReproScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&pkg, "pkg", "", "target Android package name")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write generated Frida JS script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedToolScript JSON")
	return cmd
}

func newReproJadxCmd() *cobra.Command {
	var (
		jadxPath        string
		maxClasses      int
		limit           int
		filter          string
		searchQuery     string
		className       string
		linkSO          string
		registerNatives string
		detectOnly      bool
		jsonOut         bool
	)

	cmd := &cobra.Command{
		Use:   "jadx [apk]",
		Short: "Decompile an APK/DEX workspace, browse/search Java classes, and link Java <-> JNI",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if detectOnly {
				info := repro.DetectJadx(jadxPath)
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(info)
				}
				fmt.Fprintf(out, "available=%v  path=%s  version=%s  issue=%s\n",
					info.Available, info.Path, info.Version, info.Issue)
				return nil
			}
			if len(args) != 1 {
				return fmt.Errorf("APK or DEX path argument is required (or pass --detect)")
			}

			cacheDir := filepath.Join(config.DefaultDir(), "jadx-cache")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			ws, err := repro.DecompileAPK(ctx, args[0], jadxPath, cacheDir, maxClasses)
			if err != nil {
				return err
			}

			// Mode 1: Java <-> JNI Cross-Link
			if strings.TrimSpace(linkSO) != "" || strings.TrimSpace(registerNatives) != "" {
				regJSON := strings.TrimSpace(registerNatives)
				if regJSON != "" && !strings.HasPrefix(regJSON, "[") && !strings.HasPrefix(regJSON, "{") {
					raw, readErr := os.ReadFile(regJSON)
					if readErr != nil {
						return fmt.Errorf("read --register-natives %s: %w", regJSON, readErr)
					}
					regJSON = string(raw)
				}
				report, linkErr := repro.LinkJavaToNative(ws.WorkspaceDir, linkSO, regJSON)
				if linkErr != nil {
					return linkErr
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(report)
				}
				styled := isStyledWriter(out)
				th := cliTheme(styled)
				if styled {
					printSectionHeader(out, th, i18n.T("cli.repro.jadx.title"), "Java <-> JNI")
				}
				fmt.Fprintf(out, "Summary:  %s\n", report.Summary)
				fmt.Fprintf(out, "Totals:   native=%d  static=%d  dynamic=%d  unresolved=%d\n",
					report.TotalNativeMethods, report.StaticCount, report.DynamicCount, report.UnresolvedCount)
				if len(report.Bindings) > 0 {
					fmt.Fprintf(out, "\n%-16s %-14s %-36s %s\n", "KIND", "ADDR", "JAVA METHOD", "NATIVE SYMBOL")
					for _, b := range report.Bindings {
						fmt.Fprintf(out, "%-16s %-14s %-36s %s\n",
							b.BindingKind, b.NativeAddr,
							tui.Truncate(b.JavaClass+"."+b.JavaMethod, 36), b.NativeSymbol)
					}
				}
				return nil
			}

			// Mode 2: Read single class source
			if strings.TrimSpace(className) != "" {
				src, srcErr := repro.ReadClassSource(ws.WorkspaceDir, className)
				if srcErr != nil {
					return srcErr
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(src)
				}
				fmt.Fprint(out, src.Source)
				if !strings.HasSuffix(src.Source, "\n") {
					fmt.Fprintln(out)
				}
				return nil
			}

			// Mode 3: Search source
			if strings.TrimSpace(searchQuery) != "" {
				hits, searchErr := repro.SearchSource(ws.WorkspaceDir, searchQuery, limit)
				if searchErr != nil {
					return searchErr
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(hits)
				}
				if len(hits) == 0 {
					fmt.Fprintf(out, "No matches for %q in %s\n", searchQuery, ws.WorkspaceDir)
					return nil
				}
				for _, h := range hits {
					fmt.Fprintf(out, "%s:%d:%d: %s\n", h.ClassName, h.Line, h.Column, h.Snippet)
				}
				return nil
			}

			// Mode 4: Workspace summary + class listing
			classes, listErr := repro.ListClasses(ws.WorkspaceDir, filter, limit)
			if listErr != nil {
				return listErr
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"workspace": ws,
					"classes":   classes,
				})
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.repro.jadx.title"), ws.Mode)
			}
			fmt.Fprintf(out, "Workspace: %s (mode=%s, cache_hit=%v, classes=%d, native_classes=%d)\n",
				ws.WorkspaceDir, ws.Mode, ws.CacheHit, ws.ClassCount, ws.NativeClassCount)
			if len(classes) > 0 {
				fmt.Fprintf(out, "\n%-52s %-7s %s\n", "CLASS", "NATIVE", "METHODS")
				for _, c := range classes {
					fmt.Fprintf(out, "%-52s %-7v %s\n",
						tui.Truncate(c.ClassName, 52), c.HasNative, strings.Join(c.NativeMethods, ", "))
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&jadxPath, "jadx", "", "custom jadx binary path")
	cmd.Flags().IntVar(&maxClasses, "max-classes", 0, "maximum classes to extract (0 = default)")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum classes or search hits to return")
	cmd.Flags().StringVar(&filter, "filter", "", "filter class names by substring")
	cmd.Flags().StringVar(&searchQuery, "search", "", "search decompiled Java source (case-insensitive)")
	cmd.Flags().StringVar(&className, "class", "", "print full decompiled source for a specific class")
	cmd.Flags().StringVar(&linkSO, "link-so", "", "ELF .so path to cross-link Java native methods against")
	cmd.Flags().StringVar(&registerNatives, "register-natives", "", "Frida RegisterNatives JSON file path or raw JSON")
	cmd.Flags().BoolVar(&detectOnly, "detect", false, "detect host jadx binary availability and exit")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newReproSymbolsCmd() *cobra.Command {
	var (
		inFile  string
		format  string
		outFile string
	)

	cmd := &cobra.Command{
		Use:   "symbols",
		Short: "Validate and export a SymbolBundle JSON to IDAPython, Ghidra Python, or JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if strings.TrimSpace(inFile) == "" {
				return fmt.Errorf("--in <symbol-bundle.json> is required")
			}

			var (
				raw []byte
				err error
			)
			if inFile == "-" {
				raw, err = io.ReadAll(cmd.InOrStdin())
			} else {
				raw, err = os.ReadFile(inFile)
			}
			if err != nil {
				return fmt.Errorf("read symbol bundle %s: %w", inFile, err)
			}

			bundle, err := repro.ImportSymbolBundleJSON(string(raw))
			if err != nil {
				return err
			}

			var rendered string
			switch strings.ToLower(strings.TrimSpace(format)) {
			case "ida":
				rendered = repro.ExportIDAPython(bundle)
			case "ghidra":
				rendered = repro.ExportGhidraPython(bundle)
			case "json":
				rendered, err = repro.ExportSymbolBundleJSON(bundle)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported --format %q (expected ida, ghidra, or json)", format)
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(rendered), 0o644); err != nil {
					return fmt.Errorf("write symbol output %s: %w", outFile, err)
				}
				fmt.Fprintf(out, "Exported %s symbol script to %s\n", strings.ToLower(strings.TrimSpace(format)), outFile)
				return nil
			}
			fmt.Fprint(out, rendered)
			if !strings.HasSuffix(rendered, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&inFile, "in", "i", "", "input SymbolBundle JSON file path (or - for stdin)")
	cmd.Flags().StringVarP(&format, "format", "f", "ida", "export format: ida, ghidra, or json")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write exported script or JSON to file")
	return cmd
}

func newReproIOSCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "ios <macho-or-ipa>",
		Short: "Statically inspect a Mach-O, Universal Fat Mach-O, or .ipa archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			report, err := repro.AnalyzeIOSBinary(args[0])
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
				printSectionHeader(out, th, i18n.T("cli.repro.ios.title"), report.FileName)
			}
			fmt.Fprintf(out, "File:        %s (%s, %d bytes)\n", report.FileName, report.FileKind, report.FileSize)
			fmt.Fprintf(out, "Mitigations: PIE=%v  NX=%v  ARC=%v  Canary=%v  FairPlayEncrypted=%v (cryptid=%d)\n",
				report.PIE, report.NX, report.ARC, report.StackCanary, report.FairPlayEncrypted, report.CryptID)
			if report.InfoPlist != nil {
				fmt.Fprintf(out, "Bundle:      %s (%s v%s, minOS=%s, ATS_arbitrary=%v)\n",
					report.InfoPlist.BundleID, report.InfoPlist.DisplayName,
					report.InfoPlist.Version, report.InfoPlist.MinimumOSVersion,
					report.InfoPlist.ATSAllowsArbitraryLoads)
			}
			if len(report.Architectures) > 0 {
				var archs []string
				for _, a := range report.Architectures {
					archs = append(archs, fmt.Sprintf("%s(%d-bit)", a.Arch, a.Bits))
				}
				fmt.Fprintf(out, "Slices:      %s\n", strings.Join(archs, ", "))
			}
			fmt.Fprintf(out, "Counts:      dylibs=%d  frameworks=%d  objc_classes=%d  objc_selectors=%d  exports=%d\n",
				len(report.LinkedDylibs), len(report.Frameworks),
				len(report.ObjCClasses), len(report.ObjCSelectors), len(report.ExportedSymbols))
			fmt.Fprintf(out, "Summary:     %s\n", report.Summary)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output IOSBinaryReport JSON")
	return cmd
}

func newReproIOSHarnessCmd() *cobra.Command {
	var (
		opts    repro.UnidbgIOSOptions
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "ios-harness",
		Short: "Generate a Unidbg DarwinEmulatorBuilder iOS Java emulation harness",
		RunE: func(cmd *cobra.Command, args []string) error {
			sc := repro.GenerateUnidbgIOSHarness(opts)
			return writeReproScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&opts.ClassName, "class", "", "generated Java harness class name")
	cmd.Flags().StringVar(&opts.BundleID, "bundle-id", "", "iOS bundle identifier (e.g. com.acme.app)")
	cmd.Flags().StringVar(&opts.BinaryPath, "binary", "", "path to target Mach-O binary")
	cmd.Flags().StringVar(&opts.IPAPath, "ipa", "", "path to target .ipa archive")
	cmd.Flags().StringVar(&opts.TargetSymbol, "symbol", "", "exported C symbol name to invoke")
	cmd.Flags().StringVar(&opts.ObjCClass, "objc-class", "", "Objective-C class name")
	cmd.Flags().StringVar(&opts.ObjCSelector, "objc-selector", "", "Objective-C selector name")
	cmd.Flags().StringVar(&opts.TargetOffset, "offset", "", "hex function offset inside Mach-O")
	cmd.Flags().StringArrayVar(&opts.Args, "arg", nil, "sample argument passed to target function (repeatable)")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write Java harness to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedToolScript JSON")
	return cmd
}

func newReproIOSStealthCmd() *cobra.Command {
	var (
		opts = repro.IOSStealthOptions{
			BypassPtrace:          true,
			BypassSysctl:          true,
			BypassGetppid:         true,
			BypassDyldChecks:      true,
			BypassJailbreakChecks: true,
		}
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "ios-stealth",
		Short: "Generate an authorized Frida iOS anti-debug and jailbreak-check diagnostic script",
		RunE: func(cmd *cobra.Command, args []string) error {
			sc := repro.GenerateIOSStealthScript(opts)
			return writeReproScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&opts.BundleID, "bundle-id", "", "target iOS bundle identifier")
	cmd.Flags().StringVar(&opts.TargetBinary, "binary", "", "target main Mach-O image name")
	cmd.Flags().BoolVar(&opts.BypassPtrace, "ptrace", true, "hook PT_DENY_ATTACH (ptrace)")
	cmd.Flags().BoolVar(&opts.BypassSysctl, "sysctl", true, "clear P_TRACED in sysctl")
	cmd.Flags().BoolVar(&opts.BypassGetppid, "getppid", true, "normalize getppid() parent PID")
	cmd.Flags().BoolVar(&opts.BypassDyldChecks, "dyld", true, "filter diagnostic dylibs from dyld/dladdr")
	cmd.Flags().BoolVar(&opts.BypassJailbreakChecks, "jailbreak", true, "filter common jailbreak path and URL scheme checks")
	cmd.Flags().StringSliceVar(&opts.CustomHidePaths, "hide-path", nil, "additional path substrings to hide")
	cmd.Flags().StringSliceVar(&opts.CustomHideSchemes, "hide-scheme", nil, "additional URL schemes to hide")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write Frida JS script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedToolScript JSON")
	return cmd
}
