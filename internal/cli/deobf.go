package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/deobf"
	"github.com/overkazaf/cap/internal/i18n"
)

func newDeobfCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deobf",
		Short: "Anti-obfuscation, anti-debug stealth, DEX unpacking, and VMP analysis",
		Long: `Android binary protection scanner and deobfuscation / VMP script workbench:

  scan       — Audit an APK or ELF .so for packers, OLLVM, VMP, and anti-debug checks
  stealth    — Synthesize a composable Frida Anti-Debug / Anti-Frida stealth script
  unpack     — Synthesize an in-memory Frida DEX unpacker script
  ollvm      — Synthesize an angr OLLVM CFF de-flattening & binary patching script
  vmp        — Synthesize a VMP tracer (Frida Stalker, RegisterNatives, or Unidbg)
  vmp-trace  — Analyze a raw VMP execution trace to identify dispatchers & handlers

Examples:
  cap deobf scan ./target.apk --json
  cap deobf stealth --pkg com.acme.app --patch-svc -o stealth.js
  cap deobf unpack --pkg com.acme.app
  cap deobf ollvm --so ./libsec.so --addr 0x1a20 --arch arm64
  cap deobf vmp --mode stalker --so libvmp.so --entry JNI_OnLoad
  cap deobf vmp-trace ./vmp.log --base 0x7000000000`,
	}

	cmd.AddCommand(
		newDeobfScanCmd(),
		newDeobfStealthCmd(),
		newDeobfUnpackCmd(),
		newDeobfOLLVMCmd(),
		newDeobfVMPCmd(),
		newDeobfVMPTraceCmd(),
	)
	return cmd
}

func scanProtectionPath(path string) (*deobf.ProtectionReport, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil, fmt.Errorf("target path is required")
	}
	if strings.HasSuffix(strings.ToLower(p), ".apk") {
		return deobf.ScanAPK(p)
	}
	return deobf.ScanELF(p)
}

func writeDeobfScriptOutput(cmd *cobra.Command, sc *deobf.GeneratedScript, outFile string, jsonOut bool) error {
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

func newDeobfScanCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "scan <apk|so>",
		Short: "Audit an APK or ELF .so for packers, obfuscation, VMP, and anti-debug",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			report, err := scanProtectionPath(args[0])
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
				printSectionHeader(out, th, i18n.T("cli.deobf.scan.title"), report.TargetKind)
			}
			fmt.Fprintf(out, "Target:     %s (%s)\n", report.TargetPath, report.TargetKind)
			fmt.Fprintf(out, "Hardening:  %s (risk score: %d/100)\n", report.HardeningLevel, report.RiskScore)
			fmt.Fprintf(out, "Summary:    %s\n", report.Summary)
			fmt.Fprintf(out, "Findings:   packers=%d obfuscation=%d vmp=%d anti_debug=%d so_audits=%d\n",
				len(report.Packers), len(report.Obfuscation), len(report.VMPIndicators), len(report.AntiDebugFindings), len(report.SOAudits))
			if len(report.Packers) > 0 {
				fmt.Fprintln(out, "\nPackers:")
				for _, p := range report.Packers {
					fmt.Fprintf(out, "  - %s (%s, confidence=%.0f%%)\n", p.Name, p.Vendor, p.Confidence*100)
				}
			}
			if len(report.Obfuscation) > 0 {
				fmt.Fprintln(out, "\nObfuscation:")
				for _, o := range report.Obfuscation {
					fmt.Fprintf(out, "  - [%s] %s (confidence=%.0f%%)\n", o.Kind, o.Module, o.Confidence*100)
				}
			}
			if len(report.VMPIndicators) > 0 {
				fmt.Fprintln(out, "\nVMP Indicators:")
				for _, v := range report.VMPIndicators {
					fmt.Fprintf(out, "  - [%s] %s (confidence=%.0f%%)\n", v.Kind, v.Module, v.Confidence*100)
				}
			}
			if len(report.AntiDebugFindings) > 0 {
				fmt.Fprintln(out, "\nAnti-Debug / Anti-Frida:")
				for _, ad := range report.AntiDebugFindings {
					fmt.Fprintf(out, "  - [%s/%s] %s: %s\n", ad.Severity, ad.Kind, ad.Module, ad.SymbolOrPattern)
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newDeobfStealthCmd() *cobra.Command {
	var (
		opts     = deobf.DefaultStealthOptions()
		scanPath string
		outFile  string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "stealth",
		Short: "Generate a composable Frida Anti-Debug / Anti-Frida stealth script",
		RunE: func(cmd *cobra.Command, args []string) error {
			var report *deobf.ProtectionReport
			if strings.TrimSpace(scanPath) != "" {
				var err error
				report, err = scanProtectionPath(scanPath)
				if err != nil {
					return err
				}
				derived := deobf.StealthOptionsFromReport(report)
				if opts.TargetPackage != "" {
					derived.TargetPackage = opts.TargetPackage
				}
				if opts.TargetSO != "" {
					derived.TargetSO = opts.TargetSO
				}
				derived.DryRunSVCPatch = opts.DryRunSVCPatch
				if cmd.Flags().Changed("procfs") {
					derived.BypassTracerPidAndProcFS = opts.BypassTracerPidAndProcFS
				}
				if cmd.Flags().Changed("ptrace") {
					derived.BypassPtraceAndSignals = opts.BypassPtraceAndSignals
				}
				if cmd.Flags().Changed("patch-svc") {
					derived.PatchInlineSVC = opts.PatchInlineSVC
				}
				if cmd.Flags().Changed("timing") {
					derived.BypassTimingAndInotify = opts.BypassTimingAndInotify
				}
				if cmd.Flags().Changed("java") {
					derived.BypassJavaDebugChecks = opts.BypassJavaDebugChecks
				}
				opts = derived
			}
			sc := deobf.GenerateStealthScript(opts, report)
			return writeDeobfScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&opts.TargetPackage, "pkg", "", "target Android package name")
	cmd.Flags().StringVar(&opts.TargetSO, "so", "", "target native library name (e.g. libsec.so)")
	cmd.Flags().StringVar(&scanPath, "scan", "", "optional APK/.so to scan and auto-tailor stealth modules")
	cmd.Flags().BoolVar(&opts.BypassTracerPidAndProcFS, "procfs", true, "bypass TracerPid, /proc/self/maps, and Frida string checks")
	cmd.Flags().BoolVar(&opts.BypassPtraceAndSignals, "ptrace", true, "bypass ptrace anti-debug and kill/abort signals")
	cmd.Flags().BoolVar(&opts.PatchInlineSVC, "patch-svc", false, "patch inline ARM64 SVC syscalls in target SO")
	cmd.Flags().BoolVar(&opts.DryRunSVCPatch, "dry-run-svc", false, "log inline SVC sites without patching bytes")
	cmd.Flags().BoolVar(&opts.BypassTimingAndInotify, "timing", true, "bypass timing and inotify anti-debug checks")
	cmd.Flags().BoolVar(&opts.BypassJavaDebugChecks, "java", true, "bypass Java Debug.isDebuggerConnected and root checks")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedScript JSON")
	return cmd
}

func newDeobfUnpackCmd() *cobra.Command {
	var (
		pkg     string
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "unpack",
		Short: "Generate a Frida in-memory DEX unpacker script",
		RunE: func(cmd *cobra.Command, args []string) error {
			sc := deobf.GenerateDexUnpackerScript(pkg)
			return writeDeobfScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&pkg, "pkg", "", "target Android package name")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedScript JSON")
	return cmd
}

func newDeobfOLLVMCmd() *cobra.Command {
	var (
		soPath   string
		funcAddr string
		arch     string
		outFile  string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "ollvm",
		Short: "Generate an angr OLLVM CFF de-flattening and binary patching script",
		RunE: func(cmd *cobra.Command, args []string) error {
			sc := deobf.GenerateOLLVMDeflattenScript(soPath, funcAddr, arch)
			return writeDeobfScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&soPath, "so", "./target.so", "path to OLLVM-obfuscated ELF .so")
	cmd.Flags().StringVar(&funcAddr, "addr", "0x1000", "hex address of flattened function")
	cmd.Flags().StringVar(&arch, "arch", "arm64", "binary architecture: arm64, arm, x86_64, x86")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedScript JSON")
	return cmd
}

func newDeobfVMPCmd() *cobra.Command {
	var (
		mode       string
		soName     string
		entry      string
		maxEvents  int
		pkg        string
		apkPath    string
		className  string
		methodName string
		outFile    string
		jsonOut    bool
	)

	cmd := &cobra.Command{
		Use:   "vmp",
		Short: "Generate a VMP tracing script (stalker, jni, or unidbg)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var sc *deobf.GeneratedScript
			switch strings.ToLower(strings.TrimSpace(mode)) {
			case "", "stalker", "frida":
				sc = deobf.GenerateVMPStalkerScript(soName, entry, maxEvents)
			case "jni", "register-natives", "registernatives":
				sc = deobf.GenerateVMPRegisterNativesScript(pkg)
			case "unidbg":
				sc = deobf.GenerateUnidbgVMPTraceScript(apkPath, soName, className, methodName)
			default:
				return fmt.Errorf("unsupported VMP script mode %q (expected stalker, jni, or unidbg)", mode)
			}
			return writeDeobfScriptOutput(cmd, sc, outFile, jsonOut)
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "stalker", "generator mode: stalker, jni, unidbg")
	cmd.Flags().StringVar(&soName, "so", "libvmp.so", "target native library name")
	cmd.Flags().StringVar(&entry, "entry", "JNI_OnLoad", "entry symbol or hex offset (for stalker mode)")
	cmd.Flags().IntVar(&maxEvents, "max-events", 50000, "maximum traced events (for stalker mode)")
	cmd.Flags().StringVar(&pkg, "pkg", "", "target package filter (for jni mode)")
	cmd.Flags().StringVar(&apkPath, "apk", "", "target APK path (for unidbg mode)")
	cmd.Flags().StringVar(&className, "class", "", "Java class path (for unidbg mode)")
	cmd.Flags().StringVar(&methodName, "method", "", "Java method name (for unidbg mode)")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedScript JSON")
	return cmd
}

func newDeobfVMPTraceCmd() *cobra.Command {
	var (
		baseHex string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "vmp-trace <file>",
		Short: "Analyze a raw VMP execution trace for dispatchers, handlers, and external calls",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			var raw []byte
			var err error
			if args[0] == "-" {
				raw, err = io.ReadAll(cmd.InOrStdin())
			} else {
				raw, err = os.ReadFile(args[0])
			}
			if err != nil {
				return fmt.Errorf("read VMP trace %s: %w", args[0], err)
			}
			base, err := parseCLIHexUint64(baseHex)
			if err != nil {
				return err
			}

			analysis := deobf.AnalyzeVMPTrace(string(raw), base)
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(analysis)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.deobf.vmp.title"), "")
			}
			fmt.Fprintf(out, "Instructions: %d  Unique PCs: %d\n", analysis.TotalInstructions, analysis.UniquePCs)
			fmt.Fprintf(out, "Summary:      %s\n", analysis.Summary)
			if len(analysis.DispatcherCandidates) > 0 {
				fmt.Fprintln(out, "\nDispatcher Candidates:")
				for _, d := range analysis.DispatcherCandidates {
					fmt.Fprintf(out, "  - %s (hits=%d, fanout=%d, share=%.1f%%)\n", d.Address, d.Hits, d.UniqueTargets, d.SharePercent)
				}
			}
			if len(analysis.HandlerEntries) > 0 {
				fmt.Fprintln(out, "\nTop Handler Entries:")
				limit := min(len(analysis.HandlerEntries), 10)
				for _, h := range analysis.HandlerEntries[:limit] {
					fmt.Fprintf(out, "  - %s (hits=%d, share=%.1f%%)\n", h.Address, h.Hits, h.SharePercent)
				}
			}
			if len(analysis.ExternalCalls) > 0 {
				fmt.Fprintln(out, "\nExternal Calls:")
				for _, ec := range analysis.ExternalCalls {
					fmt.Fprintf(out, "  - [%s] %s (count=%d)\n", ec.Category, ec.Target, ec.Count)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&baseHex, "base", "", "module base address in hex (e.g. 0x7000000000)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func parseCLIHexUint64(raw string) (uint64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, nil
	}
	clean := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if clean == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(clean, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid hex address %q: %w", raw, err)
	}
	return v, nil
}
