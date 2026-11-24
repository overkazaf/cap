package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/exectrace"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/tui"
)

func openExecTraceManager() (*exectrace.Manager, error) {
	return exectrace.NewManager(filepath.Join(config.DefaultDir(), "exec-traces"))
}

func newExecTraceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exectrace",
		Short: "Dynamic execution trace import, taint slicing, diffing, and export",
		Long: `Dynamic execution trace analysis engine (Unidbg, Frida Stalker, Qiling, Java/JNI, JSONL, Tenet):

  import   — Import and analyze a trace file (auto-detecting format & crypto patterns)
  list     — List stored trace sessions or inspect/delete one
  taint    — Run forward or backward register/memory taint propagation on a session
  diff     — ASLR-normalized differential comparison between two trace sessions
  collect  — Generate a ready-to-run trace collector script (stalker, java_call, unidbg, qiling)
  export   — Export a stored session to Tenet, JSONL, or Markdown report

Examples:
  cap exectrace import ./trace.log --name sign-run-1
  cap exectrace list --json
  cap exectrace taint --session <id> --direction forward --seq 1 --reg x0
  cap exectrace diff <sessionA> <sessionB>
  cap exectrace collect --kind stalker --module libsign.so --symbol JNI_OnLoad
  cap exectrace export <sessionID> --format tenet -o sign.tenet`,
	}

	cmd.AddCommand(
		newExecTraceImportCmd(),
		newExecTraceListCmd(),
		newExecTraceTaintCmd(),
		newExecTraceDiffCmd(),
		newExecTraceCollectCmd(),
		newExecTraceExportCmd(),
	)
	return cmd
}

func newExecTraceImportCmd() *cobra.Command {
	var (
		name    string
		format  string
		baseHex string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import and analyze a dynamic execution trace file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			filePath := args[0]
			raw, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("read trace file %s: %w", filePath, err)
			}
			base, err := parseCLIHexUint64(baseHex)
			if err != nil {
				return err
			}
			if strings.TrimSpace(name) == "" {
				name = strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
			}

			mgr, err := openExecTraceManager()
			if err != nil {
				return err
			}
			sess, err := mgr.ImportTrace(name, format, string(raw), base)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(sess)
			}

			fmt.Fprintf(out, "Imported session: %s (%s)\n", sess.ID, sess.Name)
			fmt.Fprintf(out, "Format/Arch:      %s / %s\n", sess.Format, sess.Arch)
			fmt.Fprintf(out, "Events:           total=%d insns=%d mem=%d calls=%d unique_pcs=%d\n",
				sess.TotalEvents, sess.InsnCount, sess.MemOpCount, sess.CallCount, sess.UniquePCs)
			if sess.Summary != nil {
				fmt.Fprintf(out, "Summary:          %s\n", sess.Summary.SummaryText)
				if len(sess.Summary.CryptoHits) > 0 {
					fmt.Fprintf(out, "Crypto hits:      %d\n", len(sess.Summary.CryptoHits))
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "session display name (defaults to file basename)")
	cmd.Flags().StringVar(&format, "format", string(exectrace.FormatAuto), "trace format: auto, unidbg, stalker, qiling, java_call, jsonl, tenet")
	cmd.Flags().StringVar(&baseHex, "base", "", "module base address in hex")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newExecTraceListCmd() *cobra.Command {
	var (
		showID   string
		deleteID string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored execution trace sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openExecTraceManager()
			if err != nil {
				return err
			}
			if deleteID != "" {
				if err := mgr.DeleteSession(deleteID); err != nil {
					return err
				}
				fmt.Fprintf(out, "Deleted trace session %s\n", deleteID)
				return nil
			}
			if showID != "" {
				sess, ok := mgr.GetSession(showID)
				if !ok {
					return fmt.Errorf("trace session %q not found", showID)
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(sess)
			}

			sessions := mgr.ListSessions()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(sessions)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.exectrace.list.title"), fmt.Sprintf("%d", len(sessions)))
			}
			if len(sessions) == 0 {
				fmt.Fprintln(out, "No execution trace sessions stored. Use 'cap exectrace import <file>' to add one.")
				return nil
			}
			fmt.Fprintf(out, "%-36s %-10s %-8s %-8s %s\n", "ID", "FORMAT", "ARCH", "EVENTS", "NAME")
			for _, s := range sessions {
				fmt.Fprintf(out, "%-36s %-10s %-8s %-8d %s\n",
					tui.Truncate(s.ID, 36), s.Format, s.Arch, s.TotalEvents, s.Name)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&showID, "show", "", "print full JSON for a single trace session ID")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete a stored trace session by ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newExecTraceTaintCmd() *cobra.Command {
	var (
		req     exectrace.TaintRequest
		memHex  string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "taint",
		Short: "Run forward or backward register/memory taint analysis on a trace session",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if strings.TrimSpace(memHex) != "" {
				addr, err := parseCLIHexUint64(memHex)
				if err != nil {
					return err
				}
				req.SeedMemAddr = addr
			}
			mgr, err := openExecTraceManager()
			if err != nil {
				return err
			}
			res, err := mgr.RunTaint(req)
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
				printSectionHeader(out, th, i18n.T("cli.exectrace.taint.title"), res.Direction)
			}
			fmt.Fprintf(out, "Direction: %s  Seed: %s  StartSeq: %d\n", res.Direction, res.Seed, res.StartSeq)
			fmt.Fprintf(out, "Summary:   %s\n", res.Summary)
			for _, st := range res.TaintedSteps {
				fmt.Fprintf(out, "  #%-6d 0x%x  %-8s %-24s  (%s)\n", st.Seq, st.Address, st.Mnemonic, st.Operands, st.Reason)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&req.SessionID, "session", "", "trace session ID")
	cmd.Flags().StringVar(&req.Direction, "direction", exectrace.TaintForward, "taint direction: forward or backward")
	cmd.Flags().IntVar(&req.StartSeq, "seq", 1, "starting event sequence number")
	cmd.Flags().StringVar(&req.SeedReg, "reg", "", "seed register name (e.g. x0, r0, rax)")
	cmd.Flags().StringVar(&memHex, "mem", "", "seed memory address in hex")
	cmd.Flags().StringVar(&req.SeedValueHex, "value-hex", "", "optional seed value hex pattern")
	cmd.Flags().IntVar(&req.MaxSteps, "max-steps", 500, "maximum propagation steps")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("session")
	return cmd
}

func newExecTraceDiffCmd() *cobra.Command {
	var (
		sessionA       string
		sessionB       string
		maxDivergences int
		jsonOut        bool
	)

	cmd := &cobra.Command{
		Use:   "diff [sessionA] [sessionB]",
		Short: "Compute an ASLR-normalized differential comparison between two trace sessions",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if len(args) >= 1 && sessionA == "" {
				sessionA = args[0]
			}
			if len(args) >= 2 && sessionB == "" {
				sessionB = args[1]
			}
			if strings.TrimSpace(sessionA) == "" || strings.TrimSpace(sessionB) == "" {
				return fmt.Errorf("two session IDs are required (positional <sessionA> <sessionB> or --a / --b)")
			}

			mgr, err := openExecTraceManager()
			if err != nil {
				return err
			}
			diff, err := mgr.DiffSessions(sessionA, sessionB, maxDivergences)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(diff)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.exectrace.diff.title"), "")
			}
			fmt.Fprintf(out, "Sessions:      %s (%d insns) vs %s (%d insns)\n",
				diff.SessionA, diff.TotalInsnsA, diff.SessionB, diff.TotalInsnsB)
			fmt.Fprintf(out, "Common Prefix: %d instructions\n", diff.CommonPrefixLen)
			fmt.Fprintf(out, "Summary:       %s\n", diff.Summary)
			if diff.FirstDivergence != nil {
				d := diff.FirstDivergence
				fmt.Fprintf(out, "First Div:     #%d vs #%d — %s\n", d.SeqA, d.SeqB, d.Reason)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionA, "a", "", "first trace session ID")
	cmd.Flags().StringVar(&sessionB, "b", "", "second trace session ID")
	cmd.Flags().IntVar(&maxDivergences, "max-divergences", 20, "maximum divergence points to collect")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newExecTraceCollectCmd() *cobra.Command {
	var (
		kind    string
		cfg     = exectrace.DefaultCollectorConfig()
		outFile string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Generate a ready-to-run execution trace collector script",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			gen := exectrace.GenerateCollector(kind, cfg)
			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(gen.Code), 0o644); err != nil {
					return fmt.Errorf("write collector %s: %w", outFile, err)
				}
				fmt.Fprintf(out, "Saved %s collector (%s) to %s\n", gen.Kind, gen.Filename, outFile)
				return nil
			}
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(gen)
			}
			fmt.Fprint(out, gen.Code)
			if !strings.HasSuffix(gen.Code, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "stalker", "collector kind: stalker, java_call, unidbg, qiling")
	cmd.Flags().StringVar(&cfg.TargetPackage, "pkg", "", "target Android package name")
	cmd.Flags().StringVar(&cfg.TargetModule, "module", cfg.TargetModule, "target native module (.so)")
	cmd.Flags().StringVar(&cfg.TargetSymbol, "symbol", cfg.TargetSymbol, "target exported symbol")
	cmd.Flags().StringVar(&cfg.TargetOffset, "offset", "", "target function hex offset")
	cmd.Flags().StringVar(&cfg.Arch, "arch", cfg.Arch, "architecture: arm64, arm, x86_64")
	cmd.Flags().StringVar(&cfg.ClassFilter, "class-filter", cfg.ClassFilter, "Java class filter pattern")
	cmd.Flags().StringVar(&cfg.MethodFilter, "method-filter", cfg.MethodFilter, "Java method filter pattern")
	cmd.Flags().IntVar(&cfg.MaxEvents, "max-events", cfg.MaxEvents, "maximum traced events")
	cmd.Flags().StringVar(&cfg.BinaryPath, "binary", "", "target binary path (for qiling)")
	cmd.Flags().StringVar(&cfg.APKPath, "apk", "", "target APK path (for unidbg)")
	cmd.Flags().StringVar(&cfg.RootFS, "rootfs", "", "Qiling rootfs directory")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write collector script to file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output GeneratedCollector JSON")
	return cmd
}

func newExecTraceExportCmd() *cobra.Command {
	var (
		sessionID string
		format    string
		outFile   string
	)

	cmd := &cobra.Command{
		Use:   "export [sessionID]",
		Short: "Export a stored execution trace session to Tenet, JSONL, or Markdown",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if len(args) == 1 && sessionID == "" {
				sessionID = args[0]
			}
			if strings.TrimSpace(sessionID) == "" {
				return fmt.Errorf("session ID is required")
			}

			mgr, err := openExecTraceManager()
			if err != nil {
				return err
			}
			exported, err := mgr.ExportTrace(sessionID, format)
			if err != nil {
				return err
			}
			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(exported), 0o644); err != nil {
					return fmt.Errorf("write exported trace %s: %w", outFile, err)
				}
				fmt.Fprintf(out, "Exported session %s (%s) to %s\n", sessionID, format, outFile)
				return nil
			}
			fmt.Fprint(out, exported)
			if !strings.HasSuffix(exported, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "trace session ID")
	cmd.Flags().StringVarP(&format, "format", "f", exectrace.ExportTenet, "export format: tenet, jsonl, markdown")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write export to file")
	return cmd
}
