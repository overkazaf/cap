package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/export/agent"
	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
)

// newExportCmd builds `cap export`: render a captured flow as runnable code
// in a target language, or export flows as compact agent/LLM-friendly
// JSONL.
func newExportCmd() *cobra.Command {
	var dbPath, flowID, lang, format string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export flows as code or agent-friendly format",
		Long: "Export a captured flow as a runnable code snippet (curl/python/go/java/js),\n" +
			"or export flows as compact JSONL optimized for an LLM / coding agent.",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			out := cmd.OutOrStdout()
			switch format {
			case "agent":
				return runExportAgent(out, st, flowID)
			case "code", "":
				return runExportCode(out, st, flowID, lang)
			default:
				return fmt.Errorf("unknown --format %q (want code or agent)", format)
			}
		},
	}

	cmd.Flags().StringVarP(&dbPath, "db", "d", "", `database path (default "~/.cap/flows.db")`)
	cmd.Flags().StringVar(&flowID, "flow", "", "flow ID (required for code mode)")
	cmd.Flags().StringVarP(&lang, "lang", "l", "curl", "language: curl, python, go, java, js, all")
	cmd.Flags().StringVarP(&format, "format", "f", "code", "format: code, agent")

	return cmd
}

// runExportAgent implements `cap export --format agent`: the named flow (if
// --flow is set) or every stored flow is rendered as compact JSONL via
// agent.Format and written cleanly to out (always uncolored for piping).
func runExportAgent(out io.Writer, st store.Store, flowID string) error {
	var flows []*types.Flow

	if flowID != "" {
		flow, err := st.GetFlow(flowID)
		if err != nil {
			return fmt.Errorf("flow %s: %w", flowID, err)
		}
		flows = []*types.Flow{flow}
	} else {
		var err error
		flows, err = st.ListFlows(types.FlowFilter{})
		if err != nil {
			return fmt.Errorf("list flows: %w", err)
		}
	}

	data, err := agent.Format(flows, agent.FormatOptions{})
	if err != nil {
		return fmt.Errorf("format flows: %w", err)
	}

	_, err = out.Write(data)
	return err
}

// runExportCode implements `cap export --format code` (the default):
// --flow is required, and the referenced flow is rendered via
// codegen.Generate. Single-language output stays 100% raw runnable code so
// piping (e.g. `| sh` or `| pbcopy`) works seamlessly.
func runExportCode(out io.Writer, st store.Store, flowID, lang string) error {
	if flowID == "" {
		return fmt.Errorf("--flow is required for code export")
	}

	flow, err := st.GetFlow(flowID)
	if err != nil {
		return fmt.Errorf("flow %s: %w", flowID, err)
	}

	if lang == "all" {
		styled := isStyledWriter(out)
		th := cliTheme(styled)
		if styled {
			printSectionHeader(out, th, i18n.T("cli.export.title"), fmt.Sprintf("%s %s (%s)", flow.Method, flow.Path, flow.ID))
			fmt.Fprintln(out)
		}
		for _, l := range codegen.Languages() {
			code, err := codegen.Generate(flow, l)
			if err != nil {
				return fmt.Errorf("generate %s: %w", l, err)
			}
			if styled {
				fmt.Fprintf(out, "%s %s %s\n%s\n\n",
					th.Fg(th.BorderMuted, "───"),
					th.Bold(th.Accent, strings.ToUpper(l)),
					th.Fg(th.BorderMuted, strings.Repeat("─", 48)),
					strings.TrimRight(code, "\n"),
				)
			} else {
				fmt.Fprintf(out, "--- %s ---\n%s\n\n", strings.ToUpper(l), code)
			}
		}
		return nil
	}

	code, err := codegen.Generate(flow, lang)
	if err != nil {
		return fmt.Errorf("generate %s: %w", lang, err)
	}
	fmt.Fprint(out, code)
	return nil
}
