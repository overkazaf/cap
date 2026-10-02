package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/export/agent"
	"github.com/overkazaf/cap/internal/export/codegen"
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

			switch format {
			case "agent":
				return runExportAgent(st, flowID)
			case "code", "":
				return runExportCode(st, flowID, lang)
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
// agent.Format and written to stdout.
func runExportAgent(st store.Store, flowID string) error {
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

	out, err := agent.Format(flows, agent.FormatOptions{})
	if err != nil {
		return fmt.Errorf("format flows: %w", err)
	}

	_, err = os.Stdout.Write(out)
	return err
}

// runExportCode implements `cap export --format code` (the default):
// --flow is required, and the referenced flow is rendered via
// codegen.Generate. lang "all" prints every supported language, each under
// a "--- LANG ---" header.
func runExportCode(st store.Store, flowID, lang string) error {
	if flowID == "" {
		return fmt.Errorf("--flow is required for code export")
	}

	flow, err := st.GetFlow(flowID)
	if err != nil {
		return fmt.Errorf("flow %s: %w", flowID, err)
	}

	if lang == "all" {
		for _, l := range codegen.Languages() {
			out, err := codegen.Generate(flow, l)
			if err != nil {
				return fmt.Errorf("generate %s: %w", l, err)
			}
			fmt.Printf("--- %s ---\n%s\n\n", strings.ToUpper(l), out)
		}
		return nil
	}

	out, err := codegen.Generate(flow, lang)
	if err != nil {
		return fmt.Errorf("generate %s: %w", lang, err)
	}
	fmt.Print(out)
	return nil
}
