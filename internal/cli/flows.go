package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/types"
)

// newFlowsCmd builds `cap flows`: list captured flows from the database,
// with optional filtering and a choice of table or JSON output.
func newFlowsCmd() *cobra.Command {
	var dbPath, host, method, tag, search, format string
	var limit int

	cmd := &cobra.Command{
		Use:   "flows",
		Short: "List captured flows",
		Long:  "List flows captured by `cap start`, optionally filtered by host, method, tag, or free-text search.",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			filter := types.FlowFilter{
				Host:   host,
				Method: method,
				Tag:    tag,
				Search: search,
				Limit:  limit,
			}

			flows, err := st.ListFlows(filter)
			if err != nil {
				return fmt.Errorf("list flows: %w", err)
			}

			switch format {
			case "json":
				return printFlowsJSON(flows)
			case "table", "":
				return printFlowsTable(flows)
			default:
				return fmt.Errorf("unknown --format %q (want table or json)", format)
			}
		},
	}

	cmd.Flags().StringVarP(&dbPath, "db", "d", "", `database path (default "~/.cap/flows.db")`)
	cmd.Flags().StringVar(&host, "host", "", "filter by host")
	cmd.Flags().StringVar(&method, "method", "", "filter by method")
	cmd.Flags().StringVar(&tag, "tag", "", "filter by tag")
	cmd.Flags().StringVarP(&search, "search", "s", "", "search URL and body")
	cmd.Flags().IntVarP(&limit, "limit", "n", 50, "max results")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table, json")

	return cmd
}

// printFlowsTable renders flows as a tab-aligned table: ID, METHOD, STATUS,
// HOST, PATH, LATENCY.
func printFlowsTable(flows []*types.Flow) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tMETHOD\tSTATUS\tHOST\tPATH\tLATENCY")
	for _, f := range flows {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%dms\n", f.ID, f.Method, f.Status, f.Host, f.Path, f.LatencyMs)
	}
	return w.Flush()
}

// printFlowsJSON renders flows as indented JSON.
func printFlowsJSON(flows []*types.Flow) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(flows)
}
