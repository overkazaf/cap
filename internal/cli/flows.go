package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/tui"
	"github.com/overkazaf/cap/internal/types"
)

// newFlowsCmd builds `cap flows`: list captured flows from the database,
// with optional filtering and a choice of table or JSON output.
func newFlowsCmd() *cobra.Command {
	var dbPath, host, method, tag, search, format string
	var limit int
	var asJSON bool

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

			out := cmd.OutOrStdout()
			effectiveFormat := format
			if asJSON {
				effectiveFormat = "json"
			}

			switch effectiveFormat {
			case "json":
				return writeFlowsJSON(out, flows)
			case "table", "":
				if isStyledWriter(out) {
					return writeFlowsStyledTable(out, flows, filter)
				}
				return writeFlowsPlainTable(out, flows)
			default:
				return fmt.Errorf("unknown --format %q (want table or json)", effectiveFormat)
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
	cmd.Flags().BoolVar(&asJSON, "json", false, "shorthand for --format json")

	return cmd
}

// writeFlowsPlainTable renders flows as a clean, uncolored tab-aligned table
// suitable for piping and shell parsing.
func writeFlowsPlainTable(out io.Writer, flows []*types.Flow) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tMETHOD\tSTATUS\tHOST\tPATH\tLATENCY")
	for _, f := range flows {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%dms\n", f.ID, f.Method, f.Status, f.Host, f.Path, f.LatencyMs)
	}
	return w.Flush()
}

// writeFlowsStyledTable renders a commercial-grade aligned ANSI table on TTYs.
func writeFlowsStyledTable(out io.Writer, flows []*types.Flow, filter types.FlowFilter) error {
	th := cliTheme(true)
	width := cliWidth(out)

	var filterSummary []string
	if filter.Method != "" {
		filterSummary = append(filterSummary, "method="+strings.ToUpper(filter.Method))
	}
	if filter.Host != "" {
		filterSummary = append(filterSummary, "host="+filter.Host)
	}
	if filter.Tag != "" {
		filterSummary = append(filterSummary, "tag="+filter.Tag)
	}
	if filter.Search != "" {
		filterSummary = append(filterSummary, "search="+filter.Search)
	}

	sub := i18n.T("cli.flows.count", len(flows))
	if len(filterSummary) > 0 {
		sub += " · " + strings.Join(filterSummary, " ")
	}
	printSectionHeader(out, th, i18n.T("cli.flows.title"), sub)

	if len(flows) == 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  "+th.Fg(th.FgMuted, i18n.T("cli.flows.empty")))
		fmt.Fprintln(out)
		printHint(out, th, i18n.T("cli.flows.empty_hint"))
		return nil
	}

	// Compute dynamic host and path column widths based on terminal width.
	idW, methodW, statusW, sizeW, latW := 6, 7, 4, 8, 7
	fixed := 2 + idW + 2 + methodW + 2 + statusW + 2 + sizeW + 2 + latW + 4
	rem := width - fixed
	if rem < 24 {
		rem = 24
	}
	hostW := min(max((rem*36)/100, 14), 30)
	pathW := max(rem-hostW-2, 12)

	hdr := fmt.Sprintf("  %s  %s  %s  %s  %s  %s  %s",
		tui.PadRight(i18n.T("cli.start.col.id"), idW),
		tui.PadRight(i18n.T("tui.col.method"), methodW),
		tui.PadRight(i18n.T("tui.col.status"), statusW),
		tui.PadRight(i18n.T("tui.col.host"), hostW),
		tui.PadRight(i18n.T("tui.col.path"), pathW),
		tui.PadLeft(i18n.T("tui.col.size"), sizeW),
		tui.PadLeft(i18n.T("tui.col.time"), latW),
	)
	fmt.Fprintln(out, th.Dim(th.FgMuted, hdr))

	for _, f := range flows {
		idStr := th.Fg(th.FgMuted, tui.PadRight(tui.Truncate(tui.SanitizeInline(f.ID), idW), idW))
		methodStr := th.Bold(th.MethodColor(f.Method), tui.PadRight(tui.Truncate(strings.ToUpper(f.Method), methodW), methodW))
		statusStr := th.Bold(th.StatusColor(f.Status), tui.PadRight(fmt.Sprintf("%d", f.Status), statusW))
		hostStr := th.Fg(th.FgSecondary, tui.PadRight(tui.Truncate(tui.SanitizeInline(f.Host), hostW), hostW))
		pathVal := f.Path
		if pathVal == "" {
			pathVal = "/"
		}
		pathStr := th.Fg(th.FgPrimary, tui.PadRight(tui.Truncate(tui.SanitizeInline(pathVal), pathW), pathW))
		sizeStr := th.Fg(th.FgMuted, tui.PadLeft(tui.FormatBytes(len(f.RespBody)), sizeW))

		latColor := th.FgMuted
		if f.LatencyMs >= 1000 {
			latColor = th.Danger
		} else if f.LatencyMs >= 400 {
			latColor = th.Warn
		}
		latStr := th.Fg(latColor, tui.PadLeft(tui.FormatLatency(f.LatencyMs), latW))

		fmt.Fprintf(out, "  %s  %s  %s  %s  %s  %s  %s\n",
			idStr, methodStr, statusStr, hostStr, pathStr, sizeStr, latStr)
	}

	fmt.Fprintln(out)
	printHint(out, th, i18n.T("cli.flows.tip", flows[0].ID))
	return nil
}

// writeFlowsJSON renders flows as indented JSON.
func writeFlowsJSON(out io.Writer, flows []*types.Flow) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(flows)
}
