// Package cli wires cap's core modules (proxy, store, export, android) into
// a cobra-based command-line interface.
package cli

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds cap's root command, with all subcommands (start, flows,
// export, android) registered.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cap",
		Short: "Packet capture for reverse engineering",
		Long:  "MITM proxy with LLM-ready output, static analysis correlation, and multi-language code generation.",
		// Errors and usage are reported by main.go via the error Execute
		// returns, so cobra shouldn't also print them (which would otherwise
		// duplicate the message and dump a usage banner on every runtime
		// failure, not just flag-parsing mistakes).
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	root.AddCommand(
		newStartCmd(),
		newFlowsCmd(),
		newExportCmd(),
		newAndroidCmd(),
		newGUICmd(),
	)

	return root
}
