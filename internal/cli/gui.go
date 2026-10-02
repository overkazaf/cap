package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/overkazaf/cap/internal/gui"
)

func newGUICmd() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "gui",
		Short: "Launch the desktop GUI",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			gui.Run(st)
			return nil
		},
	}
	cmd.Flags().StringVarP(&dbPath, "db", "d", "", "database path (default: ~/.cap/flows.db)")
	return cmd
}
