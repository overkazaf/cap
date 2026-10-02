package cli

import (
	"embed"
	"fmt"
	"io/fs"

	"github.com/spf13/cobra"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"

	"github.com/overkazaf/cap/internal/wailsgui"
)

var frontendAssets embed.FS

func SetFrontendAssets(assets embed.FS) {
	frontendAssets = assets
}

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

			app := wailsgui.NewApp(st)

			stripped, err := fs.Sub(frontendAssets, "frontend/dist")
			if err != nil {
				return fmt.Errorf("assets: %w", err)
			}

			err = wails.Run(&options.App{
				Title:            "cap",
				Width:            1400,
				Height:           900,
				MinWidth:         800,
				MinHeight:        600,
				DisableResize:    false,
				Fullscreen:       false,
				WindowStartState: options.Normal,
				AssetServer: &assetserver.Options{
					Assets: stripped,
				},
				OnStartup: app.Startup,
				Bind: []interface{}{
					app,
				},
				Mac: &mac.Options{
					TitleBar:             mac.TitleBarDefault(),
					WebviewIsTransparent: false,
					WindowIsTranslucent:  false,
				},
			})
			return err
		},
	}
	cmd.Flags().StringVarP(&dbPath, "db", "d", "", "database path (default: ~/.cap/flows.db)")
	return cmd
}
