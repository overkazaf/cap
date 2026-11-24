// Package cli wires cap's core modules (proxy, store, export, android) into
// a cobra-based command-line interface.
package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/buildinfo"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/tui"
)

// NewRootCmd builds cap's root command, with all subcommands (start, tui,
// flows, export, android, unpin, gui) registered.
func NewRootCmd() *cobra.Command {
	var uiLang string

	root := &cobra.Command{
		Use:     "cap",
		Version: buildinfo.Version(),
		Short:   "Packet capture for reverse engineering",
		Long:    "MITM proxy with LLM-ready output, static analysis correlation, and multi-language code generation.",
		// Errors and usage are reported by main.go via the error Execute
		// returns, so cobra shouldn't also print them (which would otherwise
		// duplicate the message and dump a usage banner on every runtime
		// failure, not just flag-parsing mistakes).
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Check the root persistent flag specifically so subcommands like
			// `cap export --lang curl` (which shadow --lang locally for codegen)
			// are never treated as a UI language override.
			if rootFlag := cmd.Root().PersistentFlags().Lookup("lang"); rootFlag != nil && rootFlag.Changed {
				loc, ok := i18n.ParseLocale(uiLang)
				if !ok {
					return fmt.Errorf("%s", i18n.T("cli.err.invalid_lang", uiLang))
				}
				i18n.SetLang(string(loc))
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&uiLang, "lang", "", "UI language: en, zh (default: auto-detected from CAP_LANG/LANG)")

	root.AddCommand(
		newStartCmd(),
		newTUICmd(),
		newFlowsCmd(),
		newExportCmd(),
		newAndroidCmd(),
		newUnpinCmd(),
		newFridaCmd(),
		newRECmd(),
		newDeobfCmd(),
		newExecTraceCmd(),
		newGatewayCmd(),
		newGUICmd(),
	)

	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if rootFlag := root.PersistentFlags().Lookup("lang"); rootFlag != nil && rootFlag.Changed {
			if loc, ok := i18n.ParseLocale(uiLang); ok {
				i18n.SetLang(string(loc))
			}
		}
		if cmd == root {
			renderRootHelp(cmd.OutOrStdout(), root)
			return
		}
		defaultHelp(cmd, args)
	})

	return root
}

func renderRootHelp(w io.Writer, root *cobra.Command) {
	styled := isStyledWriter(w)
	th := cliTheme(styled)

	if styled {
		fmt.Fprintf(w, "%s  %s  %s\n",
			th.Pill(th.BrandFg, th.BrandBg, true, " CAP "),
			th.Bold(th.FgPrimary, i18n.T("cli.root.tagline")),
			th.Fg(th.FgMuted, "v"+root.Version),
		)
		fmt.Fprintln(w, th.Fg(th.FgSecondary, "  "+i18n.T("cli.root.long")))
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "cap v%s — %s\n", root.Version, i18n.T("cli.root.tagline"))
		fmt.Fprintln(w, i18n.T("cli.root.long"))
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, th.Bold(th.Accent, i18n.T("cli.root.usage")))
	fmt.Fprintf(w, "  %s %s\n\n", th.Bold(th.FgPrimary, "cap"), th.Fg(th.FgSecondary, "<command> [flags]"))

	byName := make(map[string]*cobra.Command)
	for _, c := range root.Commands() {
		if c.IsAvailableCommand() {
			byName[c.Name()] = c
		}
	}

	printGroup := func(title string, names []string) {
		fmt.Fprintln(w, th.Bold(th.Accent, title))
		for _, name := range names {
			c, ok := byName[name]
			if !ok {
				continue
			}
			delete(byName, name)
			fmt.Fprintf(w, "  %s  %s\n",
				th.Bold(th.FgPrimary, tui.PadRight(c.Name(), 11)),
				th.Fg(th.FgSecondary, c.Short),
			)
		}
		fmt.Fprintln(w)
	}

	printGroup(i18n.T("cli.root.group.capture"), []string{"start", "tui", "gui", "flows", "export"})
	printGroup(i18n.T("cli.root.group.device"), []string{"android", "frida", "unpin"})
	printGroup(i18n.T("cli.root.group.re"), []string{"re", "deobf", "exectrace", "gateway"})

	var extras []string
	for _, c := range root.Commands() {
		if _, ok := byName[c.Name()]; ok && c.IsAvailableCommand() {
			extras = append(extras, c.Name())
		}
	}
	if len(extras) > 0 {
		printGroup(i18n.T("cli.root.group.other"), extras)
	}

	fmt.Fprintln(w, th.Bold(th.Accent, i18n.T("cli.root.quickstart")))
	examples := [][2]string{
		{"cap start --tui", i18n.T("cli.root.ex.start_tui")},
		{"cap start -a 127.0.0.1:8080", i18n.T("cli.root.ex.start_stream")},
		{"cap tui", i18n.T("cli.root.ex.tui")},
		{"cap flows --method POST -n 20", i18n.T("cli.root.ex.flows")},
		{"cap export --flow f1 -l curl", i18n.T("cli.root.ex.export")},
		{"cap android connect", i18n.T("cli.root.ex.android")},
	}
	for _, ex := range examples {
		fmt.Fprintf(w, "  %s  %s\n",
			th.Fg(th.Info, tui.PadRight(ex[0], 31)),
			th.Fg(th.FgMuted, ex[1]),
		)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, th.Bold(th.Accent, i18n.T("cli.root.flags")))
	flags := strings.TrimRight(root.Flags().FlagUsages(), "\n")
	if flags != "" {
		fmt.Fprintln(w, flags)
	}
	fmt.Fprintf(w, "\n%s\n", th.Fg(th.FgMuted, i18n.T("cli.root.footer")))
	fmt.Fprintf(w, "%s\n", th.Dim(th.FgMuted, i18n.T("cli.root.copyright")))
}
