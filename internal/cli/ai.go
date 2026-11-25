package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/overkazaf/cap/internal/ai"
	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/tui"
)

func openAIManager() (*ai.Manager, error) {
	return ai.NewManager(config.DefaultDir())
}

func newAICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "Multi-model AI assistant, diagnosis, and self-healing code fixes",
		Long: `Configure multi-model AI providers (OpenAI-compatible, Anthropic Claude,
Google Gemini, DeepSeek, Qwen/DashScope, local Ollama) and run AI-assisted
failure diagnosis and validated code patching:

  status    — Show active AI profile, auto-heal settings, and masked profile summary
  presets   — List built-in cloud and local LLM provider presets
  profiles  — List, add, activate, or delete configured AI model profiles
  test      — Probe connectivity to the active or specified AI profile
  diagnose  — Diagnose a failure from code, error message, and/or log file
  fix       — Diagnose and print unified diff (or apply validated patch with --apply)

Examples:
  cap ai status
  cap ai presets --json
  cap ai profiles --add --provider deepseek --api-key-env DEEPSEEK_API_KEY
  cap ai profiles --add "Local Ollama" --provider ollama --model qwen2.5-coder:14b
  cap ai profiles --activate <profile-id>
  cap ai test
  cap ai diagnose --scope qiling --file ./emulate.py --log-file ./run.log
  cap ai fix --scope frida --file ./hook.js --error "has more than one overload" --apply`,
	}

	cmd.AddCommand(
		newAIStatusCmd(),
		newAIPresetsCmd(),
		newAIProfilesCmd(),
		newAITestCmd(),
		newAIDiagnoseCmd(),
		newAIFixCmd(),
	)
	return cmd
}

func newAIStatusCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show AI provider configuration and auto-heal status",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openAIManager()
			if err != nil {
				return err
			}
			pub := mgr.GetPublicConfig()

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(pub)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.ai.status.title"), "")
			}

			activeLabel := "(none)"
			for _, p := range pub.Profiles {
				if p.ID == pub.ActiveProfileID {
					activeLabel = fmt.Sprintf("%s (%s · %s · %s)", p.Name, p.ID, p.Provider, p.Model)
					break
				}
			}
			fmt.Fprintf(out, "Active Profile:   %s\n", activeLabel)
			fmt.Fprintf(out, "Profiles:         %d\n", len(pub.Profiles))
			fmt.Fprintf(out, "Auto-Heal:        %v (max retries: %d)\n", pub.AutoHealEnabled, pub.MaxAutoRetries)
			fmt.Fprintf(out, "Redact Secrets:   %v\n", pub.RedactSecrets)
			fmt.Fprintf(out, "Config File:      %s\n", mgr.Store().Path())
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newAIPresetsCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "presets",
		Short: "List built-in AI model provider presets",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			presets := ai.ListProviderPresets()

			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(presets)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.ai.presets.title"), fmt.Sprintf("%d", len(presets)))
			}
			fmt.Fprintf(out, "%-11s %-18s %-14s %-24s %s\n", "ID", "NAME", "PROTOCOL", "DEFAULT MODEL", "BASE URL")
			for _, pr := range presets {
				fmt.Fprintf(out, "%-11s %-18s %-14s %-24s %s\n",
					pr.ID,
					tui.Truncate(pr.Name, 18),
					pr.Provider,
					tui.Truncate(pr.DefaultModel, 24),
					pr.BaseURL)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func findAIPresetByID(id string) (ai.ProviderPreset, bool) {
	needle := strings.ToLower(strings.TrimSpace(id))
	for _, pr := range ai.ListProviderPresets() {
		if strings.ToLower(pr.ID) == needle {
			return pr, true
		}
	}
	return ai.ProviderPreset{}, false
}

func newAIProfilesCmd() *cobra.Command {
	var (
		addName    string
		nameFlag   string
		idFlag     string
		provider   string
		baseURL    string
		model      string
		apiKey     string
		apiKeyEnv  string
		activateID string
		deleteID   string
		timeoutSec int
		maxTokens  int
		jsonOut    bool
	)

	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List, add, activate, or delete AI provider profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openAIManager()
			if err != nil {
				return err
			}

			if strings.TrimSpace(deleteID) != "" {
				if err := mgr.DeleteProfile(deleteID); err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]any{"deleted": deleteID})
				}
				fmt.Fprintf(out, "Deleted AI profile %s.\n", deleteID)
				return nil
			}

			if cmd.Flags().Changed("add") {
				resolvedName := strings.TrimSpace(nameFlag)
				if resolvedName == "" && addName != "" && addName != "__auto__" {
					resolvedName = strings.TrimSpace(addName)
				}
				if resolvedName == "" && len(args) > 0 {
					resolvedName = strings.TrimSpace(args[0])
				}

				effProvider := strings.TrimSpace(provider)
				effBaseURL := strings.TrimSpace(baseURL)
				effModel := strings.TrimSpace(model)

				// Support passing a preset ID (e.g. "openai", "deepseek", "qwen", "anthropic", "gemini", "ollama")
				// to --provider while honoring explicit --base-url / --model overrides.
				if pr, ok := findAIPresetByID(effProvider); ok {
					effProvider = pr.Provider
					if effBaseURL == "" {
						effBaseURL = pr.BaseURL
					}
					if effModel == "" {
						effModel = pr.DefaultModel
					}
					if resolvedName == "" {
						resolvedName = pr.Name
					}
				}

				effKey := strings.TrimSpace(apiKey)
				if envName := strings.TrimSpace(apiKeyEnv); envName != "" && effKey == "" {
					effKey = strings.TrimSpace(os.Getenv(envName))
					if effKey == "" {
						return fmt.Errorf("environment variable %q is not set or empty", envName)
					}
				}

				saved, err := mgr.UpsertProfile(ai.ProviderConfig{
					ID:         strings.TrimSpace(idFlag),
					Name:       resolvedName,
					Provider:   effProvider,
					BaseURL:    effBaseURL,
					APIKey:     effKey,
					Model:      effModel,
					MaxTokens:  maxTokens,
					TimeoutSec: timeoutSec,
					Enabled:    true,
				})
				if err != nil {
					return err
				}

				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(saved)
				}
				fmt.Fprintf(out, "Saved AI profile %s (%s · %s · %s · key=%s)\n",
					saved.ID, saved.Name, saved.Provider, saved.Model, saved.APIKeyPreview)
				return nil
			}

			if strings.TrimSpace(activateID) != "" {
				if err := mgr.SetActiveProfile(activateID); err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(mgr.GetPublicConfig())
				}
				fmt.Fprintf(out, "Activated AI profile %s.\n", activateID)
				return nil
			}

			pub := mgr.GetPublicConfig()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(pub.Profiles)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.ai.profiles.title"), fmt.Sprintf("%d", len(pub.Profiles)))
			}
			if len(pub.Profiles) == 0 {
				fmt.Fprintln(out, "No AI profiles configured. Run 'cap ai profiles --add --provider openai --api-key-env OPENAI_API_KEY' to add one.")
				return nil
			}
			fmt.Fprintf(out, "%-2s %-22s %-18s %-14s %-22s %s\n", "", "ID", "NAME", "PROVIDER", "MODEL", "API KEY")
			for _, p := range pub.Profiles {
				mark := " "
				if p.ID == pub.ActiveProfileID {
					mark = "*"
				}
				keyStatus := "(none)"
				if p.HasAPIKey {
					keyStatus = p.APIKeyPreview
				}
				fmt.Fprintf(out, "%-2s %-22s %-18s %-14s %-22s %s\n",
					mark,
					tui.Truncate(p.ID, 22),
					tui.Truncate(p.Name, 18),
					p.Provider,
					tui.Truncate(p.Model, 22),
					keyStatus)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addName, "add", "", "add a new AI profile (optional display name via --add=<name> or positional arg)")
	cmd.Flags().Lookup("add").NoOptDefVal = "__auto__"
	cmd.Flags().StringVar(&nameFlag, "name", "", "display name for --add")
	cmd.Flags().StringVar(&idFlag, "id", "", "optional explicit profile ID for --add")
	cmd.Flags().StringVar(&provider, "provider", "", "provider protocol or preset ID (openai_compat, anthropic, gemini, ollama, openai, deepseek, qwen)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "provider API base URL")
	cmd.Flags().StringVar(&model, "model", "", "model identifier")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "raw API key (stored locally with 0600 permissions)")
	cmd.Flags().StringVar(&apiKeyEnv, "api-key-env", "", "environment variable name containing the API key")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 0, "request timeout in seconds")
	cmd.Flags().IntVar(&maxTokens, "max-tokens", 0, "max completion tokens")
	cmd.Flags().StringVar(&activateID, "activate", "", "set active AI profile by ID")
	cmd.Flags().StringVar(&deleteID, "delete", "", "delete an AI profile by ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func newAITestCmd() *cobra.Command {
	var (
		profileID string
		jsonOut   bool
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test connectivity against the active or specified AI profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			mgr, err := openAIManager()
			if err != nil {
				return err
			}

			targetID := strings.TrimSpace(profileID)
			if targetID == "" {
				active, ok := mgr.Store().GetActiveProfile()
				if !ok {
					return fmt.Errorf("no active AI profile configured (add one with 'cap ai profiles --add' or specify --profile)")
				}
				targetID = active.ID
			}

			ctx, cancel := context.WithTimeout(cmdBaseContext(cmd), 30*time.Second)
			defer cancel()

			res := mgr.TestProfileByID(ctx, targetID)
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(res); encErr != nil {
					return encErr
				}
			} else {
				styled := isStyledWriter(out)
				th := cliTheme(styled)
				if styled {
					printSectionHeader(out, th, i18n.T("cli.ai.test.title"), targetID)
				}
				if res.OK {
					fmt.Fprintf(out, "OK (%dms) · %s / %s · reply=%q\n", res.LatencyMs, res.Provider, res.Model, res.Reply)
				} else {
					fmt.Fprintf(out, "FAILED (%dms) · %s / %s · error=%s\n", res.LatencyMs, res.Provider, res.Model, res.Error)
				}
			}

			if !res.OK {
				return fmt.Errorf("AI connection test failed: %s", res.Error)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profileID, "profile", "", "profile ID to test (defaults to active profile)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

type aiDiagCLIOpts struct {
	scope     string
	filePath  string
	errorText string
	logFile   string
	locale    string
	profileID string
	language  string
	jsonOut   bool
}

func inferLanguageAndScopeFromFile(filePath, explicitScope, explicitLang string) (scope, lang string) {
	lang = strings.TrimSpace(explicitLang)
	scope = strings.TrimSpace(explicitScope)

	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(filePath)))
	if lang == "" {
		switch ext {
		case ".py":
			lang = "python"
		case ".java":
			lang = "java"
		case ".js", ".mjs", ".cjs", ".ts":
			lang = "javascript"
		}
	}
	if scope == "" {
		switch ext {
		case ".java":
			scope = ai.ScopeUnidbg
		case ".js", ".mjs", ".cjs":
			scope = ai.ScopeFrida
		default:
			scope = ai.ScopeGeneral
		}
	}
	return ai.NormalizeScope(scope), lang
}

func buildDiagnoseRequestFromCLI(cmd *cobra.Command, opts aiDiagCLIOpts) (ai.DiagnoseRequest, []byte, os.FileMode, error) {
	var (
		origBytes []byte
		fileMode  os.FileMode = 0o644
		code      string
		logs      string
	)

	fp := strings.TrimSpace(opts.filePath)
	if fp != "" {
		fi, err := os.Stat(fp)
		if err != nil {
			return ai.DiagnoseRequest{}, nil, 0, fmt.Errorf("stat source file %s: %w", fp, err)
		}
		fileMode = fi.Mode().Perm()
		raw, err := os.ReadFile(fp)
		if err != nil {
			return ai.DiagnoseRequest{}, nil, 0, fmt.Errorf("read source file %s: %w", fp, err)
		}
		origBytes = raw
		code = string(raw)
	}

	lf := strings.TrimSpace(opts.logFile)
	if lf != "" {
		if lf == "-" {
			raw, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return ai.DiagnoseRequest{}, nil, 0, fmt.Errorf("read logs from stdin: %w", err)
			}
			logs = string(raw)
		} else {
			raw, err := os.ReadFile(lf)
			if err != nil {
				return ai.DiagnoseRequest{}, nil, 0, fmt.Errorf("read log file %s: %w", lf, err)
			}
			logs = string(raw)
		}
	}

	errText := strings.TrimSpace(opts.errorText)
	if strings.TrimSpace(code) == "" && errText == "" && strings.TrimSpace(logs) == "" {
		return ai.DiagnoseRequest{}, nil, 0, fmt.Errorf("at least one of --file, --error, or --log-file is required")
	}

	scope, lang := inferLanguageAndScopeFromFile(fp, opts.scope, opts.language)
	locale := strings.TrimSpace(opts.locale)
	if locale == "" {
		locale = string(i18n.Lang())
	}

	meta := map[string]string{}
	if fp != "" {
		meta["file"] = filepath.Base(fp)
	}

	req := ai.DiagnoseRequest{
		Scope:     scope,
		Code:      code,
		Language:  lang,
		ErrorText: errText,
		Logs:      logs,
		Metadata:  meta,
		Locale:    locale,
		ProfileID: strings.TrimSpace(opts.profileID),
	}
	return req, origBytes, fileMode, nil
}

func runAIDiagnoseWithTimeout(ctx context.Context, mgr *ai.Manager, req ai.DiagnoseRequest) (*ai.DiagnoseResult, error) {
	timeoutSec := ai.DefaultTimeoutSec
	if req.ProfileID != "" {
		if p, ok := mgr.Store().GetProfile(req.ProfileID); ok && p.TimeoutSec > 0 {
			timeoutSec = p.TimeoutSec
		}
	} else if p, ok := mgr.Store().GetActiveProfile(); ok && p.TimeoutSec > 0 {
		timeoutSec = p.TimeoutSec
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec+15)*time.Second)
	defer cancel()
	return mgr.DiagnoseAndFix(runCtx, req)
}

func printDiagnoseResultText(out io.Writer, res *ai.DiagnoseResult) {
	fmt.Fprintf(out, "Provider:    %s / %s (%dms · redacted=%d)\n", res.ProviderUsed, res.ModelUsed, res.ElapsedMs, res.RedactedCount)
	fmt.Fprintf(out, "Category:    %s · fix_kind=%s · confidence=%.2f\n", res.ErrorCategory, res.FixKind, res.Confidence)
	fmt.Fprintf(out, "Root Cause:  %s\n", res.RootCause)
	if strings.TrimSpace(res.Explanation) != "" {
		fmt.Fprintf(out, "\nExplanation:\n%s\n", strings.TrimSpace(res.Explanation))
	}
	if res.Validation != nil {
		state := "PASSED"
		if !res.Validation.Passed {
			state = "FAILED"
		}
		fmt.Fprintf(out, "\nValidation:  %s (%s)\n", state, res.Validation.Validator)
		for _, issue := range res.Validation.Issues {
			fmt.Fprintf(out, "  [issue] %s\n", issue)
		}
		for _, warn := range res.Validation.Warnings {
			fmt.Fprintf(out, "  [warn]  %s\n", warn)
		}
	}
	if strings.TrimSpace(res.UnifiedDiff) != "" {
		fmt.Fprintf(out, "\nUnified Diff:\n%s", res.UnifiedDiff)
		if !strings.HasSuffix(res.UnifiedDiff, "\n") {
			fmt.Fprintln(out)
		}
	}
	if len(res.ConfigChanges) > 0 {
		fmt.Fprintln(out, "\nSuggested Config Changes:")
		keys := make([]string, 0, len(res.ConfigChanges))
		for k := range res.ConfigChanges {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(out, "  %s = %s\n", k, res.ConfigChanges[k])
		}
	}
	if len(res.CommandHints) > 0 {
		fmt.Fprintln(out, "\nCommand Hints:")
		for _, c := range res.CommandHints {
			fmt.Fprintf(out, "  $ %s\n", c)
		}
	}
	if strings.TrimSpace(res.VerifyHint) != "" {
		fmt.Fprintf(out, "\nVerify Hint: %s\n", strings.TrimSpace(res.VerifyHint))
	}
}

func bindDiagFlags(cmd *cobra.Command, opts *aiDiagCLIOpts) {
	cmd.Flags().StringVar(&opts.scope, "scope", "", "diagnostic scope (unidbg, qiling, angr, frida, plugin, signer, toolchain, recon, general)")
	cmd.Flags().StringVar(&opts.filePath, "file", "", "source code file path to inspect")
	cmd.Flags().StringVar(&opts.errorText, "error", "", "error text or exception summary")
	cmd.Flags().StringVar(&opts.logFile, "log-file", "", "execution log file path (or '-' for stdin)")
	cmd.Flags().StringVar(&opts.locale, "locale", "", "response language (en, zh-CN)")
	cmd.Flags().StringVar(&opts.profileID, "profile", "", "override AI profile ID")
	cmd.Flags().StringVar(&opts.language, "language", "", "explicit code language (python, java, javascript)")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "output JSON")
}

func newAIDiagnoseCmd() *cobra.Command {
	var opts aiDiagCLIOpts

	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Diagnose an error using the configured AI provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			req, _, _, err := buildDiagnoseRequestFromCLI(cmd, opts)
			if err != nil {
				return err
			}
			mgr, err := openAIManager()
			if err != nil {
				return err
			}
			res, err := runAIDiagnoseWithTimeout(cmdBaseContext(cmd), mgr, req)
			if err != nil {
				return err
			}

			if opts.jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.ai.diagnose.title"), req.Scope)
			}
			printDiagnoseResultText(out, res)
			return nil
		},
	}

	bindDiagFlags(cmd, &opts)
	return cmd
}

type aiFixOutput struct {
	*ai.DiagnoseResult
	Applied    bool   `json:"applied"`
	TargetFile string `json:"target_file,omitempty"`
	BackupPath string `json:"backup_path,omitempty"`
}

func applyValidatedPatchToFile(filePath string, originalBytes []byte, patchedCode string, perm os.FileMode) (string, error) {
	if perm == 0 {
		perm = 0o644
	}
	backupPath := filePath + ".bak"
	if err := os.WriteFile(backupPath, originalBytes, perm); err != nil {
		return "", fmt.Errorf("write backup file %s: %w", backupPath, err)
	}

	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(filePath)+".cap-fix.*")
	if err != nil {
		return backupPath, fmt.Errorf("create temp patch file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return backupPath, fmt.Errorf("chmod temp patch file: %w", err)
	}
	if _, err := tmp.WriteString(patchedCode); err != nil {
		_ = tmp.Close()
		return backupPath, fmt.Errorf("write temp patch file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return backupPath, fmt.Errorf("sync temp patch file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return backupPath, fmt.Errorf("close temp patch file: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		return backupPath, fmt.Errorf("replace %s with patched code: %w", filePath, err)
	}
	cleanup = false
	return backupPath, nil
}

func newAIFixCmd() *cobra.Command {
	var (
		opts  aiDiagCLIOpts
		apply bool
	)

	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Diagnose and print a unified diff, or apply a validated patch with --apply",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fp := strings.TrimSpace(opts.filePath)
			if apply && fp == "" {
				return fmt.Errorf("--apply requires --file to be specified")
			}

			req, origBytes, fileMode, err := buildDiagnoseRequestFromCLI(cmd, opts)
			if err != nil {
				return err
			}
			mgr, err := openAIManager()
			if err != nil {
				return err
			}
			res, err := runAIDiagnoseWithTimeout(cmdBaseContext(cmd), mgr, req)
			if err != nil {
				return err
			}

			payload := aiFixOutput{
				DiagnoseResult: res,
				Applied:        false,
				TargetFile:     fp,
			}

			if apply {
				if res.FixKind != ai.FixKindCodePatch || strings.TrimSpace(res.PatchedCode) == "" {
					return fmt.Errorf("cannot apply patch: AI returned fix_kind=%q without patched code", res.FixKind)
				}
				if res.Validation == nil || !res.Validation.Passed {
					issues := ""
					if res.Validation != nil && len(res.Validation.Issues) > 0 {
						issues = ": " + strings.Join(res.Validation.Issues, "; ")
					}
					return fmt.Errorf("refusing to apply unvalidated patch%s", issues)
				}
				backupPath, err := applyValidatedPatchToFile(fp, origBytes, res.PatchedCode, fileMode)
				if err != nil {
					return err
				}
				payload.Applied = true
				payload.BackupPath = backupPath
			}

			if opts.jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(payload)
			}

			styled := isStyledWriter(out)
			th := cliTheme(styled)
			if styled {
				printSectionHeader(out, th, i18n.T("cli.ai.fix.title"), req.Scope)
			}
			printDiagnoseResultText(out, res)
			if payload.Applied {
				fmt.Fprintf(out, "\nApplied validated patch to %s (backup saved to %s).\n", fp, payload.BackupPath)
			} else if fp != "" && res.FixKind == ai.FixKindCodePatch && res.Validation != nil && res.Validation.Passed {
				fmt.Fprintf(out, "\nDry-run only. Re-run with --apply to write patched code to %s (creates %s.bak).\n", fp, fp)
			}
			return nil
		},
	}

	bindDiagFlags(cmd, &opts)
	cmd.Flags().BoolVar(&apply, "apply", false, "write validated patched_code back to --file (creates <file>.bak backup)")
	return cmd
}
