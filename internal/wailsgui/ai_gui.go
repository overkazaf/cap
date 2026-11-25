package wailsgui

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/ai"
	"github.com/overkazaf/cap/internal/retools"
)

// ==================== Multi-Model AI Provider & Auto-Heal ====================

func (a *App) ensureAIManager() (*ai.Manager, error) {
	a.mu.Lock()
	mgr := a.aiMgr
	capDir := a.certDir
	a.mu.Unlock()

	if mgr != nil {
		return mgr, nil
	}
	created, err := ai.NewManager(capDir)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.aiMgr == nil {
		a.aiMgr = created
	}
	mgr = a.aiMgr
	a.mu.Unlock()
	return mgr, nil
}

// GetAIConfig returns the masked public AI configuration snapshot.
func (a *App) GetAIConfig() ai.PublicAIConfig {
	mgr, err := a.ensureAIManager()
	if err != nil {
		return ai.PublicAIConfig{
			Profiles:       []ai.PublicProviderConfig{},
			MaxAutoRetries: ai.DefaultMaxAutoRetries,
			RedactSecrets:  true,
		}
	}
	return mgr.GetPublicConfig()
}

// ListAIProviderPresets returns the built-in AI model provider presets.
func (a *App) ListAIProviderPresets() []ai.ProviderPreset {
	return ai.ListProviderPresets()
}

// UpsertAIProfile creates or updates an AI provider profile.
func (a *App) UpsertAIProfile(p ai.ProviderConfig) (ai.PublicProviderConfig, error) {
	mgr, err := a.ensureAIManager()
	if err != nil {
		return ai.PublicProviderConfig{}, err
	}
	return mgr.UpsertProfile(p)
}

// DeleteAIProfile deletes a configured AI provider profile by ID.
func (a *App) DeleteAIProfile(id string) error {
	mgr, err := a.ensureAIManager()
	if err != nil {
		return err
	}
	return mgr.DeleteProfile(id)
}

// SetActiveAIProfile selects the active AI provider profile ID.
func (a *App) SetActiveAIProfile(id string) error {
	mgr, err := a.ensureAIManager()
	if err != nil {
		return err
	}
	return mgr.SetActiveProfile(id)
}

// UpdateAISettings applies partial updates to top-level AI behavior flags and returns the updated public config.
func (a *App) UpdateAISettings(upd ai.AISettingsUpdate) (ai.PublicAIConfig, error) {
	mgr, err := a.ensureAIManager()
	if err != nil {
		return ai.PublicAIConfig{}, err
	}
	if err := mgr.UpdateSettings(upd); err != nil {
		return mgr.GetPublicConfig(), err
	}
	return mgr.GetPublicConfig(), nil
}

// TestAIConnection probes connectivity for the given AI provider profile with a 30s timeout.
func (a *App) TestAIConnection(p ai.ProviderConfig) ai.TestConnectionResult {
	mgr, err := a.ensureAIManager()
	if err != nil {
		return ai.TestConnectionResult{
			OK:       false,
			Provider: p.Provider,
			Model:    p.Model,
			Error:    err.Error(),
		}
	}
	ctx, cancel := context.WithTimeout(a.appBaseContext(), 30*time.Second)
	defer cancel()
	return mgr.TestConnection(ctx, p)
}

func resolveProfileTimeoutSec(mgr *ai.Manager, profileID string) int {
	if mgr == nil || mgr.Store() == nil {
		return ai.DefaultTimeoutSec
	}
	if id := strings.TrimSpace(profileID); id != "" {
		if p, ok := mgr.Store().GetProfile(id); ok && p.TimeoutSec > 0 {
			return p.TimeoutSec
		}
	} else if p, ok := mgr.Store().GetActiveProfile(); ok && p.TimeoutSec > 0 {
		return p.TimeoutSec
	}
	return ai.DefaultTimeoutSec
}

// DiagnoseAndFixWithAI performs one-shot AI failure diagnosis and fix synthesis.
func (a *App) DiagnoseAndFixWithAI(req ai.DiagnoseRequest) (*ai.DiagnoseResult, error) {
	mgr, err := a.ensureAIManager()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Locale) == "" {
		req.Locale = a.GetSetting("locale")
	}
	timeoutSec := resolveProfileTimeoutSec(mgr, req.ProfileID)
	ctx, cancel := context.WithTimeout(a.appBaseContext(), time.Duration(timeoutSec+15)*time.Second)
	defer cancel()
	return mgr.DiagnoseAndFix(ctx, req)
}

// ApplyAIConfigChanges filters proposed setting updates via ai.SanitizeConfigChanges,
// persists each allowlisted setting via SetSetting, and returns the applied map.
func (a *App) ApplyAIConfigChanges(changes map[string]string) (map[string]string, error) {
	sanitized := ai.SanitizeConfigChanges(changes)
	applied := make(map[string]string, len(sanitized))
	if len(sanitized) == 0 {
		return applied, nil
	}
	keys := make([]string, 0, len(sanitized))
	for k := range sanitized {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := sanitized[k]
		if err := a.SetSetting(k, v); err != nil {
			return applied, err
		}
		applied[k] = v
	}
	return applied, nil
}

func reEngineScopeAndLanguage(engine string) (scope, language string) {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case retools.EngineUnidbg:
		return ai.ScopeUnidbg, "java"
	case retools.EngineQiling:
		return ai.ScopeQiling, "python"
	case retools.EngineAngr:
		return ai.ScopeAngr, "python"
	default:
		return ai.NormalizeScope(engine), ""
	}
}

func collectREJobLogs(st *retools.JobState) string {
	if st == nil || len(st.Events) == 0 {
		return ""
	}
	lines := make([]string, 0, len(st.Events))
	for _, ev := range st.Events {
		msg := ev.Raw
		if strings.TrimSpace(msg) == "" {
			msg = ev.Message
		}
		if strings.TrimSpace(msg) == "" {
			continue
		}
		switch ev.Stream {
		case "stderr":
			lines = append(lines, "[stderr] "+msg)
		case "system":
			lines = append(lines, "[system] "+msg)
		default:
			lines = append(lines, msg)
		}
	}
	return strings.Join(lines, "\n")
}

// RunREJobWithAutoHeal executes an RE job and iteratively heals failures via the
// configured AI profile, emitting live EventAIHeal events to the frontend.
func (a *App) RunREJobWithAutoHeal(req retools.RunJobRequest, maxRetries int, locale string) (*ai.AutoHealRunResult, error) {
	aiMgr, err := a.ensureAIManager()
	if err != nil {
		return nil, err
	}
	retoolsMgr, err := a.ensureRetoolsManager()
	if err != nil {
		return nil, err
	}

	// Hydrate missing fields from saved project so AI diagnosis sees full source code and engine.
	if req.ProjectID != "" && retoolsMgr.Projects() != nil {
		if proj, ok := retoolsMgr.Projects().Get(req.ProjectID); ok {
			if strings.TrimSpace(req.Engine) == "" {
				req.Engine = proj.Engine
			}
			if strings.TrimSpace(req.ProjectName) == "" {
				req.ProjectName = proj.Name
			}
			if strings.TrimSpace(req.Code) == "" {
				req.Code = proj.Code
			}
			if req.BinaryPath == "" {
				req.BinaryPath = proj.BinaryPath
			}
			if req.APKPath == "" {
				req.APKPath = proj.APKPath
			}
			if req.RootFS == "" {
				req.RootFS = proj.RootFS
			}
			if req.TargetSymbol == "" {
				req.TargetSymbol = proj.TargetSymbol
			}
			if req.TargetAddr == "" {
				req.TargetAddr = proj.TargetAddr
			}
			if req.FindAddr == "" {
				req.FindAddr = proj.FindAddr
			}
			if req.AvoidAddr == "" {
				req.AvoidAddr = proj.AvoidAddr
			}
			if len(req.Args) == 0 && len(proj.Args) > 0 {
				req.Args = append([]string(nil), proj.Args...)
			}
		}
	}

	if strings.TrimSpace(locale) == "" {
		locale = a.GetSetting("locale")
	}

	scope, lang := reEngineScopeAndLanguage(req.Engine)
	meta := make(map[string]string)
	if req.Engine != "" {
		meta["engine"] = req.Engine
	}
	if req.ProjectID != "" {
		meta["project_id"] = req.ProjectID
	}
	if req.ProjectName != "" {
		meta["project_name"] = req.ProjectName
	}
	if req.BinaryPath != "" {
		meta["binary_path"] = req.BinaryPath
	}
	if req.APKPath != "" {
		meta["apk_path"] = req.APKPath
	}
	if req.RootFS != "" {
		meta["rootfs"] = req.RootFS
	}
	if req.TargetSymbol != "" {
		meta["target_symbol"] = req.TargetSymbol
	}
	if req.TargetAddr != "" {
		meta["target_addr"] = req.TargetAddr
	}

	diagReq := ai.DiagnoseRequest{
		Scope:    scope,
		Code:     req.Code,
		Language: lang,
		Metadata: meta,
		Locale:   locale,
	}

	// Serialize cancel-previous + register-new transitions so any superseded
	// auto-heal loop fully unwinds before the next loop launches a new RE job
	// or emits EventAIHeal.
	ctx, cancel := context.WithCancel(a.appBaseContext())
	myDone := make(chan struct{})

	a.aiHealOpMu.Lock()
	a.aiHealMu.Lock()
	prevCancel := a.aiHealCancel
	prevDone := a.aiHealDone
	a.aiHealMu.Unlock()

	if prevCancel != nil {
		prevCancel()
		_ = retoolsMgr.CancelJob()
	}
	if prevDone != nil {
		select {
		case <-prevDone:
		case <-time.After(5 * time.Second):
		}
	}

	a.aiHealMu.Lock()
	a.aiHealSeq++
	mySeq := a.aiHealSeq
	a.aiHealCancel = cancel
	a.aiHealDone = myDone
	a.aiHealMu.Unlock()
	a.aiHealOpMu.Unlock()

	defer func() {
		cancel()
		a.aiHealMu.Lock()
		if a.aiHealSeq == mySeq {
			a.aiHealCancel = nil
			a.aiHealDone = nil
		}
		a.aiHealMu.Unlock()
		close(myDone)
	}()

	runner := func(rctx context.Context, code string) (int, string, error) {
		if err := rctx.Err(); err != nil {
			return -1, "", err
		}
		runReq := req
		runReq.Code = code
		started, err := retoolsMgr.StartJob(runReq)
		if err != nil {
			return -1, "", err
		}
		st, waitErr := retoolsMgr.WaitJob(rctx)
		if waitErr != nil {
			if cur := retoolsMgr.GetJobState(); cur != nil && started != nil && cur.ID == started.ID && cur.Running {
				_ = retoolsMgr.CancelJob()
			}
			cur := retoolsMgr.GetJobState()
			logs := ""
			exitCode := -1
			if cur != nil && (started == nil || cur.ID == started.ID) {
				logs = collectREJobLogs(cur)
				if cur.ExitCode != 0 {
					exitCode = cur.ExitCode
				}
			}
			return exitCode, logs, waitErr
		}
		if st != nil && started != nil && st.ID != started.ID {
			cancel()
			return -1, "", context.Canceled
		}
		logs := collectREJobLogs(st)
		if st == nil {
			return -1, logs, errors.New("RE job finished without state")
		}
		if st.Status == retools.StatusCancelled {
			cancel()
			return -1, logs, context.Canceled
		}
		if st.ExitCode != 0 || st.Status == retools.StatusError {
			exitCode := st.ExitCode
			if exitCode == 0 {
				exitCode = 1
			}
			var runErr error
			if msg := strings.TrimSpace(st.Error); msg != "" {
				runErr = errors.New(msg)
			} else {
				runErr = fmt.Errorf("RE job failed with status %s (exit %d)", st.Status, exitCode)
			}
			return exitCode, logs, runErr
		}
		return 0, logs, nil
	}

	onEvent := func(ev ai.AutoHealEvent) {
		if a.events == nil {
			return
		}
		a.aiHealMu.Lock()
		isCurrent := a.aiHealSeq == mySeq
		a.aiHealMu.Unlock()
		if isCurrent {
			a.events.Emit(EventAIHeal, ev)
		}
	}

	return aiMgr.RunAutoHealLoop(ctx, diagReq, maxRetries, runner, onEvent)
}

// CancelAIAutoHeal cancels any active AI auto-heal loop, terminates any active RE job,
// and waits briefly for the auto-heal loop goroutine to unwind cleanly.
func (a *App) CancelAIAutoHeal() error {
	a.aiHealMu.Lock()
	cancel := a.aiHealCancel
	done := a.aiHealDone
	a.aiHealCancel = nil
	a.aiHealMu.Unlock()

	if cancel != nil {
		cancel()
	}

	a.mu.Lock()
	retoolsMgr := a.retoolsMgr
	a.mu.Unlock()
	var cancelErr error
	if retoolsMgr != nil {
		cancelErr = retoolsMgr.CancelJob()
	}

	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	return cancelErr
}

// ComputeTextUnifiedDiff computes a pure-Go LCS unified diff between oldText and newText.
func (a *App) ComputeTextUnifiedDiff(oldText, newText string) string {
	return ai.ComputeUnifiedDiff(oldText, newText)
}
