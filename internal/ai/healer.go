package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ansiEscapeRe   = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	isoTimestampRe = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`)
	hmsTimestampRe = regexp.MustCompile(`\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b`)
	pidTidRe       = regexp.MustCompile(`(?i)\b(pid|tid)\s*[:=]\s*\d+\b`)
	durationRe     = regexp.MustCompile(`\b\d+(?:\.\d+)?\s*(?:ns|us|µs|ms|s)\b`)
	tempPathRe     = regexp.MustCompile(`(?:/tmp|/var/folders/[^\s/]+/[^\s/]+/T)/[^\s:'"]+`)
	multiSpaceRe   = regexp.MustCompile(`[ \t]+`)
	errorLineCueRe = regexp.MustCompile(`(?i)(error|exception|traceback|failed|fatal|panic|uc_err_|syntaxerror|typeerror|referenceerror|unsupportedoperationexception|classnotfoundexception|filenotfoundexception|undefined)`)
)

// Manager coordinates AI profile storage, provider calls, single-shot diagnosis,
// and the bounded self-healing auto-fix loop.
type Manager struct {
	store  *ConfigStore
	client *Client
}

// NewManager initializes a Manager backed by <capDir>/ai.json and a pure-Go HTTP client.
func NewManager(capDir string) (*Manager, error) {
	store, err := NewConfigStore(capDir)
	if err != nil {
		return nil, err
	}
	return &Manager{
		store:  store,
		client: NewClient(),
	}, nil
}

// Store returns the underlying thread-safe ConfigStore.
func (m *Manager) Store() *ConfigStore {
	return m.store
}

// GetPublicConfig returns the masked public AI configuration snapshot.
func (m *Manager) GetPublicConfig() PublicAIConfig {
	return m.store.GetPublicConfig()
}

// UpsertProfile saves a provider profile with atomic 0600 persistence and masked-key preservation.
func (m *Manager) UpsertProfile(p ProviderConfig) (PublicProviderConfig, error) {
	return m.store.UpsertProfile(p)
}

// DeleteProfile deletes a provider profile by ID.
func (m *Manager) DeleteProfile(id string) error {
	return m.store.DeleteProfile(id)
}

// SetActiveProfile selects the active provider profile ID.
func (m *Manager) SetActiveProfile(id string) error {
	return m.store.SetActiveProfile(id)
}

// UpdateSettings updates top-level auto-heal and redaction settings.
func (m *Manager) UpdateSettings(update AISettingsUpdate) error {
	return m.store.UpdateSettings(update)
}

// ListPresets returns the built-in provider presets.
func (m *Manager) ListPresets() []ProviderPreset {
	return ListProviderPresets()
}

// TestConnection tests connectivity for profile. If profile.ID references a
// saved profile and profile.APIKey is empty or masked, the stored key is reused
// so frontends never need to handle raw secrets.
func (m *Manager) TestConnection(ctx context.Context, profile ProviderConfig) TestConnectionResult {
	resolved := profile.Clone()
	if id := strings.TrimSpace(resolved.ID); id != "" && !resolved.ClearAPIKey {
		if existing, ok := m.store.GetProfile(id); ok {
			incomingKey := strings.TrimSpace(resolved.APIKey)
			if incomingKey == "" || IsMaskedAPIKey(incomingKey) || (existing.APIKey != "" && incomingKey == MaskAPIKey(existing.APIKey)) {
				resolved.APIKey = existing.APIKey
			}
		}
	}
	return m.client.TestConnection(ctx, resolved)
}

// TestProfileByID tests a saved provider profile by ID.
func (m *Manager) TestProfileByID(ctx context.Context, profileID string) TestConnectionResult {
	profile, ok := m.store.GetProfile(profileID)
	if !ok {
		return TestConnectionResult{
			OK:    false,
			Error: fmt.Sprintf("AI profile %q not found", profileID),
		}
	}
	return m.client.TestConnection(ctx, profile)
}

// DiagnoseAndFix runs local deterministic pre-diagnosis, optional secret
// redaction, LLM completion, JSON extraction, unified diffing, and patch validation.
func (m *Manager) DiagnoseAndFix(ctx context.Context, req DiagnoseRequest) (*DiagnoseResult, error) {
	start := time.Now()
	profile, err := m.resolveProfile(req.ProfileID)
	if err != nil {
		return nil, err
	}

	cfg := m.store.GetConfig()
	scope := NormalizeScope(req.Scope)
	locale := NormalizeLocale(req.Locale)

	// Run deterministic local pre-diagnosis on original logs before redacting
	// so parsers see exact JNI signatures / paths / Unicorn addresses, then
	// redact the resulting summary as well when RedactSecrets is enabled.
	preDiag := BuildPreDiagnosis(req)

	sanitizedReq := req
	sanitizedReq.Scope = scope
	sanitizedReq.Locale = locale
	compressedLogs, redactedCount := RedactAndCompressLogs(req.Logs, cfg.RedactSecrets)

	if cfg.RedactSecrets {
		var n int
		sanitizedReq.Code, n = RedactSecrets(req.Code)
		redactedCount += n
		sanitizedReq.ErrorText, n = RedactSecrets(req.ErrorText)
		redactedCount += n
		preDiag, n = RedactSecrets(preDiag)
		redactedCount += n
		if len(req.Metadata) > 0 {
			meta := make(map[string]string, len(req.Metadata))
			for k, v := range req.Metadata {
				rv, mn := RedactSecrets(v)
				redactedCount += mn
				meta[k] = rv
			}
			sanitizedReq.Metadata = meta
		}
		if len(req.PreviousAttempts) > 0 {
			prevs := make([]HealAttemptSummary, len(req.PreviousAttempts))
			for i, prev := range req.PreviousAttempts {
				prev.ErrorExcerpt, n = RedactSecrets(prev.ErrorExcerpt)
				redactedCount += n
				prev.RootCause, n = RedactSecrets(prev.RootCause)
				redactedCount += n
				prev.UnifiedDiff, n = RedactSecrets(prev.UnifiedDiff)
				redactedCount += n
				prevs[i] = prev
			}
			sanitizedReq.PreviousAttempts = prevs
		}
	}

	systemPrompt := BuildSystemPrompt(scope, locale)
	userPrompt := BuildUserPrompt(sanitizedReq, preDiag, compressedLogs)

	comp, err := m.client.Complete(ctx, profile, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	res, err := ParseDiagnoseJSON(comp.Content)
	if err != nil {
		return nil, err
	}

	res.ConfigChanges = SanitizeConfigChanges(res.ConfigChanges)
	if res.FixKind == FixKindCodePatch {
		res.UnifiedDiff = ComputeUnifiedDiff(req.Code, res.PatchedCode)
		val := ValidatePatchedCode(req.Language, req.Code, res.PatchedCode)
		res.Validation = &val
	}

	res.PreDiagnosis = preDiag
	res.RedactedCount = redactedCount
	res.ProviderUsed = profile.Provider
	res.ModelUsed = profile.Model
	res.ElapsedMs = time.Since(start).Milliseconds()
	res.PromptTokens = comp.PromptTokens
	res.CompletionTokens = comp.CompletionTokens
	return res, nil
}

func (m *Manager) resolveProfile(overrideID string) (ProviderConfig, error) {
	if id := strings.TrimSpace(overrideID); id != "" {
		p, ok := m.store.GetProfile(id)
		if !ok {
			return ProviderConfig{}, fmt.Errorf("AI profile %q not found", id)
		}
		if !p.Enabled {
			return ProviderConfig{}, fmt.Errorf("AI profile %q is disabled", p.ID)
		}
		return p, nil
	}
	p, ok := m.store.GetActiveProfile()
	if !ok {
		return ProviderConfig{}, errors.New("no active AI profile configured")
	}
	if !p.Enabled {
		return ProviderConfig{}, fmt.Errorf("active AI profile %q is disabled", p.ID)
	}
	return p, nil
}

// RunAutoHealLoop executes req.Code via runner, and on failure iteratively
// diagnoses, validates, patches, and re-runs up to maxRetries (1..5) while
// guarding against unchanged patches, validation failures, repeated error
// fingerprints, and context cancellation.
func (m *Manager) RunAutoHealLoop(
	ctx context.Context,
	req DiagnoseRequest,
	maxRetries int,
	runner func(ctx context.Context, code string) (exitCode int, logs string, err error),
	onEvent func(AutoHealEvent),
) (*AutoHealRunResult, error) {
	if runner == nil {
		return nil, errors.New("auto-heal runner callback is required")
	}
	if maxRetries <= 0 {
		maxRetries = m.store.GetConfig().MaxAutoRetries
	}
	maxRetries = normalizeMaxAutoRetries(maxRetries)

	totalStart := time.Now()
	emit := func(attempt int, phase, msg string, exitCode int, diag *DiagnoseResult) {
		if onEvent == nil {
			return
		}
		onEvent(AutoHealEvent{
			Attempt:    attempt,
			MaxRetries: maxRetries,
			Phase:      phase,
			Message:    msg,
			ExitCode:   exitCode,
			Diagnosis:  diag,
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		})
	}

	res := &AutoHealRunResult{
		FinalCode: req.Code,
		Attempts:  make([]AutoHealAttempt, 0, maxRetries+1),
	}
	finish := func(healed bool, stopReason string, code string, exitCode int, logs string) (*AutoHealRunResult, error) {
		res.Healed = healed
		res.StopReason = stopReason
		res.FinalCode = code
		res.FinalExitCode = exitCode
		res.FinalLogs = logs
		res.TotalElapsedMs = time.Since(totalStart).Milliseconds()
		return res, nil
	}

	if ctx.Err() != nil {
		emit(0, PhaseStopped, "Auto-heal cancelled before start.", -1, nil)
		return finish(false, StopReasonCancelled, req.Code, -1, "")
	}

	// Step 1: Initial execution before invoking AI.
	currentCode := req.Code
	emit(0, PhaseRunning, "Running initial execution...", 0, nil)
	initStart := time.Now()
	exitCode, logs, runErr := runner(ctx, currentCode)
	initElapsed := time.Since(initStart).Milliseconds()

	if ctx.Err() != nil {
		res.Attempts = append(res.Attempts, AutoHealAttempt{
			Attempt:   0,
			ExitCode:  exitCode,
			Logs:      logs,
			Outcome:   StopReasonCancelled,
			ElapsedMs: initElapsed,
		})
		emit(0, PhaseStopped, "Auto-heal cancelled during initial execution.", exitCode, nil)
		return finish(false, StopReasonCancelled, currentCode, exitCode, logs)
	}

	if exitCode == 0 && runErr == nil {
		res.Attempts = append(res.Attempts, AutoHealAttempt{
			Attempt:   0,
			ExitCode:  0,
			Logs:      logs,
			Outcome:   StopReasonAlreadyOK,
			ElapsedMs: initElapsed,
		})
		emit(0, PhaseHealed, "Initial execution succeeded; no repair needed.", 0, nil)
		return finish(true, StopReasonAlreadyOK, currentCode, 0, logs)
	}

	initialFallback := ""
	if runErr == nil && strings.TrimSpace(logs) == "" {
		initialFallback = req.ErrorText
	}
	errText := combineRunError(initialFallback, runErr, exitCode)
	fp := ComputeErrorFingerprint(errText, logs)
	seenFingerprints := map[string]struct{}{fp: {}}

	res.Attempts = append(res.Attempts, AutoHealAttempt{
		Attempt:          0,
		ExitCode:         exitCode,
		Logs:             logs,
		ErrorFingerprint: fp,
		Outcome:          "failed",
		ElapsedMs:        initElapsed,
	})

	previousAttempts := append([]HealAttemptSummary(nil), req.PreviousAttempts...)

	// Step 2: Bounded repair iterations (1..maxRetries).
	for retry := 1; retry <= maxRetries; retry++ {
		if ctx.Err() != nil {
			emit(retry, PhaseStopped, "Auto-heal cancelled.", exitCode, nil)
			return finish(false, StopReasonCancelled, currentCode, exitCode, logs)
		}

		attemptStart := time.Now()
		emit(retry, PhaseDiagnosing, fmt.Sprintf("Diagnosing failure (attempt %d/%d)...", retry, maxRetries), exitCode, nil)

		diagReq := req
		diagReq.Code = currentCode
		diagReq.ErrorText = errText
		diagReq.Logs = logs
		diagReq.PreviousAttempts = previousAttempts

		diag, diagErr := m.DiagnoseAndFix(ctx, diagReq)
		if ctx.Err() != nil {
			res.Attempts = append(res.Attempts, AutoHealAttempt{
				Attempt:          retry,
				ExitCode:         exitCode,
				Logs:             logs,
				ErrorFingerprint: fp,
				Outcome:          StopReasonCancelled,
				ElapsedMs:        time.Since(attemptStart).Milliseconds(),
			})
			emit(retry, PhaseStopped, "Auto-heal cancelled during AI diagnosis.", exitCode, nil)
			return finish(false, StopReasonCancelled, currentCode, exitCode, logs)
		}
		if diagErr != nil {
			res.Attempts = append(res.Attempts, AutoHealAttempt{
				Attempt:          retry,
				ExitCode:         exitCode,
				Logs:             logs,
				ErrorFingerprint: fp,
				Outcome:          StopReasonDiagnoseError,
				ElapsedMs:        time.Since(attemptStart).Milliseconds(),
			})
			emit(retry, PhaseStopped, "AI diagnosis failed: "+diagErr.Error(), exitCode, nil)
			return finish(false, StopReasonDiagnoseError, currentCode, exitCode, logs)
		}

		if diag.FixKind != FixKindCodePatch {
			res.Attempts = append(res.Attempts, AutoHealAttempt{
				Attempt:          retry,
				ExitCode:         exitCode,
				Logs:             logs,
				ErrorFingerprint: fp,
				Diagnosis:        diag,
				Outcome:          StopReasonNonPatchFix,
				ElapsedMs:        time.Since(attemptStart).Milliseconds(),
			})
			emit(retry, PhaseStopped, fmt.Sprintf("AI suggested %s instead of an automatic code patch.", diag.FixKind), exitCode, diag)
			return finish(false, StopReasonNonPatchFix, currentCode, exitCode, logs)
		}

		emit(retry, PhaseValidating, "Validating proposed code patch...", exitCode, diag)
		if diag.Validation == nil || !diag.Validation.Passed {
			res.Attempts = append(res.Attempts, AutoHealAttempt{
				Attempt:          retry,
				ExitCode:         exitCode,
				Logs:             logs,
				ErrorFingerprint: fp,
				Diagnosis:        diag,
				Outcome:          StopReasonValidationFailed,
				ElapsedMs:        time.Since(attemptStart).Milliseconds(),
			})
			emit(retry, PhaseStopped, "Proposed patch failed validation; aborting auto-heal.", exitCode, diag)
			return finish(false, StopReasonValidationFailed, currentCode, exitCode, logs)
		}

		if normalizeCodeForCompare(diag.PatchedCode) == normalizeCodeForCompare(currentCode) {
			res.Attempts = append(res.Attempts, AutoHealAttempt{
				Attempt:          retry,
				ExitCode:         exitCode,
				Logs:             logs,
				ErrorFingerprint: fp,
				Diagnosis:        diag,
				Outcome:          StopReasonUnchangedCode,
				ElapsedMs:        time.Since(attemptStart).Milliseconds(),
			})
			emit(retry, PhaseStopped, "AI returned unchanged code; stopping auto-heal.", exitCode, diag)
			return finish(false, StopReasonUnchangedCode, currentCode, exitCode, logs)
		}

		// Apply validated patch and re-run.
		currentCode = diag.PatchedCode
		emit(retry, PhasePatching, fmt.Sprintf("Applying validated patch and re-running (attempt %d/%d)...", retry, maxRetries), exitCode, diag)
		emit(retry, PhaseRunning, fmt.Sprintf("Re-running patched code (attempt %d/%d)...", retry, maxRetries), 0, diag)

		nextExitCode, nextLogs, nextErr := runner(ctx, currentCode)
		attemptElapsed := time.Since(attemptStart).Milliseconds()

		if ctx.Err() != nil {
			res.Attempts = append(res.Attempts, AutoHealAttempt{
				Attempt:      retry,
				ExitCode:     nextExitCode,
				Logs:         nextLogs,
				Diagnosis:    diag,
				AppliedPatch: true,
				Outcome:      StopReasonCancelled,
				ElapsedMs:    attemptElapsed,
			})
			emit(retry, PhaseStopped, "Auto-heal cancelled during re-execution.", nextExitCode, diag)
			return finish(false, StopReasonCancelled, currentCode, nextExitCode, nextLogs)
		}

		if nextExitCode == 0 && nextErr == nil {
			res.Attempts = append(res.Attempts, AutoHealAttempt{
				Attempt:      retry,
				ExitCode:     0,
				Logs:         nextLogs,
				Diagnosis:    diag,
				AppliedPatch: true,
				Outcome:      StopReasonHealed,
				ElapsedMs:    attemptElapsed,
			})
			emit(retry, PhaseHealed, fmt.Sprintf("Auto-heal succeeded on attempt %d.", retry), 0, diag)
			return finish(true, StopReasonHealed, currentCode, 0, nextLogs)
		}

		nextErrText := combineRunError("", nextErr, nextExitCode)
		nextFP := ComputeErrorFingerprint(nextErrText, nextLogs)

		if _, repeated := seenFingerprints[nextFP]; repeated {
			res.Attempts = append(res.Attempts, AutoHealAttempt{
				Attempt:          retry,
				ExitCode:         nextExitCode,
				Logs:             nextLogs,
				ErrorFingerprint: nextFP,
				Diagnosis:        diag,
				AppliedPatch:     true,
				Outcome:          StopReasonRepeatedError,
				ElapsedMs:        attemptElapsed,
			})
			emit(retry, PhaseStopped, "Repeated identical error fingerprint after patch; stopping to avoid retry loop.", nextExitCode, diag)
			return finish(false, StopReasonRepeatedError, currentCode, nextExitCode, nextLogs)
		}

		seenFingerprints[nextFP] = struct{}{}
		res.Attempts = append(res.Attempts, AutoHealAttempt{
			Attempt:          retry,
			ExitCode:         nextExitCode,
			Logs:             nextLogs,
			ErrorFingerprint: nextFP,
			Diagnosis:        diag,
			AppliedPatch:     true,
			Outcome:          "failed",
			ElapsedMs:        attemptElapsed,
		})
		previousAttempts = append(previousAttempts, HealAttemptSummary{
			Attempt:          retry,
			ErrorFingerprint: nextFP,
			ErrorExcerpt:     extractErrorExcerpt(nextErrText, nextLogs),
			RootCause:        diag.RootCause,
			FixKind:          diag.FixKind,
			Outcome:          "failed",
			UnifiedDiff:      diag.UnifiedDiff,
		})

		exitCode = nextExitCode
		logs = nextLogs
		errText = nextErrText
		fp = nextFP
	}

	emit(maxRetries, PhaseStopped, fmt.Sprintf("Reached max auto-heal retries (%d).", maxRetries), exitCode, nil)
	return finish(false, StopReasonMaxRetries, currentCode, exitCode, logs)
}

func combineRunError(initialErrText string, runErr error, exitCode int) string {
	var parts []string
	if t := strings.TrimSpace(initialErrText); t != "" {
		parts = append(parts, t)
	}
	if runErr != nil {
		if t := strings.TrimSpace(runErr.Error()); t != "" {
			parts = append(parts, t)
		}
	}
	if len(parts) == 0 && exitCode != 0 {
		parts = append(parts, fmt.Sprintf("process exited with status %d", exitCode))
	}
	return strings.Join(parts, "\n")
}

// ComputeErrorFingerprint returns a stable 16-hex-char fingerprint for an error
// + log pair after stripping volatile timestamps, ANSI escapes, PIDs, durations,
// and temp-directory names while preserving meaningful error messages and symbols.
func ComputeErrorFingerprint(errText, logs string) string {
	excerpt := extractErrorExcerpt(errText, logs)
	normalized := ansiEscapeRe.ReplaceAllString(excerpt, "")
	normalized = isoTimestampRe.ReplaceAllString(normalized, "<ts>")
	normalized = hmsTimestampRe.ReplaceAllString(normalized, "<ts>")
	normalized = pidTidRe.ReplaceAllString(normalized, "$1=<n>")
	normalized = durationRe.ReplaceAllString(normalized, "<dur>")
	normalized = tempPathRe.ReplaceAllString(normalized, "<tmp>")
	normalized = multiSpaceRe.ReplaceAllString(normalized, " ")

	lines := strings.Split(strings.ReplaceAll(normalized, "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			kept = append(kept, strings.ToLower(t))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(kept, "\n")))
	return hex.EncodeToString(sum[:8])
}

func extractErrorExcerpt(errText, logs string) string {
	var selected []string
	if t := strings.TrimSpace(errText); t != "" {
		selected = append(selected, t)
	}
	normLogs := strings.ReplaceAll(logs, "\r\n", "\n")
	lines := strings.Split(normLogs, "\n")
	var cueLines []string
	var nonEmpty []string
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		nonEmpty = append(nonEmpty, t)
		if errorLineCueRe.MatchString(t) {
			cueLines = append(cueLines, t)
		}
	}
	if len(cueLines) > 0 {
		if len(cueLines) > 12 {
			cueLines = cueLines[len(cueLines)-12:]
		}
		selected = append(selected, cueLines...)
	} else if len(nonEmpty) > 0 {
		start := 0
		if len(nonEmpty) > 10 {
			start = len(nonEmpty) - 10
		}
		selected = append(selected, nonEmpty[start:]...)
	}
	out := strings.Join(selected, "\n")
	if len(out) > 1024 {
		out = truncatePrefixUTF8(out, 1024)
	}
	return out
}
