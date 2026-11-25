// Package ai implements cap's multi-model AI provider client, encrypted-at-rest
// permission-hardened configuration store, secret redaction & local deterministic
// pre-diagnosis, unified diffing, patch validation, and self-healing auto-fix loop.
package ai

import (
	"maps"
	"strings"
)

const (
	// Supported AI provider protocols.
	ProviderOpenAICompat = "openai_compat"
	ProviderAnthropic    = "anthropic"
	ProviderGemini       = "gemini"
	ProviderOllama       = "ollama"

	// Diagnostic scopes matching cap workspaces and reverse-engineering engines.
	ScopeUnidbg    = "unidbg"
	ScopeQiling    = "qiling"
	ScopeAngr      = "angr"
	ScopeFrida     = "frida"
	ScopePlugin    = "plugin"
	ScopeSigner    = "signer"
	ScopeToolchain = "toolchain"
	ScopeRecon     = "recon"
	ScopeGeneral   = "general"

	// FixKind classifications returned by diagnosis.
	FixKindCodePatch       = "code_patch"
	FixKindConfigFix       = "config_fix"
	FixKindCommandHint     = "command_hint"
	FixKindExplanationOnly = "explanation_only"

	// Auto-heal stop reasons.
	StopReasonHealed           = "healed"
	StopReasonAlreadyOK        = "already_ok"
	StopReasonRepeatedError    = "repeated_error"
	StopReasonValidationFailed = "validation_failed"
	StopReasonNonPatchFix      = "non_patch_fix"
	StopReasonUnchangedCode    = "unchanged_code"
	StopReasonMaxRetries       = "max_retries"
	StopReasonCancelled        = "cancelled"
	StopReasonDiagnoseError    = "diagnose_error"

	// Auto-heal event phases.
	PhaseRunning    = "running"
	PhaseDiagnosing = "diagnosing"
	PhaseValidating = "validating"
	PhasePatching   = "patching"
	PhaseHealed     = "healed"
	PhaseStopped    = "stopped"

	// Configuration defaults and bounds.
	DefaultMaxAutoRetries = 3
	MinAutoRetries        = 1
	MaxAutoRetriesLimit   = 5
	DefaultMaxTokens      = 4096
	MaxTokensLimit        = 131072
	DefaultTemperature    = 0.1
	DefaultTimeoutSec     = 90
	MinTimeoutSec         = 5
	MaxTimeoutSec         = 600
)

// ProviderConfig holds the persisted configuration for one AI model profile.
// Raw APIKey is only stored locally in <capDir>/ai.json (0600) and is never
// returned in PublicProviderConfig snapshots.
type ProviderConfig struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	BaseURL      string            `json:"base_url"`
	APIKey       string            `json:"api_key,omitempty"`
	ClearAPIKey  bool              `json:"clear_api_key,omitempty"`
	Model        string            `json:"model"`
	MaxTokens    int               `json:"max_tokens,omitempty"`
	Temperature  float64           `json:"temperature"`
	TimeoutSec   int               `json:"timeout_sec,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
	Enabled      bool              `json:"enabled"`
}

// Clone returns a deep copy of the ProviderConfig.
func (p ProviderConfig) Clone() ProviderConfig {
	cp := p
	if p.ExtraHeaders != nil {
		cp.ExtraHeaders = make(map[string]string, len(p.ExtraHeaders))
		maps.Copy(cp.ExtraHeaders, p.ExtraHeaders)
	}
	return cp
}

// PublicProviderConfig is the safe external representation of a ProviderConfig.
// It intentionally omits raw APIKey and exposes only HasAPIKey and APIKeyPreview.
type PublicProviderConfig struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Provider      string            `json:"provider"`
	BaseURL       string            `json:"base_url"`
	APIKeyPreview string            `json:"api_key_preview"`
	HasAPIKey     bool              `json:"has_api_key"`
	Model         string            `json:"model"`
	MaxTokens     int               `json:"max_tokens"`
	Temperature   float64           `json:"temperature"`
	TimeoutSec    int               `json:"timeout_sec"`
	ExtraHeaders  map[string]string `json:"extra_headers,omitempty"`
	Enabled       bool              `json:"enabled"`
}

// AIConfig is the persisted AI configuration stored in <capDir>/ai.json.
type AIConfig struct {
	ActiveProfileID string           `json:"active_profile_id"`
	Profiles        []ProviderConfig `json:"profiles"`
	AutoHealEnabled bool             `json:"auto_heal_enabled"`
	MaxAutoRetries  int              `json:"max_auto_retries"`
	RedactSecrets   bool             `json:"redact_secrets"`
}

// Clone returns a deep copy of AIConfig.
func (c AIConfig) Clone() AIConfig {
	cp := c
	cp.Profiles = make([]ProviderConfig, len(c.Profiles))
	for i, p := range c.Profiles {
		cp.Profiles[i] = p.Clone()
	}
	return cp
}

// PublicAIConfig is the safe snapshot of AIConfig with all API keys masked.
type PublicAIConfig struct {
	ActiveProfileID string                 `json:"active_profile_id"`
	Profiles        []PublicProviderConfig `json:"profiles"`
	AutoHealEnabled bool                   `json:"auto_heal_enabled"`
	MaxAutoRetries  int                    `json:"max_auto_retries"`
	RedactSecrets   bool                   `json:"redact_secrets"`
}

// AISettingsUpdate applies partial updates to top-level AI behavior settings.
type AISettingsUpdate struct {
	AutoHealEnabled *bool `json:"auto_heal_enabled,omitempty"`
	MaxAutoRetries  *int  `json:"max_auto_retries,omitempty"`
	RedactSecrets   *bool `json:"redact_secrets,omitempty"`
}

// ProviderPreset describes a ready-to-use model provider template for UI/CLI setup.
type ProviderPreset struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Provider        string   `json:"provider"`
	BaseURL         string   `json:"base_url"`
	DefaultModel    string   `json:"default_model"`
	SuggestedModels []string `json:"suggested_models"`
	RequiresAPIKey  bool     `json:"requires_api_key"`
	Description     string   `json:"description"`
}

// ListProviderPresets returns built-in presets for major cloud and local LLM providers.
func ListProviderPresets() []ProviderPreset {
	return []ProviderPreset{
		{
			ID:              "openai",
			Name:            "OpenAI",
			Provider:        ProviderOpenAICompat,
			BaseURL:         "https://api.openai.com/v1",
			DefaultModel:    "gpt-4.1",
			SuggestedModels: []string{"gpt-4.1", "gpt-4o", "o3-mini"},
			RequiresAPIKey:  true,
			Description:     "OpenAI Chat Completions API (also compatible with OpenAI-style gateways).",
		},
		{
			ID:              "deepseek",
			Name:            "DeepSeek",
			Provider:        ProviderOpenAICompat,
			BaseURL:         "https://api.deepseek.com/v1",
			DefaultModel:    "deepseek-chat",
			SuggestedModels: []string{"deepseek-chat", "deepseek-reasoner"},
			RequiresAPIKey:  true,
			Description:     "DeepSeek API via OpenAI-compatible Chat Completions protocol.",
		},
		{
			ID:              "anthropic",
			Name:            "Anthropic Claude",
			Provider:        ProviderAnthropic,
			BaseURL:         "https://api.anthropic.com",
			DefaultModel:    "claude-sonnet-4-20250514",
			SuggestedModels: []string{"claude-sonnet-4-20250514", "claude-3-7-sonnet-latest", "claude-3-5-haiku-latest"},
			RequiresAPIKey:  true,
			Description:     "Anthropic Messages API using x-api-key header authentication.",
		},
		{
			ID:              "gemini",
			Name:            "Google Gemini",
			Provider:        ProviderGemini,
			BaseURL:         "https://generativelanguage.googleapis.com",
			DefaultModel:    "gemini-2.5-pro",
			SuggestedModels: []string{"gemini-2.5-pro", "gemini-2.5-flash"},
			RequiresAPIKey:  true,
			Description:     "Google Gemini generateContent API using x-goog-api-key header authentication.",
		},
		{
			ID:              "qwen",
			Name:            "Qwen / DashScope",
			Provider:        ProviderOpenAICompat,
			BaseURL:         "https://dashscope.aliyuncs.com/compatible-mode/v1",
			DefaultModel:    "qwen-plus",
			SuggestedModels: []string{"qwen-plus", "qwen-max", "qwen-coder-plus"},
			RequiresAPIKey:  true,
			Description:     "Alibaba Cloud DashScope OpenAI-compatible endpoint for Qwen models.",
		},
		{
			ID:              "ollama",
			Name:            "Local Ollama",
			Provider:        ProviderOllama,
			BaseURL:         "http://127.0.0.1:11434",
			DefaultModel:    "qwen2.5-coder:14b",
			SuggestedModels: []string{"qwen2.5-coder:14b", "deepseek-r1:14b", "llama3.1:8b"},
			RequiresAPIKey:  false,
			Description:     "Local Ollama server (/api/chat) for offline/private diagnosis.",
		},
	}
}

// HealAttemptSummary carries compact history from earlier repair iterations so
// the model avoids repeating failed patches.
type HealAttemptSummary struct {
	Attempt          int    `json:"attempt"`
	ErrorFingerprint string `json:"error_fingerprint,omitempty"`
	ErrorExcerpt     string `json:"error_excerpt"`
	RootCause        string `json:"root_cause,omitempty"`
	FixKind          string `json:"fix_kind,omitempty"`
	Outcome          string `json:"outcome"`
	UnifiedDiff      string `json:"unified_diff,omitempty"`
}

// DiagnoseRequest describes a failure context submitted for AI diagnosis and fix synthesis.
type DiagnoseRequest struct {
	Scope            string               `json:"scope"`
	Code             string               `json:"code,omitempty"`
	Language         string               `json:"language,omitempty"`
	ErrorText        string               `json:"error_text,omitempty"`
	Logs             string               `json:"logs,omitempty"`
	Metadata         map[string]string    `json:"metadata,omitempty"`
	PreviousAttempts []HealAttemptSummary `json:"previous_attempts,omitempty"`
	Locale           string               `json:"locale,omitempty"`
	ProfileID        string               `json:"profile_id,omitempty"`
}

// PatchValidation holds syntax and safety validation results for a proposed code patch.
type PatchValidation struct {
	Passed    bool     `json:"passed"`
	Validator string   `json:"validator"`
	Issues    []string `json:"issues,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// DiagnoseResult holds the structured output of one AI diagnosis call.
type DiagnoseResult struct {
	RootCause        string            `json:"root_cause"`
	ErrorCategory    string            `json:"error_category"`
	Confidence       float64           `json:"confidence"`
	FixKind          string            `json:"fix_kind"`
	Explanation      string            `json:"explanation"`
	PatchedCode      string            `json:"patched_code,omitempty"`
	UnifiedDiff      string            `json:"unified_diff,omitempty"`
	ConfigChanges    map[string]string `json:"config_changes,omitempty"`
	CommandHints     []string          `json:"command_hints,omitempty"`
	VerifyHint       string            `json:"verify_hint,omitempty"`
	Validation       *PatchValidation  `json:"validation,omitempty"`
	PreDiagnosis     string            `json:"pre_diagnosis,omitempty"`
	RedactedCount    int               `json:"redacted_count"`
	ProviderUsed     string            `json:"provider_used"`
	ModelUsed        string            `json:"model_used"`
	ElapsedMs        int64             `json:"elapsed_ms"`
	PromptTokens     int               `json:"prompt_tokens,omitempty"`
	CompletionTokens int               `json:"completion_tokens,omitempty"`
}

// AutoHealEvent reports real-time progress during RunAutoHealLoop.
type AutoHealEvent struct {
	Attempt    int             `json:"attempt"`
	MaxRetries int             `json:"max_retries"`
	Phase      string          `json:"phase"`
	Message    string          `json:"message"`
	ExitCode   int             `json:"exit_code"`
	Diagnosis  *DiagnoseResult `json:"diagnosis,omitempty"`
	Timestamp  string          `json:"timestamp"`
}

// AutoHealAttempt records one execution/repair cycle in RunAutoHealLoop.
type AutoHealAttempt struct {
	Attempt          int             `json:"attempt"`
	ExitCode         int             `json:"exit_code"`
	Logs             string          `json:"logs"`
	ErrorFingerprint string          `json:"error_fingerprint,omitempty"`
	Diagnosis        *DiagnoseResult `json:"diagnosis,omitempty"`
	AppliedPatch     bool            `json:"applied_patch"`
	Outcome          string          `json:"outcome"`
	ElapsedMs        int64           `json:"elapsed_ms"`
}

// AutoHealRunResult summarizes the final state of a self-healing loop execution.
type AutoHealRunResult struct {
	Healed         bool              `json:"healed"`
	StopReason     string            `json:"stop_reason"`
	FinalCode      string            `json:"final_code"`
	FinalExitCode  int               `json:"final_exit_code"`
	FinalLogs      string            `json:"final_logs"`
	Attempts       []AutoHealAttempt `json:"attempts"`
	TotalElapsedMs int64             `json:"total_elapsed_ms"`
}

// TestConnectionResult reports the outcome of probing an AI provider profile.
type TestConnectionResult struct {
	OK        bool   `json:"ok"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Reply     string `json:"reply,omitempty"`
	Error     string `json:"error,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
}

// IsValidProvider reports whether p is one of the 4 supported provider identifiers.
func IsValidProvider(p string) bool {
	switch strings.TrimSpace(p) {
	case ProviderOpenAICompat, ProviderAnthropic, ProviderGemini, ProviderOllama:
		return true
	default:
		return false
	}
}

// NormalizeScope maps arbitrary scope input to a canonical cap AI scope.
func NormalizeScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case ScopeUnidbg:
		return ScopeUnidbg
	case ScopeQiling:
		return ScopeQiling
	case ScopeAngr:
		return ScopeAngr
	case ScopeFrida:
		return ScopeFrida
	case ScopePlugin:
		return ScopePlugin
	case ScopeSigner:
		return ScopeSigner
	case ScopeToolchain:
		return ScopeToolchain
	case ScopeRecon:
		return ScopeRecon
	default:
		return ScopeGeneral
	}
}

// NormalizeLocale returns "zh-CN" for Chinese locales and "en" otherwise.
func NormalizeLocale(locale string) string {
	low := strings.ToLower(strings.TrimSpace(locale))
	if strings.HasPrefix(low, "zh") {
		return "zh-CN"
	}
	return "en"
}

// MaskAPIKey returns a masked preview that never exposes a usable raw API key.
func MaskAPIKey(key string) string {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return ""
	}
	runes := []rune(trimmed)
	if len(runes) <= 4 {
		return "••••"
	}
	if len(runes) <= 8 {
		return string(runes[:2]) + "••••"
	}
	return string(runes[:4]) + "••••" + string(runes[len(runes)-4:])
}

// IsMaskedAPIKey reports whether s looks like a masked placeholder rather than a fresh key.
func IsMaskedAPIKey(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, "••••") || strings.Contains(trimmed, "****") {
		return true
	}
	return trimmed == "[REDACTED]"
}
