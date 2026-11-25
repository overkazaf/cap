package ai

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/overkazaf/cap/internal/redaction"
)

const configFileName = "ai.json"

// ConfigStore manages thread-safe persistence of AIConfig in <capDir>/ai.json
// using atomic temp-file writes with strict 0600 permissions.
type ConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  AIConfig
}

// NewConfigStore opens or initializes the AI configuration store in capDir.
func NewConfigStore(capDir string) (*ConfigStore, error) {
	dir := strings.TrimSpace(capDir)
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			dir = filepath.Join(home, ".cap")
		} else {
			dir = filepath.Join(os.TempDir(), "cap")
		}
	}
	path := filepath.Join(dir, configFileName)
	s := &ConfigStore{
		path: path,
		cfg:  defaultAIConfig(),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func defaultAIConfig() AIConfig {
	return AIConfig{
		ActiveProfileID: "",
		Profiles:        []ProviderConfig{},
		AutoHealEnabled: false,
		MaxAutoRetries:  DefaultMaxAutoRetries,
		RedactSecrets:   true,
	}
}

// Path returns the full filesystem path to ai.json.
func (s *ConfigStore) Path() string {
	return s.path
}

func (s *ConfigStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read AI config: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	cfg := defaultAIConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse AI config: %w", err)
	}
	s.cfg = normalizeAIConfig(cfg)
	return nil
}

func normalizeAIConfig(cfg AIConfig) AIConfig {
	if cfg.Profiles == nil {
		cfg.Profiles = []ProviderConfig{}
	}
	cfg.MaxAutoRetries = normalizeMaxAutoRetries(cfg.MaxAutoRetries)
	seen := make(map[string]struct{}, len(cfg.Profiles))
	cleaned := make([]ProviderConfig, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		p = normalizeProfileDefaults(p)
		if p.ID == "" {
			continue
		}
		if _, dup := seen[p.ID]; dup {
			continue
		}
		seen[p.ID] = struct{}{}
		cleaned = append(cleaned, p)
	}
	cfg.Profiles = cleaned
	if cfg.ActiveProfileID != "" {
		if _, ok := seen[cfg.ActiveProfileID]; !ok {
			cfg.ActiveProfileID = ""
		}
	}
	return cfg
}

func normalizeMaxAutoRetries(v int) int {
	if v <= 0 {
		return DefaultMaxAutoRetries
	}
	if v < MinAutoRetries {
		return MinAutoRetries
	}
	if v > MaxAutoRetriesLimit {
		return MaxAutoRetriesLimit
	}
	return v
}

func normalizeProfileDefaults(p ProviderConfig) ProviderConfig {
	p = p.Clone()
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.Provider = strings.TrimSpace(p.Provider)
	p.BaseURL = strings.TrimRight(strings.TrimSpace(p.BaseURL), "/")
	p.Model = strings.TrimSpace(p.Model)
	p.APIKey = strings.TrimSpace(p.APIKey)
	p.ClearAPIKey = false

	if p.Name == "" && p.Provider != "" {
		if p.Model != "" {
			p.Name = p.Provider + " (" + p.Model + ")"
		} else {
			p.Name = p.Provider
		}
	}
	if p.MaxTokens <= 0 {
		p.MaxTokens = DefaultMaxTokens
	} else if p.MaxTokens > MaxTokensLimit {
		p.MaxTokens = MaxTokensLimit
	}
	if p.Temperature < 0 {
		p.Temperature = 0
	} else if p.Temperature > 2 {
		p.Temperature = 2
	}
	if p.TimeoutSec <= 0 {
		p.TimeoutSec = DefaultTimeoutSec
	} else if p.TimeoutSec < MinTimeoutSec {
		p.TimeoutSec = MinTimeoutSec
	} else if p.TimeoutSec > MaxTimeoutSec {
		p.TimeoutSec = MaxTimeoutSec
	}
	return p
}

// GetConfig returns a deep copy of the full AIConfig (for internal use).
func (s *ConfigStore) GetConfig() AIConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Clone()
}

// GetPublicConfig returns a safe snapshot with all API keys masked and
// sensitive ExtraHeaders redacted.
func (s *ConfigStore) GetPublicConfig() PublicAIConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pub := PublicAIConfig{
		ActiveProfileID: s.cfg.ActiveProfileID,
		Profiles:        make([]PublicProviderConfig, len(s.cfg.Profiles)),
		AutoHealEnabled: s.cfg.AutoHealEnabled,
		MaxAutoRetries:  s.cfg.MaxAutoRetries,
		RedactSecrets:   s.cfg.RedactSecrets,
	}
	for i, p := range s.cfg.Profiles {
		pub.Profiles[i] = toPublicProviderConfig(p)
	}
	return pub
}

func toPublicProviderConfig(p ProviderConfig) PublicProviderConfig {
	var safeHeaders map[string]string
	if len(p.ExtraHeaders) > 0 {
		safeHeaders = redaction.Headers(p.ExtraHeaders)
	}
	return PublicProviderConfig{
		ID:            p.ID,
		Name:          p.Name,
		Provider:      p.Provider,
		BaseURL:       p.BaseURL,
		APIKeyPreview: MaskAPIKey(p.APIKey),
		HasAPIKey:     strings.TrimSpace(p.APIKey) != "",
		Model:         p.Model,
		MaxTokens:     p.MaxTokens,
		Temperature:   p.Temperature,
		TimeoutSec:    p.TimeoutSec,
		ExtraHeaders:  safeHeaders,
		Enabled:       p.Enabled,
	}
}

// GetProfile looks up a profile by ID and returns a deep copy.
func (s *ConfigStore) GetProfile(id string) (ProviderConfig, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return ProviderConfig{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.cfg.Profiles {
		if p.ID == id {
			return p.Clone(), true
		}
	}
	return ProviderConfig{}, false
}

// GetActiveProfile returns the currently active profile, if configured.
func (s *ConfigStore) GetActiveProfile() (ProviderConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.ActiveProfileID == "" {
		return ProviderConfig{}, false
	}
	for _, p := range s.cfg.Profiles {
		if p.ID == s.cfg.ActiveProfileID {
			return p.Clone(), true
		}
	}
	return ProviderConfig{}, false
}

// UpsertProfile creates or updates a provider profile.
// Updating an existing profile with an empty or masked APIKey preserves the
// previously stored API key unless ClearAPIKey is true.
func (s *ConfigStore) UpsertProfile(input ProviderConfig) (PublicProviderConfig, error) {
	if !IsValidProvider(input.Provider) {
		return PublicProviderConfig{}, fmt.Errorf("unsupported AI provider %q", input.Provider)
	}
	if _, err := ValidateBaseURL(input.BaseURL); err != nil {
		return PublicProviderConfig{}, fmt.Errorf("invalid base_url: %w", err)
	}
	if strings.TrimSpace(input.Model) == "" {
		return PublicProviderConfig{}, errors.New("model is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	clearKey := input.ClearAPIKey
	rawIncomingKey := strings.TrimSpace(input.APIKey)

	p := normalizeProfileDefaults(input)
	if p.ID == "" {
		p.ID = generateProfileID(p.Provider)
	}

	// Reject header keys/values containing CR/LF to prevent header injection.
	if len(p.ExtraHeaders) > 0 {
		cleanHeaders := make(map[string]string, len(p.ExtraHeaders))
		for k, v := range p.ExtraHeaders {
			kt := strings.TrimSpace(k)
			if kt == "" || strings.ContainsAny(kt, "\r\n") || strings.ContainsAny(v, "\r\n") {
				return PublicProviderConfig{}, fmt.Errorf("invalid extra header %q", k)
			}
			cleanHeaders[kt] = v
		}
		p.ExtraHeaders = cleanHeaders
	}

	foundIdx := -1
	for i, existing := range next.Profiles {
		if existing.ID == p.ID {
			foundIdx = i
			break
		}
	}

	if foundIdx >= 0 {
		existing := next.Profiles[foundIdx]
		switch {
		case clearKey:
			p.APIKey = ""
		case rawIncomingKey == "" || IsMaskedAPIKey(rawIncomingKey) || (existing.APIKey != "" && rawIncomingKey == MaskAPIKey(existing.APIKey)):
			p.APIKey = existing.APIKey
		default:
			p.APIKey = rawIncomingKey
		}

		// Preserve existing sensitive ExtraHeaders if caller echoed back [REDACTED].
		if len(p.ExtraHeaders) > 0 && len(existing.ExtraHeaders) > 0 {
			merged := make(map[string]string, len(p.ExtraHeaders))
			maps.Copy(merged, p.ExtraHeaders)
			for k, v := range merged {
				if v == redaction.Placeholder {
					if oldVal, ok := existing.ExtraHeaders[k]; ok {
						merged[k] = oldVal
					}
				}
			}
			p.ExtraHeaders = merged
		}
		next.Profiles[foundIdx] = p
	} else {
		if clearKey || IsMaskedAPIKey(rawIncomingKey) {
			p.APIKey = ""
		}
		next.Profiles = append(next.Profiles, p)
		if next.ActiveProfileID == "" && p.Enabled {
			next.ActiveProfileID = p.ID
		}
	}

	if err := s.persistLocked(next); err != nil {
		return PublicProviderConfig{}, err
	}
	s.cfg = next
	return toPublicProviderConfig(p), nil
}

// DeleteProfile removes a profile by ID and updates ActiveProfileID if needed.
func (s *ConfigStore) DeleteProfile(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("profile id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	idx := -1
	for i, p := range next.Profiles {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("AI profile %q not found", id)
	}

	next.Profiles = append(next.Profiles[:idx], next.Profiles[idx+1:]...)
	if next.ActiveProfileID == id {
		next.ActiveProfileID = ""
		for _, p := range next.Profiles {
			if p.Enabled {
				next.ActiveProfileID = p.ID
				break
			}
		}
	}

	if err := s.persistLocked(next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

// SetActiveProfile selects the active profile ID (or "" to clear selection).
func (s *ConfigStore) SetActiveProfile(id string) error {
	id = strings.TrimSpace(id)

	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	if id != "" {
		found := false
		for _, p := range next.Profiles {
			if p.ID == id {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("AI profile %q not found", id)
		}
	}
	next.ActiveProfileID = id

	if err := s.persistLocked(next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

// UpdateSettings atomically updates top-level AI behavior flags.
func (s *ConfigStore) UpdateSettings(update AISettingsUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg.Clone()
	if update.AutoHealEnabled != nil {
		next.AutoHealEnabled = *update.AutoHealEnabled
	}
	if update.MaxAutoRetries != nil {
		v := *update.MaxAutoRetries
		if v < MinAutoRetries {
			v = MinAutoRetries
		} else if v > MaxAutoRetriesLimit {
			v = MaxAutoRetriesLimit
		}
		next.MaxAutoRetries = v
	}
	if update.RedactSecrets != nil {
		next.RedactSecrets = *update.RedactSecrets
	}

	if err := s.persistLocked(next); err != nil {
		return err
	}
	s.cfg = next
	return nil
}

func (s *ConfigStore) persistLocked(cfg AIConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal AI config: %w", err)
	}
	data = append(data, '\n')
	return writeFileAtomicPrivate(s.path, data)
}

// writeFileAtomicPrivate writes data to path via a same-directory temp file
// with strict 0600 permissions, fsync, and atomic rename.
func writeFileAtomicPrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create AI config directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp AI config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp AI config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp AI config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp AI config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp AI config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp AI config: %w", err)
	}
	cleanup = false
	return nil
}

func generateProfileID(provider string) string {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	prefix := strings.TrimSpace(provider)
	if prefix == "" {
		prefix = "profile"
	}
	return prefix + "-" + hex.EncodeToString(buf[:])
}
