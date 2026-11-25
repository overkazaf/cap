package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/fsutil"
)

const (
	fileAccounts            = "accounts.json"
	challengeWebhookTimeout = 5 * time.Second
	maxChallengeBodyPreview = 256
)

type persistedAccountPool struct {
	Config   AccountPoolConfig `json:"config"`
	Accounts []AccountProfile  `json:"accounts"`
}

// AccountCredentialUpdate holds refreshed credentials extracted from a refresh
// route response or explicit operator update.
type AccountCredentialUpdate struct {
	Token        string
	RefreshToken string
	Cookie       string
	Cookies      map[string]string
	AuthHeaders  map[string]string
	Tokens       map[string]string
	ExpiresAt    string
}

type accountRefreshFlight struct {
	done chan struct{}
	acc  *AccountProfile
	err  error
}

// AccountPool manages authenticated accounts/sessions with tag filtering,
// rotation strategies (round_robin, least_used, sticky_device), expiry checks,
// atomic 0600 JSON persistence, and per-account singleflight refresh locking.
type AccountPool struct {
	filePath string

	mu        sync.RWMutex
	persistMu sync.Mutex
	cfg       AccountPoolConfig
	accounts  map[string]AccountProfile
	rrCounter atomic.Uint64
	baseCtx   context.Context

	refreshMu sync.Mutex
	inflight  map[string]*accountRefreshFlight

	now func() time.Time
}

// NewAccountPool constructs a thread-safe AccountPool backed by filePath
// (if non-empty) with normalized default configuration.
func NewAccountPool(filePath string, cfg AccountPoolConfig) *AccountPool {
	return &AccountPool{
		filePath: strings.TrimSpace(filePath),
		cfg:      normalizeAccountPoolConfig(cfg),
		accounts: make(map[string]AccountProfile),
		inflight: make(map[string]*accountRefreshFlight),
		now:      time.Now,
	}
}

// SetBaseContext binds the pool's lifecycle context so in-flight refreshes
// cancel promptly when Manager.Shutdown() is invoked.
func (p *AccountPool) SetBaseContext(ctx context.Context) {
	p.mu.Lock()
	p.baseCtx = ctx
	p.mu.Unlock()
}

func (p *AccountPool) getBaseContext() context.Context {
	p.mu.RLock()
	ctx := p.baseCtx
	p.mu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func normalizeAccountPoolConfig(cfg AccountPoolConfig) AccountPoolConfig {
	switch strings.ToLower(strings.TrimSpace(cfg.Strategy)) {
	case StrategyRoundRobin, StrategyLeastUsed, StrategyStickyDevice:
		cfg.Strategy = strings.ToLower(strings.TrimSpace(cfg.Strategy))
	default:
		cfg.Strategy = StrategyRoundRobin
	}
	cfg.Refresh.RefreshRouteSlug = normalizeSlug(cfg.Refresh.RefreshRouteSlug)
	cfg.Refresh.RefreshOnBodySubstr = strings.TrimSpace(cfg.Refresh.RefreshOnBodySubstr)
	cfg.Refresh.ChallengeWebhookURL = strings.TrimSpace(cfg.Refresh.ChallengeWebhookURL)
	if cfg.Refresh.MaxRefreshAttempts < 0 {
		cfg.Refresh.MaxRefreshAttempts = 0
	}
	if cfg.Refresh.MaxRefreshAttempts > 5 {
		cfg.Refresh.MaxRefreshAttempts = 5
	}
	cfg.Refresh.RefreshOnStatuses = normalizeStatusCodes(cfg.Refresh.RefreshOnStatuses)
	return cfg
}

func normalizeStatusCodes(codes []int) []int {
	if len(codes) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(codes))
	out := make([]int, 0, len(codes))
	for _, c := range codes {
		if c < 100 || c > 599 {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Ints(out)
	return out
}

// Config returns a copy of the current AccountPoolConfig.
func (p *AccountPool) Config() AccountPoolConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneAccountPoolConfig(p.cfg)
}

// SetConfig updates AccountPoolConfig and persists to disk if configured.
func (p *AccountPool) SetConfig(cfg AccountPoolConfig) error {
	cfg = normalizeAccountPoolConfig(cfg)
	if cfg.Refresh.ChallengeWebhookURL != "" {
		if _, err := validateWebhookURL(cfg.Refresh.ChallengeWebhookURL); err != nil {
			return fmt.Errorf("invalid challenge_webhook_url: %w", err)
		}
	}
	p.mu.Lock()
	p.cfg = cloneAccountPoolConfig(cfg)
	p.mu.Unlock()
	return p.persist()
}

// LoadFromDisk loads persisted accounts and config from p.filePath if present.
func (p *AccountPool) LoadFromDisk() error {
	if p.filePath == "" {
		return nil
	}
	raw, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var persisted persistedAccountPool
	if err := json.Unmarshal(raw, &persisted); err != nil {
		return err
	}
	p.mu.Lock()
	p.cfg = normalizeAccountPoolConfig(persisted.Config)
	p.accounts = make(map[string]AccountProfile, len(persisted.Accounts))
	for _, acc := range persisted.Accounts {
		acc = normalizeAccountForLoad(acc)
		p.accounts[acc.ID] = cloneAccountProfile(acc)
	}
	p.mu.Unlock()
	return nil
}

// Load replaces in-memory accounts (used during programmatic initialization).
func (p *AccountPool) Load(accounts []AccountProfile) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accounts = make(map[string]AccountProfile, len(accounts))
	for _, acc := range accounts {
		acc = normalizeAccountForLoad(acc)
		p.accounts[acc.ID] = cloneAccountProfile(acc)
	}
}

func normalizeAccountForLoad(acc AccountProfile) AccountProfile {
	acc.ID = strings.TrimSpace(acc.ID)
	if acc.ID == "" {
		acc.ID = "acc-" + randomHex(4)
	}
	acc.Name = strings.TrimSpace(acc.Name)
	if acc.Name == "" {
		if acc.Username != "" {
			acc.Name = acc.Username
		} else {
			acc.Name = acc.ID
		}
	}
	acc.Tags = normalizeTags(acc.Tags)
	acc.Status = normalizeAccountStatus(acc.Status, acc.Enabled)
	return acc
}

func normalizeAccountStatus(status string, enabled bool) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case AccountStatusActive:
		if !enabled {
			return AccountStatusDisabled
		}
		return AccountStatusActive
	case AccountStatusExpired:
		return AccountStatusExpired
	case AccountStatusChallenged:
		return AccountStatusChallenged
	case AccountStatusDisabled:
		return AccountStatusDisabled
	default:
		if !enabled {
			return AccountStatusDisabled
		}
		return AccountStatusActive
	}
}

// List returns all accounts sorted deterministically by name then ID.
func (p *AccountPool) List() []AccountProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]AccountProfile, 0, len(p.accounts))
	for _, acc := range p.accounts {
		out = append(out, cloneAccountProfile(acc))
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if ni != nj {
			return ni < nj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns a cloned AccountProfile by ID.
func (p *AccountPool) Get(id string) (*AccountProfile, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	acc, ok := p.accounts[strings.TrimSpace(id)]
	if !ok {
		return nil, false
	}
	cp := cloneAccountProfile(acc)
	return &cp, true
}

// Upsert validates, normalizes, stores, and atomically persists an AccountProfile.
func (p *AccountPool) Upsert(acc AccountProfile) (*AccountProfile, error) {
	acc.Name = strings.TrimSpace(acc.Name)
	acc.Username = strings.TrimSpace(acc.Username)
	if acc.Name == "" {
		if acc.Username != "" {
			acc.Name = acc.Username
		} else {
			return nil, errors.New("account name or username is required")
		}
	}
	acc.ID = strings.TrimSpace(acc.ID)
	if acc.ID == "" {
		acc.ID = fmt.Sprintf("acc-%s-%s", sanitizeID(acc.Name, "user"), randomHex(4))
	}
	acc.Tags = normalizeTags(acc.Tags)
	acc.StickyDeviceID = strings.TrimSpace(acc.StickyDeviceID)
	acc.StickyProxyID = strings.TrimSpace(acc.StickyProxyID)
	acc.ExpiresAt = strings.TrimSpace(acc.ExpiresAt)
	if acc.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, acc.ExpiresAt); err != nil {
			return nil, fmt.Errorf("invalid expires_at timestamp (expected RFC3339): %w", err)
		}
	}
	acc.Status = normalizeAccountStatus(acc.Status, acc.Enabled)
	if acc.LastError != "" {
		acc.LastError = redactSecrets(acc.LastError, accountSecrets(&acc)...)
	}

	nowStr := p.now().UTC().Format(time.RFC3339)
	p.mu.Lock()
	if prev, exists := p.accounts[acc.ID]; exists {
		if acc.CreatedAt == "" {
			acc.CreatedAt = prev.CreatedAt
		}
		if acc.UseCount == 0 {
			acc.UseCount = prev.UseCount
		}
		if acc.FailCount == 0 {
			acc.FailCount = prev.FailCount
		}
		if acc.RefreshCount == 0 {
			acc.RefreshCount = prev.RefreshCount
		}
		if acc.LastUsedAt == "" {
			acc.LastUsedAt = prev.LastUsedAt
		}
		if acc.LastRefreshed == "" {
			acc.LastRefreshed = prev.LastRefreshed
		}
	}
	if acc.CreatedAt == "" {
		acc.CreatedAt = nowStr
	}
	acc.UpdatedAt = nowStr
	p.accounts[acc.ID] = cloneAccountProfile(acc)
	p.mu.Unlock()

	cp := cloneAccountProfile(acc)
	if err := p.persist(); err != nil {
		return &cp, err
	}
	return &cp, nil
}

// Delete removes an account profile by ID and persists the pool.
func (p *AccountPool) Delete(id string) error {
	id = strings.TrimSpace(id)
	p.mu.Lock()
	if _, ok := p.accounts[id]; !ok {
		p.mu.Unlock()
		return fmt.Errorf("account %q not found", id)
	}
	delete(p.accounts, id)
	p.mu.Unlock()
	return p.persist()
}

// Counts returns (total, activeNonExpired) account counts.
func (p *AccountPool) Counts() (total int, active int) {
	now := p.now().UTC()
	p.mu.RLock()
	defer p.mu.RUnlock()
	total = len(p.accounts)
	for _, acc := range p.accounts {
		if acc.Enabled && acc.Status == AccountStatusActive && !isAccountExpired(&acc, now) {
			active++
		}
	}
	return total, active
}

// IsExpired reports whether acc's status is expired or its ExpiresAt timestamp
// has elapsed relative to now.
func isAccountExpired(acc *AccountProfile, now time.Time) bool {
	if acc == nil {
		return true
	}
	if acc.Status == AccountStatusExpired {
		return true
	}
	if acc.ExpiresAt == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, acc.ExpiresAt)
	if err != nil {
		return false
	}
	return !now.Before(exp)
}

// Acquire selects an eligible AccountProfile honoring explicit ID, tag filter,
// expiry checks, sticky device binding, and rotation strategy.
func (p *AccountPool) Acquire(opts AccountSelectOptions) (*AccountProfile, error) {
	now := p.now().UTC()
	nowStr := now.Format(time.RFC3339)

	p.mu.Lock()
	defer p.mu.Unlock()

	if explicitID := strings.TrimSpace(opts.ExplicitID); explicitID != "" {
		acc, ok := p.accounts[explicitID]
		if !ok {
			return nil, fmt.Errorf("account %q not found", explicitID)
		}
		if !acc.Enabled || acc.Status == AccountStatusDisabled {
			return nil, fmt.Errorf("account %q is disabled", explicitID)
		}
		if acc.Status == AccountStatusChallenged && !opts.IncludeExpired {
			return nil, fmt.Errorf("account %q is challenged", explicitID)
		}
		if isAccountExpired(&acc, now) && !opts.IncludeExpired {
			return nil, fmt.Errorf("account %q is expired", explicitID)
		}
		acc.UseCount++
		acc.LastUsedAt = nowStr
		p.accounts[explicitID] = acc
		cp := cloneAccountProfile(acc)
		return &cp, nil
	}

	strategy := strings.ToLower(strings.TrimSpace(opts.Strategy))
	if strategy == "" {
		strategy = p.cfg.Strategy
	}
	if strategy == "" {
		strategy = StrategyRoundRobin
	}

	var activeCandidates []AccountProfile
	var expiredCandidates []AccountProfile
	for _, acc := range p.accounts {
		if !acc.Enabled || acc.Status == AccountStatusDisabled || acc.Status == AccountStatusChallenged {
			continue
		}
		if !hasAllTags(acc.Tags, opts.Tags) {
			continue
		}
		if isAccountExpired(&acc, now) {
			if opts.IncludeExpired {
				expiredCandidates = append(expiredCandidates, acc)
			}
			continue
		}
		activeCandidates = append(activeCandidates, acc)
	}

	candidates := activeCandidates
	if len(candidates) == 0 && opts.IncludeExpired {
		candidates = expiredCandidates
	}
	if len(candidates) == 0 {
		return nil, errors.New("no active account available matching criteria")
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ID < candidates[j].ID
	})

	var chosen AccountProfile
	deviceID := strings.TrimSpace(opts.DeviceID)

	if strategy == StrategyStickyDevice && deviceID != "" {
		foundSticky := false
		for _, c := range candidates {
			if strings.EqualFold(c.StickyDeviceID, deviceID) {
				chosen = c
				foundSticky = true
				break
			}
		}
		if !foundSticky {
			// Prefer unbound accounts before borrowing an account bound to another device.
			var unbound []AccountProfile
			for _, c := range candidates {
				if c.StickyDeviceID == "" {
					unbound = append(unbound, c)
				}
			}
			pool := candidates
			if len(unbound) > 0 {
				pool = unbound
			}
			idx := p.rrCounter.Add(1) - 1
			chosen = pool[idx%uint64(len(pool))]
		}
	} else {
		switch strategy {
		case StrategyLeastUsed:
			bestIdx := 0
			for i := 1; i < len(candidates); i++ {
				if candidates[i].UseCount < candidates[bestIdx].UseCount ||
					(candidates[i].UseCount == candidates[bestIdx].UseCount && candidates[i].LastUsedAt < candidates[bestIdx].LastUsedAt) {
					bestIdx = i
				}
			}
			chosen = candidates[bestIdx]
		default: // round_robin (or sticky_device without a deviceID)
			idx := p.rrCounter.Add(1) - 1
			chosen = candidates[idx%uint64(len(candidates))]
		}
	}

	chosen.UseCount++
	chosen.LastUsedAt = nowStr
	p.accounts[chosen.ID] = chosen

	cp := cloneAccountProfile(chosen)
	return &cp, nil
}

// MarkExpired marks an account expired with redacted reason and persists.
func (p *AccountPool) MarkExpired(id string, reason string) error {
	id = strings.TrimSpace(id)
	p.mu.Lock()
	acc, ok := p.accounts[id]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("account %q not found", id)
	}
	acc.Status = AccountStatusExpired
	acc.FailCount++
	acc.LastError = redactSecrets(strings.TrimSpace(reason), accountSecrets(&acc)...)
	acc.UpdatedAt = p.now().UTC().Format(time.RFC3339)
	p.accounts[id] = acc
	p.mu.Unlock()
	return p.persist()
}

// MarkChallenged marks an account challenged (non-refreshable risk control) and persists.
func (p *AccountPool) MarkChallenged(id string, reason string) error {
	id = strings.TrimSpace(id)
	p.mu.Lock()
	acc, ok := p.accounts[id]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("account %q not found", id)
	}
	acc.Status = AccountStatusChallenged
	acc.FailCount++
	acc.LastError = redactSecrets(strings.TrimSpace(reason), accountSecrets(&acc)...)
	acc.UpdatedAt = p.now().UTC().Format(time.RFC3339)
	p.accounts[id] = acc
	p.mu.Unlock()
	return p.persist()
}

// MarkHealthy marks an account active, clears LastError, and clears any
// elapsed ExpiresAt timestamp so explicitly healed accounts become acquirable.
func (p *AccountPool) MarkHealthy(id string) error {
	id = strings.TrimSpace(id)
	now := p.now().UTC()
	p.mu.Lock()
	acc, ok := p.accounts[id]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("account %q not found", id)
	}
	if acc.Enabled {
		acc.Status = AccountStatusActive
	}
	if acc.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, acc.ExpiresAt); err == nil && !now.Before(exp) {
			acc.ExpiresAt = ""
		}
	}
	acc.LastError = ""
	acc.UpdatedAt = now.Format(time.RFC3339)
	p.accounts[id] = acc
	p.mu.Unlock()
	return p.persist()
}

// UpdateCredentials merges updated tokens, cookies, headers, and expiry into an
// AccountProfile, marks it active, increments RefreshCount, and persists 0600.
func (p *AccountPool) UpdateCredentials(id string, upd AccountCredentialUpdate) (*AccountProfile, error) {
	id = strings.TrimSpace(id)
	nowStr := p.now().UTC().Format(time.RFC3339)

	p.mu.Lock()
	acc, ok := p.accounts[id]
	if !ok {
		p.mu.Unlock()
		return nil, fmt.Errorf("account %q not found", id)
	}
	if strings.TrimSpace(upd.Token) != "" {
		acc.Token = strings.TrimSpace(upd.Token)
	}
	if strings.TrimSpace(upd.RefreshToken) != "" {
		acc.RefreshToken = strings.TrimSpace(upd.RefreshToken)
	}
	if strings.TrimSpace(upd.Cookie) != "" {
		acc.Cookie = strings.TrimSpace(upd.Cookie)
	}
	if len(upd.Cookies) > 0 {
		if acc.Cookies == nil {
			acc.Cookies = make(map[string]string, len(upd.Cookies))
		}
		for k, v := range upd.Cookies {
			if strings.TrimSpace(k) != "" {
				acc.Cookies[strings.TrimSpace(k)] = v
			}
		}
	}
	if len(upd.AuthHeaders) > 0 {
		if acc.AuthHeaders == nil {
			acc.AuthHeaders = make(map[string]string, len(upd.AuthHeaders))
		}
		for k, v := range upd.AuthHeaders {
			if strings.TrimSpace(k) != "" {
				setHeaderFold(acc.AuthHeaders, strings.TrimSpace(k), v)
			}
		}
	}
	if len(upd.Tokens) > 0 {
		if acc.Tokens == nil {
			acc.Tokens = make(map[string]string, len(upd.Tokens))
		}
		for k, v := range upd.Tokens {
			if strings.TrimSpace(k) != "" {
				acc.Tokens[strings.TrimSpace(k)] = v
			}
		}
	}
	if strings.TrimSpace(upd.ExpiresAt) != "" {
		acc.ExpiresAt = strings.TrimSpace(upd.ExpiresAt)
	} else {
		// If account had an expired timestamp in the past and refresh succeeded
		// without returning a new expiry, clear stale ExpiresAt so it becomes usable.
		if isAccountExpired(&acc, p.now().UTC()) {
			acc.ExpiresAt = ""
		}
	}
	if acc.Enabled {
		acc.Status = AccountStatusActive
	}
	acc.LastError = ""
	acc.RefreshCount++
	acc.LastRefreshed = nowStr
	acc.UpdatedAt = nowStr
	p.accounts[id] = acc
	cp := cloneAccountProfile(acc)
	p.mu.Unlock()

	if err := p.persist(); err != nil {
		return &cp, err
	}
	return &cp, nil
}

// RefreshSingleflight ensures concurrent callers observing an expired session
// for the same account execute refreshFn AT MOST ONCE. Callers arriving after
// another goroutine already completed the refresh (observed via RefreshCount or
// changed credentials) receive the already-refreshed AccountProfile immediately.
func (p *AccountPool) RefreshSingleflight(
	ctx context.Context,
	accountID string,
	seenRefreshCount int64,
	seenToken string,
	seenCookie string,
	refreshFn func(context.Context) (AccountCredentialUpdate, error),
) (*AccountProfile, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, errors.New("account ID is required for refresh")
	}
	if isRefreshingAccountInCtx(ctx, accountID) {
		return nil, fmt.Errorf("re-entrant refresh blocked for account %q", accountID)
	}

	p.refreshMu.Lock()
	// 1. Join an already-running refresh flight for this account.
	if flight, exists := p.inflight[accountID]; exists {
		p.refreshMu.Unlock()
		select {
		case <-flight.done:
			if flight.err != nil {
				return nil, flight.err
			}
			if flight.acc == nil {
				return nil, errors.New("account refresh produced empty profile")
			}
			cp := cloneAccountProfile(*flight.acc)
			return &cp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// 2. Check if another caller already refreshed this account while we were in-flight.
	if cur, ok := p.Get(accountID); ok {
		if cur.Enabled && cur.Status == AccountStatusActive && !isAccountExpired(cur, p.now().UTC()) {
			if cur.RefreshCount > seenRefreshCount ||
				(seenToken != "" && cur.EffectiveToken() != seenToken) ||
				(seenCookie != "" && cur.EffectiveCookie() != seenCookie) {
				p.refreshMu.Unlock()
				return cur, nil
			}
		}
	}

	// 3. Become the singleflight leader for this account.
	flight := &accountRefreshFlight{done: make(chan struct{})}
	p.inflight[accountID] = flight
	p.refreshMu.Unlock()

	defer func() {
		p.refreshMu.Lock()
		delete(p.inflight, accountID)
		p.refreshMu.Unlock()
		close(flight.done)
	}()

	// Detach from leader's per-request cancellation while tying to Manager
	// lifecycle context (so Shutdown cancels promptly) and preserving any
	// refresh recursion state on the context.
	base := p.getBaseContext()
	if prevSt := getRefreshCtxState(ctx); prevSt != nil {
		base = context.WithValue(base, refreshCtxKey{}, prevSt)
	}
	runCtx, cancel := context.WithTimeout(base, 30*time.Second)
	defer cancel()

	upd, err := refreshFn(runCtx)
	if err != nil {
		_ = p.MarkExpired(accountID, err.Error())
		flight.err = err
		return nil, err
	}

	updated, err := p.UpdateCredentials(accountID, upd)
	if err != nil && updated == nil {
		flight.err = err
		return nil, err
	}
	flight.acc = updated
	cp := cloneAccountProfile(*updated)
	return &cp, nil
}

func (p *AccountPool) persist() error {
	if p.filePath == "" {
		return nil
	}
	p.persistMu.Lock()
	defer p.persistMu.Unlock()
	payload := persistedAccountPool{
		Config:   p.Config(),
		Accounts: p.List(),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(p.filePath, data, 0o600)
}

// EffectiveToken returns the primary bearer/session token for an account.
func (a *AccountProfile) EffectiveToken() string {
	if a == nil {
		return ""
	}
	if strings.TrimSpace(a.Token) != "" {
		return strings.TrimSpace(a.Token)
	}
	if v := lookupMapFold(a.Tokens, "access_token"); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v := lookupMapFold(a.Tokens, "token"); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

// EffectiveCookie combines raw Cookie string and structured Cookies map into a
// deterministic Cookie header string.
func (a *AccountProfile) EffectiveCookie() string {
	if a == nil {
		return ""
	}
	raw := strings.TrimSpace(a.Cookie)
	if len(a.Cookies) == 0 {
		return raw
	}
	if raw == "" {
		return formatCookieHeader(a.Cookies)
	}
	merged := parseCookieHeader(raw)
	for k, v := range a.Cookies {
		if strings.TrimSpace(k) != "" {
			merged[strings.TrimSpace(k)] = v
		}
	}
	return formatCookieHeader(merged)
}

func parseCookieHeader(raw string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// accountSecrets returns all sensitive credential strings held by an account
// (including bare Bearer/Basic/Token values and individual cookie values) so
// URLs, logs, errors, and webhook alerts never leak secrets.
func accountSecrets(acc *AccountProfile) []string {
	if acc == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	addAuthValue := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		add(v)
		for _, prefix := range []string{"Bearer ", "Token ", "Basic "} {
			if rest, ok := cutPrefixFold(v, prefix); ok {
				if bare := strings.TrimSpace(rest); len(bare) >= 4 {
					add(bare)
				}
			}
		}
	}

	addAuthValue(acc.Token)
	add(acc.RefreshToken)
	add(acc.Cookie)
	for _, v := range parseCookieHeader(acc.Cookie) {
		if len(strings.TrimSpace(v)) >= 4 {
			add(v)
		}
	}
	for _, v := range acc.Cookies {
		if len(strings.TrimSpace(v)) >= 4 {
			add(v)
		}
	}
	for _, v := range acc.Tokens {
		addAuthValue(v)
	}
	for _, v := range acc.AuthHeaders {
		if len(strings.TrimSpace(v)) >= 4 {
			addAuthValue(v)
		}
	}
	return out
}

func resolveAccountField(acc *AccountProfile, field string) string {
	if acc == nil {
		return ""
	}
	if key, ok := cutPrefixFold(field, "token."); ok {
		if v := lookupMapFold(acc.Tokens, key); v != "" {
			return v
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "default", "access_token", "token":
			return acc.EffectiveToken()
		case "refresh_token":
			return acc.RefreshToken
		}
		return ""
	}
	if key, ok := cutPrefixFold(field, "tokens."); ok {
		return lookupMapFold(acc.Tokens, key)
	}
	if key, ok := cutPrefixFold(field, "header."); ok {
		return lookupMapFold(acc.AuthHeaders, key)
	}
	if key, ok := cutPrefixFold(field, "auth."); ok {
		return lookupMapFold(acc.AuthHeaders, key)
	}
	if key, ok := cutPrefixFold(field, "cookie."); ok {
		if v := lookupMapFold(acc.Cookies, key); v != "" {
			return v
		}
		if acc.Cookie != "" {
			return lookupMapFold(parseCookieHeader(acc.Cookie), key)
		}
		return ""
	}
	if key, ok := cutPrefixFold(field, "cookies."); ok {
		if v := lookupMapFold(acc.Cookies, key); v != "" {
			return v
		}
		if acc.Cookie != "" {
			return lookupMapFold(parseCookieHeader(acc.Cookie), key)
		}
		return ""
	}

	switch strings.ToLower(strings.TrimSpace(field)) {
	case "id":
		return acc.ID
	case "name":
		return acc.Name
	case "username", "user":
		return acc.Username
	case "token", "access_token":
		return acc.EffectiveToken()
	case "refresh_token":
		return acc.RefreshToken
	case "cookie":
		return acc.EffectiveCookie()
	case "sticky_device_id":
		return acc.StickyDeviceID
	case "sticky_proxy_id":
		return acc.StickyProxyID
	default:
		return ""
	}
}

// extractCredentialsFromRefreshResult parses refreshed tokens/cookies/headers/expiry
// from a refresh route's TestInvokeResult (JSON body and Set-Cookie headers).
func extractCredentialsFromRefreshResult(res *TestInvokeResult, now time.Time) (AccountCredentialUpdate, error) {
	if res == nil {
		return AccountCredentialUpdate{}, errors.New("refresh route returned nil result")
	}
	if res.Status < 200 || res.Status >= 300 {
		return AccountCredentialUpdate{}, fmt.Errorf("refresh route returned HTTP %d", res.Status)
	}

	var upd AccountCredentialUpdate
	hasAny := false

	trimmed := strings.TrimSpace(res.Body)
	if strings.HasPrefix(trimmed, "{") {
		var root map[string]any
		if err := json.Unmarshal([]byte(trimmed), &root); err == nil {
			source := root
			if inner, ok := root["data"].(map[string]any); ok {
				if !hasRefreshKeys(root) && hasRefreshKeys(inner) {
					source = inner
				}
			}

			for _, k := range []string{"token", "access_token", "accessToken", "jwt"} {
				if v, ok := source[k]; ok && v != nil {
					if s := strings.TrimSpace(stringifyScalar(v)); s != "" {
						upd.Token = s
						hasAny = true
						break
					}
				}
			}
			for _, k := range []string{"refresh_token", "refreshToken"} {
				if v, ok := source[k]; ok && v != nil {
					if s := strings.TrimSpace(stringifyScalar(v)); s != "" {
						upd.RefreshToken = s
						hasAny = true
						break
					}
				}
			}
			if v, ok := source["cookie"]; ok && v != nil {
				if s := strings.TrimSpace(stringifyScalar(v)); s != "" {
					upd.Cookie = s
					hasAny = true
				}
			}
			if cm, ok := source["cookies"].(map[string]any); ok && len(cm) > 0 {
				upd.Cookies = make(map[string]string, len(cm))
				for k, v := range cm {
					if strings.TrimSpace(k) != "" {
						upd.Cookies[strings.TrimSpace(k)] = stringifyScalar(v)
						hasAny = true
					}
				}
			}
			if hm, ok := source["headers"].(map[string]any); ok && len(hm) > 0 {
				upd.AuthHeaders = make(map[string]string, len(hm))
				for k, v := range hm {
					if strings.TrimSpace(k) != "" {
						upd.AuthHeaders[strings.TrimSpace(k)] = stringifyScalar(v)
						hasAny = true
					}
				}
			}
			if tm, ok := source["tokens"].(map[string]any); ok && len(tm) > 0 {
				upd.Tokens = make(map[string]string, len(tm))
				for k, v := range tm {
					if strings.TrimSpace(k) != "" {
						upd.Tokens[strings.TrimSpace(k)] = stringifyScalar(v)
						hasAny = true
					}
				}
			}
			if expRaw, ok := source["expires_in"]; ok && expRaw != nil {
				if sec, err := strconv.ParseInt(strings.TrimSpace(stringifyScalar(expRaw)), 10, 64); err == nil && sec > 0 {
					upd.ExpiresAt = now.UTC().Add(time.Duration(sec) * time.Second).Format(time.RFC3339)
				}
			} else if expAtRaw, ok := source["expires_at"]; ok && expAtRaw != nil {
				s := strings.TrimSpace(stringifyScalar(expAtRaw))
				if _, err := time.Parse(time.RFC3339, s); err == nil {
					upd.ExpiresAt = s
				} else if unixSec, err := strconv.ParseInt(s, 10, 64); err == nil && unixSec > 0 {
					upd.ExpiresAt = time.Unix(unixSec, 0).UTC().Format(time.RFC3339)
				}
			}
		}
	}

	// Also harvest Set-Cookie response headers if present.
	if setCookie := lookupMapFold(res.Headers, "Set-Cookie"); strings.TrimSpace(setCookie) != "" {
		parsed := extractSetCookiePairs(setCookie)
		if len(parsed) > 0 {
			if upd.Cookies == nil {
				upd.Cookies = make(map[string]string, len(parsed))
			}
			for k, v := range parsed {
				if _, exists := upd.Cookies[k]; !exists {
					upd.Cookies[k] = v
				}
			}
			hasAny = true
		}
	}

	if !hasAny {
		return AccountCredentialUpdate{}, errors.New("refresh route response contained no refreshed token, cookie, or auth headers")
	}
	return upd, nil
}

func hasRefreshKeys(m map[string]any) bool {
	for _, k := range []string{"token", "access_token", "accessToken", "jwt", "cookie", "cookies", "headers", "tokens", "refresh_token"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func extractSetCookiePairs(raw string) map[string]string {
	out := make(map[string]string)
	// Set-Cookie headers joined by ", " may contain Expires dates; split conservatively on ';'
	// and inspect name=value tokens that aren't cookie attributes.
	attrs := map[string]bool{
		"path": true, "domain": true, "expires": true, "max-age": true,
		"secure": true, "httponly": true, "samesite": true, "priority": true, "partitioned": true,
	}
	for _, segment := range strings.Split(raw, ";") {
		seg := strings.TrimSpace(segment)
		if seg == "" {
			continue
		}
		// Handle comma-joined second Set-Cookie header like "HttpOnly, sid=xyz"
		if idx := strings.LastIndex(seg, ","); idx >= 0 && strings.Contains(seg[idx+1:], "=") {
			seg = strings.TrimSpace(seg[idx+1:])
		}
		k, v, ok := strings.Cut(seg, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" || attrs[strings.ToLower(k)] {
			continue
		}
		out[k] = strings.TrimSpace(v)
	}
	return out
}

func isBlockedWebhookIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// validateWebhookURL enforces http/https schemes and blocks link-local/cloud
// metadata SSRF destinations (including trailing-dot FQDNs) while allowing
// operator-configured webhook URLs.
func validateWebhookURL(raw string) (*url.URL, error) {
	u, err := validateHTTPURL(raw)
	if err != nil {
		return nil, err
	}
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(u.Hostname())), ".")
	if host == "" {
		return nil, fmt.Errorf("webhook URL %q has empty host", redactURLString(raw))
	}
	switch host {
	case "metadata.google.internal", "metadata.goog", "metadata", "instance-data":
		return nil, fmt.Errorf("webhook host %q is blocked by SSRF policy", host)
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedWebhookIP(ip) {
		return nil, fmt.Errorf("webhook IP %q is blocked by SSRF policy", host)
	}
	return u, nil
}

// newWebhookHTTPClient constructs a reusable webhook HTTP client that blocks
// HTTP redirects and validates resolved IPs at dial time against link-local,
// multicast, unspecified, and cloud metadata addresses.
func newWebhookHTTPClient() (*http.Client, *http.Transport) {
	baseDialer := &net.Dialer{
		Timeout:   challengeWebhookTimeout,
		KeepAlive: 30 * time.Second,
	}
	tr := &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: challengeWebhookTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			cleanHost := strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
			switch cleanHost {
			case "metadata.google.internal", "metadata.goog", "metadata", "instance-data":
				return nil, fmt.Errorf("webhook host %q is blocked by SSRF policy", cleanHost)
			}
			if ip := net.ParseIP(cleanHost); ip != nil {
				if isBlockedWebhookIP(ip) {
					return nil, fmt.Errorf("webhook IP %q is blocked by SSRF policy", ip.String())
				}
				return baseDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, cleanHost)
			if err != nil {
				return nil, err
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("webhook host %q resolved to no addresses", cleanHost)
			}
			var safeIPs []net.IP
			for _, a := range addrs {
				if isBlockedWebhookIP(a.IP) {
					return nil, fmt.Errorf("webhook host %q resolved to blocked IP %s", cleanHost, a.IP.String())
				}
				safeIPs = append(safeIPs, a.IP)
			}
			var lastErr error
			for _, ip := range safeIPs {
				conn, dialErr := baseDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   challengeWebhookTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, tr
}

// challengeWebhookPayload is the redacted JSON notification sent to an
// operator's webhook when a non-refreshable challenge or risk-control block occurs.
type challengeWebhookPayload struct {
	Event       string `json:"event"`
	Timestamp   string `json:"timestamp"`
	RouteID     string `json:"route_id,omitempty"`
	RouteSlug   string `json:"route_slug"`
	AccountID   string `json:"account_id,omitempty"`
	AccountName string `json:"account_name,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	ProxyID     string `json:"proxy_id,omitempty"`
	StatusCode  int    `json:"status_code"`
	UpstreamURL string `json:"upstream_url,omitempty"`
	Reason      string `json:"reason"`
	BodyPreview string `json:"body_preview,omitempty"`
}

func sendChallengeWebhook(ctx context.Context, client *http.Client, webhookURL string, payload challengeWebhookPayload, secrets []string) error {
	if _, err := validateWebhookURL(webhookURL); err != nil {
		return err
	}
	payload.UpstreamURL = redactSecrets(redactURLString(payload.UpstreamURL), secrets...)
	payload.Reason = redactSecrets(payload.Reason, secrets...)
	// Redact secrets BEFORE truncating so a secret straddling the preview boundary cannot leak.
	payload.BodyPreview = truncatePreview(redactSecrets(payload.BodyPreview, secrets...), maxChallengeBodyPreview)

	rawBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, challengeWebhookTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, webhookURL, bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cap-gateway-webhook/1.0")

	if client == nil {
		c, tr := newWebhookHTTPClient()
		defer tr.CloseIdleConnections()
		client = c
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

func truncatePreview(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

var challengeKeywords = []string{
	"captcha", "recaptcha", "hcaptcha", "turnstile", "geetest",
	"slider", "risk_control", "riskcontrol", "human_verification",
	"verify_human", "challenge_required", "waf_block", "access_denied",
}

func detectChallengeBody(body []byte) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	sample := body
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	lower := strings.ToLower(string(sample))
	for _, kw := range challengeKeywords {
		if strings.Contains(lower, kw) {
			return fmt.Sprintf("response body matched challenge indicator %q", kw), true
		}
	}
	return "", false
}
