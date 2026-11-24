package exectrace

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/overkazaf/cap/internal/config"
	"github.com/overkazaf/cap/internal/fsutil"
)

const (
	defaultQueryLimit = 200
	maxQueryLimit     = 5000
)

var safeSessionIDRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// Manager is a thread-safe store for dynamic execution trace sessions persisted
// under ~/.cap/exec-traces/ (gracefully degrading to in-memory storage on
// read-only filesystems).
type Manager struct {
	dir      string
	mu       sync.RWMutex
	sessions map[string]*ExecTraceSession
}

// NewManager initializes a persistent ExecTrace Manager at dir.
// If dir is empty, it defaults to "~/.cap/exec-traces".
// If dir cannot be created or written (e.g. read-only FS), Manager stays
// operational in memory without returning an error.
func NewManager(dir string) (*Manager, error) {
	if strings.TrimSpace(dir) == "" {
		dir = filepath.Join(config.DefaultDir(), "exec-traces")
	}
	_ = os.MkdirAll(dir, 0755)

	m := &Manager{
		dir:      dir,
		sessions: make(map[string]*ExecTraceSession),
	}
	_ = m.Reload()
	return m, nil
}

// Dir returns the filesystem directory where trace sessions are stored.
func (m *Manager) Dir() string {
	return m.dir
}

// Reload loads all persisted *.json trace sessions from disk into memory.
func (m *Manager) Reload() error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil
		}
		return err
	}

	loaded := make(map[string]*ExecTraceSession)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.dir, entry.Name()))
		if err != nil {
			continue
		}
		var sess ExecTraceSession
		if err := json.Unmarshal(data, &sess); err != nil {
			continue
		}
		if sess.ID == "" {
			sess.ID = strings.TrimSuffix(entry.Name(), ".json")
		}
		if sess.Summary == nil && len(sess.Events) > 0 {
			sess.Summary = AnalyzeSession(&sess)
		}
		cp := sess
		loaded[sess.ID] = &cp
	}

	m.mu.Lock()
	for id, s := range loaded {
		m.sessions[id] = s
	}
	m.mu.Unlock()
	return nil
}

// ImportTrace parses raw trace data, analyzes it, stores the session in memory,
// and persists it atomically to disk (best-effort on read-only filesystems).
func (m *Manager) ImportTrace(name, format, raw string, moduleBase uint64) (*ExecTraceSession, error) {
	sess, err := ParseTrace(name, format, raw, moduleBase)
	if err != nil {
		return nil, err
	}
	return m.SaveSession(sess)
}

// SaveSession assigns an ID if absent, stores the session in memory, and writes
// it to disk atomically (gracefully degrading to memory-only on read-only FS).
func (m *Manager) SaveSession(sess *ExecTraceSession) (*ExecTraceSession, error) {
	if sess == nil {
		return nil, errors.New("exectrace: session is nil")
	}
	if strings.TrimSpace(sess.ID) == "" {
		sess.ID = generateSessionID(sess.Name)
	}
	if sess.CreatedAt == "" {
		sess.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if sess.Summary == nil && len(sess.Events) > 0 {
		sess.Summary = AnalyzeSession(sess)
	}

	stored := cloneSession(sess, true)

	m.mu.Lock()
	m.sessions[stored.ID] = stored
	m.mu.Unlock()

	if data, err := json.Marshal(stored); err == nil {
		// Best-effort atomic persistence: keep working in-memory if FS is read-only.
		_ = fsutil.WriteFileAtomic(m.sessionFilePath(stored.ID), data, 0644)
	}

	return cloneSession(stored, true), nil
}

// ListSessions returns metadata and analysis summaries for all stored sessions
// ordered newest-first, omitting the raw Events slice so large traces remain fast.
func (m *Manager) ListSessions() []ExecTraceSession {
	m.mu.RLock()
	out := make([]ExecTraceSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		meta := *cloneSession(s, false)
		out = append(out, meta)
	}
	m.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].ID > out[j].ID
	})
	return out
}

// GetSession retrieves a full ExecTraceSession (including Events) by ID.
func (m *Manager) GetSession(id string) (*ExecTraceSession, bool) {
	id = strings.TrimSpace(id)
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return cloneSession(s, true), true
}

// QueryEvents returns a filtered, paginated window of TraceEvents for sessionID.
func (m *Manager) QueryEvents(sessionID string, filter EventFilter) (*EventPage, error) {
	sessionID = strings.TrimSpace(sessionID)
	m.mu.RLock()
	s, ok := m.sessions[sessionID]
	if !ok {
		m.mu.RUnlock()
		return nil, fmt.Errorf("exectrace: session %q not found", sessionID)
	}
	events := s.Events
	m.mu.RUnlock()

	return QuerySessionEvents(sessionID, events, filter), nil
}

// QuerySessionEvents filters and paginates an event slice directly.
func QuerySessionEvents(sessionID string, events []TraceEvent, filter EventFilter) *EventPage {
	limit := filter.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}
	if limit > maxQueryLimit {
		limit = maxQueryLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	kindFilter := strings.ToLower(strings.TrimSpace(filter.Kind))
	modFilter := strings.ToLower(strings.TrimSpace(filter.Module))
	searchFilter := strings.ToLower(strings.TrimSpace(filter.Search))

	matched := make([]TraceEvent, 0)
	for _, ev := range events {
		if kindFilter != "" && strings.ToLower(ev.Kind) != kindFilter {
			continue
		}
		if modFilter != "" && !strings.Contains(strings.ToLower(ev.Module), modFilter) {
			continue
		}
		if filter.ThreadID != 0 && ev.ThreadID != filter.ThreadID {
			continue
		}
		if filter.MinSeq > 0 && ev.Seq < filter.MinSeq {
			continue
		}
		if filter.MaxSeq > 0 && ev.Seq > filter.MaxSeq {
			continue
		}
		if filter.Address != 0 && ev.Address != filter.Address && ev.Offset != filter.Address && ev.MemAddr != filter.Address {
			continue
		}
		if filter.MinAddr != 0 && ev.Address < filter.MinAddr && ev.Offset < filter.MinAddr {
			continue
		}
		if filter.MaxAddr != 0 && ev.Address > filter.MaxAddr && ev.Offset > filter.MaxAddr {
			continue
		}
		if searchFilter != "" && !eventMatchesSearch(ev, searchFilter) {
			continue
		}
		matched = append(matched, ev)
	}

	total := len(matched)
	if offset >= total {
		return &EventPage{
			SessionID: sessionID,
			Total:     total,
			Offset:    offset,
			Limit:     limit,
			HasMore:   false,
			Events:    []TraceEvent{},
		}
	}
	end := offset + limit
	if end > total {
		end = total
	}
	pageEvents := make([]TraceEvent, end-offset)
	copy(pageEvents, matched[offset:end])

	return &EventPage{
		SessionID: sessionID,
		Total:     total,
		Offset:    offset,
		Limit:     limit,
		HasMore:   end < total,
		Events:    pageEvents,
	}
}

// DeleteSession removes a trace session from memory and disk.
func (m *Manager) DeleteSession(id string) error {
	id = strings.TrimSpace(id)
	m.mu.Lock()
	_, exists := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("exectrace: session %q not found", id)
	}
	if err := os.Remove(m.sessionFilePath(id)); err != nil && !os.IsNotExist(err) && !os.IsPermission(err) {
		return err
	}
	return nil
}

// RunTaint executes forward or backward taint analysis on a stored session.
func (m *Manager) RunTaint(req TaintRequest) (*TaintResult, error) {
	sess, ok := m.GetSession(req.SessionID)
	if !ok {
		return nil, fmt.Errorf("exectrace: session %q not found", req.SessionID)
	}
	return RunTaint(sess, req)
}

// DiffSessions performs an ASLR-normalized diff between two stored sessions.
func (m *Manager) DiffSessions(sessionAID, sessionBID string, maxDivergences int) (*TraceDiffResult, error) {
	sessA, ok := m.GetSession(sessionAID)
	if !ok {
		return nil, fmt.Errorf("exectrace: session %q not found", sessionAID)
	}
	sessB, ok := m.GetSession(sessionBID)
	if !ok {
		return nil, fmt.Errorf("exectrace: session %q not found", sessionBID)
	}
	return DiffTraces(sessA, sessB, maxDivergences), nil
}

// ExportTrace exports a stored trace session in "tenet", "jsonl", or "markdown" format.
func (m *Manager) ExportTrace(id, format string) (string, error) {
	sess, ok := m.GetSession(id)
	if !ok {
		return "", fmt.Errorf("exectrace: session %q not found", id)
	}
	return ExportSession(sess, format)
}

// ExportSession serializes an ExecTraceSession into "tenet", "jsonl", or "markdown".
func ExportSession(s *ExecTraceSession, format string) (string, error) {
	if s == nil {
		return "", errors.New("exectrace: session is nil")
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case ExportTenet:
		return exportTenet(s), nil
	case ExportJSONL, "json":
		return exportJSONL(s)
	case ExportMarkdown, "md":
		return exportMarkdown(s), nil
	default:
		return "", fmt.Errorf("exectrace: unsupported export format %q (expected tenet, jsonl, or markdown)", format)
	}
}

func exportTenet(s *ExecTraceSession) string {
	var b strings.Builder
	prevRegs := make(map[string]uint64)
	pcReg := "pc"
	switch s.Arch {
	case "x86_64":
		pcReg = "rip"
	case "x86":
		pcReg = "eip"
	}

	events := s.Events
	for i := 0; i < len(events); i++ {
		ev := events[i]
		if !isInstructionEvent(ev) {
			continue
		}
		var tokens []string
		pc := ev.Address
		if pc == 0 {
			pc = ev.Offset
		}
		tokens = append(tokens, fmt.Sprintf("%s=0x%x", pcReg, pc))

		regs := ev.RegsAfter
		if len(regs) == 0 {
			regs = ev.RegsBefore
		}
		if len(regs) > 0 {
			keys := make([]string, 0, len(regs))
			for k := range regs {
				if k == "pc" || k == "rip" || k == "eip" {
					continue
				}
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := regs[k]
				if old, seen := prevRegs[k]; !seen || old != v {
					tokens = append(tokens, fmt.Sprintf("%s=0x%x", k, v))
					prevRegs[k] = v
				}
			}
		}

		// Fold adjacent mem_read / mem_write events that belong to this instruction.
		for i+1 < len(events) {
			nxt := events[i+1]
			if (nxt.Kind == KindMemRead || nxt.Kind == KindMemWrite) && (nxt.Address == 0 || nxt.Address == ev.Address) {
				i++
				prefix := "mr"
				if nxt.Kind == KindMemWrite {
					prefix = "mw"
				}
				val := nxt.MemValueHex
				if val == "" {
					val = "00"
				}
				tokens = append(tokens, fmt.Sprintf("%s=0x%x:%s", prefix, nxt.MemAddr, val))
			} else {
				break
			}
		}

		b.WriteString(strings.Join(tokens, ","))
		b.WriteByte('\n')
	}
	return b.String()
}

func exportJSONL(s *ExecTraceSession) (string, error) {
	var b strings.Builder
	for _, ev := range s.Events {
		raw, err := json.Marshal(ev)
		if err != nil {
			return "", err
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func exportMarkdown(s *ExecTraceSession) string {
	analysis := s.Summary
	if analysis == nil {
		analysis = AnalyzeSession(s)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Execution Trace Report: %s\n\n", s.Name)
	fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Session ID | `%s` |\n", s.ID)
	fmt.Fprintf(&b, "| Source / Format | `%s` / `%s` |\n", s.Source, s.Format)
	fmt.Fprintf(&b, "| Architecture | `%s` |\n", s.Arch)
	if s.TargetModule != "" {
		fmt.Fprintf(&b, "| Target Module | `%s` (base `0x%x`) |\n", s.TargetModule, s.ModuleBase)
	}
	fmt.Fprintf(&b, "| Totals | %d events · %d insns · %d mem ops · %d calls · %d unique PCs |\n",
		s.TotalEvents, s.InsnCount, s.MemOpCount, s.CallCount, s.UniquePCs)
	fmt.Fprintf(&b, "| Summary | %s |\n\n", analysis.SummaryText)

	if len(analysis.CryptoHits) > 0 {
		b.WriteString("## Detected Cryptographic Patterns\n\n")
		b.WriteString("| Algorithm | Seq | Address / Offset | Confidence | Evidence |\n|---|---:|---|---:|---|\n")
		for _, h := range analysis.CryptoHits {
			loc := fmt.Sprintf("`0x%x`", h.Address)
			if h.Offset != 0 {
				loc = fmt.Sprintf("`0x%x` (`+0x%x`)", h.Address, h.Offset)
			}
			fmt.Fprintf(&b, "| **%s** | %d | %s | %.0f%% | %s |\n",
				h.Algorithm, h.Seq, loc, h.Confidence*100, h.Evidence)
		}
		b.WriteByte('\n')
	}

	if len(analysis.HotFunctions) > 0 {
		b.WriteString("## Hot Functions\n\n")
		b.WriteString("| Function | Module | Hits | Insns | Child Calls |\n|---|---|---:|---:|---:|\n")
		limit := len(analysis.HotFunctions)
		if limit > 20 {
			limit = 20
		}
		for _, fn := range analysis.HotFunctions[:limit] {
			fmt.Fprintf(&b, "| `%s` | `%s` | %d | %d | %d |\n",
				fn.Name, fn.Module, fn.Hits, fn.InsnCount, fn.ChildCalls)
		}
		b.WriteByte('\n')
	}

	if len(analysis.MemoryRegions) > 0 {
		b.WriteString("## Memory Regions\n\n")
		b.WriteString("| Range | Reads | Writes | Unique Addrs | Role Hint | Sample Hex |\n|---|---:|---:|---:|---|---|\n")
		for _, mr := range analysis.MemoryRegions {
			fmt.Fprintf(&b, "| `0x%x..0x%x` | %d | %d | %d | `%s` | `%s` |\n",
				mr.BaseAddr, mr.EndAddr, mr.ReadCount, mr.WriteCount, mr.UniqueAddrs, mr.RoleHint, mr.SampleHex)
		}
		b.WriteByte('\n')
	}

	if len(analysis.HotLoops) > 0 {
		b.WriteString("## Hot Loops\n\n")
		b.WriteString("| Range | Iterations | Body Insns | Crypto Ratio | Hint |\n|---|---:|---:|---:|---|\n")
		for _, lp := range analysis.HotLoops {
			fmt.Fprintf(&b, "| `0x%x..0x%x` | %d | %d | %.0f%% | %s |\n",
				lp.StartAddr, lp.EndAddr, lp.Iterations, lp.BodyInsns, lp.CryptoRatio*100, lp.Hint)
		}
		b.WriteByte('\n')
	}

	if len(analysis.CallTree) > 0 {
		b.WriteString("## Call Tree\n\n```text\n")
		var writeNode func(n CallNode, indent int)
		writeNode = func(n CallNode, indent int) {
			fmt.Fprintf(&b, "%s%s (seq %d..%d, insns=%d)\n",
				strings.Repeat("  ", indent), n.Name, n.EnterSeq, n.ExitSeq, n.InsnCount)
			for _, ch := range n.Children {
				writeNode(ch, indent+1)
			}
		}
		for _, root := range analysis.CallTree {
			writeNode(root, 0)
		}
		b.WriteString("```\n\n")
	}

	if len(s.Events) > 0 {
		b.WriteString("## Trace Sample\n\n```text\n")
		limit := len(s.Events)
		if limit > 30 {
			limit = 30
		}
		for _, ev := range s.Events[:limit] {
			if ev.Raw != "" {
				fmt.Fprintf(&b, "#%d %s\n", ev.Seq, ev.Raw)
			} else {
				fmt.Fprintf(&b, "#%d [%s] 0x%x %s %s\n", ev.Seq, ev.Kind, ev.Address, ev.Mnemonic, ev.Operands)
			}
		}
		b.WriteString("```\n")
	}

	return b.String()
}

func (m *Manager) sessionFilePath(id string) string {
	safe := safeSessionIDRe.ReplaceAllString(id, "_")
	if safe == "" {
		safe = "trace"
	}
	return filepath.Join(m.dir, safe+".json")
}

func generateSessionID(name string) string {
	slug := strings.ToLower(strings.TrimSpace(name))
	slug = safeSessionIDRe.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-._")
	if len(slug) > 24 {
		slug = slug[:24]
	}
	if slug == "" {
		slug = "trace"
	}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	return fmt.Sprintf("%s-%d-%s", slug, time.Now().UnixMilli(), hex.EncodeToString(rnd[:]))
}

func eventMatchesSearch(ev TraceEvent, needle string) bool {
	if strings.Contains(strings.ToLower(ev.Mnemonic), needle) ||
		strings.Contains(strings.ToLower(ev.Operands), needle) ||
		strings.Contains(strings.ToLower(ev.Symbol), needle) ||
		strings.Contains(strings.ToLower(ev.Module), needle) ||
		strings.Contains(strings.ToLower(ev.MemValueHex), needle) ||
		strings.Contains(strings.ToLower(ev.RetVal), needle) ||
		strings.Contains(strings.ToLower(ev.Raw), needle) {
		return true
	}
	for _, a := range ev.Args {
		if strings.Contains(strings.ToLower(a), needle) {
			return true
		}
	}
	if ev.Address != 0 && strings.Contains(fmt.Sprintf("0x%x", ev.Address), needle) {
		return true
	}
	if ev.Offset != 0 && strings.Contains(fmt.Sprintf("0x%x", ev.Offset), needle) {
		return true
	}
	if ev.MemAddr != 0 && strings.Contains(fmt.Sprintf("0x%x", ev.MemAddr), needle) {
		return true
	}
	return false
}

func cloneSession(s *ExecTraceSession, includeEvents bool) *ExecTraceSession {
	if s == nil {
		return nil
	}
	cp := *s
	if includeEvents && len(s.Events) > 0 {
		cp.Events = make([]TraceEvent, len(s.Events))
		copy(cp.Events, s.Events)
	} else {
		cp.Events = nil
	}
	return &cp
}
