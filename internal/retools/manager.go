package retools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/config"
	captrace "github.com/overkazaf/cap/internal/trace"
)

var projectSlugRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// ProjectStore manages built-in curated RE project templates plus user-saved
// projects in ~/.cap/re-projects/*.json with automatic disk hot-reload and
// graceful degradation on read-only filesystems.
type ProjectStore struct {
	dir      string
	mu       sync.RWMutex
	custom   map[string]REProject
	dirStamp string
}

// NewProjectStore initializes a persistent RE project store at dir.
// If dir cannot be created (e.g., read-only home directory), built-in templates
// remain readable and Save retries directory creation on demand.
func NewProjectStore(dir string) (*ProjectStore, error) {
	if strings.TrimSpace(dir) == "" {
		dir = filepath.Join(config.DefaultDir(), "re-projects")
	}
	_ = os.MkdirAll(dir, 0755)
	s := &ProjectStore{
		dir:    dir,
		custom: make(map[string]REProject),
	}
	_ = s.Reload()
	return s, nil
}

// Dir returns the filesystem directory where custom RE projects are persisted.
func (s *ProjectStore) Dir() string {
	return s.dir
}

// BuiltinProjects returns all built-in Unidbg, Qiling, angr, and radare2 templates.
func BuiltinProjects() []REProject {
	var all []REProject
	all = append(all, BuiltinUnidbgProjects()...)
	all = append(all, BuiltinQilingProjects()...)
	all = append(all, BuiltinAngrProjects()...)
	all = append(all, BuiltinR2Projects()...)
	return all
}

// Reload re-reads all custom *.json projects from disk.
func (s *ProjectStore) Reload() error {
	stamp := computeProjectsStamp(s.dir)
	loaded := readProjectsDir(s.dir)
	s.mu.Lock()
	s.custom = loaded
	s.dirStamp = stamp
	s.mu.Unlock()
	return nil
}

func (s *ProjectStore) maybeReload() {
	stamp := computeProjectsStamp(s.dir)
	s.mu.RLock()
	same := stamp == s.dirStamp
	s.mu.RUnlock()
	if same {
		return
	}
	_ = s.Reload()
}

// List returns all built-in templates followed by user-saved custom projects.
func (s *ProjectStore) List() []REProject {
	s.maybeReload()
	builtins := BuiltinProjects()
	s.mu.RLock()
	customs := make([]REProject, 0, len(s.custom))
	for _, p := range s.custom {
		customs = append(customs, p)
	}
	s.mu.RUnlock()

	sort.Slice(customs, func(i, j int) bool {
		if customs[i].UpdatedAt != customs[j].UpdatedAt {
			return customs[i].UpdatedAt > customs[j].UpdatedAt
		}
		return strings.ToLower(customs[i].Name) < strings.ToLower(customs[j].Name)
	})

	out := make([]REProject, 0, len(builtins)+len(customs))
	out = append(out, builtins...)
	out = append(out, customs...)
	return out
}

// ListByEngine filters projects by engine ("unidbg" | "qiling" | "angr" | "radare2").
// An empty engine string returns all projects.
func (s *ProjectStore) ListByEngine(engine string) []REProject {
	if strings.TrimSpace(engine) == "" {
		return s.List()
	}
	eng := normalizeEngineName(engine)
	if eng == "" {
		return []REProject{}
	}
	all := s.List()
	out := []REProject{}
	for _, p := range all {
		if p.Engine == eng {
			out = append(out, p)
		}
	}
	return out
}

// Get retrieves a project by ID (checking custom projects first, then built-ins).
func (s *ProjectStore) Get(id string) (*REProject, bool) {
	s.maybeReload()
	id = strings.TrimSpace(id)
	s.mu.RLock()
	if p, ok := s.custom[id]; ok {
		s.mu.RUnlock()
		return &p, true
	}
	s.mu.RUnlock()

	for _, b := range BuiltinProjects() {
		if b.ID == id {
			cp := b
			return &cp, true
		}
	}
	return nil, false
}

// Save persists a custom RE project to disk. Saving a built-in project ID
// forks it cleanly into a user-owned copy.
func (s *ProjectStore) Save(p REProject) (*REProject, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return nil, fmt.Errorf("project name is required")
	}
	eng := normalizeEngineName(p.Engine)
	if eng == "" {
		return nil, fmt.Errorf("unsupported project engine %q", p.Engine)
	}
	p.Engine = eng

	p.ID = strings.TrimSpace(p.ID)
	if p.ID == "" || strings.HasPrefix(p.ID, "builtin:") {
		p.ID = "user:" + sanitizeProjectID(p.Name)
	}
	p.Builtin = false
	now := nowRFC3339()
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return nil, fmt.Errorf("create re-projects dir: %w", err)
	}
	filePath := s.projectFilePath(p.ID)
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return nil, fmt.Errorf("write project %s: %w", filePath, err)
	}

	s.mu.Lock()
	s.custom[p.ID] = p
	s.dirStamp = computeProjectsStamp(s.dir)
	s.mu.Unlock()
	return &p, nil
}

// Delete removes a user-saved RE project from disk. Built-in templates cannot be deleted.
func (s *ProjectStore) Delete(id string) error {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, "builtin:") {
		return fmt.Errorf("cannot delete built-in template %s", id)
	}
	filePath := s.projectFilePath(id)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	s.mu.Lock()
	delete(s.custom, id)
	s.dirStamp = computeProjectsStamp(s.dir)
	s.mu.Unlock()
	return nil
}

func (s *ProjectStore) projectFilePath(id string) string {
	safe := sanitizeProjectID(strings.TrimPrefix(id, "user:"))
	return filepath.Join(s.dir, safe+".json")
}

func sanitizeProjectID(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = projectSlugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		return "project"
	}
	return s
}

func computeProjectsStamp(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", e.Name(), fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return b.String()
}

func readProjectsDir(dir string) map[string]REProject {
	out := make(map[string]REProject)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var p REProject
		if json.Unmarshal(raw, &p) == nil && p.Name != "" {
			if p.ID == "" {
				p.ID = "user:" + strings.TrimSuffix(e.Name(), ".json")
			}
			if p.Engine == "" {
				p.Engine = EngineUnidbg
			}
			p.Builtin = false
			out[p.ID] = p
		}
	}
	return out
}

// --- Manager & Async Cancellable Job Execution -----------------------------

// Manager owns the RE project store, host toolchain configuration/cache,
// binary analysis entrypoints, and async cancellable job lifecycle.
type Manager struct {
	projects *ProjectStore

	tcMu   sync.RWMutex
	tcCfg  ToolchainConfig
	tcInfo *ToolchainInfo
	tcGen  uint64

	jobOpMu  sync.Mutex // serializes StartJob / CancelJob / Shutdown transitions
	mu       sync.Mutex
	active   *activeJob
	state    *JobState
	seq      atomic.Int64
	onLog    func(JobLogEvent)
	onStatus func(*JobState)
}

type activeJob struct {
	id        string
	engine    string
	ctx       context.Context
	cancel    context.CancelFunc
	tempPaths []string
	cancelled atomic.Bool
	doneCh    chan struct{}
}

// NewManager creates an RE Manager backed by capDir (defaulting to ~/.cap).
func NewManager(capDir string) (*Manager, error) {
	if strings.TrimSpace(capDir) == "" {
		capDir = config.DefaultDir()
	}
	projectsDir := filepath.Join(capDir, "re-projects")
	store, err := NewProjectStore(projectsDir)
	if err != nil {
		return nil, err
	}
	return &Manager{
		projects: store,
		state: &JobState{
			Status:  StatusIdle,
			Events:  []JobLogEvent{},
			Results: []JobResult{},
		},
	}, nil
}

// SetCallbacks installs optional live log and status listeners (used by Wails GUI / CLI).
func (m *Manager) SetCallbacks(onLog func(JobLogEvent), onStatus func(*JobState)) {
	m.mu.Lock()
	m.onLog = onLog
	m.onStatus = onStatus
	m.mu.Unlock()
}

// SetToolchainConfig updates custom tool paths and invalidates the cached probe.
func (m *Manager) SetToolchainConfig(cfg ToolchainConfig) {
	m.tcMu.Lock()
	m.tcCfg = cfg
	m.tcInfo = nil
	m.tcGen++
	m.tcMu.Unlock()
}

// GetToolchainConfig returns the currently configured custom toolchain paths.
func (m *Manager) GetToolchainConfig() ToolchainConfig {
	return m.currentToolchainConfig()
}

// GetToolchain returns host toolchain readiness (re-probing if forceRefresh is true).
func (m *Manager) GetToolchain(forceRefresh bool) ToolchainInfo {
	m.tcMu.RLock()
	cached := m.tcInfo
	cfg := m.tcCfg
	gen := m.tcGen
	m.tcMu.RUnlock()
	if cached != nil && !forceRefresh {
		return *cached
	}
	info := DetectToolchain(cfg)
	m.tcMu.Lock()
	if m.tcGen == gen {
		m.tcInfo = &info
	}
	m.tcMu.Unlock()
	return info
}

func (m *Manager) currentToolchainConfig() ToolchainConfig {
	m.tcMu.RLock()
	defer m.tcMu.RUnlock()
	return m.tcCfg
}

// Projects returns the underlying persistent REProject store.
func (m *Manager) Projects() *ProjectStore { return m.projects }

// ListProjects lists all built-in and custom RE projects.
func (m *Manager) ListProjects() []REProject { return m.projects.List() }

// GetProject fetches a single project by ID.
func (m *Manager) GetProject(id string) (*REProject, bool) { return m.projects.Get(id) }

// SaveProject saves a custom RE project to disk.
func (m *Manager) SaveProject(p REProject) (*REProject, error) { return m.projects.Save(p) }

// DeleteProject deletes a custom RE project from disk.
func (m *Manager) DeleteProject(id string) error { return m.projects.Delete(id) }

// AnalyzeBinary analyzes binaryPath using the manager's configured r2 path (or pure-Go ELF fallback).
func (m *Manager) AnalyzeBinary(ctx context.Context, binaryPath string) (*BinaryAnalysis, error) {
	cfg := m.currentToolchainConfig()
	return AnalyzeBinary(ctx, binaryPath, cfg.R2Path)
}

// InspectFunction inspects a function using the manager's configured r2 path (or pure-Go ELF fallback).
func (m *Manager) InspectFunction(ctx context.Context, binaryPath, funcNameOrAddr string) (*FunctionDetail, error) {
	cfg := m.currentToolchainConfig()
	return InspectFunction(ctx, binaryPath, funcNameOrAddr, cfg.R2Path)
}

// RunR2Command runs a sanitized read-only r2 command using the manager's configured r2 path.
func (m *Manager) RunR2Command(ctx context.Context, binaryPath, r2Cmd string) (*R2CommandResult, error) {
	cfg := m.currentToolchainConfig()
	return RunR2Command(ctx, binaryPath, r2Cmd, cfg.R2Path)
}

// GenerateFromTrace synthesizes an emulation/analysis harness from a DeepTrace result.
func (m *Manager) GenerateFromTrace(res *captrace.TraceResult, engine string, opts GenerateOptions) (*GeneratedHarness, error) {
	cfg := m.currentToolchainConfig()
	if opts.RootFS == "" && cfg.QilingRootFS != "" {
		opts.RootFS = cfg.QilingRootFS
	}
	return GenerateFromTrace(res, engine, opts)
}

// GetJobState returns a thread-safe deep snapshot of the current or last job.
func (m *Manager) GetJobState() *JobState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneJobState(m.state)
}

// ClearJobLogs clears recorded log events and results on the current job snapshot.
func (m *Manager) ClearJobLogs() {
	m.mu.Lock()
	if m.state != nil {
		m.state.Events = []JobLogEvent{}
		m.state.Results = []JobResult{}
		m.state.EventCount = 0
	}
	snap := cloneJobState(m.state)
	onStatus := m.onStatus
	m.mu.Unlock()
	if onStatus != nil {
		onStatus(snap)
	}
}

// StartJob launches an asynchronous, cancellable execution job for Unidbg,
// Qiling, angr, or radare2. Any currently running job is cancelled cleanly first.
func (m *Manager) StartJob(req RunJobRequest) (*JobState, error) {
	// Hydrate missing fields from a saved project if ProjectID is provided.
	if req.ProjectID != "" {
		if proj, ok := m.projects.Get(req.ProjectID); ok {
			if req.Engine == "" {
				req.Engine = proj.Engine
			}
			if req.ProjectName == "" {
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

	if strings.TrimSpace(req.Engine) == "" {
		return nil, fmt.Errorf("RE engine is required (unidbg, qiling, angr, or radare2)")
	}
	eng := normalizeEngineName(req.Engine)
	if eng == "" {
		return nil, fmt.Errorf("unsupported RE engine %q", req.Engine)
	}
	req.Engine = eng

	tc := m.GetToolchain(false)
	if !tc.R2Ready && eng == EngineRadare2 ||
		!tc.Python.Ready && (eng == EngineQiling || eng == EngineAngr) ||
		!tc.UnidbgReady && eng == EngineUnidbg {
		// Refresh once in case config/environment changed.
		tc = m.GetToolchain(true)
	}

	// Prepare engine-specific execution plan before mutating manager state.
	plan, err := prepareJobPlan(req, tc)
	if err != nil {
		return nil, err
	}

	// Serialize job start/cancel transitions so concurrent StartJob calls never
	// race or orphan subprocesses.
	m.jobOpMu.Lock()
	defer m.jobOpMu.Unlock()

	m.cancelJobLocked()

	var ctx context.Context
	var cancel context.CancelFunc
	if req.TimeoutSec > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(req.TimeoutSec)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	jobID := fmt.Sprintf("rejob-%d", time.Now().UnixNano())
	startedAt := time.Now().UnixMilli()
	job := &activeJob{
		id:        jobID,
		engine:    eng,
		ctx:       ctx,
		cancel:    cancel,
		tempPaths: plan.tempPaths,
		doneCh:    make(chan struct{}),
	}

	projName := strings.TrimSpace(req.ProjectName)
	if projName == "" {
		projName = strings.ToUpper(eng) + " Job"
	}

	m.mu.Lock()
	m.active = job
	m.state = &JobState{
		ID:          jobID,
		ProjectID:   req.ProjectID,
		ProjectName: projName,
		Engine:      eng,
		Status:      StatusRunning,
		Running:     true,
		Command:     plan.displayCmd,
		StartedAtMs: startedAt,
		Events:      make([]JobLogEvent, 0, 64),
		Results:     make([]JobResult, 0, 8),
	}
	snap := cloneJobState(m.state)
	onStatus := m.onStatus
	m.mu.Unlock()

	if onStatus != nil {
		onStatus(snap)
	}
	m.appendLog(jobID, JobLogEvent{
		Stream:  "system",
		Level:   "system",
		Message: fmt.Sprintf("Starting %s job (%s)", eng, projName),
	})

	go m.runJobPlan(job, plan)
	return snap, nil
}

// CancelJob terminates the currently running job and its child process group.
func (m *Manager) CancelJob() error {
	m.jobOpMu.Lock()
	defer m.jobOpMu.Unlock()
	m.cancelJobLocked()
	return nil
}

func (m *Manager) cancelJobLocked() {
	m.mu.Lock()
	job := m.active
	m.mu.Unlock()

	if job == nil {
		return
	}
	job.cancelled.Store(true)
	// Cancelling job.ctx triggers exec.CommandContext's synchronized cmd.Cancel
	// (killProcGroup) without ever racing against cmd.Wait() reaping the PID.
	job.cancel()

	select {
	case <-job.doneCh:
	case <-time.After(2 * time.Second):
	}
}

// WaitJob blocks until the active job finishes (or ctx is cancelled) and
// returns the latest JobState snapshot.
func (m *Manager) WaitJob(ctx context.Context) (*JobState, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	job := m.active
	m.mu.Unlock()
	if job == nil {
		return m.GetJobState(), nil
	}
	select {
	case <-job.doneCh:
		return m.GetJobState(), nil
	case <-ctx.Done():
		return m.GetJobState(), ctx.Err()
	}
}

// Shutdown cancels any active RE job during application exit.
func (m *Manager) Shutdown() {
	_ = m.CancelJob()
}

// --- Execution Plan Builder & Runner ---------------------------------------

type jobStep struct {
	label       string
	bin         string
	args        []string
	resolveArgs func() ([]string, error)
	dir         string
	env         []string
}

type jobPlan struct {
	steps      []jobStep
	displayCmd string
	tempPaths  []string
}

func prepareJobPlan(req RunJobRequest, tc ToolchainInfo) (*jobPlan, error) {
	env := buildJobEnv(req, tc)

	switch req.Engine {
	case EngineQiling, EngineAngr:
		if strings.TrimSpace(req.Code) == "" {
			return nil, fmt.Errorf("%s script code is required", req.Engine)
		}
		if !tc.Python.Ready || tc.Python.Path == "" {
			return nil, fmt.Errorf("Python 3 runtime not available (%s)", tc.Python.Issue)
		}
		tmpFile, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("cap-%s-*.py", req.Engine))
		if err != nil {
			return nil, fmt.Errorf("create temp script: %w", err)
		}
		if _, err := tmpFile.WriteString(req.Code); err != nil {
			tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
			return nil, err
		}
		tmpFile.Close()

		args := append([]string{"-u", tmpFile.Name()}, req.Args...)
		return &jobPlan{
			steps: []jobStep{
				{
					label: req.Engine,
					bin:   tc.Python.Path,
					args:  args,
					dir:   req.WorkDir,
					env:   env,
				},
			},
			displayCmd: fmt.Sprintf("%s -u %s", filepath.Base(tc.Python.Path), filepath.Base(tmpFile.Name())),
			tempPaths:  []string{tmpFile.Name()},
		}, nil

	case EngineRadare2:
		r2Cmd := strings.TrimSpace(firstNonEmpty(req.R2Command, req.Code))
		if err := ValidateR2Command(r2Cmd); err != nil {
			return nil, err
		}
		binPath := strings.TrimSpace(req.BinaryPath)
		if binPath == "" {
			return nil, fmt.Errorf("binary_path is required for radare2 job")
		}
		if fi, err := os.Stat(binPath); err != nil || fi.IsDir() {
			return nil, fmt.Errorf("binary file not accessible: %s", binPath)
		}
		if abs, err := filepath.Abs(binPath); err == nil {
			binPath = abs
		}
		if !tc.R2.Ready || tc.R2.Path == "" {
			return nil, fmt.Errorf("radare2 (r2) not available (%s)", tc.R2.Issue)
		}
		args := []string{"-q", "-e", "cfg.sandbox=true", "-e", "scr.color=0", "-c", r2Cmd, binPath}
		return &jobPlan{
			steps: []jobStep{
				{
					label: "radare2",
					bin:   tc.R2.Path,
					args:  args,
					dir:   req.WorkDir,
					env:   env,
				},
			},
			displayCmd: fmt.Sprintf("%s -q -c %q %s", filepath.Base(tc.R2.Path), r2Cmd, filepath.Base(binPath)),
		}, nil

	case EngineUnidbg:
		if strings.TrimSpace(req.Code) == "" {
			return nil, fmt.Errorf("Unidbg Java source code is required")
		}
		if !tc.Java.Ready || tc.Java.Path == "" {
			return nil, fmt.Errorf("Java runtime not available (%s)", tc.Java.Issue)
		}
		if !tc.Unidbg.Ready {
			return nil, fmt.Errorf("Unidbg not configured (%s)", tc.Unidbg.Issue)
		}
		if tc.JavacPath == "" {
			return nil, fmt.Errorf("JDK javac compiler not found (required to compile Unidbg harnesses)")
		}

		tmpDir, err := os.MkdirTemp(os.TempDir(), "cap-unidbg-*")
		if err != nil {
			return nil, fmt.Errorf("create unidbg temp dir: %w", err)
		}

		className := extractJavaClassName(req.Code)
		pkgName := extractJavaPackageName(req.Code)
		srcDir := filepath.Join(tmpDir, "src")
		outDir := filepath.Join(tmpDir, "classes")
		if pkgName != "" {
			srcDir = filepath.Join(srcDir, filepath.FromSlash(strings.ReplaceAll(pkgName, ".", "/")))
		}
		if err := os.MkdirAll(srcDir, 0755); err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		if err := os.MkdirAll(outDir, 0755); err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}

		javaFile := filepath.Join(srcDir, className+".java")
		if err := os.WriteFile(javaFile, []byte(req.Code), 0644); err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}

		fqcn := className
		if pkgName != "" {
			fqcn = pkgName + "." + className
		}

		// Mode 1: Direct javac + java using discovered Unidbg JARs
		if len(tc.UnidbgJars) > 0 {
			cpJars := strings.Join(tc.UnidbgJars, string(os.PathListSeparator))
			runCP := outDir + string(os.PathListSeparator) + cpJars
			javaArgs := append([]string{"-cp", runCP, fqcn}, req.Args...)
			return &jobPlan{
				steps: []jobStep{
					{
						label: "javac",
						bin:   tc.JavacPath,
						args:  []string{"-encoding", "UTF-8", "-cp", cpJars, "-d", outDir, javaFile},
						dir:   tmpDir,
						env:   env,
					},
					{
						label: "java",
						bin:   tc.Java.Path,
						args:  javaArgs,
						dir:   firstNonEmpty(req.WorkDir, tmpDir),
						env:   env,
					},
				},
				displayCmd: fmt.Sprintf("%s && %s %s", filepath.Base(tc.JavacPath), filepath.Base(tc.Java.Path), fqcn),
				tempPaths:  []string{tmpDir},
			}, nil
		}

		// Mode 2: Maven project directory — resolve classpath via
		// `mvn dependency:build-classpath`, then compile & run the staged
		// temp Java source with javac + java.
		pomPath := resolveUnidbgPomPath(tc.Unidbg.Path)
		if tc.Mvn.Ready && tc.Mvn.Path != "" && pomPath != "" {
			cpFile := filepath.Join(tmpDir, "unidbg-classpath.txt")
			pomDir := filepath.Dir(pomPath)
			readCP := func() (string, error) {
				raw, err := os.ReadFile(cpFile)
				if err != nil {
					return "", fmt.Errorf("read maven classpath %s: %w", cpFile, err)
				}
				var entries []string
				if s := strings.TrimSpace(string(raw)); s != "" {
					entries = append(entries, s)
				}
				for _, clsDir := range []string{
					filepath.Join(pomDir, "target", "classes"),
					filepath.Join(tc.Unidbg.Path, "unidbg-android", "target", "classes"),
					filepath.Join(tc.Unidbg.Path, "target", "classes"),
				} {
					if fi, err := os.Stat(clsDir); err == nil && fi.IsDir() {
						entries = append(entries, clsDir)
					}
				}
				if len(entries) == 0 {
					return "", fmt.Errorf("maven dependency:build-classpath produced empty classpath")
				}
				return strings.Join(entries, string(os.PathListSeparator)), nil
			}
			extraArgs := append([]string(nil), req.Args...)
			return &jobPlan{
				steps: []jobStep{
					{
						label: "mvn-classpath",
						bin:   tc.Mvn.Path,
						args:  []string{"-q", "-f", pomPath, "dependency:build-classpath", "-Dmdep.outputFile=" + cpFile},
						dir:   pomDir,
						env:   env,
					},
					{
						label: "javac",
						bin:   tc.JavacPath,
						resolveArgs: func() ([]string, error) {
							cp, err := readCP()
							if err != nil {
								return nil, err
							}
							return []string{"-encoding", "UTF-8", "-cp", cp, "-d", outDir, javaFile}, nil
						},
						dir: tmpDir,
						env: env,
					},
					{
						label: "java",
						bin:   tc.Java.Path,
						resolveArgs: func() ([]string, error) {
							cp, err := readCP()
							if err != nil {
								return nil, err
							}
							runCP := outDir + string(os.PathListSeparator) + cp
							return append([]string{"-cp", runCP, fqcn}, extraArgs...), nil
						},
						dir: firstNonEmpty(req.WorkDir, tmpDir),
						env: env,
					},
				},
				displayCmd: fmt.Sprintf("%s classpath && %s && %s %s",
					filepath.Base(tc.Mvn.Path), filepath.Base(tc.JavacPath), filepath.Base(tc.Java.Path), fqcn),
				tempPaths: []string{tmpDir},
			}, nil
		}

		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("Unidbg requires either pre-built JARs + javac or a Maven pom.xml with mvn + javac")

	default:
		return nil, fmt.Errorf("unsupported RE engine %q", req.Engine)
	}
}

func resolveUnidbgPomPath(unidbgPath string) string {
	for _, cand := range []string{
		filepath.Join(unidbgPath, "unidbg-android", "pom.xml"),
		filepath.Join(unidbgPath, "pom.xml"),
	} {
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand
		}
	}
	return ""
}

func buildJobEnv(req RunJobRequest, tc ToolchainInfo) []string {
	env := os.Environ()
	add := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			env = append(env, k+"="+v)
		}
	}
	binPath := strings.TrimSpace(req.BinaryPath)
	if binPath != "" {
		if _, err := os.Stat(binPath); err == nil {
			if abs, err := filepath.Abs(binPath); err == nil {
				binPath = abs
			}
		}
	}
	add("CAP_RE_BINARY", binPath)
	add("CAP_RE_APK", req.APKPath)
	add("CAP_RE_ROOTFS", firstNonEmpty(req.RootFS, tc.QilingRootFS))
	add("CAP_RE_SYMBOL", req.TargetSymbol)
	add("CAP_RE_TARGET_ADDR", req.TargetAddr)
	add("CAP_RE_ADDR", req.TargetAddr)
	add("CAP_RE_FIND_ADDR", req.FindAddr)
	add("CAP_RE_AVOID_ADDR", req.AvoidAddr)
	for k, v := range req.Env {
		if strings.TrimSpace(k) != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func (m *Manager) runJobPlan(job *activeJob, plan *jobPlan) {
	defer close(job.doneCh)
	defer job.cancel()
	defer cleanupPaths(job.tempPaths)

	var lastErr error
	exitCode := 0

	for idx, step := range plan.steps {
		if job.ctx.Err() != nil {
			lastErr = job.ctx.Err()
			break
		}
		if len(plan.steps) > 1 {
			m.appendLog(job.id, JobLogEvent{
				Stream:  "system",
				Level:   "system",
				Message: fmt.Sprintf("Step %d/%d (%s)...", idx+1, len(plan.steps), step.label),
			})
		}

		code, err := m.runSingleStep(job, step)
		exitCode = code
		if err != nil {
			lastErr = err
			break
		}
	}

	nowMs := time.Now().UnixMilli()
	cancelled := job.cancelled.Load() || errors.Is(job.ctx.Err(), context.Canceled)
	timedOut := errors.Is(job.ctx.Err(), context.DeadlineExceeded)

	switch {
	case cancelled:
		m.appendLog(job.id, JobLogEvent{
			Stream:  "system",
			Level:   "warn",
			Message: "Job cancelled by user",
		})
	case timedOut:
		m.appendLog(job.id, JobLogEvent{
			Stream:  "system",
			Level:   "error",
			Message: "Job exceeded timeout and was terminated",
		})
	case lastErr != nil:
		m.appendLog(job.id, JobLogEvent{
			Stream:  "system",
			Level:   "error",
			Message: fmt.Sprintf("Job failed (exit %d): %v", exitCode, lastErr),
		})
	default:
		m.appendLog(job.id, JobLogEvent{
			Stream:  "system",
			Level:   "system",
			Message: "Job completed successfully (exit 0)",
		})
	}

	m.mu.Lock()
	if m.active == job {
		m.active = nil
	}
	var snap *JobState
	onStatus := m.onStatus
	if m.state != nil && m.state.ID == job.id {
		m.state.Running = false
		m.state.PID = 0
		m.state.ExitCode = exitCode
		m.state.FinishedAtMs = nowMs
		if m.state.StartedAtMs > 0 {
			m.state.ElapsedMs = nowMs - m.state.StartedAtMs
		}
		switch {
		case cancelled:
			m.state.Status = StatusCancelled
			m.state.Error = "cancelled by user"
		case timedOut:
			m.state.Status = StatusError
			m.state.Error = "job timed out"
		case lastErr != nil:
			m.state.Status = StatusError
			m.state.Error = lastErr.Error()
		default:
			m.state.Status = StatusDone
		}
		snap = cloneJobState(m.state)
	}
	m.mu.Unlock()

	if onStatus != nil && snap != nil {
		onStatus(snap)
	}
}

func (m *Manager) runSingleStep(job *activeJob, step jobStep) (int, error) {
	args := step.args
	if step.resolveArgs != nil {
		resolved, err := step.resolveArgs()
		if err != nil {
			return -1, err
		}
		args = resolved
	}
	cmd := exec.CommandContext(job.ctx, step.bin, args...)
	if step.dir != "" {
		cmd.Dir = step.dir
	}
	cmd.Env = step.env
	configureProcGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return -1, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start %s: %w", step.label, err)
	}

	// Record live PID
	m.mu.Lock()
	if m.state != nil && m.state.ID == job.id && cmd.Process != nil {
		m.state.PID = cmd.Process.Pid
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		m.streamPipe(job.id, stdout, false)
	}()
	go func() {
		defer wg.Done()
		m.streamPipe(job.id, stderr, true)
	}()

	wg.Wait()
	waitErr := cmd.Wait()

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitCode(), waitErr
		}
		return -1, waitErr
	}
	return 0, nil
}

func (m *Manager) streamPipe(jobID string, r io.Reader, isStderr bool) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 32*1024), 2*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !isStderr {
			if idx := strings.Index(trimmed, StructuredOutputPrefix); idx >= 0 {
				jsonPart := strings.TrimSpace(trimmed[idx+len(StructuredOutputPrefix):])
				var payload map[string]any
				if json.Unmarshal([]byte(jsonPart), &payload) == nil {
					kind, _ := payload["kind"].(string)
					if kind == "" {
						kind = "generic"
					}
					summary := summarizeJobResult(payload)
					m.appendResult(jobID, JobResult{
						Kind:    kind,
						Summary: summary,
						Payload: payload,
					})
					m.appendLog(jobID, JobLogEvent{
						Stream:  "result",
						Level:   "result",
						Message: summary,
						Data:    payload,
						Raw:     trimmed,
					})
					continue
				}
			}
		}

		stream := "stdout"
		lvl := "info"
		if isStderr {
			stream = "stderr"
			lvl = "error"
		}
		m.appendLog(jobID, JobLogEvent{
			Stream:  stream,
			Level:   lvl,
			Message: line,
			Raw:     line,
		})
	}
}

func (m *Manager) appendLog(jobID string, ev JobLogEvent) {
	ev.Seq = m.seq.Add(1)
	ev.JobID = jobID
	if ev.TimestampMs == 0 {
		ev.TimestampMs = time.Now().UnixMilli()
	}

	m.mu.Lock()
	if m.state != nil && m.state.ID == jobID {
		m.state.EventCount++
		m.state.Events = append(m.state.Events, ev)
		if len(m.state.Events) > MaxJobEvents {
			m.state.Events = m.state.Events[len(m.state.Events)-MaxJobEvents:]
		}
	}
	onLog := m.onLog
	m.mu.Unlock()

	if onLog != nil {
		onLog(ev)
	}
}

func (m *Manager) appendResult(jobID string, res JobResult) {
	m.mu.Lock()
	if m.state != nil && m.state.ID == jobID {
		m.state.Results = append(m.state.Results, res)
	}
	m.mu.Unlock()
}

func summarizeJobResult(payload map[string]any) string {
	kind, _ := payload["kind"].(string)
	if v, ok := payload["solution_utf8"].(string); ok && v != "" {
		return fmt.Sprintf("[%s] solution = %q", firstNonEmpty(kind, "solution"), v)
	}
	if v, ok := payload["sign"].(string); ok && v != "" {
		return fmt.Sprintf("[%s] sign = %s", firstNonEmpty(kind, "signature"), v)
	}
	if v, ok := payload["result"].(string); ok && v != "" {
		return fmt.Sprintf("[%s] result = %s", firstNonEmpty(kind, "result"), v)
	}
	if v, ok := payload["url"].(string); ok && v != "" {
		return fmt.Sprintf("[%s] listening at %s", firstNonEmpty(kind, "server"), v)
	}
	if v, ok := payload["retval"].(string); ok && v != "" {
		sym, _ := payload["symbol"].(string)
		if sym != "" {
			return fmt.Sprintf("[%s] %s -> %s", firstNonEmpty(kind, "return_value"), sym, v)
		}
		return fmt.Sprintf("[%s] retval = %s", firstNonEmpty(kind, "return_value"), v)
	}
	if v, ok := payload["message"].(string); ok && v != "" {
		return fmt.Sprintf("[%s] %s", firstNonEmpty(kind, "info"), v)
	}
	b, _ := json.Marshal(payload)
	s := string(b)
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

func cloneJobState(st *JobState) *JobState {
	if st == nil {
		return &JobState{Status: StatusIdle, Events: []JobLogEvent{}, Results: []JobResult{}}
	}
	cp := *st
	cp.Events = make([]JobLogEvent, len(st.Events))
	copy(cp.Events, st.Events)
	cp.Results = make([]JobResult, len(st.Results))
	copy(cp.Results, st.Results)
	return &cp
}

func cleanupPaths(paths []string) {
	for _, p := range paths {
		if p != "" {
			_ = os.RemoveAll(p)
		}
	}
}
