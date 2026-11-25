package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/fsutil"
)

const (
	fileWorkers                = "workers.json"
	minWorkerInstances         = 1
	maxWorkerInstances         = 8
	defaultWorkerProbeInterval = 2 * time.Second
	defaultWorkerProbeTimeout  = 2 * time.Second
	maxWorkerStderrTailBytes   = 4096
	maxWorkerRestartBackoff    = 30 * time.Second
)

// tailBuffer is a thread-safe rolling byte buffer that retains the last `limit`
// bytes written to it (used for worker stderr tail capture).
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func newTailBuffer(limit int) *tailBuffer {
	if limit <= 0 {
		limit = maxWorkerStderrTailBytes
	}
	return &tailBuffer{limit: limit}
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(p) >= t.limit {
		t.buf = append(t.buf[:0], p[len(p)-t.limit:]...)
		return len(p), nil
	}
	if len(t.buf)+len(p) > t.limit {
		excess := len(t.buf) + len(p) - t.limit
		copy(t.buf, t.buf[excess:])
		t.buf = t.buf[:len(t.buf)-excess]
	}
	t.buf = append(t.buf, p...)
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

func (t *tailBuffer) Reset() {
	t.mu.Lock()
	t.buf = t.buf[:0]
	t.mu.Unlock()
}

type managedInstanceState struct {
	mu        sync.Mutex
	index     int
	port      int
	endpoint  string
	signURL   string
	healthURL string
	pid       int
	running   bool
	healthy   bool
	inFlight  atomic.Int64
	restarts  int
	latencyMs int64
	startedAt string
	lastProbe string
	lastError string
	stderr    *tailBuffer
}

func (inst *managedInstanceState) snapshot() ManagedWorkerInstance {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return ManagedWorkerInstance{
		Index:      inst.index,
		Port:       inst.port,
		Endpoint:   inst.endpoint,
		SignURL:    inst.signURL,
		PID:        inst.pid,
		Running:    inst.running,
		Healthy:    inst.healthy,
		InFlight:   inst.inFlight.Load(),
		Restarts:   inst.restarts,
		LatencyMs:  inst.latencyMs,
		StartedAt:  inst.startedAt,
		LastProbe:  inst.lastProbe,
		LastError:  inst.lastError,
		StderrTail: strings.TrimSpace(inst.stderr.String()),
	}
}

type workerRuntime struct {
	spec      ManagedWorkerSpec
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	instances []*managedInstanceState
	probeNow  chan struct{}
	rrCounter atomic.Uint64
}

// WorkerPool supervises pools of local HTTP signer worker subprocesses bound to
// consecutive loopback ports (127.0.0.1:<BasePort+i>), probing their health
// endpoints and auto-restarting crashed instances with exponential backoff.
type WorkerPool struct {
	filePath string

	mu        sync.RWMutex
	persistMu sync.Mutex
	specs     map[string]ManagedWorkerSpec
	runtimes  map[string]*workerRuntime

	probeInterval time.Duration
	probeTimeout  time.Duration
	probeClient   *http.Client
}

// NewWorkerPool constructs a Managed Signer Worker Process Pool backed by
// filePath (if non-empty).
func NewWorkerPool(filePath string) *WorkerPool {
	tr := &http.Transport{
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
	}
	return &WorkerPool{
		filePath:      strings.TrimSpace(filePath),
		specs:         make(map[string]ManagedWorkerSpec),
		runtimes:      make(map[string]*workerRuntime),
		probeInterval: defaultWorkerProbeInterval,
		probeTimeout:  defaultWorkerProbeTimeout,
		probeClient: &http.Client{
			Transport: tr,
			Timeout:   defaultWorkerProbeTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// SetProbeInterval adjusts the periodic health check interval (primarily for
// tests or fast local supervision).
func (w *WorkerPool) SetProbeInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	w.mu.Lock()
	w.probeInterval = d
	w.mu.Unlock()
}

// LoadFromDisk loads persisted ManagedWorkerSpecs from w.filePath if present.
func (w *WorkerPool) LoadFromDisk() error {
	if w.filePath == "" {
		return nil
	}
	raw, err := os.ReadFile(w.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []ManagedWorkerSpec
	if err := json.Unmarshal(raw, &list); err != nil {
		return err
	}
	w.mu.Lock()
	w.specs = make(map[string]ManagedWorkerSpec, len(list))
	for _, spec := range list {
		if strings.TrimSpace(spec.ID) == "" {
			continue
		}
		spec = normalizeWorkerSpecDefaults(spec)
		w.specs[spec.ID] = cloneManagedWorkerSpec(spec)
	}
	w.mu.Unlock()
	return nil
}

// ValidateWorkerSpec validates a ManagedWorkerSpec configuration.
func ValidateWorkerSpec(spec *ManagedWorkerSpec) error {
	if spec == nil {
		return errors.New("worker spec is nil")
	}
	if strings.TrimSpace(spec.Name) == "" {
		return errors.New("worker name is required")
	}
	switch strings.ToLower(strings.TrimSpace(spec.Kind)) {
	case "", WorkerKindUnidbgHTTP, WorkerKindQilingHTTP, WorkerKindScriptHTTP, WorkerKindCustom:
	default:
		return fmt.Errorf("unsupported worker kind %q", spec.Kind)
	}
	if strings.TrimSpace(spec.Command) == "" {
		return errors.New("worker command is required")
	}
	if spec.BasePort <= 0 || spec.BasePort > 65535 {
		return fmt.Errorf("invalid base_port %d (must be 1..65535)", spec.BasePort)
	}
	if spec.Instances < 0 {
		return fmt.Errorf("instances must be between %d and %d (got %d)", minWorkerInstances, maxWorkerInstances, spec.Instances)
	}
	inst := spec.Instances
	if inst == 0 {
		inst = 1
	}
	if inst < minWorkerInstances || inst > maxWorkerInstances {
		return fmt.Errorf("instances must be between %d and %d (got %d)", minWorkerInstances, maxWorkerInstances, spec.Instances)
	}
	if spec.BasePort+inst-1 > 65535 {
		return fmt.Errorf("port range %d..%d exceeds 65535", spec.BasePort, spec.BasePort+inst-1)
	}
	return nil
}

func normalizeWorkerSpecDefaults(spec ManagedWorkerSpec) ManagedWorkerSpec {
	spec.Name = strings.TrimSpace(spec.Name)
	spec.Kind = strings.ToLower(strings.TrimSpace(spec.Kind))
	if spec.Kind == "" {
		spec.Kind = WorkerKindCustom
	}
	spec.Command = strings.TrimSpace(spec.Command)
	spec.WorkDir = strings.TrimSpace(spec.WorkDir)
	if spec.Instances <= 0 {
		spec.Instances = 1
	}
	if spec.Instances > maxWorkerInstances {
		spec.Instances = maxWorkerInstances
	}
	spec.HealthPath = normalizeHTTPPath(spec.HealthPath, DefaultWorkerHealthPath)
	spec.SignPath = normalizeHTTPPath(spec.SignPath, DefaultWorkerSignPath)
	if spec.MaxRestarts <= 0 {
		spec.MaxRestarts = DefaultWorkerMaxRestarts
	}
	if spec.RestartBackoffMs <= 0 {
		spec.RestartBackoffMs = DefaultWorkerRestartBackoffMs
	}
	return spec
}

func normalizeHTTPPath(raw, fallback string) string {
	p := strings.TrimSpace(raw)
	if p == "" {
		return fallback
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// ListSpecs returns all configured ManagedWorkerSpecs sorted by name then ID.
func (w *WorkerPool) ListSpecs() []ManagedWorkerSpec {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]ManagedWorkerSpec, 0, len(w.specs))
	for _, s := range w.specs {
		out = append(out, cloneManagedWorkerSpec(s))
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

// GetSpec returns a single ManagedWorkerSpec by ID.
func (w *WorkerPool) GetSpec(id string) (*ManagedWorkerSpec, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	s, ok := w.specs[strings.TrimSpace(id)]
	if !ok {
		return nil, false
	}
	cp := cloneManagedWorkerSpec(s)
	return &cp, true
}

// SaveSpec validates, normalizes, stores, and persists a ManagedWorkerSpec.
func (w *WorkerPool) SaveSpec(spec ManagedWorkerSpec) (*ManagedWorkerSpec, error) {
	if err := ValidateWorkerSpec(&spec); err != nil {
		return nil, err
	}
	spec = normalizeWorkerSpecDefaults(spec)
	spec.ID = strings.TrimSpace(spec.ID)
	if spec.ID == "" {
		spec.ID = fmt.Sprintf("worker-%s-%s", sanitizeID(spec.Name, "pool"), randomHex(4))
	}

	nowStr := nowRFC3339()
	w.mu.Lock()
	if prev, exists := w.specs[spec.ID]; exists && spec.CreatedAt == "" {
		spec.CreatedAt = prev.CreatedAt
	}
	if spec.CreatedAt == "" {
		spec.CreatedAt = nowStr
	}
	spec.UpdatedAt = nowStr
	w.specs[spec.ID] = cloneManagedWorkerSpec(spec)
	w.mu.Unlock()

	cp := cloneManagedWorkerSpec(spec)
	if err := w.persist(); err != nil {
		return &cp, err
	}
	return &cp, nil
}

// DeleteSpec stops any running runtime for id, deletes the spec, and persists.
func (w *WorkerPool) DeleteSpec(id string) error {
	id = strings.TrimSpace(id)
	_ = w.StopWorker(id)

	w.mu.Lock()
	if _, ok := w.specs[id]; !ok {
		w.mu.Unlock()
		return fmt.Errorf("worker %q not found", id)
	}
	delete(w.specs, id)
	w.mu.Unlock()
	return w.persist()
}

// StartWorker spawns all configured instances for worker spec id and starts
// background health probing and crash auto-restart supervision.
func (w *WorkerPool) StartWorker(id string) error {
	id = strings.TrimSpace(id)
	w.mu.Lock()
	spec, ok := w.specs[id]
	if !ok {
		w.mu.Unlock()
		return fmt.Errorf("worker %q not found", id)
	}
	if _, running := w.runtimes[id]; running {
		w.mu.Unlock()
		return fmt.Errorf("worker %q is already running", id)
	}
	probeInterval := w.probeInterval
	spec = normalizeWorkerSpecDefaults(spec)
	if err := ValidateWorkerSpec(&spec); err != nil {
		w.mu.Unlock()
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt := &workerRuntime{
		spec:      cloneManagedWorkerSpec(spec),
		ctx:       ctx,
		cancel:    cancel,
		instances: make([]*managedInstanceState, spec.Instances),
		probeNow:  make(chan struct{}, 1),
	}
	for i := 0; i < spec.Instances; i++ {
		port := spec.BasePort + i
		endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
		rt.instances[i] = &managedInstanceState{
			index:     i,
			port:      port,
			endpoint:  endpoint,
			signURL:   endpoint + spec.SignPath,
			healthURL: endpoint + spec.HealthPath,
			stderr:    newTailBuffer(maxWorkerStderrTailBytes),
		}
	}
	w.runtimes[id] = rt
	w.mu.Unlock()

	for _, inst := range rt.instances {
		rt.wg.Add(1)
		go w.superviseInstance(rt, inst)
	}
	rt.wg.Add(1)
	go w.runHealthSupervisor(rt, probeInterval)

	return nil
}

// StopWorker cleanly terminates all child process groups for worker id and
// waits until all subprocesses and supervisor goroutines have exited.
func (w *WorkerPool) StopWorker(id string) error {
	id = strings.TrimSpace(id)
	w.mu.Lock()
	rt, ok := w.runtimes[id]
	if !ok {
		w.mu.Unlock()
		return nil
	}
	delete(w.runtimes, id)
	w.mu.Unlock()

	w.stopRuntime(rt)
	return nil
}

// RestartWorker stops (if running) and re-starts worker id using the latest spec.
func (w *WorkerPool) RestartWorker(id string) error {
	if err := w.StopWorker(id); err != nil {
		return err
	}
	return w.StartWorker(id)
}

// Shutdown stops all running worker pools cleanly and closes probe transports.
func (w *WorkerPool) Shutdown() {
	w.mu.Lock()
	active := make([]*workerRuntime, 0, len(w.runtimes))
	for id, rt := range w.runtimes {
		active = append(active, rt)
		delete(w.runtimes, id)
	}
	w.mu.Unlock()

	var wg sync.WaitGroup
	for _, rt := range active {
		wg.Add(1)
		go func(r *workerRuntime) {
			defer wg.Done()
			w.stopRuntime(r)
		}(rt)
	}
	wg.Wait()

	if tr, ok := w.probeClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func (w *WorkerPool) stopRuntime(rt *workerRuntime) {
	if rt == nil {
		return
	}
	// Cancelling rt.ctx triggers exec.CommandContext's cmd.Cancel -> killProcGroup(cmd)
	// strictly BEFORE cmd.Wait() reaps the child, avoiding any post-reap PID-reuse hazard.
	rt.cancel()
	rt.wg.Wait()
}

func (w *WorkerPool) superviseInstance(rt *workerRuntime, inst *managedInstanceState) {
	defer rt.wg.Done()

	restarts := 0
	for {
		if rt.ctx.Err() != nil {
			return
		}

		cmd := exec.CommandContext(rt.ctx, rt.spec.Command, rt.spec.Args...)
		configureProcGroup(cmd)
		if rt.spec.WorkDir != "" {
			cmd.Dir = rt.spec.WorkDir
		}
		cmd.Env = buildWorkerEnv(rt.spec, inst)
		cmd.Stdout = io.Discard
		cmd.Stderr = inst.stderr

		if err := cmd.Start(); err != nil {
			inst.mu.Lock()
			inst.pid = 0
			inst.running = false
			inst.healthy = false
			inst.lastError = fmt.Sprintf("start failed: %v", err)
			inst.mu.Unlock()
		} else {
			pgid := 0
			if cmd.Process != nil {
				pgid = cmd.Process.Pid
			}
			inst.mu.Lock()
			inst.pid = pgid
			inst.running = true
			inst.healthy = false
			inst.startedAt = nowRFC3339()
			inst.lastError = ""
			inst.mu.Unlock()

			// Nudge health supervisor to probe promptly after start or crash restart.
			select {
			case rt.probeNow <- struct{}{}:
			default:
			}

			waitErr := cmd.Wait()
			// On spontaneous crash (not cmd.Cancel), signal only -pgid (never bare pid)
			// to reap any stray grandchildren left behind by the exited worker.
			if rt.ctx.Err() == nil && pgid > 0 {
				signalProcGroupOnly(pgid)
			}

			inst.mu.Lock()
			inst.pid = 0
			inst.running = false
			inst.healthy = false
			if waitErr != nil && rt.ctx.Err() == nil {
				inst.lastError = fmt.Sprintf("process exited: %v", waitErr)
			}
			inst.mu.Unlock()
		}

		if rt.ctx.Err() != nil {
			return
		}
		if !rt.spec.AutoRestart || restarts >= rt.spec.MaxRestarts {
			return
		}

		backoff := computeRestartBackoff(rt.spec.RestartBackoffMs, restarts)
		restarts++
		inst.mu.Lock()
		inst.restarts = restarts
		inst.mu.Unlock()

		timer := time.NewTimer(backoff)
		select {
		case <-rt.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func buildWorkerEnv(spec ManagedWorkerSpec, inst *managedInstanceState) []string {
	env := append([]string(nil), os.Environ()...)
	if len(spec.Env) > 0 {
		keys := make([]string, 0, len(spec.Env))
		for k := range spec.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.TrimSpace(k) != "" {
				env = append(env, fmt.Sprintf("%s=%s", k, spec.Env[k]))
			}
		}
	}
	portStr := strconv.Itoa(inst.port)
	env = append(env,
		"CAP_RE_HTTP_PORT="+portStr,
		"PORT="+portStr,
		"CAP_WORKER_ID="+spec.ID,
		"CAP_WORKER_INDEX="+strconv.Itoa(inst.index),
	)
	return env
}

func computeRestartBackoff(baseMs int, attempt int) time.Duration {
	if baseMs <= 0 {
		baseMs = DefaultWorkerRestartBackoffMs
	}
	shift := attempt
	if shift > 6 {
		shift = 6
	}
	d := time.Duration(baseMs) * time.Millisecond * time.Duration(1<<shift)
	if d > maxWorkerRestartBackoff {
		return maxWorkerRestartBackoff
	}
	return d
}

func (w *WorkerPool) runHealthSupervisor(rt *workerRuntime, interval time.Duration) {
	defer rt.wg.Done()
	if interval <= 0 {
		interval = defaultWorkerProbeInterval
	}

	runWarmup := func() bool {
		for _, d := range []time.Duration{40 * time.Millisecond, 80 * time.Millisecond, 150 * time.Millisecond} {
			timer := time.NewTimer(d)
			select {
			case <-rt.ctx.Done():
				timer.Stop()
				return false
			case <-timer.C:
			}
			w.probeRuntimeInstances(rt)
			if allInstancesHealthy(rt) {
				break
			}
		}
		return true
	}

	if !runWarmup() {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rt.ctx.Done():
			return
		case <-rt.probeNow:
			if !runWarmup() {
				return
			}
		case <-ticker.C:
			w.probeRuntimeInstances(rt)
		}
	}
}

func allInstancesHealthy(rt *workerRuntime) bool {
	for _, inst := range rt.instances {
		inst.mu.Lock()
		ok := inst.running && inst.healthy
		inst.mu.Unlock()
		if !ok {
			return false
		}
	}
	return len(rt.instances) > 0
}

func (w *WorkerPool) probeRuntimeInstances(rt *workerRuntime) {
	var wg sync.WaitGroup
	for _, inst := range rt.instances {
		inst.mu.Lock()
		running := inst.running
		healthURL := inst.healthURL
		inst.mu.Unlock()
		if !running {
			continue
		}
		wg.Add(1)
		go func(st *managedInstanceState, url string) {
			defer wg.Done()
			w.probeSingleInstance(rt.ctx, st, url)
		}(inst, healthURL)
	}
	wg.Wait()
}

func (w *WorkerPool) probeSingleInstance(ctx context.Context, inst *managedInstanceState, healthURL string) {
	probeCtx, cancel := context.WithTimeout(ctx, w.probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, healthURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "cap-worker-health/1.0")

	start := time.Now()
	resp, err := w.probeClient.Do(req)
	latMs := time.Since(start).Milliseconds()
	if latMs <= 0 {
		latMs = 1
	}

	nowStr := nowRFC3339()
	if err != nil {
		inst.mu.Lock()
		if inst.running {
			inst.healthy = false
			inst.lastProbe = nowStr
			inst.latencyMs = latMs
			inst.lastError = redactSecrets(err.Error())
		}
		inst.mu.Unlock()
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	ok := resp.StatusCode >= 200 && resp.StatusCode < 400
	inst.mu.Lock()
	if inst.running {
		inst.healthy = ok
		inst.lastProbe = nowStr
		inst.latencyMs = latMs
		if ok {
			inst.lastError = ""
		} else {
			inst.lastError = fmt.Sprintf("health probe HTTP %d", resp.StatusCode)
		}
	}
	inst.mu.Unlock()
}

// ListWorkerStatuses returns runtime status snapshots for all configured worker specs.
func (w *WorkerPool) ListWorkerStatuses() []ManagedWorkerStatus {
	w.mu.RLock()
	specs := make([]ManagedWorkerSpec, 0, len(w.specs))
	runtimes := make(map[string]*workerRuntime, len(w.runtimes))
	for _, s := range w.specs {
		specs = append(specs, cloneManagedWorkerSpec(s))
	}
	for id, rt := range w.runtimes {
		runtimes[id] = rt
	}
	w.mu.RUnlock()

	sort.Slice(specs, func(i, j int) bool {
		ni, nj := strings.ToLower(specs[i].Name), strings.ToLower(specs[j].Name)
		if ni != nj {
			return ni < nj
		}
		return specs[i].ID < specs[j].ID
	})

	out := make([]ManagedWorkerStatus, 0, len(specs))
	for _, spec := range specs {
		status := ManagedWorkerStatus{
			Spec:           spec,
			TotalInstances: spec.Instances,
		}
		if rt, active := runtimes[spec.ID]; active {
			status.Running = true
			status.Instances = make([]ManagedWorkerInstance, 0, len(rt.instances))
			for _, inst := range rt.instances {
				snap := inst.snapshot()
				if snap.Running && snap.Healthy {
					status.HealthyInstances++
				}
				status.Instances = append(status.Instances, snap)
			}
		} else {
			status.Instances = make([]ManagedWorkerInstance, 0, spec.Instances)
			for i := 0; i < spec.Instances; i++ {
				port := spec.BasePort + i
				endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
				status.Instances = append(status.Instances, ManagedWorkerInstance{
					Index:    i,
					Port:     port,
					Endpoint: endpoint,
					SignURL:  endpoint + spec.SignPath,
				})
			}
		}
		out = append(out, status)
	}
	return out
}

// Counts returns (totalConfiguredInstances, healthyRunningInstances) across all
// managed worker pools.
func (w *WorkerPool) Counts() (total int, healthy int) {
	w.mu.RLock()
	for _, spec := range w.specs {
		n := spec.Instances
		if n <= 0 {
			n = 1
		}
		total += n
	}
	runtimes := make([]*workerRuntime, 0, len(w.runtimes))
	for _, rt := range w.runtimes {
		runtimes = append(runtimes, rt)
	}
	w.mu.RUnlock()

	for _, rt := range runtimes {
		for _, inst := range rt.instances {
			inst.mu.Lock()
			if inst.running && inst.healthy {
				healthy++
			}
			inst.mu.Unlock()
		}
	}
	return total, healthy
}

// PickHealthyEndpoint selects the next healthy signing endpoint URL
// (`http://127.0.0.1:<port><SignPath>`) for workerID using least-inflight
// with round-robin tie-breaking.
func (w *WorkerPool) PickHealthyEndpoint(workerID string) (string, error) {
	endpoint, release, err := w.AcquireHealthyEndpoint(workerID)
	if err != nil {
		return "", err
	}
	release()
	return endpoint, nil
}

// AcquireHealthyEndpoint picks the best healthy instance for workerID,
// increments its in-flight counter, and returns its signing endpoint URL along
// with a release callback to decrement in-flight when the signing call finishes.
func (w *WorkerPool) AcquireHealthyEndpoint(workerID string) (string, func(), error) {
	workerID = strings.TrimSpace(workerID)
	w.mu.RLock()
	rt, ok := w.runtimes[workerID]
	_, specExists := w.specs[workerID]
	w.mu.RUnlock()

	if !ok {
		if !specExists {
			return "", nil, fmt.Errorf("worker pool %q not found", workerID)
		}
		return "", nil, fmt.Errorf("worker pool %q is not running", workerID)
	}

	var healthy []*managedInstanceState
	for _, inst := range rt.instances {
		inst.mu.Lock()
		isOK := inst.running && inst.healthy
		inst.mu.Unlock()
		if isOK {
			healthy = append(healthy, inst)
		}
	}
	if len(healthy) == 0 {
		return "", nil, fmt.Errorf("worker pool %q has no healthy instances", workerID)
	}

	// Single-pass least-inflight selection (capturing each Load() once so best is
	// guaranteed non-empty under concurrent mutations).
	var minInFlight int64
	best := make([]*managedInstanceState, 0, len(healthy))
	for i, inst := range healthy {
		v := inst.inFlight.Load()
		if i == 0 || v < minInFlight {
			minInFlight = v
			best = append(best[:0], inst)
		} else if v == minInFlight {
			best = append(best, inst)
		}
	}

	// Round-robin tie-break across equally loaded healthy instances.
	idx := rt.rrCounter.Add(1) - 1
	chosen := best[idx%uint64(len(best))]
	chosen.inFlight.Add(1)
	var once sync.Once
	release := func() {
		once.Do(func() {
			chosen.inFlight.Add(-1)
		})
	}
	return chosen.signURL, release, nil
}

func (w *WorkerPool) persist() error {
	if w.filePath == "" {
		return nil
	}
	w.persistMu.Lock()
	defer w.persistMu.Unlock()
	data, err := json.MarshalIndent(w.ListSpecs(), "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(w.filePath, data, 0o600)
}
