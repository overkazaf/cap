package screen

import (
	"context"
	"reflect"
	"sync"
	"time"
)

// captureFunc is the single-frame capture implementation FastStream (and
// Capture, in screen.go) call through. It defaults to FastCapture; tests
// substitute a fake so the streaming/dispatch logic can be exercised
// without a real device or the adb binary.
var captureFunc = FastCapture

var defaultCaptureFuncPtr = reflect.ValueOf(FastCapture).Pointer()

// StreamStats summarizes live throughput and latency metrics for a frame stream.
type StreamStats struct {
	FPS        float64 `json:"fps"`
	LatencyMs  int64   `json:"latency_ms"`
	FrameCount uint64  `json:"frame_count"`
	Errors     uint64  `json:"errors"`
	Width      int     `json:"width"`
	Height     int     `json:"height"`
}

// fpsTracker computes a rolling frames-per-second measurement over a sliding
// window (default 2s) without unbounded memory growth.
type fpsTracker struct {
	window time.Duration
	times  []time.Time
}

func newFPSTracker(window time.Duration) *fpsTracker {
	if window <= 0 {
		window = 2 * time.Second
	}
	return &fpsTracker{
		window: window,
		times:  make([]time.Time, 0, 64),
	}
}

func (f *fpsTracker) record(now time.Time) {
	f.times = append(f.times, now)
	f.prune(now)
}

func (f *fpsTracker) prune(now time.Time) {
	cutoff := now.Add(-f.window)
	i := 0
	for i < len(f.times) && f.times[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		copy(f.times, f.times[i:])
		f.times = f.times[:len(f.times)-i]
	}
}

func (f *fpsTracker) fps(now time.Time) float64 {
	f.prune(now)
	n := len(f.times)
	if n == 0 {
		return 0
	}
	if n == 1 {
		elapsed := now.Sub(f.times[0]).Seconds()
		if elapsed <= 0 || elapsed > f.window.Seconds() {
			return 0
		}
		return 1.0 / maxFloat(elapsed, 0.25)
	}
	span := f.times[n-1].Sub(f.times[0]).Seconds()
	if span < 0.05 {
		span = now.Sub(f.times[0]).Seconds()
	}
	if span <= 0 {
		return 0
	}
	return float64(n-1) / span
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// FastStream continuously captures JPEG frames from a device in the
// background at a target frame rate and keeps the most recent one
// available via Frame and event-driven WaitFrame. It never overlaps
// concurrent `adb screencap` calls and cancels any in-flight subprocess
// immediately on Stop.
type FastStream struct {
	serial   string
	maxSize  int
	quality  int
	interval time.Duration

	mu         sync.Mutex
	latest     []byte
	seq        uint64
	notifyCh   chan struct{}
	lastErr    error
	running    bool
	cancelFunc context.CancelFunc
	doneCh     chan struct{}

	fpsTracker *fpsTracker
	latencyMs  int64
	frameCount uint64
	errorCount uint64
}

// NewFastStream creates a stream targeting serial (empty lets adb pick its
// default device). maxSize and quality are forwarded to FastCapture for
// every frame — see its docs for their meaning and defaults. fps is the
// target capture rate; fps <= 0 uses DefaultFPS, and since the interval is
// derived as time.Second/fps, an extreme fps that would otherwise round
// down to a non-positive interval is floored to 1ms instead.
func NewFastStream(serial string, maxSize, quality, fps int) *FastStream {
	if fps <= 0 {
		fps = DefaultFPS
	}
	interval := time.Second / time.Duration(fps)
	if interval <= 0 {
		interval = time.Millisecond
	}
	return &FastStream{
		serial:     serial,
		maxSize:    maxSize,
		quality:    quality,
		interval:   interval,
		notifyCh:   make(chan struct{}),
		fpsTracker: newFPSTracker(2 * time.Second),
	}
}

// Start begins capturing frames on a background goroutine. It captures one
// frame immediately, rather than waiting for the first interval, so Frame
// and WaitFrame have data as soon as possible. Calling Start while already
// running is a no-op.
func (fs *FastStream) Start() {
	fs.mu.Lock()
	if fs.running {
		fs.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	fs.running = true
	fs.cancelFunc = cancel
	fs.doneCh = doneCh
	if fs.notifyCh == nil {
		fs.notifyCh = make(chan struct{})
	}
	fs.mu.Unlock()

	go fs.loop(ctx, doneCh)
}

// loop captures frames back-to-back capped by fs.interval (never overlapping
// concurrent capture commands) until ctx is cancelled by Stop.
func (fs *FastStream) loop(ctx context.Context, doneCh chan struct{}) {
	defer close(doneCh)

	timer := time.NewTimer(fs.interval)
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	defer timer.Stop()

	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		fs.captureOnceContext(ctx)
		if ctx.Err() != nil {
			return
		}

		wait := fs.interval - time.Since(start)
		if wait <= 0 {
			continue
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}
	}
}

// captureOnce grabs a single frame via captureFunc (kept for unit tests).
func (fs *FastStream) captureOnce() {
	fs.captureOnceContext(context.Background())
}

// captureOnceContext grabs a single frame (cancelling adb on ctx.Done when
// using the default FastCapture path) and broadcasts availability to all
// WaitFrame subscribers immediately.
func (fs *FastStream) captureOnceContext(ctx context.Context) {
	start := time.Now()
	var frame []byte
	var err error

	if reflect.ValueOf(captureFunc).Pointer() == defaultCaptureFuncPtr {
		frame, err = FastCaptureContext(ctx, fs.serial, fs.maxSize, fs.quality)
	} else {
		frame, err = captureFunc(fs.serial, fs.maxSize, fs.quality)
	}
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		return
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err != nil {
		fs.lastErr = err
		fs.errorCount++
		return
	}
	fs.lastErr = nil
	fs.latest = frame
	fs.seq++
	fs.frameCount++
	fs.latencyMs = elapsed.Milliseconds()
	if fs.fpsTracker == nil {
		fs.fpsTracker = newFPSTracker(2 * time.Second)
	}
	fs.fpsTracker.record(time.Now())
	if fs.notifyCh != nil {
		close(fs.notifyCh)
	}
	fs.notifyCh = make(chan struct{})
}

// Stop halts capturing immediately (cancelling any in-flight adb screencap),
// wakes blocked WaitFrame callers, and blocks until the background goroutine
// exits. Calling Stop when not running is a no-op.
func (fs *FastStream) Stop() {
	fs.mu.Lock()
	if !fs.running {
		fs.mu.Unlock()
		return
	}
	fs.running = false
	cancel := fs.cancelFunc
	doneCh := fs.doneCh
	if fs.notifyCh != nil {
		close(fs.notifyCh)
		fs.notifyCh = make(chan struct{})
	}
	fs.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if doneCh != nil {
		<-doneCh
	}
}

// Frame returns the most recently captured JPEG frame, or nil if no frame
// has been captured yet.
func (fs *FastStream) Frame() []byte {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.latest
}

// WaitFrame blocks until a frame newer than afterSeq arrives, the stream
// stops, or ctx is cancelled. Returns (frame, seq, true) when a new frame is
// ready, or (nil, seq, false) on stop/cancellation.
func (fs *FastStream) WaitFrame(ctx context.Context, afterSeq uint64) ([]byte, uint64, bool) {
	for {
		fs.mu.Lock()
		if fs.seq > afterSeq && fs.latest != nil {
			frame := fs.latest
			seq := fs.seq
			fs.mu.Unlock()
			return frame, seq, true
		}
		if !fs.running {
			seq := fs.seq
			fs.mu.Unlock()
			return nil, seq, false
		}
		ch := fs.notifyCh
		fs.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, afterSeq, false
		case <-ch:
		}
	}
}

// Stats returns rolling FPS, latest capture latency, frame count, and errors.
func (fs *FastStream) Stats() StreamStats {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fps := 0.0
	if fs.fpsTracker != nil {
		fps = fs.fpsTracker.fps(time.Now())
	}
	return StreamStats{
		FPS:        fps,
		LatencyMs:  fs.latencyMs,
		FrameCount: fs.frameCount,
		Errors:     fs.errorCount,
	}
}

// Err returns the error from the most recent capture attempt, or nil if
// the most recent attempt succeeded (or none has run yet).
func (fs *FastStream) Err() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.lastErr
}

// IsRunning reports whether the background capture loop is active.
func (fs *FastStream) IsRunning() bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.running
}
