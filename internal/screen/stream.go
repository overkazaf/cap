package screen

import (
	"sync"
	"time"
)

// captureFunc is the single-frame capture implementation FastStream (and
// Capture, in screen.go) call through. It defaults to FastCapture; tests
// substitute a fake so the streaming/dispatch logic can be exercised
// without a real device or the adb binary.
var captureFunc = FastCapture

// FastStream continuously captures JPEG frames from a device in the
// background at a target frame rate and keeps the most recent one
// available via Frame. It deliberately keeps only the latest frame rather
// than queuing a backlog: a mirroring UI only ever wants to show what's on
// the device right now, so a frame the consumer didn't pick up in time is
// simply overwritten by the next capture.
type FastStream struct {
	serial   string
	maxSize  int
	quality  int
	interval time.Duration

	mu      sync.Mutex
	latest  []byte
	lastErr error
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewFastStream creates a stream targeting serial (empty lets adb pick its
// default device). maxSize and quality are forwarded to FastCapture for
// every frame — see its docs for their meaning and defaults. fps is the
// target capture rate; fps <= 0 uses DefaultFPS, and since the interval is
// derived as time.Second/fps, an extreme fps that would otherwise round
// down to a non-positive interval (and make time.NewTicker panic) is
// floored to 1ms instead.
func NewFastStream(serial string, maxSize, quality, fps int) *FastStream {
	if fps <= 0 {
		fps = DefaultFPS
	}
	interval := time.Second / time.Duration(fps)
	if interval <= 0 {
		interval = time.Millisecond
	}
	return &FastStream{
		serial:   serial,
		maxSize:  maxSize,
		quality:  quality,
		interval: interval,
	}
}

// Start begins capturing frames on a background goroutine. It captures one
// frame immediately, rather than waiting for the first tick, so Frame has
// something to return as soon as possible. Calling Start while already
// running is a no-op.
func (fs *FastStream) Start() {
	fs.mu.Lock()
	if fs.running {
		fs.mu.Unlock()
		return
	}
	fs.running = true
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	fs.stopCh = stopCh
	fs.doneCh = doneCh
	fs.mu.Unlock()

	go fs.loop(stopCh, doneCh)
}

// loop is the background capture goroutine started by Start. stopCh and
// doneCh are passed in (rather than read from fs) so a Stop/Start racing
// with this goroutine always coordinates with the pair it was launched
// with, never a newer one installed by a later Start.
func (fs *FastStream) loop(stopCh, doneCh chan struct{}) {
	defer close(doneCh)

	fs.captureOnce()

	ticker := time.NewTicker(fs.interval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			fs.captureOnce()
		}
	}
}

// captureOnce grabs a single frame via captureFunc and, on success, stores
// it as the latest frame. A failed capture updates Err() but leaves any
// previous good frame in place, so a transient adb hiccup doesn't blank
// out the mirrored screen.
func (fs *FastStream) captureOnce() {
	frame, err := captureFunc(fs.serial, fs.maxSize, fs.quality)

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err != nil {
		fs.lastErr = err
		return
	}
	fs.lastErr = nil
	fs.latest = frame
}

// Stop halts capturing and blocks until the background goroutine has
// exited before returning. Calling Stop when not running is a no-op.
func (fs *FastStream) Stop() {
	fs.mu.Lock()
	if !fs.running {
		fs.mu.Unlock()
		return
	}
	fs.running = false
	stopCh := fs.stopCh
	doneCh := fs.doneCh
	fs.mu.Unlock()

	close(stopCh)
	<-doneCh
}

// Frame returns the most recently captured JPEG frame, or nil if no frame
// has been captured yet.
func (fs *FastStream) Frame() []byte {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.latest
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
