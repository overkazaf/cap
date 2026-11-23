package screen

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	mjpegBoundary          = "capframe"
	defaultMJPEGIdleTime   = 20 * time.Second
	defaultScrcpyStreamFPS = 30
)

// FrameSource abstracts a live JPEG frame producer (*FastStream or *ScrcpyServer)
// for MJPEGServer.
type FrameSource interface {
	Frame() []byte
	WaitFrame(ctx context.Context, afterSeq uint64) (frame []byte, seq uint64, ok bool)
	Stats() StreamStats
	IsRunning() bool
	Stop()
}

// MJPEGConfig configures a loopback MJPEG streaming session.
type MJPEGConfig struct {
	Serial      string
	Engine      string        // "auto", "scrcpy", "fast"
	MaxSize     int           // longest dimension in pixels (<=0 uses DefaultMaxSize)
	Quality     int           // JPEG quality 1-100 (<=0 uses DefaultQuality)
	FPS         int           // target FPS (<=0 defaults to 30 for scrcpy, DefaultFPS for fast)
	IdleTimeout time.Duration // auto-stop if no HTTP client connects within this duration (<=0 disables or uses default in NewMJPEGServer)
}

// MJPEGInfo describes a started loopback MJPEG stream.
type MJPEGInfo struct {
	URL             string `json:"url"`
	Engine          string `json:"engine"`           // active engine: "scrcpy" or "fast"
	RequestedEngine string `json:"requested_engine"` // normalized requested engine: "auto", "scrcpy", "fast"
	Width           int    `json:"width"`
	Height          int    `json:"height"`
	ScrcpyReady     bool   `json:"scrcpy_ready"`
	FallbackReason  string `json:"fallback_reason,omitempty"`
}

// MJPEGStats summarizes live telemetry for an active MJPEGServer.
type MJPEGStats struct {
	Active    bool    `json:"active"`
	Engine    string  `json:"engine"`
	Serial    string  `json:"serial"`
	FPS       float64 `json:"fps"`
	LatencyMs int64   `json:"latency_ms"`
	Frames    uint64  `json:"frames"`
	Errors    uint64  `json:"errors"`
	Width     int     `json:"width"`
	Height    int     `json:"height"`
	Clients   int     `json:"clients"`
}

// MJPEGServer serves a live `multipart/x-mixed-replace` JPEG stream over a
// loopback-only (`127.0.0.1:0`) HTTP listener protected by a per-session
// random token, so WebKit/WKWebView can render live Android screens directly
// in an `<img>` element off the JS main thread without base64 JSON-RPC overhead.
type MJPEGServer struct {
	serial          string
	engine          string
	requestedEngine string
	scrcpyReady     bool
	fallbackReason  string
	token           string
	streamPath      string
	url             string
	idleTimeout     time.Duration

	source   FrameSource
	listener net.Listener
	server   *http.Server

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	stopped   bool
	clients   int
	idleTimer *time.Timer
	width     int
	height    int
}

// StartMJPEGServer starts a loopback MJPEG server backed by either
// ScrcpyServer (when requested or in "auto" mode with ffmpeg + scrcpy-server
// available) or FastStream (with automatic fallback).
func StartMJPEGServer(cfg MJPEGConfig) (*MJPEGServer, error) {
	reqEngine := normalizeEngineName(cfg.Engine)
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	quality := clampQuality(cfg.Quality)
	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultMJPEGIdleTime
	}

	_, ffmpegErr := lookPath("ffmpeg")
	hasFFmpeg := ffmpegErr == nil
	deployed := false
	if hasFFmpeg && reqEngine != "fast" {
		deployed = IsScrcpyDeployed(cfg.Serial)
	}
	scrcpyReady := hasFFmpeg && deployed

	var (
		source         FrameSource
		activeEngine   string
		fallbackReason string
		videoW, videoH int
	)

	tryScrcpy := func(allowDeploy bool) bool {
		if !hasFFmpeg {
			fallbackReason = "ffmpeg not found in PATH"
			return false
		}
		if !allowDeploy && !deployed {
			fallbackReason = "scrcpy-server not deployed on device"
			return false
		}
		fps := cfg.FPS
		if fps <= 0 {
			fps = defaultScrcpyStreamFPS
		}
		srv := NewScrcpyServer(cfg.Serial, maxSize, fps, quality)
		if err := srv.Start(); err != nil {
			fallbackReason = err.Error()
			return false
		}
		videoW, videoH = srv.VideoSize()
		source = srv
		activeEngine = "scrcpy"
		scrcpyReady = true
		return true
	}

	switch reqEngine {
	case "scrcpy":
		if !tryScrcpy(true) {
			fs := startFastStream(cfg.Serial, maxSize, quality, cfg.FPS)
			source = fs
			activeEngine = "fast"
		}
	case "auto":
		if !tryScrcpy(false) {
			fs := startFastStream(cfg.Serial, maxSize, quality, cfg.FPS)
			source = fs
			activeEngine = "fast"
		}
	default: // "fast"
		fs := startFastStream(cfg.Serial, maxSize, quality, cfg.FPS)
		source = fs
		activeEngine = "fast"
	}

	srv, err := NewMJPEGServerWithSource(source, activeEngine, cfg.Serial, idleTimeout)
	if err != nil {
		source.Stop()
		return nil, err
	}
	srv.requestedEngine = reqEngine
	srv.scrcpyReady = scrcpyReady
	srv.fallbackReason = fallbackReason
	srv.mu.Lock()
	srv.width = videoW
	srv.height = videoH
	srv.mu.Unlock()
	return srv, nil
}

func startFastStream(serial string, maxSize, quality, fps int) *FastStream {
	if fps <= 0 {
		fps = DefaultFPS
	}
	fs := NewFastStream(serial, maxSize, quality, fps)
	fs.Start()
	return fs
}

func normalizeEngineName(engine string) string {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case "scrcpy":
		return "scrcpy"
	case "fast", "screencap":
		return "fast"
	default:
		return "auto"
	}
}

// NewMJPEGServerWithSource binds a loopback-only HTTP server serving frames
// from source. Exported so callers and tests can wire custom FrameSources.
func NewMJPEGServerWithSource(source FrameSource, engine, serial string, idleTimeout time.Duration) (*MJPEGServer, error) {
	if source == nil {
		return nil, fmt.Errorf("screen: nil frame source")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("screen: bind loopback mjpeg listener: %w", err)
	}

	token, err := randomTokenHex(16)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("screen: generate stream token: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	streamPath := "/stream/" + token + ".mjpg"
	m := &MJPEGServer{
		serial:          serial,
		engine:          engine,
		requestedEngine: engine,
		token:           token,
		streamPath:      streamPath,
		url:             fmt.Sprintf("http://%s%s", ln.Addr().String(), streamPath),
		idleTimeout:     idleTimeout,
		source:          source,
		listener:        ln,
		ctx:             ctx,
		cancel:          cancel,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(streamPath, m.handleStream)
	m.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		_ = m.server.Serve(ln)
	}()

	// Start initial idle timeout so an orphaned stream with no connected
	// browser <img> cleans itself up automatically.
	if idleTimeout > 0 {
		m.resetIdleTimerLocked(true)
	}

	return m, nil
}

func randomTokenHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SetDimensions records native device dimensions (e.g. from `wm size`) when
// the underlying source does not report them directly.
func (m *MJPEGServer) SetDimensions(w, h int) {
	m.mu.Lock()
	if w > 0 && h > 0 {
		m.width = w
		m.height = h
	}
	m.mu.Unlock()
}

// Info returns the stream URL, active engine, dimensions, and fallback details.
func (m *MJPEGServer) Info() MJPEGInfo {
	m.mu.Lock()
	w, h := m.width, m.height
	m.mu.Unlock()

	if w == 0 || h == 0 {
		st := m.source.Stats()
		if st.Width > 0 && st.Height > 0 {
			w, h = st.Width, st.Height
		}
	}

	return MJPEGInfo{
		URL:             m.url,
		Engine:          m.engine,
		RequestedEngine: m.requestedEngine,
		Width:           w,
		Height:          h,
		ScrcpyReady:     m.scrcpyReady,
		FallbackReason:  m.fallbackReason,
	}
}

// Stats returns live stream telemetry.
func (m *MJPEGServer) Stats() MJPEGStats {
	m.mu.Lock()
	active := !m.stopped && m.source.IsRunning()
	clients := m.clients
	w, h := m.width, m.height
	m.mu.Unlock()

	st := m.source.Stats()
	if w == 0 && st.Width > 0 {
		w = st.Width
	}
	if h == 0 && st.Height > 0 {
		h = st.Height
	}

	return MJPEGStats{
		Active:    active,
		Engine:    m.engine,
		Serial:    m.serial,
		FPS:       st.FPS,
		LatencyMs: st.LatencyMs,
		Frames:    st.FrameCount,
		Errors:    st.Errors,
		Width:     w,
		Height:    h,
		Clients:   clients,
	}
}

// IsRunning reports whether the MJPEG server is active.
func (m *MJPEGServer) IsRunning() bool {
	m.mu.Lock()
	stopped := m.stopped
	m.mu.Unlock()
	return !stopped && m.source.IsRunning()
}

// Stop terminates the HTTP server, closes all active client streams, and
// stops the underlying capture engine immediately. Safe to call multiple times.
func (m *MJPEGServer) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	if m.idleTimer != nil {
		m.idleTimer.Stop()
		m.idleTimer = nil
	}
	m.mu.Unlock()

	m.cancel()
	m.source.Stop()
	_ = m.server.Close()
}

func (m *MJPEGServer) resetIdleTimerLocked(needLock bool) {
	if needLock {
		m.mu.Lock()
		defer m.mu.Unlock()
	}
	if m.stopped || m.idleTimeout <= 0 {
		return
	}
	if m.idleTimer != nil {
		m.idleTimer.Stop()
		m.idleTimer = nil
	}
	if m.clients == 0 {
		m.idleTimer = time.AfterFunc(m.idleTimeout, func() {
			m.mu.Lock()
			shouldStop := !m.stopped && m.clients == 0
			m.mu.Unlock()
			if shouldStop {
				m.Stop()
			}
		})
	}
}

func (m *MJPEGServer) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		http.Error(w, "stream stopped", http.StatusGone)
		return
	}
	m.clients++
	if m.idleTimer != nil {
		m.idleTimer.Stop()
		m.idleTimer = nil
	}
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.clients--
		if m.clients < 0 {
			m.clients = 0
		}
		m.resetIdleTimerLocked(false)
		m.mu.Unlock()
	}()

	h := w.Header()
	h.Set("Content-Type", "multipart/x-mixed-replace; boundary="+mjpegBoundary)
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	h.Set("Pragma", "no-cache")
	h.Set("Connection", "close")
	h.Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodHead {
		return
	}

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	streamCtx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		select {
		case <-m.ctx.Done():
			cancel()
		case <-streamCtx.Done():
		}
	}()

	var lastSeq uint64
	headerBuf := make([]byte, 0, 128)
	for {
		frame, seq, ok := m.source.WaitFrame(streamCtx, lastSeq)
		if !ok {
			return
		}
		lastSeq = seq

		headerBuf = headerBuf[:0]
		headerBuf = append(headerBuf, "--"+mjpegBoundary+"\r\nContent-Type: image/jpeg\r\nContent-Length: "...)
		headerBuf = fmt.Appendf(headerBuf, "%d\r\n\r\n", len(frame))

		if _, err := w.Write(headerBuf); err != nil {
			return
		}
		if _, err := w.Write(frame); err != nil {
			return
		}
		if _, err := w.Write([]byte("\r\n")); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}
