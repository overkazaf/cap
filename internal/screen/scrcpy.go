// scrcpy.go implements the EngineScrcpy backend: it drives scrcpy-server
// (https://github.com/Genymobile/scrcpy) on the device to capture an H.264
// stream at up to ~15-30 FPS, then shells out to `ffmpeg` to transcode that
// H.264 into a sequence of JPEG frames cap can hand to its existing
// MJPEG-over-HTTP frontend unchanged.
//
// Decoding H.264 in pure Go isn't practical today — there's no mature
// pure-Go decoder — so this is the pragmatic alternative: reuse scrcpy's
// well-tested on-device encoder pipeline and ffmpeg's decoder, and keep cap
// itself out of the codec business entirely. If ffmpeg isn't installed,
// Start returns ErrFFmpegNotFound and callers should fall back to
// FastCapture (see captureScrcpy below, which does exactly that).
package screen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// Tuning/protocol constants for the scrcpy engine.
const (
	// ScrcpyVersion is the scrcpy-server release this package deploys and
	// drives. It's passed as the Server class's first argument, and must
	// match the jar fetched by DownloadScrcpyServer (see
	// scrcpyServerDownloadURL in scrcpy_deploy.go) — the wire protocol
	// between host and server is not guaranteed stable across versions.
	ScrcpyVersion = "3.1"

	// DefaultScrcpyBitrate is the H.264 target bitrate, in bits/sec, used
	// when starting scrcpy-server.
	DefaultScrcpyBitrate = 2_000_000

	// DefaultScrcpyLocalPort is the local TCP port `adb forward`s to the
	// device's scrcpy abstract socket.
	DefaultScrcpyLocalPort = 27183

	// scrcpyDummyByteSize is a single leading byte (always 0x00)
	// scrcpy-server writes to the video socket before anything else.
	scrcpyDummyByteSize = 1

	// scrcpyDeviceNameSize is the size, in bytes, of the NUL-padded device
	// name field that follows the dummy byte.
	scrcpyDeviceNameSize = 64

	// scrcpyCodecMetaSize is the size, in bytes, of the per-stream codec
	// metadata that follows the device name: a 4-byte codec ID, 4-byte
	// width, and 4-byte height, all big-endian. This is sent once
	// regardless of send_frame_meta — that flag only controls whether a
	// 12-byte PTS+size header precedes each individual frame, not this
	// one-time stream header.
	scrcpyCodecMetaSize = 12

	// scrcpyHeaderSize is the total number of bytes scrcpy-server sends
	// before the raw H.264 Annex B stream begins: dummy byte + device name
	// + codec metadata.
	//
	// Confirmed empirically against a real scrcpy-server v3.1 instance
	// (Pixel 7 Pro, Android 14) started the same way this package starts
	// it (tunnel_forward=true, control=false, send_frame_meta=false): byte
	// 0 is the dummy byte, bytes 1-64 are the device name, bytes 65-68 are
	// the codec ID ("h264" as 4 raw ASCII bytes), bytes 69-72 are the
	// width, bytes 73-76 are the height, and the H.264 start code (00 00
	// 00 01) begins at byte 77 — i.e. scrcpyHeaderSize itself.
	scrcpyHeaderSize = scrcpyDummyByteSize + scrcpyDeviceNameSize + scrcpyCodecMetaSize
)

// scrcpyCodecIDH264 is the wire value scrcpy-server reports for the H.264
// codec in the codec-metadata block: the ASCII bytes "h264" read back as a
// big-endian uint32 (scrcpy defines codec IDs as this kind of four-char-code
// constant). Start checks the device's reported codec ID against this so a
// protocol drift or unexpected codec fails fast with a clear error instead
// of silently feeding non-H.264 bytes into ffmpeg's "-f h264" demuxer.
const scrcpyCodecIDH264 uint32 = 0x68323634

// ErrFFmpegNotFound is returned by (*ScrcpyServer).Start when the ffmpeg
// binary isn't on PATH. It's exported so callers — namely captureScrcpy,
// below — can detect this specific, environment-capability failure and
// fall back to FastCapture instead of failing the request outright.
var ErrFFmpegNotFound = errors.New("scrcpy: ffmpeg not found in PATH (required to transcode H.264 into MJPEG)")

// lookPath resolves a binary's path; it's exec.LookPath by default, as a
// package var so tests can simulate ffmpeg's presence/absence without
// depending on the host machine's actual PATH.
var lookPath = exec.LookPath

// jpegSOI and jpegEOI are the JPEG start-of-image and end-of-image marker
// bytes splitJPEGFrames scans for.
var (
	jpegSOI = []byte{0xFF, 0xD8}
	jpegEOI = []byte{0xFF, 0xD9}
)

// ScrcpyServer drives one scrcpy-server instance on a device and exposes
// the latest decoded frame as a JPEG. Its zero value is not usable; create
// one with NewScrcpyServer.
//
// A single ScrcpyServer is meant to be started once and left running: the
// on-device process, the forwarded adb port, and the ffmpeg subprocess are
// all comparatively expensive to set up relative to reading the next
// already-decoded frame out of memory. See captureScrcpy for how Capture
// reuses a package-level singleton across repeated calls.
type ScrcpyServer struct {
	serial  string
	maxSize int
	maxFPS  int
	bitrate int
	quality int

	localPort int

	serverCmd *exec.Cmd // adb shell ... app_process ... com.genymobile.scrcpy.Server
	ffmpegCmd *exec.Cmd // ffmpeg -f h264 -i pipe:0 -f image2pipe -vcodec mjpeg ...
	conn      net.Conn  // TCP connection to the forwarded scrcpy socket

	frameCh chan []byte   // decoded JPEG frames, produced by collectFrames
	stopCh  chan struct{} // closed by Stop to unblock the background goroutines
	wg      sync.WaitGroup

	mu             sync.Mutex
	running        bool
	lastFrame      []byte
	deviceName     string
	videoW, videoH int
}

// NewScrcpyServer creates a server targeting serial (empty lets adb pick
// its default device). maxSize caps the longest video dimension in pixels
// (<=0 uses DefaultMaxSize); maxFPS caps the capture frame rate (<=0 uses
// DefaultFPS); quality is the JPEG output quality, 1-100 (out-of-range
// values are clamped as in clampQuality). The bitrate is fixed at
// DefaultScrcpyBitrate.
func NewScrcpyServer(serial string, maxSize, maxFPS, quality int) *ScrcpyServer {
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	if maxFPS <= 0 {
		maxFPS = DefaultFPS
	}
	return &ScrcpyServer{
		serial:    serial,
		maxSize:   maxSize,
		maxFPS:    maxFPS,
		bitrate:   DefaultScrcpyBitrate,
		quality:   clampQuality(quality),
		localPort: DefaultScrcpyLocalPort,
	}
}

// scrcpyServerArgs builds the argv (excluding "adb -s <serial> shell")
// that starts scrcpy-server on the device. Split out from Start so the
// exact invocation can be unit tested without adb or a device.
func scrcpyServerArgs(version string, maxSize, maxFPS, bitrate int) []string {
	return []string{
		"CLASSPATH=" + scrcpyServerDeviceFile,
		"app_process",
		"/",
		"com.genymobile.scrcpy.Server",
		version,
		"tunnel_forward=true",
		"video=true",
		"audio=false",
		"control=false",
		fmt.Sprintf("max_size=%d", maxSize),
		fmt.Sprintf("max_fps=%d", maxFPS),
		fmt.Sprintf("video_bit_rate=%d", bitrate),
		"send_frame_meta=false",
		"video_codec=h264",
	}
}

// qualityToFFmpegQV maps a JPEG-style quality value (1-100, higher is
// better — see clampQuality) onto ffmpeg's mjpeg -q:v scale (2-31, lower is
// better), linearly.
func qualityToFFmpegQV(quality int) int {
	quality = clampQuality(quality)
	const bestQV, worstQV = 2, 31
	qv := worstQV - (quality-1)*(worstQV-bestQV)/99
	switch {
	case qv < bestQV:
		return bestQV
	case qv > worstQV:
		return worstQV
	default:
		return qv
	}
}

// ffmpegArgs builds the argv (excluding "ffmpeg" itself) that transcodes a
// raw H.264 Annex B stream on stdin into a sequence of JPEG frames on
// stdout. Two of these flags are load-bearing, not cosmetic tuning — both
// confirmed against a real device:
//
//   - "-pix_fmt yuvj420p": scrcpy-server's H.264 output is limited-range
//     ("tv") YUV, which ffmpeg's mjpeg encoder refuses outright ("Non
//     full-range YUV is non-standard" / "Error while opening encoder")
//     unless explicitly converted to JPEG's full-range ("pc") convention
//     first. Without this, Start's ffmpeg subprocess opens and then never
//     produces a single frame.
//   - "-flush_packets 1": without it, ffmpeg buffers every encoded JPEG
//     internally and never writes them to the stdout pipe until the
//     process exits (or the buffer happens to fill), which silently
//     starves splitJPEGFrames of any data for the entire life of a live
//     stream.
//
// Notably absent: "-fflags nobuffer". It looks like the obvious
// complement to -flush_packets for a low-latency pipe, but empirically it
// breaks this exact pipeline on ffmpeg 8.x — the encoder opens, consumes
// input, and reports "No filtered frames for output stream" while
// producing zero output frames for the life of the process. Don't add it
// back without re-confirming against a real device.
func ffmpegArgs(qv, fps int) []string {
	return []string{
		"-f", "h264",
		"-i", "pipe:0",
		"-f", "image2pipe",
		"-vcodec", "mjpeg",
		"-pix_fmt", "yuvj420p",
		"-q:v", strconv.Itoa(qv),
		"-r", strconv.Itoa(fps),
		"-flush_packets", "1",
		"pipe:1",
	}
}

// parseDeviceName extracts the device name from a scrcpyDeviceNameSize-byte
// name field: a UTF-8 string, NUL-padded to fill the buffer.
func parseDeviceName(nameField []byte) string {
	if i := bytes.IndexByte(nameField, 0); i >= 0 {
		nameField = nameField[:i]
	}
	return string(bytes.TrimSpace(nameField))
}

// parseScrcpyHeader parses the scrcpyHeaderSize-byte header scrcpy-server
// sends before the raw H.264 stream begins: a leading dummy byte (ignored),
// a NUL-padded device name, and codec metadata (codec ID, width, height).
// See scrcpyHeaderSize's doc comment for how this layout was determined.
func parseScrcpyHeader(header []byte) (deviceName string, codecID uint32, width, height int, err error) {
	if len(header) < scrcpyHeaderSize {
		return "", 0, 0, 0, fmt.Errorf("scrcpy: device info header too short: got %d bytes, want %d", len(header), scrcpyHeaderSize)
	}

	nameField := header[scrcpyDummyByteSize : scrcpyDummyByteSize+scrcpyDeviceNameSize]
	deviceName = parseDeviceName(nameField)

	meta := header[scrcpyDummyByteSize+scrcpyDeviceNameSize : scrcpyHeaderSize]
	codecID = binary.BigEndian.Uint32(meta[0:4])
	width = int(binary.BigEndian.Uint32(meta[4:8]))
	height = int(binary.BigEndian.Uint32(meta[8:12]))
	return deviceName, codecID, width, height, nil
}

// splitJPEGFrames reads from reader (ffmpeg's stdout in production) and
// sends each complete JPEG frame it finds — delimited by an FFD8 start-of-
// image marker and the next FFD9 end-of-image marker — to frameCh. It
// returns when reader returns an error (including io.EOF, e.g. ffmpeg
// exiting) or stopCh is closed.
//
// If frameCh's consumer isn't keeping up, a completed frame is dropped
// rather than blocking: a live screen mirror only ever wants the most
// recent frame, so backpressure here would just add latency for no
// benefit.
func splitJPEGFrames(reader io.Reader, frameCh chan<- []byte, stopCh <-chan struct{}) {
	const maxBufSize = 8 * 1024 * 1024 // guards against unbounded growth if a frame never gets an EOI
	buf := make([]byte, 0, 256*1024)
	tmp := make([]byte, 32*1024)

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		n, err := reader.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)

			for {
				start := bytes.Index(buf, jpegSOI)
				if start < 0 {
					// No SOI at all yet. Keep the last byte in case it's
					// the first half of a marker split across reads;
					// drop everything else so a long run of non-JPEG
					// noise can't grow buf forever.
					if len(buf) > 1 {
						buf = buf[len(buf)-1:]
					}
					break
				}
				end := bytes.Index(buf[start+2:], jpegEOI)
				if end < 0 {
					if start > 0 {
						buf = buf[start:] // drop garbage before the marker; keep accumulating toward an EOI
					}
					if len(buf) > maxBufSize {
						buf = buf[:0] // runaway/corrupt frame; resync from the next SOI
					}
					break
				}
				end += start + 2 + 2 // include the FFD9 bytes themselves

				frame := make([]byte, end-start)
				copy(frame, buf[start:end])
				select {
				case frameCh <- frame:
				default: // consumer busy; drop this frame
				}

				buf = buf[end:]
			}
		}
		if err != nil {
			return
		}
	}
}

// killCmd kills and reaps cmd, ignoring errors from both: it's used on
// Start's failure paths to tear down a subprocess that's known to still be
// running, where there's nothing more useful to do with a kill/wait error
// than to proceed with cleaning everything else up.
func killCmd(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

// abortStart tears down everything Start had already set up by the time a
// later step failed — the socket connection (if one was made), the
// on-device server process, and the forwarded adb port — so a failed Start
// never leaks any of them. conn may be nil if the failure happened before
// connectAndReadHeader succeeded.
func (s *ScrcpyServer) abortStart(serverCmd *exec.Cmd, conn net.Conn) {
	if conn != nil {
		conn.Close()
	}
	killCmd(serverCmd)
	_, _ = runAdb(s.serial, "forward", "--remove", s.forwardSpec())
}

// Start deploys and launches scrcpy-server on the device, pipes its H.264
// output through ffmpeg, and begins populating Frame() in the background.
// Calling Start while already running is a no-op.
//
// If ffmpeg isn't on PATH, Start returns ErrFFmpegNotFound without
// touching the device.
func (s *ScrcpyServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if _, err := lookPath("ffmpeg"); err != nil {
		return ErrFFmpegNotFound
	}

	cacheDir, err := DefaultCacheDir()
	if err != nil {
		return err
	}
	if err := DeployScrcpyServer(s.serial, cacheDir); err != nil {
		return fmt.Errorf("scrcpy: deploy server: %w", err)
	}

	serverCmd := s.newServerCmd()
	if err := serverCmd.Start(); err != nil {
		return fmt.Errorf("scrcpy: start on-device server: %w", err)
	}

	if out, err := runAdb(s.serial, "forward", s.forwardSpec(), "localabstract:scrcpy"); err != nil {
		killCmd(serverCmd)
		return wrapAdbErr("scrcpy: adb forward", out, err)
	}

	conn, header, err := s.connectAndReadHeader(8 * time.Second)
	if err != nil {
		s.abortStart(serverCmd, nil)
		return fmt.Errorf("scrcpy: connect to forwarded port %d: %w", s.localPort, err)
	}
	deviceName, codecID, width, height, err := parseScrcpyHeader(header)
	if err != nil {
		s.abortStart(serverCmd, conn)
		return fmt.Errorf("scrcpy: %w", err)
	}
	if codecID != scrcpyCodecIDH264 {
		s.abortStart(serverCmd, conn)
		return fmt.Errorf("scrcpy: device reported codec ID %#08x, want h264 (%#08x)", codecID, scrcpyCodecIDH264)
	}

	ffmpegCmd := exec.Command("ffmpeg", ffmpegArgs(qualityToFFmpegQV(s.quality), s.maxFPS)...)
	stdin, err := ffmpegCmd.StdinPipe()
	if err != nil {
		s.abortStart(serverCmd, conn)
		return fmt.Errorf("scrcpy: ffmpeg stdin pipe: %w", err)
	}
	stdout, err := ffmpegCmd.StdoutPipe()
	if err != nil {
		s.abortStart(serverCmd, conn)
		return fmt.Errorf("scrcpy: ffmpeg stdout pipe: %w", err)
	}
	if err := ffmpegCmd.Start(); err != nil {
		s.abortStart(serverCmd, conn)
		return fmt.Errorf("scrcpy: start ffmpeg: %w", err)
	}

	stopCh := make(chan struct{})
	frameCh := make(chan []byte, 2)

	s.mu.Lock()
	s.serverCmd = serverCmd
	s.ffmpegCmd = ffmpegCmd
	s.conn = conn
	s.deviceName = deviceName
	s.videoW = width
	s.videoH = height
	s.stopCh = stopCh
	s.frameCh = frameCh
	s.running = true
	s.mu.Unlock()

	s.wg.Add(3)
	go s.feedFFmpeg(stdin, conn)
	go s.collectFrames(stdout, frameCh, stopCh)
	go s.dispatchFrames(frameCh, stopCh)

	return nil
}

// newServerCmd builds the `adb [-s serial] shell CLASSPATH=... app_process
// ...` command that launches scrcpy-server, without starting it.
func (s *ScrcpyServer) newServerCmd() *exec.Cmd {
	args := make([]string, 0, 2+1+13)
	if s.serial != "" {
		args = append(args, "-s", s.serial)
	}
	args = append(args, "shell")
	args = append(args, scrcpyServerArgs(ScrcpyVersion, s.maxSize, s.maxFPS, s.bitrate)...)
	return exec.Command("adb", args...)
}

// forwardSpec returns the "tcp:<port>" spec passed to `adb forward`/
// `adb forward --remove`.
func (s *ScrcpyServer) forwardSpec() string {
	return fmt.Sprintf("tcp:%d", s.localPort)
}

// connectAndReadHeader dials the forwarded local port and reads the
// scrcpyHeaderSize-byte device-info header, retrying the whole sequence
// (not just the dial) until it succeeds or timeout elapses.
//
// Retrying only the dial isn't enough: `adb forward`'s local TCP listener
// accepts a connection immediately on its own, before relaying it to the
// device-side abstract socket, and scrcpy-server can take a moment after
// its on-device process starts to actually create and bind that socket
// (JVM/ART startup, class loading, etc.). Until it does, adbd accepts the
// client's TCP connection and then immediately closes it once it finds
// nothing listening on the other end — which surfaces here not as a failed
// dial, but as a successful dial followed by an immediate EOF while
// reading the header. So a short read is treated the same as a failed
// dial: close the connection and retry the dial+read pair from scratch.
// (Confirmed empirically: without this, Start reliably lost this race
// against a real device.)
func (s *ScrcpyServer) connectAndReadHeader(timeout time.Duration) (net.Conn, []byte, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", s.localPort)
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			header := make([]byte, scrcpyHeaderSize)
			_, readErr := io.ReadFull(conn, header)
			if readErr == nil {
				return conn, header, nil
			}
			conn.Close()
			err = readErr
		}
		if time.Now().After(deadline) {
			return nil, nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// feedFFmpeg copies the device's H.264 stream into ffmpeg's stdin until
// conn is closed (by Stop) or errors, then closes stdin so ffmpeg sees EOF
// and exits cleanly.
func (s *ScrcpyServer) feedFFmpeg(stdin io.WriteCloser, conn net.Conn) {
	defer s.wg.Done()
	_, _ = io.Copy(stdin, conn)
	stdin.Close()
}

// collectFrames parses JPEG frames out of ffmpeg's stdout until it returns
// an error (ffmpeg exited) or stopCh is closed.
func (s *ScrcpyServer) collectFrames(stdout io.Reader, frameCh chan<- []byte, stopCh <-chan struct{}) {
	defer s.wg.Done()
	splitJPEGFrames(stdout, frameCh, stopCh)
}

// dispatchFrames stores each frame produced by collectFrames as the latest
// frame, until stopCh is closed or frameCh is drained and closed.
func (s *ScrcpyServer) dispatchFrames(frameCh <-chan []byte, stopCh <-chan struct{}) {
	defer s.wg.Done()
	for {
		select {
		case <-stopCh:
			return
		case frame, ok := <-frameCh:
			if !ok {
				return
			}
			s.mu.Lock()
			s.lastFrame = frame
			s.mu.Unlock()
		}
	}
}

// Stop halts the server, ffmpeg, and all background goroutines, and
// releases the forwarded adb port. It blocks until everything has
// completely shut down. Calling Stop when not running is a no-op.
func (s *ScrcpyServer) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	conn := s.conn
	stopCh := s.stopCh
	serverCmd := s.serverCmd
	ffmpegCmd := s.ffmpegCmd
	s.mu.Unlock()

	close(stopCh)
	if conn != nil {
		conn.Close() // unblocks feedFFmpeg's io.Copy
	}
	if ffmpegCmd != nil && ffmpegCmd.Process != nil {
		_ = ffmpegCmd.Process.Kill() // unblocks collectFrames via EOF on its stdout
	}

	// Wait for feedFFmpeg/collectFrames/dispatchFrames to finish before
	// reaping ffmpegCmd: exec.Cmd.Wait documents that it closes the
	// StdoutPipe reader, so it must not run concurrently with a goroutine
	// still reading from it.
	s.wg.Wait()

	if ffmpegCmd != nil {
		_ = ffmpegCmd.Wait()
	}
	killCmd(serverCmd)

	_, _ = runAdb(s.serial, "forward", "--remove", s.forwardSpec())

	s.mu.Lock()
	s.conn = nil
	s.serverCmd = nil
	s.ffmpegCmd = nil
	s.mu.Unlock()
}

// Frame returns the most recently decoded JPEG frame, or nil if none has
// been produced yet.
func (s *ScrcpyServer) Frame() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastFrame
}

// IsRunning reports whether the server is currently started.
func (s *ScrcpyServer) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// DeviceName returns the device name scrcpy-server reported when the
// current (or most recent) run of Start connected, or "" if Start has
// never completed successfully.
func (s *ScrcpyServer) DeviceName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceName
}

// VideoSize returns the negotiated video dimensions scrcpy-server reported
// when the current (or most recent) run of Start connected — not
// necessarily equal to maxSize, since the device scales its native
// resolution down to fit it while preserving aspect ratio. Returns (0, 0)
// if Start has never completed successfully.
func (s *ScrcpyServer) VideoSize() (width, height int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.videoW, s.videoH
}

// --- Capture integration ---

var (
	scrcpySingletonMu sync.Mutex
	scrcpySingleton   *ScrcpyServer
)

// getScrcpyServerFunc resolves the running scrcpy-server singleton for
// opts, starting one on first use (see getOrStartScrcpyServer). It's a
// package-level var so tests can substitute a fake and exercise
// captureScrcpy's dispatch/fallback logic without a real device, adb, or
// ffmpeg.
var getScrcpyServerFunc = getOrStartScrcpyServer

// getOrStartScrcpyServer returns the package-level ScrcpyServer singleton,
// starting one for opts on first use (or if a previously-started one has
// since stopped running, e.g. the device disconnected). Once started, the
// singleton is reused by every later call regardless of opts — tearing
// down and recreating the on-device process/ffmpeg pipe/forwarded port per
// frame would defeat the entire point of this engine.
func getOrStartScrcpyServer(opts Options) (*ScrcpyServer, error) {
	scrcpySingletonMu.Lock()
	defer scrcpySingletonMu.Unlock()

	if scrcpySingleton != nil && scrcpySingleton.IsRunning() {
		return scrcpySingleton, nil
	}

	srv := NewScrcpyServer(opts.Serial, opts.MaxSize, DefaultFPS, opts.Quality)
	if err := srv.Start(); err != nil {
		return nil, err
	}
	scrcpySingleton = srv
	return srv, nil
}

// StopScrcpy stops the package-level scrcpy-server singleton, if one is
// running, and clears it so the next Capture call with EngineScrcpy starts
// a fresh one. It's primarily useful for tests and graceful shutdown.
func StopScrcpy() {
	scrcpySingletonMu.Lock()
	srv := scrcpySingleton
	scrcpySingleton = nil
	scrcpySingletonMu.Unlock()

	if srv != nil {
		srv.Stop()
	}
}

// captureScrcpy returns a JPEG frame for opts.Serial via the scrcpy-server
// engine, starting (and reusing) the package-level singleton as needed.
//
// Two situations fall back to captureFunc (FastCapture's seam) instead of
// erroring: ffmpeg not being installed (ErrFFmpegNotFound — scrcpy simply
// isn't usable on this host), and the singleton having just started but
// not yet produced its first decoded frame (so the very first request
// after startup still returns something to display instead of an error).
// Any other failure — no device, adb missing, deploy failure, and so on —
// is a real problem the caller should see, so it's returned as-is.
func captureScrcpy(opts Options) ([]byte, error) {
	srv, err := getScrcpyServerFunc(opts)
	if err != nil {
		if errors.Is(err, ErrFFmpegNotFound) {
			return captureFunc(opts.Serial, opts.MaxSize, opts.Quality)
		}
		return nil, err
	}
	if frame := srv.Frame(); frame != nil {
		return frame, nil
	}
	return captureFunc(opts.Serial, opts.MaxSize, opts.Quality)
}
