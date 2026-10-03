package screen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---- test helpers ----

// withFakeLookPath substitutes lookPath (the seam ScrcpyServer.Start uses
// to check for ffmpeg) for the duration of the test, restoring the
// original afterward.
func withFakeLookPath(t *testing.T, fn func(file string) (string, error)) {
	t.Helper()
	orig := lookPath
	lookPath = fn
	t.Cleanup(func() { lookPath = orig })
}

// withFakeGetScrcpyServer substitutes getScrcpyServerFunc (the seam
// captureScrcpy resolves the running server through) for the duration of
// the test, restoring the original afterward.
func withFakeGetScrcpyServer(t *testing.T, fn func(opts Options) (*ScrcpyServer, error)) {
	t.Helper()
	orig := getScrcpyServerFunc
	getScrcpyServerFunc = fn
	t.Cleanup(func() { getScrcpyServerFunc = orig })
}

// resetScrcpySingleton clears the package-level singleton before and after
// a test that pokes at it directly, so tests don't leak state into each
// other regardless of order.
func resetScrcpySingleton(t *testing.T) {
	t.Helper()
	scrcpySingletonMu.Lock()
	scrcpySingleton = nil
	scrcpySingletonMu.Unlock()
	t.Cleanup(func() {
		scrcpySingletonMu.Lock()
		scrcpySingleton = nil
		scrcpySingletonMu.Unlock()
	})
}

// readerFunc adapts a function to an io.Reader, for tests that need to
// observe or control exactly what a Read call does.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// chunkReader serves data in fixed-size pieces (except possibly the last),
// to exercise splitJPEGFrames's handling of frames/markers split across
// multiple Read calls.
type chunkReader struct {
	data      []byte
	chunkSize int
	pos       int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := r.chunkSize
	if n > len(p) {
		n = len(p)
	}
	if r.pos+n > len(r.data) {
		n = len(r.data) - r.pos
	}
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}

// jpegFrame builds a minimal synthetic "JPEG" for splitting tests: a start
// marker, a payload (which must not itself contain 0xFF 0xD9), and an end
// marker. The payload doesn't need to be real JPEG data — splitJPEGFrames
// only looks for the marker bytes.
func jpegFrame(payload string) []byte {
	var buf bytes.Buffer
	buf.Write(jpegSOI)
	buf.WriteString(payload)
	buf.Write(jpegEOI)
	return buf.Bytes()
}

// drainFrames reads whatever is currently buffered in ch without blocking.
func drainFrames(ch <-chan []byte) [][]byte {
	var out [][]byte
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

// ---- splitJPEGFrames / TestJPEGFrameSplit ----

func TestJPEGFrameSplit_MultipleFramesInOneRead(t *testing.T) {
	f1, f2, f3 := jpegFrame("AAA"), jpegFrame("BB"), jpegFrame("CCCC")
	stream := bytes.Join([][]byte{f1, f2, f3}, nil)

	frameCh := make(chan []byte, 10)
	stopCh := make(chan struct{})
	splitJPEGFrames(bytes.NewReader(stream), frameCh, stopCh)

	got := drainFrames(frameCh)
	want := [][]byte{f1, f2, f3}
	if len(got) != len(want) {
		t.Fatalf("got %d frames, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("frame[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestJPEGFrameSplit_SkipsLeadingGarbage(t *testing.T) {
	garbage := []byte{0x00, 0x11, 0x22, 0xFF, 0x00} // includes a lone 0xFF that is NOT a real SOI
	f1 := jpegFrame("payload")
	stream := append(append([]byte{}, garbage...), f1...)

	frameCh := make(chan []byte, 10)
	splitJPEGFrames(bytes.NewReader(stream), frameCh, make(chan struct{}))

	got := drainFrames(frameCh)
	if len(got) != 1 || !bytes.Equal(got[0], f1) {
		t.Fatalf("got %v, want exactly one frame %q", got, f1)
	}
}

func TestJPEGFrameSplit_FramesSplitAcrossReads(t *testing.T) {
	f1, f2 := jpegFrame("hello-world"), jpegFrame("x")
	stream := append(append([]byte{}, f1...), f2...)

	for _, chunkSize := range []int{1, 2, 3, 7} {
		t.Run("", func(t *testing.T) {
			frameCh := make(chan []byte, 10)
			r := &chunkReader{data: stream, chunkSize: chunkSize}
			splitJPEGFrames(r, frameCh, make(chan struct{}))

			got := drainFrames(frameCh)
			want := [][]byte{f1, f2}
			if len(got) != len(want) {
				t.Fatalf("chunkSize=%d: got %d frames, want %d: %v", chunkSize, len(got), len(want), got)
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) {
					t.Errorf("chunkSize=%d: frame[%d] = %q, want %q", chunkSize, i, got[i], want[i])
				}
			}
		})
	}
}

func TestJPEGFrameSplit_IncompleteTrailingFrameIsNotEmitted(t *testing.T) {
	complete := jpegFrame("full")
	partial := []byte{0xFF, 0xD8, 'o', 'o', 'p', 's'} // SOI with no EOI yet
	stream := append(append([]byte{}, complete...), partial...)

	frameCh := make(chan []byte, 10)
	splitJPEGFrames(bytes.NewReader(stream), frameCh, make(chan struct{}))

	got := drainFrames(frameCh)
	if len(got) != 1 || !bytes.Equal(got[0], complete) {
		t.Fatalf("got %v, want exactly one complete frame %q (partial trailing frame must not be emitted)", got, complete)
	}
}

func TestJPEGFrameSplit_DropsFramesWhenChannelFull(t *testing.T) {
	frameCh := make(chan []byte, 1)
	frameCh <- []byte("pre-existing") // fill the buffer before splitting starts

	stream := append(jpegFrame("one"), jpegFrame("two")...)
	splitJPEGFrames(bytes.NewReader(stream), frameCh, make(chan struct{}))

	got := drainFrames(frameCh)
	if len(got) != 1 || string(got[0]) != "pre-existing" {
		t.Fatalf("got %v, want the channel untouched (both new frames dropped while full)", got)
	}
}

func TestJPEGFrameSplit_StopsReadingOnceStopChIsClosed(t *testing.T) {
	stopCh := make(chan struct{})
	close(stopCh)

	var readCalled bool
	r := readerFunc(func(p []byte) (int, error) {
		readCalled = true
		return 0, io.EOF
	})

	done := make(chan struct{})
	go func() {
		splitJPEGFrames(r, make(chan []byte, 1), stopCh)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("splitJPEGFrames did not return promptly after stopCh was already closed")
	}
	if readCalled {
		t.Error("splitJPEGFrames called Read even though stopCh was already closed")
	}
}

func TestJPEGFrameSplit_EmptyInputProducesNoFrames(t *testing.T) {
	frameCh := make(chan []byte, 1)
	splitJPEGFrames(bytes.NewReader(nil), frameCh, make(chan struct{}))
	if got := drainFrames(frameCh); len(got) != 0 {
		t.Errorf("got %v, want no frames from empty input", got)
	}
}

// ---- pure helper functions ----

func TestQualityToFFmpegQV(t *testing.T) {
	tests := []struct {
		quality int
		want    int
	}{
		{100, 2},  // best JPEG quality -> best (lowest) ffmpeg -q:v
		{1, 31},   // worst JPEG quality -> worst (highest) ffmpeg -q:v
		{70, 11},  // DefaultQuality
		{0, 11},   // clamps to DefaultQuality first
		{-5, 11},  // clamps to DefaultQuality first
		{101, 2},  // clamps to 100 first
		{1000, 2}, // clamps to 100 first
	}
	for _, tt := range tests {
		if got := qualityToFFmpegQV(tt.quality); got != tt.want {
			t.Errorf("qualityToFFmpegQV(%d) = %d, want %d", tt.quality, got, tt.want)
		}
	}
}

func TestQualityToFFmpegQV_MonotonicAndInRange(t *testing.T) {
	prev := -1
	for q := 1; q <= 100; q++ {
		qv := qualityToFFmpegQV(q)
		if qv < 2 || qv > 31 {
			t.Fatalf("qualityToFFmpegQV(%d) = %d, out of ffmpeg's valid 2-31 range", q, qv)
		}
		if q > 1 && qv > prev {
			t.Fatalf("qualityToFFmpegQV is not monotonic: quality %d -> %d came after quality %d -> %d (higher JPEG quality must not yield a worse -q:v)", q, qv, q-1, prev)
		}
		prev = qv
	}
}

func TestScrcpyServerArgs(t *testing.T) {
	got := scrcpyServerArgs("3.1", 540, 15, 2_000_000)
	want := []string{
		"CLASSPATH=/data/local/tmp/scrcpy-server.jar",
		"app_process",
		"/",
		"com.genymobile.scrcpy.Server",
		"3.1",
		"tunnel_forward=true",
		"video=true",
		"audio=false",
		"control=false",
		"max_size=540",
		"max_fps=15",
		"video_bit_rate=2000000",
		"send_frame_meta=false",
		"video_codec=h264",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scrcpyServerArgs() =\n%v\nwant\n%v", got, want)
	}
}

func TestFFmpegArgs(t *testing.T) {
	got := ffmpegArgs(5, 15)
	want := []string{
		"-f", "h264",
		"-i", "pipe:0",
		"-f", "image2pipe",
		"-vcodec", "mjpeg",
		"-pix_fmt", "yuvj420p",
		"-q:v", "5",
		"-r", "15",
		"-flush_packets", "1",
		"pipe:1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ffmpegArgs() =\n%v\nwant\n%v", got, want)
	}
}

// argValue returns the value following flag in args, and whether flag was
// found at all — a small helper for the flag-presence tests below, which
// care about specific flags' values rather than the whole argv shape.
func argValue(args []string, flag string) (string, bool) {
	for i, arg := range args {
		if arg == flag {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", true
		}
	}
	return "", false
}

// TestFFmpegArgs_FlushesOutput guards specifically against regressing the
// pipe-buffering fix: -flush_packets 1 must be present as an output option
// (i.e. after -vcodec mjpeg), since without it ffmpeg silently buffers
// every encoded frame instead of streaming them — confirmed against a real
// device, where frames only appeared after the process was killed.
func TestFFmpegArgs_FlushesOutput(t *testing.T) {
	got := ffmpegArgs(11, 10)
	if v, ok := argValue(got, "-flush_packets"); !ok || v != "1" {
		t.Fatalf("ffmpegArgs() = %v, want \"-flush_packets 1\" present (ffmpeg buffers pipe output without it)", got)
	}
}

// TestFFmpegArgs_UsesFullRangeJPEGPixelFormat guards against regressing the
// color-range fix: scrcpy's H.264 output is limited-range ("tv") YUV, which
// ffmpeg's mjpeg encoder refuses to open without an explicit conversion to
// a full-range ("pc"/JPEG) pixel format — confirmed against a real device,
// where omitting this produced "Error while opening encoder" and zero
// frames for the life of the process.
func TestFFmpegArgs_UsesFullRangeJPEGPixelFormat(t *testing.T) {
	got := ffmpegArgs(11, 10)
	if v, ok := argValue(got, "-pix_fmt"); !ok || v != "yuvj420p" {
		t.Fatalf("ffmpegArgs() = %v, want \"-pix_fmt yuvj420p\" present", got)
	}
}

// TestFFmpegArgs_DoesNotUseNobufferFflag guards against reintroducing
// "-fflags nobuffer": it looks like a reasonable low-latency companion to
// -flush_packets, but confirmed against a real device (ffmpeg 8.x) it
// breaks this exact pipeline — the mjpeg encoder opens and consumes input
// but reports "No filtered frames for output stream" and never produces a
// single output frame, for the entire life of the process.
func TestFFmpegArgs_DoesNotUseNobufferFflag(t *testing.T) {
	got := ffmpegArgs(11, 10)
	if v, ok := argValue(got, "-fflags"); ok {
		t.Fatalf("ffmpegArgs() = %v, has -fflags %s — confirmed to silently break frame output on a real device, do not add back without re-verifying", got, v)
	}
}

func TestParseDeviceName(t *testing.T) {
	tests := []struct {
		name string
		buf  func() []byte
		want string
	}{
		{
			name: "NUL-padded name",
			buf: func() []byte {
				b := make([]byte, scrcpyDeviceNameSize)
				copy(b, "Pixel 7 Pro")
				return b
			},
			want: "Pixel 7 Pro",
		},
		{
			name: "all zero bytes",
			buf:  func() []byte { return make([]byte, scrcpyDeviceNameSize) },
			want: "",
		},
		{
			name: "fills the entire buffer with no NUL",
			buf: func() []byte {
				b := make([]byte, scrcpyDeviceNameSize)
				for i := range b {
					b[i] = 'x'
				}
				return b
			},
			want: strings.Repeat("x", scrcpyDeviceNameSize),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseDeviceName(tt.buf()); got != tt.want {
				t.Errorf("parseDeviceName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// buildScrcpyHeader assembles a scrcpyHeaderSize-byte device-info header
// matching the real wire layout confirmed against a live scrcpy-server v3.1
// instance: a dummy byte, a NUL-padded device name, then big-endian codec
// ID / width / height.
func buildScrcpyHeader(name string, codecID uint32, width, height int) []byte {
	buf := make([]byte, scrcpyHeaderSize)
	copy(buf[scrcpyDummyByteSize:], name) // leaves buf[0] as the dummy 0x00 byte
	meta := buf[scrcpyDummyByteSize+scrcpyDeviceNameSize:]
	binary.BigEndian.PutUint32(meta[0:4], codecID)
	binary.BigEndian.PutUint32(meta[4:8], uint32(width))
	binary.BigEndian.PutUint32(meta[8:12], uint32(height))
	return buf
}

func TestParseScrcpyHeader(t *testing.T) {
	// Values lifted directly from a real capture (Pixel 7 Pro, Android 14,
	// max_size=540): device name "Pixel 7 Pro", codec "h264", 248x536.
	header := buildScrcpyHeader("Pixel 7 Pro", scrcpyCodecIDH264, 248, 536)

	name, codecID, width, height, err := parseScrcpyHeader(header)
	if err != nil {
		t.Fatalf("parseScrcpyHeader() error = %v, want nil", err)
	}
	if name != "Pixel 7 Pro" {
		t.Errorf("deviceName = %q, want %q", name, "Pixel 7 Pro")
	}
	if codecID != scrcpyCodecIDH264 {
		t.Errorf("codecID = %#08x, want %#08x", codecID, scrcpyCodecIDH264)
	}
	if width != 248 || height != 536 {
		t.Errorf("size = %dx%d, want 248x536", width, height)
	}
}

func TestParseScrcpyHeader_TooShort(t *testing.T) {
	for _, n := range []int{0, 1, 64, scrcpyHeaderSize - 1} {
		if _, _, _, _, err := parseScrcpyHeader(make([]byte, n)); err == nil {
			t.Errorf("parseScrcpyHeader(%d bytes): want error, got nil", n)
		}
	}
}

func TestScrcpyCodecIDH264_MatchesASCII(t *testing.T) {
	want := binary.BigEndian.Uint32([]byte("h264"))
	if scrcpyCodecIDH264 != want {
		t.Errorf("scrcpyCodecIDH264 = %#08x, want %#08x (big-endian \"h264\")", scrcpyCodecIDH264, want)
	}
}

// ---- NewScrcpyServer ----

func TestNewScrcpyServer_Defaults(t *testing.T) {
	srv := NewScrcpyServer("dev-1", 0, 0, 0)
	if srv.serial != "dev-1" {
		t.Errorf("serial = %q, want %q", srv.serial, "dev-1")
	}
	if srv.maxSize != DefaultMaxSize {
		t.Errorf("maxSize = %d, want %d (DefaultMaxSize)", srv.maxSize, DefaultMaxSize)
	}
	if srv.maxFPS != DefaultFPS {
		t.Errorf("maxFPS = %d, want %d (DefaultFPS)", srv.maxFPS, DefaultFPS)
	}
	if srv.quality != DefaultQuality {
		t.Errorf("quality = %d, want %d (DefaultQuality)", srv.quality, DefaultQuality)
	}
	if srv.bitrate != DefaultScrcpyBitrate {
		t.Errorf("bitrate = %d, want %d (DefaultScrcpyBitrate)", srv.bitrate, DefaultScrcpyBitrate)
	}
	if srv.localPort != DefaultScrcpyLocalPort {
		t.Errorf("localPort = %d, want %d (DefaultScrcpyLocalPort)", srv.localPort, DefaultScrcpyLocalPort)
	}
}

func TestNewScrcpyServer_ExplicitValuesHonored(t *testing.T) {
	srv := NewScrcpyServer("dev-2", 720, 30, 90)
	if srv.maxSize != 720 || srv.maxFPS != 30 || srv.quality != 90 {
		t.Errorf("NewScrcpyServer(_, 720, 30, 90) = {maxSize:%d maxFPS:%d quality:%d}, want {720 30 90}",
			srv.maxSize, srv.maxFPS, srv.quality)
	}
}

func TestNewScrcpyServer_FrameAndIsRunningBeforeStart(t *testing.T) {
	srv := NewScrcpyServer("", 0, 0, 0)
	if srv.Frame() != nil {
		t.Error("Frame() before Start() should be nil")
	}
	if srv.IsRunning() {
		t.Error("IsRunning() before Start() should be false")
	}
	if srv.DeviceName() != "" {
		t.Error("DeviceName() before Start() should be empty")
	}
}

func TestScrcpyServer_StopWithoutStartIsNoOp(t *testing.T) {
	srv := NewScrcpyServer("", 0, 0, 0)
	srv.Stop() // must not panic or block
	if srv.IsRunning() {
		t.Error("IsRunning() = true for a server that was never started")
	}
}

// ---- Start() guard conditions (no device/ffmpeg required) ----

func TestScrcpyServer_Start_FFmpegNotFound(t *testing.T) {
	withFakeLookPath(t, func(file string) (string, error) {
		return "", errors.New("not found")
	})

	srv := NewScrcpyServer("", 0, 0, 0)
	if err := srv.Start(); !errors.Is(err, ErrFFmpegNotFound) {
		t.Fatalf("Start() error = %v, want %v", err, ErrFFmpegNotFound)
	}
	if srv.IsRunning() {
		t.Error("IsRunning() = true after a failed Start()")
	}
}

func TestScrcpyServer_StartIsNoOpWhenAlreadyRunning(t *testing.T) {
	lookPathCalled := false
	withFakeLookPath(t, func(file string) (string, error) {
		lookPathCalled = true
		return "", errors.New("should not be reached")
	})

	srv := NewScrcpyServer("", 0, 0, 0)
	srv.running = true // simulate an already-running server without a real pipeline

	if err := srv.Start(); err != nil {
		t.Fatalf("Start() on an already-running server: error = %v, want nil", err)
	}
	if lookPathCalled {
		t.Error("Start() re-ran setup (checked for ffmpeg) despite already running")
	}
}

// ---- singleton management ----

func TestGetOrStartScrcpyServer_ReusesRunningSingleton(t *testing.T) {
	resetScrcpySingleton(t)
	fake := &ScrcpyServer{running: true}
	scrcpySingletonMu.Lock()
	scrcpySingleton = fake
	scrcpySingletonMu.Unlock()

	got, err := getOrStartScrcpyServer(Options{Serial: "whatever"})
	if err != nil {
		t.Fatalf("getOrStartScrcpyServer() error = %v, want nil", err)
	}
	if got != fake {
		t.Error("getOrStartScrcpyServer() did not reuse the already-running singleton")
	}
}

func TestGetOrStartScrcpyServer_StartsNewWhenNoneRunning(t *testing.T) {
	resetScrcpySingleton(t)
	withFakeLookPath(t, func(file string) (string, error) {
		return "", errors.New("ffmpeg not installed")
	})

	_, err := getOrStartScrcpyServer(Options{})
	if !errors.Is(err, ErrFFmpegNotFound) {
		t.Fatalf("getOrStartScrcpyServer() error = %v, want %v", err, ErrFFmpegNotFound)
	}

	scrcpySingletonMu.Lock()
	s := scrcpySingleton
	scrcpySingletonMu.Unlock()
	if s != nil {
		t.Error("getOrStartScrcpyServer() installed a singleton despite Start() failing")
	}
}

func TestStopScrcpy_StopsAndClearsSingleton(t *testing.T) {
	resetScrcpySingleton(t)
	withFakeRunAdb(t, func(serial string, args ...string) (string, error) {
		return "", nil // satisfy the `adb forward --remove` Stop() issues
	})

	fake := &ScrcpyServer{running: true, stopCh: make(chan struct{})}
	scrcpySingletonMu.Lock()
	scrcpySingleton = fake
	scrcpySingletonMu.Unlock()

	StopScrcpy()

	if fake.IsRunning() {
		t.Error("StopScrcpy() left the singleton marked running")
	}
	scrcpySingletonMu.Lock()
	cleared := scrcpySingleton == nil
	scrcpySingletonMu.Unlock()
	if !cleared {
		t.Error("StopScrcpy() did not clear the package-level singleton")
	}
}

func TestStopScrcpy_NoSingletonIsNoOp(t *testing.T) {
	resetScrcpySingleton(t)
	StopScrcpy() // must not panic
}

// ---- captureScrcpy dispatch/fallback logic ----

func TestCaptureScrcpy_ReturnsLatestFrameWithoutFallback(t *testing.T) {
	srv := &ScrcpyServer{lastFrame: []byte{1, 2, 3}}
	withFakeGetScrcpyServer(t, func(opts Options) (*ScrcpyServer, error) {
		return srv, nil
	})
	fallbackCalled := false
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		fallbackCalled = true
		return nil, nil
	})

	got, err := captureScrcpy(Options{})
	if err != nil {
		t.Fatalf("captureScrcpy() error = %v, want nil", err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Errorf("captureScrcpy() = %v, want %v", got, []byte{1, 2, 3})
	}
	if fallbackCalled {
		t.Error("captureScrcpy() called the FastCapture fallback despite a ready frame")
	}
}

func TestCaptureScrcpy_FallsBackWhenNoFrameYet(t *testing.T) {
	srv := &ScrcpyServer{} // started, but hasn't decoded a frame yet
	withFakeGetScrcpyServer(t, func(opts Options) (*ScrcpyServer, error) {
		return srv, nil
	})
	want := []byte{9, 9, 9}
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		return want, nil
	})

	got, err := captureScrcpy(Options{})
	if err != nil {
		t.Fatalf("captureScrcpy() error = %v, want nil", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("captureScrcpy() = %v, want %v (FastCapture fallback)", got, want)
	}
}

func TestCaptureScrcpy_FallsBackWhenFFmpegMissing(t *testing.T) {
	withFakeGetScrcpyServer(t, func(opts Options) (*ScrcpyServer, error) {
		return nil, ErrFFmpegNotFound
	})
	want := []byte{7, 7, 7}
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		return want, nil
	})

	got, err := captureScrcpy(Options{})
	if err != nil {
		t.Fatalf("captureScrcpy() error = %v, want nil", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("captureScrcpy() = %v, want %v", got, want)
	}
}

func TestCaptureScrcpy_PropagatesOtherErrorsWithoutFallback(t *testing.T) {
	wantErr := errors.New("no device connected")
	withFakeGetScrcpyServer(t, func(opts Options) (*ScrcpyServer, error) {
		return nil, wantErr
	})
	fallbackCalled := false
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		fallbackCalled = true
		return nil, nil
	})

	_, err := captureScrcpy(Options{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("captureScrcpy() error = %v, want %v", err, wantErr)
	}
	if fallbackCalled {
		t.Error("captureScrcpy() fell back to FastCapture for a non-ffmpeg error")
	}
}

// ---- full lifecycle against a real device (TestScrcpyServerLifecycle) ----

func TestScrcpyServerLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real device and ffmpeg; skipped with -short")
	}
	if _, err := exec.LookPath("adb"); err != nil {
		t.Skip("adb not found in PATH")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not found in PATH")
	}
	out, err := exec.Command("adb", "get-state").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "device" {
		t.Skip("no ready Android device attached (adb get-state != \"device\")")
	}

	srv := NewScrcpyServer("", 480, 10, 60)
	if err := srv.Start(); err != nil {
		if errors.Is(err, ErrFFmpegNotFound) {
			t.Skip("ffmpeg not found")
		}
		t.Fatalf("Start() error = %v", err)
	}
	defer srv.Stop()

	if !srv.IsRunning() {
		t.Error("IsRunning() = false immediately after a successful Start()")
	}

	var frame []byte
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if frame = srv.Frame(); frame != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if frame == nil {
		t.Fatal("Frame() never produced a frame within 20s of Start()")
	}
	if !bytes.HasPrefix(frame, jpegSOI) || !bytes.HasSuffix(frame, jpegEOI) {
		t.Errorf("Frame() does not look like a JPEG: first 2 bytes=%x, last 2 bytes=%x", frame[:2], frame[len(frame)-2:])
	}
	w, h := srv.VideoSize()
	t.Logf("device name: %q, video size: %dx%d, frame size: %d bytes", srv.DeviceName(), w, h, len(frame))
	if w <= 0 || h <= 0 {
		t.Errorf("VideoSize() = %dx%d, want positive dimensions", w, h)
	}

	srv.Stop()
	if srv.IsRunning() {
		t.Error("IsRunning() = true after Stop()")
	}
	if srv.Frame() == nil {
		t.Error("Frame() cleared after Stop(); want the last frame to remain readable")
	}
}
