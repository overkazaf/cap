package screen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEngineString(t *testing.T) {
	tests := []struct {
		name string
		e    Engine
		want string
	}{
		{"screencap", EngineScreencap, "screencap"},
		{"scrcpy", EngineScrcpy, "scrcpy"},
		{"unrecognized", Engine(99), "screen.Engine(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.String(); got != tt.want {
				t.Errorf("Engine(%d).String() = %q, want %q", int(tt.e), got, tt.want)
			}
		})
	}
}

func TestPixelFormatString(t *testing.T) {
	tests := []struct {
		name string
		f    PixelFormat
		want string
	}{
		{"unknown", PixelFormatUnknown, "UNKNOWN"},
		{"rgba8888", PixelFormatRGBA8888, "RGBA_8888"},
		{"rgbx8888", PixelFormatRGBX8888, "RGBX_8888"},
		{"rgb888", PixelFormatRGB888, "RGB_888"},
		{"rgb565", PixelFormatRGB565, "RGB_565"},
		{"bgra8888", PixelFormatBGRA8888, "BGRA_8888"},
		{"unrecognized", PixelFormat(42), "PixelFormat(42)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.String(); got != tt.want {
				t.Errorf("PixelFormat(%d).String() = %q, want %q", uint32(tt.f), got, tt.want)
			}
		})
	}
}

// ---- parseHeader ----

func TestParseScreencapHeader(t *testing.T) {
	header := make([]byte, rawHeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], 1080)
	binary.LittleEndian.PutUint32(header[4:8], 2400)
	binary.LittleEndian.PutUint32(header[8:12], 1) // RGBA_8888

	w, h, format, err := parseHeader(header)
	if err != nil {
		t.Fatalf("parseHeader() error = %v, want nil", err)
	}
	if w != 1080 || h != 2400 {
		t.Errorf("parseHeader() = (%d, %d), want (1080, 2400)", w, h)
	}
	if format != PixelFormatRGBA8888 {
		t.Errorf("parseHeader() format = %v, want %v", format, PixelFormatRGBA8888)
	}
}

func TestParseScreencapHeader_TooShort(t *testing.T) {
	for _, n := range []int{0, 1, 11} {
		if _, _, _, err := parseHeader(make([]byte, n)); err == nil {
			t.Errorf("parseHeader(%d bytes): want error, got nil", n)
		}
	}
}

// ---- decodeRaw ----

// buildRawFrame assembles a raw screencap payload (12-byte header followed
// by w*h*4 bytes of pixel data) for a w x h image in the given format,
// where px(x, y) supplies the raw 4 bytes stored for that pixel.
func buildRawFrame(w, h int, format PixelFormat, px func(x, y int) [4]byte) []byte {
	buf := make([]byte, rawHeaderSize+w*h*4)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(w))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(h))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(format))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			off := rawHeaderSize + (y*w+x)*4
			b := px(x, y)
			copy(buf[off:off+4], b[:])
		}
	}
	return buf
}

func TestDecodeRaw_RGBA8888(t *testing.T) {
	// 2x1 image: a red pixel with full alpha, a green pixel with alpha=0.
	// Alpha must always come out forced to 0xff: a composited screen
	// framebuffer has no real per-pixel transparency, and trusting a
	// garbage/zero alpha byte would corrupt colors once JPEG-encoded.
	raw := buildRawFrame(2, 1, PixelFormatRGBA8888, func(x, y int) [4]byte {
		if x == 0 {
			return [4]byte{0xff, 0x00, 0x00, 0xff} // red, opaque
		}
		return [4]byte{0x00, 0xff, 0x00, 0x00} // green, "transparent"
	})

	img, err := decodeRaw(raw)
	if err != nil {
		t.Fatalf("decodeRaw() error = %v, want nil", err)
	}
	if img.Bounds().Dx() != 2 || img.Bounds().Dy() != 1 {
		t.Fatalf("decodeRaw() bounds = %v, want 2x1", img.Bounds())
	}

	red := img.RGBAAt(0, 0)
	if want := (color.RGBA{0xff, 0x00, 0x00, 0xff}); red != want {
		t.Errorf("pixel(0,0) = %+v, want %+v", red, want)
	}
	green := img.RGBAAt(1, 0)
	if want := (color.RGBA{0x00, 0xff, 0x00, 0xff}); green != want {
		t.Errorf("pixel(1,0) = %+v, want %+v (alpha must be forced opaque)", green, want)
	}
}

func TestDecodeRaw_RGBX8888(t *testing.T) {
	// RGBX_8888's 4th byte is explicitly undefined; decodeRaw must ignore
	// it rather than let it leak through as alpha.
	raw := buildRawFrame(1, 1, PixelFormatRGBX8888, func(x, y int) [4]byte {
		return [4]byte{0x10, 0x20, 0x30, 0x99} // arbitrary junk in the X byte
	})

	img, err := decodeRaw(raw)
	if err != nil {
		t.Fatalf("decodeRaw() error = %v, want nil", err)
	}
	got := img.RGBAAt(0, 0)
	want := color.RGBA{0x10, 0x20, 0x30, 0xff}
	if got != want {
		t.Errorf("pixel(0,0) = %+v, want %+v", got, want)
	}
}

func TestDecodeRaw_UnsupportedFormat(t *testing.T) {
	raw := buildRawFrame(1, 1, PixelFormatRGB565, func(x, y int) [4]byte { return [4]byte{} })
	if _, err := decodeRaw(raw); err == nil {
		t.Fatal("decodeRaw() with RGB_565: want error, got nil")
	}
}

func TestDecodeRaw_Truncated(t *testing.T) {
	raw := buildRawFrame(4, 4, PixelFormatRGBA8888, func(x, y int) [4]byte { return [4]byte{} })
	raw = raw[:len(raw)-1] // chop off the last byte of pixel data
	if _, err := decodeRaw(raw); err == nil {
		t.Fatal("decodeRaw() with truncated pixel data: want error, got nil")
	}
}

func TestDecodeRaw_InvalidDimensions(t *testing.T) {
	raw := buildRawFrame(0, 0, PixelFormatRGBA8888, func(x, y int) [4]byte { return [4]byte{} })
	if _, err := decodeRaw(raw); err == nil {
		t.Fatal("decodeRaw() with 0x0 dimensions: want error, got nil")
	}
}

func TestDecodeRaw_HeaderError(t *testing.T) {
	if _, err := decodeRaw(make([]byte, 4)); err == nil {
		t.Fatal("decodeRaw() with too-short input: want error, got nil")
	}
}

// ---- targetSize ----

func TestTargetSize(t *testing.T) {
	tests := []struct {
		name         string
		srcW, srcH   int
		maxSize      int
		wantW, wantH int
	}{
		{"no max size keeps original", 1080, 2400, 0, 1080, 2400},
		{"already within max size", 400, 300, 540, 400, 300},
		{"exactly at max size", 540, 540, 540, 540, 540},
		{"portrait downscale", 1080, 2400, 540, 243, 540},
		{"landscape downscale", 2400, 1080, 540, 540, 243},
		{"square downscale", 1000, 1000, 500, 500, 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, h := targetSize(tt.srcW, tt.srcH, tt.maxSize)
			if w != tt.wantW || h != tt.wantH {
				t.Errorf("targetSize(%d, %d, %d) = (%d, %d), want (%d, %d)",
					tt.srcW, tt.srcH, tt.maxSize, w, h, tt.wantW, tt.wantH)
			}
		})
	}
}

// ---- resizeNearest ----

func TestResizeImage(t *testing.T) {
	// 2x2 source: TL=red, TR=green, BL=blue, BR=white.
	src := image.NewRGBA(image.Rect(0, 0, 2, 2))
	src.SetRGBA(0, 0, color.RGBA{0xff, 0x00, 0x00, 0xff})
	src.SetRGBA(1, 0, color.RGBA{0x00, 0xff, 0x00, 0xff})
	src.SetRGBA(0, 1, color.RGBA{0x00, 0x00, 0xff, 0xff})
	src.SetRGBA(1, 1, color.RGBA{0xff, 0xff, 0xff, 0xff})

	dst := resizeNearest(src, 4, 4)

	if dst.Bounds().Dx() != 4 || dst.Bounds().Dy() != 4 {
		t.Fatalf("resizeNearest() bounds = %v, want 4x4", dst.Bounds())
	}
	// Nearest-neighbor upscale: each source pixel should still occupy its
	// corresponding quadrant.
	if got := dst.RGBAAt(0, 0); got != (color.RGBA{0xff, 0x00, 0x00, 0xff}) {
		t.Errorf("dst(0,0) = %+v, want red", got)
	}
	if got := dst.RGBAAt(3, 0); got != (color.RGBA{0x00, 0xff, 0x00, 0xff}) {
		t.Errorf("dst(3,0) = %+v, want green", got)
	}
	if got := dst.RGBAAt(0, 3); got != (color.RGBA{0x00, 0x00, 0xff, 0xff}) {
		t.Errorf("dst(0,3) = %+v, want blue", got)
	}
	if got := dst.RGBAAt(3, 3); got != (color.RGBA{0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("dst(3,3) = %+v, want white", got)
	}
}

func TestResizeNearest_NoOpWhenSameSize(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 3, 3))
	dst := resizeNearest(src, 3, 3)
	if dst != src {
		t.Error("resizeNearest() should return the same image when size is unchanged")
	}
}

// ---- clampQuality ----

func TestClampQuality(t *testing.T) {
	tests := []struct {
		in, want int
	}{
		{-5, DefaultQuality},
		{0, DefaultQuality},
		{1, 1},
		{70, 70},
		{100, 100},
		{101, 100},
		{1000, 100},
	}
	for _, tt := range tests {
		if got := clampQuality(tt.in); got != tt.want {
			t.Errorf("clampQuality(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// ---- encodeRawFrame (the non-device part of FastCapture) ----

func TestEncodeRawFrame_ProducesValidJPEGAtRequestedSize(t *testing.T) {
	raw := buildRawFrame(1080, 2400, PixelFormatRGBA8888, func(x, y int) [4]byte {
		return [4]byte{byte(x), byte(y), 0x7f, 0xff}
	})

	out, err := encodeRawFrame(raw, 540, 70)
	if err != nil {
		t.Fatalf("encodeRawFrame() error = %v, want nil", err)
	}

	img, err := jpeg.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not valid JPEG: %v", err)
	}
	wantW, wantH := targetSize(1080, 2400, 540)
	if img.Bounds().Dx() != wantW || img.Bounds().Dy() != wantH {
		t.Errorf("decoded JPEG size = %v, want %dx%d", img.Bounds(), wantW, wantH)
	}
}

func TestEncodeRawFrame_PropagatesDecodeError(t *testing.T) {
	if _, err := encodeRawFrame([]byte{0x01, 0x02}, 540, 70); err == nil {
		t.Fatal("encodeRawFrame() with invalid input: want error, got nil")
	}
}

// ---- FastCapture (device-dependent) ----

func TestFastCaptureIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real device; skipped with -short")
	}
	if _, err := exec.LookPath("adb"); err != nil {
		t.Skip("adb not found in PATH")
	}
	out, err := exec.Command("adb", "get-state").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "device" {
		t.Skip("no ready Android device attached (adb get-state != \"device\")")
	}

	jpegBytes, err := FastCapture("", DefaultMaxSize, DefaultQuality)
	if err != nil {
		t.Fatalf("FastCapture() error = %v", err)
	}
	img, err := jpeg.Decode(bytes.NewReader(jpegBytes))
	if err != nil {
		t.Fatalf("FastCapture() output is not valid JPEG: %v", err)
	}
	if img.Bounds().Dx() == 0 || img.Bounds().Dy() == 0 {
		t.Errorf("FastCapture() produced an empty image: %v", img.Bounds())
	}
}

// ---- FastStream ----

// withFakeCapture substitutes captureFunc (the seam FastStream and Capture
// call through) for the duration of the test, restoring the original
// afterward so other tests aren't affected.
func withFakeCapture(t *testing.T, fn func(serial string, maxSize, quality int) ([]byte, error)) {
	t.Helper()
	orig := captureFunc
	captureFunc = fn
	t.Cleanup(func() { captureFunc = orig })
}

func TestNewFastStream_FPSDefaulting(t *testing.T) {
	tests := []struct {
		name         string
		fps          int
		wantInterval time.Duration
	}{
		{"zero uses default", 0, time.Second / DefaultFPS},
		{"negative uses default", -5, time.Second / DefaultFPS},
		{"explicit fps honored", 30, time.Second / 30},
		{"absurdly high fps clamps to a 1ms floor", 2_000_000_000, time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := NewFastStream("", 0, 0, tt.fps)
			if fs.interval != tt.wantInterval {
				t.Errorf("NewFastStream(fps=%d).interval = %v, want %v", tt.fps, fs.interval, tt.wantInterval)
			}
		})
	}
}

func TestFastStream_CaptureOnceStoresFrame(t *testing.T) {
	want := []byte{1, 2, 3}
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		return want, nil
	})

	fs := NewFastStream("", 0, 0, 0)
	if got := fs.Frame(); got != nil {
		t.Fatalf("Frame() before any capture = %v, want nil", got)
	}

	fs.captureOnce()

	if got := fs.Frame(); !bytes.Equal(got, want) {
		t.Errorf("Frame() = %v, want %v", got, want)
	}
	if err := fs.Err(); err != nil {
		t.Errorf("Err() = %v, want nil", err)
	}
}

func TestFastStream_KeepsLastGoodFrameOnError(t *testing.T) {
	good := []byte{9, 9, 9}
	failing := errors.New("adb exploded")
	calls := 0
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		calls++
		if calls == 1 {
			return good, nil
		}
		return nil, failing
	})

	fs := NewFastStream("", 0, 0, 0)
	fs.captureOnce() // succeeds
	fs.captureOnce() // fails

	if got := fs.Frame(); !bytes.Equal(got, good) {
		t.Errorf("Frame() after a failed capture = %v, want last good frame %v", got, good)
	}
	if err := fs.Err(); !errors.Is(err, failing) {
		t.Errorf("Err() = %v, want %v", err, failing)
	}
}

func TestFastStream_StartStopLifecycle(t *testing.T) {
	var calls int32
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		n := atomic.AddInt32(&calls, 1)
		return []byte{byte(n)}, nil
	})

	fs := NewFastStream("device-1", 540, 70, 1000) // ~1ms interval
	fs.Start()

	deadline := time.Now().Add(500 * time.Millisecond)
	for fs.Frame() == nil {
		if time.Now().After(deadline) {
			t.Fatal("Frame() never became available after Start()")
		}
		time.Sleep(time.Millisecond)
	}
	if !fs.IsRunning() {
		t.Error("IsRunning() = false after Start(), want true")
	}

	fs.Stop()
	if fs.IsRunning() {
		t.Error("IsRunning() = true after Stop(), want false")
	}

	countAtStop := atomic.LoadInt32(&calls)
	time.Sleep(30 * time.Millisecond)
	if after := atomic.LoadInt32(&calls); after != countAtStop {
		t.Errorf("capture count grew after Stop(): %d -> %d", countAtStop, after)
	}
}

func TestFastStream_StartIsNoOpWhenAlreadyRunning(t *testing.T) {
	var calls int32
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		return []byte{1}, nil
	})

	fs := NewFastStream("", 0, 0, 1000)
	fs.Start()
	fs.Start() // must be a no-op; must not leak a second loop
	time.Sleep(20 * time.Millisecond)
	fs.Stop()

	countAtStop := atomic.LoadInt32(&calls)
	time.Sleep(30 * time.Millisecond)
	if after := atomic.LoadInt32(&calls); after != countAtStop {
		t.Errorf("capture count grew after Stop(), suggesting a leaked second loop from double Start(): %d -> %d", countAtStop, after)
	}
}

func TestFastStream_StopWithoutStartIsNoOp(t *testing.T) {
	fs := NewFastStream("", 0, 0, 0)
	fs.Stop() // must not panic or block
	if fs.IsRunning() {
		t.Error("IsRunning() = true for a stream that was never started")
	}
}

// ---- Capture dispatch ----

func TestCapture_ScreencapDelegatesToCaptureFunc(t *testing.T) {
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	var gotSerial string
	var gotMaxSize, gotQuality int
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		gotSerial, gotMaxSize, gotQuality = serial, maxSize, quality
		return want, nil
	})

	got, err := Capture(Options{Engine: EngineScreencap, Serial: "S123", MaxSize: 300, Quality: 80})
	if err != nil {
		t.Fatalf("Capture() error = %v, want nil", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Capture() = %v, want %v", got, want)
	}
	if gotSerial != "S123" || gotMaxSize != 300 || gotQuality != 80 {
		t.Errorf("Capture() forwarded (serial=%q, maxSize=%d, quality=%d), want (S123, 300, 80)", gotSerial, gotMaxSize, gotQuality)
	}
}

func TestCapture_DefaultEngineIsScreencap(t *testing.T) {
	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		return []byte{1}, nil
	})
	// The zero value of Options.Engine must be EngineScreencap, so a caller
	// who doesn't set Engine still gets a working capture.
	if _, err := Capture(Options{}); err != nil {
		t.Errorf("Capture(Options{}) error = %v, want nil (zero value should mean EngineScreencap)", err)
	}
}

// withFakeScrcpyCapture substitutes scrcpyCaptureFunc (the seam Capture's
// EngineScrcpy case calls through) for the duration of the test, restoring
// the original afterward.
func withFakeScrcpyCapture(t *testing.T, fn func(opts Options) ([]byte, error)) {
	t.Helper()
	orig := scrcpyCaptureFunc
	scrcpyCaptureFunc = fn
	t.Cleanup(func() { scrcpyCaptureFunc = orig })
}

func TestCapture_ScrcpyDelegatesToScrcpyCaptureFunc(t *testing.T) {
	want := []byte{0xca, 0xfe}
	var got Options
	withFakeScrcpyCapture(t, func(opts Options) ([]byte, error) {
		got = opts
		return want, nil
	})

	out, err := Capture(Options{Engine: EngineScrcpy, Serial: "S123", MaxSize: 300, Quality: 80})
	if err != nil {
		t.Fatalf("Capture() error = %v, want nil", err)
	}
	if !bytes.Equal(out, want) {
		t.Errorf("Capture() = %v, want %v", out, want)
	}
	if got.Serial != "S123" || got.MaxSize != 300 || got.Quality != 80 {
		t.Errorf("Capture() forwarded opts = %+v, want serial=S123 maxSize=300 quality=80", got)
	}
}

func TestCapture_ScrcpyPropagatesError(t *testing.T) {
	wantErr := errors.New("scrcpy: no device")
	withFakeScrcpyCapture(t, func(opts Options) ([]byte, error) {
		return nil, wantErr
	})

	_, err := Capture(Options{Engine: EngineScrcpy})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Capture() error = %v, want %v", err, wantErr)
	}
}

func TestCapture_UnknownEngineErrors(t *testing.T) {
	_, err := Capture(Options{Engine: Engine(99)})
	if err == nil {
		t.Fatal("Capture() with an unrecognized engine: want error, got nil")
	}
}
