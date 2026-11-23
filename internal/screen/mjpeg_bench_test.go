package screen

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSampleNearestRawRGBA_PixelAccuracyAndNoSourceMutation(t *testing.T) {
	// 4x4 RGBA with non-0xff alpha values in source; verify source is untouched
	// and resized 2x2 output samples exact pixels with alpha forced to 0xff.
	raw := buildRawFrame(4, 4, PixelFormatRGBX8888, func(x, y int) [4]byte {
		if x < 2 && y < 2 {
			return [4]byte{0xaa, 0x11, 0x22, 0x00}
		}
		if x >= 2 && y < 2 {
			return [4]byte{0x11, 0xbb, 0x33, 0x12}
		}
		if x < 2 && y >= 2 {
			return [4]byte{0x22, 0x33, 0xcc, 0x34}
		}
		return [4]byte{0xdd, 0xee, 0xff, 0x56}
	})
	rawCopy := append([]byte(nil), raw...)

	pix, srcW, srcH, err := parseRawPixels(raw)
	if err != nil {
		t.Fatalf("parseRawPixels error = %v", err)
	}
	dst := make([]byte, 2*2*4)
	sampleNearestRawRGBA(pix, srcW, srcH, srcW*4, dst, 2, 2, nil)

	// Source raw buffer must NOT be modified by fast resize
	if !bytes.Equal(raw, rawCopy) {
		t.Fatalf("sampleNearestRawRGBA mutated raw source buffer")
	}

	gotImg := &image.RGBA{Pix: dst, Stride: 2 * 4, Rect: image.Rect(0, 0, 2, 2)}
	want := [2][2]color.RGBA{
		{{0xaa, 0x11, 0x22, 0xff}, {0x11, 0xbb, 0x33, 0xff}},
		{{0x22, 0x33, 0xcc, 0xff}, {0xdd, 0xee, 0xff, 0xff}},
	}
	for y := 0; y < 2; y++ {
		for x := 0; x < 2; x++ {
			if got := gotImg.RGBAAt(x, y); got != want[y][x] {
				t.Errorf("pixel(%d,%d) = %+v, want %+v", x, y, got, want[y][x])
			}
		}
	}
}

func BenchmarkEncodeRawFrame(b *testing.B) {
	// Realistic 1080x2400 smartphone framebuffer (~10.36 MB raw RGBA) scaled to 540p JPEG
	raw := buildRawFrame(1080, 2400, PixelFormatRGBA8888, func(x, y int) [4]byte {
		return [4]byte{byte(x), byte(y), byte((x + y) >> 1), 0x00}
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := encodeRawFrame(raw, 540, 70)
		if err != nil {
			b.Fatalf("encodeRawFrame error = %v", err)
		}
		if len(out) == 0 {
			b.Fatal("empty jpeg output")
		}
	}
}

func BenchmarkResizeNearestRGBA(b *testing.B) {
	raw := buildRawFrame(1080, 2400, PixelFormatRGBA8888, func(x, y int) [4]byte {
		return [4]byte{byte(x), byte(y), 0x7f, 0xff}
	})
	pix, srcW, srcH, err := parseRawPixels(raw)
	if err != nil {
		b.Fatal(err)
	}
	dstW, dstH := targetSize(srcW, srcH, 540)
	dst := make([]byte, dstW*dstH*4)
	xOff := make([]int, dstW)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sampleNearestRawRGBA(pix, srcW, srcH, srcW*4, dst, dstW, dstH, xOff)
	}
}

func TestFastStream_WaitFrameEventDrivenAndStats(t *testing.T) {
	var inFlight int32
	var maxOverlap int32
	var counter int32

	withFakeCapture(t, func(serial string, maxSize, quality int) ([]byte, error) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			prev := atomic.LoadInt32(&maxOverlap)
			if cur <= prev || atomic.CompareAndSwapInt32(&maxOverlap, prev, cur) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		n := atomic.AddInt32(&counter, 1)
		atomic.AddInt32(&inFlight, -1)
		return jpegFrame(string(rune('A' + (n % 26)))), nil
	})

	fs := NewFastStream("dev-1", 540, 70, 60)
	fs.Start()
	defer fs.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var seq uint64
	for i := 0; i < 4; i++ {
		frame, nextSeq, ok := fs.WaitFrame(ctx, seq)
		if !ok || len(frame) == 0 || nextSeq <= seq {
			t.Fatalf("WaitFrame #%d = (len=%d, seq=%d, ok=%v), want valid newer frame", i, len(frame), nextSeq, ok)
		}
		seq = nextSeq
	}

	if overlap := atomic.LoadInt32(&maxOverlap); overlap != 1 {
		t.Errorf("FastStream overlapped %d concurrent captures, want 1", overlap)
	}
	st := fs.Stats()
	if st.FrameCount < 4 {
		t.Errorf("Stats().FrameCount = %d, want >= 4", st.FrameCount)
	}
	if st.FPS <= 0 {
		t.Errorf("Stats().FPS = %v, want > 0", st.FPS)
	}
}

func TestScrcpyServer_WaitFrameBroadcastAndSkipStale(t *testing.T) {
	srv := NewScrcpyServer("dev-1", 540, 30, 70)
	stopCh := make(chan struct{})
	frameCh := make(chan []byte, 8)

	srv.mu.Lock()
	srv.running = true
	srv.videoW = 540
	srv.videoH = 1200
	srv.stopCh = stopCh
	srv.mu.Unlock()

	srv.wg.Add(1)
	go srv.dispatchFrames(frameCh, stopCh)

	// Push 3 frames rapidly before consumer reads: consumer should receive latest (f3)
	// rather than falling behind on stale frames.
	f1 := jpegFrame("frame1")
	f2 := jpegFrame("frame2")
	f3 := jpegFrame("frame3")
	frameCh <- f1
	frameCh <- f2
	frameCh <- f3

	deadline := time.Now().Add(time.Second)
	for {
		if st := srv.Stats(); st.FrameCount >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dispatchFrames did not process 3 frames in time")
		}
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, seq, ok := srv.WaitFrame(ctx, 0)
	if !ok || !bytes.Equal(got, f3) || seq != 3 {
		t.Fatalf("WaitFrame = (%q, seq=%d, ok=%v), want latest frame %q seq=3", got, seq, ok, f3)
	}

	st := srv.Stats()
	if st.Width != 540 || st.Height != 1200 || st.FrameCount != 3 {
		t.Errorf("unexpected scrcpy stats: %+v", st)
	}

	close(stopCh)
	srv.mu.Lock()
	srv.running = false
	close(srv.notifyCh)
	srv.notifyCh = make(chan struct{})
	srv.mu.Unlock()
	srv.wg.Wait()
}

// fakeFrameSource is a deterministic FrameSource for MJPEGServer HTTP tests.
type fakeFrameSource struct {
	mu       sync.Mutex
	running  bool
	stopped  bool
	frame    []byte
	seq      uint64
	notifyCh chan struct{}
	stats    StreamStats
}

func newFakeFrameSource() *fakeFrameSource {
	return &fakeFrameSource{
		running:  true,
		notifyCh: make(chan struct{}),
		stats:    StreamStats{FPS: 30, LatencyMs: 12, Width: 540, Height: 1200},
	}
}

func (f *fakeFrameSource) push(data []byte) {
	f.mu.Lock()
	if !f.running {
		f.mu.Unlock()
		return
	}
	f.frame = data
	f.seq++
	f.stats.FrameCount++
	close(f.notifyCh)
	f.notifyCh = make(chan struct{})
	f.mu.Unlock()
}

func (f *fakeFrameSource) Frame() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.frame
}

func (f *fakeFrameSource) WaitFrame(ctx context.Context, afterSeq uint64) ([]byte, uint64, bool) {
	for {
		f.mu.Lock()
		if f.seq > afterSeq && f.frame != nil {
			frame, seq := f.frame, f.seq
			f.mu.Unlock()
			return frame, seq, true
		}
		if !f.running {
			seq := f.seq
			f.mu.Unlock()
			return nil, seq, false
		}
		ch := f.notifyCh
		f.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, afterSeq, false
		case <-ch:
		}
	}
}

func (f *fakeFrameSource) Stats() StreamStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats
}

func (f *fakeFrameSource) IsRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeFrameSource) Stop() {
	f.mu.Lock()
	if !f.running {
		f.mu.Unlock()
		return
	}
	f.running = false
	f.stopped = true
	close(f.notifyCh)
	f.notifyCh = make(chan struct{})
	f.mu.Unlock()
}

// pipeListener is an in-memory net.Listener backed by net.Pipe so HTTP
// streaming tests work reliably even in network-restricted sandboxes.
type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		ch:     make(chan net.Conn, 4),
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (l *pipeListener) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	select {
	case l.ch <- c2:
		return c1, nil
	case <-l.closed:
		c1.Close()
		c2.Close()
		return nil, net.ErrClosed
	}
}

func TestMJPEGServer_MultipartStreamingTokenAndBackpressure(t *testing.T) {
	src := newFakeFrameSource()
	srv, err := NewMJPEGServerWithSource(src, "fast", "TESTDEV", 5*time.Second)
	if err != nil {
		t.Fatalf("NewMJPEGServerWithSource error = %v", err)
	}
	defer srv.Stop()

	info := srv.Info()
	if !strings.HasPrefix(info.URL, "http://127.0.0.1:") || !strings.HasSuffix(info.URL, ".mjpg") {
		t.Fatalf("unexpected MJPEG URL: %q", info.URL)
	}

	// Choose client transport: real loopback when allowed, or in-memory net.Pipe
	// serving the exact same http.Handler when CAP_SKIP_NETWORK=1.
	client := http.DefaultClient
	baseURL := info.URL
	if os.Getenv("CAP_SKIP_NETWORK") == "1" {
		pl := newPipeListener()
		pipeSrv := &http.Server{Handler: srv.server.Handler}
		go func() { _ = pipeSrv.Serve(pl) }()
		t.Cleanup(func() {
			_ = pipeSrv.Close()
			_ = pl.Close()
		})
		client = &http.Client{
			Transport: &http.Transport{DialContext: pl.DialContext},
		}
		baseURL = "http://127.0.0.1" + srv.streamPath
	}

	// Wrong token path must be rejected (404)
	badResp, err := client.Get(strings.Replace(baseURL, srv.token, "wrongtoken", 1))
	if err != nil {
		t.Fatalf("GET wrong token failed: %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusNotFound {
		t.Errorf("wrong token status = %d, want 404", badResp.StatusCode)
	}

	// Valid stream request
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET mjpeg stream error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/x-mixed-replace" || params["boundary"] != mjpegBoundary {
		t.Fatalf("Content-Type = %q (err=%v), want multipart/x-mixed-replace; boundary=%s",
			resp.Header.Get("Content-Type"), err, mjpegBoundary)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	mr := multipart.NewReader(resp.Body, params["boundary"])

	// Push frame 1 and verify immediate delivery using Content-Length (just like WebKit's MJPEG decoder)
	f1 := jpegFrame("first")
	src.push(f1)

	readPartExact := func() []byte {
		t.Helper()
		p, err := mr.NextPart()
		if err != nil {
			t.Fatalf("NextPart error = %v", err)
		}
		if ct := p.Header.Get("Content-Type"); ct != "image/jpeg" {
			t.Fatalf("part Content-Type = %q, want image/jpeg", ct)
		}
		var cl int
		if _, err := io.ReadFull(strings.NewReader(p.Header.Get("Content-Length")), nil); err != nil {
			_ = err
		}
		for _, ch := range p.Header.Get("Content-Length") {
			cl = cl*10 + int(ch-'0')
		}
		buf := make([]byte, cl)
		if _, err := io.ReadFull(p, buf); err != nil {
			t.Fatalf("ReadFull(%d) error = %v", cl, err)
		}
		return buf
	}

	body1 := readPartExact()
	if !bytes.Equal(body1, f1) {
		t.Errorf("part #1 = %q, want %q", body1, f1)
	}

	// Simulate backpressure: push 3 frames before reading next part -> latest frame delivered
	src.push(jpegFrame("stale-2"))
	src.push(jpegFrame("stale-3"))
	f4 := jpegFrame("latest-4")
	src.push(f4)

	sawLatest := false
	for i := 0; i < 3; i++ {
		b := readPartExact()
		if bytes.Equal(b, f4) {
			sawLatest = true
			break
		}
	}
	if !sawLatest {
		t.Fatalf("did not receive latest frame %q under backpressure", f4)
	}

	// Stop() must terminate stream cleanly and stop underlying source
	srv.Stop()
	if src.IsRunning() {
		t.Errorf("underlying source still running after MJPEGServer.Stop()")
	}
	if st := srv.Stats(); st.Active {
		t.Errorf("Stats().Active = true after Stop(), want false")
	}
}

func TestMJPEGServer_IdleAutoStop(t *testing.T) {
	src := newFakeFrameSource()
	srv, err := NewMJPEGServerWithSource(src, "fast", "TESTDEV", 60*time.Millisecond)
	if err != nil {
		t.Fatalf("NewMJPEGServerWithSource error = %v", err)
	}
	defer srv.Stop()

	deadline := time.Now().Add(time.Second)
	for srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("MJPEGServer did not auto-stop after idle timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if src.IsRunning() {
		t.Errorf("underlying source still running after idle auto-stop")
	}
}
