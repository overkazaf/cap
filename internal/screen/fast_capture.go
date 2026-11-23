package screen

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"image/jpeg"
	"os/exec"
	"sync"
)

// rawHeaderSize is the size, in bytes, of the header `adb exec-out
// screencap` (without -p) writes before the raw pixel data: width, height,
// and pixel format, each a little-endian uint32.
const rawHeaderSize = 12

// jpegBufPool recycles bytes.Buffer instances used during JPEG encoding to
// avoid repeated 64KB+ heap allocations on every captured frame.
var jpegBufPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 64*1024))
	},
}

// rgbaScratchPool recycles *image.RGBA backing buffers used during fast
// downscaling inside encodeRawFrame.
var rgbaScratchPool = sync.Pool{
	New: func() any {
		return &rgbaScratch{}
	},
}

type rgbaScratch struct {
	pix  []byte
	xOff []int
}

// FastCapture grabs a single frame from the device named by serial (empty
// lets adb pick its default device) via the raw screencap framebuffer
// protocol, and returns it JPEG-encoded.
//
// maxSize caps the longest output dimension in pixels, preserving aspect
// ratio; 0 keeps the device's native resolution. quality is the JPEG
// quality, 1-100; see clampQuality for how out-of-range values are
// handled.
func FastCapture(serial string, maxSize int, quality int) ([]byte, error) {
	return FastCaptureContext(context.Background(), serial, maxSize, quality)
}

// FastCaptureContext is like FastCapture but cancels any in-flight `adb
// exec-out screencap` subprocess immediately when ctx is cancelled.
func FastCaptureContext(ctx context.Context, serial string, maxSize int, quality int) ([]byte, error) {
	raw, err := runScreencapContext(ctx, serial)
	if err != nil {
		return nil, err
	}
	return encodeRawFrame(raw, maxSize, quality)
}

// runScreencap runs `adb [-s serial] exec-out screencap` and returns its
// raw stdout (the header-prefixed framebuffer).
func runScreencap(serial string) ([]byte, error) {
	return runScreencapContext(context.Background(), serial)
}

// runScreencapContext runs `adb [-s serial] exec-out screencap` tied to ctx
// so Stop() kills any hung subprocess immediately.
func runScreencapContext(ctx context.Context, serial string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	args := make([]string, 0, 4)
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "exec-out", "screencap")

	out, err := exec.CommandContext(ctx, "adb", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("adb exec-out screencap: %w", err)
	}
	return out, nil
}

// parseHeader parses the rawHeaderSize-byte raw screencap header into
// width, height, and pixel format. It returns an error if data is shorter
// than rawHeaderSize.
func parseHeader(data []byte) (width, height int, format PixelFormat, err error) {
	if len(data) < rawHeaderSize {
		return 0, 0, 0, fmt.Errorf("screen: screencap header too short: got %d bytes, want at least %d", len(data), rawHeaderSize)
	}
	w := binary.LittleEndian.Uint32(data[0:4])
	h := binary.LittleEndian.Uint32(data[4:8])
	f := binary.LittleEndian.Uint32(data[8:12])
	return int(w), int(h), PixelFormat(f), nil
}

// parseRawPixels validates a raw screencap header + payload length and
// returns the raw 4-byte-per-pixel slice without sweeping all pixels.
func parseRawPixels(raw []byte) (pix []byte, w, h int, err error) {
	w, h, format, err := parseHeader(raw)
	if err != nil {
		return nil, 0, 0, err
	}
	if w <= 0 || h <= 0 {
		return nil, 0, 0, fmt.Errorf("screen: invalid screencap dimensions %dx%d", w, h)
	}
	switch format {
	case PixelFormatRGBA8888, PixelFormatRGBX8888:
		// supported: same 4-bytes-per-pixel layout as image.RGBA
	default:
		return nil, 0, 0, fmt.Errorf("screen: unsupported screencap pixel format %s", format)
	}

	pix = raw[rawHeaderSize:]
	want := w * h * 4
	if len(pix) < want {
		return nil, 0, 0, fmt.Errorf("screen: truncated screencap frame: got %d pixel bytes, want %d for %dx%d", len(pix), want, w, h)
	}
	return pix[:want:want], w, h, nil
}

// decodeRaw parses a full raw screencap payload (header followed by pixel
// data) into an image, forcing all alpha bytes to 0xff.
func decodeRaw(raw []byte) (*image.RGBA, error) {
	pix, w, h, err := parseRawPixels(raw)
	if err != nil {
		return nil, err
	}

	for i := 3; i < len(pix); i += 4 {
		pix[i] = 0xff
	}

	return &image.RGBA{
		Pix:    pix,
		Stride: w * 4,
		Rect:   image.Rect(0, 0, w, h),
	}, nil
}

// targetSize returns the output dimensions for scaling a srcW x srcH image
// so its longest side is at most maxSize, preserving aspect ratio. If
// maxSize <= 0, or the image already fits within it, (srcW, srcH) is
// returned unchanged.
func targetSize(srcW, srcH, maxSize int) (w, h int) {
	if maxSize <= 0 || (srcW <= maxSize && srcH <= maxSize) {
		return srcW, srcH
	}
	if srcW >= srcH {
		w = maxSize
		h = int(float64(srcH) * float64(maxSize) / float64(srcW))
	} else {
		h = maxSize
		w = int(float64(srcW) * float64(maxSize) / float64(srcH))
	}
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	return w, h
}

// sampleNearestRawRGBA samples srcPix (srcW x srcH, 4 bytes/px, srcStride bytes/row)
// directly into dstPix (dstW x dstH, tightly packed 4 bytes/px) using integer
// stride arithmetic and forcing alpha = 0xff ONLY on output pixels.
// xOffScratch is an optional reusable slice of length >= dstW.
func sampleNearestRawRGBA(srcPix []byte, srcW, srcH, srcStride int, dstPix []byte, dstW, dstH int, xOffScratch []int) {
	if dstW <= 0 || dstH <= 0 {
		return
	}
	xOff := xOffScratch
	if cap(xOff) < dstW {
		xOff = make([]int, dstW)
	} else {
		xOff = xOff[:dstW]
	}
	// Precompute horizontal source byte offsets once per frame.
	// Using 64-bit integer ratio (x * srcW / dstW) avoids float conversions in
	// the hot inner loop and guarantees 0 <= srcX < srcW.
	for x := 0; x < dstW; x++ {
		xOff[x] = ((x * srcW) / dstW) * 4
	}

	dstIdx := 0
	for y := 0; y < dstH; y++ {
		srcRow := ((y * srcH) / dstH) * srcStride
		for x := 0; x < dstW; x++ {
			s := srcRow + xOff[x]
			// Bounds check hint for compiler BCE
			_ = srcPix[s+2]
			_ = dstPix[dstIdx+3]
			dstPix[dstIdx] = srcPix[s]
			dstPix[dstIdx+1] = srcPix[s+1]
			dstPix[dstIdx+2] = srcPix[s+2]
			dstPix[dstIdx+3] = 0xff
			dstIdx += 4
		}
	}
}

// resizeNearest scales img to w x h using nearest-neighbor sampling — the
// cheapest resampling method and good enough for a live screen mirror. If
// img is already an *image.RGBA measuring exactly w x h, it is returned
// unchanged with no copy.
func resizeNearest(img image.Image, w, h int) *image.RGBA {
	bounds := img.Bounds()
	srcW, srcH := bounds.Dx(), bounds.Dy()
	if same, ok := img.(*image.RGBA); ok && srcW == w && srcH == h {
		return same
	}

	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	if w <= 0 || h <= 0 || srcW <= 0 || srcH <= 0 {
		return dst
	}

	// Fast path: direct Pix slice stride indexing for *image.RGBA (zero interface boxing).
	if src, ok := img.(*image.RGBA); ok {
		startOff := src.PixOffset(bounds.Min.X, bounds.Min.Y)
		sampleNearestRawRGBA(src.Pix[startOff:], srcW, srcH, src.Stride, dst.Pix, w, h, nil)
		return dst
	}

	// Generic fallback for non-RGBA image.Image implementations.
	for y := 0; y < h; y++ {
		srcY := bounds.Min.Y + (y*srcH)/h
		for x := 0; x < w; x++ {
			srcX := bounds.Min.X + (x*srcW)/w
			dst.Set(x, y, img.At(srcX, srcY))
		}
	}
	return dst
}

// clampQuality normalizes a JPEG quality value: <= 0 becomes
// DefaultQuality, and anything above 100 is capped at 100.
func clampQuality(quality int) int {
	if quality <= 0 {
		return DefaultQuality
	}
	if quality > 100 {
		return 100
	}
	return quality
}

// encodeRawFrame decodes a raw screencap payload, resizes it per maxSize
// directly from raw pixel bytes (avoiding any full-frame pre-resize alpha
// sweep or interface-boxing At/Set calls), and JPEG-encodes the result at
// quality using pooled scratch buffers.
func encodeRawFrame(raw []byte, maxSize, quality int) ([]byte, error) {
	pix, srcW, srcH, err := parseRawPixels(raw)
	if err != nil {
		return nil, err
	}

	dstW, dstH := targetSize(srcW, srcH, maxSize)

	var resized *image.RGBA
	var scratch *rgbaScratch
	if dstW == srcW && dstH == srcH {
		// Same size: force opaque alpha in place without copying pixels.
		for i := 3; i < len(pix); i += 4 {
			pix[i] = 0xff
		}
		resized = &image.RGBA{
			Pix:    pix,
			Stride: srcW * 4,
			Rect:   image.Rect(0, 0, srcW, srcH),
		}
	} else {
		scratch = rgbaScratchPool.Get().(*rgbaScratch)
		need := dstW * dstH * 4
		if cap(scratch.pix) < need {
			scratch.pix = make([]byte, need)
		} else {
			scratch.pix = scratch.pix[:need]
		}
		if cap(scratch.xOff) < dstW {
			scratch.xOff = make([]int, dstW)
		} else {
			scratch.xOff = scratch.xOff[:dstW]
		}

		sampleNearestRawRGBA(pix, srcW, srcH, srcW*4, scratch.pix, dstW, dstH, scratch.xOff)
		resized = &image.RGBA{
			Pix:    scratch.pix,
			Stride: dstW * 4,
			Rect:   image.Rect(0, 0, dstW, dstH),
		}
	}

	buf := jpegBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	opts := &jpeg.Options{Quality: clampQuality(quality)}
	encodeErr := jpeg.Encode(buf, resized, opts)

	if scratch != nil {
		rgbaScratchPool.Put(scratch)
	}

	if encodeErr != nil {
		jpegBufPool.Put(buf)
		return nil, fmt.Errorf("screen: jpeg encode: %w", encodeErr)
	}

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	jpegBufPool.Put(buf)
	return out, nil
}
