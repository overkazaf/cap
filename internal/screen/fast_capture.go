package screen

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/jpeg"
	"os/exec"
)

// rawHeaderSize is the size, in bytes, of the header `adb exec-out
// screencap` (without -p) writes before the raw pixel data: width, height,
// and pixel format, each a little-endian uint32.
const rawHeaderSize = 12

// FastCapture grabs a single frame from the device named by serial (empty
// lets adb pick its default device) via the raw screencap framebuffer
// protocol, and returns it JPEG-encoded.
//
// maxSize caps the longest output dimension in pixels, preserving aspect
// ratio; 0 keeps the device's native resolution. quality is the JPEG
// quality, 1-100; see clampQuality for how out-of-range values are
// handled.
//
// This is the fast path: `adb exec-out screencap -p` asks the device to
// PNG-encode every frame before sending it over USB/Wi-Fi, which is the
// main cost of the old screenshot pipeline. Dropping `-p` makes the device
// hand over the raw framebuffer instead, and the decode/resize/JPEG-encode
// work happens here on the host — 3-5x faster overall.
func FastCapture(serial string, maxSize int, quality int) ([]byte, error) {
	raw, err := runScreencap(serial)
	if err != nil {
		return nil, err
	}
	return encodeRawFrame(raw, maxSize, quality)
}

// runScreencap runs `adb [-s serial] exec-out screencap` and returns its
// raw stdout (the header-prefixed framebuffer).
func runScreencap(serial string) ([]byte, error) {
	args := make([]string, 0, 4)
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "exec-out", "screencap")

	out, err := exec.Command("adb", args...).Output()
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

// decodeRaw parses a full raw screencap payload (header followed by pixel
// data) into an image.
//
// Only RGBA_8888 and RGBX_8888 are supported — in practice the only
// formats real devices emit for screencap — because both pack 4 bytes per
// pixel in the same R,G,B,(A|X) order as image.RGBA's Pix buffer, so the
// pixel bytes can be used directly with no per-pixel conversion. The 4th
// byte is always forced fully opaque: a composited screen framebuffer has
// no meaningful per-pixel transparency, and RGBX_8888's 4th byte is
// explicitly undefined, so trusting either risks a bogus alpha-premultiply
// once the image reaches the JPEG encoder.
func decodeRaw(raw []byte) (*image.RGBA, error) {
	w, h, format, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("screen: invalid screencap dimensions %dx%d", w, h)
	}
	switch format {
	case PixelFormatRGBA8888, PixelFormatRGBX8888:
		// supported: same 4-bytes-per-pixel layout as image.RGBA
	default:
		return nil, fmt.Errorf("screen: unsupported screencap pixel format %s", format)
	}

	pix := raw[rawHeaderSize:]
	want := w * h * 4
	if len(pix) < want {
		return nil, fmt.Errorf("screen: truncated screencap frame: got %d pixel bytes, want %d for %dx%d", len(pix), want, w, h)
	}
	pix = pix[:want:want]

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

// resizeNearest scales img to w x h using nearest-neighbor sampling — the
// cheapest resampling method and good enough for a live screen mirror. If
// img is already an *image.RGBA measuring exactly w x h, it is returned
// unchanged with no copy.
func resizeNearest(img image.Image, w, h int) *image.RGBA {
	bounds := img.Bounds()
	if same, ok := img.(*image.RGBA); ok && bounds.Dx() == w && bounds.Dy() == h {
		return same
	}

	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	if w == 0 || h == 0 {
		return dst
	}
	scaleX := float64(bounds.Dx()) / float64(w)
	scaleY := float64(bounds.Dy()) / float64(h)
	for y := 0; y < h; y++ {
		srcY := bounds.Min.Y + int(float64(y)*scaleY)
		for x := 0; x < w; x++ {
			srcX := bounds.Min.X + int(float64(x)*scaleX)
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

// encodeRawFrame decodes a raw screencap payload, resizes it per maxSize,
// and JPEG-encodes the result at quality. It's the device-independent half
// of FastCapture, split out so it can be unit tested without adb or a
// physical device.
func encodeRawFrame(raw []byte, maxSize, quality int) ([]byte, error) {
	img, err := decodeRaw(raw)
	if err != nil {
		return nil, err
	}

	bounds := img.Bounds()
	w, h := targetSize(bounds.Dx(), bounds.Dy(), maxSize)
	resized := resizeNearest(img, w, h)

	var buf bytes.Buffer
	opts := &jpeg.Options{Quality: clampQuality(quality)}
	if err := jpeg.Encode(&buf, resized, opts); err != nil {
		return nil, fmt.Errorf("screen: jpeg encode: %w", err)
	}
	return buf.Bytes(), nil
}
