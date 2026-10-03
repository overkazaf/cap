// Package screen captures frames from an Android device's display for
// cap's screen-mirroring GUI feature.
//
// The original implementation shelled out to `adb exec-out screencap -p`,
// which asks the device to PNG-encode every frame before sending it over
// USB/Wi-Fi — slow enough to limit mirroring to roughly 1-2 FPS. This
// package instead drives `adb exec-out screencap` (no `-p`), which returns
// the device's raw, uncompressed framebuffer. Skipping on-device PNG
// compression this way is 3-5x faster; the trade-off is that cap must
// decode the raw pixels itself, optionally resize them, and JPEG-encode
// them for the frontend. All of that is handled here using only the
// standard library (encoding/binary, image, image/jpeg) — no CGo, no
// ffmpeg, no external dependencies.
//
// A second engine, EngineScrcpy, is reserved for a future scrcpy-server
// based H.264 streaming backend capable of true 30fps mirroring. It is not
// implemented yet: Capture returns an error if it's selected.
package screen

import "fmt"

// Engine identifies which backend produces frames.
type Engine int

const (
	// EngineScreencap captures frames via `adb exec-out screencap` using
	// the device's raw (non-PNG) framebuffer. Implemented by FastCapture
	// and FastStream in this package.
	EngineScreencap Engine = iota

	// EngineScrcpy is reserved for a future scrcpy-server-based H.264
	// streaming engine. Not implemented yet.
	EngineScrcpy
)

// String returns a human-readable engine name, suitable for logging.
func (e Engine) String() string {
	switch e {
	case EngineScreencap:
		return "screencap"
	case EngineScrcpy:
		return "scrcpy"
	default:
		return fmt.Sprintf("screen.Engine(%d)", int(e))
	}
}

// PixelFormat mirrors the android.graphics.PixelFormat constants that
// `screencap` writes into its raw output header.
type PixelFormat uint32

const (
	PixelFormatUnknown  PixelFormat = 0
	PixelFormatRGBA8888 PixelFormat = 1
	PixelFormatRGBX8888 PixelFormat = 2
	PixelFormatRGB888   PixelFormat = 3
	PixelFormatRGB565   PixelFormat = 4
	PixelFormatBGRA8888 PixelFormat = 5
)

// String returns the conventional Android name for the pixel format (e.g.
// "RGBA_8888"), falling back to the raw numeric value for anything else.
func (f PixelFormat) String() string {
	switch f {
	case PixelFormatUnknown:
		return "UNKNOWN"
	case PixelFormatRGBA8888:
		return "RGBA_8888"
	case PixelFormatRGBX8888:
		return "RGBX_8888"
	case PixelFormatRGB888:
		return "RGB_888"
	case PixelFormatRGB565:
		return "RGB_565"
	case PixelFormatBGRA8888:
		return "BGRA_8888"
	default:
		return fmt.Sprintf("PixelFormat(%d)", uint32(f))
	}
}

// Default tuning values, used whenever a caller leaves the corresponding
// Options/NewFastStream field unset (<= 0).
const (
	DefaultMaxSize = 540 // max(width, height) in px; keeps mirroring smooth over USB/Wi-Fi
	DefaultQuality = 70  // JPEG quality, 1-100
	DefaultFPS     = 15  // target frames per second for FastStream
)

// Options configures a single-frame Capture call.
type Options struct {
	// Engine selects the capture backend. The zero value, EngineScreencap,
	// is always available and needs no extra setup on the device.
	Engine Engine
	// Serial is the ADB device serial to target; empty lets adb pick
	// whatever device it would by default (only unambiguous with exactly
	// one device attached).
	Serial string
	// MaxSize caps the longest output dimension, in pixels; 0 keeps the
	// device's native resolution.
	MaxSize int
	// Quality is the JPEG output quality, 1-100; out-of-range values are
	// clamped (see clampQuality).
	Quality int
}

// Capture grabs one JPEG-encoded frame using the backend selected by
// opts.Engine. EngineScreencap is implemented by FastCapture; EngineScrcpy
// is reserved for a future scrcpy-server backend and currently always
// returns an error.
func Capture(opts Options) ([]byte, error) {
	switch opts.Engine {
	case EngineScreencap:
		return captureFunc(opts.Serial, opts.MaxSize, opts.Quality)
	case EngineScrcpy:
		return nil, fmt.Errorf("screen: engine %s is not implemented yet", opts.Engine)
	default:
		return nil, fmt.Errorf("screen: unknown engine %s", opts.Engine)
	}
}
