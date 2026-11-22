package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/overkazaf/cap/internal/i18n"
)

// RuneWidth returns the monospace terminal cell width (0, 1, or 2) of r,
// properly accounting for combining marks, East Asian Wide/Fullwidth runes
// (CJK ideographs, Hiragana, Katakana, Hangul), and common emoji blocks.
func RuneWidth(r rune) int {
	if r == 0 || r < 0x20 || (r >= 0x7f && r < 0xa0) {
		return 0
	}
	// Fast path for printable ASCII.
	if r < 0x7f {
		return 1
	}
	// Zero-width combining/format characters (Mn, Me, Cf) and ZWJ/VS selectors.
	if r == 0x200d || (r >= 0xfe00 && r <= 0xfe0f) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) {
		return 0
	}
	// East Asian Wide & Fullwidth ranges + Emoji presentation blocks.
	if isWideRune(r) {
		return 2
	}
	return 1
}

func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115f: // Hangul Jamo
		return true
	case r == 0x2329 || r == 0x232a:
		return true
	case r >= 0x2e80 && r <= 0x303e: // CJK Radicals, Kangxi, Ideographic, CJK Symbols
		return true
	case r >= 0x3040 && r <= 0xa4cf: // Hiragana, Katakana, Bopomofo, Hangul, CJK Unified Ideographs
		return true
	case r >= 0xa960 && r <= 0xa97f: // Hangul Jamo Extended-A
		return true
	case r >= 0xac00 && r <= 0xd7a3: // Hangul Syllables
		return true
	case r >= 0xf900 && r <= 0xfaff: // CJK Compatibility Ideographs
		return true
	case r >= 0xfe10 && r <= 0xfe19: // Vertical Forms
		return true
	case r >= 0xfe30 && r <= 0xfe6f: // CJK Compatibility Forms & Small Form Variants
		return true
	case r >= 0xff01 && r <= 0xff60: // Fullwidth ASCII variants
		return true
	case r >= 0xffe0 && r <= 0xffe6: // Fullwidth symbol variants
		return true
	case r >= 0x1f300 && r <= 0x1faff: // Misc Symbols & Pictographs, Emoticons, Transport, Supplemental Emoji
		return true
	case r >= 0x20000 && r <= 0x3fffd: // CJK Unified Ideographs Extensions B-G
		return true
	default:
		return false
	}
}

func stringWidth(s string) int {
	w := 0
	for _, r := range s {
		w += RuneWidth(r)
	}
	return w
}

// StripANSI removes ANSI CSI escape sequences (\x1b[...letter) from s.
func StripANSI(s string) string {
	if !strings.ContainsRune(s, '\x1b') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !isCSITerminator(s[j]) {
				j++
			}
			if j < len(s) {
				i = j + 1
			} else {
				break
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isCSITerminator(b byte) bool {
	return b >= 0x40 && b <= 0x7e
}

// DisplayWidth returns the visual terminal cell width of s, ignoring ANSI
// escape sequences and properly accounting for East Asian wide runes.
func DisplayWidth(s string) int {
	return stringWidth(StripANSI(s))
}

// SanitizeInline strips control characters (including ANSI escapes, newlines,
// and tabs) from untrusted network data so a single-line cell can never
// corrupt terminal layout or inject escape codes.
func SanitizeInline(s string) string {
	clean := StripANSI(s)
	var b strings.Builder
	b.Grow(len(clean))
	for _, r := range clean {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// drop C0 control characters
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Truncate trims plain text s to at most maxWidth display cells, appending
// "…" when truncated and maxWidth >= 2. Wide East Asian characters are never
// split or allowed to overflow maxWidth.
func Truncate(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	if stringWidth(s) <= maxWidth {
		return s
	}
	if maxWidth == 1 {
		return "…"
	}
	limit := maxWidth - 1
	var b strings.Builder
	w := 0
	for _, r := range s {
		rw := RuneWidth(r)
		if w+rw > limit {
			break
		}
		b.WriteRune(r)
		w += rw
	}
	b.WriteRune('…')
	return b.String()
}

// ClampANSI trims an ANSI-styled string to at most maxWidth visual cells while
// preserving intact escape sequences and closing with a reset if truncated.
func ClampANSI(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	if DisplayWidth(s) <= maxWidth {
		return s
	}
	var b strings.Builder
	w := 0
	sawANSI := false
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !isCSITerminator(s[j]) {
				j++
			}
			if j < len(s) {
				b.WriteString(s[i : j+1])
				sawANSI = true
				i = j + 1
				continue
			}
			break
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		rw := RuneWidth(r)
		if w+rw > maxWidth {
			break
		}
		b.WriteString(s[i : i+size])
		w += rw
		i += size
	}
	if sawANSI {
		b.WriteString(ansiReset)
	}
	return b.String()
}

// PadRight pads an ANSI-aware string on the right with spaces to exact width,
// clamping if it exceeds width.
func PadRight(s string, width int) string {
	if width <= 0 {
		return ""
	}
	s = ClampANSI(s, width)
	w := DisplayWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// PadLeft pads an ANSI-aware string on the left with spaces to exact width,
// clamping if it exceeds width.
func PadLeft(s string, width int) string {
	if width <= 0 {
		return ""
	}
	s = ClampANSI(s, width)
	w := DisplayWidth(s)
	if w >= width {
		return s
	}
	return strings.Repeat(" ", width-w) + s
}

// FillLine pads s to exact width while filling the background with bgCode
// (when non-empty). Any internal \x1b[0m resets are patched to re-apply bgCode
// so bar/row highlights look completely seamless across all cells.
func FillLine(s string, width int, bgCode string) string {
	if width <= 0 {
		return ""
	}
	s = ClampANSI(s, width)
	w := DisplayWidth(s)
	pad := 0
	if w < width {
		pad = width - w
	}
	if bgCode == "" {
		if pad == 0 {
			return s
		}
		return s + strings.Repeat(" ", pad)
	}
	patched := strings.ReplaceAll(s, ansiReset, ansiReset+bgCode)
	var b strings.Builder
	b.Grow(len(patched) + len(bgCode)*2 + pad + 8)
	b.WriteString(bgCode)
	b.WriteString(patched)
	if pad > 0 {
		b.WriteString(strings.Repeat(" ", pad))
	}
	b.WriteString(ansiReset)
	return b.String()
}

// FormatBytes formats a byte count into a compact human-readable string.
func FormatBytes(n int) string {
	if n < 0 {
		n = 0
	}
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024.0)
	default:
		return fmt.Sprintf("%.2f MB", float64(n)/(1024.0*1024.0))
	}
}

// FormatLatency formats milliseconds compactly (e.g. "42ms", "1.35s").
func FormatLatency(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.2fs", float64(ms)/1000.0)
}

// IsBinary heuristically detects whether data is binary rather than UTF-8 text.
func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	if !utf8.Valid(sample) {
		return true
	}
	ctrl := 0
	for _, b := range sample {
		if b == 0 {
			return true
		}
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			ctrl++
		}
	}
	return ctrl*10 > len(sample)
}

// FormatHexDump formats binary bytes into a Wireshark-style offset + hex + ASCII dump.
func FormatHexDump(data []byte, maxBytes int, th Theme) []string {
	return FormatHexDumpLocale(data, maxBytes, th, i18n.Lang())
}

// FormatHexDumpLocale formats binary bytes into a hex+ASCII dump with localized truncation footer.
func FormatHexDumpLocale(data []byte, maxBytes int, th Theme, loc i18n.Locale) []string {
	if len(data) == 0 {
		return nil
	}
	truncated := false
	view := data
	if maxBytes > 0 && len(view) > maxBytes {
		view = view[:maxBytes]
		truncated = true
	}

	const cols = 16
	lines := make([]string, 0, (len(view)+cols-1)/cols+2)
	for offset := 0; offset < len(view); offset += cols {
		end := offset + cols
		if end > len(view) {
			end = len(view)
		}
		chunk := view[offset:end]

		var hexPart strings.Builder
		var ascPart strings.Builder
		for i := 0; i < cols; i++ {
			if i == 8 {
				hexPart.WriteByte(' ')
			}
			if i < len(chunk) {
				b := chunk[i]
				fmt.Fprintf(&hexPart, "%02x ", b)
				if b >= 0x20 && b <= 0x7e {
					ascPart.WriteByte(b)
				} else {
					ascPart.WriteByte('.')
				}
			} else {
				hexPart.WriteString("   ")
				ascPart.WriteByte(' ')
			}
		}

		line := th.Fg(th.FgMuted, fmt.Sprintf("%08x", offset)) + "  " +
			th.Fg(th.Info, hexPart.String()) + " " +
			th.Fg(th.FgMuted, "|") + th.Fg(th.FgSecondary, ascPart.String()) + th.Fg(th.FgMuted, "|")
		lines = append(lines, line)
	}
	if truncated {
		lines = append(lines, th.Fg(th.Warn, i18n.TLocale(loc, "tui.body.binary_trunc", FormatBytes(len(data)), FormatBytes(maxBytes))))
	}
	return lines
}

// HighlightJSON pretty-prints raw JSON and applies semantic ANSI syntax
// highlighting. Returns (lines, true) if data is valid JSON, or (nil, false)
// otherwise.
func HighlightJSON(data []byte, th Theme) ([]string, bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, false
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return nil, false
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, trimmed, "", "  "); err != nil {
		return nil, false
	}

	rawLines := strings.Split(pretty.String(), "\n")
	if th.NoColor {
		return rawLines, true
	}

	out := make([]string, len(rawLines))
	for i, line := range rawLines {
		out[i] = highlightJSONLine(line, th)
	}
	return out, true
}

func highlightJSONLine(line string, th Theme) string {
	var b strings.Builder
	b.Grow(len(line) + 32)
	n := len(line)
	for i := 0; i < n; {
		ch := line[i]
		switch {
		case ch == ' ' || ch == '\t':
			b.WriteByte(ch)
			i++
		case ch == '"':
			// Scan full JSON string literal including escaped quotes.
			j := i + 1
			for j < n {
				if line[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if line[j] == '"' {
					j++
					break
				}
				j++
			}
			tok := line[i:j]
			// Peek past whitespace to see if ':' follows (making this an object key).
			k := j
			for k < n && line[k] == ' ' {
				k++
			}
			if k < n && line[k] == ':' {
				b.WriteString(th.Fg(th.JSONKey, tok))
			} else {
				b.WriteString(th.Fg(th.JSONString, tok))
			}
			i = j
		case ch == '{' || ch == '}' || ch == '[' || ch == ']' || ch == ':' || ch == ',':
			b.WriteString(th.Fg(th.JSONPunct, string(ch)))
			i++
		case ch == '-' || (ch >= '0' && ch <= '9'):
			j := i + 1
			for j < n && isJSONNumByte(line[j]) {
				j++
			}
			b.WriteString(th.Fg(th.JSONNumber, line[i:j]))
			i = j
		case strings.HasPrefix(line[i:], "true"):
			b.WriteString(th.Fg(th.JSONBool, "true"))
			i += 4
		case strings.HasPrefix(line[i:], "false"):
			b.WriteString(th.Fg(th.JSONBool, "false"))
			i += 5
		case strings.HasPrefix(line[i:], "null"):
			b.WriteString(th.Fg(th.JSONBool, "null"))
			i += 4
		default:
			b.WriteByte(ch)
			i++
		}
	}
	return b.String()
}

func isJSONNumByte(b byte) bool {
	return (b >= '0' && b <= '9') || b == '.' || b == 'e' || b == 'E' || b == '+' || b == '-'
}

// FormatBodyLines formats an HTTP request or response body for display inside
// the inspector pane: valid JSON is pretty-printed and syntax-highlighted,
// binary bodies render as a hex+ASCII dump, and plain text is safely sanitized.
func FormatBodyLines(body []byte, contentType string, th Theme) []string {
	return FormatBodyLinesLocale(body, contentType, th, i18n.Lang())
}

// FormatBodyLinesLocale formats an HTTP body using the specified locale.
func FormatBodyLinesLocale(body []byte, contentType string, th Theme, loc i18n.Locale) []string {
	if len(body) == 0 {
		return []string{th.Fg(th.FgMuted, i18n.TLocale(loc, "tui.body.empty"))}
	}
	if lines, ok := HighlightJSON(body, th); ok {
		return lines
	}
	if IsBinary(body) {
		header := th.Fg(th.FgMuted, i18n.TLocale(loc, "tui.body.binary", FormatBytes(len(body)), contentTypeOrDefault(contentType)))
		dump := FormatHexDumpLocale(body, 4096, th, loc)
		return append([]string{header, ""}, dump...)
	}
	// Plain text (HTML, XML, form-encoded, JS, etc.): strip raw ANSI & CR, expand tabs.
	clean := strings.ReplaceAll(StripANSI(string(body)), "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	clean = strings.ReplaceAll(clean, "\t", "  ")
	rawLines := strings.Split(clean, "\n")
	out := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		var sb strings.Builder
		for _, r := range line {
			if unicode.IsControl(r) {
				continue
			}
			sb.WriteRune(r)
		}
		out = append(out, th.Fg(th.FgPrimary, sb.String()))
	}
	return out
}

func contentTypeOrDefault(ct string) string {
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return "application/octet-stream"
	}
	return SanitizeInline(ct)
}

// WrapPlainLines soft-wraps lines to maxWidth cells while preserving ANSI codes
// on single lines cleanly (for plain text or long URLs).
func WrapText(s string, maxWidth int) []string {
	if maxWidth <= 1 {
		return []string{s}
	}
	s = SanitizeInline(s)
	if stringWidth(s) <= maxWidth {
		return []string{s}
	}
	var lines []string
	var cur strings.Builder
	w := 0
	for _, r := range s {
		rw := RuneWidth(r)
		if w+rw > maxWidth && cur.Len() > 0 {
			lines = append(lines, cur.String())
			cur.Reset()
			w = 0
		}
		cur.WriteRune(r)
		w += rw
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}
