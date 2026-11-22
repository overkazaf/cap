package tui

import "unicode/utf8"

// KeyKind identifies special non-rune keys decoded from raw terminal bytes.
type KeyKind int

const (
	KeyNone KeyKind = iota
	KeyRune
	KeyEnter
	KeyEsc
	KeyTab
	KeyShiftTab
	KeyBackspace
	KeyDelete
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyPgUp
	KeyPgDn
	KeyCtrlC
	KeyCtrlD
	KeyCtrlU
	KeyCtrlL
	KeyCtrlW
	KeyCtrlK
)

// KeyEvent represents a single decoded key press.
type KeyEvent struct {
	Kind KeyKind
	Rune rune
}

// ParseKey decodes the next key event from raw terminal input bytes and
// returns the event plus the number of bytes consumed.
func ParseKey(buf []byte) (KeyEvent, int) {
	if len(buf) == 0 {
		return KeyEvent{Kind: KeyNone}, 0
	}

	b := buf[0]
	switch b {
	case 0x03: // Ctrl+C
		return KeyEvent{Kind: KeyCtrlC}, 1
	case 0x04: // Ctrl+D
		return KeyEvent{Kind: KeyCtrlD}, 1
	case 0x0b: // Ctrl+K
		return KeyEvent{Kind: KeyCtrlK}, 1
	case 0x0c: // Ctrl+L
		return KeyEvent{Kind: KeyCtrlL}, 1
	case 0x15: // Ctrl+U
		return KeyEvent{Kind: KeyCtrlU}, 1
	case 0x17: // Ctrl+W
		return KeyEvent{Kind: KeyCtrlW}, 1
	case '\r', '\n':
		return KeyEvent{Kind: KeyEnter}, 1
	case '\t':
		return KeyEvent{Kind: KeyTab}, 1
	case 0x7f, 0x08:
		return KeyEvent{Kind: KeyBackspace}, 1
	case 0x1b:
		return parseEscapeSeq(buf)
	}

	// Printable ASCII or multi-byte UTF-8 rune.
	if b >= 0x20 {
		r, size := utf8.DecodeRune(buf)
		if r == utf8.RuneError && size == 1 {
			return KeyEvent{Kind: KeyNone}, 1
		}
		return KeyEvent{Kind: KeyRune, Rune: r}, size
	}

	// Ignore other control bytes.
	return KeyEvent{Kind: KeyNone}, 1
}

func parseEscapeSeq(buf []byte) (KeyEvent, int) {
	if len(buf) == 1 {
		return KeyEvent{Kind: KeyEsc}, 1
	}

	// CSI sequences: ESC [ ...
	if buf[1] == '[' {
		if len(buf) < 3 {
			return KeyEvent{Kind: KeyEsc}, 1
		}
		switch buf[2] {
		case 'A':
			return KeyEvent{Kind: KeyUp}, 3
		case 'B':
			return KeyEvent{Kind: KeyDown}, 3
		case 'C':
			return KeyEvent{Kind: KeyRight}, 3
		case 'D':
			return KeyEvent{Kind: KeyLeft}, 3
		case 'H':
			return KeyEvent{Kind: KeyHome}, 3
		case 'F':
			return KeyEvent{Kind: KeyEnd}, 3
		case 'Z':
			return KeyEvent{Kind: KeyShiftTab}, 3
		case '1', '2', '3', '4', '5', '6', '7', '8':
			// Extended CSI ending in '~', e.g. ESC [ 5 ~ (PgUp), ESC [ 6 ~ (PgDn).
			for i := 3; i < len(buf) && i < 8; i++ {
				if buf[i] == '~' {
					switch buf[2] {
					case '1', '7':
						return KeyEvent{Kind: KeyHome}, i + 1
					case '3':
						return KeyEvent{Kind: KeyDelete}, i + 1
					case '4', '8':
						return KeyEvent{Kind: KeyEnd}, i + 1
					case '5':
						return KeyEvent{Kind: KeyPgUp}, i + 1
					case '6':
						return KeyEvent{Kind: KeyPgDn}, i + 1
					}
					return KeyEvent{Kind: KeyNone}, i + 1
				}
				if isCSITerminator(buf[i]) {
					return KeyEvent{Kind: KeyNone}, i + 1
				}
			}
			return KeyEvent{Kind: KeyNone}, len(buf)
		default:
			// Consume unrecognized CSI sequence cleanly so trailing bytes don't trigger keys.
			for i := 2; i < len(buf) && i < 16; i++ {
				if isCSITerminator(buf[i]) {
					return KeyEvent{Kind: KeyNone}, i + 1
				}
			}
			return KeyEvent{Kind: KeyNone}, len(buf)
		}
	}

	// SS3 sequences (application cursor mode): ESC O A/B/C/D/H/F
	if buf[1] == 'O' && len(buf) >= 3 {
		switch buf[2] {
		case 'A':
			return KeyEvent{Kind: KeyUp}, 3
		case 'B':
			return KeyEvent{Kind: KeyDown}, 3
		case 'C':
			return KeyEvent{Kind: KeyRight}, 3
		case 'D':
			return KeyEvent{Kind: KeyLeft}, 3
		case 'H':
			return KeyEvent{Kind: KeyHome}, 3
		case 'F':
			return KeyEvent{Kind: KeyEnd}, 3
		}
		return KeyEvent{Kind: KeyNone}, 3
	}

	// Bare ESC followed by something else -> treat first byte as Esc.
	return KeyEvent{Kind: KeyEsc}, 1
}
