//go:build linux

package tui

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// Terminal manages raw terminal mode, alternate screen buffer, cursor
// visibility, terminal size queries, and SIGWINCH notifications.
type Terminal struct {
	fd       int
	orig     *unix.Termios
	raw      bool
	alt      bool
	out      *os.File
	in       *os.File
	resizeCh chan os.Signal
}

// OpenTerminal wraps stdin/stdout in a Terminal controller.
func OpenTerminal(in, out *os.File) (*Terminal, error) {
	fd := int(in.Fd())
	orig, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("tui: get termios: %w", err)
	}
	return &Terminal{
		fd:   fd,
		orig: orig,
		in:   in,
		out:  out,
	}, nil
}

// EnterRaw puts the terminal into raw mode, switches to the alternate screen
// buffer, and hides the cursor.
func (t *Terminal) EnterRaw() error {
	raw := *t.orig
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(t.fd, unix.TCSETS, &raw); err != nil {
		return fmt.Errorf("tui: set raw mode: %w", err)
	}
	t.raw = true

	_, _ = t.out.WriteString("\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H")
	t.alt = true
	return nil
}

// Restore unconditionally restores terminal state. Safe to call multiple times.
func (t *Terminal) Restore() {
	if t.resizeCh != nil {
		signal.Stop(t.resizeCh)
		t.resizeCh = nil
	}
	if t.alt {
		_, _ = t.out.WriteString("\x1b[0m\x1b[?25h\x1b[?1049l")
		t.alt = false
	}
	if t.raw && t.orig != nil {
		_ = unix.IoctlSetTermios(t.fd, unix.TCSETS, t.orig)
		t.raw = false
	}
}

// Size queries the current terminal dimensions in columns and rows.
func (t *Terminal) Size() (int, int) {
	ws, err := unix.IoctlGetWinsize(int(t.out.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 || ws.Row == 0 {
		return 120, 36
	}
	return int(ws.Col), int(ws.Row)
}

// WatchResize returns a channel notified whenever SIGWINCH fires.
func (t *Terminal) WatchResize() <-chan os.Signal {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGWINCH)
	t.resizeCh = ch
	return ch
}

// TerminalSize returns the terminal size for fd (or 0, 0 on error).
func TerminalSize(fd uintptr) (int, int) {
	ws, err := unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0
	}
	return int(ws.Col), int(ws.Row)
}

// IsTTY reports whether fd refers to an interactive terminal.
func IsTTY(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}
