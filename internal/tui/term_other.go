//go:build !darwin && !freebsd && !netbsd && !openbsd && !linux

package tui

import (
	"errors"
	"os"
)

type Terminal struct {
	out *os.File
}

func OpenTerminal(in, out *os.File) (*Terminal, error) {
	return nil, errors.New("tui: interactive raw terminal mode is not supported on this OS")
}

func (t *Terminal) EnterRaw() error             { return errors.New("tui: unsupported OS") }
func (t *Terminal) Restore()                    {}
func (t *Terminal) Size() (int, int)            { return 120, 36 }
func (t *Terminal) WatchResize() <-chan os.Signal { return nil }

func TerminalSize(fd uintptr) (int, int) { return 0, 0 }
func IsTTY(fd uintptr) bool            { return false }
