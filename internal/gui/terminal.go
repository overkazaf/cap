package gui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"fyne.io/fyne/v2"

	"github.com/creack/pty"
)

var (
	ansiOSC   = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)
	ansiCSI   = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	ansiOther = regexp.MustCompile(`\x1b[()#][0-9A-Za-z]|\x1b[=>M78]`)
)

func stripANSI(s string) string {
	s = ansiOSC.ReplaceAllString(s, "")
	s = ansiCSI.ReplaceAllString(s, "")
	s = ansiOther.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r == '\x1b' || r < 0x20:
			return -1
		default:
			return r
		}
	}, s)
}

type TermSession struct {
	cmd   *exec.Cmd
	ptmx  *os.File
	lines []string
	mu    sync.Mutex
	done  chan struct{}
	once  sync.Once

	OnOutput func(line string)
	OnExit   func()
}

func NewTermSession() (*TermSession, error) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=dumb")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("pty start: %w", err)
	}

	ts := &TermSession{
		cmd:  cmd,
		ptmx: ptmx,
		done: make(chan struct{}),
	}

	go ts.readLoop()
	go ts.waitLoop()

	return ts, nil
}

func (ts *TermSession) readLoop() {
	reader := bufio.NewReader(ts.ptmx)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			clean := stripANSI(strings.TrimRight(line, "\r\n"))
			if clean == "" {
				continue
			}
			ts.mu.Lock()
			ts.lines = append(ts.lines, clean)
			ts.mu.Unlock()
			if ts.OnOutput != nil {
				ts.OnOutput(clean)
			}
		}
		if err != nil {
			if err != io.EOF {
				ts.mu.Lock()
				ts.lines = append(ts.lines, fmt.Sprintf("[error: %v]", err))
				ts.mu.Unlock()
			}
			return
		}
	}
}

func (ts *TermSession) waitLoop() {
	ts.cmd.Wait()
	close(ts.done)
	if ts.OnExit != nil {
		fyne.Do(func() { ts.OnExit() })
	}
}

func (ts *TermSession) Write(input string) {
	ts.ptmx.Write([]byte(input + "\n"))
}

func (ts *TermSession) Close() {
	ts.once.Do(func() {
		ts.ptmx.Close()
		if ts.cmd.Process != nil {
			ts.cmd.Process.Kill()
		}
	})
}

func (ts *TermSession) IsDone() bool {
	select {
	case <-ts.done:
		return true
	default:
		return false
	}
}
