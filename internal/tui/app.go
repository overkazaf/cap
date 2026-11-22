package tui

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/i18n"
	"github.com/overkazaf/cap/internal/replay"
	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
)

// Config configures an interactive TUI App session.
type Config struct {
	Store         store.Store
	Version       string
	Lang          string
	Live          bool
	ListenAddr    string
	DBPath        string
	InitialFilter string
	LightTheme    bool
	NoColor       bool

	// Optional FlowStream delivers live flows into the TUI without blocking
	// the proxy goroutine.
	FlowStream <-chan *types.Flow

	// Optional OnError / OnShutdown hooks.
	In  *os.File
	Out *os.File
}

type replayDoneMsg struct {
	res *replay.Result
	err error
}

// App orchestrates the terminal lifecycle, event loop, live flow ingestion,
// async replay, clipboard copy, and export actions.
type App struct {
	cfg Config
}

// NewApp creates a new TUI App.
func NewApp(cfg Config) *App {
	if cfg.In == nil {
		cfg.In = os.Stdin
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	return &App{cfg: cfg}
}

// Run enters raw terminal mode, runs the interactive event loop until quit
// or signal, and guarantees clean terminal restoration even on panic.
func (a *App) Run() (retErr error) {
	term, err := OpenTerminal(a.cfg.In, a.cfg.Out)
	if err != nil {
		return err
	}
	if err := term.EnterRaw(); err != nil {
		term.Restore()
		return err
	}
	defer func() {
		term.Restore()
		if r := recover(); r != nil {
			retErr = fmt.Errorf("tui panic recovered: %v", r)
		}
	}()

	w, h := term.Size()
	var initialFlows []*types.Flow
	if a.cfg.Store != nil {
		if loaded, err := a.cfg.Store.ListFlows(types.FlowFilter{Limit: 2000}); err == nil {
			initialFlows = loaded
		}
	}

	loc := i18n.Lang()
	if a.cfg.Lang != "" {
		loc = i18n.SetLang(a.cfg.Lang)
	}
	noColor := a.cfg.NoColor || DetectNoColor()
	state := NewState(StateOptions{
		Width:         w,
		Height:        h,
		Version:       a.cfg.Version,
		Locale:        loc,
		Live:          a.cfg.Live,
		ListenAddr:    a.cfg.ListenAddr,
		DBPath:        a.cfg.DBPath,
		InitialFilter: a.cfg.InitialFilter,
		LightTheme:    a.cfg.LightTheme,
		NoColor:       noColor,
		TrueColor:     DetectTrueColor(),
		Flows:         initialFlows,
	})

	renderer := NewRenderer(a.cfg.Out)
	if err := renderer.Draw(state, time.Now()); err != nil {
		return err
	}

	keyCh := make(chan KeyEvent, 32)
	readDone := make(chan struct{})
	go readKeys(a.cfg.In, keyCh, readDone)
	defer close(readDone)

	resizeCh := term.WatchResize()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	replayCh := make(chan replayDoneMsg, 4)
	toastTick := time.NewTicker(400 * time.Millisecond)
	defer toastTick.Stop()

	dirty := false
	for {
		if dirty {
			if err := renderer.Draw(state, time.Now()); err != nil {
				return err
			}
			dirty = false
		}

		select {
		case <-sigCh:
			return nil

		case <-resizeCh:
			nw, nh := term.Size()
			state.Resize(nw, nh)
			renderer.Invalidate()
			dirty = true

		case f, ok := <-a.cfg.FlowStream:
			if !ok {
				a.cfg.FlowStream = nil
				continue
			}
			state.AddFlow(f)
			// Drain any burst of queued flows before repainting so high traffic stays buttery smooth.
			for i := 0; i < 64; i++ {
				select {
				case more, ok2 := <-a.cfg.FlowStream:
					if !ok2 {
						a.cfg.FlowStream = nil
						break
					}
					state.AddFlow(more)
				default:
					i = 64
				}
			}
			dirty = true

		case msg := <-replayCh:
			state.Replaying = false
			if msg.err != nil {
				state.SetToast(ToastError, state.tr("tui.toast.replay_failed", Truncate(msg.err.Error(), 60)), 4000*time.Millisecond)
			} else if msg.res != nil && msg.res.Replayed != nil {
				rep := msg.res.Replayed
				// Give each replay a unique ID so repeated replays don't clobber each other.
				rep.ID = fmt.Sprintf("%s-r%d", msg.res.Original.ID, time.Now().Unix()%10000)
				if a.cfg.Store != nil {
					_ = a.cfg.Store.SaveFlow(rep)
				}
				state.AddFlow(rep)
				summary := state.tr("tui.toast.replay_ok", msg.res.Original.ID, rep.Status, FormatLatency(rep.LatencyMs))
				if msg.res.Diff != nil && msg.res.Diff.StatusChanged {
					summary = state.tr("tui.toast.replay_diff", msg.res.Original.ID, msg.res.Diff.StatusDiff, FormatLatency(rep.LatencyMs))
				}
				state.SetToast(ToastSuccess, summary, 4000*time.Millisecond)
			}
			dirty = true

		case <-toastTick.C:
			if state.Toast != "" && time.Now().After(state.ToastExpiry) {
				state.Toast = ""
				dirty = true
			}

		case ev, ok := <-keyCh:
			if !ok {
				return nil
			}
			cmd := state.Update(ev)
			switch cmd.Type {
			case CmdQuit:
				return nil
			case CmdRedrawFull:
				renderer.Invalidate()
			case CmdReplay:
				flow := cmd.Flow
				go func() {
					res, err := replay.Replay(flow, replay.Options{
						Timeout:            20 * time.Second,
						FollowRedirects:    true,
						InsecureSkipVerify: true,
					})
					replayCh <- replayDoneMsg{res: res, err: err}
				}()
			case CmdCopySnippet:
				a.handleCopy(state, cmd.Flow, cmd.Lang)
			case CmdExportFlow:
				a.handleExport(state, cmd.Flow, cmd.Lang)
			case CmdDeleteFlow:
				if a.cfg.Store != nil && cmd.Flow != nil {
					if err := a.cfg.Store.DeleteFlow(cmd.Flow.ID); err != nil {
						state.SetToast(ToastError, state.tr("tui.toast.delete_failed", err.Error()), 3500*time.Millisecond)
					} else {
						state.RemoveFlow(cmd.Flow.ID)
						state.SetToast(ToastWarn, state.tr("tui.toast.deleted", cmd.Flow.ID), 2500*time.Millisecond)
					}
				}
			case CmdReloadStore:
				if a.cfg.Store != nil {
					if loaded, err := a.cfg.Store.ListFlows(types.FlowFilter{Limit: 2000}); err != nil {
						state.SetToast(ToastError, state.tr("tui.toast.reload_failed", err.Error()), 3500*time.Millisecond)
					} else {
						state.SetFlows(loaded)
						state.SetToast(ToastSuccess, state.tr("tui.toast.reloaded", len(loaded)), 2500*time.Millisecond)
					}
				}
			}
			dirty = true
		}
	}
}

func (a *App) handleCopy(state *State, flow *types.Flow, lang string) {
	if flow == nil {
		return
	}
	if lang == "" {
		lang = "curl"
	}
	snippet, err := codegen.Generate(flow, lang)
	if err != nil {
		state.SetToast(ToastError, state.tr("tui.toast.gen_failed", err.Error()), 3500*time.Millisecond)
		return
	}
	if err := copyToClipboard(snippet, a.cfg.Out); err != nil {
		state.SetToast(ToastWarn, state.tr("tui.toast.clip_unavail", err.Error()), 3500*time.Millisecond)
		return
	}
	state.SetToast(ToastSuccess, state.tr("tui.toast.copied", strings.ToUpper(lang), flow.ID), 2800*time.Millisecond)
}

func (a *App) handleExport(state *State, flow *types.Flow, lang string) {
	if flow == nil {
		return
	}
	if lang == "" {
		lang = "curl"
	}
	snippet, err := codegen.Generate(flow, lang)
	if err != nil {
		state.SetToast(ToastError, state.tr("tui.toast.export_failed", err.Error()), 3500*time.Millisecond)
		return
	}
	ext := codegenExt(lang)
	safeID := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, flow.ID)
	filename := fmt.Sprintf("cap-%s.%s", safeID, ext)
	if err := os.WriteFile(filename, []byte(snippet), 0o600); err != nil {
		state.SetToast(ToastError, state.tr("tui.toast.write_failed", err.Error()), 3500*time.Millisecond)
		return
	}
	state.SetToast(ToastSuccess, state.tr("tui.toast.exported", strings.ToUpper(lang), filename), 3500*time.Millisecond)
}

func codegenExt(lang string) string {
	switch lang {
	case "curl":
		return "sh"
	case "python":
		return "py"
	case "go":
		return "go"
	case "java":
		return "java"
	case "js":
		return "js"
	default:
		return "txt"
	}
}

func copyToClipboard(text string, tty io.Writer) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd = exec.Command("wl-copy")
		} else if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		}
	}
	if cmd != nil {
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	// Fallback: OSC 52 clipboard escape sequence (supported by Ghostty, iTerm2, Kitty, WezTerm, tmux).
	if tty != nil && len(text) <= 65536 {
		encoded := base64.StdEncoding.EncodeToString([]byte(text))
		_, err := fmt.Fprintf(tty, "\x1b]52;c;%s\x07", encoded)
		return err
	}
	return fmt.Errorf("no clipboard tool found")
}

func readKeys(r io.Reader, out chan<- KeyEvent, done <-chan struct{}) {
	buf := make([]byte, 64)
	for {
		n, err := r.Read(buf)
		if err != nil {
			close(out)
			return
		}
		data := buf[:n]
		for len(data) > 0 {
			ev, consumed := ParseKey(data)
			if consumed <= 0 {
				break
			}
			data = data[consumed:]
			if ev.Kind == KeyNone {
				continue
			}
			select {
			case out <- ev:
			case <-done:
				return
			}
		}
	}
}
