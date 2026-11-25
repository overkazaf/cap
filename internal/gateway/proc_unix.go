//go:build unix

package gateway

import (
	"os/exec"
	"syscall"
	"time"
)

func configureProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return killProcGroup(cmd)
	}
	cmd.WaitDelay = 500 * time.Millisecond
}

func killProcGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}

// signalProcGroupOnly sends SIGKILL strictly to process group -pgid (never
// falling back to a bare positive PID) to reap stray grandchildren safely
// without risking PID reuse hazards.
func signalProcGroupOnly(pgid int) {
	if pgid <= 0 {
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}
