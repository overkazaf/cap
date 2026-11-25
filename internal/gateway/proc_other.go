//go:build !unix

package gateway

import (
	"os"
	"os/exec"
	"time"
)

func configureProcGroup(cmd *exec.Cmd) {
	cmd.WaitDelay = 500 * time.Millisecond
}

func killProcGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func killProcGroupPID(pid int) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
