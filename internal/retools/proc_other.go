//go:build !unix

package retools

import (
	"os/exec"
	"time"
)

func configureProcGroup(cmd *exec.Cmd) {
	cmd.WaitDelay = 800 * time.Millisecond
}

func killProcGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
