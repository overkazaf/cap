//go:build !unix

package gateway

import (
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

func signalProcGroupOnly(pgid int) {
	// Non-Unix platforms do not support negative PGID signaling.
	_ = pgid
}
