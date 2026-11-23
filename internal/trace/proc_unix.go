//go:build unix

package trace

import (
	"os/exec"
	"syscall"
	"time"
)

// configureCancellableCmd places cmd in its own process group so context
// cancellation terminates the entire process tree (e.g. the `jadx` / `sh`
// wrapper script AND its `java` JVM child) rather than leaving orphaned
// grandchildren holding stdout/stderr pipes open.
func configureCancellableCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative PID signals every process in the child's process group.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 500 * time.Millisecond
}
