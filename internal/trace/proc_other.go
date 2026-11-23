//go:build !unix

package trace

import (
	"os/exec"
	"time"
)

func configureCancellableCmd(cmd *exec.Cmd) {
	cmd.WaitDelay = 500 * time.Millisecond
}
