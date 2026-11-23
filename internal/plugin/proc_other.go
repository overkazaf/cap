//go:build !unix

package plugin

import (
	"os/exec"
	"time"
)

func configureScriptCmd(cmd *exec.Cmd) {
	cmd.WaitDelay = 500 * time.Millisecond
}
