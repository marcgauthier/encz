//go:build linux

package fault

import (
	"os/exec"
	"syscall"
)

func setDeathSig(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
}
