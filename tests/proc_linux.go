//go:build linux

package tests

import (
	"os/exec"
	"syscall"
)

func setDeathSig(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
}
