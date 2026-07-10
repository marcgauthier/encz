//go:build !linux

package fault

import "os/exec"

func setDeathSig(cmd *exec.Cmd) {}
