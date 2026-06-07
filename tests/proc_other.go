//go:build !linux

package tests

import "os/exec"

func setDeathSig(cmd *exec.Cmd) {}
