//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

// execBaoProcess is the fallback for the one platform with no process
// image to exec into: a child process, stdio inherited, and the exit
// code propagated by calling os.Exit directly -- the same end state
// bao_exec_unix.go's syscall.Exec reaches by never returning, reached
// here by leaving nothing else for accessctl's own exit-code handling in
// main() to add on top of bao's own.
func execBaoProcess(binary string, args []string, env []string) error {
	cmd := exec.Command(binary, args...) //nolint:gosec // the caller's own bao arguments, unchanged
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env

	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}
	if err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
