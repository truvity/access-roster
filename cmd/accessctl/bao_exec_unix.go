//go:build !windows

package main

import "syscall"

// execChildProcess replaces this process's image with the binary it was
// asked to run -- `bao`, or the command `accessctl pg`/`psql` was given
// -- via `syscall.Exec`, not a child process, so that an interactive
// session (`bao ssh -mode=ca`, `bao login`, `psql` itself) gets the
// terminal exactly as if it had been run directly: ctrl-C, ctrl-Z,
// window resizes, everything that a wrapper process sitting in between
// would otherwise have to forward by hand. On success this never
// returns; the exit code the caller sees is the replaced process's own,
// because there is no accessctl process left to report one.
//
// runChild (bao.go) is a variable rather than a direct call to this,
// purely so a test can substitute something that does not replace the
// test binary's own process image -- there is no other seam here, and
// production always runs this one.
func execChildProcess(binary string, args []string, env []string) error {
	argv := append([]string{binary}, args...)

	return syscall.Exec(binary, argv, env) //nolint:gosec // the caller's own arguments, unchanged
}
