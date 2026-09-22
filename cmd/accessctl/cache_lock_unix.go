//go:build !windows

package main

import (
	"os"
	"syscall"
)

// lockExclusive takes a blocking exclusive flock on the open file. It
// reports false when the lock could not be taken, and the caller then
// proceeds unsynchronised rather than failing.
func lockExclusive(f *os.File) (unlock func(), ok bool) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, false
	}

	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, true
}
