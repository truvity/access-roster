//go:build !windows

package main

import (
	"os"
	"syscall"
)

// An advisory whole-file lock, released when this process exits however
// it exits -- including a kill, which a lock file holding a flag would
// not survive.
func lockFile(lock *os.File) error {
	return syscall.Flock(int(lock.Fd()), syscall.LOCK_EX)
}

func unlockFile(lock *os.File) error {
	return syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
}
