//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// Windows has no flock. LockFileEx over the first byte is the same
// bargain: exclusive, held by the handle, and released by the kernel when
// the process ends however it ends. Without LOCKFILE_FAIL_IMMEDIATELY it
// waits rather than refusing, which is what the caller wants -- the
// waiter is here to find the answer the holder is about to write.
func lockFile(lock *os.File) error {
	return windows.LockFileEx(
		windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}

func unlockFile(lock *os.File) error {
	return windows.UnlockFileEx(windows.Handle(lock.Fd()), 0, 1, 0, new(windows.Overlapped))
}
