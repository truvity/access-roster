//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// Windows has no flock. LockFileEx is the equivalent, and without
// LOCKFILE_FAIL_IMMEDIATELY it blocks until the lock is available, which
// is the behaviour the Unix side gets from LOCK_EX.
//
// The range locked is the whole file: the offsets are zero and the length
// is the largest a 64-bit range can express, so a caller cannot slip in by
// locking a different part of a file that is empty anyway.
const (
	lockRangeLow  = ^uint32(0)
	lockRangeHigh = ^uint32(0)
)

// lockExclusive takes a blocking exclusive lock on the open file. It
// reports false when the lock could not be taken, and the caller then
// proceeds unsynchronised rather than failing.
func lockExclusive(f *os.File) (unlock func(), ok bool) {
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(
		h,
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		lockRangeLow,
		lockRangeHigh,
		new(windows.Overlapped),
	); err != nil {
		return nil, false
	}

	return func() {
		_ = windows.UnlockFileEx(h, 0, lockRangeLow, lockRangeHigh, new(windows.Overlapped))
	}, true
}
