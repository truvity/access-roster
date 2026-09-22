package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// withCacheLock runs fn while holding an exclusive lock for one cache
// entry.
//
// A cache alone does not fix the race the caches exist for, and this is
// the part that does. On a cold start every caller misses at the same
// instant and they all refresh together -- which is exactly the situation
// that spends the rotating refresh token once per caller. The lock makes
// one of them do the work while the others wait, and they then find the
// answer already written.
//
// The lock is its own file, not the cache file, so the atomic rename that
// replaces the cache cannot pull the lock out from under a waiter.
//
// Shared by the AWS credential cache (aws_cache.go) and the kubectl token
// cache (kube_cache.go): both are one file per credential, and the way
// they are raced is the same.
func withCacheLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		// Not being able to lock is not a reason to refuse to work: fall
		// back to doing it unsynchronised, which is what these commands
		// did before the caches existed.
		return fn()
	}
	defer func() { _ = lock.Close() }()

	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fn()
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	return fn()
}
