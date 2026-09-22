package main

import (
	"fmt"
	"os"
	"path/filepath"
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

	if err = lockFile(lock); err != nil {
		return fn()
	}
	defer func() { _ = unlockFile(lock) }()

	return fn()
}

// lockFile and unlockFile are the one part of this that is not portable,
// so they live in cache_lock_unix.go and cache_lock_windows.go. accessctl
// is built for Windows deliberately -- the credential helpers are what
// kubectl and the AWS SDKs run, and both exist there -- and `go build`
// for the host platform never says so: the first thing to notice was a
// release, which failed at `syscall.Flock` for windows/arm64 with the
// change already on master.
