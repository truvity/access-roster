package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// THE POINT OF THE LOCK. Concurrent callers must produce exactly one mint:
// each extra one is a refresh that spends the rotating token again and
// signs the operator out.
func TestCacheLockMintsOnce(t *testing.T) {
	path := cacheFile(t)

	var mu sync.Mutex
	mints := 0

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = withCacheLock(path, func() error {
				if _, ok := readAWSCache(path); ok {
					return nil // another caller already did the work
				}
				mu.Lock()
				mints++
				mu.Unlock()

				return writeAWSCache(path, tokens.Credentials{
					AccessKeyID: "A", SecretAccessKey: "B", Expires: time.Now().Add(time.Hour),
				})
			})
		}()
	}
	wg.Wait()

	if mints != 1 {
		t.Fatalf("minted %d times across 8 concurrent callers, want 1", mints)
	}
}

// The lock lives beside the cache rather than on it, so the atomic rename
// that replaces the cache cannot drop a waiter's lock.
func TestCacheLockIsASeparateFile(t *testing.T) {
	path := cacheFile(t)
	if err := withCacheLock(path, func() error { return nil }); err != nil {
		t.Fatalf("withAWSCacheLock: %v", err)
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("expected a lock file beside %s: %v", filepath.Base(path), err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("locking created the cache file itself; the rename would then race a waiter")
	}
}
