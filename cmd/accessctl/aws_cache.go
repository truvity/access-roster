package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// The AWS credential cache exists because `credential_process` is not
// called once.
//
// A provider-based tool resolves credentials in EVERY provider process it
// starts, each with its own in-memory cache, so each one runs this command.
// Pulumi's `aws` stack for one estate declares four providers; Terraform
// and the AWS CLI's own sub-processes behave the same way. Without a shared
// cache that is four sign-in refreshes racing each other.
//
// THAT RACE DESTROYS THE SESSION, which is why this is a correctness fix
// rather than a speed one. A refresh SPENDS the old token (see
// internal/issuer/storage.go): the first process to finish rotates it, and
// every other process is then holding a token the issuer will refuse with
// "the refresh token is not live". The operator is signed out, and the AWS
// SDK -- having got nothing from us -- falls through to the rest of its
// chain, so the failure surfaces as somebody else's credentials being
// wrong. Measured 2026-09-22 on a four-provider stack: every run, and the
// reported error named an unrelated SSO profile.
//
// The cache is keyed by what determines the credential and nothing else,
// written 0600 beside the session, and treated as advisory throughout: any
// error reading it means mint afresh, never fail.

// awsCacheMargin is how long before expiry a cached credential stops being
// offered. The AWS SDK refreshes its own copy around five minutes out, so
// anything shorter hands back a credential the caller is about to discard,
// and anything much longer wastes the tail of a perfectly good one.
const awsCacheMargin = 5 * time.Minute

// awsCachePath names the file for one audience-and-role pair.
//
// Hashed rather than spelled out: an audience is `aws:<account>:<role>`
// and an ARN has slashes, so neither is a filename, and the account id is
// not something to scatter across a filesystem in cleartext.
func awsCachePath(audience, roleARN string) (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(audience + "\x00" + roleARN))

	return filepath.Join(dir, "aws", hex.EncodeToString(sum[:16])+".json"), nil
}

// readAWSCache returns a cached credential that is still worth using.
//
// Every failure is a miss rather than an error: a truncated file, a
// half-written one, a credential from an older version of this command.
// The caller can always mint a new one, so there is nothing a hard failure
// here would buy.
func readAWSCache(path string) (tokens.Credentials, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return tokens.Credentials{}, false
	}
	var creds tokens.Credentials
	if err = json.Unmarshal(body, &creds); err != nil {
		return tokens.Credentials{}, false
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return tokens.Credentials{}, false
	}
	// A credential with no expiry is not cacheable: we cannot tell when it
	// stops being true, and guessing is how a stale one gets served.
	if creds.Expires.IsZero() || time.Until(creds.Expires) <= awsCacheMargin {
		return tokens.Credentials{}, false
	}

	return creds, true
}

// writeAWSCache stores a credential, atomically and readable only by this
// account.
//
// Written to a temporary file and renamed, so a reader never sees half a
// credential -- the whole point is that several processes are looking at
// this file at once.
func writeAWSCache(path string, creds tokens.Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	body, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("render the credential: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".aws-*.tmp")
	if err != nil {
		return fmt.Errorf("create a temporary file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("restrict %s: %w", tmp.Name(), err)
	}
	if _, err = tmp.Write(body); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}

	return os.Rename(tmp.Name(), path)
}

// withAWSCacheLock runs fn while holding an exclusive lock for this cache
// entry.
//
// A cache alone does not fix the race, and this is the part that does. On
// a cold start every provider process misses the cache at the same instant
// and they all refresh together -- which is exactly the situation that
// spends the refresh token four times. The lock makes one of them do the
// work while the others wait, and they then find the answer already
// written.
//
// The lock is its own file, not the cache file, so the atomic rename that
// replaces the cache cannot pull the lock out from under a waiter.
func withAWSCacheLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		// Not being able to lock is not a reason to refuse to work: fall
		// back to doing it unsynchronised, which is what this command did
		// before the cache existed.
		return fn()
	}
	defer func() { _ = lock.Close() }()

	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fn()
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	return fn()
}
