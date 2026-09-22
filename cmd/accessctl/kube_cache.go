package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// The kubectl token cache exists for the reason the AWS one does: an exec
// plugin is not called once.
//
// kubectl runs the plugin in every kubectl process that has no cached
// credential of its own, so each one asks the issuer. A refresh SPENDS the
// refresh token (internal/issuer/storage.go): the first process to finish
// rotates it, and every other one is left holding a token the issuer
// refuses with "the refresh token is not live" -- which this command
// reports as "not signed in". The session ends for EVERY audience at once,
// not only for the caller that lost the race, and the operator is signed
// out in the middle of a command they did not think was a sign-in.
//
// Two at once is ordinary rather than exotic: a script looping over
// contexts, a cluster watch beside a terminal, a console beside kubectl, a
// provider's kubernetes client beside anything else. Measured 2026-09-22:
// one loop polling three clusters every thirty seconds, beside a
// foreground kubectl on a fourth, ended the session within the hour.
//
// The cache is advisory in every direction -- absent, truncated,
// unreadable, expired, unwritable all mean mint afresh, none fail -- and
// the lock beside it (cache_lock.go) is what turns a cold start by eight
// callers into one refresh rather than eight.

// kubeCacheMargin is how long before expiry a cached token stops being
// offered. client-go re-runs the plugin once `expirationTimestamp` has
// passed and not before, so this has to cover the API call the credential
// is about to make and no more: a wider margin would throw away most of
// the life of a token from a client with a short lifetime cap.
const kubeCacheMargin = time.Minute

// kubeCachePath names the file for one issuer, client and audience.
//
// All three decide what the token is -- the same audience at another
// issuer, or presented by another client, is a different credential -- and
// a key that left one out would hand back somebody else's token. Hashed
// because an issuer is a URL and an audience is `k8s:<cluster>`, neither
// of which is a filename.
func kubeCachePath(issuer, clientID, audience string) (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(issuer + "\x00" + clientID + "\x00" + audience))

	return filepath.Join(dir, "kube", hex.EncodeToString(sum[:16])+".json"), nil
}

// readKubeCache returns a cached token that is still worth using.
//
// Every failure is a miss rather than an error: a half-written file, a
// token from an older version of this command, one whose audience has
// since been revoked. The caller can always mint a new one, so there is
// nothing a hard failure here would buy.
func readKubeCache(path string) (tokens.Token, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return tokens.Token{}, false
	}
	var token tokens.Token
	if err = json.Unmarshal(body, &token); err != nil {
		return tokens.Token{}, false
	}
	if token.AccessToken == "" {
		return tokens.Token{}, false
	}
	// A token with no expiry is not cacheable: we cannot tell when it stops
	// being true, and guessing is how a stale one gets served. kubectl is
	// handed the same expiry, so the two agree about when it is done.
	if token.Expires.IsZero() || time.Until(token.Expires) <= kubeCacheMargin {
		return tokens.Token{}, false
	}

	return token, true
}

// writeKubeCache stores a token, atomically and readable only by this
// account.
//
// Written to a temporary file and renamed, so a reader never sees half a
// token -- the whole point is that several processes are looking at this
// file at once.
func writeKubeCache(path string, token tokens.Token) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	body, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("render the token: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kube-*.tmp")
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
