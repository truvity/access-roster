package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The OpenBAO login cache exists for the reason `accessctl bao` exists
// at all: unlike `accessctl credential`, which logs in once and revokes
// on the way out because it only ever makes one call, `accessctl bao`
// hands its login to an arbitrary `bao` invocation and is meant to be run
// often -- once per shell command, sometimes more than once a minute in a
// script. Logging in again every time would spend a network round trip
// and a line in OpenBAO's audit log for no reason, and would make a
// `bao ssh -mode=ca` session wait on an exchange before doing the one
// thing it was asked to do.
//
// The cache is advisory in every direction, exactly like the kubectl and
// AWS ones beside it (kube_cache.go, aws_cache.go): absent, truncated,
// unreadable, expired or unwritable all mean log in afresh, none fail.

// cachedBaoToken is what this command keeps between runs.
//
// This is NOT ~/.vault-token and NOT bao's own token helper file: ADR
// 0013 is explicit that this cache is accessctl's own, so that a login
// minted for one exchanged identity is never picked up by bao's own
// tooling running as somebody else, and so that `accessctl bao --forget`
// has exactly one place to clear.
type cachedBaoToken struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires,omitempty"`
}

// baoTokenMargin is how long before expiry a cached OpenBAO token stops
// being offered.
//
// A short margin, on purpose. The kubectl and AWS caches beside this one
// use a margin sized to when THEIR caller re-checks (a minute, five
// minutes) -- but nothing here re-checks a token mid-command, and
// OpenBAO's own side of this contract keeps the jwt-roster role's TTL
// deliberately short in the first place ("the login exists to make one
// call", docs/connect/openbao.md#manager-side). What this margin has to
// cover is the moment between this check and the child `bao` process
// making ITS first call -- one round trip -- so it is the same margin
// `refresh` gives the session's own access token before an exchange
// (commands.go's sessionTokenMargin), not the longer ones sized for a
// re-check loop this command does not have.
const baoTokenMargin = sessionTokenMargin

// baoCachePath names the cache file for one OpenBAO address, namespace,
// mount, login role and subject.
//
// The namespace is part of the key and not an afterthought: a token
// minted by logging in to one OpenBAO namespace is only valid in that
// namespace and its children, never a sibling (see
// docs/decisions/0013-openbao-access-through-the-bao-cli.md) -- so a
// cache keyed on the address and the subject alone would hand a
// `dev`-namespace token to a caller about to run `bao -namespace=stage
// ...`, and OpenBAO would then refuse it, which reads as an outage
// rather than as a cache bug. The mount and the login role are in the
// key for the same reason, one level down: an installation that logs in
// through more than one JWT mount (or role) at the same address and
// namespace mints a DIFFERENT token from each, and `accessctl bao` and
// `accessctl pg`/`psql` sharing this cache (bao.go's openBAOLogin) must
// not hand one caller's mount's token to the other's. Hashed, like the
// kubectl and AWS caches, because none of these pieces is a filename.
func baoCachePath(address, namespace, mount, loginRole, subject string) (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(address + "\x00" + namespace + "\x00" + mount + "\x00" + loginRole + "\x00" + subject))

	return filepath.Join(dir, "bao", hex.EncodeToString(sum[:16])+".json"), nil
}

// readBaoCache returns a cached token that is still worth presenting.
func readBaoCache(path string) (cachedBaoToken, bool) {
	cached, ok := readBaoCacheFile(path)
	if !ok {
		return cachedBaoToken{}, false
	}
	// A token with no expiry accessctl could see is not cacheable: we
	// cannot tell when it stops being true, and guessing is how a stale
	// one gets served.
	if cached.Expires.IsZero() || time.Until(cached.Expires) <= baoTokenMargin {
		return cachedBaoToken{}, false
	}
	return cached, true
}

// readBaoCacheFile is the raw read, with no expiry check -- what
// `--forget` uses, since revoking a token that is about to expire anyway
// is still the right thing to attempt.
func readBaoCacheFile(path string) (cachedBaoToken, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return cachedBaoToken{}, false
	}
	var cached cachedBaoToken
	if err = json.Unmarshal(body, &cached); err != nil || cached.Token == "" {
		return cachedBaoToken{}, false
	}
	return cached, true
}

// writeBaoCache stores a token, atomically and readable only by this
// account.
func writeBaoCache(path string, cached cachedBaoToken) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	body, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("render the cached token: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bao-*.tmp")
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

// removeBaoCache deletes the cache entry. Already gone is success: the
// caller asked for "no cached token" and that is what is now true.
func removeBaoCache(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
