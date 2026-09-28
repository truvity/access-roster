package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// The R2 broker token cache is kube_cache.go's own shape, applied to a
// different audience.
//
// `accessctl r2` hands its token to a CHILD process (r2broker) rather
// than consuming it itself, and on most platforms that hand-off replaces
// this process entirely (bao_exec_unix.go's syscall.Exec) -- but nothing
// re-runs mid-command the way kubectl re-runs its exec plugin, so
// mint-then-cache buys exactly what kube-token's cache already does:
// several concurrent callers in one job (a build tool with more than one
// uploader, each starting its own AWS-SDK credential_process) share one
// exchange rather than each spending their own.
//
// No --forget. Unlike `accessctl bao`'s OpenBAO login -- a Vault token
// this tool minted itself and must explicitly revoke -- what is cached
// here is an ordinary exchanged access token, the same shape kube-token
// and aws already cache with no revoke path of their own: it expires,
// and that is the only "forgetting" it needs.

// r2CacheMargin is how long before expiry a cached token stops being
// offered -- the same margin the kubectl cache uses (kube_cache.go's
// kubeCacheMargin): this only has to cover one round trip, to r2broker's
// own `/v1/credentials` call or its in-process mint under `--config`, not
// a re-check loop this command does not have.
const r2CacheMargin = kubeCacheMargin

// r2CachePath names the cache file for one issuer, client and audience --
// the same three kube_cache.go's kubeCachePath keys on, because an
// r2-broker token is the same kind of thing a kube-token credential is: a
// bearer token for one audience, presented by one client, from one
// issuer. Hashed, because an issuer is a URL and an audience is a client
// id, neither of which is a filename.
func r2CachePath(issuer, clientID, audience string) (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(issuer + "\x00" + clientID + "\x00" + audience))

	return filepath.Join(dir, "r2", hex.EncodeToString(sum[:16])+".json"), nil
}

// readR2Cache returns a cached token that is still worth using.
//
// Every failure is a miss rather than an error: a half-written file, a
// token from an older version of this command, one whose audience has
// since been revoked. The caller can always mint a new one.
func readR2Cache(path string) (tokens.Token, bool) {
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
	// A token with no expiry accessctl could see is not cacheable: we
	// cannot tell when it stops being true, and guessing is how a stale
	// one gets served.
	if token.Expires.IsZero() || time.Until(token.Expires) <= r2CacheMargin {
		return tokens.Token{}, false
	}

	return token, true
}

// writeR2Cache stores a token, atomically and readable only by this
// account.
func writeR2Cache(path string, token tokens.Token) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	body, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("render the token: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".r2-*.tmp")
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

// r2Token returns a usable token for request.audience, minting one only
// when nothing cached is good enough -- the same "mint, cache, lock"
// shape kube_cache.go's kubeToken and bao.go's openBAOLogin both use.
func r2Token(ctx context.Context, cfg Config, request r2Request) (tokens.Token, error) {
	path, cacheErr := r2CachePath(cfg.Issuer, cfg.ClientID, request.audience)
	if cacheErr == nil {
		if cached, ok := readR2Cache(path); ok {
			return cached, nil
		}
	}

	mint := func() (tokens.Token, error) {
		// Re-read under the lock: a caller that waited here while another
		// exchanged finds the answer already written, which is the whole
		// point -- one exchange, not one per caller.
		if cacheErr == nil {
			if cached, ok := readR2Cache(path); ok {
				return cached, nil
			}
		}

		held, err := proofFor(ctx, cfg, request.audience)
		if err != nil {
			return tokens.Token{}, err
		}
		issued, err := exchangeAs(ctx, cfg.Issuer, held.Client, held.Subject, held.Type, request.audience)
		if err != nil {
			return tokens.Token{}, err
		}
		// A cache that cannot be written is not a reason to withhold a
		// token the caller already has.
		if cacheErr == nil {
			_ = writeR2Cache(path, issued)
		}
		return issued, nil
	}

	if cacheErr != nil {
		return mint()
	}

	var result tokens.Token
	err := withCacheLock(path, func() error {
		var mintErr error
		result, mintErr = mint()
		return mintErr
	})
	return result, err
}
