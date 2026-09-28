package main

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// testIssuer, testClientID and testAudience are declared once, in
// kube_cache_test.go -- an r2-broker token cache is keyed exactly the
// same way a kube-token one is, so this file reuses them rather than
// inventing a second set of the same three names.

func r2CacheFile(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path, err := r2CachePath(testIssuer, testClientID, testAudience)
	if err != nil {
		t.Fatalf("r2CachePath: %v", err)
	}

	return path
}

func TestR2CacheRoundTrip(t *testing.T) {
	path := r2CacheFile(t)
	want := tokens.Token{AccessToken: "header.payload.signature", Expires: time.Now().Add(time.Hour)}
	if err := writeR2Cache(path, want); err != nil {
		t.Fatalf("writeR2Cache: %v", err)
	}
	got, ok := readR2Cache(path)
	if !ok {
		t.Fatal("a token written a moment ago read back as a miss")
	}
	if got.AccessToken != want.AccessToken {
		t.Fatalf("read back %q, want %q", got.AccessToken, want.AccessToken)
	}
	if !got.Expires.Equal(want.Expires.Truncate(time.Second)) && got.Expires.Sub(want.Expires).Abs() > time.Second {
		t.Fatalf("expiry %v, want %v", got.Expires, want.Expires)
	}
}

// The file holds a bearer token for an R2 broker: nothing else on the
// machine may read it.
func TestR2CacheIsPrivate(t *testing.T) {
	path := r2CacheFile(t)
	if err := writeR2Cache(path, tokens.Token{
		AccessToken: "t", Expires: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("writeR2Cache: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode %o, want 600", perm)
	}
}

// Every one of these must be a MISS rather than an error: the caller can
// always mint afresh, and serving a stale or half-written token is the
// only outcome worth preventing.
func TestR2CacheMisses(t *testing.T) {
	near := time.Now().Add(r2CacheMargin / 2)
	for _, tc := range []struct {
		name  string
		write func(path string)
	}{
		{"absent", func(string) {}},
		{"garbage", func(p string) { _ = os.WriteFile(p, []byte("{not json"), 0o600) }},
		{"no token", func(p string) {
			_ = writeR2Cache(p, tokens.Token{Expires: time.Now().Add(time.Hour)})
		}},
		{"no expiry", func(p string) {
			_ = writeR2Cache(p, tokens.Token{AccessToken: "t"})
		}},
		{"already expired", func(p string) {
			_ = writeR2Cache(p, tokens.Token{AccessToken: "t", Expires: time.Now().Add(-time.Minute)})
		}},
		{"inside the margin", func(p string) {
			_ = writeR2Cache(p, tokens.Token{AccessToken: "t", Expires: near})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := r2CacheFile(t)
			tc.write(path)
			if _, ok := readR2Cache(path); ok {
				t.Fatal("read back as usable; want a miss")
			}
		})
	}
}

// The key must separate every input that decides what the token IS, or
// one audience is served another audience's credential.
func TestR2CachePathSeparatesKeys(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	key := func(t *testing.T, issuer, clientID, audience string) string {
		t.Helper()
		path, err := r2CachePath(issuer, clientID, audience)
		if err != nil {
			t.Fatalf("r2CachePath: %v", err)
		}

		return path
	}

	base := key(t, testIssuer, testClientID, testAudience)
	for _, tc := range []struct {
		name string
		path string
	}{
		{"another audience", key(t, testIssuer, testClientID, testAudience+"-other")},
		{"another client", key(t, testIssuer, testClientID+"-other", testAudience)},
		{"another issuer", key(t, testIssuer+".other", testClientID, testAudience)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.path == base {
				t.Fatal("shares a cache entry with the base credential")
			}
		})
	}
	if again := key(t, testIssuer, testClientID, testAudience); again != base {
		t.Fatal("the same inputs produced two different paths; nothing would ever hit")
	}
}

// THE POINT OF THE CACHE: several concurrent callers in one job (a build
// tool with more than one uploader, each starting its own
// AWS-SDK credential_process) must share one exchange, not spend one
// each.
func TestR2CacheLockMintsOnce(t *testing.T) {
	path := r2CacheFile(t)

	var mu sync.Mutex
	mints := 0

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = withCacheLock(path, func() error {
				if _, ok := readR2Cache(path); ok {
					return nil // another caller already did the work
				}
				mu.Lock()
				mints++
				mu.Unlock()

				return writeR2Cache(path, tokens.Token{
					AccessToken: "t", Expires: time.Now().Add(time.Hour),
				})
			})
		}()
	}
	wg.Wait()

	if mints != 1 {
		t.Fatalf("minted %d times across 8 concurrent callers, want 1", mints)
	}
}
