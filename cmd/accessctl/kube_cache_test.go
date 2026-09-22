package main

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/tokens"
)

const (
	testIssuer   = "https://issuer.example"
	testClientID = "laptop"
	testAudience = "k8s:example"
)

func kubeCacheFile(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path, err := kubeCachePath(testIssuer, testClientID, testAudience)
	if err != nil {
		t.Fatalf("kubeCachePath: %v", err)
	}

	return path
}

func TestKubeCacheRoundTrip(t *testing.T) {
	path := kubeCacheFile(t)
	want := tokens.Token{AccessToken: "header.payload.signature", Expires: time.Now().Add(time.Hour)}
	if err := writeKubeCache(path, want); err != nil {
		t.Fatalf("writeKubeCache: %v", err)
	}
	got, ok := readKubeCache(path)
	if !ok {
		t.Fatal("a token written a moment ago read back as a miss")
	}
	if got.AccessToken != want.AccessToken {
		t.Fatalf("read back %q, want %q", got.AccessToken, want.AccessToken)
	}
	// The expiry is what kubectl is handed as expirationTimestamp: if it
	// did not survive the round trip, kubectl would run this plugin on
	// every API call and the cache would buy nothing.
	if !got.Expires.Equal(want.Expires.Truncate(time.Second)) && got.Expires.Sub(want.Expires).Abs() > time.Second {
		t.Fatalf("expiry %v, want %v", got.Expires, want.Expires)
	}
}

// The file holds a bearer token for a cluster: nothing else on the
// machine may read it.
func TestKubeCacheIsPrivate(t *testing.T) {
	path := kubeCacheFile(t)
	if err := writeKubeCache(path, tokens.Token{
		AccessToken: "t", Expires: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("writeKubeCache: %v", err)
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
func TestKubeCacheMisses(t *testing.T) {
	near := time.Now().Add(kubeCacheMargin / 2)
	for _, tc := range []struct {
		name  string
		write func(path string)
	}{
		{"absent", func(string) {}},
		{"garbage", func(p string) { _ = os.WriteFile(p, []byte("{not json"), 0o600) }},
		{"no token", func(p string) {
			_ = writeKubeCache(p, tokens.Token{Expires: time.Now().Add(time.Hour)})
		}},
		{"no expiry", func(p string) {
			_ = writeKubeCache(p, tokens.Token{AccessToken: "t"})
		}},
		{"already expired", func(p string) {
			_ = writeKubeCache(p, tokens.Token{AccessToken: "t", Expires: time.Now().Add(-time.Minute)})
		}},
		{"inside the margin", func(p string) {
			_ = writeKubeCache(p, tokens.Token{AccessToken: "t", Expires: near})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := kubeCacheFile(t)
			tc.write(path)
			if _, ok := readKubeCache(path); ok {
				t.Fatal("read back as usable; want a miss")
			}
		})
	}
}

// The key must separate every input that decides what the token IS, or
// one context is served another context's credential -- and a token for
// the wrong cluster is refused by the API server with a message about
// the token, naming nothing that would lead here.
func TestKubeCachePathSeparatesKeys(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	key := func(t *testing.T, issuer, clientID, audience string) string {
		t.Helper()
		path, err := kubeCachePath(issuer, clientID, audience)
		if err != nil {
			t.Fatalf("kubeCachePath: %v", err)
		}

		return path
	}

	base := key(t, testIssuer, testClientID, testAudience)
	for _, tc := range []struct {
		name string
		path string
	}{
		{"another cluster", key(t, testIssuer, testClientID, testAudience+"-other")},
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

// THE POINT OF THE CACHE, in the shape the kube path is raced: kubectl
// starts one plugin per kubectl process, so a loop over contexts beside a
// foreground command is several at once. Each extra mint is a refresh
// that spends the rotating token again and signs the operator out of
// every audience.
func TestKubeCacheLockMintsOnce(t *testing.T) {
	path := kubeCacheFile(t)

	var mu sync.Mutex
	mints := 0

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = withCacheLock(path, func() error {
				if _, ok := readKubeCache(path); ok {
					return nil // another caller already did the work
				}
				mu.Lock()
				mints++
				mu.Unlock()

				return writeKubeCache(path, tokens.Token{
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
