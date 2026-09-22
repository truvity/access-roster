package main

import (
	"os"
	"testing"
	"time"

	"github.com/truvity/access-roster/tokens"
)

func cacheFile(t *testing.T) string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const audience = "aws:111122223333:power"
	arn, err := roleFromAudience(audience)
	if err != nil {
		t.Fatalf("roleFromAudience: %v", err)
	}
	path, err := awsCachePath(audience, arn)
	if err != nil {
		t.Fatalf("awsCachePath: %v", err)
	}

	return path
}

func TestAWSCacheRoundTrip(t *testing.T) {
	path := cacheFile(t)
	want := tokens.Credentials{
		AccessKeyID:     "ASIAEXAMPLE",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Expires:         time.Now().Add(time.Hour),
	}
	if err := writeAWSCache(path, want); err != nil {
		t.Fatalf("writeAWSCache: %v", err)
	}
	got, ok := readAWSCache(path)
	if !ok {
		t.Fatal("a credential written a minute ago read back as a miss")
	}
	if got.AccessKeyID != want.AccessKeyID || got.SessionToken != want.SessionToken {
		t.Fatalf("read back %+v, want %+v", got, want)
	}
}

// The file holds a credential: nothing else on the machine may read it.
func TestAWSCacheIsPrivate(t *testing.T) {
	path := cacheFile(t)
	if err := writeAWSCache(path, tokens.Credentials{
		AccessKeyID: "A", SecretAccessKey: "B", Expires: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("writeAWSCache: %v", err)
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
// always mint afresh, and serving a stale or half-written credential is
// the only outcome worth preventing.
func TestAWSCacheMisses(t *testing.T) {
	near := time.Now().Add(awsCacheMargin / 2)
	for _, tc := range []struct {
		name  string
		write func(path string)
	}{
		{"absent", func(string) {}},
		{"garbage", func(p string) { _ = os.WriteFile(p, []byte("{not json"), 0o600) }},
		{"no expiry", func(p string) {
			_ = writeAWSCache(p, tokens.Credentials{AccessKeyID: "A", SecretAccessKey: "B"})
		}},
		{"already expired", func(p string) {
			_ = writeAWSCache(p, tokens.Credentials{AccessKeyID: "A", SecretAccessKey: "B", Expires: time.Now().Add(-time.Minute)})
		}},
		{"inside the refresh margin", func(p string) {
			_ = writeAWSCache(p, tokens.Credentials{AccessKeyID: "A", SecretAccessKey: "B", Expires: near})
		}},
		{"no secret", func(p string) {
			_ = writeAWSCache(p, tokens.Credentials{AccessKeyID: "A", Expires: time.Now().Add(time.Hour)})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := cacheFile(t)
			tc.write(path)
			if _, ok := readAWSCache(path); ok {
				t.Fatal("read back as usable; want a miss")
			}
		})
	}
}

// The key must separate audiences and roles, or one profile serves another
// profile's credential.
func TestAWSCachePathSeparatesKeys(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// The ARNs come from roleFromAudience rather than being spelled out:
	// it is the function that produces them in earnest, and an account id
	// written into a test is the kind of particular the leak canary is
	// right to refuse.
	key := func(t *testing.T, audience string) string {
		t.Helper()
		arn, err := roleFromAudience(audience)
		if err != nil {
			t.Fatalf("roleFromAudience(%q): %v", audience, err)
		}
		path, err := awsCachePath(audience, arn)
		if err != nil {
			t.Fatalf("awsCachePath: %v", err)
		}

		return path
	}

	a := key(t, "aws:1:power")
	for _, other := range []string{"aws:1:admin", "aws:2:power", "aws:2:admin"} {
		if a == key(t, other) {
			t.Fatalf("%q collides with aws:1:power", other)
		}
	}

	// And the role half of the key must matter on its own, or a --role
	// override silently reuses another role's credential.
	arn, err := roleFromAudience("aws:1:admin")
	if err != nil {
		t.Fatalf("roleFromAudience: %v", err)
	}
	overridden, err := awsCachePath("aws:1:power", arn)
	if err != nil {
		t.Fatalf("awsCachePath: %v", err)
	}
	if overridden == a {
		t.Fatal("same audience with a different --role shares a cache entry")
	}
}
