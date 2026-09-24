package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// refreshServer is an issuer that counts how often the refresh token was
// spent, which is the number every test here is about.
func refreshServer(t *testing.T, expiresIn int64) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var spent atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("the issuer was asked for a %q grant, want refresh_token", r.Form.Get("grant_type"))
		}
		n := spent.Add(1)
		answer := map[string]any{
			"access_token": "minted",
			// Rotated, as the issuer rotates it: the old one is dead from
			// here on, which is the whole reason these tests exist.
			"refresh_token": "refresh-" + strings.Repeat("x", int(n)),
		}
		if expiresIn > 0 {
			answer["expires_in"] = expiresIn
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(server.Close)

	return server, &spent
}

func signedInWith(t *testing.T, issuer string, session Session) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := saveSession(issuer, session); err != nil {
		t.Fatalf("save the session: %v", err)
	}
}

// A token still in hand is presented again. The refresh token is not
// spent, because spending it is what rotates it out from under whoever
// else is holding it.
func TestRefreshReusesTheSessionToken(t *testing.T) {
	server, spent := refreshServer(t, 600)
	signedInWith(t, server.URL, Session{
		RefreshToken:  "a-refresh",
		AccessToken:   "still-good",
		AccessExpires: time.Now().Add(time.Hour),
	})

	token, err := refresh(context.Background(), Config{Issuer: server.URL, ClientID: "accessctl"})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if token.AccessToken != "still-good" {
		t.Errorf("presented %q, want the token already in the session", token.AccessToken)
	}
	if n := spent.Load(); n != 0 {
		t.Errorf("spent the refresh token %d times for a token already in hand, want 0", n)
	}
}

// And it does mint when there is nothing to reuse -- storing both halves,
// or the next command would spend the refresh token all over again.
func TestRefreshMintsWhenTheSessionTokenIsSpent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		session Session
	}{
		{"never had one", Session{RefreshToken: "a-refresh"}},
		{"expired", Session{RefreshToken: "a-refresh", AccessToken: "old", AccessExpires: time.Now().Add(-time.Minute)}},
		{"inside the margin", Session{
			RefreshToken: "a-refresh", AccessToken: "old", AccessExpires: time.Now().Add(sessionTokenMargin / 2),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, spent := refreshServer(t, 600)
			signedInWith(t, server.URL, tc.session)

			token, err := refresh(context.Background(), Config{Issuer: server.URL, ClientID: "accessctl"})
			if err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if token.AccessToken != "minted" {
				t.Errorf("presented %q, want a freshly minted token", token.AccessToken)
			}
			if n := spent.Load(); n != 1 {
				t.Errorf("spent the refresh token %d times, want 1", n)
			}

			stored, err := loadSession(server.URL)
			if err != nil {
				t.Fatalf("load the session: %v", err)
			}
			if stored.AccessToken != "minted" || stored.AccessExpires.IsZero() {
				t.Error("the minted token was not kept; the next command would spend the refresh token for the same thing")
			}
			if stored.RefreshToken == tc.session.RefreshToken {
				t.Error("the rotated refresh token was not kept; the next command would present a dead one")
			}
		})
	}
}

// THE POINT. Concurrent commands must spend the refresh token once: every
// extra spend leaves another caller holding a token the issuer refuses,
// and this command reports that as "not signed in" -- for every audience
// at once, not only for the caller that lost.
func TestRefreshSpendsTheRefreshTokenOnceAcrossConcurrentCallers(t *testing.T) {
	server, spent := refreshServer(t, 600)
	signedInWith(t, server.URL, Session{RefreshToken: "a-refresh"})

	cfg := Config{Issuer: server.URL, ClientID: "accessctl"}

	var wg sync.WaitGroup
	tokens := make([]string, 8)
	errs := make([]error, 8)
	for i := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := refresh(context.Background(), cfg)
			tokens[i], errs[i] = token.AccessToken, err
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if tokens[i] != "minted" {
			t.Errorf("caller %d got %q, want the one minted token", i, tokens[i])
		}
	}
	if n := spent.Load(); n != 1 {
		t.Fatalf("spent the refresh token %d times across 8 concurrent callers, want 1", n)
	}
}

// An issuer that declares no lifetime leaves the token uncacheable: a
// guessed span would be served past its expiry, and the relying party's
// refusal names neither this file nor the exchange.
func TestRefreshWillNotCacheATokenWithNoDeclaredLifetime(t *testing.T) {
	server, spent := refreshServer(t, 0)
	signedInWith(t, server.URL, Session{RefreshToken: "a-refresh"})

	cfg := Config{Issuer: server.URL, ClientID: "accessctl"}
	if _, err := refresh(context.Background(), cfg); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	stored, err := loadSession(server.URL)
	if err != nil {
		t.Fatalf("load the session: %v", err)
	}
	if stored.AccessToken != "" || !stored.AccessExpires.IsZero() {
		t.Error("cached a token with no expiry; it would be served after it stopped working")
	}
	// The rotated refresh token is still kept -- that half never depended
	// on a lifetime.
	if stored.RefreshToken == "a-refresh" {
		t.Error("the rotated refresh token was dropped")
	}
	if _, err = refresh(context.Background(), cfg); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if n := spent.Load(); n != 2 {
		t.Errorf("spent the refresh token %d times over two commands, want 2", n)
	}
}

// The session is the only copy of the refresh token: a reader must never
// see half of one, and a failed write must not leave the secret in a file
// nobody meant to keep.
func TestSaveSessionLeavesNoDebris(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const issuer = "https://issuer.invalid"

	if err := saveSession(issuer, Session{RefreshToken: "a-refresh"}); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	path, err := sessionPath(issuer)
	if err != nil {
		t.Fatalf("sessionPath: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode %o, want 600", perm)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read the directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("left %s behind: a temporary file holding the refresh token", entry.Name())
		}
	}
}
