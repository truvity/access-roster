package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func login(t *testing.T, ta *testApp, f *fakeIDP, extra ...string) int {
	t.Helper()
	ta.openBrowser = followBrowser(t)
	return ta.do(append([]string{"login", "--issuer", f.srv.URL, "--client-id", "sluis-cli", "--timeout", "10s"}, extra...)...)
}

func TestLoginStoresTokensPrivately(t *testing.T) {
	f := newFakeIDP(t)
	ta := newTestApp(t)
	if code := login(t, ta, f, "--output", "json"); code != 0 {
		t.Fatalf("exit = %d, stdout %q stderr %q", code, ta.out.String(), ta.err.String())
	}
	o := ta.object(t)
	l := o["login"].(map[string]any)
	if o["outcome"] != "done" || l["subject"] != "alice" || l["issuer"] != f.srv.URL {
		t.Fatalf("object = %v", o)
	}
	if strings.Contains(ta.out.String(), "access-1") || strings.Contains(ta.out.String(), "refresh-1") {
		t.Fatal("login printed a token")
	}
	dir := filepath.Join(ta.cache, "sluis", "tokens")
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("token directory: %v, %v", st, err)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatalf("%d cache files, want 1 (and no temporary file)", len(files))
	}
	fi, _ := files[0].Info()
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode = %v, want 0600", fi.Mode().Perm())
	}
	// The code exchange carried the PKCE verifier, and the redirect was the loopback IP literal on a port.
	req := f.lastRequests()[0]
	if len(req.Get("code_verifier")) != 43 || !strings.HasPrefix(req.Get("redirect_uri"), "http://127.0.0.1:") {
		t.Fatalf("code exchange = %v", req)
	}
}

func TestLoginPrintsURLWithoutBrowser(t *testing.T) {
	f := newFakeIDP(t)
	ta := newTestApp(t)
	opened := false
	ta.openBrowser = func(string) error { opened = true; return nil }
	done := make(chan int, 1)
	go func() {
		done <- ta.do("login", "--issuer", f.srv.URL, "--client-id", "sluis-cli", "--no-browser", "--timeout", "1s")
	}()
	if code := <-done; code != 1 { // nobody opens the URL, so it times out
		t.Fatalf("exit = %d, want 1 on a timeout", code)
	}
	if opened {
		t.Fatal("--no-browser opened a browser")
	}
	if !strings.Contains(ta.err.String(), "/auth?") || !strings.Contains(ta.err.String(), "code_challenge_method=S256") {
		t.Fatalf("stderr = %q, want the sign-in URL", ta.err.String())
	}
	if ta.out.Len() != 0 {
		t.Fatalf("stdout = %q, want nothing", ta.out.String())
	}
}

func TestLoginWithClientSecretFromDescriptor(t *testing.T) {
	f := newFakeIDP(t)
	f.clientSecret = "s3cret/+ value"
	ta := newTestApp(t)
	ta.secretFd = func(fd int) io.Reader {
		if fd != 7 {
			t.Errorf("fd = %d", fd)
		}
		return strings.NewReader(f.clientSecret + "\n")
	}
	if code := login(t, ta, f, "--secret-fd", "7"); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, ta.err.String())
	}
	if strings.Contains(ta.out.String()+ta.err.String(), f.clientSecret) {
		t.Fatal("the secret was printed")
	}
	// Without the secret the issuer refuses the client: exit 3, and the issuer's description is not shown.
	ta2 := newTestApp(t)
	if code := login(t, ta2, f); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if strings.Contains(ta2.err.String(), "SECRET-DETAIL") {
		t.Fatal("the issuer's error description reached the output")
	}
}

func TestLoginRefusals(t *testing.T) {
	t.Run("issuer in the metadata differs", func(t *testing.T) {
		f := newFakeIDP(t)
		f.issuerOverride = "https://other.example.com"
		if code := login(t, newTestApp(t), f); code != 3 {
			t.Fatalf("exit = %d, want 3", code)
		}
	})
	t.Run("nonce of the identity token differs", func(t *testing.T) {
		f := newFakeIDP(t)
		f.idTokenNonce = "another"
		ta := newTestApp(t)
		if code := login(t, ta, f); code != 3 {
			t.Fatalf("exit = %d, want 3; stderr %q", code, ta.err.String())
		}
		if _, err := os.Stat(filepath.Join(ta.cache, "sluis")); err == nil {
			t.Fatal("a refused sign-in left a cache")
		}
	})
	t.Run("http issuer off loopback", func(t *testing.T) {
		ta := newTestApp(t)
		if code := ta.do("login", "--issuer", "http://idp.example.com", "--no-browser"); code != 1 {
			t.Fatalf("exit = %d, want 1; stderr %q", code, ta.err.String())
		}
		if !strings.Contains(ta.err.String(), "loopback") {
			t.Fatalf("stderr = %q", ta.err.String())
		}
	})
	t.Run("not a URL", func(t *testing.T) {
		if code := newTestApp(t).do("login", "--issuer", "idp", "--no-browser"); code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
	})
}

func TestCheckEndpoint(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://idp.example.com/realms/x": true,
		"http://127.0.0.1:8180/realms/x":   true,
		"http://localhost:8180":            true,
		"http://[::1]:8180":                true,
		"http://idp.example.com":           false,
		"http://127.0.0.1.example.com":     false,
		"ftp://127.0.0.1":                  false,
		"https://u:p@idp.example.com":      false,
		"https://idp.example.com/#frag":    false,
		"idp.example.com":                  false,
	} {
		if _, err := checkEndpoint(raw); (err == nil) != ok {
			t.Errorf("checkEndpoint(%q) error = %v, want ok = %v", raw, err, ok)
		}
	}
}

func TestLoginNeedsIssuerWhenCacheIsEmpty(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.do("login", "--no-browser"); code != 3 {
		t.Fatalf("exit = %d, want 3, stderr %q", code, ta.err.String())
	}
}

func TestCacheRefusesReadableFile(t *testing.T) {
	f := newFakeIDP(t)
	ta := newTestApp(t)
	if code := login(t, ta, f); code != 0 {
		t.Fatalf("login exit = %d", code)
	}
	dir := filepath.Join(ta.cache, "sluis", "tokens")
	files, _ := os.ReadDir(dir)
	p := filepath.Join(dir, files[0].Name())
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		code := ta.do("token", "--audience", "globex-app", "--output", "json")
		if code != 3 {
			t.Fatalf("mode %v: exit = %d, want 3", mode, code)
		}
		if !strings.Contains(ta.out.String(), "cache.mode") || strings.Contains(ta.out.String(), "access-1") {
			t.Fatalf("mode %v: stdout = %q", mode, ta.out.String())
		}
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := ta.do("token", "--audience", "globex-app"); code != 0 {
		t.Fatalf("mode 0600: exit = %d, stderr %q", code, ta.err.String())
	}
	// A symbolic link in place of the file is not followed.
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSet(link); err == nil || !strings.Contains(err.Error(), "cache.type") {
		t.Fatalf("readSet(symlink) = %v, want cache.type", err)
	}
}

func TestTokenExchangeAndCache(t *testing.T) {
	f := newFakeIDP(t)
	ta := newTestApp(t)
	if code := login(t, ta, f); code != 0 {
		t.Fatalf("login exit = %d", code)
	}
	// Name no issuer: it comes from the cache.
	if code := ta.do("token", "--audience", "globex-app", "--boundary", "dev"); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, ta.err.String())
	}
	if strings.TrimSpace(ta.out.String()) != "exchanged-for-globex-app" {
		t.Fatalf("stdout = %q, want the token alone", ta.out.String())
	}
	reqs := f.lastRequests()
	ex := reqs[len(reqs)-1]
	if ex.Get("grant_type") != grantTokenExchange || ex.Get("subject_token") != "access-1" ||
		ex.Get("subject_token_type") != tokenTypeAccess || ex.Get("audience") != "globex-app" {
		t.Fatalf("exchange request = %v", ex)
	}
	// A second call is answered from the cache, in JSON, without another request.
	n := len(reqs)
	if code := ta.do("token", "--audience", "globex-app", "--boundary", "dev", "--output", "json"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if len(f.lastRequests()) != n {
		t.Fatal("a valid exchanged token was requested again")
	}
	tok := ta.object(t)["token"].(map[string]any)
	if tok["access_token"] != "exchanged-for-globex-app" || tok["audience"] != "globex-app" || tok["issuer"] != f.srv.URL {
		t.Fatalf("token = %v", tok)
	}
	if _, err := time.Parse(time.RFC3339, tok["expires_at"].(string)); err != nil {
		t.Fatalf("expires_at: %v", err)
	}
	// Another boundary is another cache key.
	if code := ta.do("token", "--audience", "globex-app", "--boundary", "stage"); code != 0 || len(f.lastRequests()) != n+1 {
		t.Fatalf("exit = %d, requests = %d", code, len(f.lastRequests()))
	}
}

func TestTokenRefusals(t *testing.T) {
	f := newFakeIDP(t)
	ta := newTestApp(t)
	if code := login(t, ta, f); code != 0 {
		t.Fatalf("login exit = %d", code)
	}
	// An audience the issuer refuses: exit 3, with the reason that does not say why.
	if code := ta.do("token", "--audience", "unknown-app", "--output", "json"); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if strings.Contains(ta.out.String(), "invalid_target") || strings.Contains(ta.out.String(), "SECRET-DETAIL") {
		t.Fatalf("stdout = %q gives away why the audience was refused", ta.out.String())
	}
	if code := ta.do("token"); code != 2 {
		t.Fatalf("no audience: exit = %d, want 2", code)
	}
	// Nothing is cached: 3.
	if code := newTestApp(t).do("token", "--audience", "globex-app"); code != 3 {
		t.Fatalf("not signed in: exit = %d, want 3", code)
	}
}

func TestTokenRefreshesAnExpiredAccessToken(t *testing.T) {
	f := newFakeIDP(t)
	ta := newTestApp(t)
	if code := login(t, ta, f); code != 0 {
		t.Fatalf("login exit = %d", code)
	}
	// An hour later the access token of 300 seconds has expired, and the refresh token brings a new one.
	ta.now = func() time.Time { return time.Now().Add(time.Hour) }
	if code := ta.do("token", "--audience", "globex-app"); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, ta.err.String())
	}
	reqs := f.lastRequests()
	if g := reqs[len(reqs)-2].Get("grant_type"); g != "refresh_token" {
		t.Fatalf("grant before the exchange = %q, want refresh_token", g)
	}
	if reqs[len(reqs)-1].Get("subject_token") != "access-2" {
		t.Fatal("the exchange did not use the refreshed access token")
	}
	// The issuer now refuses the refresh token: the person signs in again.
	ta.now = func() time.Time { return time.Now().Add(3 * time.Hour) }
	f.refuseRefresh = true
	if code := ta.do("token", "--audience", "other-app", "--output", "json"); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(ta.out.String(), "cache.login") {
		t.Fatalf("stdout = %q", ta.out.String())
	}
}

func TestUsageAndVersion(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.do(); code != 2 {
		t.Fatalf("no command: exit = %d", code)
	}
	if code := ta.do("frobnicate"); code != 2 {
		t.Fatalf("unknown command: exit = %d", code)
	}
	if code := ta.do("login", "--output", "xml"); code != 2 {
		t.Fatalf("bad output: exit = %d", code)
	}
	if code := ta.do("login", "--output", "json", "--bogus"); code != 2 {
		t.Fatalf("bad flag: exit = %d", code)
	}
	if o := ta.object(t); o["outcome"] != "usage" || o["exit_code"] != float64(2) {
		t.Fatalf("object = %v", o)
	}
	if code := ta.do("version"); code != 0 || !strings.Contains(ta.out.String(), "sluis") {
		t.Fatalf("version: exit = %d, stdout %q", code, ta.out.String())
	}
	if code := ta.do("--help"); code != 0 || !strings.Contains(ta.out.String(), "audit verify") {
		t.Fatalf("help: exit = %d", code)
	}
}
