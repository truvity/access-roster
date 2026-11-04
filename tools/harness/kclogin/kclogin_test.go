package kclogin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// RFC 6238 appendix B: the SHA-1 secret "12345678901234567890", whose eight-digit codes end in the six digits here.
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, c := range []struct {
		unix int64
		want string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"},
	} {
		if got := TOTP(key, time.Unix(c.unix, 0)); got != c.want {
			t.Errorf("TOTP(%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

// fakeIDP is a login page, an OTP page and a redirect to the client, in the shape Keycloak's forms have.
func fakeIDP(t *testing.T, wantOTP func() string, otpFails *atomic.Int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("SSO"); err == nil && c.Value == "yes" {
			http.Redirect(w, r, "http://127.0.0.1:1/callback?code=c2", http.StatusFound)
			return
		}
		_, _ = fmt.Fprint(w, `<form id="kc-form-login" action="`+srv.URL+`/login?a=1&amp;b=2" method="post">`+
			`<input type="hidden" name="credentialId" value=""/><input id="username" name="username"/><input type="password" name="password"/></form>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Query().Get("b") != "2" || r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != "pw" {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprint(w, `<form action="`+srv.URL+`/otp" method="post"><input type="hidden" name="session_code" value="s&amp;1"/><input name="otp"/></form>`)
	})
	mux.HandleFunc("/otp", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("session_code") != "s&1" {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		if otpFails.Add(-1) >= 0 || r.PostForm.Get("otp") != wantOTP() {
			_, _ = fmt.Fprint(w, `<span class="kc-feedback-text">Invalid authenticator code.</span><form action="`+srv.URL+`/otp" method="post"><input type="hidden" name="session_code" value="s&amp;1"/><input name="otp"/></form>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "SSO", Value: "yes", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "http://127.0.0.1:1/callback?code=c1", http.StatusFound)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func stopAtCallback(u *url.URL) bool { return u.Host == "127.0.0.1:1" }

func TestAuthorizeFillsThePasswordAndOTPForms(t *testing.T) {
	const authKey = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // the RFC 6238 key, base32
	now := time.Unix(1111111111, 0)
	var fails atomic.Int32
	idp := fakeIDP(t, func() string { return "050471" }, &fails)
	d := &Driver{Client: idp.Client(), Stop: stopAtCallback, Now: func() time.Time { return now }}
	u, err := d.Authorize(context.Background(), idp.URL+"/auth", Credentials{Username: "alice", Password: "pw", TOTPSecret: authKey})
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code") != "c1" {
		t.Errorf("redirect = %s", u.Redacted())
	}
	// The second visit of the same browser is answered by the provider's session: no form, and no code is made.
	u, err = d.Authorize(context.Background(), idp.URL+"/auth", Credentials{})
	if err != nil || u.Query().Get("code") != "c2" {
		t.Errorf("second visit = %v, %v", u, err)
	}
}

func TestAuthorizeWaitsForTheNextStepAfterARefusedCode(t *testing.T) {
	const authKey = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	clock := time.Unix(1111111111, 0)
	var slept []time.Duration
	var fails atomic.Int32
	fails.Store(1) // the first code is refused, as a code already used in this step is
	idp := fakeIDP(t, func() string { return TOTP([]byte("12345678901234567890"), clock) }, &fails)
	d := &Driver{
		Client: idp.Client(), Stop: stopAtCallback, Now: func() time.Time { return clock },
		Sleep: func(_ context.Context, w time.Duration) error {
			slept = append(slept, w)
			clock = clock.Add(w)
			return nil
		},
	}
	if _, err := d.Authorize(context.Background(), idp.URL+"/auth", Credentials{Username: "alice", Password: "pw", TOTPSecret: authKey}); err != nil {
		t.Fatal(err)
	}
	if len(slept) != 1 || slept[0] <= 0 || slept[0] > Period*time.Second {
		t.Errorf("slept %v, want one wait of at most a step", slept)
	}
}

func TestAuthorizeRefusesWhatItCannotAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `<form action="/x"><input name="phone"/></form>`)
	}))
	defer srv.Close()
	d := &Driver{Client: srv.Client(), Stop: stopAtCallback}
	_, err := d.Authorize(context.Background(), srv.URL, Credentials{})
	if err == nil || !strings.Contains(err.Error(), "cannot give") {
		t.Errorf("err = %v", err)
	}
	if _, err := (&Driver{}).Authorize(context.Background(), srv.URL, Credentials{}); err == nil {
		t.Error("a driver with no client signed in")
	}
}
