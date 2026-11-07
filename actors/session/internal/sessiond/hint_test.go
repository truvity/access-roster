//go:build sluis_test

package sessiond_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// signInWithHint runs authorize with the hint and, when the request is accepted, the callback, and returns the redirect to
// the client. It stops at the authorize redirect when that is an error.
func (e *env) signInWithHint(hint, prompt string) (q map[string][]string, authorized bool) {
	e.t.Helper()
	p := newAuthorize()
	p.req.IdTokenHint, p.req.Prompt = hint, prompt
	a := e.authorize(p.req)
	u := location(e.t, a)
	if u.Query().Get("error") != "" {
		return u.Query(), false
	}
	cb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + u.Query().Get("state")[:8], State: u.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(e.t, a),
	})
	return location(e.t, cb).Query(), true
}

// errorOf is the error of a redirect, "" when it has none; it never panics on an empty one.
func errorOf(q map[string][]string) string {
	if v := q["error"]; len(v) == 1 {
		return v[0]
	}
	return ""
}

// hintOf makes an id_token_hint with the claims, and a signature that is nothing.
func hintOf(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES384","typ":"JWT"}`)) + "." + enc(b) + "." + enc([]byte("not-a-signature"))
}

func hintClaims(sub string) map[string]any {
	return map[string]any{"iss": testIssuer, "sub": sub, "aud": testClient, "iat": 1, "exp": 2}
}

// An id_token_hint names the person the client expects (OpenID Connect Core section 3.1.2.1). A sign-in of that person is
// answered with a code, even when the hint has expired; a sign-in of anyone else is login_required, and nothing is made for
// the other person (no Person, no code). The hint is not checked for a signature, because it can only refuse.
func TestAnIDTokenHintHoldsTheSignInToItsPerson(t *testing.T) {
	signed := func(e *env, who string) string {
		e.upstream.assertion = upstreamAssertion("preferred_username", who)
		return e.signInClient(testClient)["id_token"].(string)
	}
	t.Run("the same person", func(t *testing.T) {
		e := newEnv(t, nil)
		hint := signed(e, "alice")
		q, ok := e.signInWithHint(hint, "")
		if !ok || q["code"] == nil || q["error"] != nil {
			t.Fatalf("refused: %v", q)
		}
		// An expired hint is accepted: the OP SHOULD accept it.
		e.clk.advance(72 * time.Hour)
		if q, ok := e.signInWithHint(hint, ""); !ok || q["code"] == nil {
			t.Fatalf("an expired hint was refused: %v", q)
		}
	})
	t.Run("another known person", func(t *testing.T) {
		e := newEnv(t, nil)
		hint := signed(e, "alice")
		signed(e, "bob")
		people := e.store.count("person", testTenant)
		before := len(e.signer.requests())
		e.upstream.assertion = upstreamAssertion("preferred_username", "bob")
		q, ok := e.signInWithHint(hint, "")
		if !ok || errorOf(q) != "login_required" || q["code"] != nil || len(q["state"]) != 1 || q["state"][0] != "client-state-1" {
			t.Fatalf("redirect = %v", q)
		}
		if e.store.count("person", testTenant) != people || len(e.signer.requests()) != before {
			t.Error("something was made for the person who is not the hint's")
		}
		recs := e.records()
		if got := recs[len(recs)-1]["status_code"]; got != "id_token_hint" {
			t.Errorf("status_code = %v", got)
		}
	})
	t.Run("a person who is new to sluis", func(t *testing.T) {
		e := newEnv(t, nil)
		hint := signed(e, "alice")
		people := e.store.count("person", testTenant)
		e.upstream.assertion = upstreamAssertion("preferred_username", "carol")
		q, ok := e.signInWithHint(hint, "")
		if !ok || errorOf(q) != "login_required" {
			t.Fatalf("redirect = %v", q)
		}
		if got := e.store.count("person", testTenant); got != people {
			t.Errorf("%d people, want %d: a person was made for a refused sign-in", got, people)
		}
	})
	t.Run("a hint made up by the caller", func(t *testing.T) {
		e := newEnv(t, nil)
		issued := signed(e, "alice")
		var c map[string]any
		parts := strings.Split(issued, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(raw, &c)
		// The right claims under no signature are taken (the hint only refuses); the claims of another person refuse.
		if q, ok := e.signInWithHint(hintOf(c), ""); !ok || q["code"] == nil {
			t.Fatalf("refused: %v", q)
		}
		c["sub"] = "someone-else"
		if q, ok := e.signInWithHint(hintOf(c), ""); !ok || errorOf(q) != "login_required" {
			t.Fatalf("redirect = %v", q)
		}
	})
	t.Run("aud as a list", func(t *testing.T) {
		e := newEnv(t, nil)
		issued := signed(e, "alice")
		raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(issued, ".")[1])
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		c["aud"] = []string{"another-app", testClient}
		if q, ok := e.signInWithHint(hintOf(c), ""); !ok || q["code"] == nil {
			t.Fatalf("refused: %v", q)
		}
	})
}

// A hint that is not an ID token of this issuer for this client is invalid_request at the redirect, and the upstream is not
// asked.
func TestAnIDTokenHintOfAnotherIssuerOrClientOrShapeIsRefused(t *testing.T) {
	const other = "other-app"
	long := hintOf(map[string]any{"iss": testIssuer, "sub": "s", "aud": testClient, "pad": strings.Repeat("x", 5000)})
	with := func(edit func(map[string]any)) string {
		c := hintClaims("s-1")
		edit(c)
		return hintOf(c)
	}
	for name, hint := range map[string]string{
		"not a JWT":                 "abc",
		"a header that is not JSON": "x." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","sub":"s","aud":"`+testClient+`"}`)) + ".y",
		"a header that is a list":   base64.RawURLEncoding.EncodeToString([]byte(`[]`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","sub":"s","aud":"`+testClient+`"}`)) + ".y",
		"a header that is null":     base64.RawURLEncoding.EncodeToString([]byte(`null`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","sub":"s","aud":"`+testClient+`"}`)) + ".y",
		"two parts":                 "a.b",
		"four parts":                "a.b.c.d",
		"payload not base64":        "a.%%%.c",
		"payload not JSON":          "a." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".c",
		"another issuer":            with(func(c map[string]any) { c["iss"] = "https://sluis.other.test" }),
		"no issuer":                 with(func(c map[string]any) { delete(c, "iss") }),
		"another client":            with(func(c map[string]any) { c["aud"] = other }),
		"no audience":               with(func(c map[string]any) { delete(c, "aud") }),
		"an audience list":          with(func(c map[string]any) { c["aud"] = []string{other, "x"} }),
		"an audience number":        with(func(c map[string]any) { c["aud"] = 1 }),
		"no subject":                with(func(c map[string]any) { delete(c, "sub") }),
		"an empty subject":          with(func(c map[string]any) { c["sub"] = "" }),
		"a subject too long":        with(func(c map[string]any) { c["sub"] = strings.Repeat("s", 129) }),
		"a subject with a nul":      with(func(c map[string]any) { c["sub"] = "a\x00b" }),
		"over the bound":            long,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(o *options) { o.extra = []*configv2alpha1.InstallationClient{clientOf(other)} })
			q, ok := e.signInWithHint(hint, "")
			if ok || errorOf(q) != "invalid_request" || len(q["state"]) != 1 || q["state"][0] != "client-state-1" {
				t.Fatalf("redirect = %v", q)
			}
			if len(e.upstream.begins) != 0 {
				t.Error("the upstream was asked")
			}
			if recs := e.records(); recs[len(recs)-1]["status_code"] != "id_token_hint" {
				t.Errorf("records = %v", recs)
			}
		})
	}
}

// A held person who signs in with the hint of their own sub goes on to the hold and is refused as held; a held person whose
// sub is not the hint's is refused for the hint first. Either way no code is made.
func TestAnIDTokenHintDoesNotLetAHeldPersonThrough(t *testing.T) {
	e := newEnv(t, nil)
	e.upstream.assertion = upstreamAssertion("preferred_username", "alice")
	hint := e.signInClient(testClient)["id_token"].(string)
	e.store.putRaw("person-hold", testTenant, e.store.ids("person", testTenant)[0], []byte{1})
	q, ok := e.signInWithHint(hint, "")
	if !ok || errorOf(q) != "access_denied" || q["code"] != nil {
		t.Fatalf("redirect = %v", q)
	}
	if recs := e.records(); recs[len(recs)-1]["status_code"] != "held" {
		t.Errorf("status_code = %v", recs[len(recs)-1]["status_code"])
	}
	q, ok = e.signInWithHint(hintOf(hintClaims("someone-else")), "")
	if !ok || errorOf(q) != "login_required" || q["code"] != nil {
		t.Fatalf("redirect = %v", q)
	}
	if recs := e.records(); recs[len(recs)-1]["status_code"] != "id_token_hint" {
		t.Errorf("status_code = %v", recs[len(recs)-1]["status_code"])
	}
}

// The sign-in cookie stays under 4 KiB with the longest hint subject that is taken, and the callback still opens it: the
// hint's person is not this one, so the answer is login_required for the hint, which it can only be once the cookie
// opened and the state matched.
//
// verifies: REQ-SESS-050
func TestAuthorizeNeverSetsACookieLargerThan4KiBWithAHint(t *testing.T) {
	const part = 128
	longClient := strings.Repeat("c", part)
	long := "https://app.example.com/" + strings.Repeat("p", 1000)
	e := newEnv(t, func(o *options) {
		o.client.Id = longClient
		o.client.Redirects = []string{long}
		o.boundary.DefaultTenant = strings.Repeat("t", part)
		o.upstream.Name = strings.Repeat("u", part)
	})
	p := newAuthorize()
	p.req.ClientId, p.req.RedirectUri = longClient, long
	p.req.State, p.req.Nonce = strings.Repeat("s", 256), strings.Repeat("n", 256)
	p.req.Scope, p.req.MaxAge = "openid profile email", "2147483647"
	hint := map[string]any{"iss": testIssuer, "sub": strings.Repeat("h", part), "aud": longClient}
	p.req.IdTokenHint = hintOf(hint)
	r := e.authorize(p.req)
	up := location(t, r)
	v := cookieValue(t, r)
	if v == "" || len(v) > 4096 {
		t.Fatalf("a sign-in cookie of %d bytes", len(v))
	}
	t.Logf("the largest sign-in cookie with a hint is %d bytes of 4096", len(v))
	cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: up.Query().Get("state"), Cookie: v})
	if q := location(t, cb).Query(); q.Get("error") != "login_required" || q.Get("state") != p.req.State {
		t.Fatalf("the callback did not open the cookie: %v", q)
	}
	if recs := e.records(); recs[len(recs)-1]["status_code"] != "id_token_hint" {
		t.Errorf("status_code = %v", recs[len(recs)-1]["status_code"])
	}
}
