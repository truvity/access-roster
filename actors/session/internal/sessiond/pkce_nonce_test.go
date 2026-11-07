//go:build sluis_test

package sessiond_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// The `pkce` setting of a client (ADR 0021; RFC 9700 sections 2.1.1 and 4.8.2): a confidential client that is set to `nonce` may
// ask for a code without PKCE when its request carries a nonce, and nobody else may.

const (
	nonceClient = "conf-app"            // confidential, named secret, pkce: nonce
	plainConf   = "conf-plain"          // confidential, named secret, the default
	nonceNoSec  = "conf-nonce-nosecret" // confidential, pkce: nonce, and no secret named (a document that got past the loader)
	nonceOnPub  = "pub-nonce"           // public, pkce: nonce and a secret named (the same)
	nonceValue  = "n-0123456789"        // ten characters, as the OpenID Foundation's suite makes them
)

// nonceEnv is an installation with the clients above, and the secret of the first two.
func nonceEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, func(o *options) {
		o.extra = []*configv2alpha1.InstallationClient{
			{Id: nonceClient, Kind: "confidential", Redirects: []string{confRedirect}, Requires: []string{testGroup}, Secret: credential(nonceClient), Pkce: "nonce"},
			{Id: plainConf, Kind: "confidential", Redirects: []string{confRedirect}, Requires: []string{testGroup}, Secret: credential(plainConf)},
			{Id: nonceNoSec, Kind: "confidential", Redirects: []string{confRedirect}, Requires: []string{testGroup}, Pkce: "nonce"},
			{Id: nonceOnPub, Kind: "public", Redirects: []string{"http://127.0.0.1/callback"}, Requires: []string{testGroup}, Secret: credential(nonceOnPub), Pkce: "nonce"},
		}
	})
	for _, id := range []string{nonceClient, plainConf} {
		e.store.put("installation-client-secret", "", id, &configv2alpha1.InstallationClientSecret{Client: id, Secret: []byte(confSecret)})
	}
	return e
}

// noPKCE is an authorization request of a client that sends no challenge and the given nonce.
func noPKCE(client, nonce string) *sessionv2alpha1.AuthorizeRequest {
	redirect := confRedirect
	if client == nonceOnPub || client == testClient {
		redirect = testRedirect
	}
	return &sessionv2alpha1.AuthorizeRequest{
		ResponseType: "code", ClientId: client, RedirectUri: redirect, Scope: "openid", State: "client-state-1", Nonce: nonce,
	}
}

// answered says what an authorization request got: the upstream's address (the sign-in began), or the error that went to the
// client's redirect, or "page" for a request that cannot be redirected.
func answered(e *env, r *sessionv2alpha1.AuthorizeRequest) (began bool, errCode string, upstream *url.URL, cookie string) {
	e.t.Helper()
	reply := e.authorize(r)
	if reply.GetStatus() != http.StatusFound {
		return false, "page", nil, ""
	}
	u := location(e.t, reply)
	if c := u.Query().Get("error"); c != "" {
		return false, c, u, ""
	}
	return true, "", u, cookieValue(e.t, reply)
}

// finish runs the callback of a begun sign-in and returns the code.
func finish(e *env, up *url.URL, cookie string) string {
	e.t.Helper()
	cb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookie,
	})
	code := location(e.t, cb).Query().Get("code")
	if code == "" {
		e.t.Fatalf("no code in %s", cb.GetBody())
	}
	return code
}

func nonceCode(code, client string) *sessionv2alpha1.TokenRequest {
	r := &sessionv2alpha1.TokenRequest{GrantType: "authorization_code", Code: code, RedirectUri: confRedirect, ClientId: client}
	return withBasic(r, client, confSecret)
}

// reasonsOf lists the status codes (the closed reasons) of the failed records of the audit.
func reasonsOf(e *env) []string {
	var out []string
	for _, r := range e.records() {
		if s, ok := r["status_code"].(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// A confidential client that is set to the nonce signs a person in without PKCE, redeems the code with its secret and no
// verifier, and its ID token carries the nonce it sent. Both steps are audit facts that name the way.
//
// verifies: REQ-AUTHN-002, REQ-AUTHN-110, REQ-TOKEN-030
func TestAClientSetToTheNonceSignsInWithoutPKCE(t *testing.T) {
	e := nonceEnv(t)
	began, errCode, up, cookie := answered(e, noPKCE(nonceClient, nonceValue))
	if !began {
		t.Fatalf("refused: %s", errCode)
	}
	code := finish(e, up, cookie)
	r := e.token(nonceCode(code, nonceClient))
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("status %d: %s", r.GetStatus(), r.GetBody())
	}
	_, id := tokenClaims(t, body(t, r)["id_token"].(string))
	if id["nonce"] != nonceValue || id["aud"] != nonceClient {
		t.Errorf("ID token = %v", id)
	}
	var seen []string
	for _, rec := range e.records() {
		md, _ := rec["metadata"].(map[string]any)
		sl, _ := rec["unmapped"].(map[string]any)["sluis"].(map[string]any)
		if p, ok := sl["pkce"].(string); ok {
			seen = append(seen, md["event_code"].(string)+"="+p)
		}
	}
	if strings.Join(seen, ",") != "session.authorize=nonce,session.token=nonce" {
		t.Errorf("records name the way as %v", seen)
	}
	// The ordinary way is named too.
	e2 := newEnv(t, nil)
	e2.redeemed()
	var plain []string
	for _, rec := range e2.records() {
		md, _ := rec["metadata"].(map[string]any)
		if sl, _ := rec["unmapped"].(map[string]any)["sluis"].(map[string]any); sl["pkce"] != nil {
			plain = append(plain, md["event_code"].(string)+"="+sl["pkce"].(string))
		}
	}
	if strings.Join(plain, ",") != "session.authorize=s256,session.token=s256" {
		t.Errorf("a PKCE sign-in is named %v", plain)
	}
}

// Without PKCE, the request must carry a nonce of at least eight characters, and the client must be set to it. A client that is
// not, and a client that cannot be, is refused whatever it sends: a stripped challenge is the downgrade.
//
// verifies: REQ-AUTHN-104, REQ-AUTHN-026, REQ-AUTHN-109
func TestARequestWithoutPKCEIsHeldByTheNonceOrRefused(t *testing.T) {
	e := nonceEnv(t)
	cases := []struct {
		name   string
		req    *sessionv2alpha1.AuthorizeRequest
		reason string // "" when the sign-in begins
	}{
		{"REQ-AUTHN-104/set to the nonce, a nonce of eight characters", noPKCE(nonceClient, "12345678"), ""},
		{"REQ-AUTHN-104/set to the nonce, the suite's nonce", noPKCE(nonceClient, nonceValue), ""},
		{"REQ-AUTHN-104/set to the nonce, no nonce", noPKCE(nonceClient, ""), "nonce"},
		{"REQ-AUTHN-104/set to the nonce, a nonce of seven characters", noPKCE(nonceClient, "1234567"), "nonce"},
		{"REQ-AUTHN-026/a confidential client not set to it, with a nonce", noPKCE(plainConf, nonceValue), "pkce"},
		{"REQ-AUTHN-026/a confidential client not set to it, no nonce", noPKCE(plainConf, ""), "pkce"},
		{"REQ-AUTHN-026/a public client, with a nonce", noPKCE(testClient, nonceValue), "pkce"},
		{"REQ-AUTHN-109/a public client whose document says nonce", noPKCE(nonceOnPub, nonceValue), "pkce"},
		{"REQ-AUTHN-109/a confidential client set to it that names no secret", noPKCE(nonceNoSec, nonceValue), "pkce"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(e.upstream.begins)
			began, errCode, _, _ := answered(e, c.req)
			switch {
			case c.reason == "" && !began:
				t.Fatalf("refused with %s", errCode)
			case c.reason != "" && (began || errCode != "invalid_request"):
				t.Fatalf("began=%v error=%q, want invalid_request", began, errCode)
			case c.reason != "" && len(e.upstream.begins) != before:
				t.Error("the upstream was called for a refused request")
			}
			if c.reason != "" {
				rs := reasonsOf(e)
				if got := rs[len(rs)-1]; got != c.reason {
					t.Errorf("reason = %s, want %s", got, c.reason)
				}
			}
		})
	}
}

// A request that sends a challenge or a method is a PKCE request whatever the client's setting is. A bad one is refused, not
// read as "no PKCE", and a good one is enforced at the token endpoint.
//
// verifies: REQ-AUTHN-105
func TestAChallengeThatIsSentIsCheckedWhateverTheSettingSays(t *testing.T) {
	e := nonceEnv(t)
	good := newAuthorize()
	for name, edit := range map[string]func(*sessionv2alpha1.AuthorizeRequest){
		"the plain method":                  func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallengeMethod = "plain" },
		"a challenge that is too short":     func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallenge = "short" },
		"a challenge with no method":        func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallengeMethod = "" },
		"a method with no challenge":        func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallenge = "" },
		"a method that is not one":          func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallengeMethod = "none" },
		"a challenge of the wrong alphabet": func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallenge = strings.Repeat("!", 43) },
	} {
		t.Run(name, func(t *testing.T) {
			r := noPKCE(nonceClient, nonceValue)
			r.CodeChallenge, r.CodeChallengeMethod = good.req.GetCodeChallenge(), "S256"
			edit(r)
			began, errCode, _, _ := answered(e, r)
			if began || errCode != "invalid_request" {
				t.Fatalf("began=%v error=%q: a sent challenge was not checked", began, errCode)
			}
			if rs := reasonsOf(e); rs[len(rs)-1] != "pkce" {
				t.Errorf("reason = %v", rs)
			}
		})
	}
	// A good challenge is enforced at the token endpoint for this client too.
	r := noPKCE(nonceClient, nonceValue)
	r.CodeChallenge, r.CodeChallengeMethod = good.req.GetCodeChallenge(), "S256"
	began, errCode, up, cookie := answered(e, r)
	if !began {
		t.Fatalf("refused: %s", errCode)
	}
	code := finish(e, up, cookie)
	assertOAuth(t, e.token(nonceCode(code, nonceClient)), http.StatusBadRequest, "invalid_request") // no verifier
	wrong := nonceCode(code, nonceClient)
	wrong.CodeVerifier = strings.Repeat("a", 50)
	assertOAuth(t, e.token(wrong), http.StatusBadRequest, "invalid_grant")
	right := nonceCode(code, nonceClient)
	right.CodeVerifier = good.verifier
	if r := e.token(right); r.GetStatus() != http.StatusOK {
		t.Fatalf("the right verifier: %d %s", r.GetStatus(), r.GetBody())
	}
}

// A verifier that comes with a code issued without a challenge is refused (RFC 9700 section 4.8.2), whatever the client's
// setting. The refusal spends nothing.
//
// verifies: REQ-AUTHN-106
func TestAVerifierForACodeWithoutAChallengeIsRefused(t *testing.T) {
	e := nonceEnv(t)
	began, errCode, up, cookie := answered(e, noPKCE(nonceClient, nonceValue))
	if !began {
		t.Fatalf("refused: %s", errCode)
	}
	code := finish(e, up, cookie)
	withVerifier := nonceCode(code, nonceClient)
	withVerifier.CodeVerifier = newAuthorize().verifier
	assertOAuth(t, e.token(withVerifier), http.StatusBadRequest, "invalid_grant")
	if rs := reasonsOf(e); rs[len(rs)-1] != "pkce" {
		t.Errorf("reason = %v", rs)
	}
	if r := e.token(nonceCode(code, nonceClient)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the refusal spent the code: %d %s", r.GetStatus(), r.GetBody())
	}
}

// A code issued without a challenge is redeemed only while the client is still set to the nonce, and only if it holds the nonce
// its ID token will carry. The setting may be taken away between the request, the callback and the token request.
//
// verifies: REQ-AUTHN-107
func TestACodeWithoutAChallengeNeedsTheSettingAtEveryStep(t *testing.T) {
	declare := func(e *env, c *configv2alpha1.InstallationClient) {
		e.store.put("installation-client", "", c.GetId(), c)
	}
	off := &configv2alpha1.InstallationClient{Id: nonceClient, Kind: "confidential", Redirects: []string{confRedirect}, Requires: []string{testGroup}, Secret: credential(nonceClient)}

	t.Run("taken away before the token request", func(t *testing.T) {
		e := nonceEnv(t)
		_, _, up, cookie := answered(e, noPKCE(nonceClient, nonceValue))
		code := finish(e, up, cookie)
		declare(e, off)
		assertOAuth(t, e.token(nonceCode(code, nonceClient)), http.StatusBadRequest, "invalid_grant")
	})
	t.Run("taken away before the callback", func(t *testing.T) {
		e := nonceEnv(t)
		_, _, up, cookie := answered(e, noPKCE(nonceClient, nonceValue))
		declare(e, off)
		cb := e.callback(&sessionv2alpha1.CallbackRequest{
			Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
			Iss: "https://idp.example.test/realms/test", Cookie: cookie,
		})
		if cb.GetStatus() == http.StatusFound && location(t, cb).Query().Get("code") != "" {
			t.Fatal("a code was issued to a client that is no longer set to the nonce")
		}
		if e.store.count("auth-code", testTenant) != 0 {
			t.Error("a code was written")
		}
	})
	t.Run("a code without the nonce its ID token needs", func(t *testing.T) {
		e := nonceEnv(t)
		_, _, up, cookie := answered(e, noPKCE(nonceClient, nonceValue))
		code := finish(e, up, cookie)
		id := secretIDForTest(code)
		raw, _, _ := e.store.raw("auth-code", testTenant, id)
		ac := protoOf(t, raw, &sessionv2alpha1.AuthCode{})
		ac.Nonce = ""
		e.store.put("auth-code", testTenant, id, ac)
		assertOAuth(t, e.token(nonceCode(code, nonceClient)), http.StatusBadRequest, "invalid_grant")
	})
	t.Run("a public client never redeems a code without a challenge", func(t *testing.T) {
		e := nonceEnv(t)
		code, p := e.signIn()
		id := secretIDForTest(code)
		raw, _, _ := e.store.raw("auth-code", testTenant, id)
		ac := protoOf(t, raw, &sessionv2alpha1.AuthCode{})
		ac.CodeChallenge = ""
		e.store.put("auth-code", testTenant, id, ac)
		r := codeRequest(code, p)
		r.CodeVerifier = ""
		assertOAuth(t, e.token(r), http.StatusBadRequest, "invalid_grant")
		// Whatever the document of the public client says.
		declare(e, &configv2alpha1.InstallationClient{Id: testClient, Kind: "public", Redirects: []string{"http://127.0.0.1/callback"}, Requires: []string{testGroup}, Secret: credential(nonceOnPub), Pkce: "nonce"})
		assertOAuth(t, e.token(r), http.StatusBadRequest, "invalid_grant")
	})
	t.Run("a confidential client not set to the nonce does not redeem it either", func(t *testing.T) {
		e := nonceEnv(t)
		code, v := confSignInAs(e, plainConf)
		id := secretIDForTest(code)
		raw, _, _ := e.store.raw("auth-code", testTenant, id)
		ac := protoOf(t, raw, &sessionv2alpha1.AuthCode{})
		ac.CodeChallenge = ""
		e.store.put("auth-code", testTenant, id, ac)
		r := nonceCode(code, plainConf)
		_ = v
		assertOAuth(t, e.token(r), http.StatusBadRequest, "invalid_grant")
	})
}

// confSignInAs is confSignIn for another confidential client.
func confSignInAs(e *env, client string) (code, verifier string) {
	e.t.Helper()
	p := newAuthorize()
	p.req.ClientId, p.req.RedirectUri = client, confRedirect
	began, errCode, up, cookie := answered(e, p.req)
	if !began {
		e.t.Fatalf("refused: %s", errCode)
	}
	return finish(e, up, cookie), p.verifier
}
