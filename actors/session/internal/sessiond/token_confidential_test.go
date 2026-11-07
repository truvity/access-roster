//go:build sluis_test

package sessiond_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// The confidential client at the token and revocation endpoints (ADR 0021; RFC 6749 section 2.3).

const (
	confClient   = "conf-app"
	confRedirect = "https://app.example.com/cb"
	// confSecret holds characters that a form-URL-encoding has to escape (REQ-CLIENT-002).
	confSecret  = "s3cret:with %&+=/ and ü CANARY-right"
	wrongSecret = "CANARY-wrong-0123456789"
)

// credential is the name of the credential that holds the secret of a client in the secret source (as local.sh makes them).
func credential(client string) string { return "client-" + client }

// confEnv is an installation with a confidential client and its secret, a confidential client whose secret the
// secret source does not hold, an exchange client with a secret of its own, and the public client of the other tests.
func confEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, func(o *options) {
		o.extra = []*configv2alpha1.InstallationClient{
			{Id: confClient, Kind: "confidential", Redirects: []string{confRedirect}, Requires: []string{testGroup}, Secret: credential(confClient)},
			{Id: "conf-ghost", Kind: "confidential", Redirects: []string{confRedirect}, Requires: []string{testGroup}, Secret: credential("conf-ghost")},
			{Id: "conf-other", Kind: "confidential", Redirects: []string{confRedirect}, Requires: []string{testGroup}, Secret: credential("conf-other")},
			{Id: "exch-app", Kind: "exchange", Secret: credential("exch-app")},
		}
	})
	for id, secret := range map[string]string{confClient: confSecret, "conf-other": "another-clients-secret", "exch-app": confSecret} {
		e.store.put("installation-client-secret", "", id, &configv2alpha1.InstallationClientSecret{Client: id, Secret: []byte(secret)})
	}
	return e
}

// basicFor is the Authorization header of client_secret_basic: each part form-URL-encoded, then base64 (RFC 6749 2.3.1).
func basicFor(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

// confSignIn signs a person in at the confidential client and returns its code and PKCE verifier.
func confSignIn(e *env) (code, verifier string) {
	e.t.Helper()
	p := newAuthorize()
	p.req.ClientId, p.req.RedirectUri = confClient, confRedirect
	a := e.authorize(p.req)
	up := location(e.t, a)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(e.t, a),
	})
	code = location(e.t, cb).Query().Get("code")
	if code == "" {
		e.t.Fatal("no code")
	}
	return code, p.verifier
}

func confCode(code, verifier string) *sessionv2alpha1.TokenRequest {
	return &sessionv2alpha1.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectUri: confRedirect, CodeVerifier: verifier, ClientId: confClient,
	}
}

func withBasic(r *sessionv2alpha1.TokenRequest, id, secret string) *sessionv2alpha1.TokenRequest {
	r.Authorization = basicFor(id, secret)
	return r
}

func withPost(r *sessionv2alpha1.TokenRequest, secret string) *sessionv2alpha1.TokenRequest {
	r.ClientSecret = secret
	return r
}

// A confidential client redeems its code with its secret, by HTTP Basic (each part form-URL-decoded) or in the body.
//
// verifies: REQ-CLIENT-042, REQ-CLIENT-002
func TestAConfidentialClientRedeemsItsCodeWithItsSecret(t *testing.T) {
	for name, auth := range map[string]func(*sessionv2alpha1.TokenRequest) *sessionv2alpha1.TokenRequest{
		"REQ-CLIENT-002/client_secret_basic, form-encoded": func(r *sessionv2alpha1.TokenRequest) *sessionv2alpha1.TokenRequest {
			return withBasic(r, confClient, confSecret)
		},
		"REQ-CLIENT-002/client_secret_post": func(r *sessionv2alpha1.TokenRequest) *sessionv2alpha1.TokenRequest {
			return withPost(r, confSecret)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := confEnv(t)
			code, v := confSignIn(e)
			r := e.token(auth(confCode(code, v)))
			if r.GetStatus() != http.StatusOK {
				t.Fatalf("status %d: %s", r.GetStatus(), r.GetBody())
			}
			b := body(t, r)
			_, id := tokenClaims(t, b["id_token"].(string))
			if id["aud"] != confClient {
				t.Errorf("aud = %v", id["aud"])
			}
			if b["refresh_token"] == "" || b["access_token"] == "" {
				t.Errorf("body = %v", b)
			}
		})
	}
}

// Whatever is wrong with the credentials of a confidential client, the answer is the same invalid_client, nothing is
// spent, and the right secret then still works. Two methods in one request are an invalid request.
//
// verifies: REQ-CLIENT-042, REQ-CLIENT-045
func TestAConfidentialClientThatDoesNotAuthenticateIsRefusedAlike(t *testing.T) {
	e := confEnv(t)
	code, v := confSignIn(e)
	type c struct {
		name string
		req  *sessionv2alpha1.TokenRequest
		code string
	}
	both := withPost(withBasic(confCode(code, v), confClient, confSecret), confSecret)
	rawPercent := confCode(code, v)
	// A secret with a "%" that is not form-URL-encoded cannot be decoded.
	rawPercent.Authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(confClient+":100%real"))
	mismatch := withBasic(confCode(code, v), "conf-other", "another-clients-secret") // the header says another client than the body
	cases := []c{
		{"no secret", confCode(code, v), "invalid_client"},
		{"wrong secret in the body", withPost(confCode(code, v), wrongSecret), "invalid_client"},
		{"wrong secret by basic", withBasic(confCode(code, v), confClient, wrongSecret), "invalid_client"},
		{"the right secret not form-encoded", rawPercent, "invalid_client"},
		{"the secret of another client", withBasic(confCode(code, v), confClient, "another-clients-secret"), "invalid_client"},
		{"a header that names another client than the body", mismatch, "invalid_client"},
		{"a client_secret with no client_id", func() *sessionv2alpha1.TokenRequest {
			r := withPost(confCode(code, v), confSecret)
			r.ClientId = ""
			return r
		}(), "invalid_client"},
		{"a scheme that is not Basic", func() *sessionv2alpha1.TokenRequest {
			r := confCode(code, v)
			r.Authorization = "Bearer " + base64.StdEncoding.EncodeToString([]byte(confClient+":"+confSecret))
			return r
		}(), "invalid_client"},
		{"the right secret by two methods", both, "invalid_request"},
	}
	var bodies []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.token(tc.req)
			status := int32(http.StatusUnauthorized)
			if tc.code == "invalid_request" {
				status = http.StatusBadRequest
			}
			assertOAuth(t, r, status, tc.code)
			if tc.code == "invalid_client" {
				bodies = append(bodies, string(r.GetBody()))
			}
			for _, canary := range []string{"CANARY", "another-clients-secret", confClient} {
				if strings.Contains(string(r.GetBody()), canary) {
					t.Errorf("the answer repeats %q", canary)
				}
			}
		})
	}
	for _, b := range bodies {
		if b != bodies[0] {
			t.Errorf("invalid_client bodies differ: %q vs %q", b, bodies[0])
		}
	}
	if r := e.token(withBasic(confCode(code, v), confClient, confSecret)); r.GetStatus() != http.StatusOK {
		t.Fatalf("a refused request spent the code: %s", r.GetBody())
	}
}

// A confidential client with no secret in the secret source, an exchange client and an unknown client never authenticate,
// whatever they send, and look like every other failure.
//
// verifies: REQ-CLIENT-042
func TestClientsThatCannotHoldASecretAtTheTokenEndpointAreRefused(t *testing.T) {
	e := confEnv(t)
	code, v := confSignIn(e)
	for _, id := range []string{"conf-ghost", "exch-app", "nobody-0123"} {
		t.Run(id, func(t *testing.T) {
			for _, secret := range []string{confSecret, "", "x"} {
				r := confCode(code, v)
				r.ClientId = id
				if secret != "" {
					r = withBasic(r, id, secret)
				}
				assertOAuth(t, e.token(r), http.StatusUnauthorized, "invalid_client")
			}
		})
	}
}

// A confidential client's refresh and revocation take the same credentials: no secret and a wrong secret are refused and
// end nothing, and the right one is served.
//
// verifies: REQ-CLIENT-042
func TestAConfidentialClientAuthenticatesToRefreshAndToRevoke(t *testing.T) {
	e := confEnv(t)
	code, v := confSignIn(e)
	first := body(t, e.token(withPost(confCode(code, v), confSecret)))
	rt := first["refresh_token"].(string)
	refresh := func() *sessionv2alpha1.TokenRequest {
		return &sessionv2alpha1.TokenRequest{GrantType: "refresh_token", RefreshToken: rt, ClientId: confClient}
	}
	assertOAuth(t, e.token(refresh()), http.StatusUnauthorized, "invalid_client")
	assertOAuth(t, e.token(withPost(refresh(), wrongSecret)), http.StatusUnauthorized, "invalid_client")
	assertOAuth(t, e.token(withBasic(refresh(), confClient, wrongSecret)), http.StatusUnauthorized, "invalid_client")
	// The refused refreshes did not rotate the token or end the chain.
	second := e.token(withBasic(refresh(), confClient, confSecret))
	if second.GetStatus() != http.StatusOK {
		t.Fatalf("refresh with the secret: %d %s", second.GetStatus(), second.GetBody())
	}
	rt = body(t, second)["refresh_token"].(string)

	rev := func(secret string) *sessionv2alpha1.RevokeRequest {
		r := &sessionv2alpha1.RevokeRequest{Token: rt, ClientId: confClient}
		if secret != "" {
			r.ClientSecret = secret
		}
		return r
	}
	assertOAuth(t, e.revoke(rev("")), http.StatusUnauthorized, "invalid_client")
	assertOAuth(t, e.revoke(rev(wrongSecret)), http.StatusUnauthorized, "invalid_client")
	// Still alive: the refused revocations ended nothing.
	if r := e.token(withPost(refresh(), confSecret)); r.GetStatus() != http.StatusOK {
		t.Fatalf("a refused revocation ended the chain: %d %s", r.GetStatus(), r.GetBody())
	}
}

// The audit record of a step names how the client authenticated and the outcome, and no log line or record holds a
// secret, a header or a body.
//
// verifies: REQ-CLIENT-044
func TestClientAuthenticationLeavesNoSecretInTheLogOrTheRecords(t *testing.T) {
	e := confEnv(t)
	code, v := confSignIn(e)
	good := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(confClient) + ":" + url.QueryEscape(confSecret)))
	bad := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(confClient) + ":" + url.QueryEscape(wrongSecret)))
	lines, raw := logLines(t, func() {
		e.token(withBasic(confCode(code, v), confClient, wrongSecret))
		e.token(withPost(confCode(code, v), wrongSecret))
		e.token(withBasic(confCode(code, v), confClient, confSecret))
	})
	recs, err := json.Marshal(e.records())
	if err != nil {
		t.Fatal(err)
	}
	all := raw + string(recs)
	for _, secret := range []string{confSecret, url.QueryEscape(confSecret), wrongSecret, good, bad, "CANARY"} {
		if strings.Contains(all, secret) {
			t.Errorf("a log line or a record holds %q", secret)
		}
	}
	var failed, served []map[string]any
	for _, r := range e.records() {
		md, _ := r["metadata"].(map[string]any)
		if md["event_code"] != "session.token" {
			continue
		}
		if r["status_code"] != nil {
			failed = append(failed, r)
		} else {
			served = append(served, r)
		}
	}
	method := func(r map[string]any) (string, any) {
		sl := r["unmapped"].(map[string]any)["sluis"].(map[string]any)["client"].(map[string]any)
		return sl["method"].(string), sl["authenticated"]
	}
	if len(failed) != 2 || len(served) != 1 {
		t.Fatalf("%d failed and %d served token records, want 2 and 1", len(failed), len(served))
	}
	for i, want := range []string{"client_secret_basic", "client_secret_post"} {
		if m, a := method(failed[i]); m != want || a != false {
			t.Errorf("failed record %d: %s %v", i, m, a)
		}
		if failed[i]["status_code"] != "client_auth" {
			t.Errorf("failed record %d: reason %v", i, failed[i]["status_code"])
		}
	}
	if m, a := method(served[0]); m != "client_secret_basic" || a != true {
		t.Errorf("served record: %s %v", m, a)
	}
	for _, l := range lines {
		if l["msg"] == "refused" && l["reason"] == "client_auth" && l["client_id"] != confClient {
			t.Errorf("refusal line = %v", l)
		}
	}
}

// A request that presents credentials takes one path whoever the client is: one read of the client's declaration and
// one fetch of its secret, which the kit then compares once (kits/go/clientauth counts the comparison). The count is
// of calls, not of time: a bound on wall-clock time would fail on a loaded machine, and the number of calls does not.
//
// verifies: REQ-CLIENT-043
func TestEveryClientAuthenticationTakesTheSamePath(t *testing.T) {
	cases := map[string]struct {
		id, secret string
		method     func(*sessionv2alpha1.TokenRequest, string, string) *sessionv2alpha1.TokenRequest
	}{
		"an unknown client, basic": {"nobody-0123", "x", func(r *sessionv2alpha1.TokenRequest, id, s string) *sessionv2alpha1.TokenRequest {
			return withBasic(r, id, s)
		}},
		"an unknown client, post": {"nobody-0123", "x", func(r *sessionv2alpha1.TokenRequest, id, s string) *sessionv2alpha1.TokenRequest {
			r.ClientId = id
			return withPost(r, s)
		}},
		"a public client": {testClient, "x", func(r *sessionv2alpha1.TokenRequest, id, s string) *sessionv2alpha1.TokenRequest {
			return withBasic(r, id, s)
		}},
		"an exchange client": {"exch-app", confSecret, func(r *sessionv2alpha1.TokenRequest, id, s string) *sessionv2alpha1.TokenRequest {
			return withBasic(r, id, s)
		}},
		"a confidential client with no secret": {"conf-ghost", "x", func(r *sessionv2alpha1.TokenRequest, id, s string) *sessionv2alpha1.TokenRequest {
			return withBasic(r, id, s)
		}},
		"a confidential client, the wrong one": {confClient, wrongSecret, func(r *sessionv2alpha1.TokenRequest, id, s string) *sessionv2alpha1.TokenRequest {
			return withBasic(r, id, s)
		}},
		"a confidential client, the right one": {confClient, confSecret, func(r *sessionv2alpha1.TokenRequest, id, s string) *sessionv2alpha1.TokenRequest {
			return withBasic(r, id, s)
		}},
		"a confidential client, right, by post": {confClient, confSecret, func(r *sessionv2alpha1.TokenRequest, id, s string) *sessionv2alpha1.TokenRequest {
			r.ClientId = id
			return withPost(r, s)
		}},
	}
	e := confEnv(t)
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// A refresh grant with a token that is not one: the flow ends at the first lookup after the client is known, so
			// the count is of the client's authentication alone.
			secrets, clients := e.store.getsOf("installation-client-secret"), e.store.getsOf("installation-client")
			r := &sessionv2alpha1.TokenRequest{GrantType: "refresh_token", RefreshToken: "no-such-refresh-token"}
			_ = e.token(c.method(r, c.id, c.secret))
			if got := e.store.getsOf("installation-client-secret") - secrets; got != 1 {
				t.Errorf("%d fetches of the secret, want 1", got)
			}
			if got := e.store.getsOf("installation-client") - clients; got != 1 {
				t.Errorf("%d reads of the declaration, want 1", got)
			}
		})
	}
}

// A secret is asked for only when the request presents one, and then exactly once: a public client that presents none
// costs no fetch (it has nothing to compare), and a failure of the secret source is an outage, not a refusal.
//
// verifies: REQ-CLIENT-043
func TestAPublicClientWithoutCredentialsFetchesNoSecret(t *testing.T) {
	e := confEnv(t)
	code, p := e.signIn()
	secrets := e.store.getsOf("installation-client-secret")
	if r := e.token(codeRequest(code, p)); r.GetStatus() != http.StatusOK {
		t.Fatalf("status %d: %s", r.GetStatus(), r.GetBody())
	}
	if got := e.store.getsOf("installation-client-secret") - secrets; got != 0 {
		t.Errorf("%d fetches of a secret for a public client with no credentials", got)
	}
}

// Another client that presents a spent code ends nothing: only the client the code was issued to reads a replay as a leak and
// ends the chain. The public client needs no secret and knows a code that leaked, so without the owner check it could end the
// sessions of a confidential client; and the owner's own replay still ends them.
//
// verifies: REQ-CLIENT-042
func TestASpentCodeEndsTheChainOnlyForTheClientItWasIssuedTo(t *testing.T) {
	e := confEnv(t)
	code, v := confSignIn(e)
	first := e.token(withPost(confCode(code, v), confSecret))
	if first.GetStatus() != http.StatusOK {
		t.Fatalf("first: %d %s", first.GetStatus(), first.GetBody())
	}
	rt := body(t, first)["refresh_token"].(string)
	if e.store.count("session-chain", testTenant) != 1 {
		t.Fatal("no chain")
	}
	// The public client presents the leaked code with the redirect_uri of the confidential client and a well-formed verifier.
	other := &sessionv2alpha1.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectUri: confRedirect, CodeVerifier: v, ClientId: testClient,
	}
	assertOAuth(t, e.token(other), http.StatusBadRequest, "invalid_grant")
	// Another confidential client, with its own right secret.
	third := confCode(code, v)
	third.ClientId = "conf-other"
	third = withBasic(third, "conf-other", "another-clients-secret")
	assertOAuth(t, e.token(third), http.StatusBadRequest, "invalid_grant")
	if n := e.store.count("session-chain", testTenant); n != 1 {
		t.Fatalf("%d chains: a client that does not own the code ended the chain", n)
	}
	refreshed := e.token(withPost(&sessionv2alpha1.TokenRequest{GrantType: "refresh_token", RefreshToken: rt, ClientId: confClient}, confSecret))
	if refreshed.GetStatus() != http.StatusOK {
		t.Fatalf("the owner's refresh token was ended: %d %s", refreshed.GetStatus(), refreshed.GetBody())
	}
	// The owner's own replay ends it.
	assertOAuth(t, e.token(withPost(confCode(code, v), confSecret)), http.StatusBadRequest, "invalid_grant")
	if n := e.store.count("session-chain", testTenant); n != 0 {
		t.Errorf("%d chains survive the owner's replay", n)
	}
}

// A client whose kind changes between the authorization request and the callback is not given a code: the callback reads the
// declaration again, and only a public or a confidential client signs a person in.
//
// verifies: REQ-CLIENT-042
func TestACallbackRefusesAClientThatIsNoLongerOneThatSignsPeopleIn(t *testing.T) {
	for _, kind := range []string{"exchange", "service", ""} {
		t.Run("changed to "+kind, func(t *testing.T) {
			e := confEnv(t)
			p := newAuthorize()
			p.req.ClientId, p.req.RedirectUri = confClient, confRedirect
			a := e.authorize(p.req)
			up := location(e.t, a)
			e.store.put("installation-client", "", confClient, &configv2alpha1.InstallationClient{
				Id: confClient, Kind: kind, Redirects: []string{confRedirect}, Requires: []string{testGroup}, Secret: credential(confClient),
			})
			cb := e.callback(&sessionv2alpha1.CallbackRequest{
				Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
				Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(e.t, a),
			})
			if cb.GetStatus() == http.StatusFound {
				t.Fatalf("a redirect to %s", location(t, cb))
			}
			if e.store.count("auth-code", testTenant) != 0 {
				t.Error("a code was written")
			}
		})
	}
}
