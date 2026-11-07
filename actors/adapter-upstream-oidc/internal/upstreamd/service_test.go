//go:build sluis_test

package upstreamd_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

const (
	callback = "http://127.0.0.1:43210/callback"
	nonce    = "n-0S6_WzA2Mj"
	state    = "s-5kT0pXr9Q"
)

// pkcePair makes a verifier and its S256 challenge (RFC 7636 sections 4.1 and 4.2).
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func upstreamOf(issuer string) *configv2alpha1.Upstream {
	return &configv2alpha1.Upstream{
		Name: "workforce", Kind: "oidc", Issuer: issuer, ClientId: idpClientID,
		SubjectClaim: "preferred_username", OrgClaim: "org", Scopes: []string{"profile", "email"}, Secret: "upstream-workforce",
	}
}

// fixture is an env over a fake upstream, with the verifier of the begin step.
type fixture struct {
	*env
	t        *testing.T
	idp      *fakeIDP
	verifier string
}

func newFixture(t *testing.T, mutate func(*envOptions, *fakeIDP)) *fixture {
	t.Helper()
	idp := newFakeIDP(t)
	o := envOptions{environment: "development", upstream: upstreamOf(idp.issuer), secret: idpClientSecret}
	if mutate != nil {
		mutate(&o, idp)
	}
	f := &fixture{env: newEnv(t, o), t: t, idp: idp}
	f.idp.nonce = nonce
	return f
}

// completeReq is a Complete request that the fake upstream accepts.
func (f *fixture) completeReq() *integrationv2alpha1.CompleteRequest {
	if f.verifier == "" {
		f.verifier, _ = pkcePair(f.t)
	}
	return &integrationv2alpha1.CompleteRequest{
		Upstream: "workforce", Code: idpGoodCode, RedirectUri: callback, CodeVerifier: f.verifier, Nonce: nonce, Iss: f.idp.issuer,
	}
}

func TestBeginMakesAnS256AuthorizationURL(t *testing.T) {
	f := newFixture(t, nil)
	verifier, challenge := pkcePair(t)
	res, err := f.begin(context.Background(), &integrationv2alpha1.BeginRequest{
		Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(res.GetAuthorizationUrl())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": idpClientID, "redirect_uri": callback, "state": state, "nonce": nonce,
		"code_challenge": challenge, "code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if got := strings.Fields(q.Get("scope")); strings.Join(got, " ") != "openid profile email" {
		t.Errorf("scope = %v", got)
	}
	if u.Host != strings.TrimPrefix(f.idp.srv.URL, "http://") || u.Path != "/realms/test/auth" {
		t.Errorf("the URL does not point to the upstream's authorization endpoint")
	}
	if strings.Contains(res.GetAuthorizationUrl(), verifier) || strings.Contains(res.GetAuthorizationUrl(), idpClientSecret) {
		t.Fatal("the URL carries the verifier or the client secret")
	}
}

// What the client asked of the authentication reaches the upstream's authorization request as given, and nothing else does:
// a request that asked for neither carries neither.
//
// verifies: REQ-AUTHN-007, REQ-AUTHN-008
func TestBeginPassesPromptAndMaxAgeOn(t *testing.T) {
	_, challenge := pkcePair(t)
	age := func(n int64) *int64 { return &n }
	for _, c := range []struct {
		name   string
		prompt string
		maxAge *int64
		want   map[string]string
	}{
		{"neither", "", nil, map[string]string{"prompt": "", "max_age": ""}},
		{"prompt none", "none", nil, map[string]string{"prompt": "none", "max_age": ""}},
		{"prompt login", "login", nil, map[string]string{"prompt": "login", "max_age": ""}},
		{"max_age", "", age(900), map[string]string{"prompt": "", "max_age": "900"}},
		{"max_age zero is sent as zero", "", age(0), map[string]string{"prompt": "", "max_age": "0"}},
		{"both", "login", age(60), map[string]string{"prompt": "login", "max_age": "60"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			res, err := f.begin(context.Background(), &integrationv2alpha1.BeginRequest{
				Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge,
				Prompt: c.prompt, MaxAge: c.maxAge,
			})
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(res.GetAuthorizationUrl())
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range c.want {
				if got := u.Query()[k]; v == "" && len(got) != 0 || v != "" && (len(got) != 1 || got[0] != v) {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
		})
	}
}

// The client's acr_values reach the upstream's authorization request as one parameter, in the client's order, values that
// start with - or _ among them; a request that asked for none carries none.
//
// verifies: REQ-AUTHN-009
func TestBeginPassesACRValuesOn(t *testing.T) {
	_, challenge := pkcePair(t)
	for _, asked := range []string{"", "urn:example:acr:mfa", "urn:example:acr:hw urn:example:acr:mfa", "-a _b"} {
		f := newFixture(t, nil)
		res, err := f.begin(context.Background(), &integrationv2alpha1.BeginRequest{
			Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge, AcrValues: asked,
		})
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(res.GetAuthorizationUrl())
		if err != nil {
			t.Fatal(err)
		}
		got := u.Query()["acr_values"]
		if asked == "" && len(got) != 0 || asked != "" && (len(got) != 1 || got[0] != asked) {
			t.Errorf("acr_values = %q, want %q", got, asked)
		}
	}
}

func TestBeginRefusals(t *testing.T) {
	_, challenge := pkcePair(t)
	good := func() *integrationv2alpha1.BeginRequest {
		return &integrationv2alpha1.BeginRequest{Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge}
	}
	cases := []struct {
		name   string
		edit   func(*integrationv2alpha1.BeginRequest)
		reason string
		code   connect.Code
		path   string
	}{
		{"no upstream", func(r *integrationv2alpha1.BeginRequest) { r.Upstream = "" }, "INVALID", connect.CodeInvalidArgument, "upstream"},
		{"unknown upstream", func(r *integrationv2alpha1.BeginRequest) { r.Upstream = "nobody" }, "NOT_FOUND", connect.CodeNotFound, "upstream"},
		{"no state", func(r *integrationv2alpha1.BeginRequest) { r.State = "" }, "INVALID", connect.CodeInvalidArgument, "state"},
		{"no nonce", func(r *integrationv2alpha1.BeginRequest) { r.Nonce = "" }, "INVALID", connect.CodeInvalidArgument, "nonce"},
		{"state with a space", func(r *integrationv2alpha1.BeginRequest) { r.State = "a b" }, "INVALID", connect.CodeInvalidArgument, "state"},
		{"plain challenge", func(r *integrationv2alpha1.BeginRequest) { r.CodeChallenge = "plain-verifier-is-not-a-challenge" }, "INVALID", connect.CodeInvalidArgument, "code_challenge"},
		{"no challenge", func(r *integrationv2alpha1.BeginRequest) { r.CodeChallenge = "" }, "INVALID", connect.CodeInvalidArgument, "code_challenge"},
		{"callback over http off loopback", func(r *integrationv2alpha1.BeginRequest) { r.RedirectUri = "http://example.com/cb" }, "INVALID", connect.CodeInvalidArgument, "redirect_uri"},
		{"prompt consent is session's to answer", func(r *integrationv2alpha1.BeginRequest) { r.Prompt = "consent" }, "INVALID", connect.CodeInvalidArgument, "prompt"},
		{"prompt with two values", func(r *integrationv2alpha1.BeginRequest) { r.Prompt = "none login" }, "INVALID", connect.CodeInvalidArgument, "prompt"},
		{"negative max_age", func(r *integrationv2alpha1.BeginRequest) { v := int64(-1); r.MaxAge = &v }, "INVALID", connect.CodeInvalidArgument, "max_age"},
		{"max_age over the bound", func(r *integrationv2alpha1.BeginRequest) { v := int64(1) << 31; r.MaxAge = &v }, "INVALID", connect.CodeInvalidArgument, "max_age"},
		{"acr_values with an empty member", func(r *integrationv2alpha1.BeginRequest) { r.AcrValues = "a  b" }, "INVALID", connect.CodeInvalidArgument, "acr_values"},
		{"acr_values with a quote", func(r *integrationv2alpha1.BeginRequest) { r.AcrValues = "a\"b" }, "INVALID", connect.CodeInvalidArgument, "acr_values"},
		{"acr_values with a backslash", func(r *integrationv2alpha1.BeginRequest) { r.AcrValues = "a\\b" }, "INVALID", connect.CodeInvalidArgument, "acr_values"},
		{"acr_values with a newline", func(r *integrationv2alpha1.BeginRequest) { r.AcrValues = "a\nb" }, "INVALID", connect.CodeInvalidArgument, "acr_values"},
		{"acr_values over 256 bytes", func(r *integrationv2alpha1.BeginRequest) { r.AcrValues = strings.Repeat("a", 257) }, "INVALID", connect.CodeInvalidArgument, "acr_values"},
		{"nine acr_values", func(r *integrationv2alpha1.BeginRequest) { r.AcrValues = "a b c d e f g h i" }, "INVALID", connect.CodeInvalidArgument, "acr_values"},
		{"callback with a fragment", func(r *integrationv2alpha1.BeginRequest) { r.RedirectUri = "https://example.com/cb#x" }, "INVALID", connect.CodeInvalidArgument, "redirect_uri"},
	}
	f := newFixture(t, nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := good()
			c.edit(r)
			_, err := f.begin(context.Background(), r)
			refused(t, err, c.reason, c.code, c.path)
		})
	}
}

func TestBeginRefusesAnUpstreamWithoutS256(t *testing.T) {
	f := newFixture(t, func(_ *envOptions, idp *fakeIDP) {
		idp.discovery = func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} }
	})
	_, challenge := pkcePair(t)
	_, err := f.begin(context.Background(), &integrationv2alpha1.BeginRequest{Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge})
	refused(t, err, "UNSUPPORTED", connect.CodeUnimplemented, "discovery.code_challenge_methods_supported")
}

func TestUpstreamOfAnotherKindIsUnsupported(t *testing.T) {
	f := newFixture(t, func(o *envOptions, _ *fakeIDP) { o.upstream.Kind = "saml" })
	_, challenge := pkcePair(t)
	_, err := f.begin(context.Background(), &integrationv2alpha1.BeginRequest{Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge})
	refused(t, err, "UNSUPPORTED", connect.CodeUnimplemented, "upstream.kind")
}

// verifies: REQ-FED-016, REQ-FED-005
func TestCompleteReturnsTheVerifiedAssertion(t *testing.T) {
	f := newFixture(t, nil)
	f.verifier, _ = pkcePair(t)
	a, err := f.complete(context.Background(), f.completeReq())
	if err != nil {
		t.Fatal(err)
	}
	if a.GetIssuer() != f.idp.issuer || a.GetSubjectClaim() != "preferred_username" || a.GetSubject() != "alice" {
		t.Errorf("identity = %q %q %q", a.GetIssuer(), a.GetSubjectClaim(), a.GetSubject())
	}
	if a.Acr == nil || a.GetAcr() != "2" || !a.GetAmrPresent() || strings.Join(a.GetAmr(), ",") != "pwd,otp,mfa" {
		t.Errorf("assurance = %v %v %v", a.Acr, a.GetAmr(), a.GetAmrPresent())
	}
	if a.GetAuthTime() == nil || a.GetOrgId() != "globex" {
		t.Errorf("auth_time = %v, org = %q", a.GetAuthTime(), a.GetOrgId())
	}
	// REQ-FED-016: the assertion has no place for groups or roles, and the contract carries nothing else.
	b, _ := json.Marshal(a)
	if strings.Contains(string(b), "admin") {
		t.Errorf("the assertion carries a role or a group: %s", b)
	}
	// The client authenticated with Basic, and the verifier went in the body, the secret did not.
	f.idp.mu.Lock()
	defer f.idp.mu.Unlock()
	if f.idp.basicID != idpClientID || f.idp.basicSecret != idpClientSecret {
		t.Error("the client did not authenticate with HTTP Basic")
	}
	if f.idp.form.Get("code_verifier") != f.verifier || f.idp.form.Get("redirect_uri") != callback || f.idp.form.Get("client_secret") != "" {
		t.Error("the token request is not the one of RFC 6749 section 4.1.3 with PKCE")
	}
}

func TestCompleteReadsTheConfiguredSubjectClaimAndLeavesAbsentValuesUnknown(t *testing.T) {
	f := newFixture(t, func(o *envOptions, idp *fakeIDP) {
		o.upstream.SubjectClaim, o.upstream.OrgClaim = "sub", ""
		idp.claims = func(c map[string]any) { delete(c, "acr"); delete(c, "amr"); delete(c, "auth_time") }
	})
	a, err := f.complete(context.Background(), f.completeReq())
	if err != nil {
		t.Fatal(err)
	}
	if a.GetSubject() != "11111111-2222-3333-4444-555555555555" || a.GetSubjectClaim() != "sub" {
		t.Errorf("subject = %q (%q)", a.GetSubject(), a.GetSubjectClaim())
	}
	// An absent value is unknown, never a default (ADR 0025, "Facts").
	if a.Acr != nil || a.GetAmrPresent() || len(a.GetAmr()) != 0 || a.GetAuthTime() != nil || a.GetOrgId() != "" {
		t.Errorf("a default was made up: %v", a)
	}
}

// verifies: REQ-SUBJ-040
func TestCompleteBoundsTheSubjectClaimAt255Characters(t *testing.T) {
	cases := []struct {
		name  string
		value any // nil: the claim is not in the token
		ok    bool
	}{
		{"255 characters", strings.Repeat("a", 255), true},
		{"256 characters", strings.Repeat("a", 256), false},
		{"300 characters", strings.Repeat("a", 300), false},
		// Counted in bytes of UTF-8: "é" is two.
		{"255 bytes of multi-byte UTF-8", strings.Repeat("é", 127) + "a", true},
		{"256 bytes of multi-byte UTF-8", strings.Repeat("é", 128), false},
		{"under 255 characters but over 255 bytes", strings.Repeat("€", 86), false},
		{"a number", 42, false},
		{"empty", "", false},
		{"absent", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, func(_ *envOptions, idp *fakeIDP) {
				idp.claims = func(m map[string]any) {
					if c.value == nil {
						delete(m, "preferred_username")
					} else {
						m["preferred_username"] = c.value
					}
				}
			})
			a, err := f.complete(context.Background(), f.completeReq())
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				if a.GetSubject() != c.value {
					t.Errorf("subject of %d bytes", len(a.GetSubject()))
				}
				return
			}
			// No assertion, so session has nothing to create a person from.
			if a != nil {
				t.Fatal("an assertion was returned")
			}
			refused(t, err, "INVALID", connect.CodeInvalidArgument, "id_token.preferred_username")
		})
	}
}

func TestAnEmptyAMRIsPresent(t *testing.T) {
	f := newFixture(t, func(_ *envOptions, idp *fakeIDP) {
		idp.claims = func(c map[string]any) { c["amr"] = []string{} }
	})
	a, err := f.complete(context.Background(), f.completeReq())
	if err != nil {
		t.Fatal(err)
	}
	if !a.GetAmrPresent() || len(a.GetAmr()) != 0 {
		t.Errorf("amr_present = %v, amr = %v; an empty list the upstream sent is not the same as none", a.GetAmrPresent(), a.GetAmr())
	}
}

// verifies: REQ-FED-001, REQ-FED-011, REQ-FED-012, REQ-FED-013, REQ-FED-015, REQ-FED-003, REQ-SEC-012
func TestCompleteRefusesWhatDoesNotVerify(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		tweak  func(*fakeIDP)
		edit   func(*integrationv2alpha1.CompleteRequest)
		reason string
		code   connect.Code
		path   string
	}{
		{name: "a bad nonce", edit: func(r *integrationv2alpha1.CompleteRequest) { r.Nonce = "another-nonce" }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.nonce"},
		{name: "no nonce in the token", tweak: func(i *fakeIDP) { i.claims = func(c map[string]any) { delete(c, "nonce") } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.nonce"},
		{name: "a wrong iss in the token", tweak: func(i *fakeIDP) { i.claims = func(c map[string]any) { c["iss"] = "https://evil.example.com" } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.iss"},
		{name: "a wrong iss parameter", edit: func(r *integrationv2alpha1.CompleteRequest) { r.Iss = "https://evil.example.com/realms/test" }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "iss"},
		{name: "a missing iss parameter when the upstream advertises it", edit: func(r *integrationv2alpha1.CompleteRequest) { r.Iss = "" }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "iss"},
		{name: "a wrong audience", tweak: func(i *fakeIDP) { i.claims = func(c map[string]any) { c["aud"] = "someone-else" } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.aud"},
		{name: "several audiences and a wrong azp", tweak: func(i *fakeIDP) {
			i.claims = func(c map[string]any) { c["aud"] = []string{idpClientID, "other"}; c["azp"] = "other" }
		}, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.azp"},
		{name: "several audiences and no azp", tweak: func(i *fakeIDP) {
			i.claims = func(c map[string]any) { c["aud"] = []string{idpClientID, "other"}; delete(c, "azp") }
		}, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.azp"},
		{name: "no iat", tweak: func(i *fakeIDP) { i.claims = func(c map[string]any) { delete(c, "iat") } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.iat"},
		{name: "an expired token", tweak: func(i *fakeIDP) {
			i.claims = func(c map[string]any) { c["exp"] = time.Now().Add(-10 * time.Minute).Unix() }
		}, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.exp"},
		{name: "no expiry", tweak: func(i *fakeIDP) { i.claims = func(c map[string]any) { delete(c, "exp") } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.exp"},
		{name: "a token not yet valid", tweak: func(i *fakeIDP) {
			i.claims = func(c map[string]any) { c["nbf"] = time.Now().Add(10 * time.Minute).Unix() }
		}, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.nbf"},
		{name: "a token issued in the future", tweak: func(i *fakeIDP) {
			i.claims = func(c map[string]any) { c["iat"] = time.Now().Add(10 * time.Minute).Unix() }
		}, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.iat"},
		{name: "a bad signature", tweak: func(i *fakeIDP) { i.sign = func(p []byte) string { return i.signES384(p, other) } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.signature"},
		{name: "alg none", tweak: func(i *fakeIDP) {
			i.sign = func(p []byte) string { return forge(map[string]any{"alg": "none", "typ": "JWT"}, p, nil) }
		}, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.alg"},
		{name: "alg HS256", tweak: func(i *fakeIDP) { i.sign = hs256 }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.alg"},
		{name: "a key id the set does not hold", tweak: func(i *fakeIDP) {
			i.sign = func(p []byte) string {
				return forge(map[string]any{"alg": "ES384", "kid": "unknown"}, p, make([]byte, 96))
			}
		}, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.signature"},
		{name: "a subject claim that is not there", tweak: func(i *fakeIDP) { i.claims = func(c map[string]any) { delete(c, "preferred_username") } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.preferred_username"},
		{name: "a subject claim that is not a string", tweak: func(i *fakeIDP) { i.claims = func(c map[string]any) { c["preferred_username"] = 42 } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.preferred_username"},
		{name: "an amr that is not a list", tweak: func(i *fakeIDP) { i.claims = func(c map[string]any) { c["amr"] = "pwd" } }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "id_token.amr"},
		{name: "a code the upstream rejects", edit: func(r *integrationv2alpha1.CompleteRequest) { r.Code = "used-code" }, reason: "UPSTREAM_REJECTED", code: connect.CodeFailedPrecondition, path: "code"},
		{name: "a token endpoint that is down", tweak: func(i *fakeIDP) { i.tokenStatus = http.StatusServiceUnavailable }, reason: "UNAVAILABLE", code: connect.CodeUnavailable, path: "token_endpoint"},
		{name: "a token endpoint that asks to slow down", tweak: func(i *fakeIDP) { i.tokenStatus = http.StatusTooManyRequests }, reason: "RATE_LIMITED", code: connect.CodeResourceExhausted, path: "token_endpoint"},
		{name: "a rejected client", tweak: func(i *fakeIDP) { i.tokenStatus = http.StatusUnauthorized }, reason: "UPSTREAM_REJECTED", code: connect.CodeFailedPrecondition, path: "client"},
		{name: "no code", edit: func(r *integrationv2alpha1.CompleteRequest) { r.Code = "" }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "code"},
		{name: "a short verifier", edit: func(r *integrationv2alpha1.CompleteRequest) { r.CodeVerifier = "short" }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "code_verifier"},
		{name: "a verifier with a forbidden character", edit: func(r *integrationv2alpha1.CompleteRequest) { r.CodeVerifier = strings.Repeat("a", 42) + "/" }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "code_verifier"},
		{name: "no nonce in the request", edit: func(r *integrationv2alpha1.CompleteRequest) { r.Nonce = "" }, reason: "INVALID", code: connect.CodeInvalidArgument, path: "nonce"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			if c.tweak != nil {
				c.tweak(f.idp)
			}
			r := f.completeReq()
			if c.edit != nil {
				c.edit(r)
			}
			a, err := f.complete(context.Background(), r)
			if a != nil {
				t.Fatal("an assertion was returned")
			}
			refused(t, err, c.reason, c.code, c.path)
			// An error shows a path, never a value: not the vendor's text, the code, the verifier or the secret.
			for _, v := range []string{"vendor text", idpGoodCode, r.GetCodeVerifier(), idpClientSecret, "alice"} {
				if strings.Contains(err.Error(), v) {
					t.Fatalf("the error shows a value: %v", err)
				}
			}
		})
	}
}

func TestTheKeySetIsFetchedAgainWhenAKeyIdIsUnknown(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.complete(context.Background(), f.completeReq()); err != nil {
		t.Fatal(err)
	}
	if got := f.idp.jwksHits.Load(); got != 1 {
		t.Fatalf("key set fetched %d times for one sign-in", got)
	}
	// The next sign-in uses the memory: one discovery and one key set for both.
	if _, err := f.complete(context.Background(), f.completeReq()); err != nil {
		t.Fatal(err)
	}
	if f.idp.discoveryHits.Load() != 1 || f.idp.jwksHits.Load() != 1 {
		t.Fatalf("discovery %d, key set %d: the metadata was not kept", f.idp.discoveryHits.Load(), f.idp.jwksHits.Load())
	}
}

func TestDiscoveryThatNamesAnotherIssuerIsRefused(t *testing.T) {
	f := newFixture(t, func(_ *envOptions, idp *fakeIDP) {
		idp.discovery = func(d map[string]any) { d["issuer"] = "https://evil.example.com/realms/test" }
	})
	_, err := f.complete(context.Background(), f.completeReq())
	refused(t, err, "UPSTREAM_REJECTED", connect.CodeFailedPrecondition, "discovery.issuer")
}

// verifies: REQ-ISO-110
// An upstream that declares host A: a call to host B is refused before it leaves the adapter.
func TestAnEndpointAtAnotherHostIsNotCalled(t *testing.T) {
	var hostB atomic.Int32
	b := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hostB.Add(1) }))
	t.Cleanup(b.Close)
	for _, field := range []string{"token_endpoint", "jwks_uri", "authorization_endpoint"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t, func(_ *envOptions, idp *fakeIDP) {
				idp.discovery = func(d map[string]any) { d[field] = b.URL + "/x" }
			})
			_, err := f.complete(context.Background(), f.completeReq())
			refused(t, err, "UNSUPPORTED", connect.CodeUnimplemented, "discovery."+field)
			if hostB.Load() != 0 || f.idp.tokenHits.Load() != 0 {
				t.Fatalf("host B got %d requests, the token endpoint %d: the call left the adapter", hostB.Load(), f.idp.tokenHits.Load())
			}
		})
	}
}

// D-11: an http issuer is for a development boundary only, a floor in code.
func TestAnHTTPIssuerIsRefusedOutsideDevelopment(t *testing.T) {
	for _, environment := range []string{"staging", "production", ""} {
		t.Run("environment="+environment, func(t *testing.T) {
			f := newFixture(t, func(o *envOptions, _ *fakeIDP) { o.environment = environment })
			r := f.completeReq()
			r.RedirectUri = "https://sluis.example.com/callback"
			_, err := f.complete(context.Background(), r)
			refused(t, err, "UNSUPPORTED", connect.CodeUnimplemented, "upstream.issuer")
			if f.idp.discoveryHits.Load() != 0 {
				t.Fatal("the upstream was called")
			}
		})
	}
}

// REQ-FED-008: the address is checked after the name is resolved. Outside a development boundary, loopback is refused
// even for an https issuer; the test server counts the connections it is offered.
// verifies: REQ-FED-008
func TestLoopbackIsRefusedAfterResolutionOutsideDevelopment(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	idp := newFakeIDP(t)
	o := envOptions{environment: "production", upstream: upstreamOf(srv.URL + "/realms/test"), secret: idpClientSecret}
	f := &fixture{env: newEnv(t, o), t: t, idp: idp}
	r := f.completeReq()
	r.RedirectUri, r.Iss = "https://sluis.example.com/callback", srv.URL+"/realms/test"
	_, err := f.complete(context.Background(), r)
	refused(t, err, "UNSUPPORTED", connect.CodeUnimplemented, "discovery")
	if conns.Load() != 0 {
		t.Fatalf("the server was offered %d connections", conns.Load())
	}
}

func TestNoClientSecretNoSignIn(t *testing.T) {
	f := newFixture(t, func(o *envOptions, _ *fakeIDP) { o.noSecret = true })
	_, err := f.complete(context.Background(), f.completeReq())
	refused(t, err, "UNAVAILABLE", connect.CodeUnavailable, "upstream.client_secret")
	if f.idp.tokenHits.Load() != 0 {
		t.Fatal("a token request was made without a credential")
	}
}

// verifies: REQ-ISO-106
// The health check reads no secret value: it checks that the Upstream names one. A sign-in tells a store@ outage
// (path store) from a secret store@ does not hold (path upstream.client_secret).
func TestTheCheckReadsNoSecretAndAnOutageIsNotAMissingSecret(t *testing.T) {
	f := newFixture(t, nil)
	if bad := f.svc.Check(context.Background()); len(bad) != 0 {
		t.Fatalf("Check = %v", bad)
	}
	if n := f.store.count("upstream-secret"); n != 0 {
		t.Fatalf("Check read the secret %d times", n)
	}
	up := upstreamOf(f.idp.issuer)
	up.Secret = ""
	f.store.set("upstream/workforce", up)
	if bad := f.svc.Check(context.Background()); len(bad) != 1 || bad[0] != "upstream.workforce.secret" {
		t.Fatalf("Check without a declared secret = %v", bad)
	}
	f.store.set("upstream/workforce", upstreamOf(f.idp.issuer))
	f.store.failOn("upstream-secret", refusal.New(connect.CodeUnavailable, "engine", ""))
	_, err := f.complete(context.Background(), f.completeReq())
	refused(t, err, "UNAVAILABLE", connect.CodeUnavailable, "store")
	if f.idp.tokenHits.Load() != 0 {
		t.Fatal("a token request was made without a credential")
	}
}

func TestOnlyTheCallersOfTheRegistryMayCall(t *testing.T) {
	// policy is not a caller of the upstream adapter (actors.yaml): the call is refused before the message is decoded.
	f := newFixture(t, func(o *envOptions, _ *fakeIDP) { o.caller = "policy" })
	_, err := f.complete(context.Background(), f.completeReq())
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v (%v), want permission_denied", connect.CodeOf(err), err)
	}
	if f.idp.discoveryHits.Load() != 0 {
		t.Fatal("a refused caller reached the upstream")
	}
	if n := len(f.transport.records()); n != 0 {
		t.Fatalf("%d audit records for a call the guard refused", n)
	}
}

func TestEveryCallIsAudited(t *testing.T) {
	f := newFixture(t, nil)
	_, challenge := pkcePair(t)
	ctx := context.Background()
	if _, err := f.begin(ctx, &integrationv2alpha1.BeginRequest{Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.complete(ctx, f.completeReq()); err != nil {
		t.Fatal(err)
	}
	bad := f.completeReq()
	bad.Nonce = "another-nonce"
	if _, err := f.complete(ctx, bad); err == nil {
		t.Fatal("a bad nonce was accepted")
	}

	msgs := f.transport.records()
	if len(msgs) != 3 {
		t.Fatalf("%d audit records, want 3", len(msgs))
	}
	recs := make([]map[string]any, len(msgs))
	for i, m := range msgs {
		if err := json.Unmarshal(m.GetRecord(), &recs[i]); err != nil {
			t.Fatal(err)
		}
		raw := string(m.GetRecord())
		// A record never carries the person's name, the issuer URL or any value of the exchange.
		for _, v := range []string{"alice", idpGoodCode, idpClientSecret, "11111111-2222"} {
			if strings.Contains(raw, v) {
				t.Fatalf("record %d carries a value of the sign-in", i)
			}
		}
	}
	md := func(i int, k string) any { return recs[i]["metadata"].(map[string]any)[k] }
	if md(0, "event_code") != "upstream.begin" || recs[0]["status_id"] != float64(1) || userUID(recs[0]) != "unknown" {
		t.Errorf("begin record = %v", recs[0])
	}
	if md(1, "event_code") != "upstream.complete" || recs[1]["status_id"] != float64(1) || recs[1]["class_uid"] != float64(3002) || recs[1]["activity_id"] != float64(1) {
		t.Errorf("complete record = %v", recs[1])
	}
	user, _ := recs[1]["user"].(map[string]any)
	if uid, _ := user["uid"].(string); !strings.HasPrefix(uid, "p1.") {
		t.Errorf("the subject is not a pseudonym: %v", user)
	}
	un := recs[1]["unmapped"].(map[string]any)["sluis"].(map[string]any)["assurance"].(map[string]any)
	if un["acr"] != "2" || len(un["amr"].([]any)) != 3 {
		t.Errorf("assurance = %v", un)
	}
	if md(1, "tenant_uid") != "acme" {
		t.Errorf("tenant = %v, want the boundary's default tenant", md(1, "tenant_uid"))
	}
	if recs[2]["status_id"] != float64(2) || recs[2]["status_code"] != "INVALID" || userUID(recs[2]) != "unknown" {
		t.Errorf("refusal record = %v", recs[2])
	}

	// The pseudonym is asked of key@ with the kind of identity set, for the boundary's tenant, from the issuer and the
	// subject (0029 "Pseudonyms"): the kind is in the keyed input, length-prefixed.
	macs := f.key.requests()
	if len(macs) != 1 || macs[0].GetPurpose() != "pseudonym" || macs[0].GetTenant() != "acme" || !strings.Contains(string(macs[0].GetInput()), "person") {
		t.Fatalf("mac requests = %v", macs)
	}
}

func TestEveryRefusalIsAConnectErrorWithADetail(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.complete(context.Background(), &integrationv2alpha1.CompleteRequest{Upstream: "workforce"})
	if _, ok := refusal.Reason(err); !ok {
		t.Fatalf("no Refusal detail on %v", err)
	}
}

// verifies: REQ-ISO-106
// The adapter holds no credential at rest: it reads the client secret through store@ (UpstreamSecret) for each call and
// keeps it for that call only. A changed secret is used at the next call, and a secret store@ no longer serves stops
// the next sign-in.
func TestTheClientSecretIsReadThroughStoreForEachCall(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.complete(context.Background(), f.completeReq()); err != nil {
		t.Fatal(err)
	}
	if f.idp.basicSecret != idpClientSecret || f.store.count("upstream-secret") != 1 {
		t.Fatalf("token request secret ok=%v, %d reads of UpstreamSecret", f.idp.basicSecret == idpClientSecret, f.store.count("upstream-secret"))
	}
	// The upstream's client secret is rotated in the secret source. The fake upstream records the secret each token
	// request carries.
	const rotated = "rotated-client-secret-value"
	f.store.set("upstream-secret/workforce", &configv2alpha1.UpstreamSecret{Upstream: "workforce", Secret: []byte(rotated)})
	f.idp.mu.Lock()
	f.idp.basicSecret = ""
	f.idp.mu.Unlock()
	_, err := f.complete(context.Background(), f.completeReq())
	if f.idp.basicSecret != rotated || f.store.count("upstream-secret") != 2 {
		t.Fatalf("after rotation: secret is the new one=%v, %d reads (%v)", f.idp.basicSecret == rotated, f.store.count("upstream-secret"), err)
	}
	// store@ no longer serves it: no token request is made.
	f.store.set("upstream-secret/workforce", nil)
	hits := f.idp.tokenHits.Load()
	_, err = f.complete(context.Background(), f.completeReq())
	refused(t, err, "UNAVAILABLE", connect.CodeUnavailable, "upstream.client_secret")
	if f.idp.tokenHits.Load() != hits {
		t.Fatal("a token request was made without a credential")
	}
	// A secret for another upstream is not this one's.
	f.store.set("upstream-secret/workforce", &configv2alpha1.UpstreamSecret{Upstream: "other", Secret: []byte(idpClientSecret)})
	_, err = f.complete(context.Background(), f.completeReq())
	refused(t, err, "UNAVAILABLE", connect.CodeUnavailable, "upstream.client_secret")
}

// A sign-in whose fact the transport refuses does not leave the adapter, and that fact is not a lost one: it is not
// counted. A refused sign-in is answered as it was whatever happens to its fact, so that fact is best effort: the
// loss is counted, and the next record says so (0029 "Facts that are lost are counted").
//
// verifies: REQ-AUDIT-186, REQ-AUDIT-187
func TestAFailedAuditFactFailsASuccessUncountedAndIsCountedForARefusal(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	_, challenge := pkcePair(t)
	begin := &integrationv2alpha1.BeginRequest{Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge}

	f.transport.mu.Lock()
	f.transport.fail = true
	f.transport.mu.Unlock()
	if _, err := f.begin(ctx, begin); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("a success whose fact was refused: err = %v, want unavailable", err)
	}
	if n := f.audit.Lost(); n != 0 {
		t.Fatalf("a fact whose operation failed was counted as lost (%d)", n)
	}

	bad := f.completeReq()
	bad.Nonce = "another-nonce"
	_, err := f.complete(ctx, bad)
	if err == nil || connect.CodeOf(err) == connect.CodeUnavailable {
		t.Fatalf("a refused sign-in with a failing transport: err = %v, want the refusal itself", err)
	}
	if n := f.audit.Lost(); n != 1 {
		t.Fatalf("Lost() = %d, want 1: the fact of the refusal is lost and must be counted", n)
	}

	f.transport.mu.Lock()
	f.transport.fail = false
	f.transport.mu.Unlock()
	if _, err := f.complete(ctx, bad); err == nil {
		t.Fatal("a bad nonce was accepted")
	}
	msgs := f.transport.records()
	var rec struct {
		Unmapped struct {
			Sluis struct {
				Lost struct{ Total int64 } `json:"lost"`
			} `json:"sluis"`
		} `json:"unmapped"`
	}
	if err := json.Unmarshal(msgs[len(msgs)-1].GetRecord(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Unmapped.Sluis.Lost.Total != 1 {
		t.Fatalf("the next refusal carries %+v, want a total of 1", rec.Unmapped.Sluis.Lost)
	}
}

// userUID is the user.uid of a record: OCSF requires the user of an Authentication, and a step that identified nobody (the
// begin of a sign-in, a refused completion) says `unknown` (0030, "The OCSF attributes a class requires").
func userUID(rec map[string]any) string {
	u, _ := rec["user"].(map[string]any)
	s, _ := u["uid"].(string)
	return s
}
