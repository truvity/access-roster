//go:build sluis_test

package sessiond_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// goldenDiscovery reads the discovery document that entry serves, as entry's own tests hold it (a golden file): the
// claims in it about sign-in are session's to keep, and these tests hold session to them. Editing the file without the
// behaviour, or the behaviour without the file, fails here.
func goldenDiscovery(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../../entry/tests/testdata/discovery.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func listed(t *testing.T, doc map[string]any, field string) []string {
	t.Helper()
	raw, ok := doc[field].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("%s is not a list in the golden document", field)
	}
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i], _ = v.(string)
	}
	return out
}

// refusedWith is the error that an authorize request gets in its redirect, "" when it is accepted (sent on to the upstream).
func (e *env) refusedWith(edit func(*sessionv2alpha1.AuthorizeRequest)) string {
	e.t.Helper()
	p := newAuthorize()
	edit(p.req)
	u := location(e.t, e.authorize(p.req))
	if u.Query().Get("iss") == testIssuer && u.Query().Get("error") == "" {
		e.t.Fatalf("a redirect to the client without an error: %s", u)
	}
	return u.Query().Get("error")
}

// The authorization endpoint accepts each response type, response mode and PKCE method that the discovery document
// lists, and refuses the ones it does not list: a relying party that configures itself from the document gets the
// behaviour it was told of.
//
// verifies: REQ-AUTHN-006
func TestDiscoveryListsTheResponseTypesModesAndChallengeMethodsThatAuthorizeServes(t *testing.T) {
	doc := goldenDiscovery(t)
	e := newEnv(t, nil)

	types := listed(t, doc, "response_types_supported")
	for _, v := range types {
		if got := e.refusedWith(func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseType = v }); got != "" {
			t.Errorf("response_type %q is listed and refused: %s", v, got)
		}
	}
	for _, v := range []string{"token", "id_token", "none", "code token", "code id_token", "code id_token token", "id_token token"} {
		if slices.Contains(types, v) {
			t.Errorf("response_type %q is listed", v)
			continue
		}
		if got := e.refusedWith(func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseType = v }); got != "unsupported_response_type" {
			t.Errorf("response_type %q: %q", v, got)
		}
	}

	modes := listed(t, doc, "response_modes_supported")
	for _, v := range modes {
		if got := e.refusedWith(func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseMode = v }); got != "" {
			t.Errorf("response_mode %q is listed and refused: %s", v, got)
		}
	}
	for _, v := range []string{"fragment", "form_post", "query.jwt", "fragment.jwt", "form_post.jwt", "jwt", "web_message"} {
		if slices.Contains(modes, v) {
			t.Errorf("response_mode %q is listed", v)
			continue
		}
		if got := e.refusedWith(func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseMode = v }); got != "invalid_request" {
			t.Errorf("response_mode %q: %q", v, got)
		}
	}

	methods := listed(t, doc, "code_challenge_methods_supported")
	for _, v := range methods {
		if got := e.refusedWith(func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallengeMethod = v }); got != "" {
			t.Errorf("code_challenge_method %q is listed and refused: %s", v, got)
		}
	}
	for _, v := range []string{"plain", "S512", "s256", "S256 "} {
		if slices.Contains(methods, v) {
			t.Errorf("code_challenge_method %q is listed", v)
			continue
		}
		if got := e.refusedWith(func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallengeMethod = v }); got != "invalid_request" {
			t.Errorf("code_challenge_method %q: %q", v, got)
		}
	}
}

// The document says whether the issuer is in every authorization response (RFC 9207 section 3), and it is: a code, an
// error from session itself and an error that the upstream returned are all redirected with iss, so the claim must be
// true. A document that left the field out would say false, which this fails.
//
// verifies: REQ-AUTHN-006
func TestDiscoveryAdvertisesTheIssuerParameterBecauseEveryRedirectCarriesIt(t *testing.T) {
	doc := goldenDiscovery(t)
	claim, _ := doc["authorization_response_iss_parameter_supported"].(bool)

	e := newEnv(t, nil)
	carries := func(name string, got string) bool {
		t.Helper()
		if got != "" && got != testIssuer {
			t.Errorf("%s: iss = %q, want %q", name, got, testIssuer)
		}
		return got == testIssuer
	}
	all := true

	// An error of session's own, after the redirect_uri is the client's.
	p := newAuthorize()
	p.req.ResponseType = "token"
	all = carries("authorize error", location(t, e.authorize(p.req)).Query().Get("iss")) && all

	// A code, and an error that the upstream answered with.
	cb, _ := e.started()
	all = carries("code", location(t, e.callback(cb)).Query().Get("iss")) && all
	cb, _ = e.started()
	cb.Code, cb.Error = "", "access_denied"
	all = carries("upstream error", location(t, e.callback(cb)).Query().Get("iss")) && all

	if claim != all {
		t.Errorf("the document says authorization_response_iss_parameter_supported = %v; every redirect carries iss = %v", claim, all)
	}
}

// The document lists the subject types of the ID tokens that session issues. A person's subject at a tenant is the
// pairwise one (ADR 0034: a keyed hash of the sector and the person); the public one, the person's own id, is for a sector
// declared public, and the first version has no Tenant item to declare it. So the list is pairwise and no more.
//
// verifies: REQ-AUTHN-006
func TestDiscoveryListsPairwiseBecauseThatIsTheSubjectSessionIssues(t *testing.T) {
	types := listed(t, goldenDiscovery(t), "subject_types_supported")
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	_, id := tokenClaims(t, b["id_token"].(string))
	person := e.store.ids("person", testTenant)[0]
	sub, _ := id["sub"].(string)
	if sub == "" || sub == person {
		t.Fatalf("sub = %q, person %q: not pairwise", sub, person)
	}
	if !slices.Contains(types, "pairwise") {
		t.Errorf("subject_types_supported = %v, and sub is pairwise", types)
	}
	if slices.Contains(types, "public") {
		t.Errorf("subject_types_supported = %v lists public, and no tenant can declare it yet", types)
	}
}

// The issuer that session puts in iss (the ID token, the access token and the iss parameter of every redirect) is the
// boundary's issuer as written, byte for byte, whatever its form. entry's discovery document names the same string for
// the same boundary (its test takes the same issuers), so the two cannot differ.
//
// verifies: REQ-AUTHN-030
func TestTheIssClaimIsTheBoundarysIssuerByteForByte(t *testing.T) {
	for _, iss := range []string{
		"https://Sluis.Example.TEST:8443/tenant-a/v2",
		"https://sluis.example.test:443",
		"https://sluis.example.test/Tenant%2FA/%7e",
	} {
		t.Run(iss, func(t *testing.T) {
			e := newEnv(t, func(o *options) {
				o.boundary = &configv2alpha1.Boundary{Name: testBoundary, Environment: "development", Issuer: iss, DefaultTenant: testTenant}
			})
			p := newAuthorize()
			p.req.ResponseType = "token"
			if got := location(t, e.authorize(p.req)).Query().Get("iss"); got != iss {
				t.Errorf("iss of a redirect = %q", got)
			}
			code, p := e.signIn()
			b := body(t, e.token(codeRequest(code, p)))
			for _, tok := range []string{"id_token", "access_token"} {
				_, claims := tokenClaims(t, b[tok].(string))
				if claims["iss"] != iss {
					t.Errorf("%s iss = %q, want %q", tok, claims["iss"], iss)
				}
			}
		})
	}
}

// The scopes the discovery document lists are the scopes that session grants, and the ones it does not list are refused
// with invalid_scope, as are address and phone, which a client that reads no list may ask for. The parameters that
// OpenID Connect Core defines and session does not serve are answered with their own errors at the client's redirect,
// where the document says they are not supported (request_uri_parameter_supported false; request_parameter_supported and
// claims_parameter_supported are absent, so false).
//
// verifies: REQ-AUTHN-006
func TestDiscoveryListsTheScopesAuthorizeGrantsAndTheParametersItAnswersAsUnsupported(t *testing.T) {
	doc := goldenDiscovery(t)
	e := newEnv(t, nil)
	scopes := listed(t, doc, "scopes_supported")
	for _, sc := range scopes {
		if got := e.refusedWith(func(r *sessionv2alpha1.AuthorizeRequest) { r.Scope = "openid " + sc }); got != "" {
			t.Errorf("scope %q is listed and refused: %s", sc, got)
		}
	}
	for _, sc := range []string{"address", "phone", "offline_access", "groups", "email profile address"} {
		if slices.Contains(scopes, sc) {
			t.Fatalf("%q is listed", sc)
		}
		if got := e.refusedWith(func(r *sessionv2alpha1.AuthorizeRequest) { r.Scope = "openid " + sc }); got != "invalid_scope" {
			t.Errorf("scope %q is not listed and is answered %q", sc, got)
		}
	}
	if doc["request_uri_parameter_supported"] != false || doc["request_parameter_supported"] != nil || doc["claims_parameter_supported"] != nil {
		t.Fatalf("the document's claims about request objects changed: %v", doc)
	}
	for _, c := range []struct {
		edit func(*sessionv2alpha1.AuthorizeRequest)
		want string
	}{
		{func(r *sessionv2alpha1.AuthorizeRequest) { r.Request = "eyJhbGciOiJub25lIn0.e30." }, "request_not_supported"},
		{func(r *sessionv2alpha1.AuthorizeRequest) { r.RequestUri = "https://rp.example.test/request.jwt" }, "request_uri_not_supported"},
		{func(r *sessionv2alpha1.AuthorizeRequest) { r.Registration = "{}" }, "registration_not_supported"},
	} {
		if got := e.refusedWith(c.edit); got != c.want {
			t.Errorf("answered %q, want %q", got, c.want)
		}
	}
	// The answer goes to the registered redirect_uri only: an unknown client or a redirect_uri that is not registered gets
	// the fixed page, as for any request, and the request object is not read.
	p := newAuthorize()
	p.req.Request, p.req.RedirectUri = "eyJ", "https://evil.example.test/cb"
	if r := e.authorize(p.req); r.GetStatus() != 400 {
		t.Errorf("status %d for a request object to a redirect_uri that is not registered", r.GetStatus())
	}
}
