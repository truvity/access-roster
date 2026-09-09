package issuer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// fakeVerifier stands in for GitHub's keys and the organisation
// allow-list, or for a TokenReview. What it returns is a proof, never a
// permission: everything after verification is policy, which is exactly
// the seam this test exercises.
type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, token, _ string) (issuer.Proof, error) {
	// "github:<owner>/<repo>@<ref>" and "k8s:<namespace>/<name>" stand in
	// for tokens the real verifiers would have checked signatures on.
	switch {
	case strings.HasPrefix(token, "github:"):
		rest := strings.TrimPrefix(token, "github:")
		repo, ref, ok := strings.Cut(rest, "@")
		if !ok {
			return issuer.Proof{}, issuer.ErrUnverified
		}
		owner, _, _ := strings.Cut(repo, "/")
		return issuer.Proof{GitHub: &policy.GitHubClaims{Repository: repo, Owner: owner, Ref: ref}}, nil
	case strings.HasPrefix(token, "k8s:"):
		ns, name, ok := strings.Cut(strings.TrimPrefix(token, "k8s:"), "/")
		if !ok {
			return issuer.Proof{}, issuer.ErrUnverified
		}
		return issuer.Proof{ServiceAccount: &policy.ServiceAccountRef{Namespace: ns, Name: name}}, nil
	default:
		return issuer.Proof{}, issuer.ErrUnverified
	}
}

// serveIssuer brings up the real OpenID surface over the real storage,
// so that what this test exercises is the library and our storage
// together — the half of the design that unit tests cannot reach.
func serveIssuer(t *testing.T) (*httptest.Server, *issuer.Issuer) {
	t.Helper()

	return serveIssuerFor(t, &fakeDirectory{})
}

// serveIssuerFor is the same over a named directory, for the tests whose
// subject is what the issuer says about a person it can vouch for.
func serveIssuerFor(t *testing.T, dir issuer.Directory) (*httptest.Server, *issuer.Issuer) {
	t.Helper()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("parse the demonstration policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	iss := issuer.New(issuer.Config{URL: "http://issuer.example", AllowInsecure: true}, set, dir, issuer.NewMemoryState())

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	handler, err := issuer.Handler(iss, storage)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, iss
}

// exchange posts one RFC 8693 token exchange and returns the response.
func exchange(t *testing.T, server *httptest.Server, subjectToken, audience string) (int, map[string]any) {
	t.Helper()

	form := url.Values{
		"grant_type":         {string(oidc.GrantTypeTokenExchange)},
		"subject_token":      {subjectToken},
		"subject_token_type": {string(oidc.JWTTokenType)},
		"audience":           {audience},
		"scope":              {"openid"},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		server.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The library reads the exchange's client credentials from HTTP Basic
	// alone — unlike the code grant, it never looks at a posted client_id.
	// A public client therefore authenticates as its id with an empty
	// password, which is what the GitHub Action will have to send.
	req.SetBasicAuth("local-dev", "")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("post the exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	return resp.StatusCode, body
}

// claimsOf verifies an access token against the issuer's published JWKS
// and returns its claims. Verifying rather than merely decoding is the
// point: a relying party will verify offline, and if that does not work
// the token is worthless however good its contents look.
func claimsOf(t *testing.T, server *httptest.Server, raw string) map[string]any {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/keys", nil)
	if err != nil {
		t.Fatalf("build the JWKS request: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("fetch the JWKS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		t.Fatalf("decode the JWKS: %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("the JWKS carries %d keys, want one", len(keys.Keys))
	}

	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse the access token: %v", err)
	}
	payload, err := parsed.Verify(keys.Keys[0])
	if err != nil {
		t.Fatalf("verify the access token against the published key: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode the claims: %v", err)
	}
	return claims
}

// The design's central claim, end to end through the real library: a CI
// job exchanges its own identity token for one whose audience is the AWS
// role, and gets it only because a rule admits it.
func TestTokenExchangeMintsTheGatedAudience(t *testing.T) {
	t.Parallel()
	server, iss := serveIssuer(t)

	status, body := exchange(t, server, "github:example-org/gitops@refs/heads/master", "aws:1111:deployer")
	if status != http.StatusOK {
		t.Fatalf("exchange on master: %d %v", status, body)
	}
	raw, _ := body["access_token"].(string)
	if raw == "" {
		t.Fatalf("no access token in %v", body)
	}
	if got, _ := body["issued_token_type"].(string); got != string(oidc.AccessTokenType) {
		t.Errorf("issued_token_type = %q", got)
	}

	claims := claimsOf(t, server, raw)

	// The audience is the decision. A cloud trust policy for a custom
	// issuer can see only sub, aud, amr and email, so this field is what
	// the AWS role's trust policy will name, and nothing else in the
	// token can stand in for it.
	switch aud := claims["aud"].(type) {
	case string:
		if aud != "aws:1111:deployer" {
			t.Errorf("aud = %q", aud)
		}
	case []any:
		if len(aud) != 1 || aud[0] != "aws:1111:deployer" {
			t.Errorf("aud = %v, want exactly the requested role", aud)
		}
	default:
		t.Errorf("aud is %T: %v", aud, claims["aud"])
	}

	// The subject is the repository. The person who pushed is not the
	// principal here, and an audit that cannot tell them apart is
	// worthless.
	if sub, _ := claims["sub"].(string); sub != "github:example-org/gitops" {
		t.Errorf("sub = %q, want the repository", sub)
	}
	if iss, _ := claims["iss"].(string); iss != "http://issuer.example" {
		t.Errorf("iss = %q", iss)
	}

	// The groups claim is what a relying party reads, and it carries the
	// internal group names rather than any directory address.
	groups, _ := claims["groups"].([]any)
	var names []string
	for _, g := range groups {
		names = append(names, g.(string))
	}
	if !contains(names, "all:gitops:deployer") || !contains(names, "all:gitops:builder") {
		t.Errorf("groups = %v, want both rules the job matches", names)
	}
	for _, name := range names {
		if strings.Contains(name, "@") {
			t.Errorf("groups leak a directory address: %q", name)
		}
	}

	// all:gitops:builder says 30 minutes and is the shortest the job holds, so
	// the token lives that long and not the hour the issuer would default
	// to.
	if expires, ok := body["expires_in"].(float64); !ok || expires > 30*60 || expires < 29*60 {
		t.Errorf("expires_in = %v, want the shortest lifetime across the rules", body["expires_in"])
	}

	// No session is recorded, and that is the right answer rather than a
	// gap: an exchange yields an access token and no refresh token, so
	// there is nothing outstanding to list or revoke. The job's access
	// ends when the token expires, half an hour from now, whether or not
	// anyone remembers to end it. A CI job holding a refresh token would
	// be a standing credential on a machine that should have none.
	sessions, err := iss.Sessions().List(context.Background(), issuer.Query{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(sessions) != 0 {
		t.Errorf("an exchange left %d sessions behind, want none", len(sessions))
	}
}

// The case that must fail: the same repository on a branch anyone with a
// fork can push. It matches only the owner-wide rule, which opens no
// client, so the audience is refused rather than minted.
func TestTokenExchangeRefusesAnUngatedAudience(t *testing.T) {
	t.Parallel()
	server, _ := serveIssuer(t)

	status, body := exchange(t, server, "github:example-org/gitops@refs/heads/patch-1", "aws:1111:deployer")
	if status == http.StatusOK {
		t.Fatalf("a fork branch was issued a deployer token: %v", body)
	}
	if got, _ := body["error"].(string); got != "invalid_target" {
		t.Errorf("error = %q, want invalid_target", got)
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(desc, "all:gitops:deployer") {
		t.Errorf("error_description = %q, want it to name what would have admitted the job", desc)
	}

	// An audience that does not exist is a different answer from one the
	// caller may not have, and neither leaks the other.
	status, body = exchange(t, server, "github:example-org/gitops@refs/heads/master", "aws:9999:nobody")
	if status == http.StatusOK {
		t.Fatalf("an undeclared audience was minted: %v", body)
	}

	// A token no verifier recognises is refused before policy is ever
	// consulted.
	status, body = exchange(t, server, "not-a-token", "aws:1111:deployer")
	if status == http.StatusOK {
		t.Fatalf("an unverified subject token was accepted: %v", body)
	}
}

// Discovery is what every relying party reads first, and what the
// conformance suite checks before anything else.
func TestDiscoveryDescribesWhatIsServed(t *testing.T) {
	t.Parallel()
	server, _ := serveIssuer(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		server.URL+"/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("fetch discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	if got, _ := doc["issuer"].(string); got != "http://issuer.example" {
		t.Errorf("issuer = %q", got)
	}
	for _, endpoint := range []string{"token_endpoint", "jwks_uri", "revocation_endpoint", "end_session_endpoint"} {
		if _, ok := doc[endpoint]; !ok {
			t.Errorf("discovery does not advertise %s", endpoint)
		}
	}

	var grants []string
	for _, g := range doc["grant_types_supported"].([]any) {
		grants = append(grants, g.(string))
	}
	for _, want := range []string{
		string(oidc.GrantTypeCode), string(oidc.GrantTypeRefreshToken),
		string(oidc.GrantTypeTokenExchange), string(oidc.GrantTypeDeviceCode),
	} {
		if !contains(grants, want) {
			t.Errorf("discovery does not advertise %s", want)
		}
	}

	// The implicit flow is deliberately not served: it puts tokens in a
	// redirect, which is what PKCE exists to stop needing.
	var responses []string
	for _, r := range doc["response_types_supported"].([]any) {
		responses = append(responses, r.(string))
	}
	if contains(responses, "token") || contains(responses, "id_token token") {
		t.Errorf("the implicit flow is advertised: %v", responses)
	}
}

// Revocation is the mechanism under both Revoke in the console and a
// person's own sign-out-everywhere, and RFC 7009 asks that it be
// idempotent.
func TestRevocationEndsTheSession(t *testing.T) {
	t.Parallel()
	server, iss := serveIssuer(t)
	sessions := iss.Sessions()

	if _, err := sessions.Record(t.Context(), issuer.Opened{
		Identity: "ada@north.example", ClientID: "argocd", How: issuer.HowCode, Token: "refresh-1",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	post := func(token string) int {
		form := url.Values{"token": {token}}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			server.URL+"/revoke", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("build the request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("local-dev", "")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("post the revocation: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	if status := post("refresh-1"); status != http.StatusOK {
		t.Fatalf("revoke: %d", status)
	}
	left, err := sessions.List(t.Context(), issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(left) != 0 {
		t.Errorf("the session survived revocation: %d left", len(left))
	}
	// Revoking again must succeed: telling a caller whether a token they
	// do not hold ever existed is itself a disclosure.
	if status := post("refresh-1"); status != http.StatusOK {
		t.Errorf("revoking twice: %d, want it to be idempotent", status)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

var _ = time.Second
