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
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// multiAlgPolicy declares one client and one resource per case this
// package's signing tests need to tell apart: a default row, a row
// pinned to RS256, and — for Back-Channel Logout — a client that asks
// for it. "everyone" and "ci" are two disjoint ways in, so a sign-in's
// proof can reach the client/resource rows and a CI proof can reach the
// exchange rows, exactly as a real installation's two kinds of caller
// would.
func multiAlgPolicy(backchannelURI string) string {
	return `
version: 1
lifetimes:
  default: 1h
groups:
  everyone:
    matchers:
      - email: ada@north.example
  ci:
    matchers:
      - github: { owner: example-org }
clients:
  local-dev:
    kind: public
    redirects: ["http://localhost:8000/callback"]
    requires: ["everyone"]
  backchannel-rs256:
    kind: public
    redirects: ["http://localhost:8000/callback"]
    requires: ["everyone"]
    signing_alg: RS256
    backchannel_logout_uri: ` + backchannelURI + `
  svc-default:
    kind: exchange
    requires: ["ci"]
  svc-rs256:
    kind: exchange
    requires: ["ci"]
    signing_alg: RS256
  mint-default:
    kind: exchange
    requires: ["everyone"]
  mint-rs256:
    kind: exchange
    requires: ["everyone"]
    signing_alg: RS256
resources:
  "https://resource.example/rs256":
    requires: ["everyone"]
    signing_alg: RS256
  "https://resource.example/default":
    requires: ["everyone"]
`
}

// newMultiAlgServer brings up the real issuer, over the real library,
// with TWO signing keys at once: the primary (ES384, this installation's
// default) and one additional (RS256) — so every mint path in
// [multiAlgPolicy] can be driven through the actual code and its real
// signed output inspected, exactly as a relying party would see it.
//
// told is where a Back-Channel Logout token lands, for the one test that
// needs it; every other test simply never reads from it.
func newMultiAlgServer(t *testing.T) (server *httptest.Server, told <-chan string, primary, rsaKey *issuer.SigningKey) {
	t.Helper()

	toldCh := make(chan string, 8)
	backchannel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		toldCh <- r.Form.Get("logout_token")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backchannel.Close)

	declared, err := policy.Parse([]byte(multiAlgPolicy(backchannel.URL + "/backchannel")))
	if err != nil {
		t.Fatalf("parse the policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}

	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {Found: true, Authoritative: true},
	}}
	state := issuer.NewMemoryState()
	iss := issuer.New(issuer.Config{URL: "http://issuer.example", AllowInsecure: true}, set, dir, state)

	primary, err = issuer.NewSigningKey() // P-384 / ES384, matching the chart's own default
	if err != nil {
		t.Fatal(err)
	}
	rsaKey = rsaSigningKey(t) // defined in keyring_test.go, same test binary

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, primary, []*issuer.SigningKey{rsaKey}, state)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	handler, err := issuer.HandlerWithSignIn(iss, storage, issuer.SignInDeps{
		Providers: []issuer.SignIn{oneProvider{email: "ada@north.example"}},
		State:     access.NewStateCodec([]byte("a-test-key-for-signing-state"), 0),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	server = httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server, toldCh, primary, rsaKey
}

// verifiedHeader fetches the server's REAL published JWKS, verifies raw
// against whichever key its own `kid` names, and returns the token's
// header and claims. Verifying — not merely decoding, the way [jwtPart]
// elsewhere in this package does for a token whose shape is the only
// thing under test — is the point here: the header's `alg` and `kid` are
// exactly what a relying party keys its trust on, and a mismatch between
// what a token CLAIMS and what actually verifies is the one failure mode
// worth ruling out first.
func verifiedHeader(t *testing.T, server *httptest.Server, raw string) (header, claims map[string]any) {
	t.Helper()

	resp, err := http.Get(server.URL + "/keys") //nolint:noctx,gosec // a test server, fetched once per call
	if err != nil {
		t.Fatalf("fetch the JWKS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		t.Fatalf("decode the JWKS: %v", err)
	}

	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		t.Fatalf("parse the token: %v", err)
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("token carries %d signatures, want 1", len(parsed.Signatures))
	}
	sig := parsed.Signatures[0]

	var matched *jose.JSONWebKey
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == sig.Header.KeyID {
			matched = &keys.Keys[i]
			break
		}
	}
	if matched == nil {
		t.Fatalf("kid %q is not among the published keys", sig.Header.KeyID)
	}

	payload, err := parsed.Verify(matched)
	if err != nil {
		t.Fatalf("the token did not verify against its own published key: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("decode claims: %v", err)
	}

	return map[string]any{"alg": string(sig.Header.Algorithm), "kid": sig.Header.KeyID}, out
}

// audMatches reads `aud` whichever shape the library rendered it in — a
// bare string for one audience, or a one-element array — the same
// leniency [TestTokenExchangeMintsTheGatedAudience] already needs.
func audMatches(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		return len(v) == 1 && v[0] == want
	default:
		return false
	}
}

// audContains is [audMatches] for an ID token specifically: the library's
// own [oidc.NewIDTokenClaims] always folds the client id into `aud`
// alongside whatever [op.IDTokenRequest.GetAudience] returned (RFC-required
// once a resource makes it more than one value), so an ID token minted
// for a request that named a resource carries BOTH — this only checks
// that the client is among them, which is the one fact the signing
// algorithm decision actually depends on.
func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, one := range v {
			if one == want {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// The core acceptance for the authorize/code-exchange path: an ACCESS
// token follows the RESOURCE it was minted for, and the ID token — whose
// audience is always the client, never a resource — follows the CLIENT
// instead, even though both were minted for the SAME request a moment
// apart. The easy way to get this wrong is [Storage.SigningKey] reading
// back whichever one the ACCESS token already marked; this is the test
// that would catch it.
func TestSigningCodeExchangeAccessTokenFollowsResourceIDTokenFollowsClient(t *testing.T) {
	t.Parallel()
	server, _, primary, rsaKey := newMultiAlgServer(t)

	b := newBrowser(t, server)
	b.signIn()

	tokens := redeem(t, b, b.authorize("&resource="+url.QueryEscape("https://resource.example/rs256")))

	access, accessClaims := verifiedHeader(t, server, tokens["access_token"].(string))
	if access["alg"] != string(jose.RS256) {
		t.Errorf("access token alg = %v, want RS256 — the resource's own signing_alg", access["alg"])
	}
	if access["kid"] != rsaKey.ID() {
		t.Errorf("access token kid = %v, want the RSA key %s, never an EC key", access["kid"], rsaKey.ID())
	}
	if !audMatches(accessClaims["aud"], "https://resource.example/rs256") {
		t.Errorf("access token aud = %v, want the resource", accessClaims["aud"])
	}

	idToken, idClaims := verifiedHeader(t, server, tokens["id_token"].(string))
	if idToken["alg"] != string(jose.ES384) {
		t.Errorf("ID token alg = %v, want ES384 — the CLIENT's default, never the resource's RS256", idToken["alg"])
	}
	if idToken["kid"] != primary.ID() {
		t.Errorf("ID token kid = %v, want the default key %s", idToken["kid"], primary.ID())
	}
	if !audContains(idClaims["aud"], "local-dev") {
		t.Errorf("ID token aud = %v, want the client among it", idClaims["aud"])
	}
	if idClaims["azp"] != "local-dev" {
		t.Errorf("ID token azp = %v, want the client", idClaims["azp"])
	}
}

// The other half of the same guarantee, made explicit: a client that
// names no `signing_alg` and asks for no resource gets the installation
// DEFAULT on both tokens — not merely "not RS256", but exactly the
// primary key, so a carrier that silently stayed unmarked would still be
// caught by the wrong `kid`.
func TestSigningDefaultAudienceGetsTheDefaultAlgorithm(t *testing.T) {
	t.Parallel()
	server, _, primary, _ := newMultiAlgServer(t)

	b := newBrowser(t, server)
	b.signIn()

	tokens := redeem(t, b, b.authorize(""))

	for _, name := range []string{"access_token", "id_token"} {
		header, _ := verifiedHeader(t, server, tokens[name].(string))
		if header["alg"] != string(jose.ES384) {
			t.Errorf("%s alg = %v, want the installation default ES384", name, header["alg"])
		}
		if header["kid"] != primary.ID() {
			t.Errorf("%s kid = %v, want the default key %s", name, header["kid"], primary.ID())
		}
	}
}

// A refresh reissues an access token for the SAME audience the original
// carried, algorithm included — a session opened against a resource does
// not quietly drift back to the client's own default the next time it is
// renewed.
func TestSigningRefreshFollowsTheSameAudienceAsTheOriginalToken(t *testing.T) {
	t.Parallel()
	server, _, _, rsaKey := newMultiAlgServer(t)

	b := newBrowser(t, server)
	b.signIn()

	tokens := redeem(t, b, b.authorizeWith(map[string]string{"scope": "openid offline_access"}, ""+
		"&resource="+url.QueryEscape("https://resource.example/rs256")))
	refreshToken, _ := tokens["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("no refresh token in the response; this test needs one to renew")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"local-dev"},
	}
	resp, err := http.Post(server.URL+"/token", //nolint:noctx // a test
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var renewed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&renewed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh answered %d: %v", resp.StatusCode, renewed)
	}

	header, claims := verifiedHeader(t, server, renewed["access_token"].(string))
	if header["alg"] != string(jose.RS256) {
		t.Errorf("renewed access token alg = %v, want RS256 — the resource the session was opened for", header["alg"])
	}
	if header["kid"] != rsaKey.ID() {
		t.Errorf("renewed access token kid = %v, want the RSA key %s", header["kid"], rsaKey.ID())
	}
	if !audMatches(claims["aud"], "https://resource.example/rs256") {
		t.Errorf("renewed aud = %v, want the resource to survive the refresh", claims["aud"])
	}
}

// Token exchange keys on the GRANTED target, never the client presenting
// the exchange — "local-dev" is who is asking, "svc-rs256" is who the
// token is FOR, and if [Storage.SigningKey] ever read the wrong one this
// would mint an ES384 token (local-dev's non-existent default, since it
// names none) that happens to look identical to a correct one for the
// DEFAULT case, which is why this test checks BOTH targets, not just one.
func TestSigningTokenExchangeFollowsTheGrantedTargetNotTheCaller(t *testing.T) {
	t.Parallel()
	server, _, primary, rsaKey := newMultiAlgServer(t)

	const proof = "github:example-org/gitops@refs/heads/master"

	status, body := exchange(t, server, proof, "svc-rs256")
	if status != http.StatusOK {
		t.Fatalf("exchange to svc-rs256: %d %v", status, body)
	}
	raw, _ := body["access_token"].(string)
	header, claims := verifiedHeader(t, server, raw)
	if header["alg"] != string(jose.RS256) {
		t.Errorf("alg = %v, want RS256 for svc-rs256", header["alg"])
	}
	if header["kid"] != rsaKey.ID() {
		t.Errorf("kid = %v, want the RSA key %s", header["kid"], rsaKey.ID())
	}
	if !audMatches(claims["aud"], "svc-rs256") {
		t.Errorf("aud = %v, want the granted target, not the caller local-dev", claims["aud"])
	}

	status, body = exchange(t, server, proof, "svc-default")
	if status != http.StatusOK {
		t.Fatalf("exchange to svc-default: %d %v", status, body)
	}
	raw, _ = body["access_token"].(string)
	header, _ = verifiedHeader(t, server, raw)
	if header["alg"] != string(jose.ES384) {
		t.Errorf("alg = %v, want the installation default for svc-default", header["alg"])
	}
	if header["kid"] != primary.ID() {
		t.Errorf("kid = %v, want the default key", header["kid"])
	}
}

// A Back-Channel Logout token's whole audience is the RECEIVING client,
// which is a client row exactly like any other and reads its own
// `signing_alg` the same way — resolved directly, with no context to
// carry it through, because [Storage.mintLogoutToken] already holds its
// target and never asks the library for a signing key at all.
func TestSigningBackChannelLogoutFollowsTheReceivingClient(t *testing.T) {
	t.Parallel()
	server, told, _, rsaKey := newMultiAlgServer(t)

	b := newBrowser(t, server)
	b.signIn()

	// `openid` alone: this client holds no refresh token, and is still
	// told — see [TestBackChannelLogoutTellsAClientThatHoldsNoRefreshToken]
	// for why that is the interesting case to sign out from.
	redeemAs(t, b, "backchannel-rs256", b.authorizeWith(map[string]string{
		"client_id": "backchannel-rs256",
		"scope":     "openid",
	}, ""))

	b.do(http.MethodGet, "/logout")

	var raw string
	select {
	case raw = <-told:
	case <-time.After(3 * time.Second):
		t.Fatal("no logout token arrived")
	}

	header, claims := verifiedHeader(t, server, raw)
	if header["alg"] != string(jose.RS256) {
		t.Errorf("logout token alg = %v, want RS256 — backchannel-rs256's own signing_alg", header["alg"])
	}
	if header["kid"] != rsaKey.ID() {
		t.Errorf("logout token kid = %v, want the RSA key %s", header["kid"], rsaKey.ID())
	}
	if claims["aud"] != "backchannel-rs256" {
		t.Errorf("logout token aud = %v, want the receiving client", claims["aud"])
	}
}

// MintFor signs directly, with no library and no context carrier: it
// already holds its own target audience, so it resolves the algorithm
// for it the same direct way [Storage.mintLogoutToken] does. Two targets,
// exactly as the token exchange test above, so a carrier-shaped bug could
// not hide behind "it always happens to be the default".
func TestSigningMintForFollowsItsOwnTargetAudience(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(multiAlgPolicy("https://unused.example/backchannel")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {Found: true, Authoritative: true},
	}}
	state := issuer.NewMemoryState()
	iss := issuer.New(issuer.Config{URL: "https://issuer.example"}, set, dir, state)

	primary, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := rsaSigningKey(t)
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, primary, []*issuer.SigningKey{rsaKey}, state)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	ctx := context.Background()
	keys, err := storage.KeySet(ctx)
	if err != nil {
		t.Fatalf("KeySet: %v", err)
	}

	rsToken, _, err := storage.MintFor(ctx, "ada@north.example", "mint-rs256", time.Minute)
	if err != nil {
		t.Fatalf("MintFor mint-rs256: %v", err)
	}
	header, claims := verifyMinted(t, keys, rsToken)
	if header["alg"] != string(jose.RS256) || header["kid"] != rsaKey.ID() {
		t.Errorf("MintFor mint-rs256: alg/kid = %v/%v, want RS256 / %s", header["alg"], header["kid"], rsaKey.ID())
	}
	if !audMatches(claims["aud"], "mint-rs256") {
		t.Errorf("aud = %v, want mint-rs256", claims["aud"])
	}

	defaultToken, _, err := storage.MintFor(ctx, "ada@north.example", "mint-default", time.Minute)
	if err != nil {
		t.Fatalf("MintFor mint-default: %v", err)
	}
	header, _ = verifyMinted(t, keys, defaultToken)
	if header["alg"] != string(jose.ES384) || header["kid"] != primary.ID() {
		t.Errorf("MintFor mint-default: alg/kid = %v/%v, want ES384 / %s", header["alg"], header["kid"], primary.ID())
	}
}

// verifyMinted is [verifiedHeader] over a [Storage.KeySet] snapshot
// rather than an HTTP JWKS fetch, for a caller — [Storage.MintFor] — that
// has no server to ask.
// redeemAs is [redeem] for a client OTHER than "local-dev" — [redeem]
// itself hardcodes that id in the token request, which is right for
// every test that authorizes as it and wrong for
// [TestSigningBackChannelLogoutFollowsTheReceivingClient], which has to
// sign in as the client that asked to be told about its own sign-out.
func redeemAs(t *testing.T, b *browser, clientID, sentTo string) map[string]any {
	t.Helper()

	for strings.HasPrefix(sentTo, "/") {
		_, sentTo, _ = b.do(http.MethodGet, sentTo)
	}

	back, err := url.Parse(sentTo)
	if err != nil || back.Query().Get("code") == "" {
		t.Fatalf("the browser was sent to %q, want the callback with a code", sentTo)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {back.Query().Get("code")},
		"redirect_uri":  {"http://localhost:8000/callback"},
		"client_id":     {clientID},
		"code_verifier": {pkceVerifier},
	}

	response, err := http.Post(b.server.URL+"/token", //nolint:noctx // a test
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("token response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("redeem answered %d: %v", response.StatusCode, body)
	}

	return body
}

func verifyMinted(t *testing.T, keys []op.Key, raw string) (header, claims map[string]any) {
	t.Helper()

	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		t.Fatalf("parse the token: %v", err)
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("token carries %d signatures, want 1", len(parsed.Signatures))
	}
	sig := parsed.Signatures[0]

	var match op.Key
	for _, key := range keys {
		if key.ID() == sig.Header.KeyID {
			match = key
			break
		}
	}
	if match == nil {
		t.Fatalf("kid %q is not among the published keys", sig.Header.KeyID)
	}

	jwk := &jose.JSONWebKey{Key: match.Key(), KeyID: match.ID(), Algorithm: string(match.Algorithm())}
	payload, err := parsed.Verify(jwk)
	if err != nil {
		t.Fatalf("the token did not verify against its own published key: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("decode claims: %v", err)
	}

	return map[string]any{"alg": string(sig.Header.Algorithm), "kid": sig.Header.KeyID}, out
}

// A `signing_alg` naming an algorithm this installation has no key
// configured for is refused loudly, AT START — never a silent fall back
// to the default, which is exactly what an operator would never notice
// until a relying party that demanded RS256 started rejecting tokens.
func TestSigningAlgWithNoConfiguredKeyRefusesAtStart(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"client": "version: 1\ngroups: { a: { members: [g@h.example] } }\n" +
			"clients: { c: { kind: public, requires: [a], redirects: ['https://a.example/cb'], signing_alg: RS256 } }\n",
		"resource": "version: 1\ngroups: { a: { members: [g@h.example] } }\n" +
			"resources: { 'https://a.example/': { requires: [a], signing_alg: RS256 } }\n",
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			declared, err := policy.Parse([]byte(doc))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			set, err := policy.NewSet(declared)
			if err != nil {
				t.Fatalf("set: %v", err)
			}
			iss := issuer.New(issuer.Config{URL: "https://issuer.example"}, set, nil, issuer.NewMemoryState())

			// Only the installation default (ES384) is configured -- no
			// RS256 key anywhere -- so the RS256 pin above must refuse
			// construction rather than let the FIRST request to reach it
			// discover the gap.
			_, err = issuer.NewStorage(iss, nil, nil, nil, nil, nil)
			if err == nil {
				t.Fatalf("%s naming signing_alg: RS256 with no RS256 key configured was accepted", name)
			}
			if !strings.Contains(err.Error(), "RS256") {
				t.Errorf("refusal %q does not name the missing algorithm", err)
			}
		})
	}
}
