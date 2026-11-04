//go:build sluis_test

package exchanged_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/v2/actors/exchange/internal/exchanged"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
)

// idp is a trusted issuer: it publishes a key set and counts the fetches.
type idp struct {
	srv          *httptest.Server
	mu           sync.Mutex
	keys         map[string]*ecdsa.PrivateKey // kid -> key
	hits         int
	status       int
	cacheControl string
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	i := &idp{keys: map[string]*ecdsa.PrivateKey{}, status: 200, cacheControl: "max-age=600"}
	i.addKey(t, "k1")
	i.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.hits++
		if i.status != 200 {
			w.WriteHeader(i.status)
			return
		}
		if i.cacheControl != "" {
			w.Header().Set("Cache-Control", i.cacheControl)
		}
		w.Header().Set("Content-Type", "application/json")
		var set jose.JSONWebKeySet
		for kid, k := range i.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"})
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(i.srv.Close)
	return i
}

func (i *idp) addKey(t *testing.T, kid string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	i.keys[kid] = k
	i.mu.Unlock()
	return k
}

func (i *idp) fetches() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.hits
}

func (i *idp) trust(audiences ...string) *configv2alpha1.ExchangeTrust {
	if len(audiences) == 0 {
		audiences = []string{"sluis-dev"}
	}
	return &configv2alpha1.ExchangeTrust{Issuers: []*configv2alpha1.TrustedIssuer{
		{Issuer: i.srv.URL, Audiences: audiences, ProofKind: "github-oidc", JwksUri: i.srv.URL + "/jwks"},
	}}
}

// token signs a proof of the issuer.
func (i *idp) token(t *testing.T, kid string, over map[string]any) string {
	t.Helper()
	m := map[string]any{
		"iss": i.srv.URL, "sub": "repo:acme/app:ref:refs/tags/v1", "aud": "sluis-dev", "jti": "gh-job-1",
		"iat": t0.Add(-time.Minute).Unix(), "exp": t0.Add(9 * time.Minute).Unix(), "repository": "acme/app",
	}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	i.mu.Lock()
	k := i.keys[kid]
	i.mu.Unlock()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: k, KeyID: kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := jws.CompactSerialize()
	return c
}

func (e *env) verifier() *exchanged.Verifier { return e.verifierAt(func() time.Time { return t0 }) }

func (e *env) verifierAt(now func() time.Time) *exchanged.Verifier {
	return exchanged.NewVerifier(e.cfg, e.signerCl, now)
}

func devBoundary() *configv2alpha1.Boundary {
	return &configv2alpha1.Boundary{Name: testBoundary, Environment: "development", Issuer: testIssuer, DefaultTenant: testTenant}
}

// refusedReason checks that Verify refused the token as an answer, with this OAuth code and audit reason.
func refusedReason(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want the refusal %q", want)
	}
	if !strings.Contains(err.Error(), "invalid_request") || !strings.Contains(err.Error(), "("+want+")") {
		t.Fatalf("err = %v, want invalid_request (%s)", err, want)
	}
}

func TestATrustedIssuersProofIsVerifiedAndItsKeysAreKeptAsLongAsHTTPCachingAllows(t *testing.T) {
	i := newIDP(t)
	e := newEnv(t, envOptions{trust: i.trust()})
	v := e.verifier()

	s, err := v.Verify(context.Background(), i.token(t, "k1", nil), devBoundary())
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != "github-oidc" || s.Issuer != i.srv.URL || s.Subject != "repo:acme/app:ref:refs/tags/v1" || s.Audience != "sluis-dev" || s.JTI != "gh-job-1" || !s.Exp.Equal(t0.Add(9*time.Minute)) {
		t.Errorf("subject = %+v", s)
	}
	// The key set is in VerifierKeyCache for max-age, and the next proof does not fetch it again.
	id := hexSHA256(i.srv.URL)
	if ttl, ok := e.store.ttl("verifier-key-cache", id); !ok || ttl != 600*time.Second {
		t.Errorf("VerifierKeyCache ttl = %v (%v), want 10m", ttl, ok)
	}
	if _, err := v.Verify(context.Background(), i.token(t, "k1", map[string]any{"jti": "gh-job-2"}), devBoundary()); err != nil {
		t.Fatal(err)
	}
	if n := i.fetches(); n != 1 {
		t.Errorf("the issuer's keys were fetched %d times, want 1", n)
	}
}

func hexSHA256(s string) string { return sha256Hex(s) }

func TestACacheControlOfNoStoreKeepsNothing(t *testing.T) {
	i := newIDP(t)
	i.cacheControl = "no-store"
	e := newEnv(t, envOptions{trust: i.trust()})
	v := e.verifier()
	for _, jti := range []string{"a", "b"} {
		if _, err := v.Verify(context.Background(), i.token(t, "k1", map[string]any{"jti": jti}), devBoundary()); err != nil {
			t.Fatal(err)
		}
	}
	if e.store.has("verifier-key-cache", hexSHA256(i.srv.URL)) || i.fetches() != 2 {
		t.Errorf("keys kept (%v) or fetched %d times", e.store.has("verifier-key-cache", hexSHA256(i.srv.URL)), i.fetches())
	}
}

func TestTheKeyCacheNeverLastsLongerThanADay(t *testing.T) {
	i := newIDP(t)
	i.cacheControl = "public, max-age=999999999"
	e := newEnv(t, envOptions{trust: i.trust()})
	if _, err := e.verifier().Verify(context.Background(), i.token(t, "k1", nil), devBoundary()); err != nil {
		t.Fatal(err)
	}
	if ttl, _ := e.store.ttl("verifier-key-cache", hexSHA256(i.srv.URL)); ttl != 24*time.Hour {
		t.Errorf("ttl = %v, want 24h", ttl)
	}
}

func TestAProofWithAJtiIsAcceptedOnce(t *testing.T) {
	i := newIDP(t)
	e := newEnv(t, envOptions{trust: i.trust()})
	v := e.verifier()
	proof := i.token(t, "k1", nil)

	if _, err := v.Verify(context.Background(), proof, devBoundary()); err != nil {
		t.Fatal(err)
	}
	_, err := v.Verify(context.Background(), proof, devBoundary())
	refusedReason(t, err, "replay")

	// The mark is under exchange/, named by a hash, and lives as long as the proof is valid (9 minutes).
	h := sha512.New384()
	h.Write([]byte(i.srv.URL + "\x00gh-job-1"))
	id := "exchange/" + hex.EncodeToString(h.Sum(nil))
	if ttl, ok := e.store.ttl("replay-guard", id); !ok || ttl != 9*time.Minute {
		t.Errorf("ReplayGuard ttl = %v (%v), want 9m", ttl, ok)
	}
	// Another jti is another proof.
	if _, err := v.Verify(context.Background(), i.token(t, "k1", map[string]any{"jti": "gh-job-2"}), devBoundary()); err != nil {
		t.Fatal(err)
	}
}

func TestAProofWithNoJtiHasNothingToGuard(t *testing.T) {
	i := newIDP(t)
	e := newEnv(t, envOptions{trust: i.trust()})
	v := e.verifier()
	proof := i.token(t, "k1", map[string]any{"jti": nil})
	for range 2 {
		if _, err := v.Verify(context.Background(), proof, devBoundary()); err != nil {
			t.Fatal(err)
		}
	}
	if e.store.writes != 1 { // the key cache only
		t.Errorf("store writes = %d", e.store.writes)
	}
}

func TestAProofThatStaysValidLongerThanTheGuardCanRememberIsRefused(t *testing.T) {
	i := newIDP(t)
	e := newEnv(t, envOptions{trust: i.trust()})
	_, err := e.verifier().Verify(context.Background(), i.token(t, "k1", map[string]any{"exp": t0.Add(2 * time.Hour).Unix()}), devBoundary())
	refusedReason(t, err, "replay")
}

func TestATrustedProofIsRefusedForItsIssuerItsAudienceItsKeyAndItsTimes(t *testing.T) {
	i := newIDP(t)
	other := newIDP(t)
	e := newEnv(t, envOptions{trust: i.trust("sluis-dev", "sluis-other")})
	v := e.verifier()
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: a weak key on purpose; the verifier must refuse it
	if err != nil {
		t.Fatal(err)
	}
	weak, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: rsa1024, KeyID: "k1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	weakJWS, _ := weak.Sign([]byte(`{"iss":"` + i.srv.URL + `","sub":"s","aud":"sluis-dev","exp":` + itoa64(t0.Add(time.Minute).Unix()) + `}`))
	weakToken, _ := weakJWS.CompactSerialize()
	hs := base64.RawURLEncoding.EncodeToString
	mac := hmac.New(sha512.New384, []byte("k"))
	hsToken := hs([]byte(`{"alg":"HS384","kid":"k1"}`)) + "." + hs([]byte(`{"iss":"`+i.srv.URL+`"}`)) + "." + hs(mac.Sum(nil))

	cases := []struct{ name, token, reason string }{
		{"an issuer nobody trusts", other.token(t, "k1", map[string]any{"iss": other.srv.URL}), "issuer"},
		{"another audience", i.token(t, "k1", map[string]any{"aud": "sluis-prod"}), "claims"},
		{"signed by a key the issuer does not publish", func() string {
			k := other.keys["k1"]
			other.keys["rogue"] = k
			return other.token(t, "rogue", map[string]any{"iss": i.srv.URL})
		}(), "signature"},
		{"expired", i.token(t, "k1", map[string]any{"exp": t0.Add(-time.Second).Unix(), "jti": "e"}), "expired"},
		{"not yet valid", i.token(t, "k1", map[string]any{"nbf": t0.Add(time.Hour).Unix(), "jti": "n"}), "claims"},
		{"no subject", i.token(t, "k1", map[string]any{"sub": nil, "jti": "s"}), "claims"},
		{"a weak RSA key", weakToken, "signature"},
		{"an HMAC algorithm", hsToken, "signature"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), c.token, devBoundary())
			refusedReason(t, err, c.reason)
		})
	}
	// An audience that is an array, with one of the accepted ones in it, is accepted (RFC 7519 section 4.1.3).
	if _, err := v.Verify(context.Background(), i.token(t, "k1", map[string]any{"aud": []string{"x", "sluis-other"}, "jti": "arr"}), devBoundary()); err != nil {
		t.Errorf("an audience array was refused: %v", err)
	}
}

func itoa64(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestARotatedKeyIsFoundByOneFreshFetchAndAnUnknownKidCannotFloodTheIssuer(t *testing.T) {
	i := newIDP(t)
	e := newEnv(t, envOptions{trust: i.trust()})
	now := t0
	v := e.verifierAt(func() time.Time { return now })
	if _, err := v.Verify(context.Background(), i.token(t, "k1", nil), devBoundary()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute) // past the gap between fetches for an unknown kid
	// The issuer rotates. The cached set does not hold k2, so one fresh fetch finds it.
	i.addKey(t, "k2")
	if _, err := v.Verify(context.Background(), i.token(t, "k2", map[string]any{"jti": "r1"}), devBoundary()); err != nil {
		t.Fatal(err)
	}
	if n := i.fetches(); n != 2 {
		t.Errorf("fetches = %d, want 2", n)
	}
	// A kid the issuer never published: refused, and within the gap it does not fetch again.
	k := i.keys["k1"]
	i.keys["ghost"] = k
	ghost := i.token(t, "ghost", map[string]any{"jti": "g1"})
	delete(i.keys, "ghost")
	for range 3 {
		_, err := v.Verify(context.Background(), ghost, devBoundary())
		refusedReason(t, err, "signature")
	}
	if n := i.fetches(); n != 2 {
		t.Errorf("fetches = %d after unknown kids, want 2", n)
	}
}

func TestATrustedIssuerCannotBeGivenTheProofKindOfThisBoundarysOwnTokens(t *testing.T) {
	i := newIDP(t)
	trust := i.trust()
	trust.Issuers[0].ProofKind = exchanged.KindOwn
	e := newEnv(t, envOptions{trust: trust})
	_, err := e.verifier().Verify(context.Background(), i.token(t, "k1", nil), devBoundary())
	refusedReason(t, err, "issuer")
	if bad := e.svc.Check(context.Background()); len(bad) != 1 || bad[0] != "exchange_trust.issuers[0]" {
		t.Errorf("check = %v", bad)
	}
}

func TestAnIssuerThatDoesNotAnswerIsAnOutageAndNotAnAcceptedProof(t *testing.T) {
	i := newIDP(t)
	i.status = 500
	e := newEnv(t, envOptions{trust: i.trust()})
	_, err := e.verifier().Verify(context.Background(), i.token(t, "k1", nil), devBoundary())
	if err == nil || !strings.Contains(err.Error(), "unavailable: issuer_keys") {
		t.Fatalf("err = %v", err)
	}
}

func TestOutsideADevelopmentBoundaryAnHTTPKeyEndpointIsNotReached(t *testing.T) {
	i := newIDP(t)
	e := newEnv(t, envOptions{environment: "production", trust: i.trust()})
	prod := devBoundary()
	prod.Environment = "production"
	_, err := e.verifier().Verify(context.Background(), i.token(t, "k1", nil), prod)
	if err == nil || !strings.Contains(err.Error(), "unavailable: issuer_keys") {
		t.Fatalf("err = %v", err)
	}
	if n := i.fetches(); n != 0 {
		t.Errorf("the key endpoint was reached %d times", n)
	}
}

func TestAVerifiedProofOfATrustedIssuerIsNotATokenForAPerson(t *testing.T) {
	i := newIDP(t)
	e := newEnv(t, envOptions{trust: i.trust()})
	r := e.exchange(request(i.token(t, "k1", nil)))
	failure(t, r, "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "proof_kind" {
		t.Errorf("reason = %v", got)
	}
	// It was verified, so the replay guard is set: the same proof is a replay.
	failure(t, e.exchange(request(i.token(t, "k1", nil))), "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "replay" {
		t.Errorf("reason = %v", got)
	}
	if n := len(e.policy.requests()) + len(e.signer.requests()) + len(e.dir.seen); n != 0 {
		t.Errorf("a workload proof reached policy, signer or the directory %d times", n)
	}
}
