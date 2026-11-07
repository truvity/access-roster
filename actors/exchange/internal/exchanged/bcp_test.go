//go:build sluis_test

package exchanged_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/v2/tests/jwtbcp"
)

// The subject token is the one place where exchange reads a token that somebody else made, so the negative vectors of
// RFC 8725 are run against both of its verifiers: the boundary's own access token (ES384, typ at+jwt) and the proof of
// a trusted issuer (ES256, no typ). Each vector differs from the valid token in one respect; the valid token is
// accepted first, so a refusal is the vector's and not the setup's.

// verifies: REQ-SEC-001, REQ-SEC-012, REQ-SEC-013
func TestTheSubjectTokenOfThisBoundaryRefusesEveryVectorOfTheJWTBestPractices(t *testing.T) {
	e := newEnv(t, envOptions{})
	v := e.verifier()
	spare := spareRSA(t)
	p := jwtbcp.Profile{
		SpareRSA: spare,
		Alg:      jose.ES384, Key: e.signer.key, KID: testKID, Typ: "at+jwt", Now: t0,
		Claims:      subjectClaims(nil),
		IssuerClaim: "iss", AudienceClaim: "aud", CheckExp: true,
	}
	e.signer.extra = []jose.JSONWebKey{p.Spare()}
	if _, err := v.Verify(context.Background(), jwtbcp.Valid(t, p), devBoundary()); err != nil {
		t.Fatalf("the valid token was refused: %v", err)
	}
	n := 0
	for _, vec := range jwtbcp.Negative(t, p) {
		n++
		t.Run(string(vec.Rule)+"/"+vec.Name, func(t *testing.T) {
			if s, err := v.Verify(context.Background(), vec.Token, devBoundary()); err == nil {
				t.Fatalf("accepted a token with this defect; subject %q", s.Subject)
			}
		})
	}
	if n < 50 {
		t.Fatalf("only %d vectors ran", n)
	}
}

// verifies: REQ-SEC-001, REQ-SEC-012, REQ-SEC-013
func TestTheProofOfATrustedIssuerRefusesEveryVectorOfTheJWTBestPractices(t *testing.T) {
	i := newIDP(t)
	e := newEnv(t, envOptions{trust: i.trust()})
	v := e.verifier()
	p := jwtbcp.Profile{
		SpareRSA: spareRSA(t), RSAPinned: true,
		Alg: jose.ES256, Key: i.keys["k1"], KID: "k1", Now: t0,
		Claims: map[string]any{
			"iss": i.srv.URL, "sub": "repo:acme/app:ref:refs/tags/v1", "aud": "sluis-dev",
			"iat": t0.Add(-time.Minute).Unix(), "exp": t0.Add(9 * time.Minute).Unix(),
			"repository": "acme/app", "ref": "refs/tags/v1", "ref_type": "tag", "event_name": "push",
		},
		IssuerClaim: "iss", AudienceClaim: "aud", CheckExp: true,
	}
	i.extra = []jose.JSONWebKey{p.Spare()}
	if _, err := v.Verify(context.Background(), jwtbcp.Valid(t, p), devBoundary()); err != nil {
		t.Fatalf("the valid proof was refused: %v", err)
	}
	for _, vec := range jwtbcp.Negative(t, p) {
		t.Run(string(vec.Rule)+"/"+vec.Name, func(t *testing.T) {
			if s, err := v.Verify(context.Background(), vec.Token, devBoundary()); err == nil {
				t.Fatalf("accepted a proof with this defect; subject %q", s.Subject)
			}
		})
	}
}

func spareRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
