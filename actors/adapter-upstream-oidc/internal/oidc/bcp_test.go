package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/v2/tests/jwtbcp"
)

// verifies: REQ-SEC-001, REQ-SEC-012, REQ-SEC-013, REQ-FED-001
func TestAnIDTokenRefusesEveryVectorOfTheJWTBestPractices(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		alg   jose.SignatureAlgorithm
		curve elliptic.Curve
	}{{jose.ES256, elliptic.P256()}, {jose.ES384, elliptic.P384()}} {
		t.Run(string(c.alg), func(t *testing.T) {
			key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			rk, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			const issuer, client, nonce = "https://idp.example.com/realms/test", "sluis", "n-0S6_WzA2Mj"
			p := jwtbcp.Profile{
				SpareRSA: rk, RSAPinned: true,
				Alg: c.alg, Key: key, KID: "k1", Now: now,
				Claims: map[string]any{
					"iss": issuer, "aud": client, "sub": "u-1", "nonce": nonce,
					"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
				},
				IssuerClaim: "iss", AudienceClaim: "aud", CheckExp: true,
			}
			d := NewDirectory(func() time.Time { return now })
			prov := &Provider{Issuer: issuer, JWKSURI: "https://idp.example.com/jwks"}
			d.keys[prov.JWKSURI] = cachedKeys{set: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{p.Public(), p.Spare()}}, fetched: now}
			verify := func(token string) error {
				_, err := d.VerifyIDToken(context.Background(), prov, false, token, client, nonce)
				return err
			}
			if err := verify(jwtbcp.Valid(t, p)); err != nil {
				t.Fatalf("the valid token was refused: %v", err)
			}
			for _, v := range jwtbcp.Negative(t, p) {
				t.Run(string(v.Rule)+"/"+v.Name, func(t *testing.T) {
					if verify(v.Token) == nil {
						t.Fatal("accepted a token with this defect")
					}
				})
			}
		})
	}
}
