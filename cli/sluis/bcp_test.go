package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/v2/tests/jwtbcp"
)

// verifies: REQ-SEC-001, REQ-SEC-012, REQ-SEC-013
func TestAnIdentityTokenRefusesEveryVectorOfTheJWTBestPractices(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const clientID, nonce = "sluis-cli", "n-0S6_WzA2Mj"
	var issuer string
	p := jwtbcp.Profile{SpareRSA: rk, RSAPinned: true, Alg: jose.ES384, Key: key, KID: "k1", Now: now, IssuerClaim: "iss", AudienceClaim: "aud", CheckExp: true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{p.Public(), p.Spare()}})
	}))
	t.Cleanup(srv.Close)
	issuer = srv.URL
	p.Claims = map[string]any{
		"iss": issuer, "aud": clientID, "sub": "alice", "nonce": nonce,
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	verify := func(token string) error {
		_, err := verifyIDToken(context.Background(), srv.Client(), srv.URL+"/jwks", token, issuer, clientID, nonce, now)
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
}
