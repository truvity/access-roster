// Package testissuer is an OpenID provider just real enough to verify a
// token against: a discovery document, a key set, and a signer. It is
// for tests only.
package testissuer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Issuer is the fake provider.
type Issuer struct {
	*httptest.Server
	Key *rsa.PrivateKey
	KID string
}

// New starts one and stops it with the test.
func New(t *testing.T) *Issuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuer := &Issuer{Key: key, KID: "test-key"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer.URL,
			"jwks_uri":                              issuer.URL + "/keys",
			"authorization_endpoint":                issuer.URL + "/authorize",
			"token_endpoint":                        issuer.URL + "/token",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), KeyID: issuer.KID, Algorithm: string(jose.RS256), Use: "sig",
		}}})
	})
	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Close)

	return issuer
}

// Mint signs a token with this issuer's key. Claims override the
// defaults (iss = this issuer, exp = in an hour).
func (i *Issuer) Mint(t *testing.T, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: i.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", i.KID),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	full := map[string]any{
		"iss": i.URL,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		full[k] = v
	}
	raw, err := jwt.Signed(signer).Claims(full).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}
