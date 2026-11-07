// Package gojose is the Go side of the test of signer: it verifies a token the way a relying party does, with
// go-jose (the library the approved list names for JWS and JWK): the signature against the key set by its kid, then
// the header type and the claims.
//
// TestToken is driven by the Rust test of signer (actors/signer/tests/sign.rs), which signs through a stand-in for
// key@, publishes the key set built from the SigningRing, and runs the compiled test binary on both. It skips when it
// is run on its own. TestVerifier always runs: it checks the verifier against tokens go-jose signs itself, so that a
// verifier which accepts everything is caught here and not trusted there.
package gojose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// algs are the algorithms a relying party of sluis accepts for a token: the same list as the CLI's.
var algs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256}

// verify checks raw against the key set in data and returns the kid of the key that verified it. The algorithm is the one
// the relying party expects of the audience (ES384, or RS256 for an audience that asked for it): a token of another
// algorithm is refused, whatever key set it would verify against.
func verify(data []byte, raw, issuer, audience, typ, alg string, now time.Time) (string, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return "", fmt.Errorf("key set: %w", err)
	}
	tok, err := jose.ParseSignedCompact(raw, algs)
	if err != nil || len(tok.Signatures) != 1 {
		return "", errors.New("not a compact JWS of an allowed algorithm")
	}
	h := tok.Signatures[0].Header
	if h.Algorithm != alg {
		return "", fmt.Errorf("alg %q is not %s", h.Algorithm, alg)
	}
	if got, _ := h.ExtraHeaders[jose.HeaderType].(string); got != typ {
		return "", errors.New("typ is not the expected one")
	}
	keys := set.Key(h.KeyID)
	if h.KeyID == "" || len(keys) != 1 {
		return "", errors.New("the key set does not hold the token's kid exactly once")
	}
	if keys[0].Use != "sig" || keys[0].Algorithm != alg {
		return "", fmt.Errorf("the key is not a %s signature key", alg)
	}
	// The kid is the RFC 7638 thumbprint of the key (SHA-256), so that a verifier that recomputes it agrees.
	tp, err := keys[0].Thumbprint(crypto.SHA256)
	if err != nil || base64.RawURLEncoding.EncodeToString(tp) != h.KeyID {
		return "", errors.New("the kid is not the thumbprint of the key")
	}
	payload, err := tok.Verify(keys[0])
	if err != nil {
		return "", errors.New("the signature does not verify")
	}
	var c struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", errors.New("the payload is not JSON claims")
	}
	switch {
	case c.Iss != issuer:
		return "", errors.New("iss")
	case c.Aud != audience:
		return "", errors.New("aud")
	case c.Exp <= now.Unix():
		return "", errors.New("exp")
	case c.Iat > now.Unix()+60:
		return "", errors.New("iat")
	}
	return h.KeyID, nil
}

// TestToken verifies the token and the key set that the Rust test hands over in the environment, at the time it
// names. It prints kid=<kid> on success.
func TestToken(t *testing.T) {
	jwks := os.Getenv("SLUIS_SIGNER_JWKS")
	if jwks == "" {
		t.Skip("SKIP: driven by the Rust test of signer (actors/signer/tests/sign.rs), which sets SLUIS_SIGNER_JWKS")
	}
	data, err := os.ReadFile(jwks) //nolint:gosec // the path is the test's own
	if err != nil {
		t.Fatal(err)
	}
	secs, err := strconv.ParseInt(os.Getenv("SLUIS_SIGNER_NOW"), 10, 64)
	if err != nil {
		t.Fatal("SLUIS_SIGNER_NOW is not a Unix time")
	}
	alg := os.Getenv("SLUIS_SIGNER_ALG")
	if alg == "" {
		alg = "ES384"
	}
	kid, err := verify(data, os.Getenv("SLUIS_SIGNER_TOKEN"), os.Getenv("SLUIS_SIGNER_ISSUER"),
		os.Getenv("SLUIS_SIGNER_AUDIENCE"), os.Getenv("SLUIS_SIGNER_TYP"), alg, time.Unix(secs, 0))
	if err != nil {
		t.Fatalf("not verified: %v", err)
	}
	fmt.Printf("kid=%s\n", kid)
}

func TestVerifier(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: key.Public(), Use: "sig", Algorithm: "ES384"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(tp)
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(typ string, claims map[string]any) string {
		opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: &jose.JSONWebKey{Key: key, KeyID: jwk.KeyID}}, opts)
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(claims)
		jws, err := s.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		out, err := jws.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	good := map[string]any{"iss": "https://sluis.dev.local.test", "aud": "sluis-cli", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()}
	tok := sign("at+jwt", good)
	if kid, err := verify(set, tok, "https://sluis.dev.local.test", "sluis-cli", "at+jwt", "ES384", now); err != nil || kid != jwk.KeyID {
		t.Fatalf("a good token: kid %q, err %v", kid, err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSet, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: other.Public(), KeyID: jwk.KeyID, Use: "sig", Algorithm: "ES384"}}})
	for name, c := range map[string]struct {
		set             []byte
		token, aud, typ string
		now             time.Time
	}{
		"another key under the same kid": {otherSet, tok, "sluis-cli", "at+jwt", now},
		"another audience":               {set, tok, "other-app", "at+jwt", now},
		"another typ":                    {set, tok, "sluis-cli", "JWT", now},
		"expired":                        {set, tok, "sluis-cli", "at+jwt", now.Add(time.Hour)},
		"an empty key set":               {[]byte(`{"keys":[]}`), tok, "sluis-cli", "at+jwt", now},
		"a token cut short":              {set, tok[:len(tok)-4], "sluis-cli", "at+jwt", now},
	} {
		if _, err := verify(c.set, c.token, "https://sluis.dev.local.test", c.aud, c.typ, "ES384", c.now); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := verify(set, tok, "https://sluis.other.test", "sluis-cli", "at+jwt", "ES384", now); err == nil {
		t.Error("another issuer: verified")
	}
}

// TestVerifierRS256 holds the RS256 side of the verifier to tokens go-jose signs itself: an RS256 token verifies when the
// audience expects RS256 and not when it expects ES384, an ES384 token does not verify when RS256 is expected, and a key
// set whose entry says another algorithm than the token is refused.
func TestVerifierRS256(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: key.Public(), Use: "sig", Algorithm: "RS256"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(tp)
	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: key, KeyID: jwk.KeyID}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"iss": "https://sluis.dev.local.test", "aud": "rs-app", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()})
	jws, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://sluis.dev.local.test"
	if kid, err := verify(set, tok, iss, "rs-app", "JWT", "RS256", now); err != nil || kid != jwk.KeyID {
		t.Fatalf("a good RS256 token: kid %q, err %v", kid, err)
	}
	if _, err := verify(set, tok, iss, "rs-app", "JWT", "ES384", now); err == nil {
		t.Error("an RS256 token verified for an audience that expects ES384")
	}
	other := jwk
	other.Algorithm = "ES384"
	otherSet, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{other}})
	if _, err := verify(otherSet, tok, iss, "rs-app", "JWT", "RS256", now); err == nil {
		t.Error("a key set entry that says ES384 verified an RS256 token")
	}
	if _, err := verify(set, tok, iss, "rs-app", "at+jwt", "RS256", now); err == nil {
		t.Error("an RS256 token verified as an access token")
	}
}
