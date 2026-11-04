// Command gojose verifies a token the way a relying party does, with go-jose (the library the approved list names
// for JWS and JWK): the signature against the key set by its kid, then the header type and the claims. It is the Go
// side of the test of signer: the Rust test signs through a stand-in for key@, publishes the key set built from the
// SigningRing, and runs this program on both. It is test tooling and is not part of a release.
//
// Usage: gojose <jwks.json> <token> <issuer> <audience> <typ> [now]
// The time of the check is now, a Unix time in seconds, or the real time when it is left out. It exits 0 and prints the kid when the token verifies, and exits 1 with the reason on standard error otherwise.
package main

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// algs are the algorithms a relying party of sluis accepts for a token: the same list as the CLI's.
var algs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256}

func main() {
	if len(os.Args) != 6 && len(os.Args) != 7 {
		fmt.Fprintln(os.Stderr, "usage: gojose <jwks.json> <token> <issuer> <audience> <typ> [now]")
		os.Exit(2)
	}
	now := time.Now()
	if len(os.Args) == 7 {
		secs, err := strconv.ParseInt(os.Args[6], 10, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gojose: now is not a Unix time")
			os.Exit(2)
		}
		now = time.Unix(secs, 0)
	}
	kid, err := verify(os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gojose:", err)
		os.Exit(1)
	}
	fmt.Println(kid)
}

func verify(jwksPath, raw, issuer, audience, typ string, now time.Time) (string, error) {
	data, err := os.ReadFile(jwksPath) //nolint:gosec // the path is the test's own argument
	if err != nil {
		return "", err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return "", fmt.Errorf("key set: %w", err)
	}
	tok, err := jose.ParseSignedCompact(raw, algs)
	if err != nil || len(tok.Signatures) != 1 {
		return "", errors.New("not a compact JWS of an allowed algorithm")
	}
	h := tok.Signatures[0].Header
	if h.Algorithm != string(jose.ES384) {
		return "", fmt.Errorf("alg %q is not ES384", h.Algorithm)
	}
	if got, _ := h.ExtraHeaders[jose.HeaderType].(string); got != typ {
		return "", errors.New("typ is not the expected one")
	}
	keys := set.Key(h.KeyID)
	if h.KeyID == "" || len(keys) != 1 {
		return "", errors.New("the key set does not hold the token's kid exactly once")
	}
	if keys[0].Use != "sig" || keys[0].Algorithm != string(jose.ES384) {
		return "", errors.New("the key is not an ES384 signature key")
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
