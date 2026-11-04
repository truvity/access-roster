package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// idTokenAlgs are the signature algorithms an ID token may use (REQ-FED-011). The list is fixed: go-jose refuses any
// other algorithm, "none" and the HMAC family included, before it looks at a key. It matches the sluis CLI's.
var idTokenAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256}

// skew is the leeway for the clocks of the two sides, on exp, nbf and iat.
const skew = 30 * time.Second

// Every refusal here is INVALID: 0025 ("The upstream contract") refuses a bad token, a missing claim and a missing iss
// with that reason and gives no lenient fallback.

// Claims are the claims of a verified ID token. The adapter reads only the ones it is configured to read
// (REQ-FED-005): the subject claim, the organisation claim, acr, amr and auth_time. Roles and groups are never read
// (REQ-FED-016).
type Claims map[string]json.RawMessage

// VerifyIDToken checks the signature of the ID token against the upstream's key set (REQ-FED-001), then its claims
// (REQ-FED-012): iss, aud, azp, nonce and the time claims (OpenID Connect Core 1.0 section 3.1.3.7, items 2, 3, 5,
// 7, 9, 10 and 11). The signature is checked even though the token came from the token endpoint over a connection
// the adapter opened: in a development boundary the connection is plain HTTP on loopback (D-11), and Core item 6
// allows skipping the check only over TLS. A claim is not read before the signature has verified (REQ-FED-013).
func (d *Directory) VerifyIDToken(ctx context.Context, p *Provider, development bool, raw, clientID, nonce string) (Claims, error) {
	tok, err := jose.ParseSignedCompact(raw, idTokenAlgs)
	if err != nil || len(tok.Signatures) != 1 {
		// Not a compact JWS, or an algorithm outside idTokenAlgs (none, HS256, ...).
		return nil, Invalid("id_token.alg")
	}
	kid := tok.Signatures[0].Header.KeyID
	payload, err := d.verifySignature(ctx, p, development, tok, kid, false)
	if err != nil {
		return nil, err
	}
	return checkClaims(payload, p.Issuer, clientID, nonce, d.now())
}

// verifySignature tries the keys of the set that fit the token's key id. A key id the set does not hold, or a failed
// signature, makes one fresh fetch of the set (a key rotation), which the Directory limits.
func (d *Directory) verifySignature(ctx context.Context, p *Provider, development bool, tok *jose.JSONWebSignature, kid string, retried bool) ([]byte, error) {
	set, err := d.keySet(ctx, p, development, retried)
	if err != nil {
		return nil, err
	}
	candidates := set.Keys
	if kid != "" {
		candidates = set.Key(kid)
	}
	for _, k := range candidates {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if b, err := tok.Verify(k); err == nil {
			return b, nil
		}
	}
	if !retried {
		return d.verifySignature(ctx, p, development, tok, kid, true)
	}
	return nil, Invalid("id_token.signature")
}

func checkClaims(payload []byte, issuer, clientID, nonce string, now time.Time) (Claims, error) {
	var c Claims
	if json.Unmarshal(payload, &c) != nil {
		return nil, Invalid("id_token")
	}
	var iss, gotNonce, azp string
	var exp, nbf, iat int64
	if !decode(c, "iss", &iss) || !decode(c, "nonce", &gotNonce) || !decode(c, "azp", &azp) ||
		!decode(c, "exp", &exp) || !decode(c, "nbf", &nbf) || !decode(c, "iat", &iat) {
		return nil, Invalid("id_token")
	}
	aud, ok := audience(c["aud"])
	switch {
	case iss != issuer:
		return nil, Invalid("id_token.iss")
	case !ok || !contains(aud, clientID):
		return nil, Invalid("id_token.aud")
	case len(aud) > 1 && azp != clientID, azp != "" && azp != clientID:
		return nil, Invalid("id_token.azp")
	case exp == 0 || !time.Unix(exp, 0).Add(skew).After(now):
		return nil, Invalid("id_token.exp")
	case nbf != 0 && time.Unix(nbf, 0).After(now.Add(skew)):
		return nil, Invalid("id_token.nbf")
	case iat == 0 || time.Unix(iat, 0).After(now.Add(skew)):
		// iat is REQUIRED (OpenID Connect Core 1.0 section 2): a token without it is refused.
		return nil, Invalid("id_token.iat")
	case nonce == "" || subtle.ConstantTimeCompare([]byte(gotNonce), []byte(nonce)) != 1:
		return nil, Invalid("id_token.nonce")
	}
	return c, nil
}

// decode reads an optional claim into v. An absent claim leaves the zero value; a claim of another type is false.
func decode[T any](c Claims, name string, v *T) bool {
	raw, ok := c[name]
	if !ok {
		return true
	}
	return json.Unmarshal(raw, v) == nil
}

// audience reads aud, a string or a list of strings (RFC 7519 section 4.1.3).
func audience(raw json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many, true
	}
	return nil, false
}

// String reads a string claim. The second result is false when the claim is absent or not a string.
func (c Claims) String(name string) (string, bool) {
	var s string
	raw, ok := c[name]
	if !ok || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// Strings reads a claim that is a list of strings. present is true when the claim is there at all; ok is false when
// it is there and is not a list of strings.
func (c Claims) Strings(name string) (list []string, present, ok bool) {
	raw, present := c[name]
	if !present {
		return nil, false, true
	}
	if string(raw) == "null" {
		return nil, true, true
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil, true, false
	}
	return list, true, true
}

// Int reads a number claim that is a whole number. present is true when the claim is there; ok is false when it is
// there and is not a whole number.
func (c Claims) Int(name string) (v int64, present, ok bool) {
	raw, present := c[name]
	if !present {
		return 0, false, true
	}
	if json.Unmarshal(raw, &v) != nil {
		return 0, true, false
	}
	return v, true, true
}
