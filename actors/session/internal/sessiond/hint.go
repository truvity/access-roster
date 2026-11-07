package sessiond

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// maxHint bounds an id_token_hint. An ID token of sluis is far shorter; the bound keeps a request small.
const maxHint = 4096

// maxHintSubject bounds the sub of a hint that is kept in the sign-in cookie.
const maxHintSubject = 128

var errHint = errors.New("id_token_hint: not an ID token of this issuer for this client")

// hintSubject reads the sub of an id_token_hint (OpenID Connect Core section 3.1.2.1): a compact JWT whose header and claims
// are JSON objects, whose iss is this issuer and whose aud is the client. It does not check the signature or the expiry, and
// does not need to: the hint is only ever used to refuse. The callback signs the person in only if the person's own sub is
// the hint's, so a hint made up by the caller can end the caller's own request and nothing else, and an expired hint is
// accepted as the specification asks (the OP "SHOULD accept" it). A hint that is not shaped like an ID token of this issuer
// for this client is errHint.
//
// This holds only while the hint is used to refuse. Any use that selects a session, a person or a client from a hint (RP-initiated
// logout, #779, is the first that comes to mind) MUST verify the signature against the key set first: an unverified
// hint there would let a caller name someone else's session.
func hintSubject(hint, issuer, client string) (string, error) {
	parts := strings.Split(hint, ".")
	if len(hint) > maxHint || len(parts) != 3 {
		return "", errHint
	}
	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]json.RawMessage
	if err != nil || json.Unmarshal(head, &header) != nil || header == nil {
		return "", errHint
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errHint
	}
	var c struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Iss != issuer || c.Sub == "" || !vschar(c.Sub, maxHintSubject, false) {
		return "", errHint
	}
	var one string
	var many []string
	switch {
	case json.Unmarshal(c.Aud, &one) == nil:
		many = []string{one}
	case json.Unmarshal(c.Aud, &many) != nil:
		return "", errHint
	}
	for _, a := range many {
		if a == client {
			return c.Sub, nil
		}
	}
	return "", errHint
}
