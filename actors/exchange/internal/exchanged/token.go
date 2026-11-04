package exchanged

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// pairwiseLabel separates the use of the pairwise key from every other (key@ binds the label into the Mac).
const pairwiseLabel = "pairwise"

// subBytes is how much of the Mac a pairwise subject keeps: 256 bits (ADR 0034, "Subjects and sectors").
const subBytes = 32

// pairwiseInput is the input of the Mac that makes a pairwise subject (ADR 0034: "the length-prefixed sector and the
// person's Person id"): the sector with a 4-byte big-endian length in front, as the audit pseudonym has, then the id.
// The sector is length-prefixed, so ("ab", "c") and ("a", "bc") differ. session derives the subject of a sign-in
// from the same input, which is why the encoding is written down here.
func pairwiseInput(sector, personID string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(sector))) //nolint:gosec // a sector is at most 32 characters
	b = append(b, sector...)
	return append(b, personID...)
}

// pairwiseSub turns the Mac into a subject: truncated to 256 bits, base64url without padding.
func pairwiseSub(mac []byte) string {
	if len(mac) > subBytes {
		mac = mac[:subBytes]
	}
	return base64.RawURLEncoding.EncodeToString(mac)
}

// narrow returns the grant names of the held set that the audience asks for: each held name whose
// `<scope>:<thing>` pair appears among the pairs of the audience's `requires`, in any role (ADR 0020, "The claims of
// a token"). Admission was decided on the full set; narrowing only keeps a relying party from reading a name meant
// for another system. The result is sorted and has no repeats; it is never nil.
func narrow(held, requires []string) []string {
	pairs := map[string]bool{}
	for _, r := range requires {
		if p, ok := pairOf(r); ok {
			pairs[p] = true
		}
	}
	out := []string{}
	seen := map[string]bool{}
	for _, h := range held {
		if p, ok := pairOf(h); ok && pairs[p] && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// pairOf returns "<scope>:<thing>" of a grant name "<scope>:<thing>:<role>". A name of another shape, and a wildcard
// (never allowed in `requires`, ADR 0020), have none.
func pairOf(name string) (string, bool) {
	parts := strings.Split(name, ":")
	if len(parts) != 3 || strings.Contains(name, "*") {
		return "", false
	}
	for _, p := range parts {
		if p == "" {
			return "", false
		}
	}
	return parts[0] + ":" + parts[1], true
}

// lifetime is the lifetime of the token: the earliest of the issuer's, the audience client's `ttl_cap`, the built-in
// maximum and the end of the subject token (ADR 0020, "Lifetimes"; REQ-EXCH-004: an exchange never yields a token
// that outlives the token it was made from). It returns the `iat` and `exp` in whole seconds, and false when the
// subject token has less than a second left.
func lifetime(now time.Time, issuer, clientCap time.Duration, subjectExp time.Time) (iat, exp int64, ok bool) {
	d := min(issuer, hardCap)
	if clientCap > 0 {
		d = min(d, clientCap)
	}
	iat = now.Unix()
	exp = min(iat+int64(d/time.Second), subjectExp.Unix())
	return iat, exp, exp > iat
}

// accessClaims are the claims of the access token that exchange has signed (ADR 0020, "The claims of a token"). A
// claim that is not here is not issued; signer refuses one that is outside the set.
type accessClaims struct {
	Iss      string    `json:"iss"`
	Sub      string    `json:"sub"`
	Aud      string    `json:"aud"`
	Exp      int64     `json:"exp"`
	Iat      int64     `json:"iat"`
	JTI      string    `json:"jti"`
	ClientID string    `json:"client_id"`
	AuthTime *int64    `json:"auth_time,omitempty"`
	ACR      *string   `json:"acr,omitempty"`
	AMR      *[]string `json:"amr,omitempty"`
	SID      string    `json:"sid,omitempty"`
	Groups   []string  `json:"groups"`
}

// claimsOf builds the claims of the new token. `acr`, `amr`, `auth_time` and `sid` pass from the subject token as
// they are, and an absent one stays absent (ADR 0020): exchange fills in nothing the upstream did not send.
func claimsOf(issuer, sub, audience string, iat, exp int64, jti string, s *Subject, groups []string) ([]byte, error) {
	c := accessClaims{
		Iss: issuer, Sub: sub, Aud: audience, Exp: exp, Iat: iat, JTI: jti, ClientID: s.ClientID,
		AuthTime: s.AuthTime, ACR: s.ACR, SID: s.SID, Groups: groups,
	}
	if s.AMRPresent {
		amr := append([]string{}, s.AMR...)
		c.AMR = &amr
	}
	return json.Marshal(c)
}

// newJTI is a random id for the token: 128 bits from the operating system's generator.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// authAge is the seconds since the person last authenticated, counted from the subject token's `auth_time`. It is
// absent when the token has none: policy has no clock, and an absent name is unknown (policy.md, "Context").
func authAge(s *Subject, now time.Time) *int64 {
	if s.AuthTime == nil {
		return nil
	}
	age := max(now.Unix()-*s.AuthTime, 0)
	return &age
}
