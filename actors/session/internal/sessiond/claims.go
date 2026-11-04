package sessiond

import (
	"encoding/json"
	"strings"
	"time"
)

// claims is the input of a token's claim set (0020 "The claims of a token"). The set is fixed: signer refuses a claim
// outside it, and the table below is where session says which ones it fills.
type claims struct {
	issuer, audience, subject, sid string
	issuedAt, expires              time.Time
	assure                         assurance
	groups                         []string
	nonce                          string // ID token only
	jti, clientID                  string // access token only
}

// idToken is the claim set of an ID token: iss, sub, aud, exp, iat, the nonce when the client sent one,
// auth_time, acr and amr as the upstream said them (absent stays absent), sid and groups.
func (c claims) idToken() ([]byte, error) {
	m := c.common()
	if c.nonce != "" {
		m["nonce"] = c.nonce
	}
	return json.Marshal(m)
}

// accessToken is the claim set of an access token (RFC 9068 section 2.2): the common ones plus jti and
// client_id.
func (c claims) accessToken() ([]byte, error) {
	m := c.common()
	m["jti"] = c.jti
	m["client_id"] = c.clientID
	return json.Marshal(m)
}

func (c claims) common() map[string]any {
	m := map[string]any{
		"iss": c.issuer, "sub": c.subject, "aud": c.audience,
		"iat": c.issuedAt.Unix(), "exp": c.expires.Unix(),
		"sid": c.sid,
	}
	if c.assure.hasAuthTime {
		m["auth_time"] = c.assure.authTime.Unix()
	}
	if c.assure.acr != nil {
		m["acr"] = *c.assure.acr
	}
	if len(c.assure.amr) > 0 {
		m["amr"] = c.assure.amr
	}
	if len(c.groups) > 0 {
		m["groups"] = c.groups
	}
	return m
}

// narrowGroups is the groups claim (0020): the held grant names whose <scope>:<thing> pair appears among the pairs
// of the client's requires, in any role, so a relying party never reads a grant name meant for another system.
// Narrowing never changes what requires admits: admission was decided on the full set. The order is policy's
// (sorted) and a name appears once.
func narrowGroups(held, requires []string) []string {
	pairs := map[string]bool{}
	for _, r := range requires {
		if p, ok := pairOf(r); ok {
			pairs[p] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, g := range held {
		if p, ok := pairOf(g); ok && pairs[p] && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}

// pairOf is the <scope>:<thing> of a grant name <scope>:<thing>:<role>.
func pairOf(name string) (string, bool) {
	parts := strings.Split(name, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", false
	}
	return parts[0] + ":" + parts[1], true
}

// expiry is the exp of a token: the earliest of the issuer's lifetime for the type, the client's ttl_cap and the end
// of the session chain that backs it (0020 "Lifetimes"). zero ttlCap means the client sets none.
func expiry(now time.Time, lifetime, ttlCap time.Duration, chainEnd time.Time) time.Time {
	exp := now.Add(lifetime)
	if ttlCap > 0 && now.Add(ttlCap).Before(exp) {
		exp = now.Add(ttlCap)
	}
	if chainEnd.Before(exp) {
		exp = chainEnd
	}
	return exp
}
