package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// ErrNoPerson is a mint asked for somebody with no address: only a person
// signed in to this service's console is minted a token here.
var ErrNoPerson = errors.New("a token is minted here only for a person")

// MintFor signs an access token for a person already signed in to this
// service, for one declared client, lasting at most lifetime.
//
// It is how this service's own console reads another service as the person
// using it — the audit installation's query service, first — without the
// browser holding a token: the console asks, and the token goes from here
// to the service it is for. The decision is the one a token exchange makes
// (Exchange: the client's requirements against the person's groups, and
// recorded as an exchange), and the token is the one an exchange issues:
// the same issuer, key, claims and lifetime cap.
//
// It opens no session and carries no auth_time, so the absolute session
// limit does not cap it directly -- there is nothing here to measure it
// from, the same reason a workload's exchange is unaffected (see
// [Sessions.Record]). It is bounded all the same, twice over: `lifetime`
// is a few minutes in every caller today, and the console session that
// authorizes the call in the first place is itself capped at the limit
// (see internal/app's use of ABSOLUTE_LIFETIME) -- so a person who could
// no longer reach the console at all cannot reach this either.
func (s *Storage) MintFor(ctx context.Context, email, audience string, lifetime time.Duration) (string, time.Time, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", time.Time{}, ErrNoPerson
	}
	grant, err := s.iss.Exchange(ctx, Proof{Email: email}, audience)
	if err != nil {
		return "", time.Time{}, err
	}
	if capped := time.Duration(s.iss.Lifetime(grant)); capped > 0 && capped < lifetime {
		lifetime = capped
	}
	if lifetime <= 0 || lifetime > s.iss.Config().TokenLifetime {
		lifetime = s.iss.Config().TokenLifetime
	}
	now := time.Now().UTC()
	expires := now.Add(lifetime)
	claims := map[string]any{}
	for k, v := range grant.Claims {
		claims[k] = v
	}
	// The registered claims last, so that no group's fragment can set them.
	claims["iss"] = s.iss.Config().URL
	claims["sub"] = grant.Subject
	claims["aud"] = []string{grant.Audience}
	claims["client_id"] = grant.Audience
	claims["email"] = email
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["exp"] = expires.Unix()
	claims["jti"] = uuid.NewString()

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: s.key.SignatureAlgorithm(), Key: s.key.Key()},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.key.ID()),
	)
	if err != nil {
		return "", time.Time{}, err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", time.Time{}, err
	}
	token, err := signed.CompactSerialize()
	return token, expires, err
}
