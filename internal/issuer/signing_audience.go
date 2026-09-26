package issuer

import (
	"context"
	"sync"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// signingAudienceKey is the context key one HTTP request's [signingAudience]
// carrier lives under.
type signingAudienceKey struct{}

// signingAudience carries the ONE audience id this replica is about to
// sign a token for, from whichever storage hook learns it first to the
// [Storage.SigningKey] call the library makes a moment later with nothing
// but a context.
//
// It exists because zitadel/oidc v3's `Storage.SigningKey(ctx)` takes
// nothing else — see op/token.go's CreateJWT and CreateIDToken. Every
// OTHER hook this issuer implements is handed the real request and could
// read its audience directly, but the library asks for the signing key
// before most of them run, threading only a context through to get
// there. So the audience travels through this one mutable cell instead,
// on the SAME context tree every hook for one HTTP request shares:
//
//   - [withSigningAudienceContext] installs an empty one, once, before
//     the OpenID library sees the request at all.
//   - [Storage.CreateAccessToken] and [Storage.CreateAccessAndRefreshTokens]
//     mark it with the ACCESS token's audience — the request's own
//     [op.TokenRequest.GetAudience], which is already the resource a
//     caller named or the client itself, and for a token exchange the
//     GRANTED target rather than the client presenting the exchange —
//     before the library calls [Storage.SigningKey] for that token.
//   - [client.RestrictAdditionalIdTokenScopes] marks it with the ID
//     token's audience — always the client itself, never a resource —
//     which the library calls right before it calls [Storage.SigningKey]
//     for THAT token. It runs after the access token's SigningKey call
//     and before the ID token's, which is what makes overwriting the
//     SAME cell correct rather than a race: the library never asks for
//     two signing keys at once for one request.
//
// A carrier that is never marked — a path this design missed, or a test
// that builds a [Storage] directly and calls a method without going
// through [withSigningAudience] at all — reads back unset, and
// [Storage.SigningKey] then signs with the installation default. That is
// the one risk every negative test in this package exists to rule out:
// silence here looks exactly like an audience that was never meant to be
// anything special.
type signingAudience struct {
	mu  sync.Mutex
	id  string
	set bool
}

// withSigningAudienceContext installs a fresh, empty carrier on ctx.
// Called ONCE per incoming request — see [withSigningAudience] — so a
// carrier is never shared between two different people's requests and
// never missing where a hook expects one.
func withSigningAudienceContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, signingAudienceKey{}, &signingAudience{})
}

// signingAudienceFrom reads the carrier off ctx, or nil where none was
// installed. A nil carrier answers exactly like an unmarked one: every
// method below is safe to call on it.
func signingAudienceFrom(ctx context.Context) *signingAudience {
	carrier, _ := ctx.Value(signingAudienceKey{}).(*signingAudience)
	return carrier
}

// mark records the id this replica is about to sign a token for.
func (c *signingAudience) mark(id string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.id, c.set = id, true
}

// get reads back what was marked, and whether anything was.
func (c *signingAudience) get() (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id, c.set
}

// accessAudienceOf is the id an ACCESS token about to be minted for
// request is FOR: a resource a caller named with `resource` (RFC 8707),
// or the client itself — [op.TokenRequest.GetAudience] already resolves
// exactly that for an authorization code and a refresh (see
// [authRequest.GetAudience] and [refreshRequest.GetAudience]).
//
// For a TOKEN EXCHANGE it is the same call for a different reason: the
// library's own exchange request carries the audience this issuer
// GRANTED it in [Storage.ValidateTokenExchangeRequest] — the requested
// target, one exact value, checked there — never the id of the client
// presenting the exchange. Reusing [op.TokenRequest.GetClientID] here, as
// some other paths correctly do for OTHER purposes, would key an
// exchanged token's algorithm on the wrong party.
func accessAudienceOf(request op.TokenRequest) string {
	audience := request.GetAudience()
	if len(audience) == 0 {
		return ""
	}
	return audience[0]
}
