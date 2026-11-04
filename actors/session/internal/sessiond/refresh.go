package sessiond

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// maxSpent is how many spent markers a chain keeps. A refresh token spent longer ago than that is still refused (it
// is not the current one); it is just no longer recognised as a reuse that ends the chain.
const maxSpent = 16

// refreshGrant exchanges a refresh token for a new pair of tokens and a new refresh token (RFC 6749 section 6).
//
// The refresh token is "<sid>.<secret>"; the chain is found by the sid and the secret is compared by its hash. Every
// refresh rotates the token, and presenting a spent one ends the chain at once (0018 "Session chains", REQ-SESS-001).
// The idle limit counts from the last refresh and the absolute limit from the sign-in, and neither is reset by the
// other (0018 "Human sessions"). Policy decides again at every refresh, with the person's state, so a held person or
// a tightened policy ends the session at its next refresh.
func (s *Service) refreshGrant(ctx context.Context, r *sessionv2alpha1.TokenRequest) (*connect.Response[typev2alpha1.HttpReply], error) {
	tc, done, err := s.tokenContext(ctx, r, actionRefresh)
	if done != nil || err != nil {
		return done, err
	}
	clientSubj := clientSubject(tc.tenant, tc.client.GetId())
	sid, secret, ok := splitRefresh(r.GetRefreshToken())
	if !ok {
		return s.refuse(ctx, tc, clientSubj, nil, reasonRefresh, errInvalidGrant()), nil
	}
	it, err := s.chains.Get(ctx, tc.tenant, sid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return s.refuse(ctx, tc, clientSubj, nil, reasonRefresh, errInvalidGrant()), nil
	case err != nil:
		return nil, unavailable("store", err)
	}
	chain := it.Value
	if !equal(chain.GetClientId(), tc.client.GetId()) || chain.GetClass() != chainClassHuman {
		return s.refuse(ctx, tc, clientSubj, nil, reasonRefresh, errInvalidGrant()), nil
	}
	person := personSubject(tc.tenant, chain.GetSubject())

	// A narrower scope is allowed, a wider one is not (RFC 6749 section 6).
	scope := chain.GetScope()
	if want := strings.Fields(r.GetScope()); len(want) > 0 {
		var ok bool
		if scope, ok = narrowScope(chain.GetScope(), want); !ok {
			return s.refuse(ctx, tc, person, nil, reasonScope, errInvalidScope()), nil
		}
	}

	// Which token is this? The current one rotates; a spent one is a reuse and ends the chain, once policy has given a
	// grant to delete with; any other is not a token of this chain, and nothing is decided for it.
	h := secretHash(secret)
	reused := !hashEqual(h, chain.GetRefreshHash()) && hashIn(h, chain.GetSpentHashes())
	if !reused && !hashEqual(h, chain.GetRefreshHash()) {
		return s.refuse(ctx, tc, person, nil, reasonRefresh, errInvalidGrant()), nil
	}

	var facts sessionv2alpha1.SignInFacts
	if err := s.keys.openChainFacts(ctx, sid, chain.GetSealedFacts(), &facts); err != nil {
		if errors.Is(err, errNotOurs) {
			return s.refuse(ctx, tc, person, nil, reasonRefresh, errInvalidGrant()), nil
		}
		return nil, unavailable("key", err)
	}
	assure := assuranceFrom(chain.GetAuthTime(), chain.Acr, chain.GetAmr(), chain.GetAmrPresent())
	state, err := s.stateOf(ctx, tc.tenant, chain.GetSubject())
	if err != nil {
		return nil, unavailable("store", err)
	}
	v, err := s.decide(ctx, question{
		tenant: tc.tenant, subject: chain.GetSubject(), accounts: facts.GetAccounts(), state: state,
		client: tc.client, assure: assure, now: tc.now, verbs: []string{"update", "delete"},
	})
	if err != nil {
		return nil, unavailable("policy", err)
	}
	if !v.allow {
		return s.refuse(ctx, tc, person, &v, deniedReason(state, v), deniedError(v)), nil
	}

	if reused {
		if err := s.deleteChain(ctx, tc, sid, v.grant, reasonReuse); err != nil {
			return nil, err
		}
		return s.refuse(ctx, tc, person, &v, reasonReuse, errInvalidGrant()), nil
	}

	ends := chain.GetEndsAt().AsTime()
	idleEnd := chain.GetRefreshedAt().AsTime().Add(tc.life.RefreshIdle)
	if !tc.now.Before(ends) || !tc.now.Before(idleEnd) {
		if err := s.deleteChain(ctx, tc, sid, v.grant, reasonExpired); err != nil {
			return nil, err
		}
		return s.refuse(ctx, tc, person, &v, reasonExpired, errInvalidGrant()), nil
	}

	next, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	spent := append(append([][]byte(nil), chain.GetSpentHashes()...), chain.GetRefreshHash())
	if len(spent) > maxSpent {
		spent = spent[len(spent)-maxSpent:]
	}
	chain.SpentHashes, chain.RefreshHash, chain.RefreshedAt = spent, secretHash(next), timestamppb.New(tc.now)
	// The chain keeps its absolute end: every write passes what is left of it as the lifetime, so a rotation never
	// extends the session (0018: "an absolute limit from the start of the session, never reset by use").
	if _, err := s.chains.Update(ctx, tc.tenant, sid, chain, it.Version, store.WithGrant(v.grant), store.WithTTL(ends.Sub(tc.now))); err != nil {
		if errors.Is(err, store.ErrVersion) || errors.Is(err, store.ErrNotFound) {
			// Another request rotated this token first: this one is a spent token presented again. End the chain.
			if derr := s.deleteChain(ctx, tc, sid, v.grant, reasonReuse); derr != nil {
				return nil, derr
			}
			return s.refuse(ctx, tc, person, &v, reasonReuse, errInvalidGrant()), nil
		}
		return nil, unavailable("store", err)
	}

	out, err := s.mint(ctx, tc, mintInput{
		person: chain.GetSubject(), sid: sid, scope: scope, assure: assure,
		groups: narrowGroups(v.grantNames, tc.client.GetRequires()), chainEnd: ends, refresh: sid + "." + next,
	})
	switch {
	case errors.Is(err, errSessionOver):
		return s.refuse(ctx, tc, person, &v, reasonExpired, errInvalidGrant()), nil
	case err != nil:
		return nil, err
	}
	if aerr := s.record(ctx, audited{
		action: tc.action, tenant: tc.tenant, subject: person, policy: v.ref(),
		sluis: map[string]any{"grant_type": "refresh_token", "sid": sid},
	}); aerr != nil {
		return nil, aerr
	}
	return tokenOK(out)
}

// splitRefresh reads "<sid>.<secret>": a 26-character session id and the 43-character secret.
func splitRefresh(t string) (sid, secret string, ok bool) {
	sid, secret, ok = strings.Cut(t, ".")
	if !ok || len(sid) != cookieIDLen || len(secret) != 43 || store.ValidateID(sid) != nil || !vschar(secret, 43, false) {
		return "", "", false
	}
	return sid, secret, true
}

// narrowScope returns the requested scopes if every one was granted, in the order they were granted.
func narrowScope(granted string, want []string) (string, bool) {
	have := map[string]bool{}
	for _, sc := range strings.Fields(granted) {
		have[sc] = true
	}
	asked := map[string]bool{}
	for _, sc := range want {
		if !have[sc] {
			return "", false
		}
		asked[sc] = true
	}
	var out []string
	for _, sc := range strings.Fields(granted) {
		if asked[sc] {
			out = append(out, sc)
		}
	}
	return strings.Join(out, " "), true
}

func hashEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// hashIn reports whether h is one of the hashes, comparing every one in constant time.
func hashIn(h []byte, list [][]byte) bool {
	found := 0
	for _, x := range list {
		found |= subtle.ConstantTimeCompare(h, x)
	}
	return found == 1
}

// deleteChain ends a chain at once, under the grant of the decision in hand, and records the end. A chain that is
// already gone is ended.
func (s *Service) deleteChain(ctx context.Context, tc *tokenCtx, sid string, grant []byte, reason string) error {
	err := s.chains.Delete(ctx, tc.tenant, sid, 0, store.WithGrant(grant))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return unavailable("store", err)
	}
	return s.recordChainEnd(ctx, tc, sid, reason)
}

func (s *Service) recordChainEnd(ctx context.Context, tc *tokenCtx, sid, reason string) error {
	// The end of a chain is recorded as a failure of the step that found the reason, and as the end of the session:
	// a rule on failed logons and a rule on session ends both see it.
	return s.record(ctx, audited{
		action: actionChainEnd, tenant: tc.tenant, subject: clientSubject(tc.tenant, tc.client.GetId()),
		sluis: map[string]any{"sid": sid, "reason": reason},
	})
}

// endChain ends the chain of a replayed code. It asks policy for a grant to delete with: the person's facts are in
// the chain. A denial leaves the chain to expire, which it does within its absolute limit, and refusing the code is
// the answer either way.
func (s *Service) endChain(ctx context.Context, tc *tokenCtx, sid, reason string) error {
	it, err := s.chains.Get(ctx, tc.tenant, sid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return unavailable("store", err)
	}
	chain := it.Value
	var facts sessionv2alpha1.SignInFacts
	if err := s.keys.openChainFacts(ctx, sid, chain.GetSealedFacts(), &facts); err != nil {
		if errors.Is(err, errNotOurs) {
			return nil
		}
		return unavailable("key", err)
	}
	state, err := s.stateOf(ctx, tc.tenant, chain.GetSubject())
	if err != nil {
		return unavailable("store", err)
	}
	v, err := s.decide(ctx, question{
		tenant: tc.tenant, subject: chain.GetSubject(), accounts: facts.GetAccounts(), state: state,
		client: tc.client, assure: assuranceFrom(chain.GetAuthTime(), chain.Acr, chain.GetAmr(), chain.GetAmrPresent()),
		now: tc.now, verbs: []string{"delete"},
	})
	if err != nil {
		return unavailable("policy", err)
	}
	if !v.allow {
		return nil
	}
	return s.deleteChain(ctx, tc, sid, v.grant, reason)
}
