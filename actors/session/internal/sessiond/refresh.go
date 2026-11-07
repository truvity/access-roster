package sessiond

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
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
// refresh rotates the token. Presenting a spent one ends the chain at once (0018 "Session chains", REQ-SESS-001), with
// one exception: the token the last rotation replaced is answered again, with the same successor, for 30 seconds, so
// that a retry or a racing replica does not sign a person out (REQ-SESS-013, refresh_grace.go).
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

	// Which token is this? The current one rotates. A spent one is a reuse, unless it is the one the last rotation
	// replaced and that was moments ago (the grace window, below); a reuse ends the chain once policy has given a
	// grant to delete with. Any other is not a token of this chain, and nothing is decided for it.
	h := secretHash(secret)
	current := hashEqual(h, chain.GetRefreshHash())
	spent := !current && hashIn(h, chain.GetSpentHashes())
	if !current && !spent {
		return s.refuse(ctx, tc, person, nil, reasonRefresh, errInvalidGrant()), nil
	}

	var facts sessionv2alpha1.SignInFacts
	if err := s.keys.openChain(ctx, tc.tenant, sid, chain.GetSealedFacts(), &facts); err != nil {
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

	// The token this presentation is answered with is a function of the one presented, so a twin of this request, on
	// this replica or another, is answered with the same one (REQ-SESS-013).
	next, err := s.keys.refreshSuccessor(ctx, tc.tenant, sid, h)
	if err != nil {
		return nil, unavailable("key", err)
	}

	// A spent token is answered again, with the same successor and with no write, only when it is the one the chain's
	// last rotation replaced and the rotation was within the grace window. Every other spent token, and that one
	// later, is a theft or a replay: the chain ends and its refresh tokens end with it (REQ-SESS-014).
	replay := spent && isSuccessor(chain, next) && inGrace(tc.now, chain.GetRefreshedAt())
	if spent && !replay {
		if err := s.deleteChain(ctx, tc, sid, v.grant, reasonReuse); err != nil {
			return nil, err
		}
		return s.refuse(ctx, tc, person, &v, reasonReuse, errInvalidGrant()), nil
	}

	ends := chain.GetEndsAt().AsTime()
	// The idle limit counts from the stamp of the last rotation as it is. A stamp from the future (a replica that runs ahead)
	// leaves the end after now whether or not it is cut back to now, so there is nothing to clamp: the chain is not ended for
	// it, and it idles out later by as much as that replica is ahead (see inGrace).
	idleEnd := chain.GetRefreshedAt().AsTime().Add(tc.life.RefreshIdle)
	if !tc.now.Before(ends) || !tc.now.Before(idleEnd) {
		if err := s.deleteChain(ctx, tc, sid, v.grant, reasonExpired); err != nil {
			return nil, err
		}
		return s.refuse(ctx, tc, person, &v, reasonExpired, errInvalidGrant()), nil
	}

	if !replay {
		spentNow := append(append([][]byte(nil), chain.GetSpentHashes()...), chain.GetRefreshHash())
		if len(spentNow) > maxSpent {
			spentNow = spentNow[len(spentNow)-maxSpent:]
		}
		rotated := proto.Clone(chain).(*sessionv2alpha1.SessionChain)
		rotated.SpentHashes, rotated.RefreshHash, rotated.RefreshedAt = spentNow, secretHash(next), timestamppb.New(tc.now)
		// The chain keeps its absolute end: every write passes what is left of it as the lifetime, so a rotation never
		// extends the session (0018: "an absolute limit from the start of the session, never reset by use").
		_, err := s.chains.Update(ctx, tc.tenant, sid, rotated, it.Version, store.WithGrant(v.grant), store.WithTTL(ends.Sub(tc.now)))
		switch {
		case errors.Is(err, store.ErrVersion) || errors.Is(err, store.ErrNotFound):
			// Another request moved the chain first. If it was this token's twin, this one is answered as the twin was.
			c, res, rerr := s.afterLostRace(ctx, tc, sid, next, person, &v)
			if res != nil || rerr != nil {
				return res, rerr
			}
			chain, replay = c, true
		case err != nil:
			return nil, unavailable("store", err)
		}
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
		sluis: refreshFacts(sid, replay),
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

// deleteChain ends a chain at once, under the grant of the decision in hand, and records the end once. Many
// presentations of one spent token can arrive together: each deletes at the version it read, only one succeeds, and
// only that one records the end, so a replay storm adds one record of an end and not one for each request. A chain
// that is gone already was ended, and recorded, by whoever ended it.
func (s *Service) deleteChain(ctx context.Context, tc *tokenCtx, sid string, grant []byte, reason string) error {
	_, err := s.endedChain(ctx, tc, sid, grant, 0, reason)
	return err
}

// endedChain is deleteChain that also says whether this request ended the chain: false when the chain was gone already,
// so a caller that records more than the end (a revocation) records it only for the request that did the deleting. A caller
// that has just read the chain gives the version it read (0 for none) and the first delete is made at it with no new read:
// the read of a chain that is not there is a refusal that store@ audits (ADR 0005), and the chain is there but for a race.
func (s *Service) endedChain(ctx context.Context, tc *tokenCtx, sid string, grant []byte, read uint64, reason string) (bool, error) {
	for range 3 {
		version := read
		read = 0
		if version == 0 {
			it, err := s.chains.Get(ctx, tc.tenant, sid)
			switch {
			case errors.Is(err, store.ErrNotFound):
				return false, nil
			case err != nil:
				return false, unavailable("store", err)
			}
			version = it.Version
		}
		switch err := s.chains.Delete(ctx, tc.tenant, sid, version, store.WithGrant(grant)); {
		case err == nil:
			return true, s.recordChainEnd(ctx, tc, sid, reason)
		case errors.Is(err, store.ErrNotFound):
			return false, nil
		case errors.Is(err, store.ErrVersion):
			continue // a legitimate refresh moved the chain between the read and the delete: read again
		default:
			return false, unavailable("store", err)
		}
	}
	// Moved under every attempt: end it whatever the version is. The end is what is owed; the record is owed once.
	switch err := s.chains.Delete(ctx, tc.tenant, sid, 0, store.WithGrant(grant)); {
	case err == nil:
		return true, s.recordChainEnd(ctx, tc, sid, reason)
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	default:
		return false, unavailable("store", err)
	}
}

func (s *Service) recordChainEnd(ctx context.Context, tc *tokenCtx, sid, reason string) error {
	// The end of a chain is recorded as a failure of the step that found the reason, and as the end of the session:
	// a rule on failed logons and a rule on session ends both see it.
	//
	// It is recorded after the delete, by the one request whose delete succeeded (deleteChain), so a storm records one.
	// It is best effort and counted (Emit), not required: the chain is gone whether the fact is accepted or not, and
	// answering unavailable then would hide the refusal and lose the fact all the same, with no loss counted and no
	// other request left to cover for it. A fact that is not accepted is in the count the next record carries
	// (ADR 0029, "Facts that are lost are counted").
	ev := s.event(audited{
		action: actionChainEnd, tenant: tc.tenant, subject: clientSubject(tc.tenant, tc.client.GetId()),
		sluis: map[string]any{"sid": sid, "reason": reason},
	})
	if err := s.opts.Audit.Emit(ctx, ev); err != nil {
		slog.Error("audit emit failed", "action", actionChainEnd.Name)
	}
	return nil
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
	if err := s.keys.openChain(ctx, tc.tenant, sid, chain.GetSealedFacts(), &facts); err != nil {
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
