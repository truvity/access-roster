package sessiond

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// maxRevokeToken bounds the token of a revocation request. It is longer than a refresh token (maxCredential) because the
// request may carry an access token, which is a JWT, to be told that it is not revoked.
const maxRevokeToken = 4096

// maxRevokeHint bounds token_type_hint.
const maxRevokeHint = 64

// Revoke serves the revocation endpoint (RFC 7009): a client ends a token it holds.
//
// What it ends is the grant a refresh token belongs to, and exactly that one: the session chain of the token's sid, with its
// refresh tokens (REQ-TOKEN-025). The chain is ended when the caller holds a token of it (the secret half of the refresh token
// is the proof: the sid is in every token of the chain and is no secret) and the chain is the calling client's. The client
// authenticates as at the token endpoint (REQ-TOKEN-009).
//
// The answer is 200 (RFC 7009 section 2.2: "200 ... if the client submitted an invalid token") for a token that is revoked and
// for every one that is not: unknown, ended, expired, of another client, or with a wrong secret. The answers are the same, so
// the answer says nothing about whether the token existed, and a client cannot end another client's token or learn that it
// exists (REQ-TOKEN-026). What a caller can tell is its own request's shape. The one other answer for a refresh token is 503,
// when the token is proved and policy gives no grant to delete the chain with: it is the caller's own session, so the answer
// reveals nothing, and 200 would say an ended session that is not.
//
// An access token is not revoked: a signed token is checked by its signature and exp alone elsewhere, and recalling one that
// was issued is REQ-SESS-055, which is not built. A token of that shape (three parts, as an access token and an ID token are)
// is answered unsupported_token_type, whatever its content, so the answer is a function of the shape alone and tells nothing
// about the token. (RFC 7009 section 2.2.1 names this answer for a server that does not revoke access tokens.)
//
// The type of the token is read from the token. token_type_hint is checked for its syntax and then ignored, as the RFC allows
// ("the authorization server MAY ignore"), so a wrong hint cannot change the answer.
func (s *Service) Revoke(ctx context.Context, req *connect.Request[sessionv2alpha1.RevokeRequest]) (*connect.Response[typev2alpha1.HttpReply], error) {
	r := req.Msg
	tc, done, err := s.tokenContext(ctx, &sessionv2alpha1.TokenRequest{
		ClientId: r.GetClientId(), ClientSecret: r.GetClientSecret(), Authorization: r.GetAuthorization(),
	}, actionRevoke)
	if done != nil || err != nil {
		return done, err
	}
	clientSubj := clientSubject(tc.tenant, tc.client.GetId())
	tok := r.GetToken()
	if !vschar(tok, maxRevokeToken, false) || !vschar(r.GetTokenTypeHint(), maxRevokeHint, true) {
		return s.refuse(ctx, tc, clientSubj, nil, reasonRequest, errInvalidRequest()), nil
	}
	if strings.Count(tok, ".") == 2 {
		return s.refuse(ctx, tc, clientSubj, nil, reasonTokenType, errUnsupportedTokenType()), nil
	}
	sid, secret, ok := splitRefresh(tok)
	if !ok {
		return revoked(), nil
	}
	return s.revokeRefresh(ctx, tc, sid, secret)
}

// revoked is the answer to a revocation that is accepted, and to every one that is not refused.
func revoked() *connect.Response[typev2alpha1.HttpReply] {
	return reply(http.StatusOK, nil, noStore()...)
}

// revokeRefresh ends the chain of the refresh token if the token is a token of that chain and the chain is the client's. A
// chain that is not there is not an error: whoever ended it already has, and the answer is the same. Reading a chain that is
// not there is a refusal that store@ audits (ADR 0005), once for each such request; session writes no record of its own for
// it, because it refused nothing.
func (s *Service) revokeRefresh(ctx context.Context, tc *tokenCtx, sid, secret string) (*connect.Response[typev2alpha1.HttpReply], error) {
	it, err := s.chains.Get(ctx, tc.tenant, sid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return revoked(), nil
	case err != nil:
		return nil, unavailable("store", err)
	}
	chain := it.Value
	h := secretHash(secret)
	// Another client's chain, and a token that is not one the chain issued, are not this caller's to end. The class of the
	// chain does not matter: a client ends any chain of its own that it holds a token of.
	var endedBy string
	switch {
	case !equal(chain.GetClientId(), tc.client.GetId()):
		return revoked(), nil
	case hashEqual(h, chain.GetRefreshHash()):
		endedBy = "current"
	case hashIn(h, chain.GetSpentHashes()):
		endedBy = "spent"
	default:
		return revoked(), nil
	}
	person := personSubject(tc.tenant, chain.GetSubject())

	var facts sessionv2alpha1.SignInFacts
	if err := s.keys.openChain(ctx, tc.tenant, sid, chain.GetSealedFacts(), &facts); err != nil {
		if errors.Is(err, errNotOurs) {
			return revoked(), nil
		}
		return nil, unavailable("key", err)
	}
	state, err := s.stateOf(ctx, tc.tenant, chain.GetSubject())
	if err != nil {
		return nil, unavailable("store", err)
	}
	v, err := s.decide(ctx, question{
		tenant: tc.tenant, subject: chain.GetSubject(), accounts: facts.GetAccounts(), state: state,
		client: tc.client, assure: assuranceFrom(chain.GetAuthTime(), chain.Acr, chain.GetAmr(), chain.GetAmrPresent()),
		now: tc.now, verbs: []string{"delete"},
	})
	if err != nil {
		return nil, unavailable("policy", err)
	}
	if !v.allow {
		// Policy gave no grant to delete with, and a chain is personal data that only a grant deletes: session cannot end it.
		// The caller has proved a token of the chain by now, so an answer that says "not done" tells it nothing it does not
		// know, and 200 would tell it that the session has ended when it has not. RFC 7009 section 2.2.1 has the answer for a
		// server that cannot do it now: 503. (The example policy forbids a person who is not live every action, so a held
		// person cannot sign out until the hold is lifted; the refresh token is refused all the same, by the same decision.)
		// The denial is audited.
		_ = s.refuse(ctx, tc, person, &v, deniedReason(state, v), deniedError(v))
		return nil, refusal.New(connect.CodeUnavailable, "grant", "")
	}
	// The chain is deleted whether or not the records are accepted. The end of a session the client asked for is not held
	// back by the audit transport: a failed record is counted (the next record carries the count, ADR 0029, "Facts that are
	// lost are counted") and the client is answered, where answering 503 after the delete would have the retry read "absent",
	// answer 200 and record nothing at all. The delete is the step that may fail the request. The end of the chain is
	// recorded by deleteChain, once, by the request whose delete succeeded; a chain that another request ended first has
	// been recorded by it, and is no revocation of ours.
	ended, err := s.endedChain(ctx, tc, sid, v.grant, reasonRevoked)
	if err != nil {
		return nil, err
	}
	if !ended {
		return revoked(), nil
	}
	s.emit(ctx, audited{
		action: tc.action, tenant: tc.tenant, subject: person, policy: v.ref(),
		sluis: map[string]any{"sid": sid, "ended_by": endedBy},
	})
	return revoked(), nil
}

// emit hands a fact to the audit transport without waiting for it to be accepted; a fact that is not accepted is counted.
func (s *Service) emit(ctx context.Context, a audited) {
	if err := s.opts.Audit.Emit(ctx, s.event(a)); err != nil {
		slog.Error("audit emit failed", "action", a.action.Name)
	}
}
