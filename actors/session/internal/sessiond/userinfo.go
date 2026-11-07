package sessiond

import (
	"context"
	"encoding/json"
	"net/http"

	"connectrpc.com/connect"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// UserInfo serves the UserInfo endpoint (OpenID Connect Core section 5.3): the claims of the person whose session an
// access token belongs to, for the scopes the session was granted.
//
// The token is a bearer token in the Authorization header and is checked by bearer (REQ-SEC-038, REQ-TOKEN-024): an ID
// token, a token of another audience, a token of a client the installation does not declare and a token whose session
// chain is gone are all refused as invalid_token. The scope openid is needed (section 5.3.1), and without it the answer is
// insufficient_scope.
//
// What is released is sub, the same pairwise subject the ID token carries (section 5.3.2: they must be the same), taken
// from the verified token. Nothing releases a name or an e-mail address yet: the claims the upstream gives wait for the
// allow-list of REQ-TOKEN-006, so the scopes profile and email add nothing here, and the answer never holds a claim that was
// not decided. The person's state is not read: UserInfo does not look at a hold or a suspension, and a refresh that policy
// denies for a held person is refused without ending the chain. So a held person's access token is served until it expires
// or its chain ends, and a narrowed token is not enforced either (the scope read is the chain's, not the refresh's). Neither
// matters while only `sub` is released; both are a gate on releasing anything more (REQ-TOKEN-006). A token already issued
// elsewhere lives out its lifetime (REQ-SESS-055).
func (s *Service) UserInfo(ctx context.Context, req *connect.Request[sessionv2alpha1.UserInfoRequest]) (*connect.Response[typev2alpha1.HttpReply], error) {
	t, done, err := s.bearer(ctx, req.Msg.GetAuthorization(), actionUserInfo, "openid")
	if done != nil || err != nil {
		return done, err
	}
	body, err := json.Marshal(map[string]string{"sub": t.claims.Sub})
	if err != nil {
		return nil, internal("userinfo", err)
	}
	if aerr := s.record(ctx, audited{
		action: actionUserInfo, tenant: t.tenant, subject: personSubject(t.tenant, t.chain.GetSubject()),
		sluis: map[string]any{"sid": t.claims.SID},
	}); aerr != nil {
		return nil, aerr
	}
	h := append([]*typev2alpha1.Header{header("Content-Type", "application/json")}, noStore()...)
	return reply(http.StatusOK, body, h...), nil
}
