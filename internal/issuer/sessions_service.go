package issuer

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessissuerv1 "github.com/truvity/access-roster/gen/accessissuer/v1"
	"github.com/truvity/access-roster/gen/accessissuer/v1/accessissuerv1connect"
	"github.com/truvity/access-roster/policy"
)

// SessionsService is the only thing this issuer answers about itself,
// and it can only ever remove: list what is open, end some of it. There is no call
// here that grants anything, which is what makes it safe to point a
// console at.
//
// The console is served by the hub, and the hub must not depend on this
// service — it answers "is this account live" for consumers, and that has
// to keep working when the issuer is down. So the BROWSER calls this at
// the issuer's own host and the hub's code learns nothing about it.
type SessionsService struct {
	sessions *Sessions
	// verify turns the caller's own bearer into who they are. It is this
	// issuer's token, verified against this issuer's key: the one caller
	// whose identity it can establish without asking anyone.
	verify func(ctx context.Context, bearer string) (identity string, groups []string, err error)
}

var _ accessissuerv1connect.SessionServiceHandler = (*SessionsService)(nil)

// NewSessionsService returns the handler over an issuer.
func NewSessionsService(iss *Issuer, verifier *op.AccessTokenVerifier) *SessionsService {
	return &SessionsService{
		sessions: iss.Sessions(),
		verify: func(ctx context.Context, bearer string) (string, []string, error) {
			claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, bearer, verifier)
			if err != nil {
				return "", nil, err
			}

			return claims.Subject, groupsOf(claims), nil
		},
	}
}

// groupsOf reads the `groups` claim, which is the whole of what this
// service authorizes on — the same string a cluster binds and a client
// gates with, re-mapped nowhere.
func groupsOf(claims *oidc.AccessTokenClaims) []string {
	raw, ok := claims.Claims["groups"]
	if !ok {
		return nil
	}

	values, ok := raw.([]any)
	if !ok {
		return nil
	}

	out := make([]string, 0, len(values))

	for _, value := range values {
		if name, ok := value.(string); ok {
			out = append(out, name)
		}
	}

	return out
}

// caller is who is asking, and whether they may ask about anyone.
type caller struct {
	identity string
	operator bool
}

// may reports whether this caller may act on that identity's sessions.
// Your own, always; anyone's, only as an operator. That asymmetry is the
// whole authorization model here, and it is why "sign out everywhere"
// needs no special case: it is this rule applied to yourself.
func (c caller) may(identity string) bool {
	return c.operator || strings.EqualFold(c.identity, identity)
}

// who verifies the caller's bearer.
func (s *SessionsService) who(ctx context.Context, header string) (caller, error) {
	bearer := strings.TrimSpace(header)
	if len(bearer) < 7 || !strings.EqualFold(bearer[:7], "bearer ") {
		return caller{}, connect.NewError(connect.CodeUnauthenticated,
			errors.New("this service needs a token from this issuer"))
	}

	identity, groups, err := s.verify(ctx, strings.TrimSpace(bearer[7:]))
	if err != nil {
		// Why it failed goes nowhere near the caller: telling an
		// unauthenticated client what was wrong with its token helps it
		// produce a better one.
		return caller{}, connect.NewError(connect.CodeUnauthenticated,
			errors.New("that token was not accepted"))
	}

	held := caller{identity: identity}

	for _, group := range groups {
		if group == policy.GroupOperators {
			held.operator = true

			break
		}
	}

	return held, nil
}

// ListSessions implements the contract.
func (s *SessionsService) ListSessions(
	ctx context.Context, req *connect.Request[accessissuerv1.ListSessionsRequest],
) (*connect.Response[accessissuerv1.ListSessionsResponse], error) {
	who, err := s.who(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}

	identity := strings.TrimSpace(req.Msg.GetIdentity())
	clientID := strings.TrimSpace(req.Msg.GetClientId())

	// A request that narrows to neither names every person signed in.
	// This service does not answer that, and refusing is not a
	// limitation: the two questions an operator actually has are "what
	// does this person have open" and "who is on this client".
	if identity == "" && clientID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("name an identity or a client: this service does not list every session"))
	}

	// Listing by client alone would name everybody on it, so it is an
	// operator's question. Listing your own is anyone's.
	if identity == "" && !who.operator {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("listing a client's sessions is an operator's"))
	}

	if identity != "" && !who.may(identity) {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("that is somebody else's session"))
	}

	found, err := s.sessions.List(ctx, Query{Identity: identity, ClientID: clientID})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	out := &accessissuerv1.ListSessionsResponse{
		Sessions: make([]*accessissuerv1.Session, 0, len(found)),
	}

	for i := range found {
		out.Sessions = append(out.Sessions, described(found[i]))
	}

	return connect.NewResponse(out), nil
}

// RevokeSessions implements the contract.
func (s *SessionsService) RevokeSessions(
	ctx context.Context, req *connect.Request[accessissuerv1.RevokeSessionsRequest],
) (*connect.Response[accessissuerv1.RevokeSessionsResponse], error) {
	who, err := s.who(ctx, req.Header().Get("Authorization"))
	if err != nil {
		return nil, err
	}

	identity := strings.TrimSpace(req.Msg.GetIdentity())
	if identity == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("name the identity whose sessions to end"))
	}

	if !who.may(identity) {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("that is somebody else's session"))
	}

	// One session by id, when the console offers a row its own button.
	// Still checked against the identity above, so an id alone is never
	// enough to end a session belonging to somebody else.
	if id := strings.TrimSpace(req.Msg.GetSessionId()); id != "" {
		one, found, err := s.sessions.ByID(ctx, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		if !found || !strings.EqualFold(one.Identity, identity) {
			// A session that is not there and one that is somebody
			// else's are the same answer, so that an id cannot be probed.
			return connect.NewResponse(&accessissuerv1.RevokeSessionsResponse{}), nil
		}

		gone, err := s.sessions.RevokeID(ctx, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		return connect.NewResponse(&accessissuerv1.RevokeSessionsResponse{Ended: boolToCount(gone)}), nil
	}

	ended, err := s.sessions.Revoke(ctx, Query{
		Identity: identity,
		ClientID: strings.TrimSpace(req.Msg.GetClientId()),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&accessissuerv1.RevokeSessionsResponse{Ended: int32(ended)}), nil
}

func boolToCount(gone bool) int32 {
	if gone {
		return 1
	}

	return 0
}

// described puts one session on the wire.
func described(s Session) *accessissuerv1.Session {
	out := &accessissuerv1.Session{
		Id:        s.ID,
		Identity:  s.Identity,
		ClientId:  s.ClientID,
		How:       howOf(s.How),
		IssuedAt:  timestamppb.New(s.IssuedAt),
		ExpiresAt: timestamppb.New(s.ExpiresAt),
	}

	if !s.LastRefreshed.IsZero() {
		out.LastRefreshed = timestamppb.New(s.LastRefreshed)
	}

	return out
}

func howOf(how How) accessissuerv1.How {
	switch how {
	case HowCode:
		return accessissuerv1.How_HOW_CODE
	case HowDevice:
		return accessissuerv1.How_HOW_DEVICE
	case HowExchange:
		return accessissuerv1.How_HOW_EXCHANGE
	default:
		return accessissuerv1.How_HOW_UNSPECIFIED
	}
}
