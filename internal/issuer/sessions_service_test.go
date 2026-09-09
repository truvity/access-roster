package issuer_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	accessissuerv1 "github.com/truvity/access-roster/gen/accessissuer/v1"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// service returns the session contract with a stubbed verifier, so the
// authorization rules can be exercised without minting real tokens: what
// is under test is who may act on whose sessions, not the signature.
func service(t *testing.T, state issuer.State) *issuer.SessionsService {
	t.Helper()

	return issuer.NewSessionsServiceForTest(
		issuer.NewSessions(state, time.Hour),
		func(_ context.Context, bearer string) (string, []string, error) {
			// The stub reads "identity|group,group" so a test says who is
			// calling in one string.
			identity, rest, _ := issuer.CutForTest(bearer, "|")
			if identity == "" {
				return "", nil, issuer.ErrUnverifiedForTest
			}

			var groups []string
			if rest != "" {
				groups = issuer.SplitForTest(rest, ",")
			}

			return identity, groups, nil
		},
	)
}

func list(t *testing.T, s *issuer.SessionsService, as string, req *accessissuerv1.ListSessionsRequest) (*accessissuerv1.ListSessionsResponse, error) {
	t.Helper()

	r := connect.NewRequest(req)
	r.Header().Set("Authorization", "Bearer "+as)

	got, err := s.ListSessions(context.Background(), r)
	if err != nil {
		return nil, err
	}

	return got.Msg, nil
}

func revoke(t *testing.T, s *issuer.SessionsService, as string, req *accessissuerv1.RevokeSessionsRequest) (int32, error) {
	t.Helper()

	r := connect.NewRequest(req)
	r.Header().Set("Authorization", "Bearer "+as)

	got, err := s.RevokeSessions(context.Background(), r)
	if err != nil {
		return 0, err
	}

	return got.Msg.GetEnded(), nil
}

// Your own sessions are yours to see and end; somebody else's need an
// operator. That asymmetry is the whole authorization model, and it is
// why "sign out everywhere" needs no special case.
func TestYourOwnSessionsAreYours(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sessions := issuer.NewSessions(state, time.Hour)
	svc := service(t, state)

	if _, err := sessions.Record(ctx, "ada@north.example", "argocd", issuer.HowCode, "t-ada"); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Ada, no groups at all.
	got, err := list(t, svc, "ada@north.example|", &accessissuerv1.ListSessionsRequest{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("Ada listing her own: %v", err)
	}

	if len(got.GetSessions()) != 1 {
		t.Errorf("Ada sees %d of her own sessions, want 1", len(got.GetSessions()))
	}

	// Eli, no groups, asking about Ada.
	if _, err = list(t, svc, "eli@south.example|", &accessissuerv1.ListSessionsRequest{Identity: "ada@north.example"}); err == nil {
		t.Error("somebody else listed Ada's sessions without being an operator")
	}

	// An operator, asking about Ada.
	if _, err = list(t, svc, "ops@north.example|"+policy.GroupOperators,
		&accessissuerv1.ListSessionsRequest{Identity: "ada@north.example"}); err != nil {
		t.Errorf("an operator could not list Ada's sessions: %v", err)
	}
}

// A request that narrows to neither an identity nor a client names every
// person signed in. This service does not answer that.
func TestListingEverythingIsRefused(t *testing.T) {
	t.Parallel()

	svc := service(t, issuer.NewMemoryState())

	if _, err := list(t, svc, "ops@north.example|"+policy.GroupOperators,
		&accessissuerv1.ListSessionsRequest{}); err == nil {
		t.Error("an unnarrowed listing was answered")
	}
}

// Listing a client names everybody on it, so it is an operator's
// question even though listing your own is anyone's.
func TestListingAClientIsAnOperators(t *testing.T) {
	t.Parallel()

	svc := service(t, issuer.NewMemoryState())

	if _, err := list(t, svc, "ada@north.example|",
		&accessissuerv1.ListSessionsRequest{ClientId: "argocd"}); err == nil {
		t.Error("a non-operator listed a client's sessions")
	}
}

// Ending one client's session leaves the others: an operator dealing with
// one incident must not cut off unrelated work.
func TestRevokeNarrowsToOneClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sessions := issuer.NewSessions(state, time.Hour)
	svc := service(t, state)

	for _, client := range []string{"argocd", "k8s:kernel"} {
		if _, err := sessions.Record(ctx, "ada@north.example", client, issuer.HowCode, "t-"+client); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	ended, err := revoke(t, svc, "ada@north.example|",
		&accessissuerv1.RevokeSessionsRequest{Identity: "ada@north.example", ClientId: "argocd"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if ended != 1 {
		t.Errorf("ended %d, want 1", ended)
	}

	left, err := sessions.List(ctx, issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(left) != 1 || left[0].ClientID != "k8s:kernel" {
		t.Errorf("Ada keeps %v, want only her kubectl session", left)
	}
}

// A session id alone must not be enough to end somebody else's: the id is
// checked against the identity the caller is allowed to act on, and a
// mismatch answers exactly as an absent session does, so an id cannot be
// probed.
func TestASessionIdIsNotEnoughOnItsOwn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sessions := issuer.NewSessions(state, time.Hour)
	svc := service(t, state)

	ada, err := sessions.Record(ctx, "ada@north.example", "argocd", issuer.HowCode, "t-ada")
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	// Eli names his own identity — which he may act on — and Ada's id.
	ended, err := revoke(t, svc, "eli@south.example|",
		&accessissuerv1.RevokeSessionsRequest{Identity: "eli@south.example", SessionId: ada.ID})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if ended != 0 {
		t.Errorf("ended %d of somebody else's sessions", ended)
	}

	left, err := sessions.List(ctx, issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(left) != 1 {
		t.Error("Ada's session was ended by somebody naming its id")
	}
}
