package issuer_test

import (
	"context"
	"fmt"
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

	return issuer.NewSessionsServiceForTest(issuer.NewSessions(state, time.Hour), verifier())
}

// verifier is the stub the fixtures share: it reads "identity|group,group"
// so a test says who is calling in one string.
func verifier() func(context.Context, string) (string, []string, error) {
	return func(_ context.Context, bearer string) (string, []string, error) {
		identity, rest, _ := issuer.CutForTest(bearer, "|")
		if identity == "" {
			return "", nil, issuer.ErrUnverifiedForTest
		}

		var groups []string
		if rest != "" {
			groups = issuer.SplitForTest(rest, ",")
		}

		return identity, groups, nil
	}
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

	if _, err := sessions.Record(ctx, issuer.Opened{Identity: "ada@north.example", ClientID: "argocd", How: issuer.HowCode, Token: "t-ada"}); err != nil {
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
// person signed in. That is the global listing (INF-682), and a
// non-operator does not get it.
func TestListingEverythingIsRefused(t *testing.T) {
	t.Parallel()

	svc := service(t, issuer.NewMemoryState())

	if _, err := list(t, svc, "ada@north.example|",
		&accessissuerv1.ListSessionsRequest{}); err == nil {
		t.Error("a non-operator's unnarrowed listing was answered")
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
		if _, err := sessions.Record(ctx, issuer.Opened{Identity: "ada@north.example", ClientID: client, How: issuer.HowCode, Token: "t-" + client}); err != nil {
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

// The global listing -- neither identity nor client named -- is every
// session in the installation, and it is operator-only (INF-682): the
// incident case is the one where you do not know WHOSE session to look
// for.
func TestGlobalListingIsOperatorOnly(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sessions := issuer.NewSessions(state, time.Hour)
	svc := service(t, state)

	for _, who := range []string{"ada@north.example", "eli@south.example"} {
		if _, err := sessions.Record(ctx, issuer.Opened{Identity: who, ClientID: "argocd", How: issuer.HowCode, Token: "t-" + who}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	if _, err := list(t, svc, "ada@north.example|", &accessissuerv1.ListSessionsRequest{}); err == nil {
		t.Error("a non-operator listed every session")
	}

	got, err := list(t, svc, "ops@north.example|"+policy.GroupOperators, &accessissuerv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("an operator could not list every session: %v", err)
	}

	if len(got.GetSessions()) != 2 {
		t.Errorf("operator sees %d sessions, want 2", len(got.GetSessions()))
	}
}

// Paging the global listing returns a token while sessions remain, and
// none once the last page is reached; walking every page with it visits
// each session exactly once.
func TestGlobalListingPages(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sessions := issuer.NewSessions(state, time.Hour)
	svc := service(t, state)

	for i := 0; i < 5; i++ {
		identity := fmt.Sprintf("person%d@north.example", i)
		if _, err := sessions.Record(ctx, issuer.Opened{Identity: identity, ClientID: "argocd", How: issuer.HowCode, Token: "t-" + identity}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	seen := map[string]bool{}
	token := ""

	for {
		got, err := list(t, svc, "ops@north.example|"+policy.GroupOperators,
			&accessissuerv1.ListSessionsRequest{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatalf("list: %v", err)
		}

		if len(got.GetSessions()) == 0 {
			t.Fatal("a page came back empty while a token was still outstanding")
		}

		for _, s := range got.GetSessions() {
			if seen[s.GetId()] {
				t.Errorf("session %s returned twice across pages", s.GetId())
			}
			seen[s.GetId()] = true
		}

		token = got.GetNextPageToken()
		if token == "" {
			break
		}
	}

	if len(seen) != 5 {
		t.Errorf("paged through %d sessions, want 5", len(seen))
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

	ada, err := sessions.Record(ctx, issuer.Opened{Identity: "ada@north.example", ClientID: "argocd", How: issuer.HowCode, Token: "t-ada"})
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

// Signing a BROWSER out ends the sign-in, not only what it opened.
//
// This is the bug behind "I revoked all sessions, but still has access
// everywhere". The console's Revoke button sent a session id, that path
// never touched the sign-in, and a browser whose sessions were all ended
// one by one could still open new ones with no password: every row gone,
// the next /authorize completed silently.
func TestSigningABrowserOutEndsTheSignInToo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sessions := issuer.NewSessions(state, time.Hour)
	sso := issuer.NewSSO(state, time.Hour)
	svc := issuer.NewSessionsServiceWithSSOForTest(sessions, sso, verifier())

	browser, err := sso.Begin(ctx, "ada@north.example", "google")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	// Two clients opened from that browser, and one opened from another.
	for _, client := range []string{"argocd", "kargo"} {
		if _, err = sessions.Record(ctx, issuer.Opened{
			Identity: "ada@north.example", ClientID: client,
			How: issuer.HowCode, Token: "t-" + client, SSO: browser.ID,
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	if _, err = sessions.Record(ctx, issuer.Opened{
		Identity: "ada@north.example", ClientID: "k8s:kernel",
		How: issuer.HowCode, Token: "t-laptop", SSO: "another-browser",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	ended, err := revoke(t, svc, "ada@north.example|",
		&accessissuerv1.RevokeSessionsRequest{Identity: "ada@north.example", Sso: browser.ID})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if ended != 2 {
		t.Errorf("ended %d, want the 2 sessions that browser opened", ended)
	}

	// The sign-in is gone, which is the half that was missing: without
	// it the browser walks back in with no password.
	if _, found, err := sso.Get(ctx, browser.ID); err != nil || found {
		t.Errorf("the sign-in survived: found=%v err=%v", found, err)
	}

	// And the other browser is untouched — signing one out is not
	// signing out everywhere.
	left, err := sessions.List(ctx, issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(left) != 1 || left[0].ClientID != "k8s:kernel" {
		t.Errorf("left with %v, want only the other browser's session", left)
	}
}

// A sign-in id alone is not enough, exactly as a session id is not.
//
// The permission check is against the IDENTITY the caller names, so
// without reading the record first, naming your own identity and
// somebody else's browser would end their sign-in.
func TestASignInIdIsNotEnoughOnItsOwn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sessions := issuer.NewSessions(state, time.Hour)
	sso := issuer.NewSSO(state, time.Hour)
	svc := issuer.NewSessionsServiceWithSSOForTest(sessions, sso, verifier())

	hers, err := sso.Begin(ctx, "eli@south.example", "google")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	ended, err := revoke(t, svc, "ada@north.example|",
		&accessissuerv1.RevokeSessionsRequest{Identity: "ada@north.example", Sso: hers.ID})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if ended != 0 {
		t.Errorf("ended %d, want 0", ended)
	}

	if _, found, err := sso.Get(ctx, hers.ID); err != nil || !found {
		t.Errorf("Ada ended Eli's sign-in: found=%v err=%v", found, err)
	}
}

// The listing includes the SIGN-INS, not only what they opened.
//
// Leaving them out is what made the console lie by omission: every
// per-client session was shown and none of the sign-ins, so revoking
// every row emptied the page and left the thing that admits a browser
// exactly where it was. The console's own sign-in is worse than hidden —
// it opens no session at all, because it never redeems the code it gets
// back, so without this it appears nowhere.
func TestTheListingIncludesTheSignInsBehindTheSessions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sessions := issuer.NewSessions(state, time.Hour)
	sso := issuer.NewSSO(state, time.Hour)
	svc := issuer.NewSessionsServiceWithSSOForTest(sessions, sso, verifier())

	browser, err := sso.Begin(ctx, "ada@north.example", "google")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	// A sign-in that opened NOTHING, which is the console's shape.
	got, err := list(t, svc, "ada@north.example|", &accessissuerv1.ListSessionsRequest{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(got.GetSessions()) != 0 {
		t.Errorf("sessions = %d, want 0: nothing has been opened", len(got.GetSessions()))
	}

	if len(got.GetSignIns()) != 1 {
		t.Fatalf("sign-ins = %d, want 1: the sign-in exists and nothing else lists it", len(got.GetSignIns()))
	}

	if in := got.GetSignIns()[0]; in.GetId() != browser.ID || in.GetHow() != "google" {
		t.Errorf("signin = %+v, want the browser's own", in)
	}

	// And it disappears when the browser is signed out, which is the
	// whole point of listing it.
	if _, err = revoke(t, svc, "ada@north.example|",
		&accessissuerv1.RevokeSessionsRequest{Identity: "ada@north.example", Sso: browser.ID}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, err = list(t, svc, "ada@north.example|", &accessissuerv1.ListSessionsRequest{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(got.GetSignIns()) != 0 {
		t.Errorf("sign-ins = %d after signing the browser out, want 0", len(got.GetSignIns()))
	}
}
