package server

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/githubroster/connection"
)

// Refresh: the operator of the organisation's owner, or the
// installation-wide operator, asks for a pass now; it is kept as a marker the
// controller compares with its last pass, shown on the status, audited, and
// refused again within a minute. A viewer, a foreign operator and an
// organisation with nothing installed are refused.
func TestRequestingAGitHubPassIsForTheOrganisationsOperatorsAndRateLimited(t *testing.T) {
	store := newMemoryConnections()
	seedOrganisations(t, store)
	// A connected organisation whose App is created and not yet installed.
	if err := store.Put(context.Background(), connection.Record{Org: "pending", AppID: 1, AppSlug: "pending", Owner: "C0north"},
		connection.Credential{Org: "pending", AppID: 1, PrivateKey: "key"}); err != nil {
		t.Fatal(err)
	}
	_, console := ownerConsoleOver(t, store)
	trail := audittest.New(t)
	console.deps.Audit = trail
	ask := func(ctx context.Context, org string) error {
		_, err := console.RequestGitHubPass(ctx, connect.NewRequest(&directoryrosterv1.RequestGitHubPassRequest{Org: org}))
		return err
	}
	for name, who := range map[string]context.Context{
		"a viewer of the owner":  asIdentity(northViewer),
		"a foreign operator":     asIdentity(southOp),
		"an installation viewer": viewer(),
	} {
		if err := ask(who, "globex"); !refused(err) {
			t.Errorf("%s = %v, want permission denied", name, err)
		}
	}
	if err := ask(context.Background(), "globex"); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("nobody signed in = %v, want unauthenticated", err)
	}
	if err := ask(asIdentity(everywhere), "not a login!"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a bad login = %v", err)
	}
	if err := ask(asIdentity(everywhere), "pending"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("an organisation with nothing installed = %v, want failed precondition", err)
	}
	if err := ask(asIdentity(everywhere), "unknown"); connect.CodeOf(err) != connect.CodeFailedPrecondition && !refused(err) {
		t.Errorf("an organisation nobody connected = %v", err)
	}
	if requests, _ := store.PassRequests(context.Background()); len(requests) != 0 {
		t.Fatalf("a refused request left a marker: %v", requests)
	}
	if got := trail.Find("roster.github_org.pass_requested"); len(got) != 0 {
		t.Fatalf("a refused request was audited: %d records", len(got))
	}

	if err := ask(asIdentity(northOp), "globex"); err != nil {
		t.Fatalf("the owner's operator = %v", err)
	}
	if err := ask(asIdentity(everywhere), "globex"); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("a second request within a minute = %v, want resource exhausted", err)
	}
	// Another organisation has its own limit; the installation-wide operator may ask.
	if err := ask(asIdentity(everywhere), "acme"); err != nil {
		t.Errorf("the installation-wide operator = %v", err)
	}
	requests, _ := store.PassRequests(context.Background())
	if len(requests) != 2 || requests["globex"].By != "ada@example.test" || requests["globex"].At.IsZero() {
		t.Fatalf("markers = %+v", requests)
	}
	if got := trail.Find("roster.github_org.pass_requested"); len(got) != 2 || got[0].GetTargets()[0].GetId() != "globex" {
		t.Errorf("audit records = %v, want one per kept request", trail.Actions())
	}

	status, err := githubStatus(t, console, access.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if got := organisation(t, status, "globex").GetPassRequestedAt(); got == nil || got.AsTime().Sub(requests["globex"].At).Abs() > time.Second {
		t.Errorf("the status says the pass was requested at %v, want %v", got, requests["globex"].At)
	}
	if got := organisation(t, status, "initech").GetPassRequestedAt(); got != nil {
		t.Errorf("an organisation nobody asked for shows a request: %v", got)
	}
}
