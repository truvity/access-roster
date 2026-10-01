package server

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/backend/fake"
	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// ownerHub is a hub over the directories the owner tests name: C0north,
// which serves north.example, and C0south, which serves south.example.
// Nothing else is connected, so "a connected directory" in these tests is
// one of those two and C0nowhere is not.
func ownerHub(t *testing.T) *hub.Hub {
	t.Helper()
	h := hub.New(hub.NewMemoryStore(), hub.NewMemorySnapshots(), hub.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tenant := range []struct{ id, domain string }{{"C0north", "north.example"}, {"C0south", "south.example"}} {
		directory := fake.New(tenant.id, tenant.domain).WithAccount("admin@"+tenant.domain, "Admin", tenant.id)
		if _, err := h.Adopt(context.Background(), hub.Workspace{ID: tenant.id, Admin: "admin@" + tenant.domain}, directory); err != nil {
			t.Fatalf("Adopt %s: %v", tenant.id, err)
		}
	}
	h.Wait()
	return h
}

// seedSlackWorkspace records a connected Slack workspace as connecting it
// would have left it: the team recorded at the first install and the owner
// chosen then. A team of "" is a workspace whose App is created and not yet
// installed.
func seedSlackWorkspace(t *testing.T, store *kube.SlackWorkspaces, workspace, owner, team string) {
	t.Helper()
	record := connection.Record{
		Workspace: workspace, TeamID: team, Owner: owner, AppID: "A0" + workspace,
		AuthorizeURL:   "https://slack.com/oauth/v2/authorize?client_id=seeded",
		ManifestScopes: slices.Clone(connection.BotScopes),
		ConnectedAt:    time.Now().UTC(), ConnectedBy: "ada@north.example",
	}
	credential := connection.Credential{Workspace: workspace, AppID: record.AppID, ClientID: "client", ClientSecret: "secret"}
	if team != "" {
		record.BotUserID, credential.BotToken = "B"+team, "xoxb-seeded-"+team
		record.Scopes = slices.Clone(connection.BotScopes)
	}
	if err := store.Put(context.Background(), record, credential); err != nil {
		t.Fatalf("seed %s: %v", workspace, err)
	}
}

// The controllers' read of what each directory serves is gated like every
// other read: an installation-wide viewer is told of every connected
// directory, a scoped viewer of its own alone, and nobody else of any.
func TestListServedDomainsIsScopedLikeEveryOtherRead(t *testing.T) {
	console := &Console{deps: ConsoleDeps{Hub: ownerHub(t)}}
	list := func(ctx context.Context) ([]string, error) {
		got, err := console.ListServedDomains(ctx, connect.NewRequest(&directoryrosterv1.ListServedDomainsRequest{}))
		if err != nil {
			return nil, err
		}
		var out []string
		for _, dir := range got.Msg.GetDirectories() {
			out = append(out, dir.GetWorkspaceId()+"="+strings.Join(dir.GetDomains(), ",")+"/"+dir.GetPrimaryDomain())
		}
		return out, nil
	}
	got, err := list(asIdentity(access.Identity{Role: access.RoleViewer}))
	if want := []string{"C0north=north.example/north.example", "C0south=south.example/south.example"}; err != nil || !slices.Equal(got, want) {
		t.Errorf("an installation-wide viewer = %v, %v; want %v", got, err, want)
	}
	if got, err = list(asIdentity(northViewer)); err != nil || !slices.Equal(got, []string{"C0north=north.example/north.example"}) {
		t.Errorf("a scoped viewer = %v, %v; want its own directory alone", got, err)
	}
	if _, err = list(context.Background()); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("nobody signed in = %v", err)
	}
	if _, err = list(asIdentity(access.Identity{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("an identity with no role = %v", err)
	}
}

// A directory serving several domains is labelled by ALL the domains it is
// authoritative for, sorted; a served domain that is not authoritative is
// left out, and a directory with none is just its id.
func TestAnOwnerIsLabelledByEveryAuthoritativeDomain(t *testing.T) {
	dirs := []connectedDirectory{
		{
			id: "C0north", primary: "globex.example", served: []string{"alpha.example", "contested.example", "globex.example"},
			authoritative: []string{"alpha.example", "globex.example"},
		},
		{id: "C0bare", primary: "C0bare"},
	}
	if got := ownerDomains(dirs); got["C0north"] != "alpha.example, globex.example" || got["C0bare"] != "" {
		t.Errorf("ownerDomains = %v", got)
	}
	refs, _ := ownerChoices(access.Identity{Role: access.RoleOperator}, dirs)
	if len(refs) != 2 || !slices.Equal(refs[0].GetDomains(), []string{"alpha.example", "globex.example"}) || len(refs[1].GetDomains()) != 0 {
		t.Errorf("owner choices = %v", refs)
	}
}
