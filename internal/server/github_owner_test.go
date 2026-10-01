package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"k8s.io/client-go/kubernetes/fake"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/policy"
)

// Three organisations the policy binds. Who owns each is not in the policy:
// it is recorded when the organisation is connected, which these tests do
// with [seedOrganisations] — two companies, each with a directory workspace
// and an organisation of its own, and one organisation nobody owns.
const ownerPolicy = `
version: 1
groups:
  all:platform:engineer: { members: [team-platform@globex.example] }
github:
  globex:
    teams:
      team-platform: { members: [all:platform:engineer] }
  acme:
    teams:
      team-platform: { members: [all:platform:engineer] }
  initech:
    teams:
      team-platform: { members: [all:platform:engineer] }
`

const ownerCatalogue = `
apps:
  - id: globex-bot
    org: globex
    permissions: {contents: read}
  - id: acme-bot
    org: acme
    permissions: {contents: read}
  - id: initech-bot
    org: initech
    permissions: {contents: read}
`

// ownerConsole is a console over ownerPolicy with every GitHub store wired,
// so that a call passing its role check goes on to fail (or not) for some
// other reason, and only a permission error means the role check refused.
func ownerConsole(t *testing.T) (*ConsoleServer, *Console) {
	t.Helper()
	store := newMemoryConnections()
	seedOrganisations(t, store)
	return ownerConsoleOver(t, store)
}

// seedOrganisations records the three organisations as connecting them would
// have: globex owned by C0north's directory, acme by C0south's, initech by
// nobody's.
func seedOrganisations(t *testing.T, store *memoryConnections) {
	t.Helper()
	for org, owner := range map[string]string{"globex": "C0north", "acme": "C0south", "initech": ""} {
		record := connection.Record{
			Org: org, AppID: 42, AppSlug: org + "-access-roster", InstallationID: 7, Owner: owner,
			ConnectedAt: time.Now().UTC(), ConnectedBy: "ada@north.example",
		}
		if err := store.Put(context.Background(), record, connection.Credential{Org: org, AppID: 42, InstallationID: 7, PrivateKey: "key"}); err != nil {
			t.Fatalf("seed %s: %v", org, err)
		}
	}
}

// ownerConsoleOver is [ownerConsole] over a store the test seeded itself.
func ownerConsoleOver(t *testing.T, store *memoryConnections) (*ConsoleServer, *Console) {
	t.Helper()
	startFakeGitHub(t)
	server, console := connectServer(t, store)
	console.deps.Hub = ownerHub(t)
	declared, err := policy.Parse([]byte(ownerPolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	console.deps.Authorizer = access.NewAuthorizer(set, nil, 0)
	client := kube.NewClient(fake.NewClientset(), "access-issuer", "access-issuer")
	console.deps.GitHubRunnerApps = kube.NewGitHubRunnerApps(client)
	console.deps.GitHubRunnerTiers = []string{"standard"}
	console.deps.GitHubCatalogueApps = kube.NewGitHubCatalogueApps(client)
	entries, err := catalogue.Parse([]byte(ownerCatalogue))
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	console.deps.GitHubCatalogue = entries
	console.deps.GitHubConfirmations = &memoryConfirmations{byOrg: map[string]connection.Confirmation{}}
	document, err := status.Encode(status.Org{Org: "globex", Breaker: &status.Breaker{Affected: 3, Members: 4, Fingerprint: "abc123"}})
	if err != nil {
		t.Fatal(err)
	}
	console.deps.GitHub = reports{status.Key("globex"): document}
	return server, console
}

func asIdentity(id access.Identity) context.Context {
	id.Email = "ada@example.test"
	return WithIdentity(context.Background(), id)
}

var (
	everywhere  = access.Identity{Role: access.RoleOperator}
	northOp     = access.Identity{Scopes: map[string]access.Role{"C0north": access.RoleOperator}}
	southOp     = access.Identity{Scopes: map[string]access.Role{"C0south": access.RoleOperator}}
	northViewer = access.Identity{Scopes: map[string]access.Role{"C0north": access.RoleViewer}}
	elsewhereOp = access.Identity{Scopes: map[string]access.Role{"C0nowhere": access.RoleOperator}}
)

func refused(err error) bool { return connect.CodeOf(err) == connect.CodePermissionDenied }

// Every mutating GitHub call asks the same question of the organisation it
// names: the installation-wide operator may act on any; the operator of the
// owning directory on its organisation alone; and nobody but the
// installation-wide operator on an organisation with no owner.
func TestEveryGitHubActionAsksWhoOwnsTheOrganisation(t *testing.T) {
	_, console := ownerConsole(t)
	app := map[string]string{"globex": "globex-controller", "acme": "acme-controller", "initech": "initech-controller"}
	actions := map[string]func(ctx context.Context, org string) error{
		"connect": func(ctx context.Context, org string) error {
			_, err := console.BeginGitHubConnect(ctx, connect.NewRequest(&directoryrosterv1.BeginGitHubConnectRequest{Org: org}))
			return err
		},
		"disconnect": func(ctx context.Context, org string) error {
			_, err := console.DisconnectGitHubOrganisation(ctx, connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: org}))
			return err
		},
		"confirm removals": func(ctx context.Context, org string) error {
			_, err := console.ConfirmGitHubRemovals(ctx, connect.NewRequest(&directoryrosterv1.ConfirmGitHubRemovalsRequest{Org: org, Fingerprint: "abc123"}))
			return err
		},
		"begin runner app": func(ctx context.Context, org string) error {
			_, err := console.BeginGitHubRunnerAppConnect(ctx, connect.NewRequest(&directoryrosterv1.BeginGitHubRunnerAppConnectRequest{Org: org, Tier: "standard"}))
			return err
		},
		"disconnect runner app": func(ctx context.Context, org string) error {
			_, err := console.DisconnectGitHubRunnerApp(ctx, connect.NewRequest(&directoryrosterv1.DisconnectGitHubRunnerAppRequest{Org: org, Tier: "standard"}))
			return err
		},
		"begin catalogue app": func(ctx context.Context, org string) error {
			_, err := console.BeginGitHubCatalogueAppConnect(ctx, connect.NewRequest(&directoryrosterv1.BeginGitHubCatalogueAppConnectRequest{Id: org + "-bot"}))
			return err
		},
		"check catalogue app": func(ctx context.Context, org string) error {
			_, err := console.CheckGitHubCatalogueApp(ctx, connect.NewRequest(&directoryrosterv1.CheckGitHubCatalogueAppRequest{Id: org + "-bot"}))
			return err
		},
		"disconnect catalogue app": func(ctx context.Context, org string) error {
			_, err := console.DisconnectGitHubCatalogueApp(ctx, connect.NewRequest(&directoryrosterv1.DisconnectGitHubCatalogueAppRequest{Id: org + "-bot"}))
			return err
		},
		"begin app": func(ctx context.Context, org string) error {
			_, err := console.BeginGitHubAppConnect(ctx, connect.NewRequest(&directoryrosterv1.BeginGitHubAppConnectRequest{Id: app[org]}))
			return err
		},
		"check app": func(ctx context.Context, org string) error {
			_, err := console.CheckGitHubApp(ctx, connect.NewRequest(&directoryrosterv1.CheckGitHubAppRequest{Id: app[org]}))
			return err
		},
		"disconnect app": func(ctx context.Context, org string) error {
			_, err := console.DisconnectGitHubApp(ctx, connect.NewRequest(&directoryrosterv1.DisconnectGitHubAppRequest{Id: app[org]}))
			return err
		},
		"app tokens": func(ctx context.Context, org string) error {
			_, err := console.ListGitHubAppTokens(ctx, connect.NewRequest(&directoryrosterv1.ListGitHubAppTokensRequest{Id: org + "-bot"}))
			return err
		},
	}
	who := []struct {
		name string
		id   access.Identity
		may  map[string]bool
	}{
		{"installation-wide operator", everywhere, map[string]bool{"globex": true, "acme": true, "initech": true}},
		{"operator of the directory owning globex", northOp, map[string]bool{"globex": true}},
		{"operator of the directory owning acme", southOp, map[string]bool{"acme": true}},
		{"operator of a directory owning nothing", elsewhereOp, nil},
		{"scoped viewer of globex's directory", northViewer, nil},
		{"installation-wide viewer", access.Identity{Role: access.RoleViewer}, nil},
	}
	for name, act := range actions {
		for _, w := range who {
			for _, org := range []string{"globex", "acme", "initech"} {
				// An action may disconnect what it acts on, and an owner is
				// the connection's: start each from the three connected.
				seedOrganisations(t, console.deps.GitHubOrgs.(*memoryConnections))
				err := act(asIdentity(w.id), org)
				switch {
				case w.may[org] && refused(err):
					t.Errorf("%s: %s on %s was refused: %v", name, w.name, org, err)
				case !w.may[org] && !refused(err):
					t.Errorf("%s: %s on %s = %v, want permission denied", name, w.name, org, err)
				}
			}
		}
		if err := act(context.Background(), "globex"); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: no identity = %v, want unauthenticated", name, err)
		}
	}
}

// The refusal names the organisation, so an operator of one company does
// not think a role was lost.
func TestTheRefusalNamesTheOrganisation(t *testing.T) {
	_, console := ownerConsole(t)
	_, err := console.DisconnectGitHubOrganisation(asIdentity(northOp),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: "acme"}))
	if !refused(err) || err.Error() != "permission_denied: this needs the operator role over acme's directory" {
		t.Errorf("another company's organisation = %v", err)
	}
	_, err = console.DisconnectGitHubOrganisation(asIdentity(northOp),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: "initech"}))
	if !refused(err) || err.Error() != "permission_denied: this needs the installation-wide operator role: initech names no owning directory" {
		t.Errorf("an organisation with no owner = %v", err)
	}
}

// A scoped viewer sees its own organisations and nothing of another
// company's, on the status page, the Apps list and an App's page; and
// a viewer of a directory that owns no organisation is refused outright.
func TestAScopedViewerSeesOnlyItsOwnersOrganisations(t *testing.T) {
	_, console := ownerConsole(t)
	ctx := asIdentity(northViewer)

	got, err := console.GetGitHubStatus(ctx, connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
	if err != nil {
		t.Fatalf("GetGitHubStatus: %v", err)
	}
	var seen []string
	for _, o := range got.Msg.GetOrganisations() {
		seen = append(seen, o.GetOrg())
		if o.GetCanOperate() {
			t.Errorf("a viewer is told it can operate %s", o.GetOrg())
		}
	}
	if !slices.Equal(seen, []string{"globex"}) {
		t.Errorf("organisations seen = %v, want [globex]", seen)
	}
	if got.Msg.GetLinkApp() != nil || len(got.Msg.GetLinks()) != 0 {
		t.Error("a scoped viewer was shown the link App or links, which are every organisation's")
	}
	for _, app := range got.Msg.GetCatalogueApps() {
		if app.GetOrg() != "globex" {
			t.Errorf("catalogue App %s of %s shown to globex's viewer", app.GetId(), app.GetOrg())
		}
	}

	listed, err := console.ListGitHubApps(ctx, connect.NewRequest(&directoryrosterv1.ListGitHubAppsRequest{}))
	if err != nil {
		t.Fatalf("ListGitHubApps: %v", err)
	}
	for _, app := range listed.Msg.GetApps() {
		if app.GetOrg() != "globex" || app.GetPurpose() == directoryrosterv1.AppPurpose_APP_PURPOSE_LINK {
			t.Errorf("App %s (%s) shown to globex's viewer", app.GetId(), app.GetOrg())
		}
	}
	if len(listed.Msg.GetApps()) == 0 {
		t.Error("the viewer sees none of its own Apps")
	}
	if !slices.Equal(listed.Msg.GetBoundOrganisations(), []string{"globex"}) {
		t.Errorf("bound organisations = %v, want [globex]", listed.Msg.GetBoundOrganisations())
	}

	if _, err = console.GetGitHubApp(ctx, connect.NewRequest(&directoryrosterv1.GetGitHubAppRequest{Id: "acme-controller"})); !refused(err) {
		t.Errorf("another company's App page = %v, want permission denied", err)
	}
	if _, err = console.GetGitHubApp(ctx, connect.NewRequest(&directoryrosterv1.GetGitHubAppRequest{Id: "globex-controller"})); err != nil {
		t.Errorf("its own App page = %v", err)
	}

	lonely := asIdentity(access.Identity{Scopes: map[string]access.Role{"C0nowhere": access.RoleViewer}})
	if _, err = console.GetGitHubStatus(lonely, connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{})); !refused(err) {
		t.Errorf("a viewer of a directory owning nothing = %v, want permission denied", err)
	}
}

// Each row says whether the caller may operate it, so the console does not
// carry the rule a second time.
func TestEachRowSaysWhetherTheCallerMayOperateIt(t *testing.T) {
	_, console := ownerConsole(t)
	can := func(id access.Identity) map[string]bool {
		got, err := console.GetGitHubStatus(asIdentity(id), connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
		if err != nil {
			t.Fatalf("GetGitHubStatus: %v", err)
		}
		out := map[string]bool{}
		for _, o := range got.Msg.GetOrganisations() {
			out[o.GetOrg()] = o.GetCanOperate()
		}
		return out
	}
	if got := can(everywhere); !got["globex"] || !got["acme"] || !got["initech"] || len(got) != 3 {
		t.Errorf("installation-wide operator = %v, want all three operable", got)
	}
	if got := can(northOp); len(got) != 1 || !got["globex"] {
		t.Errorf("operator of globex's directory = %v, want only globex, operable", got)
	}
	if got := can(access.Identity{Role: access.RoleViewer}); got["globex"] || got["acme"] || got["initech"] || len(got) != 3 {
		t.Errorf("installation-wide viewer = %v, want all three visible and none operable", got)
	}

	listed, err := console.ListGitHubApps(asIdentity(northOp), connect.NewRequest(&directoryrosterv1.ListGitHubAppsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range listed.Msg.GetApps() {
		if !app.GetCanOperate() {
			t.Errorf("App %s of %s: the operator of its directory is told it cannot operate it", app.GetId(), app.GetOrg())
		}
	}
}

// A record written before owners were recorded names none, and its
// organisation behaves as it always did: the installation-wide roles alone,
// scoped roles shut out of it.
func TestARecordWithNoOwnerMeansInstallationWideOnly(t *testing.T) {
	console := githubConsole(t, reports{})
	store := newMemoryConnections()
	// The record as v1.41.0 and earlier wrote it: no owner key at all.
	old, err := connection.DecodeRecord(`{"version":1,"org":"globex","app_id":42,"app_slug":"globex-access-roster","installation_id":7,` +
		`"connected_at":"2026-09-01T09:00:00Z","connected_by":"o@example.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Put(context.Background(), old, connection.Credential{Org: "globex", AppID: 42, InstallationID: 7, PrivateKey: "key"}); err != nil {
		t.Fatal(err)
	}
	console.deps.GitHubOrgs = store
	_, err = console.DisconnectGitHubOrganisation(asIdentity(northOp),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: "globex"}))
	if !refused(err) {
		t.Errorf("a scoped operator on a record with no owner = %v, want permission denied", err)
	}
	_, err = console.DisconnectGitHubOrganisation(asIdentity(everywhere),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: "globex"}))
	if refused(err) {
		t.Errorf("the installation-wide operator = %v", err)
	}
}

// The callback asks the role question again, by the same rule, about whoever
// is signed in when GitHub sends the browser back: a flow begun for one
// company's organisation does not finish as another company's operator. The
// owner it records is the one the flow was begun with.
func TestTheCallbackChecksTheOwnerAgain(t *testing.T) {
	store := newMemoryConnections()
	server, console := ownerConsoleOver(t, store)
	begin := func() (state string) {
		response, err := console.BeginGitHubConnect(asIdentity(northOp),
			connect.NewRequest(&directoryrosterv1.BeginGitHubConnectRequest{Org: "globex"}))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		return mustQuery(t, response.Msg.GetUrl(), "state")
	}
	finish := func(ctx context.Context) *httptest.ResponseRecorder {
		state := begin()
		query := url.Values{"state": {state}, "code": {"created"}}
		request := httptest.NewRequest(http.MethodGet, "/connect/github/callback?"+query.Encode(), nil).WithContext(ctx)
		request.AddCookie(&http.Cookie{Name: access.ConnectCookieName, Value: state})
		recorder := httptest.NewRecorder()
		server.githubCallback(recorder, request)
		return recorder
	}

	if got := finish(asIdentity(southOp)); got.Code != http.StatusForbidden {
		t.Errorf("another company's operator finishing = %d, want 403", got.Code)
	}
	if got := finish(asIdentity(northViewer)); got.Code != http.StatusForbidden {
		t.Errorf("a viewer finishing = %d, want 403", got.Code)
	}
	if len(store.records) != 0 {
		t.Fatalf("a refused callback kept a record: %v", store.records)
	}
	if got := finish(asIdentity(northOp)); got.Code != http.StatusFound {
		t.Errorf("the owning directory's operator finishing = %d, want 302", got.Code)
	}
	if got := store.records["globex"].Owner; got != "C0north" {
		t.Errorf("the owner recorded = %q, want the directory the flow was begun with", got)
	}
	// Created and not installed, the organisation now belongs to its owner.
	if got := finish(asIdentity(southOp)); got.Code != http.StatusForbidden {
		t.Errorf("another company's operator finishing a recorded organisation = %d, want 403", got.Code)
	}
	if got := finish(asIdentity(everywhere)); got.Code != http.StatusFound {
		t.Errorf("the installation-wide operator finishing = %d, want 302", got.Code)
	}
	if got := store.records["globex"].Owner; got != "C0north" {
		t.Errorf("finishing as the installation-wide operator moved the owner to %q", got)
	}
}

// Who may connect an organisation nobody has connected yet, and who then
// owns it: the same rule as for a Slack workspace, whichever call begins it.
func TestConnectingAnUnconnectedOrganisationFollowsTheOwnerRule(t *testing.T) {
	for _, c := range []struct {
		name  string
		who   access.Identity
		owner string // what the request names
		// want is the code refused with, or 0 for success; recorded is the
		// owner kept once the flow is finished.
		want     connect.Code
		recorded string
	}{
		{"the installation-wide operator chooses a directory", everywhere, "C0south", 0, "C0south"},
		{"the installation-wide operator may choose none", everywhere, "", 0, ""},
		{"the installation-wide operator cannot name a directory that is not connected", everywhere, "C0nowhere", connect.CodeInvalidArgument, ""},
		{"an operator of one directory owns it without saying so", northOp, "", 0, "C0north"},
		{"an operator of one directory may name it", northOp, "C0north", 0, "C0north"},
		{"an operator of one directory cannot hand it to another", northOp, "C0south", connect.CodePermissionDenied, ""},
		{"a foreign operator cannot name the other directory", southOp, "C0north", connect.CodePermissionDenied, ""},
		{"an operator of several must choose", bothOp, "", connect.CodeInvalidArgument, ""},
		{"an operator of several chooses among theirs", bothOp, "C0south", 0, "C0south"},
		{"an operator of several cannot choose another", bothOp, "C0nowhere", connect.CodePermissionDenied, ""},
		{"an operator of a directory that is not connected", elsewhereOp, "", connect.CodePermissionDenied, ""},
		{"a viewer", access.Identity{Role: access.RoleViewer}, "", connect.CodePermissionDenied, ""},
		{"the owner's viewer", northViewer, "C0north", connect.CodePermissionDenied, ""},
	} {
		for _, call := range []string{"BeginGitHubConnect", "BeginGitHubAppConnect"} {
			t.Run(c.name+"/"+call, func(t *testing.T) {
				store := newMemoryConnections()
				server, console := ownerConsoleOver(t, store)
				var (
					target string
					err    error
				)
				if call == "BeginGitHubConnect" {
					var response *connect.Response[directoryrosterv1.BeginGitHubConnectResponse]
					if response, err = console.BeginGitHubConnect(asIdentity(c.who), connect.NewRequest(
						&directoryrosterv1.BeginGitHubConnectRequest{Org: "globex", OwnerDirectory: c.owner})); err == nil {
						target = response.Msg.GetUrl()
					}
				} else {
					var response *connect.Response[directoryrosterv1.BeginGitHubAppConnectResponse]
					if response, err = console.BeginGitHubAppConnect(asIdentity(c.who), connect.NewRequest(
						&directoryrosterv1.BeginGitHubAppConnectRequest{Id: "globex-controller", OwnerDirectory: c.owner})); err == nil {
						target = response.Msg.GetUrl()
					}
				}
				if (err == nil) != (c.want == 0) || (err != nil && connect.CodeOf(err) != c.want) {
					t.Fatalf("begin = %v, want code %v (0 is success)", err, c.want)
				}
				if err != nil {
					return
				}
				state := mustQuery(t, target, "state")
				query := url.Values{"state": {state}, "code": {"created"}}
				request := httptest.NewRequest(http.MethodGet, "/connect/github/callback?"+query.Encode(), nil).WithContext(asIdentity(c.who))
				request.AddCookie(&http.Cookie{Name: access.ConnectCookieName, Value: state})
				recorder := httptest.NewRecorder()
				server.githubCallback(recorder, request)
				if recorder.Code != http.StatusFound {
					t.Fatalf("callback = %d: %s", recorder.Code, recorder.Body)
				}
				if got := store.records["globex"].Owner; got != c.recorded {
					t.Errorf("owner recorded = %q, want %q", got, c.recorded)
				}
			})
		}
	}
}

// Only the installation-wide operator changes a recorded owner, to a
// connected directory or to none, and the change is audited.
func TestOnlyTheInstallationWideOperatorChangesAnOrganisationsOwner(t *testing.T) {
	_, console := ownerConsole(t)
	recorded := audittest.New(t)
	console.deps.Audit = recorded
	change := func(ctx context.Context, org, owner string) error {
		_, err := console.ChangeGitHubOrganisationOwner(ctx, connect.NewRequest(
			&directoryrosterv1.ChangeGitHubOrganisationOwnerRequest{Org: org, OwnerDirectory: owner}))
		return err
	}
	for name, who := range map[string]access.Identity{
		"the owner's operator":     northOp,
		"the new owner's operator": southOp,
		"an operator of several":   bothOp,
		"a viewer":                 {Role: access.RoleViewer},
	} {
		if err := change(asIdentity(who), "globex", "C0south"); !refused(err) {
			t.Errorf("%s changed the owner: %v", name, err)
		}
	}
	if err := change(context.Background(), "globex", "C0south"); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("nobody signed in = %v", err)
	}
	if len(recorded.Find("roster.github_org.owner_changed")) != 0 {
		t.Error("a refused change was recorded")
	}
	if err := change(asIdentity(everywhere), "globex", "C0nowhere"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an owner that is not a connected directory = %v", err)
	}
	if err := change(asIdentity(everywhere), "umbrella", "C0south"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("an organisation that is not connected = %v", err)
	}
	if err := change(asIdentity(everywhere), "globex", "C0south"); err != nil {
		t.Fatalf("the installation-wide operator = %v", err)
	}
	// The new owner operates it now, and the old one does not.
	disconnect := func(who access.Identity) error {
		_, err := console.DisconnectGitHubOrganisation(asIdentity(who),
			connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: "globex"}))
		return err
	}
	if err := disconnect(northOp); !refused(err) {
		t.Errorf("the previous owner's operator = %v, want permission denied", err)
	}
	if err := change(asIdentity(everywhere), "globex", ""); err != nil {
		t.Fatalf("removing the owner = %v", err)
	}
	if err := disconnect(southOp); !refused(err) {
		t.Errorf("an operator of a removed owner = %v, want permission denied", err)
	}
	changed := recorded.Find("roster.github_org.owner_changed")
	if len(changed) != 2 || !strings.Contains(fmt.Sprint(changed[0]), "C0north") || !strings.Contains(fmt.Sprint(changed[0]), "C0south") ||
		!strings.Contains(fmt.Sprint(changed[1]), "none") {
		t.Errorf("owner changes recorded = %v", changed)
	}
}

// The status and the Apps list say who owns each organisation by the domain
// its directory is known by, who may change it, and what an operator may
// choose when connecting one.
func TestTheGitHubPagesShowTheOwnersDomainAndWhoMayChangeIt(t *testing.T) {
	_, console := ownerConsole(t)
	rows := func(id access.Identity) map[string]*directoryrosterv1.GitHubOrganisation {
		got, err := console.GetGitHubStatus(asIdentity(id), connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
		if err != nil {
			t.Fatalf("GetGitHubStatus: %v", err)
		}
		out := map[string]*directoryrosterv1.GitHubOrganisation{}
		for _, o := range got.Msg.GetOrganisations() {
			out[o.GetOrg()] = o
		}
		return out
	}
	all := rows(everywhere)
	if all["globex"].GetOwnerDirectory() != "C0north" || all["globex"].GetOwnerDomain() != "north.example" || !all["globex"].GetCanChangeOwner() ||
		all["initech"].GetOwnerDirectory() != "" || !all["initech"].GetCanChangeOwner() {
		t.Errorf("installation-wide rows = %v", all)
	}
	if scoped := rows(northOp)["globex"]; scoped.GetOwnerDomain() != "north.example" || scoped.GetCanChangeOwner() || !scoped.GetCanOperate() {
		t.Errorf("the owner's operator sees %v: may operate, may not change the owner", scoped)
	}
	listed, err := console.ListGitHubApps(asIdentity(everywhere), connect.NewRequest(&directoryrosterv1.ListGitHubAppsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var choices []string
	for _, dir := range listed.Msg.GetOwnerChoices() {
		choices = append(choices, dir.GetWorkspaceId()+"="+dir.GetPrimaryDomain())
	}
	if !slices.Equal(choices, []string{"C0north=north.example", "C0south=south.example"}) || !listed.Msg.GetMayConnectWithoutOwner() {
		t.Errorf("installation-wide choices = %v, without owner %v", choices, listed.Msg.GetMayConnectWithoutOwner())
	}
	for _, app := range listed.Msg.GetApps() {
		if app.GetId() == "globex-controller" && (app.GetOwnerDirectory() != "C0north" || app.GetOwnerDomain() != "north.example" || !app.GetCanChangeOwner()) {
			t.Errorf("globex-controller = %v", app)
		}
		if app.GetPurpose() == directoryrosterv1.AppPurpose_APP_PURPOSE_RUNNERS && app.GetCanChangeOwner() {
			t.Errorf("a runner App offers to change the organisation's owner: %v", app)
		}
	}
	scoped, err := console.ListGitHubApps(asIdentity(northOp), connect.NewRequest(&directoryrosterv1.ListGitHubAppsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := scoped.Msg.GetOwnerChoices(); len(got) != 1 || got[0].GetWorkspaceId() != "C0north" || scoped.Msg.GetMayConnectWithoutOwner() {
		t.Errorf("a scoped operator's choices = %v, without owner %v", got, scoped.Msg.GetMayConnectWithoutOwner())
	}
}
