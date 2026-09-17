package server

import (
	"context"
	"encoding/json"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/kube"
)

// kinds records the kind of every audit event.
type kinds struct {
	mu   sync.Mutex
	seen []string
}

func (k *kinds) Record(_ context.Context, e audit.Event) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.seen = append(k.seen, e.Kind)
}

func (k *kinds) RecordDurable(ctx context.Context, e audit.Event) error {
	k.Record(ctx, e)
	return nil
}

func (k *kinds) list() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.seen)
}

const testCatalogue = `
apps:
  - id: renovate
    org: globex
    description: Dependency updates
    permissions: {contents: write, pull_requests: write}
    installation: selected
    grants:
      - group: all:platform:engineer
        repositories: ["*"]
        permissions: {contents: read}
      - group: all:nobody:declares
        repositories: [docs]
        permissions: {pull_requests: read}
  - id: releases
    org: globex
    permissions: {contents: write}
`

// catalogueServer is connectServer with catalogue Apps kept in a Secret,
// as a deployment keeps them.
func catalogueServer(t *testing.T) (*ConsoleServer, *Console, *kube.Client, *kinds) {
	t.Helper()
	server, console := connectServer(t, newMemoryConnections())
	client := kube.NewClient(fake.NewClientset(), "access-issuer", "access-issuer")
	declared, err := catalogue.Parse([]byte(testCatalogue))
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	recorded := &kinds{}
	console.deps.GitHubCatalogue = declared
	console.deps.GitHubCatalogueApps = kube.NewGitHubCatalogueApps(client)
	console.deps.Audit = recorded
	return server, console, client, recorded
}

func catalogueSecret(t *testing.T, client *kube.Client) map[string][]byte {
	t.Helper()
	secret, err := client.API().CoreV1().Secrets("access-issuer").Get(context.Background(), "access-issuer-github-catalogue-apps", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read the catalogue Apps Secret: %v", err)
	}
	return secret.Data
}

func catalogueApp(t *testing.T, console *Console, id string) *directoryrosterv1.GitHubCatalogueApp {
	t.Helper()
	status, err := console.GetGitHubStatus(operator(), connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
	if err != nil {
		t.Fatalf("GetGitHubStatus: %v", err)
	}
	if !status.Msg.GetCatalogueAvailable() {
		t.Fatal("the catalogue is not available")
	}
	for _, app := range status.Msg.GetCatalogueApps() {
		if app.GetId() == id {
			return app
		}
	}
	t.Fatalf("no catalogue App %s in %v", id, status.Msg.GetCatalogueApps())
	return nil
}

// Declared, created, installed, drifted, disconnected: the whole life of a
// catalogue App, as an operator walks it and as GitHub answers.
func TestACatalogueAppIsCreatedInstalledCheckedForDriftAndDisconnected(t *testing.T) {
	github := startFakeGitHub(t)
	server, console, client, recorded := catalogueServer(t)
	ctx := context.Background()

	// Declared and not created: shown with what it would ask for, and
	// which of its grants' groups the policy knows.
	app := catalogueApp(t, console, "renovate")
	if app.GetState() != catalogueNotCreated || app.GetName() != "globex-renovate" || app.GetInstallation() != "selected" ||
		!app.GetDeclared() || len(app.GetPermissions()) != 2 || len(app.GetGrants()) != 2 ||
		!app.GetGrants()[0].GetGroupDeclared() || app.GetGrants()[1].GetGroupDeclared() {
		t.Errorf("before Create = %+v", app)
	}

	begun, err := console.BeginGitHubCatalogueAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubCatalogueAppConnectRequest{Id: "renovate"}))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	var manifest githubapp.Manifest
	if err = json.Unmarshal([]byte(begun.Msg.GetManifest()), &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.Name != "globex-renovate" || manifest.Description != "Dependency updates" || manifest.DefaultPermissions["pull_requests"] != "write" ||
		manifest.RedirectURL != "https://access.example"+githubCatalogueCallbackPath || manifest.SetupURL != "https://access.example"+githubCatalogueSetupPath ||
		!strings.HasPrefix(begun.Msg.GetUrl(), "https://github.example/organizations/globex/settings/apps/new?state=") {
		t.Errorf("manifest = %+v, url %s", manifest, begun.Msg.GetUrl())
	}
	cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")

	// No other GitHub flow finishes a catalogue App's, nor the other way.
	if got := redirect(server.githubRunnerCallback, githubRunnerCallbackPath, url.Values{"code": {"created"}, "state": {state}}, cookie); got.Code != 400 {
		t.Errorf("a catalogue state at the runner callback = %d, want 400", got.Code)
	}

	created := redirect(server.githubCatalogueCallback, githubCatalogueCallbackPath, url.Values{"code": {"created"}, "state": {state}}, cookie)
	if created.Code != 302 || !strings.Contains(created.Header().Get("Location"), "/installations/new?state=") {
		t.Fatalf("after Create = %d to %q:\n%s", created.Code, created.Header().Get("Location"), created.Body)
	}
	data := catalogueSecret(t, client)
	for _, property := range []string{catalogueapp.AppIDProperty, catalogueapp.InstallationIDProperty, catalogueapp.PrivateKeyProperty} {
		if _, ok := data[catalogueapp.Key("renovate", property)]; ok {
			t.Errorf("before Install the Secret already has %s", property)
		}
	}
	if string(data["renovate.pending_private_key"]) != github.pem {
		t.Error("the App's key was not kept while it waits to be installed")
	}

	// Created, and GitHub holds what was declared: GitHub's own implied
	// metadata read is not drift.
	github.app = map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}
	if app = catalogueApp(t, console, "renovate"); app.GetState() != catalogueCreated || len(app.GetDrift()) != 0 || app.GetReason() != "" {
		t.Errorf("created = state %s, drift %v, reason %q", app.GetState(), app.GetDrift(), app.GetReason())
	}
	// Begin again picks up at Install rather than creating a second App.
	again, err := console.BeginGitHubCatalogueAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubCatalogueAppConnectRequest{Id: "renovate"}))
	if err != nil || again.Msg.GetManifest() != "" || !strings.Contains(again.Msg.GetUrl(), "/apps/globex-access-roster/installations/new") {
		t.Errorf("Begin after Create = %+v, %v", again.Msg, err)
	}

	github.installed = map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}
	install := created.Header().Get("Location")
	installed := redirect(server.githubCatalogueSetup, githubCatalogueSetupPath,
		url.Values{"installation_id": {"999"}, "state": {mustQuery(t, install, "state")}}, cookieFrom(t, created.Header()))
	if installed.Code != 302 || installed.Header().Get("Location") != "/console/#/github/apps/catalogue" {
		t.Fatalf("after Install = %d to %q:\n%s", installed.Code, installed.Header().Get("Location"), installed.Body)
	}
	data = catalogueSecret(t, client)
	if string(data["renovate.github_app_id"]) != "42" || string(data["renovate.github_app_installation_id"]) != "7" ||
		string(data["renovate.github_app_private_key"]) != github.pem {
		t.Errorf("after Install the keys are %v", slices.Sorted(maps.Keys(data)))
	}
	if _, pending := data["renovate.pending_private_key"]; pending {
		t.Error("the pending key outlived Install")
	}
	var record catalogueapp.Record
	if err = json.Unmarshal(data["renovate.record.json"], &record); err != nil || record.Version != 1 || record.ID != "renovate" ||
		record.Org != "globex" || record.AppID != 42 || record.InstallationID != 7 || record.ConnectedBy != "ada@north.example" {
		t.Errorf("record = %+v, %v", record, err)
	}
	// What a token exchange reads: the key and the installation, by id.
	if got, key, ok, err := console.deps.GitHubCatalogueApps.Get(ctx, "renovate"); err != nil || !ok || key != github.pem || got.InstallationID != 7 {
		t.Errorf("Get = %+v, key %t, %t, %v", got, key == github.pem, ok, err)
	}

	app = catalogueApp(t, console, "renovate")
	if app.GetState() != catalogueInstalled || app.GetRepositorySelection() != "selected" || app.GetConnectedBy() != "ada@north.example" {
		t.Errorf("installed = %+v", app)
	}
	if _, err = console.BeginGitHubCatalogueAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubCatalogueAppConnectRequest{Id: "renovate"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("creating an installed App again = %v, want failed precondition", err)
	}

	// An owner edits the App on GitHub: it now asks for more, and the
	// installation has not approved it. Re-check shows both.
	github.app = map[string]string{"contents": "write", "pull_requests": "read", "issues": "write", "metadata": "read"}
	checked, err := console.CheckGitHubCatalogueApp(operator(), connect.NewRequest(&directoryrosterv1.CheckGitHubCatalogueAppRequest{Id: "renovate"}))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	app = checked.Msg.GetApp()
	drift := strings.Join(app.GetDrift(), "\n")
	if app.GetState() != catalogueDrifted || !strings.Contains(drift, "issues: write, which the catalogue does not declare") ||
		!strings.Contains(drift, "pull_requests: read, and the catalogue declares write") || !strings.Contains(drift, "approve the permission request") {
		t.Errorf("drifted = %s:\n%s", app.GetState(), drift)
	}
	rows := map[string]*directoryrosterv1.GitHubAppPermission{}
	for _, row := range app.GetPermissions() {
		rows[row.GetName()] = row
	}
	if rows["pull_requests"].GetDeclared() != "write" || rows["pull_requests"].GetApp() != "read" || rows["pull_requests"].GetInstallation() != "write" ||
		rows["issues"].GetDeclared() != "" || rows["issues"].GetApp() != "write" {
		t.Errorf("permission rows = %v", app.GetPermissions())
	}

	// Uninstalled on GitHub by somebody else: drift, with what to do.
	github.installed = nil
	checked, _ = console.CheckGitHubCatalogueApp(operator(), connect.NewRequest(&directoryrosterv1.CheckGitHubCatalogueAppRequest{Id: "renovate"}))
	if !strings.Contains(strings.Join(checked.Msg.GetApp().GetDrift(), "\n"), "installation is gone on GitHub") {
		t.Errorf("an uninstalled App = %v", checked.Msg.GetApp().GetDrift())
	}

	gone, err := console.DisconnectGitHubCatalogueApp(operator(),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubCatalogueAppRequest{Id: "renovate"}))
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if !gone.Msg.GetUninstalled() || !slices.Equal(github.uninstalled, []string{"7"}) ||
		gone.Msg.GetAppSettingsUrl() != "https://github.example/organizations/globex/settings/apps/globex-access-roster" {
		t.Errorf("Disconnect = %+v, calls %v", gone.Msg, github.uninstalled)
	}
	for key := range catalogueSecret(t, client) {
		if strings.HasPrefix(key, "renovate.") {
			t.Errorf("%s outlived Disconnect", key)
		}
	}
	if app = catalogueApp(t, console, "renovate"); app.GetState() != catalogueNotCreated {
		t.Errorf("after Disconnect = %s", app.GetState())
	}
	if _, err = console.DisconnectGitHubCatalogueApp(operator(),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubCatalogueAppRequest{Id: "renovate"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("disconnecting what is gone = %v, want not found", err)
	}

	want := []string{"github.catalogue-app.created", "github.catalogue-app.installed", "github.catalogue-app.disconnected"}
	if got := recorded.list(); !slices.Equal(got, want) {
		t.Errorf("audit = %v, want %v", got, want)
	}
}

// Only an operator creates one, only an App the catalogue declares, and
// only under the organisation the catalogue names.
func TestACatalogueAppIsOnlyWhatTheCatalogueDeclares(t *testing.T) {
	github := startFakeGitHub(t)
	server, console, client, _ := catalogueServer(t)
	viewer := WithIdentity(context.Background(), access.Identity{Role: access.RoleViewer})
	for _, c := range []struct {
		name string
		ctx  context.Context
		id   string
		want connect.Code
	}{
		{"a viewer", viewer, "renovate", connect.CodePermissionDenied},
		{"an undeclared id", operator(), "something-else", connect.CodeInvalidArgument},
	} {
		_, err := console.BeginGitHubCatalogueAppConnect(c.ctx, connect.NewRequest(&directoryrosterv1.BeginGitHubCatalogueAppConnectRequest{Id: c.id}))
		if connect.CodeOf(err) != c.want {
			t.Errorf("%s = %v, want %v", c.name, err, c.want)
		}
	}
	_, err := console.CheckGitHubCatalogueApp(viewer, connect.NewRequest(&directoryrosterv1.CheckGitHubCatalogueAppRequest{Id: "renovate"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer's re-check = %v", err)
	}

	// Created by somebody under another organisation: refused, and nothing
	// is kept.
	github.owner = "initech"
	begun, err := console.BeginGitHubCatalogueAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubCatalogueAppConnectRequest{Id: "releases"}))
	if err != nil {
		t.Fatal(err)
	}
	refused := redirect(server.githubCatalogueCallback, githubCatalogueCallbackPath,
		url.Values{"code": {"created"}, "state": {mustQuery(t, begun.Msg.GetUrl(), "state")}}, cookieFrom(t, begun.Header()))
	if refused.Code != 409 || !strings.Contains(refused.Body.String(), "created under initech") {
		t.Errorf("an App under another organisation = %d:\n%s", refused.Code, refused.Body)
	}
	if records, _ := console.deps.GitHubCatalogueApps.List(context.Background()); len(records) != 0 {
		t.Errorf("an App under another organisation was kept: %+v", records)
	}
	_ = client

	// A deployment keeping no state in Kubernetes keeps no catalogue Apps.
	_, none := connectServer(t, newMemoryConnections())
	if _, err = none.BeginGitHubCatalogueAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubCatalogueAppConnectRequest{Id: "renovate"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("no store = %v, want failed precondition", err)
	}
	status, err := none.GetGitHubStatus(operator(), connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
	if err != nil || status.Msg.GetCatalogueAvailable() || len(status.Msg.GetCatalogueApps()) != 0 {
		t.Errorf("status without a store = %v, %v", status.Msg.GetCatalogueApps(), err)
	}
}

// The page does not ask GitHub on every load: an answer is kept for a
// minute, a re-check asks again, and a failure is the App's reason rather
// than the page's error.
func TestWhatGitHubSaysOfACatalogueAppIsCachedBriefly(t *testing.T) {
	github := startFakeGitHub(t)
	_, console, _, _ := catalogueServer(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	console.githubSeen.clock = func() time.Time { return now }
	github.app = map[string]string{"contents": "write"}
	github.installed = map[string]string{"contents": "write"}
	if err := console.deps.GitHubCatalogueApps.Put(context.Background(), catalogueapp.Record{
		ID: "releases", Org: "globex", AppID: 42, AppSlug: "globex-releases", InstallationID: 7, ConnectedAt: now,
	}, github.pem); err != nil {
		t.Fatal(err)
	}
	reads := func() int {
		github.mu.Lock()
		defer github.mu.Unlock()
		return github.reads
	}

	if app := catalogueApp(t, console, "releases"); app.GetState() != catalogueInstalled || reads() != 2 {
		t.Fatalf("first read = %s after %d calls, want installed after 2", app.GetState(), reads())
	}
	github.app = map[string]string{"contents": "read"}
	now = now.Add(30 * time.Second)
	if app := catalogueApp(t, console, "releases"); app.GetState() != catalogueInstalled || reads() != 2 {
		t.Errorf("within the minute = %s after %d calls, want the cached answer", app.GetState(), reads())
	}
	if checked, err := console.CheckGitHubCatalogueApp(operator(),
		connect.NewRequest(&directoryrosterv1.CheckGitHubCatalogueAppRequest{Id: "releases"})); err != nil ||
		checked.Msg.GetApp().GetState() != catalogueDrifted || reads() != 4 {
		t.Errorf("re-check = %v after %d calls, %v", checked.Msg.GetApp(), reads(), err)
	}
	github.app = map[string]string{"contents": "write"}
	now = now.Add(2 * time.Minute)
	if app := catalogueApp(t, console, "releases"); app.GetState() != catalogueInstalled || reads() != 6 {
		t.Errorf("after the minute = %s after %d calls, want asked again", app.GetState(), reads())
	}

	// GitHub unreachable: the status still answers, the App says why.
	console.deps.GitHubCatalogueApps = brokenKeys{console.deps.GitHubCatalogueApps}
	now = now.Add(2 * time.Minute)
	app := catalogueApp(t, console, "releases")
	if app.GetState() != catalogueInstalled || !strings.Contains(app.GetReason(), "key") {
		t.Errorf("without a usable key = %s, reason %q", app.GetState(), app.GetReason())
	}
}

// brokenKeys is a store whose key has been damaged.
type brokenKeys struct{ GitHubCatalogueApps }

func (b brokenKeys) Get(ctx context.Context, id string) (catalogueapp.Record, string, bool, error) {
	record, _, ok, err := b.GitHubCatalogueApps.Get(ctx, id)
	return record, "not a key", ok, err
}

// An App whose entry was removed from the catalogue is still listed, so it
// can be disconnected, and cannot be created again.
func TestAnAppTheCatalogueNoLongerDeclaresCanStillBeDisconnected(t *testing.T) {
	github := startFakeGitHub(t)
	_, console, _, _ := catalogueServer(t)
	if err := console.deps.GitHubCatalogueApps.Put(context.Background(), catalogueapp.Record{
		ID: "retired", Org: "globex", AppID: 42, AppSlug: "globex-retired", InstallationID: 7,
	}, github.pem); err != nil {
		t.Fatal(err)
	}
	app := catalogueApp(t, console, "retired")
	if app.GetDeclared() || app.GetState() != catalogueInstalled || app.GetReason() == "" {
		t.Errorf("retired = %+v", app)
	}
	if github.reads != 0 {
		t.Errorf("GitHub was asked about an App nothing declares: %d calls", github.reads)
	}
	if _, err := console.DisconnectGitHubCatalogueApp(operator(),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubCatalogueAppRequest{Id: "retired"})); err != nil {
		t.Errorf("Disconnect = %v", err)
	}
}
