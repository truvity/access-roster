package server

import (
	"context"
	"encoding/json"
	"maps"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/kube"
)

// runnerServer is connectServer with runner Apps kept in a Secret, as a
// deployment keeps them, for the tiers given.
func runnerServer(t *testing.T, tiers ...string) (*ConsoleServer, *Console, *kube.Client) {
	t.Helper()
	server, console := connectServer(t, newMemoryConnections())
	client := kube.NewClient(fake.NewClientset(), "access-issuer", "access-issuer")
	console.deps.GitHubRunnerApps = kube.NewGitHubRunnerApps(client)
	console.deps.GitHubRunnerTiers = tiers
	return server, console, client
}

func runnerSecret(t *testing.T, client *kube.Client) map[string][]byte {
	t.Helper()
	secret, err := client.API().CoreV1().Secrets("access-issuer").Get(context.Background(), "access-issuer-github-runner-apps", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read the runner Apps Secret: %v", err)
	}
	return secret.Data
}

// Create, then Install, as for an organisation's App. The three keys a
// runner scale set reads exist only once the App is installed, so a copy of
// the Secret taken in between can never hand runners an App they cannot
// register with.
func TestARunnerAppIsCreateThenInstallAndItsKeysAppearOnlyOnceInstalled(t *testing.T) {
	github := startFakeGitHub(t)
	server, console, client := runnerServer(t, "preview", "stable")

	begun, err := console.BeginGitHubRunnerAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubRunnerAppConnectRequest{Org: "truvity", Tier: "stable"}))
	if err != nil {
		t.Fatalf("BeginGitHubRunnerAppConnect: %v", err)
	}
	var manifest githubapp.Manifest
	if err = json.Unmarshal([]byte(begun.Msg.GetManifest()), &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.Name != "truvity-runners-stable" || manifest.DefaultPermissions["organization_self_hosted_runners"] != "write" ||
		manifest.RedirectURL != "https://access.example"+githubRunnerCallbackPath || manifest.SetupURL != "https://access.example"+githubRunnerSetupPath {
		t.Errorf("manifest = %+v", manifest)
	}
	cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")

	// An organisation connect's callback does not finish a runner flow.
	if got := redirect(server.githubCallback, githubCallbackPath, url.Values{"code": {"created"}, "state": {state}}, cookie); got.Code != 400 {
		t.Errorf("a runner state at the organisation callback = %d, want 400", got.Code)
	}

	created := redirect(server.githubRunnerCallback, githubRunnerCallbackPath, url.Values{"code": {"created"}, "state": {state}}, cookie)
	if created.Code != 302 || !strings.Contains(created.Header().Get("Location"), "/installations/new?state=") {
		t.Fatalf("after Create = %d to %q:\n%s", created.Code, created.Header().Get("Location"), created.Body)
	}
	data := runnerSecret(t, client)
	for _, property := range []string{runnerapp.AppIDProperty, runnerapp.InstallationIDProperty, runnerapp.PrivateKeyProperty} {
		if _, ok := data[runnerapp.Key("stable", "truvity", property)]; ok {
			t.Errorf("before Install the Secret already has %s", property)
		}
	}
	if key, ok, _ := console.deps.GitHubRunnerApps.PrivateKey(context.Background(), "stable", "truvity"); !ok || key != github.pem {
		t.Error("the App's key was not kept while it waits to be installed")
	}

	install := created.Header().Get("Location")
	installed := redirect(server.githubRunnerSetup, githubRunnerSetupPath,
		url.Values{"installation_id": {"999"}, "state": {mustQuery(t, install, "state")}}, cookieFrom(t, created.Header()))
	if installed.Code != 302 || installed.Header().Get("Location") != "/console/#/github/apps" {
		t.Fatalf("after Install = %d to %q:\n%s", installed.Code, installed.Header().Get("Location"), installed.Body)
	}
	data = runnerSecret(t, client)
	if string(data["stable.truvity.github_app_id"]) != "42" || string(data["stable.truvity.github_app_installation_id"]) != "7" ||
		string(data["stable.truvity.github_app_private_key"]) != github.pem {
		t.Errorf("after Install the keys are %v", slices.Sorted(maps.Keys(data)))
	}
	if _, pending := data["stable.truvity.pending_private_key"]; pending {
		t.Error("the pending key outlived Install")
	}

	status, err := console.GetGitHubStatus(operator(), connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
	if err != nil {
		t.Fatalf("GetGitHubStatus: %v", err)
	}
	if !slices.Equal(status.Msg.GetRunnerTiers(), []string{"preview", "stable"}) || len(status.Msg.GetRunnerApps()) != 1 ||
		!status.Msg.GetRunnerApps()[0].GetInstalled() || status.Msg.GetRunnerApps()[0].GetConnectedBy() != "ada@north.example" {
		t.Errorf("status = tiers %v, apps %+v", status.Msg.GetRunnerTiers(), status.Msg.GetRunnerApps())
	}

	_, err = console.BeginGitHubRunnerAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubRunnerAppConnectRequest{Org: "truvity", Tier: "stable"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("creating an installed tier's App again = %v, want failed precondition", err)
	}
	// Another tier is another App.
	if _, err = console.BeginGitHubRunnerAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubRunnerAppConnectRequest{Org: "truvity", Tier: "preview"})); err != nil {
		t.Errorf("the preview tier beside an installed stable one = %v", err)
	}
}

// Only an operator, only an organisation the policy binds, only a tier the
// deployment declares.
func TestARunnerAppNeedsADeclaredTierABoundOrganisationAndAnOperator(t *testing.T) {
	startFakeGitHub(t)
	_, console, _ := runnerServer(t, "stable")
	begin := func(ctx context.Context, org, tier string) error {
		_, err := console.BeginGitHubRunnerAppConnect(ctx, connect.NewRequest(&directoryrosterv1.BeginGitHubRunnerAppConnectRequest{Org: org, Tier: tier}))
		return err
	}
	viewer := WithIdentity(context.Background(), access.Identity{Role: access.RoleViewer})
	for _, c := range []struct {
		name      string
		ctx       context.Context
		org, tier string
		want      connect.Code
	}{
		{"a viewer", viewer, "truvity", "stable", connect.CodePermissionDenied},
		{"an undeclared tier", operator(), "truvity", "preview", connect.CodeInvalidArgument},
		{"an unbound organisation", operator(), "not-bound", "stable", connect.CodeFailedPrecondition},
		{"a malformed login", operator(), "not a login", "stable", connect.CodeInvalidArgument},
	} {
		if err := begin(c.ctx, c.org, c.tier); connect.CodeOf(err) != c.want {
			t.Errorf("%s = %v, want %v", c.name, err, c.want)
		}
	}

	_, none, _ := runnerServer(t)
	_, err := none.BeginGitHubRunnerAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubRunnerAppConnectRequest{Org: "truvity", Tier: "stable"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("no declared tiers = %v, want failed precondition", err)
	}
	status, err := none.GetGitHubStatus(operator(), connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
	if err != nil || len(status.Msg.GetRunnerTiers()) != 0 {
		t.Errorf("status without tiers = %v, %v", status.Msg.GetRunnerTiers(), err)
	}
}

// Disconnect uninstalls on GitHub and forgets every key of that one App.
func TestDisconnectingARunnerAppUninstallsThenForgetsItsKeys(t *testing.T) {
	github := startFakeGitHub(t)
	_, console, client := runnerServer(t, "preview", "stable")
	store := console.deps.GitHubRunnerApps
	at := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for _, tier := range []string{"preview", "stable"} {
		if err := store.Put(context.Background(), runnerapp.Record{
			Tier: tier, Org: "truvity", AppID: 42, AppSlug: "truvity-runners-" + tier, InstallationID: 7, ConnectedAt: at,
		}, github.pem); err != nil {
			t.Fatal(err)
		}
	}

	gone, err := console.DisconnectGitHubRunnerApp(operator(),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubRunnerAppRequest{Org: "truvity", Tier: "stable"}))
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if !gone.Msg.GetUninstalled() || !slices.Equal(github.uninstalled, []string{"7"}) ||
		gone.Msg.GetAppSettingsUrl() != "https://github.example/organizations/truvity/settings/apps/truvity-runners-stable" {
		t.Errorf("response = %+v, calls = %v", gone.Msg, github.uninstalled)
	}
	for key := range runnerSecret(t, client) {
		if strings.HasPrefix(key, "stable.") {
			t.Errorf("the stable App's %s outlived Disconnect", key)
		}
	}
	if records, _ := store.List(context.Background()); len(records) != 1 || records[0].Tier != "preview" {
		t.Errorf("after Disconnect = %+v, want the preview App alone", records)
	}

	if _, err = console.DisconnectGitHubRunnerApp(operator(),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubRunnerAppRequest{Org: "truvity", Tier: "stable"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("disconnecting what is gone = %v, want not found", err)
	}
}
