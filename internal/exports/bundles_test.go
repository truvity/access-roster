package exports_test

import (
	"context"
	"maps"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/exports"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/portstore"
	slackcatalogueapp "github.com/truvity/access-roster/internal/slackapp/catalogueapp"
	slackconnection "github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

// The bundles are what the Kubernetes Secrets held, byte for byte: they are
// restored from by the procedure written for those Secrets, and a consumer of
// the per-App properties reads values, not their encodings. So the assertion
// is against the legacy store itself: the same data goes into the kube stores
// (a fake API server) and into the State-backed ones, and each bundle read
// from State must equal the Secret the kube store wrote.

var ctx = context.Background()

const (
	namespace = "access-issuer"
	release   = "access-roster"
)

type fixtures struct {
	ws      hub.Workspace
	cred    backend.Credential
	org     connection.Record
	orgCred connection.Credential
	linkApp link.App
	linkCrd link.AppCredential
	link    link.Link
	runner  runnerapp.Record
	cat     catalogueapp.Record
	slack   slackcatalogueapp.Record
	slackCr slackcatalogueapp.Credentials
	slackWs slackconnection.Record
	slackWc slackconnection.Credential
	shared  reconcile.SharedChannel
	console reconcile.ConsoleChannel
}

func data() fixtures {
	at := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	return fixtures{
		ws: hub.Workspace{
			ID: "C030qgizn", Backend: "google", Domains: []string{"one.example"}, Serve: []string{"one.example"},
			Admin: "integrations@one.example", Credential: hub.CredentialServiceAccountKey,
			ConnectedBy: "operator@one.example", ConnectedAt: at,
			Health: hub.Health{ProbedAt: at.Add(time.Minute), OK: true},
		},
		cred:    backend.Credential{Type: "service-account-key", Admin: "integrations@one.example", Data: []byte(`{"private_key":"WS-KEY"}`)},
		org:     connection.Record{Org: "acme", AppID: 7, AppSlug: "acme-roster", InstallationID: 9, ConnectedAt: at, ConnectedBy: "ada@acme.example"},
		orgCred: connection.Credential{Org: "acme", AppID: 7, InstallationID: 9, PrivateKey: "ORG-PEM"},
		linkApp: link.App{Owner: "acme", AppID: 5, AppSlug: "acme-link", ClientID: "Iv1.x", ConnectedAt: at, ConnectedBy: "ada@acme.example"},
		linkCrd: link.AppCredential{AppID: 5, ClientID: "Iv1.x", ClientSecret: "LINK-SECRET"},
		link: link.Link{
			Version: link.Version, ID: 42, Login: "ada", AppID: 5, Emails: []string{"ada@acme.example"}, State: link.StateLinked,
			LinkedAt: at, Revision: 3, AccessToken: "gho_access", AccessExpires: at.Add(8 * time.Hour), RefreshToken: "ghr_refresh",
		},
		runner: runnerapp.Record{Tier: "stable", Org: "acme", AppID: 3, AppSlug: "acme-stable", InstallationID: 4, ConnectedAt: at, ConnectedBy: "ada@acme.example"},
		cat: catalogueapp.Record{
			ID: "renovate", Org: "acme", AppID: 8, AppSlug: "acme-renovate", InstallationID: 11,
			ConnectedAt: at, ConnectedBy: "ada@acme.example",
		},
		slack:   slackcatalogueapp.Record{ID: "alerts", Workspace: "acme", AppID: "A1", ClientID: "c1", TeamID: "T1", CreatedAt: at, CreatedBy: "ada@acme.example"},
		slackCr: slackcatalogueapp.Credentials{ClientSecret: "SLACK-CLIENT-SECRET", BotToken: "xoxb-BOT"},
		slackWs: slackconnection.Record{Workspace: "acme", TeamID: "T1", AppID: "A1", BotUserID: "U1", ConnectedAt: at, ConnectedBy: "ada@acme.example"},
		slackWc: slackconnection.Credential{Workspace: "acme", AppID: "A1", ClientID: "c1", ClientSecret: "CLIENT-SECRET", BotToken: "xoxb-WS"},
		shared:  reconcile.SharedChannel{Name: "partners", Host: "acme", With: []string{"globex"}, Sources: []string{"all@acme.example"}},
		console: reconcile.ConsoleChannel{Workspace: "acme", Name: "ops", Sources: []string{"ops@acme.example"}},
	}
}

// secretData is what the legacy stores wrote into the Secret of that name.
func secretData(t *testing.T, client *kube.Client, name string) map[string]string {
	t.Helper()
	secret, err := client.API().CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return asText(secret.Data)
}

func asText(in map[string][]byte) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = string(v)
	}
	return out
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// build puts the fixtures in both storages and returns the legacy client and
// the sources over State.
func build(t *testing.T) (*kube.Client, exports.Sources) {
	t.Helper()
	d := data()

	client := kube.NewClient(fake.NewClientset(), namespace, release)
	kw, kc := kube.NewWorkspaces(client), kube.NewCredentials(client)
	must(t, kc.Save(ctx, d.ws.ID, d.cred))
	must(t, kw.Put(ctx, d.ws)) // the record, which the credential then carries a copy of
	ko := kube.NewGitHubOrgs(client)
	must(t, ko.Put(ctx, d.org, d.orgCred))
	must(t, ko.PutLinkApp(ctx, d.linkApp, d.linkCrd))
	kl := kube.NewGitHubLinks(client)
	must(t, kl.Ensure(ctx))
	must(t, kl.Restore(ctx, d.link))
	must(t, kube.NewGitHubRunnerApps(client).Put(ctx, d.runner, "RUNNER-KEY"))
	must(t, kube.NewGitHubCatalogueApps(client).Put(ctx, d.cat, "CAT-KEY"))
	must(t, kube.NewSlackCatalogueApps(client).Put(ctx, d.slack, d.slackCr))
	ksw := kube.NewSlackWorkspaces(client)
	must(t, ksw.Put(ctx, d.slackWs, d.slackWc))
	ksh, ksc := kube.NewSlackShared(client), kube.NewSlackChannels(client)
	must(t, ksh.Apply(ctx, d.shared.Name, func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return &d.shared, nil }))
	must(t, ksc.Apply(ctx, d.console.Workspace, d.console.Name, keepConsole(&d.console)))

	base := portstore.New(memory.New().Set())
	sw, sc := portstore.NewWorkspaces(base), portstore.NewCredentials(base)
	must(t, sc.Save(ctx, d.ws.ID, d.cred))
	must(t, sw.Put(ctx, d.ws))
	so := portstore.NewGitHubOrgs(base)
	must(t, so.Put(ctx, d.org, d.orgCred))
	must(t, so.PutLinkApp(ctx, d.linkApp, d.linkCrd))
	sl := portstore.NewGitHubLinks(base)
	must(t, sl.Restore(ctx, d.link))
	runners := portstore.NewGitHubRunnerApps(base)
	must(t, runners.Put(ctx, d.runner, "RUNNER-KEY"))
	cats := portstore.NewGitHubCatalogueApps(base)
	must(t, cats.Put(ctx, d.cat, "CAT-KEY"))
	slacks := portstore.NewSlackCatalogueApps(base)
	must(t, slacks.Put(ctx, d.slack, d.slackCr))
	ssw := portstore.NewSlackWorkspaces(base)
	must(t, ssw.Put(ctx, d.slackWs, d.slackWc))
	ssh, ssc := portstore.NewSlackShared(base), portstore.NewSlackChannels(base)
	must(t, ssh.Apply(ctx, d.shared.Name, func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return &d.shared, nil }))
	must(t, ssc.Apply(ctx, d.console.Workspace, d.console.Name, keepConsole(&d.console)))

	return client, exports.Sources{
		Workspaces: sw, Credentials: sc, GitHubOrgs: so, GitHubLinks: sl,
		RunnerApps: runners, GitHubCatalogueApps: cats, SlackCatalogueApps: slacks,
		SlackWorkspaces: ssw, SlackShared: ssh, SlackChannels: ssc,
	}
}

func read(t *testing.T, s exports.Sources, spec exports.Spec) (map[string]string, bool) {
	t.Helper()
	got, found, err := s.Read(ctx, spec)
	if err != nil {
		t.Fatalf("%s: %v", spec.Name, err)
	}
	return got, found
}

func TestEachBundleIsWhatTheKubernetesSecretHeld(t *testing.T) {
	client, sources := build(t)
	for bundle, secret := range map[string]string{
		exports.BundleWorkspaceCredentials: release + "-workspace-credentials",
		exports.BundleGitHubApps:           release + "-github-apps",
		exports.BundleGitHubLinks:          release + "-github-links",
		exports.BundleGitHubRunnerApps:     release + "-github-runner-apps",
		exports.BundleGitHubCatalogueApps:  release + "-github-catalogue-apps",
		exports.BundleSlackCredentials:     release + "-slack-credentials",
		exports.BundleSlackRecords:         release + "-slack-records",
	} {
		t.Run(bundle, func(t *testing.T) {
			want := secretData(t, client, secret)
			if len(want) == 0 {
				t.Fatalf("the fixtures left %s empty: the comparison would prove nothing", secret)
			}
			got, found := read(t, sources, exports.Spec{Name: "b", Source: exports.SourceBundle, Bundle: bundle})
			if !found {
				t.Fatalf("%s: nothing found", bundle)
			}
			if !maps.Equal(got, want) {
				for k := range want {
					if got[k] != want[k] {
						t.Errorf("entry %s:\n  state  %s\n  secret %s", k, got[k], want[k])
					}
				}
				for k := range got {
					if _, ok := want[k]; !ok {
						t.Errorf("entry %s is in the bundle and not in the Secret", k)
					}
				}
			}
		})
	}
}

func TestThePerAppSourcesReadTheNamesTheirPushSecretsWrote(t *testing.T) {
	_, sources := build(t)
	cases := []struct {
		name string
		spec exports.Spec
		want map[string]string
	}{
		{
			"slack-app",
			exports.Spec{Name: "s", Source: exports.SourceSlackApp, App: "alerts", Properties: map[string]string{"bot_token": "bot_token"}},
			map[string]string{"bot_token": "xoxb-BOT"},
		},
		{
			"github-app",
			exports.Spec{Name: "g", Source: exports.SourceGitHubApp, App: "renovate", Properties: map[string]string{
				"app_id": "app_id", "installation_id": "installation_id", "private_key": "private_key",
			}},
			map[string]string{"app_id": "8", "installation_id": "11", "private_key": "CAT-KEY"},
		},
		{
			"runner-app",
			exports.Spec{Name: "r", Source: exports.SourceRunnerApp, Tier: "stable", Org: "acme", Properties: map[string]string{
				"app_id": "github-app-id", "installation_id": "github-installation-id", "private_key": "github-private-key",
			}},
			map[string]string{"github-app-id": "3", "github-installation-id": "4", "github-private-key": "RUNNER-KEY"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, found := read(t, sources, c.spec)
			if !found || !maps.Equal(got, c.want) {
				t.Fatalf("got %v (found %v), want %v", got, found, c.want)
			}
		})
	}
}

func TestAnAppThatIsNotInstalledHasNothingToCopy(t *testing.T) {
	d := data()
	base := portstore.New(memory.New().Set())
	runners := portstore.NewGitHubRunnerApps(base)
	pending := d.runner
	pending.InstallationID = 0
	must(t, runners.Put(ctx, pending, "PENDING-KEY"))
	slacks := portstore.NewSlackCatalogueApps(base)
	created := d.slack
	created.TeamID = ""
	must(t, slacks.Put(ctx, created, slackcatalogueapp.Credentials{ClientSecret: d.slackCr.ClientSecret}))
	cats := portstore.NewGitHubCatalogueApps(base)
	cat := d.cat
	cat.InstallationID = 0
	must(t, cats.Put(ctx, cat, "CAT-PENDING"))
	sources := exports.Sources{RunnerApps: runners, SlackCatalogueApps: slacks, GitHubCatalogueApps: cats}
	props := map[string]string{"bot_token": "bot_token", "app_id": "app_id", "installation_id": "installation_id", "private_key": "private_key"}
	for _, spec := range []exports.Spec{
		{Name: "r", Source: exports.SourceRunnerApp, Tier: "stable", Org: "acme", Properties: props},
		{Name: "s", Source: exports.SourceSlackApp, App: "alerts", Properties: props},
		{Name: "g", Source: exports.SourceGitHubApp, App: "renovate", Properties: props},
		{Name: "absent", Source: exports.SourceRunnerApp, Tier: "stable", Org: "nobody", Properties: props},
	} {
		if got, found := read(t, sources, spec); found {
			t.Errorf("%s: copied %v of an App that is not installed", spec.Name, got)
		}
	}
	// A bundle with nothing in it is nothing to copy, not an emptied backup.
	if got, found := read(t, exports.Sources{GitHubLinks: portstore.NewGitHubLinks(base)},
		exports.Spec{Name: "l", Source: exports.SourceBundle, Bundle: exports.BundleGitHubLinks}); found {
		t.Errorf("an empty bundle was copied: %v", got)
	}
}

func TestAMappingWritesOnlyWhatItNamesUnderTheNamesItGives(t *testing.T) {
	_, sources := build(t)
	spec := exports.Spec{Name: "r", Source: exports.SourceRunnerApp, Tier: "stable", Org: "acme",
		Properties: map[string]string{"private_key": "key"}}
	got, found := read(t, sources, spec)
	if !found || !maps.Equal(got, map[string]string{"key": "RUNNER-KEY"}) {
		t.Fatalf("got %v, %v", got, found)
	}
}

func TestSourcesRefuseAnExportWhoseStoreIsNotKept(t *testing.T) {
	specs := []exports.Spec{{Name: "b", Source: exports.SourceBundle, Bundle: exports.BundleGitHubLinks}}
	if err := (exports.Sources{}).Check(specs); err == nil {
		t.Fatal("an export of a store this deployment does not keep was accepted")
	}
	if err := (exports.Sources{GitHubLinks: portstore.NewGitHubLinks(portstore.New(memory.New().Set()))}).Check(specs); err != nil {
		t.Fatal(err)
	}
}

func keepConsole(c *reconcile.ConsoleChannel) func(*reconcile.ConsoleChannel, []slackconnection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
	return func(*reconcile.ConsoleChannel, []slackconnection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		return c, nil
	}
}
