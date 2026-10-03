package migrate_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	ghconn "github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/migrate"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/legacy"
	"github.com/truvity/access-roster/internal/port/memory"
	slackcatalogueapp "github.com/truvity/access-roster/internal/slackapp/catalogueapp"
	slconn "github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/store"
	"github.com/truvity/access-roster/internal/valkey"
)

var ctx = context.Background()

// The secrets the fixtures hold. A report must never contain one.
var secrets = []string{
	"TOPSECRET-WS", "TOPSECRET-PEM", "LINK-SECRET", "RUNNER-KEY", "CAT-KEY", "SLACK-CLIENT-SECRET",
	"xoxb-BOT", "xoxb-TOPSECRET", "ghu_ACCESS_ada", "ghr_REFRESH_ada", "refresh-ada", "SESSIONKEY",
}

// legacySide is today's storage on a fake API server and a miniredis: what an
// installation that has never moved looks like.
type legacySide struct {
	stores *store.Stores
	redis  *miniredis.Miniredis
	api    *fake.Clientset
	state  *valkey.State
}

func newLegacy(t *testing.T) *legacySide {
	t.Helper()
	server := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	api := fake.NewSimpleClientset()
	state := valkey.NewState(rc, "access-roster")
	backendStores := &legacy.Backend{Kube: kube.NewClient(api, "ns", "access-roster"), Valkey: state}
	return &legacySide{
		stores: &store.Stores{
			Ports: backendStores.Ports(legacy.Options{}), Backend: backendStores,
			Adapter: store.AdapterLegacy, Shared: true, Usable: true,
		},
		redis: server, api: api, state: state,
	}
}

// portSide is a Stores over a set of ports, with a Blob if the set has none.
func portSide(set port.Set, adapter string) *store.Stores {
	if set.Blob == nil {
		set.Blob = memory.New().Blobs()
	}
	return &store.Stores{Ports: set, Adapter: adapter, Shared: true, Usable: true}
}

func side(name string, st *store.Stores) migrate.Side {
	return migrate.Side{Name: name, Stores: st}
}

var now = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// seed fills a side with one of everything, through the stores the service
// itself writes with, so that what is copied is what a deployment holds.
func seed(t *testing.T, st *store.Stores) {
	t.Helper()
	d, err := migrate.OpenDomains(ctx, st, true)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Directory.
	must(d.Workspaces.Put(ctx, hub.Workspace{ID: "C01", Backend: "google", Domains: []string{"acme.example"}, Admin: "root@acme.example",
		Credential: hub.CredentialServiceAccountKey, ConnectedBy: "ada@acme.example", ConnectedAt: now,
		Health: hub.Health{ProbedAt: now, OK: true}}))
	must(d.Credentials.Save(ctx, "C01", backend.Credential{
		Type: "service-account-key", Admin: "root@acme.example", Data: []byte(`{"private_key":"TOPSECRET-WS"}`),
	}))
	must(d.Workspaces.Put(ctx, hub.Workspace{ID: "C02", Backend: "google", Domains: []string{"globex.example"}, ConnectedAt: now}))

	// GitHub.
	must(d.Orgs.Put(ctx,
		ghconn.Record{Org: "acme", AppID: 7, AppSlug: "acme-roster", InstallationID: 9, ConnectedAt: now, ConnectedBy: "ada@acme.example", Owner: "C01"},
		ghconn.Credential{Org: "acme", AppID: 7, InstallationID: 9, PrivateKey: "TOPSECRET-PEM"}))
	must(d.Orgs.PutLinkApp(ctx,
		link.App{Owner: "acme", AppID: 5, AppSlug: "acme-link", ClientID: "Iv1.x", ConnectedAt: now, ConnectedBy: "ada@acme.example"},
		link.AppCredential{AppID: 5, ClientID: "Iv1.x", ClientSecret: "LINK-SECRET"}))
	must(d.Runner.Put(ctx, runnerapp.Record{
		Tier: "stable", Org: "acme", AppID: 3, AppSlug: "acme-stable", InstallationID: 4, ConnectedAt: now, ConnectedBy: "ada@acme.example",
	}, "RUNNER-KEY"))
	must(d.Catalogue.Put(ctx, catalogueapp.Record{
		ID: "renovate", Org: "acme", AppID: 8, AppSlug: "acme-renovate", InstallationID: 11, ConnectedAt: now, ConnectedBy: "ada@acme.example",
	}, "CAT-KEY"))
	must(d.Links.Restore(ctx, link.Link{
		ID: 101, Login: "ada", AppID: 5, Emails: []string{"ada@acme.example"}, State: link.StateLinked, LinkedAt: now, Revision: 3,
		AccessToken: "ghu_ACCESS_ada", AccessExpires: now.Add(8 * time.Hour),
		RefreshToken: "ghr_REFRESH_ada", RefreshExpires: now.Add(180 * 24 * time.Hour),
	}))
	must(d.Links.Restore(ctx, link.Link{
		ID: 102, Login: "grace", AppID: 5, Emails: []string{"grace@acme.example"}, State: link.StateLinked, LinkedAt: now, Revision: 1,
	}))
	must(d.Orgs.PutConfirmation(ctx, ghconn.Confirmation{Org: "acme", Fingerprint: "f1", By: "ada@acme.example", At: time.Now().UTC()}))
	if kept, _, err := d.Orgs.RequestPass(ctx, ghconn.PassRequest{Org: "acme", At: time.Now().UTC(), By: "ada@acme.example"}); err != nil || !kept {
		t.Fatalf("RequestPass = %v, %v", kept, err)
	}

	// Slack.
	must(d.Slack.Put(ctx,
		slconn.Record{Workspace: "acme", TeamID: "T1", AppID: "A1", BotUserID: "U1", ConnectedAt: now, ConnectedBy: "ada@acme.example"},
		slconn.Credential{Workspace: "acme", AppID: "A1", ClientID: "c1", ClientSecret: "SLACK-CLIENT-SECRET", BotToken: "xoxb-TOPSECRET"}))
	must(d.SlackApps.Put(ctx,
		slackcatalogueapp.Record{ID: "notifier", Workspace: "acme", AppID: "A2", ClientID: "c2", AuthorizeURL: "https://slack.example/install",
			TeamID: "T1", BotUserID: "U2", CreatedAt: now, CreatedBy: "ada@acme.example"},
		slackcatalogueapp.Credentials{ClientSecret: "SLACK-CLIENT-SECRET", BotToken: "xoxb-BOT"}))
	must(d.Shared.Apply(ctx, "partners", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
		return &reconcile.SharedChannel{Name: "partners", Host: "acme", With: []string{"globex"}, Sources: []string{"all@acme.example"}}, nil
	}))
	for _, name := range []string{"ops", "dev"} {
		must(d.Channels.Apply(ctx, "acme", name, func(*reconcile.ConsoleChannel, []slconn.ChannelRecord) (*reconcile.ConsoleChannel, error) {
			return &reconcile.ConsoleChannel{Workspace: "acme", Name: name, Sources: []string{name + "@acme.example"}}, nil
		}))
	}
	at := time.Now().UTC()
	must(d.Slack.PutConfirmation(ctx, slconn.Confirmation{Workspace: "acme", Fingerprint: "f1", By: "ada@acme.example", At: at}))
	must(d.Slack.PutConfirmation(ctx, slconn.Confirmation{Workspace: "acme", Channel: "ops", Fingerprint: "f2", By: "ada@acme.example", At: at}))
	if kept, _, err := d.Slack.RequestPass(ctx, slconn.PassRequest{Workspace: "acme", At: at, By: "ada@acme.example"}); err != nil || !kept {
		t.Fatalf("Slack RequestPass = %v, %v", kept, err)
	}

	// Console.
	must(d.SessionKey.Put(ctx, []byte(strings.Repeat("S", 24)+"SESSIONKEY"+"12345678")))
}

// sessionLifetime is how long the fixture's refresh tokens live.
const sessionLifetime = 30 * 24 * time.Hour

// seedLogins opens a session the way the issuer does, on the side's own
// ports, and a code and a keyring entry beside it.
func seedLogins(t *testing.T, st *store.Stores) (issuer.Session, string) {
	t.Helper()
	state := issuer.NewPortState(st.Ports.State, st.Ports.Index)
	sessions := issuer.NewSessions(state, sessionLifetime, 0)
	session, err := sessions.Record(ctx, issuer.Opened{
		Identity: "ada@north.example", ClientID: "local-dev", How: issuer.HowCode, Token: "refresh-ada",
		Scopes: []string{"openid", "profile", "email"}, AuthTime: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Set(ctx, "issuer:code:one-time-code", []byte(`{"request":"r"}`), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = state.Set(ctx, "issuer:keyring:entry:ES384:kid1", []byte(`{"first":"2026-09-01T00:00:00Z"}`), 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	return session, "refresh-ada"
}

// counts is a report's step by name.
func step(t *testing.T, r *migrate.Report, domain, kind string) migrate.Step {
	t.Helper()
	for _, s := range r.Steps {
		if s.Domain == domain && s.Kind == kind {
			return s
		}
	}
	t.Fatalf("the report has no %s/%s step: %+v", domain, kind, r.Steps)
	return migrate.Step{}
}

// noSecrets fails if the report names a value the fixtures hold.
func noSecrets(t *testing.T, r *migrate.Report) {
	t.Helper()
	raw := string(r.JSON())
	for _, s := range secrets {
		if strings.Contains(raw, s) {
			t.Errorf("the report contains %q", s)
		}
	}
}
