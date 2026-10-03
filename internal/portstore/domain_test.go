package portstore_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/portstore"
	slackcatalogueapp "github.com/truvity/access-roster/internal/slackapp/catalogueapp"
	slackconnection "github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

// replayedUnderAnotherKey copies the raw bytes at one key to another and says
// whether the reader at the second still opens what the first sealed.
func copyRaw(t *testing.T, st port.State, from, to string) {
	t.Helper()
	rec, err := st.Get(ctx, from)
	if err != nil {
		t.Fatalf("read %s: %v", from, err)
	}
	if _, err = st.Put(ctx, to, rec.Value, 0); err != nil {
		t.Fatalf("write %s: %v", to, err)
	}
}

// noPlaintext fails if a secret is readable in anything the State holds.
func noPlaintext(t *testing.T, st port.State, secret string) {
	t.Helper()
	for _, prefix := range []string{"ws.", "gh.", "app.", "rec.", "gate."} {
		page, err := st.List(ctx, prefix, "", 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range page.Records {
			if bytes.Contains(rec.Value, []byte(secret)) {
				t.Errorf("the secret is readable in State under %s", rec.Key)
			}
		}
	}
}

func TestWorkspacesAndTheirCredentialsAreOneSealedItem(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		b := portstore.New(set)
		ws, creds := portstore.NewWorkspaces(b), portstore.NewCredentials(b)

		if _, err := ws.Get(ctx, "C01"); !errors.Is(err, hub.ErrNotFound) {
			t.Fatalf("Get of nothing = %v, want hub.ErrNotFound", err)
		}
		// The credential saved first is not a workspace yet.
		cred := backend.Credential{Type: "service-account-key", Admin: "root@acme.example", Data: []byte(`{"private_key":"TOPSECRET"}`)}
		if err := creds.Save(ctx, "C01", cred); err != nil {
			t.Fatal(err)
		}
		if list, err := ws.List(ctx); err != nil || len(list) != 0 {
			t.Fatalf("List with a credential and no record = %v, %v", list, err)
		}
		record := hub.Workspace{ID: "C01", Backend: "google", Domains: []string{"acme.example"}, Admin: "root@acme.example",
			Credential: hub.CredentialServiceAccountKey, ConnectedBy: "ada@acme.example", ConnectedAt: time.Unix(1700000000, 0).UTC()}
		if err := ws.Put(ctx, record); err != nil {
			t.Fatal(err)
		}
		// A probe rewrites the record and must carry the credential along.
		record.Health = hub.Health{ProbedAt: time.Unix(1700000600, 0).UTC(), OK: true}
		if err := ws.Put(ctx, record); err != nil {
			t.Fatal(err)
		}
		got, err := ws.Get(ctx, "C01")
		if err != nil || got.ID != "C01" || !got.Health.OK || got.Domains[0] != "acme.example" {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		loaded, found, err := creds.Load(ctx, "C01")
		if err != nil || !found || loaded.Type != cred.Type || string(loaded.Data) != string(cred.Data) || loaded.Admin != cred.Admin {
			t.Fatalf("Load = %+v, %v, %v", loaded, found, err)
		}
		noPlaintext(t, set.State, "TOPSECRET")

		// A sealed value copied under another key does not open.
		copyRaw(t, set.State, "ws.dir.C01", "ws.dir.C02")
		if _, _, err = creds.Load(ctx, "C02"); !errors.Is(err, port.ErrUnwrap) {
			t.Errorf("a credential replayed under another key opened: %v", err)
		}
		if err = ws.Delete(ctx, "C02"); err != nil {
			t.Fatal(err)
		}

		// Deleting the record keeps the credential until it is deleted too.
		if err = ws.Delete(ctx, "C01"); err != nil {
			t.Fatal(err)
		}
		if _, err = ws.Get(ctx, "C01"); !errors.Is(err, hub.ErrNotFound) {
			t.Errorf("Get after Delete = %v", err)
		}
		if _, found, _ = creds.Load(ctx, "C01"); !found {
			t.Error("deleting the record deleted the credential")
		}
		if err = creds.Delete(ctx, "C01"); err != nil {
			t.Fatal(err)
		}
		if _, err = set.State.Get(ctx, "ws.dir.C01"); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("the item outlived both halves: %v", err)
		}
		if err = creds.Delete(ctx, "C01"); err != nil {
			t.Errorf("deleting an unknown credential = %v", err)
		}
	})
}

func TestTwoReplicasSeeOneAnotherAndSortById(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		a, b := portstore.NewWorkspaces(e.base(t)), portstore.NewWorkspaces(e.base(t))
		for _, id := range []string{"C03", "C01", "C02"} {
			if err := a.Put(ctx, hub.Workspace{ID: id, Backend: "google"}); err != nil {
				t.Fatal(err)
			}
		}
		list, err := b.List(ctx)
		if err != nil || len(list) != 3 || list[0].ID != "C01" || list[2].ID != "C03" {
			t.Fatalf("List = %v, %v", list, err)
		}
	})
}

func TestGitHubOrganisationsKeepRecordAndSealedKeyTogether(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		s := portstore.NewGitHubOrgs(portstore.New(set))
		record := connection.Record{
			Org: "acme", AppID: 7, AppSlug: "acme-roster", InstallationID: 9,
			ConnectedAt: time.Unix(1700000000, 0).UTC(), ConnectedBy: "ada@acme.example",
		}
		cred := connection.Credential{Org: "acme", AppID: 7, InstallationID: 9, PrivateKey: "TOPSECRET-PEM"}
		if err := s.Put(ctx, record, cred); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, record, connection.Credential{Org: "other", AppID: 7, PrivateKey: "x"}); err == nil {
			t.Error("a record with another organisation's credential was kept")
		}
		list, err := s.List(ctx)
		if err != nil || len(list) != 1 || list[0].Org != "acme" || list[0].AppSlug != "acme-roster" {
			t.Fatalf("List = %+v, %v", list, err)
		}
		got, found, err := s.Credential(ctx, "acme")
		if err != nil || !found || got.PrivateKey != "TOPSECRET-PEM" {
			t.Fatalf("Credential = %+v, %v, %v", got, found, err)
		}
		noPlaintext(t, set.State, "TOPSECRET-PEM")

		previous, found, err := s.SetOwner(ctx, "acme", "C01")
		if err != nil || !found || previous != "" {
			t.Fatalf("SetOwner = %q, %v, %v", previous, found, err)
		}
		if previous, found, err = s.SetOwner(ctx, "acme", "C02"); err != nil || !found || previous != "C01" {
			t.Fatalf("SetOwner again = %q, %v, %v", previous, found, err)
		}
		if _, found, err = s.SetOwner(ctx, "nobody", "C01"); err != nil || found {
			t.Errorf("SetOwner of an unknown organisation = %v, %v", found, err)
		}
		if got, found, _ = s.Credential(ctx, "acme"); !found || got.PrivateKey != "TOPSECRET-PEM" {
			t.Error("changing the owner lost the credential")
		}

		copyRaw(t, set.State, "gh.org.acme", "gh.org.evil")
		if _, _, err = s.Credential(ctx, "evil"); !errors.Is(err, port.ErrUnwrap) {
			t.Errorf("a credential replayed under another organisation opened: %v", err)
		}

		// The link App is built the same way.
		app := link.App{
			Owner: "acme", AppID: 5, AppSlug: "acme-link", ClientID: "Iv1.x",
			ConnectedAt: time.Unix(1700000000, 0).UTC(), ConnectedBy: "ada@acme.example",
		}
		if err = s.PutLinkApp(ctx, app, link.AppCredential{AppID: 5, ClientID: "Iv1.x", ClientSecret: "LINK-SECRET"}); err != nil {
			t.Fatal(err)
		}
		if gotApp, ok, err := s.LinkApp(ctx); err != nil || !ok || gotApp.AppSlug != "acme-link" {
			t.Fatalf("LinkApp = %+v, %v, %v", gotApp, ok, err)
		}
		if c, ok, err := s.LinkAppCredential(ctx); err != nil || !ok || c.ClientSecret != "LINK-SECRET" {
			t.Fatalf("LinkAppCredential = %+v, %v, %v", c, ok, err)
		}
		noPlaintext(t, set.State, "LINK-SECRET")
		if err = s.DeleteLinkApp(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.LinkApp(ctx); ok {
			t.Error("the link App survived its deletion")
		}

		if err = s.Delete(ctx, "acme"); err != nil {
			t.Fatal(err)
		}
		if _, found, _ = s.Credential(ctx, "acme"); found {
			t.Error("the credential outlived its organisation")
		}
	})
}

func TestGitHubConfirmationsAndPassRequests(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		s := portstore.NewGitHubOrgs(e.base(t))
		at := time.Now().UTC()
		if err := s.PutConfirmation(ctx, connection.Confirmation{Org: "acme", Fingerprint: "f1", By: "ada@acme.example", At: at}); err != nil {
			t.Fatal(err)
		}
		got, err := s.Confirmations(ctx)
		if err != nil || got["acme"].Fingerprint != "f1" || !got["acme"].Current(at) {
			t.Fatalf("Confirmations = %+v, %v", got, err)
		}
		e.advance(connection.ConfirmationTTL + time.Minute)
		if got, _ = s.Confirmations(ctx); len(got) != 0 {
			t.Errorf("a confirmation outlived its day: %+v", got)
		}

		kept, last, err := s.RequestPass(ctx, connection.PassRequest{Org: "acme", At: at, By: "ada@acme.example"})
		if err != nil || !kept || !last.IsZero() {
			t.Fatalf("first RequestPass = %v, %v, %v", kept, last, err)
		}
		kept, last, err = s.RequestPass(ctx, connection.PassRequest{Org: "acme", At: at.Add(time.Second), By: "ada@acme.example"})
		if err != nil || kept || !last.Equal(at) {
			t.Fatalf("a second request inside the gap = %v, %v, %v; want refused with the first's time", kept, last, err)
		}
		requests, err := s.PassRequests(ctx)
		if err != nil || !requests["acme"].At.Equal(at) {
			t.Fatalf("PassRequests = %+v, %v", requests, err)
		}
	})
}

func TestTheConsolesPassGapHoldsAcrossReplicas(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		a, b := portstore.NewGitHubOrgs(e.base(t)), portstore.NewGitHubOrgs(e.base(t))
		at := time.Now().UTC()
		var wg sync.WaitGroup
		var mu sync.Mutex
		kept := 0
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := a
				if i%2 == 1 {
					s = b
				}
				ok, _, err := s.RequestPass(ctx, connection.PassRequest{Org: "acme", At: at, By: "ada@acme.example"})
				if err != nil {
					t.Error(err)
				}
				if ok {
					mu.Lock()
					kept++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if kept != 1 {
			t.Errorf("%d simultaneous requests were kept, want exactly one", kept)
		}
	})
}

func TestAppsKeepTheirKeysSealed(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		b := portstore.New(set)
		now := time.Unix(1700000000, 0).UTC()

		runner := portstore.NewGitHubRunnerApps(b)
		rrec := runnerapp.Record{Tier: "stable", Org: "acme", AppID: 3, AppSlug: "acme-stable", InstallationID: 4, ConnectedAt: now, ConnectedBy: "ada@acme.example"}
		if err := runner.Put(ctx, rrec, "RUNNER-KEY"); err != nil {
			t.Fatal(err)
		}
		if list, err := runner.List(ctx); err != nil || len(list) != 1 || list[0].Tier != "stable" {
			t.Fatalf("runner List = %+v, %v", list, err)
		}
		if key, ok, err := runner.PrivateKey(ctx, "stable", "acme"); err != nil || !ok || key != "RUNNER-KEY" {
			t.Fatalf("runner PrivateKey = %q, %v, %v", key, ok, err)
		}
		if _, ok, _ := runner.PrivateKey(ctx, "stable", "globex"); ok {
			t.Error("a key for an App nobody made")
		}

		cat := portstore.NewGitHubCatalogueApps(b)
		crec := catalogueapp.Record{ID: "renovate", Org: "acme", AppID: 8, AppSlug: "acme-renovate", ConnectedAt: now, ConnectedBy: "ada@acme.example"}
		if err := cat.Put(ctx, crec, "CAT-KEY"); err != nil { // pending: no installation yet
			t.Fatal(err)
		}
		rec, key, ok, err := cat.Get(ctx, "renovate")
		if err != nil || !ok || key != "CAT-KEY" || rec.Installed() {
			t.Fatalf("catalogue Get = %+v, %q, %v, %v", rec, key, ok, err)
		}
		crec.InstallationID = 11
		if err = cat.Put(ctx, crec, "CAT-KEY"); err != nil {
			t.Fatal(err)
		}
		if rec, _, _, _ = cat.Get(ctx, "renovate"); !rec.Installed() {
			t.Error("the installed record did not replace the pending one")
		}

		slack := portstore.NewSlackCatalogueApps(b)
		srec := slackcatalogueapp.Record{
			ID: "notifier", Workspace: "acme", AppID: "A1", ClientID: "c1",
			AuthorizeURL: "https://slack.example/install", CreatedAt: now, CreatedBy: "ada@acme.example",
		}
		if err = slack.Put(ctx, srec, slackcatalogueapp.Credentials{ClientSecret: "SLACK-CLIENT-SECRET"}); err != nil {
			t.Fatal(err)
		}
		srec.TeamID, srec.BotUserID = "T1", "U1"
		if err = slack.Put(ctx, srec, slackcatalogueapp.Credentials{ClientSecret: "SLACK-CLIENT-SECRET", BotToken: "xoxb-BOT"}); err != nil {
			t.Fatal(err)
		}
		_, creds, ok, err := slack.Get(ctx, "notifier")
		if err != nil || !ok || creds.BotToken != "xoxb-BOT" || creds.ClientSecret != "SLACK-CLIENT-SECRET" {
			t.Fatalf("Slack catalogue Get = %+v, %v, %v", creds, ok, err)
		}
		for _, secret := range []string{"RUNNER-KEY", "CAT-KEY", "SLACK-CLIENT-SECRET", "xoxb-BOT"} {
			noPlaintext(t, set.State, secret)
		}

		copyRaw(t, set.State, "app.gh.cat.renovate", "app.gh.cat.evil")
		crec.ID = "evil"
		if _, _, _, err = cat.Get(ctx, "evil"); err == nil {
			// The record names another id, but the key is what is checked:
			// opening the sealed key must fail.
			t.Error("a catalogue key replayed under another id opened")
		}
		for _, del := range []func() error{
			func() error { return runner.Delete(ctx, "stable", "acme") },
			func() error { return cat.Delete(ctx, "renovate") },
			func() error { return slack.Delete(ctx, "notifier") },
		} {
			if err = del(); err != nil {
				t.Fatal(err)
			}
		}
		if list, _ := runner.List(ctx); len(list) != 0 {
			t.Errorf("a deleted runner App is listed: %+v", list)
		}
	})
}

func TestSlackWorkspacesKeepRecordAndSealedTokenTogether(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		s := portstore.NewSlackWorkspaces(portstore.New(set))
		record := slackconnection.Record{
			Workspace: "acme", TeamID: "T1", AppID: "A1", BotUserID: "U1",
			ConnectedAt: time.Unix(1700000000, 0).UTC(), ConnectedBy: "ada@acme.example",
		}
		cred := slackconnection.Credential{Workspace: "acme", AppID: "A1", ClientID: "c1", ClientSecret: "CLIENT-SECRET", BotToken: "xoxb-TOPSECRET"}
		if err := s.Put(ctx, record, cred); err != nil {
			t.Fatal(err)
		}
		list, err := s.List(ctx)
		if err != nil || len(list) != 1 || list[0].TeamID != "T1" {
			t.Fatalf("List = %+v, %v", list, err)
		}
		rec, got, found, err := s.Get(ctx, "acme")
		if err != nil || !found || got.BotToken != "xoxb-TOPSECRET" || rec.TeamID != "T1" {
			t.Fatalf("Get = %+v %+v %v %v", rec, got, found, err)
		}
		noPlaintext(t, set.State, "xoxb-TOPSECRET")
		noPlaintext(t, set.State, "CLIENT-SECRET")
		if previous, found, err := s.SetOwner(ctx, "acme", "C01"); err != nil || !found || previous != "" {
			t.Fatalf("SetOwner = %q %v %v", previous, found, err)
		}
		if rec, got, _, _ = s.Get(ctx, "acme"); rec.Owner != "C01" || got.BotToken != "xoxb-TOPSECRET" {
			t.Errorf("after SetOwner: %+v %+v", rec, got)
		}
		copyRaw(t, set.State, "ws.slack.acme", "ws.slack.evil")
		if _, _, _, err = s.Get(ctx, "evil"); !errors.Is(err, port.ErrUnwrap) {
			t.Errorf("a token replayed under another workspace opened: %v", err)
		}
		if err = s.Delete(ctx, "evil"); err != nil {
			t.Fatal(err)
		}

		// Confirmations are per workspace or per channel, and go with the workspace.
		at := time.Now().UTC()
		for _, c := range []slackconnection.Confirmation{
			{Workspace: "acme", Fingerprint: "f1", By: "ada@acme.example", At: at},
			{Workspace: "acme", Channel: "ops", Fingerprint: "f2", By: "ada@acme.example", At: at},
		} {
			if err = s.PutConfirmation(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		confirmations, err := s.Confirmations(ctx)
		if err != nil || len(confirmations) != 2 ||
			confirmations[slackconnection.ConfirmationKey("acme", "")].Fingerprint != "f1" ||
			confirmations[slackconnection.ConfirmationKey("acme", "ops")].Fingerprint != "f2" {
			t.Fatalf("Confirmations = %+v, %v", confirmations, err)
		}
		if kept, _, err := s.RequestPass(ctx, slackconnection.PassRequest{Workspace: "acme", At: at, By: "ada@acme.example"}); err != nil || !kept {
			t.Fatalf("RequestPass = %v, %v", kept, err)
		}
		if kept, _, _ := s.RequestPass(ctx, slackconnection.PassRequest{Workspace: "acme", At: at.Add(time.Second), By: "ada@acme.example"}); kept {
			t.Error("a request inside the gap was kept")
		}
		if requests, err := s.PassRequests(ctx); err != nil || len(requests) != 1 {
			t.Fatalf("PassRequests = %+v, %v", requests, err)
		}
		if err = s.Delete(ctx, "acme"); err != nil {
			t.Fatal(err)
		}
		if confirmations, _ = s.Confirmations(ctx); len(confirmations) != 0 {
			t.Errorf("confirmations outlived their workspace: %+v", confirmations)
		}
		if requests, _ := s.PassRequests(ctx); len(requests) != 0 {
			t.Errorf("a pass request outlived its workspace: %+v", requests)
		}
	})
}

func TestSlackSharedAndChannelRecordsAreEditedUnderTheirRevision(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		b := e.base(t)
		shared, channels := portstore.NewSlackShared(b), portstore.NewSlackChannels(b)
		def := reconcile.SharedChannel{Name: "partners", Host: "acme", With: []string{"globex"}, Sources: []string{"all@acme.example"}}
		if err := shared.Apply(ctx, "partners", func(cur *reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
			if cur != nil {
				t.Errorf("a new record has a current: %+v", cur)
			}
			return &def, nil
		}); err != nil {
			t.Fatal(err)
		}
		def.Sources = []string{"all@acme.example", "eng@acme.example"}
		if err := shared.Apply(ctx, "partners", func(cur *reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
			if cur == nil || len(cur.Sources) != 1 {
				t.Errorf("current = %+v, want the first definition", cur)
			}
			return &def, nil
		}); err != nil {
			t.Fatal(err)
		}
		list, err := shared.List(ctx)
		if err != nil || len(list) != 1 || list[0].Err != nil || len(list[0].Channel.Sources) != 2 {
			t.Fatalf("List = %+v, %v", list, err)
		}
		// An error from decide writes nothing.
		boom := errors.New("refused")
		if err = shared.Apply(ctx, "partners", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return nil, boom }); !errors.Is(err, boom) {
			t.Errorf("Apply = %v, want decide's own error", err)
		}
		if list, _ = shared.List(ctx); len(list[0].Channel.Sources) != 2 {
			t.Error("a refused edit changed the record")
		}
		// A conflict that outlasts every retry is the contract's own error.
		err = shared.Apply(ctx, "partners", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
			// Another replica writes between this read and this write, every time.
			other := def
			other.Private.All = !other.Private.All
			rival := portstore.NewSlackShared(e.base(t))
			if aerr := rival.Apply(ctx, "partners", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
				return &other, nil
			}); aerr != nil {
				t.Error(aerr)
			}
			return &def, nil
		})
		if !errors.Is(err, slackconnection.ErrSharedConflict) {
			t.Errorf("a record that kept changing = %v, want ErrSharedConflict", err)
		}
		if err = shared.Apply(ctx, "partners", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return nil, nil }); err != nil {
			t.Fatal(err)
		}
		if list, _ = shared.List(ctx); len(list) != 0 {
			t.Errorf("a deleted record is listed: %+v", list)
		}

		ch := reconcile.ConsoleChannel{Workspace: "acme", Name: "ops", Sources: []string{"ops@acme.example"}}
		if err = channels.Apply(ctx, "acme", "ops", func(cur *reconcile.ConsoleChannel, all []slackconnection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
			if cur != nil || len(all) != 0 {
				t.Errorf("current %+v all %+v", cur, all)
			}
			return &ch, nil
		}); err != nil {
			t.Fatal(err)
		}
		other := reconcile.ConsoleChannel{Workspace: "acme", Name: "dev", Sources: []string{"dev@acme.example"}}
		if err = channels.Apply(ctx, "acme", "dev", func(_ *reconcile.ConsoleChannel, all []slackconnection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
			if len(all) != 1 || all[0].Name != "ops" {
				t.Errorf("all = %+v, want the one record already there", all)
			}
			return &other, nil
		}); err != nil {
			t.Fatal(err)
		}
		recs, err := channels.List(ctx)
		if err != nil || len(recs) != 2 || recs[0].Name != "dev" || recs[1].Name != "ops" || recs[0].Err != nil {
			t.Fatalf("List = %+v, %v", recs, err)
		}
	})
}

func TestAConsoleSessionKeyIsOneKeyForEveryReplica(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		a, b := portstore.New(set), portstore.New(e.open(t))
		gen := func(seed byte) func() ([]byte, error) {
			return func() ([]byte, error) { return bytes.Repeat([]byte{seed}, 32), nil }
		}
		first, err := a.SessionKey(ctx, gen(1))
		if err != nil {
			t.Fatal(err)
		}
		second, err := b.SessionKey(ctx, gen(2))
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("the second replica read %x, want the first's %x (%v)", second, first, err)
		}
		noPlaintext(t, set.State, string(first))
		if err = a.CheckSealer(ctx); err != nil {
			t.Errorf("CheckSealer = %v", err)
		}
	})
}

func TestASealerThatCannotSealIsRefusedAtStart(t *testing.T) {
	b := portstore.New(port.Set{State: nil, Sealer: unsupportedSealer{}})
	err := b.CheckSealer(ctx)
	if err == nil || !strings.Contains(err.Error(), "ports.sealer") {
		t.Errorf("CheckSealer = %v, want a refusal naming ports.sealer", err)
	}
}

type unsupportedSealer struct{}

func (unsupportedSealer) Wrap(context.Context, []byte, string) (port.Wrapped, error) {
	return port.Wrapped{}, port.ErrUnsupported
}

func (unsupportedSealer) Unwrap(context.Context, port.Wrapped, string) ([]byte, error) {
	return nil, port.ErrUnsupported
}
