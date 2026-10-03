package migrate_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/migrate"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/portstore/portstoretest"
	"github.com/truvity/access-roster/internal/store"
)

// natsEnvs are the destinations the tests run over: an embedded JetStream, sealed
// by the in-process Sealer and by the KMS adapter over a fake KMS.
func natsEnvs(t *testing.T) []portstoretest.Env {
	t.Helper()
	var out []portstoretest.Env
	for _, e := range portstoretest.Envs(t) {
		if strings.HasPrefix(e.Name, "nats") {
			out = append(out, e)
		}
	}
	return out
}

var stopped = migrate.Options{WritersStopped: true}

// total of every item of a seeded side: workspaces 2, organisations 1, link App
// 1, runner Apps 1, catalogue Apps 1, links 2, GitHub confirmations 1 and pass
// requests 1, Slack workspaces 1, catalogue Apps 1, shared channels 1, console
// channels 2, confirmations 2, pass requests 1, the session key 1.
const seededItems = 2 + 1 + 1 + 1 + 1 + 2 + 1 + 1 + 1 + 1 + 1 + 2 + 2 + 1 + 1

func TestLegacyToNATSCopiesEveryDomainAndVerifies(t *testing.T) {
	for _, env := range natsEnvs(t) {
		t.Run(env.Name, func(t *testing.T) {
			src := newLegacy(t)
			seed(t, src.stores)
			session, token := seedLogins(t, src.stores)
			dst := portSide(env.Open(t), store.AdapterNATS)

			report, err := migrate.Run(ctx, side("old.yaml", src.stores), side("new.yaml", dst), stopped)
			if err != nil {
				t.Fatalf("Run = %v\n%s", err, report.JSON())
			}
			if !report.OK || report.Totals.Mismatched != 0 || report.Totals.Conflicts != 0 {
				t.Fatalf("report = %s", report.JSON())
			}
			noSecrets(t, report)

			// Every domain item was copied, and read back equal.
			for _, c := range []struct {
				domain, kind string
				n            int
			}{
				{"directory", "workspaces", 2}, {"github", "organisations", 1}, {"github", "link-app", 1},
				{"github", "runner-apps", 1}, {"github", "catalogue-apps", 1}, {"github", "links", 2},
				{"github", "confirmations", 1}, {"github", "pass-requests", 1},
				{"slack", "workspaces", 1}, {"slack", "catalogue-apps", 1}, {"slack", "shared-channels", 1},
				{"slack", "console-channels", 2}, {"slack", "confirmations", 2}, {"slack", "pass-requests", 1},
				{"console", "session-key", 1},
			} {
				s := step(t, report, c.domain, c.kind)
				if s.Source != c.n || s.Copied != c.n || s.Verified != c.n || s.New != c.n {
					t.Errorf("%s/%s = %+v, want %d copied and verified", c.domain, c.kind, s, c.n)
				}
			}
			if sum := report.Totals.Copied; sum < seededItems {
				t.Errorf("copied %d, want at least %d domain items", sum, seededItems)
			}
			if s := step(t, report, "issuer", "state"); s.Source < 3 || s.Verified != s.Source {
				t.Errorf("issuer state = %+v", s)
			}
			if s := step(t, report, "issuer", "index"); s.Source != 3 || s.Verified != 3 {
				t.Errorf("issuer index = %+v, want the three session sets", s)
			}

			// The destination holds the credentials sealed, and a clear read through its
			// own stores gives back what the source had.
			d, err := migrate.OpenDomains(ctx, dst, false)
			if err != nil {
				t.Fatal(err)
			}
			cred, found, err := d.Credentials.Load(ctx, "C01")
			if err != nil || !found || !bytes.Contains(cred.Data, []byte("TOPSECRET-WS")) {
				t.Fatalf("the workspace credential on the destination = %+v, %v, %v", cred, found, err)
			}
			for _, prefix := range []string{"ws.", "gh.", "app.", "rec."} {
				page, err := dst.Ports.State.List(ctx, prefix, "", 1000)
				if err != nil {
					t.Fatal(err)
				}
				for _, rec := range page.Records {
					for _, s := range secrets {
						if bytes.Contains(rec.Value, []byte(s)) {
							t.Errorf("%q is readable in the destination's State under %s", s, rec.Key)
						}
					}
				}
			}
			links, err := d.Links.List(ctx)
			if err != nil || len(links) != 2 || links[0].Revision != 3 || links[0].RefreshToken != "ghr_REFRESH_ada" {
				t.Fatalf("the links on the destination = %+v, %v: the revision and the tokens must come across as they were", links, err)
			}

			// A refresh token copied from the source works on the destination's issuer state,
			// the session is found by its person, and its lifetime was kept, not reset.
			sessions := issuer.NewSessions(issuer.NewPortState(dst.Ports.State, dst.Ports.Index), sessionLifetime, 0)
			got, ok, err := sessions.ByRefreshToken(ctx, token)
			if err != nil || !ok || got.ID != session.ID {
				t.Fatalf("ByRefreshToken on the destination = %+v, %v, %v", got, ok, err)
			}
			listed, err := sessions.List(ctx, issuer.Query{Identity: "ada@north.example"})
			if err != nil || len(listed) != 1 {
				t.Fatalf("the person's sessions on the destination = %+v, %v", listed, err)
			}
			if _, rotated, ok, err := sessions.Refreshed(ctx, token, "refresh-ada-2"); err != nil || !ok || rotated == "" {
				t.Fatalf("Refreshed on the destination = %q, %v, %v", rotated, ok, err)
			}
			if _, ok, _ = sessions.ByRefreshToken(ctx, "refresh-ada-2"); !ok {
				t.Error("the rotated token does not work on the destination")
			}
			var ttl time.Duration
			err = dst.Ports.State.(port.StateExporter).ExportState(ctx, "issuer:code:", func(x port.Exported) error {
				ttl = x.TTL
				return nil
			})
			if err != nil || ttl <= 4*time.Minute || ttl > 5*time.Minute+10*time.Second {
				t.Errorf("a 5 minute code has %s left on the destination (%v): its lifetime was not carried", ttl, err)
			}
			env.Advance(sessionLifetime + time.Hour)
			if _, ok, _ = sessions.ByRefreshToken(ctx, "refresh-ada-2"); ok {
				t.Error("a copied session outlived its lifetime")
			}
		})
	}
}

func TestMemoryToNATS(t *testing.T) {
	env := natsEnvs(t)[0]
	mem := memory.New()
	src := portSide(mem.Set(), store.AdapterMemory)
	seed(t, src)
	seedLogins(t, src)
	dst := portSide(env.Open(t), store.AdapterNATS)
	report, err := migrate.Run(ctx, side("memory", src), side("new.yaml", dst), stopped)
	if err != nil || !report.OK || report.Totals.Mismatched != 0 {
		t.Fatalf("Run = %v\n%s", err, report.JSON())
	}
	if report.Totals.Copied < seededItems {
		t.Errorf("copied %d, want at least %d", report.Totals.Copied, seededItems)
	}
}

func TestARerunCopiesNothingAndAFailedRunCompletes(t *testing.T) {
	env := natsEnvs(t)[0]
	src := newLegacy(t)
	seed(t, src.stores)
	seedLogins(t, src.stores)
	healthy := env.Open(t)

	// The destination's State fails on its seventh write: a run that stops half way.
	flaky := &failing{State: healthy.State, after: 7}
	set := healthy
	set.State = flaky
	dst := portSide(set, store.AdapterNATS)

	report, err := migrate.Run(ctx, side("old", src.stores), side("new", dst), stopped)
	if err == nil || report.OK {
		t.Fatalf("a run with a failing destination = %v, %+v", err, report)
	}
	copied := report.Totals.Copied
	if copied == 0 || copied >= seededItems {
		t.Errorf("a run that failed half way copied %d", copied)
	}

	// Run again against the healthy destination: what is missing is copied, and what is
	// there is left alone.
	dst = portSide(healthy, store.AdapterNATS)
	report, err = migrate.Run(ctx, side("old", src.stores), side("new", dst), stopped)
	if err != nil || !report.OK {
		t.Fatalf("the re-run = %v\n%s", err, report.JSON())
	}
	if report.Totals.Present == 0 || report.Totals.Copied == 0 {
		t.Errorf("the re-run = %+v, want some already present and the rest copied", report.Totals)
	}

	// And a third time there is nothing left to do.
	report, err = migrate.Run(ctx, side("old", src.stores), side("new", dst), stopped)
	if err != nil || report.Totals.Copied != 0 || report.Totals.New != 0 || report.Totals.Present != report.Totals.Source {
		t.Fatalf("the third run = %v\n%s", err, report.JSON())
	}
}

// failing is a State whose writes fail after a number of them, and which says
// what it holds the way the healthy one does.
type failing struct {
	port.State
	after, n int
}

func (f *failing) bump() error {
	f.n++
	if f.n > f.after {
		return port.ErrUnavailable
	}
	return nil
}

func (f *failing) Put(ctx context.Context, key string, v []byte, ttl time.Duration) (port.Revision, error) {
	if err := f.bump(); err != nil {
		return "", err
	}
	return f.State.Put(ctx, key, v, ttl)
}

func (f *failing) Create(ctx context.Context, key string, v []byte, ttl time.Duration) (port.Revision, error) {
	if err := f.bump(); err != nil {
		return "", err
	}
	return f.State.Create(ctx, key, v, ttl)
}

func (f *failing) Update(ctx context.Context, key string, v []byte, ttl time.Duration, rev port.Revision) (port.Revision, error) {
	if err := f.bump(); err != nil {
		return "", err
	}
	return f.State.Update(ctx, key, v, ttl, rev)
}

func (f *failing) ExportState(ctx context.Context, prefix string, fn func(port.Exported) error) error {
	return f.State.(port.StateExporter).ExportState(ctx, prefix, fn)
}

// altering is a State that corrupts what it keeps of the issuer's state, so that
// a copy that does not verify is seen not to.
type altering struct{ port.State }

func (a altering) Put(ctx context.Context, key string, v []byte, ttl time.Duration) (port.Revision, error) {
	if strings.HasPrefix(key, "issuer:session:") {
		v = append(slices.Clone(v), ' ')
	}
	return a.State.Put(ctx, key, v, ttl)
}

func (a altering) ExportState(ctx context.Context, prefix string, fn func(port.Exported) error) error {
	return a.State.(port.StateExporter).ExportState(ctx, prefix, fn)
}

func TestACopyThatDoesNotVerifyFails(t *testing.T) {
	env := natsEnvs(t)[0]
	src := newLegacy(t)
	seedLogins(t, src.stores)
	set := env.Open(t)
	set.State = altering{set.State}
	report, err := migrate.Run(ctx, side("old", src.stores), side("new", portSide(set, store.AdapterNATS)), stopped)
	if !errors.Is(err, migrate.ErrMismatch) || report.OK || report.Totals.Mismatched != 1 {
		t.Fatalf("Run = %v, %+v", err, report)
	}
	m := report.Mismatches[0]
	if m.Domain != "issuer" || !strings.HasPrefix(m.Key, "issuer:session:#") {
		t.Errorf("the mismatch = %+v, want the session named by kind and hash, not by id", m)
	}
}

func TestADifferentValueOnTheDestinationFailsTheRunBeforeAnythingIsWritten(t *testing.T) {
	env := natsEnvs(t)[0]
	src := newLegacy(t)
	seed(t, src.stores)
	seedLogins(t, src.stores)
	dst := portSide(env.Open(t), store.AdapterNATS)

	// The destination already has the organisation, with another owner.
	d, err := migrate.OpenDomains(ctx, dst, false)
	if err != nil {
		t.Fatal(err)
	}
	sd, _ := migrate.OpenDomains(ctx, src.stores, false)
	records, _ := sd.Orgs.List(ctx)
	cred, _, _ := sd.Orgs.Credential(ctx, "acme")
	cred.Record = nil
	records[0].Owner = "somebody-else"
	if err = d.Orgs.Put(ctx, records[0], cred); err != nil {
		t.Fatal(err)
	}

	report, err := migrate.Run(ctx, side("old", src.stores), side("new", dst), stopped)
	if !errors.Is(err, migrate.ErrConflict) || !strings.Contains(err.Error(), "github/organisations acme") {
		t.Fatalf("Run = %v, want a conflict naming github/organisations acme", err)
	}
	if report.OK || len(report.Conflicts) != 1 || report.Totals.Copied != 0 {
		t.Fatalf("report = %s", report.JSON())
	}
	if ws, _ := d.Workspaces.List(ctx); len(ws) != 0 {
		t.Errorf("a run that stopped on a conflict had written %d workspaces", len(ws))
	}
	if n := countState(t, dst, "issuer:"); n != 0 {
		t.Errorf("a run that stopped on a conflict had written %d issuer records", n)
	}

	// With --overwrite the destination takes the source's value.
	opts := stopped
	opts.Overwrite = true
	report, err = migrate.Run(ctx, side("old", src.stores), side("new", dst), opts)
	if err != nil || !report.OK {
		t.Fatalf("Run with Overwrite = %v\n%s", err, report.JSON())
	}
	if s := step(t, report, "github", "organisations"); s.Conflicts != 1 || s.Copied != 1 || s.Verified != 1 {
		t.Errorf("organisations = %+v", s)
	}
	if got, _ := d.Orgs.List(ctx); len(got) != 1 || got[0].Owner != "C01" {
		t.Errorf("the destination's organisation = %+v, want the source's owner", got)
	}
}

func countState(t *testing.T, st *store.Stores, prefix string) int {
	t.Helper()
	n := 0
	err := st.Ports.State.(port.StateExporter).ExportState(ctx, prefix, func(port.Exported) error { n++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestADryRunPlansAndTouchesNothing(t *testing.T) {
	env := natsEnvs(t)[0]
	src := newLegacy(t)
	seed(t, src.stores)
	seedLogins(t, src.stores)
	dst := portSide(env.Open(t), store.AdapterNATS)

	report, err := migrate.Run(ctx, side("old", src.stores), side("new", dst), migrate.Options{DryRun: true})
	if err != nil || !report.OK || !report.DryRun {
		t.Fatalf("Run = %v\n%s", err, report.JSON())
	}
	if report.Totals.New < seededItems || report.Totals.Copied != 0 || report.Totals.Verified != 0 {
		t.Errorf("totals = %+v, want everything new and nothing copied", report.Totals)
	}
	if s := step(t, report, "github", "links"); s.Source != 2 || s.New != 2 {
		t.Errorf("links = %+v", s)
	}
	for _, prefix := range []string{"ws.", "gh.", "app.", "rec.", "gate.", "issuer:"} {
		if n := countState(t, dst, prefix); n != 0 {
			t.Errorf("a dry run wrote %d records under %s", n, prefix)
		}
	}

	// Nor does it touch a legacy destination's objects.
	legacyDst := newLegacy(t)
	before := len(legacyDst.api.Actions())
	if _, err = migrate.Run(ctx, side("old", src.stores), side("legacy", legacyDst.stores), migrate.Options{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	for _, a := range legacyDst.api.Actions()[before:] {
		if v := a.GetVerb(); v != "get" && v != "list" {
			t.Errorf("a dry run did a %s of %s on the destination's namespace", v, a.GetResource().Resource)
		}
	}
	// And the source's console key was not created by reading it.
	if _, err = migrate.Run(ctx, side("new", dst), side("empty", portSide(memory.New().Set(), store.AdapterMemory)), migrate.Options{DryRun: true}); err != nil {
		t.Fatal(err)
	}
}

func TestARunThatWritesNeedsTheSourceStopped(t *testing.T) {
	src := newLegacy(t)
	dst := portSide(memory.New().Set(), store.AdapterMemory)
	if _, err := migrate.Run(ctx, side("old", src.stores), side("new", dst), migrate.Options{}); !errors.Is(err, migrate.ErrWritersRunning) {
		t.Errorf("Run without the statement = %v", err)
	}
	if _, err := migrate.Run(ctx, side("old", src.stores), side("new", dst), migrate.Options{DryRun: true}); err != nil {
		t.Errorf("a dry run = %v", err)
	}
	if _, err := migrate.Run(ctx, side("old", src.stores), side("new", dst), migrate.Options{WritersStopped: true, Skip: []string{"nonsense"}}); err == nil {
		t.Error("an unknown domain to skip was accepted")
	}
}

// The way back: what was moved to NATS moves again into the old objects, which is
// the rollback of the runbook, and the second copy is the first's equal.
func TestNATSBackToLegacyIsTheRollback(t *testing.T) {
	env := natsEnvs(t)[0]
	src := newLegacy(t)
	seed(t, src.stores)
	seedLogins(t, src.stores)
	mid := portSide(env.Open(t), store.AdapterNATS)
	if _, err := migrate.Run(ctx, side("old", src.stores), side("new", mid), stopped); err != nil {
		t.Fatal(err)
	}

	back := newLegacy(t)
	report, err := migrate.Run(ctx, side("new", mid), side("restored", back.stores), stopped)
	if err != nil || !report.OK || report.Totals.Mismatched != 0 {
		t.Fatalf("the rollback = %v\n%s", err, report.JSON())
	}
	// A refresh token still works on the restored Valkey, with its lifetime.
	sessions := issuer.NewSessions(issuer.NewPortState(back.stores.Ports.State, back.stores.Ports.Index), sessionLifetime, 0)
	if _, ok, err := sessions.ByRefreshToken(ctx, "refresh-ada"); err != nil || !ok {
		t.Fatalf("ByRefreshToken after the rollback = %v, %v", ok, err)
	}
	if ttl := back.redis.TTL("access-roster:" + "issuer:session-token:" + hashed(t, back)); ttl < 29*24*time.Hour || ttl > sessionLifetime {
		t.Errorf("the restored refresh token has %s left", ttl)
	}
}

// hashed finds the hash a refresh token was filed under on the legacy side.
func hashed(t *testing.T, l *legacySide) string {
	t.Helper()
	for _, k := range l.redis.Keys() {
		if rest, ok := strings.CutPrefix(k, "access-roster:issuer:session-token:"); ok {
			return rest
		}
	}
	t.Fatalf("no refresh token key in %v", l.redis.Keys())
	return ""
}

func TestUnreadableSourceItemsAreReportedAndTheRestIsCopied(t *testing.T) {
	env := natsEnvs(t)[0]
	mem := memory.New()
	src := portSide(mem.Set(), store.AdapterMemory)
	seed(t, src)
	// A Slack Connect channel record that does not decode.
	if _, err := mem.Put(ctx, "rec.slack.shared.broken", []byte("{not json"), 0); err != nil {
		t.Fatal(err)
	}
	dst := portSide(env.Open(t), store.AdapterNATS)
	report, err := migrate.Run(ctx, side("memory", src), side("new", dst), stopped)
	if !errors.Is(err, migrate.ErrUnreadable) || report.OK {
		t.Fatalf("Run = %v", err)
	}
	if len(report.Unreadable) != 1 || report.Unreadable[0].Key != "broken" {
		t.Errorf("unreadable = %+v", report.Unreadable)
	}
	if s := step(t, report, "directory", "workspaces"); s.Verified != 2 {
		t.Errorf("the rest was not copied and verified: %+v", s)
	}
	if s := step(t, report, "slack", "shared-channels"); s.Source != 1 || s.Unreadable != 1 || s.Verified != 1 {
		t.Errorf("shared channels = %+v", s)
	}
}

func TestReportsAreCopiedOnlyWhenTheBlobsAreInDifferentPlaces(t *testing.T) {
	for _, c := range []struct {
		name, from, to string
		mode           migrate.BlobMode
		copied         bool
	}{
		{"different places", "legacy", "s3", migrate.BlobsAuto, true},
		{"the same place", "s3", "s3", migrate.BlobsAuto, false},
		{"forced", "s3", "s3", migrate.BlobsCopy, true},
		{"skipped", "legacy", "s3", migrate.BlobsSkip, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, b := memory.New(), memory.New()
			if _, err := a.Blobs().Write(ctx, "reports/github/acme.json", []byte(`{"pass":1}`)); err != nil {
				t.Fatal(err)
			}
			from, to := portSide(a.Set(), store.AdapterMemory), portSide(b.Set(), store.AdapterMemory)
			report, err := migrate.Run(ctx, migrate.Side{Name: "a", Stores: from, BlobID: c.from},
				migrate.Side{Name: "b", Stores: to, BlobID: c.to}, migrate.Options{WritersStopped: true, Blobs: c.mode})
			if err != nil {
				t.Fatalf("Run = %v\n%s", err, report.JSON())
			}
			_, rerr := b.Blobs().Read(ctx, "reports/github/acme.json")
			if (rerr == nil) != c.copied {
				t.Errorf("the report was copied = %v, want %v", rerr == nil, c.copied)
			}
		})
	}
}

func TestSkipLeavesADomainOutAndTheReportCanBeKept(t *testing.T) {
	src := portSide(memory.New().Set(), store.AdapterMemory)
	seed(t, src)
	seedLogins(t, src)
	dstMem := memory.New()
	dst := portSide(dstMem.Set(), store.AdapterMemory)
	report, err := migrate.Run(ctx, side("a", src), side("b", dst), migrate.Options{
		WritersStopped: true, Skip: []string{"issuer", "slack"}, ReportBlob: "reports/migration.json",
	})
	if err != nil {
		t.Fatalf("Run = %v\n%s", err, report.JSON())
	}
	for _, s := range report.Steps {
		if s.Domain == "issuer" || s.Domain == "slack" {
			t.Errorf("a skipped domain was run: %+v", s)
		}
	}
	obj, err := dstMem.Blobs().Read(ctx, "reports/migration.json")
	if err != nil || !bytes.Contains(obj.Body, []byte(`"ok": true`)) {
		t.Errorf("the report on the destination = %q, %v", obj.Body, err)
	}
}
