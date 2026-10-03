package controller_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/truvity/access-roster/internal/portstore"
	"github.com/truvity/access-roster/internal/portstore/portstoretest"
	"github.com/truvity/access-roster/internal/slackapp/slackfake"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// connectOnPorts is what the console does when a workspace is connected and
// installed, on the State port instead of a ConfigMap and a Secret, and empties
// the rig's mounted directories so that nothing can be read from them.
func (r *rig) connectOnPorts(s *portstore.SlackWorkspaces) {
	r.t.Helper()
	r.creds, r.records = r.t.TempDir(), r.t.TempDir()
	for ws, team := range teams {
		err := s.Put(context.Background(),
			connection.Record{
				Workspace: ws, TeamID: team, Owner: "C0" + ws, AppID: "A1", BotUserID: slackfake.BotID(team),
				ConnectedAt: r.now, ConnectedBy: "ada@acme.example",
			},
			connection.Credential{Workspace: ws, AppID: "A1", ClientID: "c", ClientSecret: "s", BotToken: slackfake.Token(team)})
		if err != nil {
			r.t.Fatal(err)
		}
	}
}

func TestAWorkspaceIsMadeToMatchFromRecordsOnTheStatePort(t *testing.T) {
	portstoretest.Each(t, func(t *testing.T, e portstoretest.Env) {
		r := newRig(t)
		base := portstore.New(e.Open(t))
		r.connectOnPorts(portstore.NewSlackWorkspaces(base))
		r.source = portstore.NewSlackSource(base)
		ann := r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")

		r.pass("acme")

		ch, ok := r.fake.ChannelNamed("TACME", "eng")
		if !ok || !ch.Private || !slices.Contains(ch.Members, ann) {
			t.Fatalf("eng = %+v (found %v), want a private channel with ann in it", ch, ok)
		}
		if got := r.reports.workspace(t, "acme"); !got.Enabled || got.Tick.Outcome != status.OutcomeApplied {
			t.Fatalf("tick = %+v, want applied", got.Tick)
		}
		r.pass("acme")
		if got := r.reports.workspace(t, "acme"); got.Tick.Outcome != status.OutcomeInSync {
			t.Errorf("second pass tick = %+v, want in sync", got.Tick)
		}
	})
}

// A workspace the console has not connected on the State port is waiting, not
// failed, exactly as one with no mounted file is.
func TestAWorkspaceWithNoRecordOnThePortsIsWaiting(t *testing.T) {
	portstoretest.Each(t, func(t *testing.T, e portstoretest.Env) {
		r := newRig(t)
		r.source = portstore.NewSlackSource(portstore.New(e.Open(t)))
		r.creds, r.records = t.TempDir(), t.TempDir()

		r.pass("acme")

		if got := r.reports.workspace(t, "acme"); got.Tick.Outcome != status.OutcomeWaiting {
			t.Errorf("tick = %+v, want waiting", got.Tick)
		}
	})
}

// The host's tick and the guest's tick are different processes, each with its
// own connection to the State: the share record, written by one, is what the
// other acts on, and the guest's accept is recorded for the host to read.
func TestAShareIsHandedAcrossProcessesOnTheStatePort(t *testing.T) {
	portstoretest.Each(t, func(t *testing.T, e portstoretest.Env) {
		r := newRig(t)
		hostSet, guestSet := e.Open(t), e.Open(t)
		hostBase, guestBase := portstore.New(hostSet), portstore.New(guestSet)
		r.connectOnPorts(portstore.NewSlackWorkspaces(hostBase))
		r.person("ann@acme.example", []string{"g-all", dirAll}, "acme")
		r.person("bob@globex.example", []string{"g-all", dirAll}, "globex")
		def := reconcile.SharedChannel{Name: "fresh", Host: "acme", With: []string{"globex"}, Sources: []string{dirAll}}
		if err := portstore.NewSlackShared(hostBase).Apply(context.Background(), "fresh",
			func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return &def, nil }); err != nil {
			t.Fatal(err)
		}

		woken := make(chan string, 8)
		stop := guestSet.Trigger.Subscribe(func(target string) { woken <- target })
		defer stop()

		// Each process has its own source, hand-off and trigger.
		r.source, r.handoff, r.trigger = portstore.NewSlackSource(hostBase), portstore.NewHandoff(hostBase, hostSet.Trigger), hostSet.Trigger
		host := r.fresh("acme", "globex")
		guestHandoff := portstore.NewHandoff(guestBase, guestSet.Trigger)
		r.source, r.handoff, r.trigger = portstore.NewSlackSource(guestBase), guestHandoff, guestSet.Trigger
		guest := r.fresh("acme", "globex")

		if _, _, err := host.RunTarget(context.Background(), "acme"); err != nil {
			t.Fatal(err)
		}
		if r.fake.Count("conversations.inviteShared") != 1 {
			t.Fatalf("the host did not invite: %d", r.fake.Count("conversations.inviteShared"))
		}
		select {
		case target := <-woken:
			if target != "globex" {
				t.Errorf("the guest's process was asked to tick %q", target)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("writing the share did not ask the guest's process to tick")
		}
		waiting, err := guestHandoff.Waiting(context.Background(), "globex")
		if err != nil || len(waiting) != 1 || waiting[0].Host != "acme" || waiting[0].Channel != "fresh" {
			t.Fatalf("the guest's process reads %+v, %v; want the host's share", waiting, err)
		}

		if _, _, err = guest.RunTarget(context.Background(), "globex"); err != nil {
			t.Fatal(err)
		}
		if r.fake.Count("conversations.acceptSharedInvite") != 1 {
			t.Errorf("the guest's tick accepted %d times, want once", r.fake.Count("conversations.acceptSharedInvite"))
		}
		share, found, err := portstore.NewHandoff(hostBase, nil).Status(context.Background(), "acme", "fresh")
		if err != nil || !found || !share.Settled() {
			t.Errorf("the host reads %+v, %v, %v; want the guest's side accepted", share, found, err)
		}
		if waiting, _ = guestHandoff.Waiting(context.Background(), "globex"); len(waiting) != 0 {
			t.Errorf("an accepted share is still waiting: %+v", waiting)
		}
	})
}

// users.info is asked once per member per day, not once per pass: a second
// controller, a restart or another runner, finds the answer on the State port.
// The hits and the misses are counted.
func TestWhoAMemberIsIsAskedOfSlackOnceAndCounted(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	portstoretest.Each(t, func(t *testing.T, e portstoretest.Env) {
		r := newRig(t)
		base := portstore.New(e.Open(t))
		r.members = portstore.NewUserCache(base)
		ann := r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")
		stranger := r.person("stranger@acme.example", nil, "acme")
		r.strictChannel(ann, stranger)

		r.pass() // a dry run observes everything and changes nothing
		first := r.fake.Count("users.info")
		if first == 0 {
			t.Fatal("the first pass identified nobody: the test has nothing to cache")
		}
		r.fresh().Pass(context.Background()) // another runner, nothing in memory
		if again := r.fake.Count("users.info"); again != first {
			t.Errorf("users.info was called %d more times on the second pass, want none", again-first)
		}
		if hits, misses := userCacheCounts(t, reader); hits == 0 || misses == 0 {
			t.Errorf("the cache counted %d hits and %d misses, want both", hits, misses)
		}
		// A day later the member is asked about again.
		e.Advance(portstore.UserCacheTTL + time.Minute)
		r.fresh().Pass(context.Background())
		if third := r.fake.Count("users.info"); third == first {
			t.Error("a member was never asked about again after the cache's day")
		}
	})
}

func userCacheCounts(t *testing.T, reader sdkmetric.Reader) (hits, misses int64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "slack_roster.user_cache" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("the metric is %T, want a counter", m.Data)
			}
			for _, point := range sum.DataPoints {
				if v, _ := point.Attributes.Value("result"); v.AsString() == "hit" {
					hits += point.Value
				} else {
					misses += point.Value
				}
			}
		}
	}
	return hits, misses
}
