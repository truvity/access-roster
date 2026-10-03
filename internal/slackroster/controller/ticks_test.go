package controller_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/controller"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

func (r *reports) putsOf(ws string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.puts[status.Key(ws)]
}

// One workspace's tick failing does not stop another's, and each publishes its
// own report.
func TestOneWorkspacesFailureDoesNotStopAnothersTick(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")
	r.person("gus@globex.example", []string{"g-gx"}, "globex")
	// Globex's credential cannot be read: its tick fails.
	if err := os.WriteFile(filepath.Join(r.creds, connection.Key("globex")), []byte("not a credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := r.controller()

	if _, err := c.Tick(context.Background(), "globex"); err != nil {
		t.Fatalf("a tick that fails to reach its workspace reports it, and is not an error: %v", err)
	}
	if got := r.reports.workspace(t, "globex").Tick.Outcome; got != status.OutcomeFailed {
		t.Fatalf("globex = %v, want a failed tick", got)
	}
	if _, err := c.Tick(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if got := r.reports.workspace(t, "acme").Tick; got.Outcome != status.OutcomeDryRun {
		t.Errorf("acme = %+v, want its own dry run beside globex's failure", got)
	}
	// A sweep goes through both whichever fails, once each.
	r.reports.puts = nil
	c.Pass(context.Background())
	if r.reports.putsOf("acme") != 1 || r.reports.putsOf("globex") != 1 {
		t.Errorf("a sweep published acme %d and globex %d times, want once each", r.reports.putsOf("acme"), r.reports.putsOf("globex"))
	}
}

// A tick publishes its own report and no other, and the bytes of the one it
// did not tick are exactly what they were.
func TestATickPublishesOnlyItsOwnReport(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")
	c := r.controller()
	c.Pass(context.Background())
	documents, _ := r.reports.Reports(context.Background())
	before := documents[status.Key("globex")]
	acme, globex := r.reports.putsOf("acme"), r.reports.putsOf("globex")

	r.now = r.now.Add(time.Minute)
	if _, err := c.Tick(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if r.reports.putsOf("acme") != acme+1 || r.reports.putsOf("globex") != globex {
		t.Errorf("acme's tick wrote acme %d and globex %d times, want 1 and 0", r.reports.putsOf("acme")-acme, r.reports.putsOf("globex")-globex)
	}
	documents, _ = r.reports.Reports(context.Background())
	if documents[status.Key("globex")] != before {
		t.Error("globex's report bytes changed under acme's tick")
	}
}

func TestATickOfAnUnknownWorkspaceIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.controller()
	if _, err := c.Tick(context.Background(), "initech"); !errors.Is(err, controller.ErrUnknownTarget) {
		t.Errorf("Tick(initech) = %v, want ErrUnknownTarget", err)
	}
	if _, _, err := c.RunTarget(context.Background(), "initech"); !errors.Is(err, controller.ErrUnknownTarget) {
		t.Errorf("RunTarget(initech) = %v, want ErrUnknownTarget", err)
	}
}

// A notification ticks its workspace and nobody else.
func TestTheTriggerTicksOnlyItsWorkspace(t *testing.T) {
	r := newRig(t)
	trigger := memory.New()
	r.trigger = trigger
	c := controller.New(controller.Config{CredentialsDir: r.creds, RecordsDir: r.records, CredentialPoll: -1, Interval: time.Hour},
		controller.Deps{
			Log: r.logger(), Access: r.console, Audit: r.audit, Status: r.reports, Policy: r.policy, Digest: testPolicy,
			Trigger: trigger, Now: func() time.Time { return r.now },
		})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, "the first sweep", func() bool { return r.reports.putsOf("acme") >= 1 && r.reports.putsOf("globex") >= 1 })
	acme, globex := r.reports.putsOf("acme"), r.reports.putsOf("globex")

	if err := trigger.Notify(ctx, "globex"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "globex's tick", func() bool { return r.reports.putsOf("globex") > globex })
	time.Sleep(200 * time.Millisecond)
	if got := r.reports.putsOf("globex"); got != globex+1 {
		t.Errorf("globex ticked %d times for one notification", got-globex)
	}
	if got := r.reports.putsOf("acme"); got != acme {
		t.Errorf("a notification for globex ticked acme (%d -> %d)", acme, got)
	}
}

// With a lease per workspace, a workspace another runner holds is left to it,
// and the others tick.
func TestAWorkspaceAnotherRunnerHoldsIsLeftToIt(t *testing.T) {
	r := newRig(t)
	state := memory.New()
	r.leases = &rails.Leases{State: state, Holder: "me", TTL: time.Minute}
	theirs := &rails.Leases{State: state, Holder: "them", TTL: time.Minute}
	c := r.controller()

	held, err := theirs.Acquire(context.Background(), "slack-tick", "acme")
	if err != nil {
		t.Fatal(err)
	}
	c.Pass(context.Background())
	if r.reports.putsOf("acme") != 0 {
		t.Error("acme ticked under a lease another runner holds")
	}
	if r.reports.putsOf("globex") != 1 {
		t.Error("globex, which nobody holds, did not tick")
	}
	if ran, _, err := c.RunTarget(context.Background(), "acme"); err != nil || ran {
		t.Errorf("RunTarget(acme) = %v, %v; want it left to its holder", ran, err)
	}
	if err = held.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ran, _, err := c.RunTarget(context.Background(), "acme"); err != nil || !ran {
		t.Errorf("after the release RunTarget(acme) = %v, %v; want it run", ran, err)
	}
	if _, err = theirs.Acquire(context.Background(), "slack-tick", "acme"); err != nil {
		t.Errorf("a finished tick left its lease: %v", err)
	}
}

// The host's tick invites the guest and asks the guest to tick; the guest
// accepts on its own tick. No storage is shared between the two.
func TestANewShareWakesItsGuestWhichAcceptsOnItsOwnTick(t *testing.T) {
	r := newRig(t)
	trigger := memory.New()
	r.trigger = trigger
	var mu sync.Mutex
	var woken []string
	trigger.Subscribe(func(target string) {
		mu.Lock()
		defer mu.Unlock()
		woken = append(woken, target)
	})
	wokenTargets := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(woken)
	}
	r.person("ann@acme.example", []string{"g-all", dirAll}, "acme")
	r.person("bob@globex.example", []string{"g-all", dirAll}, "globex")
	r.writeShared("fresh", "acme", "globex")
	c := r.controller("acme", "globex")

	if _, _, err := c.RunTarget(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if r.fake.Count("conversations.inviteShared") != 1 {
		t.Fatalf("the host did not invite: %d", r.fake.Count("conversations.inviteShared"))
	}
	if r.fake.Count("conversations.acceptSharedInvite") != 0 {
		t.Fatal("the guest accepted without a tick of its own")
	}
	waitFor(t, "the guest to be woken", func() bool { return slices.Contains(wokenTargets(), "globex") })
	if slices.Contains(wokenTargets(), "acme") {
		t.Error("the host woke itself")
	}

	if _, _, err := c.RunTarget(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	if r.fake.Count("conversations.acceptSharedInvite") != 1 {
		t.Errorf("the guest's tick accepted %d times, want once", r.fake.Count("conversations.acceptSharedInvite"))
	}
}

// A share still waiting for its guest wakes the guest again on the host's next
// tick: a notification is a hint and may have been lost.
func TestAPendingShareWakesItsGuestAgain(t *testing.T) {
	r := newRig(t)
	trigger := memory.New()
	r.trigger = trigger
	var mu sync.Mutex
	woken := 0
	trigger.Subscribe(func(target string) {
		if target == "globex" {
			mu.Lock()
			woken++
			mu.Unlock()
		}
	})
	count := func() int { mu.Lock(); defer mu.Unlock(); return woken }
	r.person("ann@acme.example", []string{"g-all", dirAll}, "acme")
	r.person("bob@globex.example", []string{"g-all", dirAll}, "globex")
	r.writeShared("fresh", "acme", "globex")
	c := r.controller("acme", "globex")

	if _, _, err := c.RunTarget(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first wake", func() bool { return count() == 1 })
	if _, _, err := c.RunTarget(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a second wake for the share that is still pending", func() bool { return count() == 2 })
	if r.fake.Count("conversations.inviteShared") != 1 {
		t.Errorf("the pending share was invited again: %d", r.fake.Count("conversations.inviteShared"))
	}
}

// The host's tick reads the guest's last report from the blob: a guest that
// lists the channel itself is not probed.
func TestTheHostReadsTheGuestsReportBeforeProbingIt(t *testing.T) {
	r := newRig(t)
	ch := r.fake.AddSharedChannel("legacy", "TACME", []string{"TGLOBEX"}, map[string]bool{"TACME": false, "TGLOBEX": false}, r.creator())
	r.manage("legacy", ch.ID, "globex")
	c := r.controller()

	if _, err := c.Tick(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	if got := r.reports.workspace(t, "globex").DiscoveredShared; len(got) != 1 || got[0].ID != ch.ID {
		t.Fatalf("globex does not list the channel itself: %+v", got)
	}
	if _, err := c.Tick(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if n := r.probes("TGLOBEX"); n != 0 {
		t.Errorf("globex lists the channel in its published report and was probed %d times", n)
	}
	if got := r.reports.workspace(t, "acme").GuestSides; len(got) != 0 {
		t.Errorf("acme published guest sides for a guest that lists it: %+v", got)
	}
}

// A guest is never the one that probes: only the host's tick does.
func TestOnlyTheHostsTickProbes(t *testing.T) {
	r := newRig(t)
	ch := r.shareHostedByAcme()
	r.manage("legacy", ch.ID, "globex")
	c := r.controller()

	if _, err := c.Tick(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	if n := r.probes("TGLOBEX") + r.probes("TACME"); n != 0 {
		t.Errorf("the guest's tick probed %d times", n)
	}
	if _, err := c.Tick(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if n := r.probes("TGLOBEX"); n != 1 {
		t.Errorf("the host's tick probed the guest %d times, want once", n)
	}
}

// The inputs the ticks share are read once for a sweep, and again when what
// is mounted changes.
func TestTheSharedInputsAreReadOnceForASweep(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")
	c := r.controller()
	c.Pass(context.Background())
	if r.console.heldQuestions() == 0 {
		t.Fatal("no holders were asked")
	}
	asked := r.console.heldQuestions()

	for _, ws := range []string{"acme", "globex", "acme"} {
		if _, err := c.Tick(context.Background(), ws); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.console.heldQuestions(); got != asked {
		t.Errorf("ticks within the cache asked the console who holds a group %d more times", got-asked)
	}

	r.writeRecord("_pass.acme.json", `{"workspace":"acme","at":"2026-10-03T10:00:00Z","by":"ann"}`)
	if _, err := c.Tick(context.Background(), "acme"); err != nil {
		t.Fatal(err)
	}
	if got := r.console.heldQuestions(); got == asked {
		t.Error("a changed record did not read the shared inputs again")
	}
}

// writeShared is the console's record of a shared channel the host makes.
func (r *rig) writeShared(name, host string, with ...string) {
	r.t.Helper()
	raw, err := connection.EncodeShared(reconcile.SharedChannel{Name: name, Host: host, With: with, Sources: []string{dirAll}})
	if err != nil {
		r.t.Fatal(err)
	}
	r.writeRecord(connection.SharedKey(name), raw)
}
