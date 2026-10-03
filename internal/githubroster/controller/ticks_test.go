package controller_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/controller"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/policy"
)

// twoOrgs binds an organisation with no credential ("acme", which sorts first
// and fails every tick) beside the connected one ("globex").
var twoOrgs = map[string]policy.GitHubOrg{
	"acme":   {Members: []string{"all:acme:employee"}},
	"globex": bindings["globex"],
}

// tickers builds a controller over the rig with the given bindings, trigger and leases.
func (r *rig) tickers(bind map[string]policy.GitHubOrg, trigger *memory.Store, leases *rails.Leases) *controller.Controller {
	deps := controller.Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
		Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bind, Policy: testPolicy,
		Leases: leases,
	}
	if trigger != nil {
		deps.Trigger = trigger
	}
	return controller.New(controller.Config{
		AppsDir: r.appsDir, Enabled: map[string]bool{"globex": false, "acme": false}, CredentialPoll: -1, Interval: time.Hour,
	}, deps)
}

// One organisation's tick failing does not stop another's: each has its own
// report, and the failure is only the failing one's.
func TestOneOrganisationsFailureDoesNotStopAnothersTick(t *testing.T) {
	r := newRig(t)
	c := r.tickers(twoOrgs, nil, nil)

	if _, err := c.Tick(context.Background(), "acme"); err != nil {
		t.Fatalf("a tick that fails to reach its organisation reports it, and is not an error: %v", err)
	}
	if got := r.report.org(t, "acme"); got.Tick.Outcome != status.OutcomeFailed {
		t.Errorf("acme = %+v, want a failed tick (it has no credential)", got.Tick)
	}
	if _, err := c.Tick(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	if got := r.report.org(t, "globex"); got.Tick.Outcome != status.OutcomeDryRun {
		t.Errorf("globex = %+v, want its own dry run", got.Tick)
	}

	// And a sweep runs them both, whichever fails.
	c.Pass(context.Background())
	if r.report.putsOf("acme") != 2 || r.report.putsOf("globex") != 2 {
		t.Errorf("a sweep published acme %d and globex %d times, want 2 each (a tick and a sweep)", r.report.putsOf("acme"), r.report.putsOf("globex"))
	}
}

// A tick publishes its own report and no other: what another target last
// published is not written again.
func TestATickPublishesOnlyItsOwnReport(t *testing.T) {
	r := newRig(t)
	c := r.tickers(twoOrgs, nil, nil)
	c.Pass(context.Background())
	acme, globex := r.report.putsOf("acme"), r.report.putsOf("globex")
	documents, _ := r.report.Reports(context.Background())
	before := documents[status.Key("acme")]

	if _, err := c.Tick(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	if got := r.report.putsOf("acme"); got != acme {
		t.Errorf("globex's tick wrote acme's report (%d -> %d)", acme, got)
	}
	if got := r.report.putsOf("globex"); got != globex+1 {
		t.Errorf("globex's tick wrote globex's report %d times, want once", got-globex)
	}
	documents, _ = r.report.Reports(context.Background())
	if documents[status.Key("acme")] != before {
		t.Error("acme's report bytes changed under globex's tick")
	}
}

// A target that is not the controller's is refused by name.
func TestATickOfAnUnknownTargetIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.tickers(twoOrgs, nil, nil)
	if _, err := c.Tick(context.Background(), "initech"); !errors.Is(err, controller.ErrUnknownTarget) {
		t.Errorf("Tick(initech) = %v, want ErrUnknownTarget", err)
	}
	if _, _, err := c.RunTarget(context.Background(), "initech"); !errors.Is(err, controller.ErrUnknownTarget) {
		t.Errorf("RunTarget(initech) = %v, want ErrUnknownTarget", err)
	}
}

// The link check is a target of its own: it checks the links and publishes no
// organisation's report, and an organisation's tick does not check them.
func TestTheLinkCheckIsItsOwnTarget(t *testing.T) {
	r := newRig(t)
	c := r.tickers(twoOrgs, nil, nil)
	id := r.newbie.ID

	if _, err := c.Tick(context.Background(), "globex"); err != nil {
		t.Fatal(err)
	}
	if !r.links.get(id).CheckedAt.IsZero() {
		t.Fatal("an organisation's tick checked a link: it only reads them")
	}
	if got := r.report.org(t, "globex"); got.Tick.Outcome == status.OutcomeFailed {
		t.Fatalf("an organisation's tick without the link check failed: %+v", got.Tick)
	}

	puts := r.report.putsOf("globex")
	if _, err := c.Tick(context.Background(), controller.LinksTarget); err != nil {
		t.Fatal(err)
	}
	if r.links.get(id).CheckedAt.IsZero() {
		t.Error("the link target did not check the link")
	}
	if r.report.putsOf("globex") != puts || r.report.putsOf("acme") != 0 {
		t.Error("the link check published an organisation's report")
	}
}

// A notification ticks its target and nobody else.
func TestTheTriggerTicksOnlyItsTarget(t *testing.T) {
	r := newRig(t)
	trigger := memory.New()
	c := r.tickers(twoOrgs, trigger, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, "the first sweep", func() bool { return r.report.putsOf("acme") >= 1 && r.report.putsOf("globex") >= 1 })
	acme, globex := r.report.putsOf("acme"), r.report.putsOf("globex")

	if err := trigger.Notify(ctx, "globex"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "globex's tick", func() bool { return r.report.putsOf("globex") > globex })
	time.Sleep(200 * time.Millisecond)
	if got := r.report.putsOf("globex"); got != globex+1 {
		t.Errorf("globex ticked %d times for one notification", got-globex)
	}
	if got := r.report.putsOf("acme"); got != acme {
		t.Errorf("a notification for globex ticked acme (%d -> %d)", acme, got)
	}
}

// With a lease per target, a target another runner holds is left to it, and
// the others tick.
func TestATargetAnotherRunnerHoldsIsLeftToIt(t *testing.T) {
	r := newRig(t)
	state := memory.New()
	mine := &rails.Leases{State: state, Holder: "me", TTL: time.Minute}
	theirs := &rails.Leases{State: state, Holder: "them", TTL: time.Minute}
	c := r.tickers(twoOrgs, nil, mine)

	held, err := theirs.Acquire(context.Background(), "github-tick", "globex")
	if err != nil {
		t.Fatal(err)
	}
	c.Pass(context.Background())
	if r.report.putsOf("globex") != 0 {
		t.Error("globex ticked under a lease another runner holds")
	}
	if r.report.putsOf("acme") != 1 {
		t.Error("acme, which nobody holds, did not tick")
	}
	ran, _, err := c.RunTarget(context.Background(), "globex")
	if err != nil || ran {
		t.Errorf("RunTarget(globex) = %v, %v; want it left to its holder", ran, err)
	}

	if err = held.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ran, _, err = c.RunTarget(context.Background(), "globex"); err != nil || !ran {
		t.Errorf("after the release RunTarget(globex) = %v, %v; want it run", ran, err)
	}
	if r.report.putsOf("globex") != 1 {
		t.Error("globex did not publish after taking its lease")
	}
	// The lease was released with the tick.
	if _, err = theirs.Acquire(context.Background(), "github-tick", "globex"); err != nil {
		t.Errorf("a finished tick left its lease: %v", err)
	}
}
