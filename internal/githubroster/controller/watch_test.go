package controller_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/controller"
)

// watchRig is a controller that polls its mounted credentials and records
// every few milliseconds and otherwise waits an hour.
type watchRig struct {
	*rig
	records string
}

func startWatching(t *testing.T) *watchRig {
	t.Helper()
	r := &watchRig{rig: newRig(t), records: t.TempDir()}
	c := controller.New(controller.Config{
		AppsDir: r.appsDir, RecordsDir: r.records, Enabled: map[string]bool{"globex": false},
		Interval: time.Hour, CredentialPoll: 10 * time.Millisecond,
	}, controller.Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
		Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bindings, Policy: testPolicy,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the first pass", func() bool { return r.report.published() >= 1 })
	return r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settled asserts that no further pass runs in many polls.
func (r *watchRig) settled(t *testing.T, what string, want int) {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
	if got := r.report.published(); got != want {
		t.Fatalf("%d publications %s, want %d", got, what, want)
	}
}

// An install lands as a changed credential in the mounted Secret. The
// controller notices within its poll period and passes then, instead of
// leaving the result for the full interval (an hour here); a poll that finds
// nothing changed passes nothing, and neither does a reserved key such as an
// operator's confirmation.
func TestAChangedCredentialRunsAPassWithoutWaitingForTheInterval(t *testing.T) {
	r := startWatching(t)
	r.settled(t, "with nothing changed", 1)

	if err := os.WriteFile(filepath.Join(r.records, connection.ConfirmationKey("globex")), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.settled(t, "after a confirmation changed", 1)

	writeCredential(t, r.appsDir, "globex")
	waitFor(t, "a pass after the credential changed", func() bool { return r.report.published() >= 2 })

	// A new organisation's record is a change too.
	raw, err := connection.EncodeRecord(connection.Record{Org: "initech", AppID: 1, AppSlug: "roster-initech"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(r.records, connection.Key("initech")), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a pass after a record appeared", func() bool { return r.report.published() >= 3 })
}

// An operator's request for a pass is a marker in the records. A request
// newer than the last one acted on runs a pass at once; the one that was
// already there when the controller started, and one that is not newer, run
// nothing.
func TestARequestedPassRunsOnceForANewerMarkerOnly(t *testing.T) {
	r := &watchRig{rig: newRig(t), records: t.TempDir()}
	marker := func(at time.Time) {
		raw, err := connection.EncodePassRequest(connection.PassRequest{Org: "globex", At: at, By: "ada@globex.example"})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(r.records, connection.PassKey("globex")), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().UTC().Truncate(time.Second)
	marker(base)
	c := controller.New(controller.Config{
		AppsDir: r.appsDir, RecordsDir: r.records, Enabled: map[string]bool{"globex": false},
		Interval: time.Hour, CredentialPoll: 10 * time.Millisecond,
	}, controller.Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
		Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bindings, Policy: testPolicy,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, "the first pass", func() bool { return r.report.published() >= 1 })
	r.settled(t, "with only the marker that was there at start", 1)
	marker(base.Add(-time.Hour))
	r.settled(t, "after an older marker", 1)
	marker(base.Add(time.Minute))
	waitFor(t, "a pass after a newer marker", func() bool { return r.report.published() >= 2 })
	r.settled(t, "for one request", 2)
}

// A negative poll turns the watch off: nothing wakes the loop but the
// interval.
func TestANegativePollWatchesNothing(t *testing.T) {
	r := &watchRig{rig: newRig(t), records: t.TempDir()}
	c := controller.New(controller.Config{
		AppsDir: r.appsDir, RecordsDir: r.records, Enabled: map[string]bool{"globex": false},
		Interval: time.Hour, CredentialPoll: -1,
	}, controller.Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
		Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bindings, Policy: testPolicy,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the first pass", func() bool { return r.report.published() >= 1 })
	writeCredential(t, r.appsDir, "globex")
	r.settled(t, "after a credential changed with the watch off", 1)
}
