package legacy_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/truvity/access-roster/internal/rails"
)

// The tick leases (docs/decisions/0029) over today's storage: a lease key of
// the form `lease.<kind>:<target>` is a Valkey key of the hub's lease family,
// and two runners sharing the Valkey exclude one another.
func TestTwoRunnersOnTheLegacyAdapterShareALease(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := &rails.Leases{State: f.ports.State, Holder: "a", TTL: time.Minute}
	b := &rails.Leases{State: f.ports.State, Holder: "b", TTL: time.Minute}

	held, err := a.Acquire(ctx, "slack-tick", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(ctx, "slack-tick", "acme"); !errors.Is(err, rails.ErrHeld) {
		t.Fatalf("a second runner took a held lease: %v", err)
	}
	if !hasKey(f, "{acme}:lease:slack-tick") {
		t.Errorf("the lease is not in the hub's lease slot of the workspace: %v", f.redis.Keys())
	}
	other, err := b.Acquire(ctx, "slack-tick", "globex")
	if err != nil {
		t.Fatalf("another target is free: %v", err)
	}
	_ = other.Release(ctx)
	if err := held.Renew(ctx); err != nil {
		t.Fatalf("the holder renews: %v", err)
	}
	if err := held.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if hasKey(f, "{acme}:lease:slack-tick") {
		t.Error("a released lease is still there")
	}
}

// hasKey is whether the Valkey holds a key ending in suffix: the adapter's
// installation prefix comes before it.
func hasKey(f *fixture, suffix string) bool {
	for _, k := range f.redis.Keys() {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

func TestALegacyLeaseIsTakenOverAfterItExpires(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := &rails.Leases{State: f.ports.State, Holder: "a", TTL: time.Minute}
	b := &rails.Leases{State: f.ports.State, Holder: "b", TTL: time.Minute}

	old, err := a.Acquire(ctx, "github-tick", "acme")
	if err != nil {
		t.Fatal(err)
	}
	f.redis.FastForward(2 * time.Minute)
	taken, err := b.Acquire(ctx, "github-tick", "acme")
	if err != nil {
		t.Fatalf("an expired lease is free: %v", err)
	}
	if err := old.Renew(ctx); !errors.Is(err, rails.ErrLost) {
		t.Fatalf("the old holder's renewal = %v, want ErrLost", err)
	}
	if err := old.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Acquire(ctx, "github-tick", "acme"); !errors.Is(err, rails.ErrHeld) {
		t.Fatalf("the old holder's release deleted the new holder's lease: %v", err)
	}
	if err := taken.Renew(ctx); err != nil {
		t.Fatal(err)
	}
}

// Of runners racing for one target on the legacy adapter, exactly one ticks.
func TestOneLegacyRunnerTicksATarget(t *testing.T) {
	f := newFixture(t)
	var ran atomic.Int32
	release := make(chan struct{})
	done := make(chan struct{})
	for i := range 5 {
		go func() {
			l := &rails.Leases{State: f.ports.State, Holder: string(rune('a' + i))}
			_, _ = l.Do(context.Background(), "slack-tick", "acme", func(context.Context) {
				ran.Add(1)
				<-release
			})
			done <- struct{}{}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	for range 5 {
		<-done
	}
	if got := ran.Load(); got != 1 {
		t.Fatalf("%d runners ticked, want 1", got)
	}
}

// A tick writes its own report's entry and no other: the other targets'
// entries are not touched, and an unchanged entry costs no write at all.
func TestATickRewritesOnlyItsOwnReportEntry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	reports := rails.NewBlobReports(f.ports.Blob, "reports/slack/")
	if err := reports.Replace(ctx, map[string]string{"acme.json": `{"a":1}`, "globex.json": `{"g":1}`}); err != nil {
		t.Fatal(err)
	}
	var updates atomic.Int32
	f.api.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates.Add(1)
		return false, nil, nil
	})
	before, _ := f.ports.Blob.Read(ctx, "reports/slack/globex.json")

	if err := reports.Put(ctx, "acme.json", `{"a":2}`); err != nil {
		t.Fatal(err)
	}
	if got := updates.Load(); got != 1 {
		t.Errorf("one tick's report took %d ConfigMap updates, want 1", got)
	}
	after, _ := f.ports.Blob.Read(ctx, "reports/slack/globex.json")
	if string(after.Body) != string(before.Body) || after.Version != before.Version {
		t.Errorf("globex's entry changed under acme's tick: %q -> %q", before.Body, after.Body)
	}
	if err := reports.Put(ctx, "acme.json", `{"a":2}`); err != nil {
		t.Fatal(err)
	}
	if got := updates.Load(); got != 1 {
		t.Errorf("a report that did not change cost %d more updates, want none", got-1)
	}
}
