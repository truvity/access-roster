package rails_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/rails"
)

func twoRunners(t *testing.T) (a, b *rails.Leases, store *memory.Store) {
	t.Helper()
	store = memory.New()
	return &rails.Leases{State: store, Holder: "a", TTL: time.Minute},
		&rails.Leases{State: store, Holder: "b", TTL: time.Minute}, store
}

// Two runners never hold one target at once, and each can hold another.
func TestALeaseIsExclusivePerTarget(t *testing.T) {
	ctx := context.Background()
	a, b, _ := twoRunners(t)
	held, err := a.Acquire(ctx, "slack-tick", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(ctx, "slack-tick", "acme"); !errors.Is(err, rails.ErrHeld) {
		t.Fatalf("a second runner took a held lease: %v", err)
	}
	other, err := b.Acquire(ctx, "slack-tick", "globex")
	if err != nil {
		t.Fatalf("another target is free: %v", err)
	}
	_ = other.Release(ctx)
	if err := held.Release(ctx); err != nil {
		t.Fatal(err)
	}
	again, err := b.Acquire(ctx, "slack-tick", "acme")
	if err != nil {
		t.Fatalf("a released lease is free: %v", err)
	}
	_ = again.Release(ctx)
}

// Of several runners racing for one target exactly one runs its tick.
func TestOneOfManyRacingRunnersRunsTheTick(t *testing.T) {
	store := memory.New()
	var ran atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	gate := make(chan struct{})
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := &rails.Leases{State: store, Holder: string(rune('a' + i))}
			<-start
			l.Do(context.Background(), "github-tick", "acme", func(context.Context) { //nolint:errcheck // asserted by the count
				ran.Add(1)
				<-gate
			})
		}()
	}
	close(start)
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()
	if got := ran.Load(); got != 1 {
		t.Fatalf("%d runners ran the tick, want exactly 1", got)
	}
}

// A lease that expired is taken over, and the old holder's renewal and
// release neither extend nor delete the new one.
func TestAnExpiredLeaseIsTakenOverAndTheOldHolderLosesIt(t *testing.T) {
	ctx := context.Background()
	a, b, store := twoRunners(t)
	old, err := a.Acquire(ctx, "slack-tick", "acme")
	if err != nil {
		t.Fatal(err)
	}
	store.Advance(2 * time.Minute)
	taken, err := b.Acquire(ctx, "slack-tick", "acme")
	if err != nil {
		t.Fatalf("an expired lease must be free: %v", err)
	}
	if err := old.Renew(ctx); !errors.Is(err, rails.ErrLost) {
		t.Fatalf("the old holder's renewal = %v, want ErrLost", err)
	}
	if err := old.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Acquire(ctx, "slack-tick", "acme"); !errors.Is(err, rails.ErrHeld) {
		t.Fatalf("the old holder's release deleted the new holder's lease: %v", err)
	}
	if err := taken.Renew(ctx); err != nil {
		t.Fatalf("the new holder renews: %v", err)
	}
}

// Do tells a caller that another runner has the target, with no error.
func TestDoSkipsATargetAnotherRunnerHolds(t *testing.T) {
	ctx := context.Background()
	a, b, _ := twoRunners(t)
	if _, err := a.Acquire(ctx, "slack-tick", "acme"); err != nil {
		t.Fatal(err)
	}
	ran, err := b.Do(ctx, "slack-tick", "acme", func(context.Context) { t.Error("ran under a lease it does not hold") })
	if err != nil || ran {
		t.Fatalf("Do = %v, %v; want false, nil", ran, err)
	}
}

// A tick that loses its lease has its context cancelled, and the lease is
// released on a normal return.
func TestATickLosesItsContextWhenItsLeaseIsTaken(t *testing.T) {
	store := memory.New()
	l := &rails.Leases{State: store, Holder: "a", TTL: 30 * time.Millisecond}
	var cause error
	ran, err := l.Do(context.Background(), "slack-tick", "acme", func(ctx context.Context) {
		// Another runner force-takes the lease under us.
		_ = store.Delete(context.Background(), rails.Key("slack-tick", "acme"))
		if _, err := store.Create(context.Background(), rails.Key("slack-tick", "acme"), []byte("b"), time.Hour); err != nil {
			t.Error(err)
		}
		select {
		case <-ctx.Done():
			cause = context.Cause(ctx)
		case <-time.After(5 * time.Second):
		}
	})
	if err != nil || !ran {
		t.Fatalf("Do = %v, %v", ran, err)
	}
	if !errors.Is(cause, rails.ErrLost) {
		t.Fatalf("cause = %v, want ErrLost", cause)
	}
	if _, err := store.Get(context.Background(), rails.Key("slack-tick", "acme")); err != nil {
		t.Fatalf("the new holder's lease was deleted by the old holder's release: %v", err)
	}
}

func TestALeaseIsReleasedWhenTheTickReturns(t *testing.T) {
	a, b, _ := twoRunners(t)
	if _, err := a.Do(context.Background(), "slack-tick", "acme", func(context.Context) {}); err != nil {
		t.Fatal(err)
	}
	lease, err := b.Acquire(context.Background(), "slack-tick", "acme")
	if err != nil {
		t.Fatalf("a finished tick left its lease: %v", err)
	}
	_ = lease.Release(context.Background())
}
