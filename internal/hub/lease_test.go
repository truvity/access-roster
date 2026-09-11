package hub_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/internal/hub"
)

// shared is one snapshot store two hubs use, with the lease a real shared
// store carries. It is deliberately not the memory store: that one has no
// lease, which is exactly why it is for a single replica.
type shared struct {
	*hub.MemorySnapshots

	mu     sync.Mutex
	leases map[string]bool
	// failLock makes taking a lease fail rather than refuse, which is a
	// different case with a different right answer.
	failLock error
	// ttl is the last lease length asked for, which is the whole of what
	// keeps a scheduled tick from being refused by its predecessor.
	ttl time.Duration
}

func newShared() *shared {
	return &shared{MemorySnapshots: hub.NewMemorySnapshots(), leases: map[string]bool{}}
}

func (s *shared) Lock(_ context.Context, key string, ttl time.Duration) (func(context.Context), bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = ttl
	if s.failLock != nil {
		return nil, false, s.failLock
	}
	if s.leases[key] {
		return nil, false, nil
	}
	s.leases[key] = true
	return func(context.Context) {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.leases, key)
	}, true, nil
}

// Two replicas, one directory: the scheduled pass must read it once. A
// directory's API quota is per tenant, not per reader, and the snapshot
// they would each produce is the same one.
func TestOneReplicaReadsPerScheduledPass(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	directory := fake.New("C0north", "north.example").
		WithAccount("ada@north.example", "Ada", "North")
	snapshots := newShared()
	store := hub.NewMemoryStore()

	one := hub.New(store, snapshots, hub.Config{}, quiet)
	if _, err := one.Adopt(ctx, hub.Workspace{Admin: "admin@north.example"}, directory); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	one.Wait()
	two := hub.New(store, snapshots, hub.Config{}, quiet)
	if err := two.Attach(ctx, "C0north", directory); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// Adoption already took one snapshot; count from here.
	before := directory.Calls(fake.OpAccounts)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); one.RefreshAll(ctx) }()
	go func() { defer wg.Done(); two.RefreshAll(ctx) }()
	wg.Wait()

	if got := directory.Calls(fake.OpAccounts) - before; got != 1 {
		t.Errorf("the directory was read %d times in one pass, want 1", got)
	}

	// And the lease outlives the work: a replica whose own tick comes
	// four minutes later must not read the same directory again. It is
	// the interval that frees it, not the pass finishing.
	before = directory.Calls(fake.OpAccounts)
	one.RefreshAll(ctx)
	two.RefreshAll(ctx)
	if got := directory.Calls(fake.OpAccounts) - before; got != 0 {
		t.Errorf("a later pass in the same interval read the directory %d times, want 0", got)
	}
}

// A pass that failed must hand the lease back: somebody else should try,
// and holding it for the interval would turn one failed read into a whole
// interval of staleness.
func TestAFailedPassHandsTheLeaseBack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	directory := fake.New("C0north", "north.example").
		WithAccount("ada@north.example", "Ada", "North")
	snapshots := newShared()
	store := hub.NewMemoryStore()
	first := hub.New(store, snapshots, hub.Config{}, quiet)
	if _, err := first.Adopt(ctx, hub.Workspace{Admin: "admin@north.example"}, directory); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	first.Wait()
	second := hub.New(store, snapshots, hub.Config{}, quiet)
	if err := second.Attach(ctx, "C0north", directory); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	directory.Fail(fake.OpAccounts, io.ErrUnexpectedEOF)
	first.RefreshAll(ctx)
	directory.Heal(fake.OpAccounts)

	before := directory.Calls(fake.OpAccounts)
	second.RefreshAll(ctx)
	if got := directory.Calls(fake.OpAccounts) - before; got != 1 {
		t.Errorf("after a failed pass the next replica read %d times, want 1", got)
	}
}

// A lease that can be neither taken nor refused is a broken cache, not a
// signal to stop refreshing: a duplicate read costs quota, a skipped one
// costs freshness, and freshness is what authority is made of.
func TestARefusedLeaseStopsAPassButABrokenOneDoesNot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	directory := fake.New("C0north", "north.example").
		WithAccount("ada@north.example", "Ada", "North")
	snapshots := newShared()
	store := hub.NewMemoryStore()
	directoryHub := hub.New(store, snapshots, hub.Config{}, quiet)
	if _, err := directoryHub.Adopt(ctx, hub.Workspace{Admin: "admin@north.example"}, directory); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	directoryHub.Wait()

	// Somebody else holds it: this replica does nothing.
	release, taken, err := snapshots.Lock(ctx, "refresh:C0north", time.Minute)
	if err != nil || !taken {
		t.Fatalf("Lock: %v, %v", taken, err)
	}
	before := directory.Calls(fake.OpAccounts)
	directoryHub.RefreshAll(ctx)
	if got := directory.Calls(fake.OpAccounts) - before; got != 0 {
		t.Errorf("a replica read the directory while another held the lease (%d reads)", got)
	}
	release(ctx)

	// The cache is broken: refresh anyway.
	snapshots.failLock = io.ErrUnexpectedEOF
	before = directory.Calls(fake.OpAccounts)
	directoryHub.RefreshAll(ctx)
	if got := directory.Calls(fake.OpAccounts) - before; got != 1 {
		t.Errorf("a broken lease stopped the refresh (%d reads, want 1)", got)
	}
}

// The lease must be SHORTER than the interval that schedules it.
//
// Equal lengths beat against each other: a tick arriving a second before
// its predecessor's lease expired is refused, the next chance comes a
// whole interval later, and the effective period doubles. With a
// fifteen-minute interval that is thirty minutes — exactly the freshness
// window — so the snapshot ages out and every domain in it reads
// provisional on a service that is working. Seen on 2026-09-11: two
// directories stale at 32 minutes while a third, which happened to miss
// the collision, sat at 17.
func TestTheLeaseIsShorterThanTheIntervalThatSchedulesIt(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	interval := 15 * time.Minute

	directory := fake.New("C0north", "north.example").
		WithAccount("ada@north.example", "Ada", "North")
	snapshots := newShared()

	h := hub.New(hub.NewMemoryStore(), snapshots, hub.Config{RefreshInterval: interval}, quiet)
	if _, err := h.Adopt(ctx, hub.Workspace{Admin: "admin@north.example"}, directory); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	h.Wait()

	h.RefreshAll(ctx)

	store := snapshots

	if store.ttl == 0 {
		t.Fatal("no lease was taken at all")
	}

	if store.ttl >= interval {
		t.Errorf("lease %s >= interval %s: a tick on schedule will be refused by its own predecessor",
			store.ttl, interval)
	}

	// And long enough to still be doing its job: a replica whose turn
	// comes a few minutes later must be refused, or both read the same
	// directory and spend the tenant's quota twice.
	if store.ttl <= interval/2 {
		t.Errorf("lease %s is under half the interval %s: a replica ticking soon after would read again",
			store.ttl, interval)
	}
}
