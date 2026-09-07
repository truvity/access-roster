package valkey_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/valkey"
)

func newStore(t *testing.T) (*valkey.Snapshots, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return valkey.NewSnapshots(client, "test", time.Hour), server
}

func sample(taken time.Time) *hub.Snapshot {
	return hub.NewSnapshot("C0north", taken,
		[]backend.Account{
			{Email: "ada@north.example", Live: true, GivenName: "Ada", FamilyName: "North"},
			{Email: "cleo@north.example", Live: false, GivenName: "Cleo", FamilyName: "Chase"},
		},
		[]backend.Group{
			{Email: "engineering@north.example", Members: []string{"ada@north.example"}},
			{Email: "everyone@north.example", Members: []string{"ada@north.example", "cleo@north.example"}},
		})
}

// Everything a snapshot answers must come back: liveness decides whether
// a consumer removes access, and the reverse index is what a login reads.
func TestASnapshotComesBackWhole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := newStore(t)

	taken := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if err := store.Put(ctx, sample(taken)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(ctx, "C0north")
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %v", got, err)
	}
	if got.Workspace != "C0north" || !got.TakenAt.Equal(taken) {
		t.Errorf("snapshot = %s at %s", got.Workspace, got.TakenAt)
	}
	if len(got.Accounts) != 2 || !got.Accounts["ada@north.example"].Live {
		t.Errorf("accounts = %+v", got.Accounts)
	}
	// A leaver read back as live would keep access for someone who has
	// gone: the one field worth naming in an assertion.
	if got.Accounts["cleo@north.example"].Live {
		t.Error("a suspended account came back live")
	}
	if names := got.Accounts["ada@north.example"]; names.GivenName != "Ada" || names.FamilyName != "North" {
		t.Errorf("names = %+v", names)
	}
	if members := got.Groups["everyone@north.example"].Members; len(members) != 2 {
		t.Errorf("members = %v", members)
	}
	// The index is rebuilt on read rather than stored, so this is the
	// assertion that it is rebuilt at all.
	if groups := got.GroupsOf("ada@north.example"); !slices.Equal(groups,
		[]string{"engineering@north.example", "everyone@north.example"}) {
		t.Errorf("GroupsOf = %v", groups)
	}
}

// An empty cache is a hub with no snapshots, which answers "not
// authoritative" until the next refresh — never an error, and never an
// absence a consumer could act on.
func TestAMissingSnapshotIsNotAnError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := newStore(t)

	got, err := store.Get(ctx, "C0nothing")
	if err != nil || got != nil {
		t.Errorf("Get of an unknown workspace = %v, %v; want nil and no error", got, err)
	}

	if err = store.Put(ctx, sample(time.Now())); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err = store.Delete(ctx, "C0north"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, err = store.Get(ctx, "C0north"); err != nil || got != nil {
		t.Errorf("Get after Delete = %v, %v", got, err)
	}
	// Deleting what is already gone is the state being asked for.
	if err = store.Delete(ctx, "C0north"); err != nil {
		t.Errorf("second Delete: %v", err)
	}
}

// A workspace disconnected while a replica was down must not leave a copy
// of a company's directory in a cache for ever.
func TestASnapshotExpires(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, server := newStore(t)

	if err := store.Put(ctx, sample(time.Now())); err != nil {
		t.Fatalf("Put: %v", err)
	}
	server.FastForward(2 * time.Hour)
	got, err := store.Get(ctx, "C0north")
	if err != nil || got != nil {
		t.Errorf("after the TTL = %v, %v; want it gone", got, err)
	}
}

// One replica does the reading. Google's quota is per tenant, not per
// reader, so a second replica refreshing the same directory at the same
// moment buys nothing and costs somebody's quota.
func TestOnlyOneReplicaTakesTheRefreshLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, server := newStore(t)

	release, acquired, err := store.Lock(ctx, "refresh:C0north", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("the first lease was not taken: %v, %v", acquired, err)
	}
	if _, second, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || second {
		t.Errorf("a second replica took the same lease: %v, %v", second, err)
	}
	// A different workspace is a different lease.
	if _, other, err := store.Lock(ctx, "refresh:C0south", time.Minute); err != nil || !other {
		t.Errorf("an unrelated workspace was blocked: %v, %v", other, err)
	}

	release(ctx)
	if _, again, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || !again {
		t.Errorf("the lease was not released: %v, %v", again, err)
	}

	// A replica killed mid-refresh must not stop every other replica from
	// refreshing that workspace ever again.
	server.FastForward(2 * time.Minute)
	if _, expired, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || !expired {
		t.Errorf("the lease outlived its ttl: %v, %v", expired, err)
	}
}

// Releasing a lease that has already expired must not delete the lease of
// whoever took it next.
func TestAnExpiredLeaseReleasesNobodyElsesLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, server := newStore(t)

	stale, acquired, err := store.Lock(ctx, "refresh:C0north", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("Lock: %v, %v", acquired, err)
	}
	server.FastForward(2 * time.Minute)

	if _, taken, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || !taken {
		t.Fatalf("the second replica could not take the expired lease: %v, %v", taken, err)
	}
	stale(ctx) // the first replica finishes late and lets go

	if _, third, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || third {
		t.Errorf("a late release freed somebody else's lease: %v, %v", third, err)
	}
}
