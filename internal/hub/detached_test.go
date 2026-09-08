package hub_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/internal/hub"
)

// slowBackend is a fake that will not finish a full read until it is let
// go. It is how a test says "the directory is slower than this request's
// deadline" without sleeping.
type slowBackend struct {
	*fake.Backend
	gate chan struct{}
}

func newSlowBackend(inner *fake.Backend) *slowBackend {
	return &slowBackend{Backend: inner, gate: make(chan struct{})}
}

func (s *slowBackend) release() { close(s.gate) }

func (s *slowBackend) Accounts(ctx context.Context) ([]backend.Account, error) {
	select {
	case <-s.gate:
		return s.Backend.Accounts(ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newDetachedHub(t *testing.T) (*hub.Hub, *hub.MemoryStore) {
	t.Helper()
	store := hub.NewMemoryStore()
	return hub.New(store, hub.NewMemorySnapshots(), hub.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil))), store
}

// Adopting a workspace must not wait on the directory.
//
// The first snapshot is a full read of a whole tenant, and the caller is a
// browser finishing a consent behind a gateway with a route timeout. Live,
// that timeout cancelled the read at fifteen seconds and answered 502 for
// a workspace that had already been stored — a failure reported for work
// that succeeded, with the next attempt starting again from nothing.
func TestAdoptDoesNotWaitOnTheDirectory(t *testing.T) {
	t.Parallel()
	directory, store := newDetachedHub(t)
	slow := newSlowBackend(fake.New("C0slow", "slow.example").
		WithAccount("ada@slow.example", "Ada", "Slow"))

	// A context that is already finished with: the request it belonged to
	// has gone, exactly as a cancelled one has.
	ctx, cancel := context.WithCancel(context.Background())
	adopted, err := directory.Adopt(ctx, hub.Workspace{Admin: "admin@slow.example"}, slow)
	cancel()
	if err != nil {
		t.Fatalf("Adopt: %v", err)
	}

	// The record is complete before any snapshot exists: the tenant read
	// that found the id also returned the domains and proved the
	// credential, so an operator has something to act on immediately.
	if adopted.ID != "C0slow" {
		t.Errorf("adopted.ID = %q, want C0slow", adopted.ID)
	}
	if len(adopted.Domains) != 1 || adopted.Domains[0] != "slow.example" {
		t.Errorf("adopted.Domains = %v, want the discovered domain", adopted.Domains)
	}
	if !adopted.Health.OK {
		t.Errorf("adopted.Health = %+v, want the tenant read to count as the first probe", adopted.Health)
	}

	// Nothing has been read yet, and the domain is provisional for the
	// honest reason rather than because anything failed.
	views, err := directory.WorkspaceViews(context.Background())
	if err != nil {
		t.Fatalf("WorkspaceViews: %v", err)
	}
	if len(views) != 1 || len(views[0].Domains) != 1 {
		t.Fatalf("views = %+v, want one workspace with one domain", views)
	}
	if views[0].Domains[0].Authoritative {
		t.Error("a domain was authoritative before its first snapshot")
	}

	// The read finishes on its own context, after the request's is gone.
	slow.release()
	directory.Wait()
	if snap, err := directory.Group(context.Background(), "irrelevant@slow.example", nil); err != nil {
		t.Fatalf("Group: %v", err)
	} else if snap.SnapshotAt.IsZero() {
		t.Error("the first snapshot never landed after the directory answered")
	}
	if _, err := store.Get(context.Background(), "C0slow"); err != nil {
		t.Fatalf("the workspace did not survive: %v", err)
	}
}

// A read that did not ask for freshness never reaches the directory, even
// when there is no snapshot at all. "There is no snapshot yet" is an
// answer — provisional and empty — and holding the request open for a
// full tenant read is what turned a console list into a gateway timeout.
func TestAReadWithNoSnapshotAnswersRatherThanFetching(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	directory, _ := newDetachedHub(t)
	slow := newSlowBackend(fake.New("C0slow", "slow.example").
		WithGroup("team@slow.example", "ada@slow.example"))
	if _, err := directory.Adopt(ctx, hub.Workspace{Admin: "admin@slow.example"}, slow); err != nil {
		t.Fatalf("Adopt: %v", err)
	}

	// The first snapshot is still blocked on the directory. A listing must
	// come back now, empty, rather than joining the queue.
	done := make(chan struct{})
	go func() {
		defer close(done)
		groups, served, err := directory.ListGroups(ctx, "", nil)
		if err != nil {
			t.Errorf("ListGroups: %v", err)
		}
		if len(groups) != 0 {
			t.Errorf("groups = %v, want none before the first snapshot", groups)
		}
		if len(served) != 1 || served[0].Authoritative {
			t.Errorf("served = %+v, want the domain listed and not authoritative", served)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a listing with no snapshot waited on the directory")
	}

	slow.release()
	directory.Wait()
}

// Narrowing takes effect at once, from what is already in memory.
//
// Waiting for a fresh read would leave the excluded people cached for as
// long as the directory takes, and a read that failed would leave them
// cached until the next pass — which is what happened live, where the
// refresh landed on a replica that did not know the workspace and the
// snapshot was dropped entirely.
func TestNarrowingExcludesAtOnceAndRereadsLater(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	directory, _ := newDetachedHub(t)
	both := fake.New("C0both", "kept.example", "dropped.example").
		WithAccount("ada@kept.example", "Ada", "Kept").
		WithAccount("otto@dropped.example", "Otto", "Dropped").
		WithGroup("theirs@dropped.example", "otto@dropped.example")
	if _, err := directory.Adopt(ctx, hub.Workspace{Admin: "admin@kept.example"}, both); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	directory.Wait()
	if people, _, err := directory.People(ctx, hub.PeopleQuery{}, 0); err != nil {
		t.Fatalf("People: %v", err)
	} else if len(people) != 2 {
		t.Fatalf("people = %d, want both before narrowing", len(people))
	}

	// From here the directory answers nothing at all: the exclusion must
	// not depend on a read succeeding.
	both.Fail(fake.OpAccounts, errors.New("the directory is unreachable"))
	if _, err := directory.SetServed(ctx, "C0both", []string{"kept.example"}); err != nil {
		t.Fatalf("SetServed: %v", err)
	}

	people, _, err := directory.People(ctx, hub.PeopleQuery{}, 0)
	if err != nil {
		t.Fatalf("People: %v", err)
	}
	if len(people) != 1 || people[0].Email != "ada@kept.example" {
		t.Errorf("people = %+v, want only the served domain's account, immediately", people)
	}
	// And the group that lived entirely at the excluded domain is gone
	// with it, rather than surviving as a group nothing routes to.
	if got, err := directory.Group(ctx, "theirs@dropped.example", nil); err != nil {
		t.Fatalf("Group: %v", err)
	} else if got.Found {
		t.Error("a group at an excluded domain is still answerable")
	}
	directory.Wait()
}
