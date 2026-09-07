package hub_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/internal/hub"
)

// served is a hub over one tenant that owns two domains and serves one of
// them: the shape of a Workspace an installation shares with a company it
// only partly deals with.
type servedHarness struct {
	t     *testing.T
	hub   *hub.Hub
	store *hub.MemoryStore
	both  *fake.Backend
	clock time.Time
}

const bothID = "C0both"

// newServedHarness builds a tenant owning kept.example and other.example,
// with people and groups on each side and one group that spans them.
func newServedHarness(t *testing.T, serve ...string) *servedHarness {
	t.Helper()
	h := &servedHarness{
		t:     t,
		store: hub.NewMemoryStore(),
		clock: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
	}
	h.both = fake.New(bothID, "kept.example", "other.example").
		WithAccount("ada@kept.example", "Ada", "Kept").
		WithAccount("otto@other.example", "Otto", "Other").
		WithGroup("team@kept.example", "ada@kept.example").
		WithGroup("shared@other.example", "ada@kept.example", "otto@other.example").
		WithGroup("theirs@other.example", "otto@other.example")

	h.hub = hub.New(h.store, hub.NewMemorySnapshots(), hub.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.hub.SetClock(func() time.Time { return h.clock })

	if _, err := h.hub.Adopt(context.Background(), hub.Workspace{
		ID: bothID, Admin: "admin@kept.example", Serve: serve,
	}, h.both); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	return h
}

func (h *servedHarness) views() []hub.WorkspaceView {
	h.t.Helper()
	views, err := h.hub.WorkspaceViews(context.Background())
	if err != nil {
		h.t.Fatalf("WorkspaceViews: %v", err)
	}
	return views
}

func (h *servedHarness) standing(workspace, domain string) hub.DomainStanding {
	h.t.Helper()
	views := h.views()
	for i := range views {
		v := &views[i]
		if v.Workspace.ID != workspace {
			continue
		}
		for _, d := range v.Domains {
			if d.Name == domain {
				return d
			}
		}
	}
	h.t.Fatalf("no standing for %s in %s", domain, workspace)
	return hub.DomainStanding{}
}

// Narrowing changes what the hub answers, not what it discovered. The
// operator still sees the whole tenant, which is the only way to tell the
// difference between a domain left out on purpose and one that is missing.
func TestServeNarrowsRoutingAndLeavesDiscoveryAlone(t *testing.T) {
	t.Parallel()
	h := newServedHarness(t, "kept.example")
	ctx := context.Background()

	served, err := h.hub.Describe(ctx)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(served) != 1 || served[0].Name != "kept.example" {
		t.Fatalf("Describe = %+v, want only kept.example", served)
	}

	if got := h.standing(bothID, "kept.example"); !got.Served || !got.Owned || !got.Authoritative {
		t.Errorf("kept.example standing = %+v, want served, owned and authoritative", got)
	}
	if got := h.standing(bothID, "other.example"); got.Served || !got.Owned || got.Authoritative {
		t.Errorf("other.example standing = %+v, want owned but not served", got)
	}

	// An address in the unserved domain is nobody's business: not found,
	// not in domain, no opinion — exactly as if the tenant were unknown.
	if got, err := h.hub.ResolveUser(ctx, "otto@other.example", nil); err != nil {
		t.Fatalf("ResolveUser: %v", err)
	} else if got.InDomain || got.Found || got.Authoritative {
		t.Errorf("otto = %+v, want no opinion at all", got)
	}
	if got, err := h.hub.ResolveUser(ctx, "ada@kept.example", nil); err != nil {
		t.Fatalf("ResolveUser: %v", err)
	} else if !got.Found || !got.Authoritative {
		t.Errorf("ada = %+v, want a live authoritative answer", got)
	}
}

// The narrowing reaches the snapshot, which is the point: an unserved
// domain's people are not cached at all. What is kept is what a served
// answer needs — including a group at the other domain that a served
// person belongs to, because dropping it would quietly shrink that
// person's access.
func TestServeKeepsOnlyWhatAServedAnswerNeeds(t *testing.T) {
	t.Parallel()
	h := newServedHarness(t, "kept.example")
	ctx := context.Background()

	people, total, err := h.hub.People(ctx, hub.PeopleQuery{}, 100)
	if err != nil {
		t.Fatalf("People: %v", err)
	}
	if total != 1 || people[0].Email != "ada@kept.example" {
		t.Errorf("people = %+v (total %d), want only the served domain's account", people, total)
	}

	got, err := h.hub.ResolveUser(ctx, "ada@kept.example", nil)
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if !slices.Contains(got.Groups, "shared@other.example") {
		t.Errorf("groups = %v, want the cross-domain group a served person is in", got.Groups)
	}
	if !slices.Contains(got.Groups, "team@kept.example") {
		t.Errorf("groups = %v, want the served domain's own group", got.Groups)
	}

	// A group of the unserved domain that no served person is in has no
	// reader here, so it is not kept.
	group, err := h.hub.Group(ctx, "theirs@other.example", nil)
	if err != nil {
		t.Fatalf("Group: %v", err)
	}
	if group.Found {
		t.Errorf("theirs@other.example = %+v, want it absent from the snapshot", group)
	}

	// Listing the groups of the tenant returns the served domain's, and
	// asking for the unserved domain's returns nothing at all.
	groups, domains, err := h.hub.ListGroups(ctx, "", nil)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(domains) != 1 || domains[0].Name != "kept.example" {
		t.Errorf("served domains = %+v, want only kept.example", domains)
	}
	for _, g := range groups {
		if g.Domain != "kept.example" {
			t.Errorf("ListGroups returned %s, from an unserved domain", g.Email)
		}
	}
	// The kept cross-domain group keeps every member: a group answered
	// short would be a partial list presented as a whole.
	h.both.SetDomains("kept.example", "other.example")
	if _, err = h.hub.SetServed(ctx, bothID, nil); err != nil {
		t.Fatalf("SetServed: %v", err)
	}
	shared, err := h.hub.Group(ctx, "shared@other.example", nil)
	if err != nil {
		t.Fatalf("Group: %v", err)
	}
	if len(shared.Members) != 2 {
		t.Errorf("shared members = %v, want both", shared.Members)
	}
}

// Owning a domain is not claiming it. Only two workspaces that both serve
// one domain contest it — otherwise an installation could not park a
// tenant that happens to hold a domain another tenant answers for.
func TestOnlyTwoServingWorkspacesContestADomain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := hub.NewMemoryStore()
	clock := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	directory := hub.New(store, hub.NewMemorySnapshots(), hub.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	directory.SetClock(func() time.Time { return clock })

	holder := fake.New("C0holder", "shared.example", "holder.example").
		WithAccount("held@shared.example", "Held", "Account")
	server := fake.New("C0server", "shared.example").
		WithAccount("live@shared.example", "Live", "Account")

	// The holder owns shared.example but serves only its own domain.
	if _, err := directory.Adopt(ctx, hub.Workspace{
		ID: "C0holder", Admin: "a@holder.example", Serve: []string{"holder.example"},
	}, holder); err != nil {
		t.Fatalf("Adopt holder: %v", err)
	}
	if _, err := directory.Adopt(ctx, hub.Workspace{ID: "C0server", Admin: "a@shared.example"}, server); err != nil {
		t.Fatalf("Adopt server: %v", err)
	}

	got, err := directory.ResolveUser(ctx, "live@shared.example", nil)
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if !got.Authoritative || got.Workspace != "C0server" {
		t.Errorf("result = %+v, want the serving workspace to answer authoritatively", got)
	}

	// Widen the holder to shared.example and it becomes a real conflict.
	if _, err = directory.SetServed(ctx, "C0holder", []string{"holder.example", "shared.example"}); err != nil {
		t.Fatalf("SetServed: %v", err)
	}
	if got, err = directory.ResolveUser(ctx, "live@shared.example", nil); err != nil {
		t.Fatalf("ResolveUser: %v", err)
	} else if got.Authoritative {
		t.Errorf("result = %+v, want a contested domain to be authoritative for neither", got)
	}
}

// The migration this was built for: a domain leaves one tenant for
// another. The hub follows discovery, so the hand-over needs no edit and
// has no window in which both claim it — and the stale entry is shown as
// something to tidy rather than silently ignored.
func TestAServedDomainTheTenantLosesIsHandedOverAndFlagged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := hub.NewMemoryStore()
	clock := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	directory := hub.New(store, hub.NewMemorySnapshots(), hub.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	directory.SetClock(func() time.Time { return clock })

	// Today: the old tenant owns both domains and is narrowed to the one
	// that will move. The new tenant does not have it yet.
	old := fake.New("C0old", "moving.example", "staying.example").
		WithAccount("pat@moving.example", "Pat", "Mover")
	fresh := fake.New("C0new", "new.example")
	if _, err := directory.Adopt(ctx, hub.Workspace{
		ID: "C0old", Admin: "a@staying.example", Serve: []string{"moving.example"},
	}, old); err != nil {
		t.Fatalf("Adopt old: %v", err)
	}
	if _, err := directory.Adopt(ctx, hub.Workspace{ID: "C0new", Admin: "a@new.example"}, fresh); err != nil {
		t.Fatalf("Adopt new: %v", err)
	}
	if got, err := directory.ResolveUser(ctx, "pat@moving.example", nil); err != nil {
		t.Fatalf("ResolveUser: %v", err)
	} else if got.Workspace != "C0old" || !got.Authoritative {
		t.Errorf("before the move: %+v, want the old tenant answering", got)
	}

	// The move: the domain and its people appear in the new tenant and
	// leave the old one.
	old.SetDomains("staying.example")
	fresh.SetDomains("new.example", "moving.example")
	fresh.WithAccount("pat@moving.example", "Pat", "Mover")
	if _, err := directory.Probe(ctx, ""); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if _, err := directory.Refresh(ctx, "C0new"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	got, err := directory.ResolveUser(ctx, "pat@moving.example", nil)
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if got.Workspace != "C0new" || !got.Found || !got.Authoritative {
		t.Errorf("after the move: %+v, want the new tenant answering authoritatively", got)
	}

	// The old workspace still names the domain in its served list. It
	// routes nothing, and it is reported as no longer owned.
	views, err := directory.WorkspaceViews(ctx)
	if err != nil {
		t.Fatalf("WorkspaceViews: %v", err)
	}
	var found bool
	for _, v := range views {
		if v.Workspace.ID != "C0old" {
			continue
		}
		for _, d := range v.Domains {
			if d.Name != "moving.example" {
				continue
			}
			found = true
			if d.Owned || d.Served || d.Conflict {
				t.Errorf("stale entry = %+v, want unowned, unserved and uncontested", d)
			}
		}
	}
	if !found {
		t.Error("the stale served entry vanished from the console's view instead of being flagged")
	}
}

// A domain may only be served if the directory says the tenant owns it,
// and a declared workspace's list belongs to the deployment.
func TestSetServedIsBoundedByDiscoveryAndByTheDeployment(t *testing.T) {
	t.Parallel()
	h := newServedHarness(t)
	ctx := context.Background()

	if _, err := h.hub.SetServed(ctx, bothID, []string{"someone.else.example"}); !errors.Is(err, hub.ErrUnknownDomain) {
		t.Errorf("SetServed with a foreign domain = %v, want ErrUnknownDomain", err)
	}
	if _, err := h.hub.SetServed(ctx, bothID, []string{"KEPT.example ", "kept.example"}); err != nil {
		t.Fatalf("SetServed: %v", err)
	}
	if got := h.standing(bothID, "other.example"); got.Served {
		t.Errorf("other.example = %+v, want it no longer served", got)
	}

	ws, err := h.store.Get(ctx, bothID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	ws.Declared = true
	if err = h.store.Put(ctx, ws); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err = h.hub.SetServed(ctx, bothID, nil); !errors.Is(err, hub.ErrDeclared) {
		t.Errorf("SetServed on a declared workspace = %v, want ErrDeclared", err)
	}
}
