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

// harness is one hub over two fake tenants, with a clock the test drives.
type harness struct {
	t     *testing.T
	hub   *hub.Hub
	store *hub.MemoryStore
	one   *fake.Backend
	two   *fake.Backend
	clock time.Time
}

const (
	oneID = "C0one"
	twoID = "C0two"
)

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t:     t,
		store: hub.NewMemoryStore(),
		clock: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC),
	}
	h.one = fake.New(oneID, "one.example").
		WithAccount("alice@one.example", "Alice", "Ant").
		WithAccount("bob@one.example", "Bob", "Bee").
		WithGroup("platform@one.example", "alice@one.example").
		WithGroup("all@one.example", "alice@one.example", "bob@one.example")
	h.two = fake.New(twoID, "two.example").
		WithAccount("carol@two.example", "Carol", "Cat").
		WithGroup("all@two.example", "carol@two.example")

	h.hub = hub.New(h.store, hub.NewMemorySnapshots(), hub.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.hub.SetClock(func() time.Time { return h.clock })

	ctx := context.Background()
	for _, ws := range []struct {
		id string
		b  *fake.Backend
	}{{oneID, h.one}, {twoID, h.two}} {
		if _, err := h.hub.Adopt(ctx, hub.Workspace{ID: ws.id, Admin: "admin@" + ws.id}, ws.b); err != nil {
			t.Fatalf("Adopt %s: %v", ws.id, err)
		}
	}
	return h
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

func (h *harness) resolve(email string, maxAge *time.Duration) hub.UserResult {
	h.t.Helper()
	got, err := h.hub.ResolveUser(context.Background(), email, maxAge)
	if err != nil {
		h.t.Fatalf("ResolveUser(%s): %v", email, err)
	}
	return got
}

func (h *harness) probe() {
	h.t.Helper()
	if _, err := h.hub.Probe(context.Background(), ""); err != nil {
		h.t.Fatalf("Probe: %v", err)
	}
}

func ptr(d time.Duration) *time.Duration { return &d }

func TestAdoptDiscoversDomainsAndServes(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	served, err := h.hub.Describe(context.Background())
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(served) != 2 {
		t.Fatalf("served = %+v, want two domains", served)
	}
	for _, d := range served {
		if !d.Authoritative {
			t.Errorf("domain %s is not authoritative right after Adopt", d.Name)
		}
	}
	if served[0].Name != "one.example" || served[0].Workspace != oneID {
		t.Errorf("first served domain = %+v", served[0])
	}
}

func TestOmittedMaxAgeServesTheSnapshot(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	before := h.one.Calls(fake.OpAccount)

	got := h.resolve("alice@one.example", nil)
	if !got.InDomain || !got.Found || got.Suspended || !got.Authoritative {
		t.Errorf("result = %+v, want a live authoritative account", got)
	}
	if !slices.Contains(got.Groups, "platform@one.example") {
		t.Errorf("groups = %v, want the platform group", got.Groups)
	}
	if h.one.Calls(fake.OpAccount) != before {
		t.Error("an omitted max_age went to the backend; it must serve the snapshot")
	}
}

func TestMaxAgeTakesTheCheapestPath(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	fullReads := h.one.Calls(fake.OpAccounts)
	h.advance(20 * time.Minute)

	got := h.resolve("alice@one.example", ptr(time.Minute))
	if !got.Authoritative || !got.Found {
		t.Errorf("result = %+v, want a fresh authoritative answer", got)
	}
	if h.one.Calls(fake.OpAccount) == 0 {
		t.Error("a short max_age did not read the account live")
	}
	if h.one.Calls(fake.OpAccounts) != fullReads {
		t.Error("a point lookup triggered a full directory read; it must not")
	}
	if !got.SnapshotAt.Equal(h.clock) {
		t.Errorf("snapshot_at = %v, want now (%v) after a live read", got.SnapshotAt, h.clock)
	}
}

func TestInDomainMissAlwaysChecksLiveOnce(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// An account created after the snapshot: absent from it, live in the
	// directory. Answering "not found" here would be a removal signal.
	h.one.WithAccount("dan@one.example", "Dan", "Doe")

	got := h.resolve("dan@one.example", nil)
	if !got.Found || !got.Authoritative {
		t.Errorf("result = %+v, want the new account found and authoritative", got)
	}
	if h.one.Calls(fake.OpAccount) == 0 {
		t.Error("a snapshot miss did not check the backend")
	}
}

func TestNotFoundIsAuthoritativeOnlyAfterTheBackendSaysSo(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	got := h.resolve("nobody@one.example", nil)
	if got.Found {
		t.Errorf("result = %+v, want not found", got)
	}
	if !got.InDomain || !got.Authoritative {
		t.Errorf("result = %+v, want an authoritative absence after the live check", got)
	}
}

func TestFailedLiveReadHoldsRatherThanRemoves(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.one.Fail(fake.OpAccount, nil)

	got := h.resolve("nobody@one.example", nil)
	if got.Authoritative {
		t.Errorf("result = %+v, want a non-authoritative answer when the live read fails", got)
	}
	if got.InDomain != true {
		t.Error("the address is still in a served domain")
	}
}

func TestFailedProbeCostsAuthority(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.one.Fail(fake.OpProbe, nil)
	h.probe()

	got := h.resolve("alice@one.example", nil)
	if !got.Found {
		t.Errorf("result = %+v, want the snapshot still served", got)
	}
	if got.Authoritative {
		t.Error("a failed probe must cost authority")
	}
	// The other workspace is unaffected.
	if other := h.resolve("carol@two.example", nil); !other.Authoritative {
		t.Error("a failure in one workspace must not touch another")
	}
}

func TestStaleSnapshotCostsAuthority(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.advance(hub.DefaultFreshnessWindow + time.Minute)

	got := h.resolve("alice@one.example", nil)
	if got.Authoritative {
		t.Errorf("result = %+v, want no authority past the freshness window", got)
	}
	if !got.Found {
		t.Error("a stale snapshot is still served")
	}
}

func TestSuspendedAccountIsAuthoritativelyGone(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.one.Suspend("alice@one.example")
	if _, err := h.hub.Refresh(context.Background(), oneID); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	got := h.resolve("alice@one.example", nil)
	if !got.Found || !got.Suspended || !got.Authoritative {
		t.Errorf("result = %+v, want found, suspended and authoritative", got)
	}
}

func TestOutOfDomainIsNoOpinion(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	got := h.resolve("stranger@elsewhere.example", nil)
	if got.InDomain || got.Found || got.Authoritative {
		t.Errorf("result = %+v, want no opinion at all", got)
	}
}

func TestDomainConflictIsAuthoritativeForNeither(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// A domain move in progress: the second tenant starts claiming the
	// first one's domain before the first drops it.
	h.two.SetDomains("two.example", "one.example")
	h.probe()

	got := h.resolve("alice@one.example", nil)
	if got.Authoritative {
		t.Error("a contested domain must be authoritative for neither")
	}

	served, err := h.hub.Describe(context.Background())
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	for _, d := range served {
		if d.Name == "one.example" && d.Authoritative {
			t.Errorf("Describe still calls %s authoritative", d.Name)
		}
	}

	// The move completes: the first tenant drops it, and the second serves
	// it authoritatively again — with no window in which it read as gone.
	h.one.SetDomains("one.example.new")
	h.probe()
	if _, err = h.hub.Refresh(context.Background(), twoID); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	authoritative, conflict := false, true
	views, err := h.hub.WorkspaceViews(context.Background())
	if err != nil {
		t.Fatalf("WorkspaceViews: %v", err)
	}
	for _, v := range views {
		for _, d := range v.Domains {
			if v.Workspace.ID == twoID && d.Name == "one.example" {
				authoritative, conflict = d.Authoritative, d.Conflict
			}
		}
	}
	if !authoritative || conflict {
		t.Errorf("after the move: authoritative=%v conflict=%v, want true/false", authoritative, conflict)
	}
}

func TestDeclaredWorkspaceWinsAConflict(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	ws, err := h.store.Get(ctx, oneID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	ws.Declared = true
	if err = h.store.Put(ctx, ws); err != nil {
		t.Fatalf("Put: %v", err)
	}
	h.two.SetDomains("two.example", "one.example")
	h.probe()

	if got := h.resolve("alice@one.example", nil); !got.Authoritative {
		t.Errorf("result = %+v, want the declared workspace to win the domain", got)
	}
}

func TestGroupsAndListing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	group, err := h.hub.Group(ctx, "Platform@one.example", nil)
	if err != nil {
		t.Fatalf("Group: %v", err)
	}
	if !group.Found || !group.Authoritative || len(group.Members) != 1 {
		t.Errorf("group = %+v", group)
	}

	all, served, err := h.hub.ListGroups(ctx, "", nil)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(all) != 3 || len(served) != 2 {
		t.Errorf("union = %d groups over %d domains, want 3 over 2", len(all), len(served))
	}

	one, _, err := h.hub.ListGroups(ctx, "One.Example", nil)
	if err != nil {
		t.Fatalf("ListGroups(one): %v", err)
	}
	if len(one) != 2 {
		t.Errorf("one.example has %d groups, want 2", len(one))
	}
	for _, g := range one {
		if g.Domain != "one.example" {
			t.Errorf("group %s tagged with domain %q", g.Email, g.Domain)
		}
	}
}

func TestFailedRefreshKeepsTheOldSnapshot(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()
	h.one.Fail(fake.OpGroups, nil)
	h.advance(time.Hour)

	if _, err := h.hub.Refresh(ctx, oneID); err == nil {
		t.Fatal("Refresh must report the failure")
	}
	group, err := h.hub.Group(ctx, "platform@one.example", ptr(time.Minute))
	if err != nil {
		t.Fatalf("Group: %v", err)
	}
	if !group.Found || len(group.Members) != 1 {
		t.Errorf("group = %+v, want the old snapshot still served", group)
	}
	if group.Authoritative {
		t.Error("a stale snapshot must not be authoritative")
	}
}

func TestDisconnect(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if err := h.hub.Disconnect(ctx, twoID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if !h.two.Revoked() {
		t.Error("Disconnect did not revoke the credential")
	}
	if got := h.resolve("carol@two.example", nil); got.InDomain {
		t.Errorf("result = %+v, want no opinion once the workspace is gone", got)
	}

	ws, err := h.store.Get(ctx, oneID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	ws.Declared = true
	if err = h.store.Put(ctx, ws); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err = h.hub.Disconnect(ctx, oneID); err == nil {
		t.Error("Disconnect must refuse a declared workspace")
	}
}

func TestInvalidAddress(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if _, err := h.hub.ResolveUser(context.Background(), "not-an-address", nil); err == nil {
		t.Error("want an error for an address with no domain")
	}
}

func TestDirectoryGroupResolvesMembersAndPeopleFilterByTenant(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	// A group with a member from the other tenant and a member nobody
	// reads: the first resolves to a name, the second is honestly unknown.
	h.one.WithGroup("mixed@one.example", "alice@one.example", "carol@two.example", "ghost@elsewhere.example")
	h.one.Suspend("alice@one.example")
	if _, err := h.hub.Refresh(ctx, oneID); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	group, err := h.hub.DirectoryGroup(ctx, "Mixed@one.example")
	if err != nil {
		t.Fatalf("DirectoryGroup: %v", err)
	}
	if !group.Found || group.Workspace != oneID || !group.Authoritative {
		t.Fatalf("group = %+v", group.GroupResult)
	}
	want := map[string]hub.GroupMember{
		"alice@one.example":       {Email: "alice@one.example", GivenName: "Alice", FamilyName: "Ant", Known: true, Live: false},
		"carol@two.example":       {Email: "carol@two.example", GivenName: "Carol", FamilyName: "Cat", Known: true, Live: true},
		"ghost@elsewhere.example": {Email: "ghost@elsewhere.example"},
	}
	if len(group.Members) != len(want) {
		t.Fatalf("members = %+v", group.Members)
	}
	for _, m := range group.Members {
		if m != want[m.Email] {
			t.Errorf("member %s = %+v, want %+v", m.Email, m, want[m.Email])
		}
	}

	missing, err := h.hub.DirectoryGroup(ctx, "nobody@one.example")
	if err != nil || missing.Found || len(missing.Members) != 0 {
		t.Errorf("missing group = %+v, %v", missing, err)
	}

	two, total, err := h.hub.People(ctx, hub.PeopleQuery{Workspace: twoID}, 0)
	if err != nil || total != 1 || len(two) != 1 || two[0].Email != "carol@two.example" {
		t.Errorf("People(two) = %+v, %v, %v", two, total, err)
	}
	one, total, err := h.hub.People(ctx, hub.PeopleQuery{}, 1)
	if err != nil || total != 3 || len(one) != 1 {
		t.Errorf("People(limit 1) = %d shown of %d, %v", len(one), total, err)
	}
	if who := h.resolve("alice@one.example", nil); who.Workspace != oneID {
		t.Errorf("ResolveUser workspace = %q, want %q", who.Workspace, oneID)
	}
	none, _, err := h.hub.People(ctx, hub.PeopleQuery{Text: "carol", Workspace: oneID}, 0)
	if err != nil || len(none) != 0 {
		t.Errorf("People(carol in one) = %+v, %v", none, err)
	}
	suspended := false
	gone, _, err := h.hub.People(ctx, hub.PeopleQuery{Live: &suspended}, 0)
	if err != nil || len(gone) != 1 || gone[0].Email != "alice@one.example" {
		t.Errorf("People(suspended) = %+v, %v", gone, err)
	}
}

func TestAdoptDiscoversAndChecksTheTenantID(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	// A declaration that names no id gets the one the credential opens,
	// so nothing has to be copied out of a cloud console by hand.
	three := fake.New("C0three", "three.example").WithAccount("dana@three.example", "Dana", "Dee")
	adopted, err := h.hub.Adopt(ctx, hub.Workspace{Admin: "admin@three.example", Declared: true}, three)
	if err != nil {
		t.Fatalf("adopt without an id: %v", err)
	}
	if adopted.ID != "C0three" {
		t.Errorf("id = %q, want the tenant's own", adopted.ID)
	}

	// A declaration that names the right one is unchanged.
	four := fake.New("C0four", "four.example")
	if _, err := h.hub.Adopt(ctx, hub.Workspace{ID: "C0four", Admin: "admin@four.example"}, four); err != nil {
		t.Fatalf("adopt with the right id: %v", err)
	}

	// A declaration that names the wrong one is refused rather than
	// silently reading a different company's directory.
	five := fake.New("C0five", "five.example")
	_, err = h.hub.Adopt(ctx, hub.Workspace{ID: "C0typo", Admin: "admin@five.example"}, five)
	if !errors.Is(err, hub.ErrTenantMismatch) {
		t.Errorf("adopt with a mismatched id = %v, want a refusal", err)
	}
	views, err := h.hub.WorkspaceViews(ctx)
	if err != nil {
		t.Fatalf("WorkspaceViews: %v", err)
	}
	for i := range views {
		if views[i].Workspace.ID == "C0typo" {
			t.Errorf("the refused workspace was stored anyway")
		}
	}
}

func TestParseOverlay(t *testing.T) {
	t.Parallel()

	overlay, err := hub.ParseOverlay([]byte(`
workspaces:
  - backend: google
    admin: integrations@example.com
    keyFile: /keys/example/key.json
  - id: C0known
    backend: google
    admin: integrations@other.example
    keyFile: /keys/other/key.json
    serve:
      - one.example
      - two.example
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(overlay.Workspaces) != 2 {
		t.Fatalf("workspaces = %+v", overlay.Workspaces)
	}
	if overlay.Workspaces[0].ID != "" || overlay.Workspaces[1].ID != "C0known" {
		t.Errorf("ids = %q, %q", overlay.Workspaces[0].ID, overlay.Workspaces[1].ID)
	}
	// serve is optional: omitted means every domain the tenant owns.
	if len(overlay.Workspaces[0].Serve) != 0 {
		t.Errorf("serve = %v, want empty when it is not declared", overlay.Workspaces[0].Serve)
	}
	if got := overlay.Workspaces[1].Serve; len(got) != 2 || got[0] != "one.example" {
		t.Errorf("serve = %v", got)
	}

	// A field nobody reads is a rollout that silently declares nothing.
	if _, err := hub.ParseOverlay([]byte("workspaces:\n  - backend: google\n    adminEmail: x@y.z\n    keyFile: /k\n")); err == nil {
		t.Errorf("an unknown key was accepted")
	}
	// The three that cannot be discovered are required.
	for _, missing := range []string{
		"workspaces:\n  - admin: a@b.c\n    keyFile: /k\n",
		"workspaces:\n  - backend: google\n    keyFile: /k\n",
		"workspaces:\n  - backend: google\n    admin: a@b.c\n",
	} {
		if _, err := hub.ParseOverlay([]byte(missing)); err == nil {
			t.Errorf("accepted an incomplete declaration: %q", missing)
		}
	}
	// No file at all is the ordinary standalone case.
	if o, err := hub.LoadOverlay("/nonexistent/overlay.yaml"); err != nil || len(o.Workspaces) != 0 {
		t.Errorf("a missing overlay = %+v, %v", o, err)
	}
}
