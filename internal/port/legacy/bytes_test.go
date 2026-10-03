package legacy_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/legacy"
	"github.com/truvity/access-roster/internal/valkey"
)

// The adapter's whole claim is that it reaches the objects the domain stores
// write, byte for byte. These tests read each one through the other.

// A record written through the port is the one the console's store lists, and
// the other way round: the same ConfigMap entry.
func TestAnOrganisationRecordIsTheSameEntryThroughThePortAndTheDomainStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	orgs := kube.NewGitHubOrgs(f.client)

	at := time.Date(2026, 9, 12, 23, 0, 0, 0, time.UTC)
	record := connection.Record{Org: "acme", AppID: 42, AppSlug: "acme-access-roster", ConnectedAt: at}
	if err := orgs.Put(ctx, record, connection.Credential{Org: "acme", AppID: 42, PrivateKey: "k"}); err != nil {
		t.Fatal(err)
	}
	got, err := f.ports.State.Get(ctx, "gh.org.acme")
	if err != nil {
		t.Fatalf("Get through the port: %v", err)
	}
	want, _ := connection.EncodeRecord(record)
	if string(got.Value) != want {
		t.Fatalf("the port read %q, the domain store wrote %q", got.Value, want)
	}

	// And a write through the port is read back by the domain store.
	record.AppSlug = "renamed"
	raw, _ := connection.EncodeRecord(record)
	if _, err = f.ports.State.Update(ctx, "gh.org.acme", []byte(raw), 0, got.Revision); err != nil {
		t.Fatalf("Update through the port: %v", err)
	}
	records, err := orgs.List(ctx)
	if err != nil || len(records) != 1 || records[0].AppSlug != "renamed" {
		t.Fatalf("the domain store reads %+v, %v", records, err)
	}
	cm, _ := f.client.API().CoreV1().ConfigMaps("ns").Get(ctx, orgs.ConfigMapName(), metav1.GetOptions{})
	if cm.Data["acme.json"] != raw || len(cm.Data) != 1 {
		t.Fatalf("the ConfigMap holds %v: the port wrote something other than the record's entry", cm.Data)
	}
	if cm.Labels["access-roster.truvity.github.io/kind"] != "github-orgs" {
		t.Errorf("labels = %v", cm.Labels)
	}
}

// Several writers racing one entry, on a ConfigMap whose version the API
// server enforces: exactly one wins.
func TestRacingUpdatesOfAnOrganisationRecordHaveOneWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	rev, err := f.ports.State.Put(ctx, "gh.org.acme", []byte(`{"v":0}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	var wins, conflicts int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.ports.State.Update(ctx, "gh.org.acme", []byte(`{"v":`+strconv.Itoa(i+1)+`}`), 0, rev)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, port.ErrConflict):
				conflicts++
			default:
				t.Errorf("Update: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || conflicts != 11 {
		t.Fatalf("%d won and %d conflicted, want 1 and 11", wins, conflicts)
	}
}

func TestAnOrganisationKeyThatIsNotALoginIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if _, err := f.ports.State.Put(context.Background(), "gh.org.not a login", []byte("x"), 0); !errors.Is(err, port.ErrUnsupported) {
		t.Fatalf("Put = %v, want ErrUnsupported", err)
	}
}

// The layout's keys that have no object today are refused by name, never
// written somewhere else.
func TestAKeyWithNoObjectOfItsOwnIsUnsupported(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, key := range []string{"ses.ada.s1", "sid.s1", "ws.T1", "gh.link.ada", "app.x", "gate.t.n", "share.h.c", "notify.t", "plain"} {
		if _, err := f.ports.State.Put(context.Background(), key, []byte("x"), time.Minute); !errors.Is(err, port.ErrUnsupported) {
			t.Errorf("Put %s = %v, want ErrUnsupported", key, err)
		}
	}
	if keys := f.redis.Keys(); len(keys) != 0 {
		t.Fatalf("a refused key wrote %v", keys)
	}
}

// The issuer's keys: a port key of the layout is the Valkey key the issuer
// writes today, and a colon key is itself.
func TestTheLayoutsKeysAreTheKeysTheIssuerWritesToday(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	for key, valkeyKey := range map[string]string{
		"req.r1":             "t:issuer:request:r1",
		"code.c1":            "t:issuer:code:c1",
		"codesess.r1":        "t:issuer:code-session:r1",
		"tok.j1":             "t:issuer:token:j1",
		"sso.s1":             "t:issuer:sso:s1",
		"rt.abc":             "t:issuer:session-token:abc",
		"rtrot.abc":          "t:issuer:session-rotated:abc",
		"keyring.ES384:k1":   "t:issuer:keyring:entry:ES384:k1",
		"lease.plain":        "t:lease:plain",
		"lease.refresh:C0n":  "t:{C0n}:lease:refresh",
		"issuer:session:abc": "t:issuer:session:abc",
	} {
		if _, err := f.ports.State.Put(ctx, key, []byte("value-"+key), time.Hour); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
		got, err := f.redis.Get(valkeyKey)
		if err != nil || got != "value-"+key {
			t.Errorf("%s: Valkey %s holds %q, %v", key, valkeyKey, got, err)
		}
		if ttl := f.redis.TTL(valkeyKey); ttl != time.Hour {
			t.Errorf("%s: lifetime %v, want the hour it was given", key, ttl)
		}
	}
	// Written by the issuer's own state, read through the port.
	if err := f.state.Set(ctx, "issuer:token:j2", []byte("minted"), time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := f.ports.State.Get(ctx, "tok.j2")
	if err != nil || string(got.Value) != "minted" || string(got.Revision) != valkey.Revision([]byte("minted")) {
		t.Fatalf("tok.j2 = %q rev %q, %v", got.Value, got.Revision, err)
	}
	// And a set is a Valkey set, under its own key.
	if err = f.ports.Index.Add(ctx, "issuer:sessions-of:ada", "s1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if members, _ := f.redis.SMembers("t:issuer:sessions-of:ada"); !slices.Equal(members, []string{"s1"}) {
		t.Fatalf("set members = %v", members)
	}
}

// A report written through the blob port is the ConfigMap the controller's
// store writes, one update for a whole replacement.
func TestAReportIsTheSameConfigMapThroughThePortAndTheDomainStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	domain := kube.NewGitHubStatus(f.client)

	if err := domain.Replace(ctx, map[string]string{"acme.json": `{"a":1}`, "globex.json": `{"g":1}`}); err != nil {
		t.Fatal(err)
	}
	names, err := f.ports.Blob.List(ctx, "reports/github/")
	if err != nil || !slices.Equal(names, []string{"reports/github/acme.json", "reports/github/globex.json"}) {
		t.Fatalf("List = %v, %v", names, err)
	}
	object, err := f.ports.Blob.Read(ctx, "reports/github/acme.json")
	if err != nil || string(object.Body) != `{"a":1}` {
		t.Fatalf("Read = %q, %v", object.Body, err)
	}

	f.api.ClearActions()
	if err = f.ports.Blob.(port.Replacer).Replace(ctx, "reports/github/", map[string][]byte{"acme.json": []byte(`{"a":2}`)}); err != nil {
		t.Fatal(err)
	}
	updates := 0
	for _, action := range f.api.Actions() {
		if action.GetVerb() == "update" {
			updates++
		}
	}
	if updates != 1 {
		t.Errorf("a replacement made %d updates, want the one the controller makes", updates)
	}
	reports, err := domain.Reports(ctx)
	if err != nil || len(reports) != 1 || reports["acme.json"] != `{"a":2}` {
		t.Fatalf("the domain store reads %v, %v", reports, err)
	}
}

func TestAReportEntryIsText(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if _, err := f.ports.Blob.Write(context.Background(), "reports/github/x.json", []byte{0xff, 0xfe}); !errors.Is(err, port.ErrUnsupported) {
		t.Fatalf("Write of invalid UTF-8 = %v, want ErrUnsupported", err)
	}
}

func TestAWriteToAReportTheServiceHasNotCreatedIsUnavailable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	if err := f.client.API().CoreV1().ConfigMaps("ns").Delete(ctx, "rel-github-status", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ports.Blob.Write(ctx, "reports/github/x.json", []byte("{}")); !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("Write = %v, want ErrUnavailable", err)
	}
	if _, err := f.ports.Blob.Read(ctx, "reports/github/x.json"); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("Read = %v, want ErrNotFound: not yet written", err)
	}
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
		},
		[]string{"engineering@north.example", "everyone@north.example", "social@north.example"})
}

// Everything a snapshot answers must come back: liveness decides whether a
// consumer removes access, and the reverse index is what a login reads.
func TestASnapshotComesBackWholeAndIsTheBytesTheCacheHasAlwaysHeld(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	store := hub.NewBlobSnapshots(f.ports.Blob, f.ports.State)

	taken := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if err := store.Put(ctx, sample(taken)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	raw, err := f.redis.Get("t:{C0north}:snapshot")
	if err != nil {
		t.Fatalf("the snapshot is not at the key the cache has always used: %v", err)
	}
	if want, _ := hub.EncodeSnapshot(sample(taken)); raw != string(want) {
		t.Error("the stored bytes are not the encoding the cache has always held")
	}
	if ttl := f.redis.TTL("t:{C0north}:snapshot"); ttl != time.Hour {
		t.Errorf("lifetime = %v, want the configured hour", ttl)
	}
	got, err := store.Get(ctx, "C0north")
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %v", got, err)
	}
	if got.Workspace != "C0north" || !got.TakenAt.Equal(taken) || len(got.Accounts) != 2 {
		t.Errorf("snapshot = %s at %s with %d accounts", got.Workspace, got.TakenAt, len(got.Accounts))
	}
	// A leaver read back as live would keep access for someone who has gone.
	if got.Accounts["cleo@north.example"].Live {
		t.Error("a suspended account came back live")
	}
	if len(got.Discovered) != 3 {
		t.Errorf("discovered = %v, want every group the tenant held", got.Discovered)
	}
	if groups := got.GroupsOf("ada@north.example"); !slices.Equal(groups,
		[]string{"engineering@north.example", "everyone@north.example"}) {
		t.Errorf("GroupsOf = %v", groups)
	}
}

// An empty cache is a hub with no snapshots, never an error.
func TestAMissingSnapshotIsNotAnError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	store := hub.NewBlobSnapshots(f.ports.Blob, f.ports.State)

	if got, err := store.Get(ctx, "C0nothing"); err != nil || got != nil {
		t.Errorf("Get of an unknown workspace = %v, %v; want nil and no error", got, err)
	}
	if err := store.Put(ctx, sample(time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "C0north"); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(ctx, "C0north"); err != nil || got != nil {
		t.Errorf("Get after Delete = %v, %v", got, err)
	}
	if err := store.Delete(ctx, "C0north"); err != nil {
		t.Errorf("second Delete: %v", err)
	}
}

// A workspace disconnected while a replica was down must not leave a copy of
// a company's directory in a cache for ever.
func TestASnapshotExpires(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	store := hub.NewBlobSnapshots(f.ports.Blob, f.ports.State)

	if err := store.Put(ctx, sample(time.Now())); err != nil {
		t.Fatal(err)
	}
	f.redis.FastForward(2 * time.Hour)
	if got, err := store.Get(ctx, "C0north"); err != nil || got != nil {
		t.Errorf("after the TTL = %v, %v; want it gone", got, err)
	}
}

// One replica does the reading. Google's quota is per tenant, not per reader.
func TestOnlyOneReplicaTakesTheRefreshLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	store := hub.NewBlobSnapshots(f.ports.Blob, f.ports.State)

	release, acquired, err := store.Lock(ctx, "refresh:C0north", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("the first lease was not taken: %v, %v", acquired, err)
	}
	held, err := f.redis.Get("t:{C0north}:lease:refresh")
	if err != nil || len(held) != 32 {
		t.Fatalf("the lease is not at the key and shape it always was: %q, %v", held, err)
	}
	if _, second, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || second {
		t.Errorf("a second replica took the same lease: %v, %v", second, err)
	}
	if _, other, err := store.Lock(ctx, "refresh:C0south", time.Minute); err != nil || !other {
		t.Errorf("an unrelated workspace was blocked: %v, %v", other, err)
	}
	release(ctx)
	if _, again, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || !again {
		t.Errorf("the lease was not released: %v, %v", again, err)
	}
	// A replica killed mid-refresh must not stop every other replica for ever.
	f.redis.FastForward(2 * time.Minute)
	if _, expired, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || !expired {
		t.Errorf("the lease outlived its ttl: %v, %v", expired, err)
	}
}

// Releasing a lease that has already expired must not delete the lease of
// whoever took it next.
func TestAnExpiredLeaseReleasesNobodyElsesLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t)
	store := hub.NewBlobSnapshots(f.ports.Blob, f.ports.State)

	stale, acquired, err := store.Lock(ctx, "refresh:C0north", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("Lock: %v, %v", acquired, err)
	}
	f.redis.FastForward(2 * time.Minute)
	if _, taken, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || !taken {
		t.Fatalf("the second replica could not take the expired lease: %v, %v", taken, err)
	}
	stale(ctx)
	if _, third, err := store.Lock(ctx, "refresh:C0north", time.Minute); err != nil || third {
		t.Errorf("a late release freed somebody else's lease: %v, %v", third, err)
	}
}

// What is not configured is refused by name, not answered from somewhere else.
func TestAnAbsentBackendIsUnsupported(t *testing.T) {
	t.Parallel()
	ports := (&legacy.Backend{}).Ports(legacy.Options{})
	ctx := context.Background()
	if _, err := ports.State.Get(ctx, "tok.x"); !errors.Is(err, port.ErrUnsupported) {
		t.Errorf("no Valkey: Get = %v", err)
	}
	if _, err := ports.State.Get(ctx, "gh.org.acme"); !errors.Is(err, port.ErrUnsupported) {
		t.Errorf("no cluster: Get = %v", err)
	}
	if _, err := ports.Blob.Read(ctx, "reports/github/x"); !errors.Is(err, port.ErrUnsupported) {
		t.Errorf("no cluster: Read = %v", err)
	}
	if _, err := ports.Identity.Verify(ctx, "t", []string{"a"}); !errors.Is(err, port.ErrUnsupported) {
		t.Errorf("no cluster: Verify = %v", err)
	}
}
