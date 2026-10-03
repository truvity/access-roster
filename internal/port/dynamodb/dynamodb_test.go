package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/porttest"
)

// A DynamoDB table holds State, Index and Trigger; Blob, Sealer and Identity
// are other adapters' ports, so their assertions are skipped here and run there.
var otherPorts = map[string]string{
	"blob/round-trip":       "Blob is not a DynamoDB port: the S3 and legacy adapters hold it",
	"blob/write-if-version": "Blob is not a DynamoDB port: the S3 and legacy adapters hold it",
	"blob/list-delete":      "Blob is not a DynamoDB port: the S3 and legacy adapters hold it",
	"sealing/context":       "Sealer is not a DynamoDB port: the KMS adapter holds it",
	"identity/verify":       "Identity is not a DynamoDB port: the TokenReview adapter holds it",
}

var tables atomic.Int64

func fakeStore(t *testing.T, api API) *Store {
	t.Helper()
	s, err := New(context.Background(), api, Config{Table: fmt.Sprintf("t%d", tables.Add(1)), Create: true}, WithPollInterval(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The whole conformance suite over the fake: what `go test ./...` runs with no
// network. The same suite runs against LocalStack in conformance_test.go.
func TestConformanceOverTheFake(t *testing.T) {
	porttest.Run(t, func(t *testing.T) porttest.Env {
		s := fakeStore(t, newFake())
		return porttest.Env{Set: s.Set(), Advance: s.Advance, Skips: otherPorts}
	})
}

func ctx() context.Context { return context.Background() }

func TestAKeyMapsToItsFamilysPartition(t *testing.T) {
	f := newFake()
	s := fakeStore(t, f)
	for _, key := range []string{"ses.ada.s1", "ses.ada.s2", "ses.bob.s3", "rt.h1", "lease"} {
		if _, err := s.Put(ctx(), key, []byte("v"), time.Minute); err != nil && !errors.Is(err, port.ErrNoLifetime) {
			t.Fatal(err)
		}
	}
	tbl := f.tables[s.table]
	if got := len(tbl["ses"]); got != 3 {
		t.Errorf("partition ses has %d items, want 3 (one family, one partition)", got)
	}
	if _, ok := tbl["ses"]["ses.ada.s1"]; !ok {
		t.Errorf("the sort key is the whole key: %v", tbl["ses"])
	}
	if len(tbl["rt"]) != 1 {
		t.Errorf("partition rt = %v", tbl["rt"])
	}
	// A prefix with a dot is one Query; the listing never scans.
	before := f.calls["Scan"]
	page, err := s.List(ctx(), "ses.ada.", "", 0)
	if err != nil || len(page.Records) != 2 || f.calls["Scan"] != before {
		t.Fatalf("List(ses.ada.) = %v, %v, scans %d -> %d: want 2 records from a Query", page.Records, err, before, f.calls["Scan"])
	}
}

func TestAPrefixWithoutADotIsAScanInKeyOrder(t *testing.T) {
	f := newFake()
	s := fakeStore(t, f)
	for _, key := range []string{"tok.b", "ses.a.1", "tok.a", "rt.z"} {
		if _, err := s.Put(ctx(), key, []byte("v"), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for token := ""; ; {
		page, err := s.List(ctx(), "", token, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Records {
			got = append(got, r.Key)
		}
		if token = page.Next; token == "" {
			break
		}
	}
	if want := []string{"rt.z", "ses.a.1", "tok.a", "tok.b"}; !slices.Equal(got, want) {
		t.Fatalf("a listing of every key = %v, want %v", got, want)
	}
	if f.calls["Scan"] == 0 {
		t.Error("a dotless prefix was not a Scan")
	}
}

func TestAReadFiltersAnItemTheEngineHasNotReaped(t *testing.T) {
	f := newFake()
	s := fakeStore(t, f)
	if _, err := s.Put(ctx(), "tok.x", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	s.Advance(2 * time.Minute)
	if len(f.tables[s.table]["tok"]) != 1 {
		t.Fatal("the fake reaped the item: the test would prove nothing")
	}
	if _, err := s.Get(ctx(), "tok.x"); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("Get of an expired, unreaped item: %v", err)
	}
	if page, _ := s.List(ctx(), "tok.", "", 0); len(page.Records) != 0 {
		t.Fatalf("List returned the expired item: %v", page.Records)
	}
}

// A record that goes A, deleted, A must not be mistaken for one that never
// moved: the revision of the second A is not the first's.
func TestABAIsDetected(t *testing.T) {
	s := fakeStore(t, newFake())
	r1, err := s.Create(ctx(), "lease.t", []byte("A"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(ctx(), "lease.t"); err != nil {
		t.Fatal(err)
	}
	r2, err := s.Create(ctx(), "lease.t", []byte("A"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r1 == r2 {
		t.Fatalf("a recreated record has the revision %q it had before the delete", r1)
	}
	if _, err = s.Update(ctx(), "lease.t", []byte("B"), time.Minute, r1); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("Update with the pre-delete revision: %v, want ErrConflict", err)
	}
	if err = s.DeleteIfRevision(ctx(), "lease.t", r1); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("DeleteIfRevision with the pre-delete revision: %v, want ErrConflict", err)
	}
	// An identical rewrite changes the revision as well.
	r3, err := s.Update(ctx(), "lease.t", []byte("A"), time.Minute, r2)
	if err != nil || r3 == r2 {
		t.Fatalf("an identical rewrite: %q -> %q, %v", r2, r3, err)
	}
}

func TestErrorsMapToThePortsNames(t *testing.T) {
	s := fakeStore(t, newFake())
	if _, err := s.Update(ctx(), "tok.none", []byte("x"), time.Minute, "123"); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("Update of an absent key: %v, want ErrNotFound", err)
	}
	if err := s.DeleteIfRevision(ctx(), "tok.none", "123"); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("DeleteIfRevision of an absent key: %v, want ErrNotFound", err)
	}
	r, err := s.Create(ctx(), "tok.k", []byte("x"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Create(ctx(), "tok.k", []byte("y"), time.Minute); !errors.Is(err, port.ErrExists) {
		t.Errorf("Create over a live record: %v, want ErrExists", err)
	}
	if _, err = s.Update(ctx(), "tok.k", []byte("y"), time.Minute, "not-a-number"); !errors.Is(err, port.ErrConflict) {
		t.Errorf("Update with a malformed revision: %v, want ErrConflict", err)
	}
	if _, err = s.Update(ctx(), "tok.k", []byte("y"), time.Minute, r+"1"); !errors.Is(err, port.ErrConflict) {
		t.Errorf("Update with another revision: %v, want ErrConflict", err)
	}
	if _, err = s.Put(ctx(), ".bad", []byte("x"), time.Minute); !errors.Is(err, port.ErrUnsupported) {
		t.Errorf("a key with no first segment: %v, want ErrUnsupported", err)
	}
	if _, err = s.Put(ctx(), "tok."+strings.Repeat("x", 2000), []byte("x"), time.Minute); !errors.Is(err, port.ErrUnsupported) {
		t.Errorf("a key over the sort key limit: %v, want ErrUnsupported", err)
	}
}

func TestAnUnreachableTableIsUnavailableNotNotFound(t *testing.T) {
	f := newFake()
	if _, err := New(ctx(), f, Config{Table: "absent"}); !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("binding a table that is not there: %v, want ErrUnavailable", err)
	}
	s := fakeStore(t, f)
	delete(f.tables, s.table)
	if _, err := s.Get(ctx(), "tok.x"); !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("Get from a missing table: %v, want ErrUnavailable", err)
	}
	if err := s.Ping(ctx()); !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("Ping: %v", err)
	}
}

func TestCreatingTheTableIsIdempotent(t *testing.T) {
	f := newFake()
	for range 2 {
		if _, err := New(ctx(), f, Config{Table: "same", Create: true}); err != nil {
			t.Fatal(err)
		}
	}
	if f.calls["UpdateTimeToLive"] != 2 {
		t.Errorf("TTL was enabled %d times for 2 starts", f.calls["UpdateTimeToLive"])
	}
}

func TestTheIndexIsPerMemberAndStaysOutOfState(t *testing.T) {
	f := newFake()
	s := fakeStore(t, f)
	if err := s.Add(ctx(), "sessions.ada", "s1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx(), "sessions.ada", "s2", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx(), "sessions.bob", "s3", time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Members(ctx(), "sessions.ada"); !slices.Equal(sorted(got), []string{"s1", "s2"}) {
		t.Fatalf("Members = %v", got)
	}
	// The members are in no State listing and not readable as State.
	if page, _ := s.List(ctx(), "", "", 0); len(page.Records) != 0 {
		t.Fatalf("an index member is a State record: %v", page.Records)
	}
	if page, _ := s.List(ctx(), "idx#sessions.ada", "", 0); len(page.Records) != 0 {
		t.Fatalf("an index member is a State record: %v", page.Records)
	}
	s.Advance(2 * time.Minute)
	if got, _ := s.Members(ctx(), "sessions.ada"); !slices.Equal(got, []string{"s2"}) {
		t.Fatalf("Members after one member's lifetime = %v", got)
	}
	var sets []string
	err := s.ExportIndex(ctx(), "sessions.", func(x port.Exported) error {
		sets = append(sets, fmt.Sprint(x.Key, x.Members, x.TTL > 50*time.Minute))
		return nil
	})
	if err != nil || fmt.Sprint(sets) != "[sessions.ada[s2] true sessions.bob[s3] true]" {
		t.Fatalf("ExportIndex = %v, %v", sets, err)
	}
	if err = s.Remove(ctx(), "sessions.ada", "s2"); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove(ctx(), "sessions.ada", "s2"); err != nil {
		t.Fatalf("removing an absent member: %v", err)
	}
}

func sorted(s []string) []string { slices.Sort(s); return s }

func TestExportStateCarriesTheRemainingLifetime(t *testing.T) {
	s := fakeStore(t, newFake())
	if _, err := s.Put(ctx(), "tok.a", []byte("v"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx(), "gh.org.x", []byte("w"), 0); err != nil {
		t.Fatal(err)
	}
	s.Advance(10 * time.Minute)
	got := map[string]time.Duration{}
	err := s.ExportState(ctx(), "", func(x port.Exported) error {
		got[x.Key] = x.TTL
		return nil
	})
	if err != nil || len(got) != 2 {
		t.Fatalf("ExportState = %v, %v", got, err)
	}
	if ttl := got["tok.a"]; ttl < 49*time.Minute || ttl > 51*time.Minute {
		t.Errorf("tok.a has %s left, want about 50m", ttl)
	}
	if got["gh.org.x"] != 0 {
		t.Errorf("a permanent record has a lifetime: %s", got["gh.org.x"])
	}
}

func TestAWatchSeesAPutADeleteAndAnExpiryByPolling(t *testing.T) {
	s := fakeStore(t, newFake())
	c, cancel := context.WithCancel(ctx())
	defer cancel()
	ch, err := s.Watch(c, "tok.w.")
	if err != nil {
		t.Fatal(err)
	}
	r1, _ := s.Put(ctx(), "tok.w.a", []byte("1"), time.Minute)
	ev := <-ch
	if ev.Key != "tok.w.a" || ev.Deleted || ev.Revision != r1 {
		t.Fatalf("event = %+v", ev)
	}
	// An identical rewrite is a change: the revision moved.
	r2, _ := s.Put(ctx(), "tok.w.a", []byte("1"), time.Minute)
	if ev = <-ch; ev.Revision != r2 || ev.Deleted {
		t.Fatalf("event after a rewrite = %+v", ev)
	}
	s.Advance(time.Hour)
	if ev = <-ch; ev.Key != "tok.w.a" || !ev.Deleted {
		t.Fatalf("event after expiry = %+v", ev)
	}
}

func TestAWatchEndsWithTheErrorWhenTheStoreStaysDown(t *testing.T) {
	f := newFake()
	s := fakeStore(t, f)
	ch, err := s.Watch(ctx(), "tok.")
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	delete(f.tables, s.table)
	f.mu.Unlock()
	select {
	case ev := <-ch:
		if !errors.Is(ev.Err, port.ErrUnavailable) {
			t.Fatalf("event = %+v, want an ErrUnavailable", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not end")
	}
	if _, ok := <-ch; ok {
		t.Fatal("the channel stayed open after its error")
	}
}

func TestTheTriggerCrossesStoresOnOneTable(t *testing.T) {
	f := newFake()
	a := fakeStore(t, f)
	b := &Store{api: f, table: a.table, now: time.Now, poll: 20 * time.Millisecond}
	got := make(chan string, 4)
	stop := b.Subscribe(func(target string) { got <- target })
	defer stop()
	if err := a.Notify(ctx(), "slack.T01"); err != nil {
		t.Fatal(err)
	}
	select {
	case target := <-got:
		if target != "slack.T01" {
			t.Fatalf("delivered %q", target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a notification did not reach the other process")
	}
}
