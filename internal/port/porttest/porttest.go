// Package porttest is the conformance suite of docs/design/ports.md. It is
// written once against the port interfaces and run against every adapter:
// the in-memory one, the legacy one, and, in later changes, NATS JetStream
// and DynamoDB, where it is the gate for adding or changing an adapter and
// for the migration tool.
//
// An adapter that cannot pass an assertion for a stated engine reason lists
// it in [Env.Skips] with the reason. The skip is a visible t.Skip naming
// the assertion and the reason; it is never a silent pass, and a Skips key
// that names no assertion fails the suite so a typo cannot hide one.
package porttest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/port"
)

// Keys the suite writes. They are keys of the layout in ports.md, so an
// adapter that maps the layout onto its own objects (the legacy one) can
// hold them: a record with a lifetime, a lease, and a permanent record.
const (
	recordPrefix    = "tok."
	leasePrefix     = "lease."
	permanentPrefix = "gh.org."
)

// Proof is a token an [port.Identity] accepts, for the audience.
type Proof struct {
	Token, Subject, Audience string
}

// Env is one adapter under test, fresh for every call of the factory.
type Env struct {
	Set port.Set
	// Advance moves the engine's clock past a lifetime without sleeping.
	Advance func(d time.Duration)
	// BlobPrefixes are the blob name prefixes to run the blob assertions
	// under, each a family the adapter holds and each holding any bytes.
	BlobPrefixes []string
	// TextBlobPrefixes are families whose engine holds text only (a
	// ConfigMap entry); they run the same assertions with a text body.
	TextBlobPrefixes []string
	// Proof makes a token the adapter's Identity accepts; nil skips nothing
	// silently, it is an assertion listed in Skips.
	Proof func() Proof
	// Skips maps an assertion name to the engine reason it cannot pass.
	Skips map[string]string
}

// Assertions are the names Run's subtests carry, and the keys of
// [Env.Skips].
var Assertions = []string{
	"cas/update-race",
	"cas/create-race",
	"cas/delete-if-revision",
	"ttl/visibility",
	"ttl/create-over-expired",
	"ttl/list-omits-expired",
	"ttl/index-expiry",
	"lease/held-cannot-be-taken",
	"lease/takeover-by-one",
	"lease/renewal-after-takeover",
	"paging/every-record-once",
	"paging/concurrent-write",
	"paging/foreign-token",
	"revisions/change-with-content",
	"revisions/change-on-identical-rewrite",
	"revisions/stale-update",
	"watch/put-delete",
	"watch/expiry",
	"watch/recover-by-listing",
	"limits/too-large",
	"limits/no-lifetime",
	"limits/permanent-family",
	"index/members",
	"blob/round-trip",
	"blob/write-if-version",
	"blob/list-delete",
	"trigger/notify",
	"sealing/context",
	"identity/verify",
}

// Run runs every assertion against a fresh adapter each.
func Run(t *testing.T, factory func(t *testing.T) Env) {
	t.Helper()
	known := map[string]bool{}
	for _, name := range Assertions {
		known[name] = true
	}
	for name := range factory(t).Skips {
		if !known[name] {
			t.Fatalf("Skips names %q, which is not an assertion", name)
		}
	}
	tests := map[string]func(*testing.T, Env){
		"cas/update-race":                       casUpdateRace,
		"cas/create-race":                       casCreateRace,
		"cas/delete-if-revision":                casDeleteIfRevision,
		"ttl/visibility":                        ttlVisibility,
		"ttl/create-over-expired":               ttlCreateOverExpired,
		"ttl/list-omits-expired":                ttlListOmitsExpired,
		"ttl/index-expiry":                      ttlIndexExpiry,
		"lease/held-cannot-be-taken":            leaseHeld,
		"lease/takeover-by-one":                 leaseTakeover,
		"lease/renewal-after-takeover":          leaseRenewalAfterTakeover,
		"paging/every-record-once":              pagingEveryRecord,
		"paging/concurrent-write":               pagingConcurrentWrite,
		"paging/foreign-token":                  pagingForeignToken,
		"revisions/change-with-content":         revisionsChangeWithContent,
		"revisions/change-on-identical-rewrite": revisionsIdenticalRewrite,
		"revisions/stale-update":                revisionsStaleUpdate,
		"watch/put-delete":                      watchPutDelete,
		"watch/expiry":                          watchExpiry,
		"watch/recover-by-listing":              watchRecover,
		"limits/too-large":                      limitsTooLarge,
		"limits/no-lifetime":                    limitsNoLifetime,
		"limits/permanent-family":               limitsPermanent,
		"index/members":                         indexMembers,
		"blob/round-trip":                       blobRoundTrip,
		"blob/write-if-version":                 blobWriteIfVersion,
		"blob/list-delete":                      blobListDelete,
		"trigger/notify":                        triggerNotify,
		"sealing/context":                       sealingContext,
		"identity/verify":                       identityVerify,
	}
	for _, name := range Assertions {
		run, ok := tests[name]
		if !ok {
			t.Fatalf("assertion %q has no test", name)
		}
		t.Run(name, func(t *testing.T) {
			env := factory(t)
			if reason, skip := env.Skips[name]; skip {
				t.Skipf("SKIPPED by the adapter, not passed: %s", reason)
			}
			run(t, env)
		})
	}
}

const (
	lifetime = time.Minute
	racers   = 16
)

func ctx() context.Context { return context.Background() }

func mustPut(t *testing.T, s port.State, key, value string, ttl time.Duration) port.Revision {
	t.Helper()
	rev, err := s.Put(ctx(), key, []byte(value), ttl)
	if err != nil {
		t.Fatalf("Put %s: %v", key, err)
	}
	return rev
}

// race runs n copies of f at once and returns each one's error.
func race(n int, f func(i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = f(i)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

func exactlyOne(t *testing.T, errs []error, loser error) {
	t.Helper()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, loser):
		default:
			t.Errorf("a racer failed with %v, want success or %v", err, loser)
		}
	}
	if won != 1 {
		t.Fatalf("%d racers won, want exactly 1", won)
	}
}

func casUpdateRace(t *testing.T, e Env) {
	key := recordPrefix + "cas"
	rev := mustPut(t, e.Set.State, key, "v0", lifetime)
	errs := race(racers, func(i int) error {
		_, err := e.Set.State.Update(ctx(), key, []byte("v"+strconv.Itoa(i+1)), lifetime, rev)
		return err
	})
	exactlyOne(t, errs, port.ErrConflict)
}

func casCreateRace(t *testing.T, e Env) {
	key := recordPrefix + "create"
	errs := race(racers, func(i int) error {
		_, err := e.Set.State.Create(ctx(), key, []byte("v"+strconv.Itoa(i)), lifetime)
		return err
	})
	exactlyOne(t, errs, port.ErrExists)
}

func casDeleteIfRevision(t *testing.T, e Env) {
	key := recordPrefix + "delrev"
	rev := mustPut(t, e.Set.State, key, "one", lifetime)
	newer := mustPut(t, e.Set.State, key, "two", lifetime)
	if err := e.Set.State.DeleteIfRevision(ctx(), key, rev); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("DeleteIfRevision with a stale revision: %v, want ErrConflict", err)
	}
	if got, err := e.Set.State.Get(ctx(), key); err != nil || string(got.Value) != "two" {
		t.Fatalf("a stale delete removed or changed the record: %v %q", err, got.Value)
	}
	if err := e.Set.State.DeleteIfRevision(ctx(), key, newer); err != nil {
		t.Fatalf("DeleteIfRevision with the current revision: %v", err)
	}
	if _, err := e.Set.State.Get(ctx(), key); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("Get after delete: %v, want ErrNotFound", err)
	}
	if err := e.Set.State.DeleteIfRevision(ctx(), key, newer); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("DeleteIfRevision of a gone key: %v, want ErrNotFound", err)
	}
	if err := e.Set.State.Delete(ctx(), key); err != nil {
		t.Fatalf("Delete of an absent key: %v", err)
	}
}

func ttlVisibility(t *testing.T, e Env) {
	key := recordPrefix + "ttl"
	mustPut(t, e.Set.State, key, "x", lifetime)
	e.Advance(lifetime / 2)
	if _, err := e.Set.State.Get(ctx(), key); err != nil {
		t.Fatalf("Get before expiry: %v", err)
	}
	e.Advance(lifetime)
	if _, err := e.Set.State.Get(ctx(), key); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("Get after expiry: %v, want ErrNotFound", err)
	}
	rev := mustPut(t, e.Set.State, key, "y", lifetime)
	e.Advance(lifetime * 2)
	if _, err := e.Set.State.Update(ctx(), key, []byte("z"), lifetime, rev); !errors.Is(err, port.ErrNotFound) {
		t.Fatalf("Update of an expired record: %v, want ErrNotFound", err)
	}
}

func ttlCreateOverExpired(t *testing.T, e Env) {
	key := recordPrefix + "reuse"
	if _, err := e.Set.State.Create(ctx(), key, []byte("first"), lifetime); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Set.State.Create(ctx(), key, []byte("second"), lifetime); !errors.Is(err, port.ErrExists) {
		t.Fatalf("Create over a live record: %v, want ErrExists", err)
	}
	e.Advance(2 * lifetime)
	if _, err := e.Set.State.Create(ctx(), key, []byte("third"), lifetime); err != nil {
		t.Fatalf("Create over an expired record: %v", err)
	}
	if got, _ := e.Set.State.Get(ctx(), key); string(got.Value) != "third" {
		t.Fatalf("the record is %q, want third", got.Value)
	}
}

func ttlListOmitsExpired(t *testing.T, e Env) {
	mustPut(t, e.Set.State, recordPrefix+"l.short", "s", lifetime)
	mustPut(t, e.Set.State, recordPrefix+"l.long", "l", 10*lifetime)
	e.Advance(2 * lifetime)
	page, err := e.Set.State.List(ctx(), recordPrefix+"l.", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].Key != recordPrefix+"l.long" {
		t.Fatalf("List after expiry: %v, want only the long-lived record", keys(page.Records))
	}
}

func ttlIndexExpiry(t *testing.T, e Env) {
	if e.Set.Index == nil {
		t.Skip("the adapter has no Index")
	}
	if err := e.Set.Index.Add(ctx(), "idx:expiry", "m", lifetime); err != nil {
		t.Fatal(err)
	}
	e.Advance(2 * lifetime)
	if got, err := e.Set.Index.Members(ctx(), "idx:expiry"); err != nil || len(got) != 0 {
		t.Fatalf("Members after expiry: %v %v, want none", got, err)
	}
}

func leaseHeld(t *testing.T, e Env) {
	key := leasePrefix + "held"
	if _, err := e.Set.State.Create(ctx(), key, []byte("a"), lifetime); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Set.State.Create(ctx(), key, []byte("b"), lifetime); !errors.Is(err, port.ErrExists) {
		t.Fatalf("taking a held lease: %v, want ErrExists", err)
	}
}

func leaseTakeover(t *testing.T, e Env) {
	key := leasePrefix + "takeover"
	if _, err := e.Set.State.Create(ctx(), key, []byte("old"), lifetime); err != nil {
		t.Fatal(err)
	}
	e.Advance(2 * lifetime)
	errs := race(racers, func(i int) error {
		_, err := e.Set.State.Create(ctx(), key, []byte("taker"+strconv.Itoa(i)), lifetime)
		return err
	})
	exactlyOne(t, errs, port.ErrExists)
}

func leaseRenewalAfterTakeover(t *testing.T, e Env) {
	key := leasePrefix + "renew"
	rev, err := e.Set.State.Create(ctx(), key, []byte("holder"), lifetime)
	if err != nil {
		t.Fatal(err)
	}
	rev, err = e.Set.State.Update(ctx(), key, []byte("holder"), lifetime, rev)
	if err != nil {
		t.Fatalf("renewing a held lease: %v", err)
	}
	e.Advance(2 * lifetime)
	if _, err = e.Set.State.Create(ctx(), key, []byte("taker"), lifetime); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if _, err = e.Set.State.Update(ctx(), key, []byte("holder"), lifetime, rev); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("renewal after takeover: %v, want ErrConflict", err)
	}
	if err = e.Set.State.DeleteIfRevision(ctx(), key, rev); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("release after takeover: %v, want ErrConflict", err)
	}
}

func keys(records []port.Record) []string {
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.Key
	}
	return out
}

func pageAll(t *testing.T, s port.State, prefix string, limit int) []string {
	t.Helper()
	var all []string
	token := ""
	for range 1000 {
		page, err := s.List(ctx(), prefix, token, limit)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		all = append(all, keys(page.Records)...)
		if page.Next == "" {
			return all
		}
		token = page.Next
	}
	t.Fatal("a listing did not end")
	return nil
}

func pagingEveryRecord(t *testing.T, e Env) {
	prefix := recordPrefix + "p."
	var want []string
	for i := range 25 {
		key := fmt.Sprintf("%s%03d", prefix, i)
		mustPut(t, e.Set.State, key, "v", lifetime)
		want = append(want, key)
	}
	mustPut(t, e.Set.State, recordPrefix+"other.1", "v", lifetime)
	got := pageAll(t, e.Set.State, prefix, 10)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("paged listing: %v\nwant %v", got, want)
	}
}

func pagingConcurrentWrite(t *testing.T, e Env) {
	prefix := recordPrefix + "pc."
	for i := range 20 {
		mustPut(t, e.Set.State, fmt.Sprintf("%s%03d", prefix, i*2), "v", lifetime)
	}
	page, err := e.Set.State.List(ctx(), prefix, "", 5)
	if err != nil || page.Next == "" {
		t.Fatalf("first page: %v next=%q", err, page.Next)
	}
	// A record written between pages may or may not appear; none appears twice.
	mustPut(t, e.Set.State, prefix+"001", "v", lifetime)
	mustPut(t, e.Set.State, prefix+"999", "v", lifetime)
	seen := map[string]int{}
	for _, k := range keys(page.Records) {
		seen[k]++
	}
	for token := page.Next; token != ""; {
		page, err = e.Set.State.List(ctx(), prefix, token, 5)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys(page.Records) {
			seen[k]++
		}
		token = page.Next
	}
	for i := range 20 {
		if k := fmt.Sprintf("%s%03d", prefix, i*2); seen[k] != 1 {
			t.Errorf("record %s seen %d times, want once", k, seen[k])
		}
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("record %s seen %d times", k, n)
		}
	}
}

func pagingForeignToken(t *testing.T, e Env) {
	for i := range 3 {
		mustPut(t, e.Set.State, fmt.Sprintf("%sf.a.%d", recordPrefix, i), "v", lifetime)
		mustPut(t, e.Set.State, fmt.Sprintf("%sf.b.%d", recordPrefix, i), "v", lifetime)
	}
	page, err := e.Set.State.List(ctx(), recordPrefix+"f.a.", "", 1)
	if err != nil || page.Next == "" {
		t.Fatalf("first page: %v next=%q", err, page.Next)
	}
	if _, err = e.Set.State.List(ctx(), recordPrefix+"f.b.", page.Next, 1); !errors.Is(err, port.ErrBadPage) {
		t.Fatalf("a token from another prefix: %v, want ErrBadPage", err)
	}
}

func revisionsChangeWithContent(t *testing.T, e Env) {
	key := recordPrefix + "rev"
	r1 := mustPut(t, e.Set.State, key, "one", lifetime)
	r2 := mustPut(t, e.Set.State, key, "two", lifetime)
	if r1 == r2 {
		t.Fatalf("a write with new content kept the revision %q", r1)
	}
	got, err := e.Set.State.Get(ctx(), key)
	if err != nil || got.Revision != r2 {
		t.Fatalf("Get revision %q (%v), want %q", got.Revision, err, r2)
	}
}

func revisionsIdenticalRewrite(t *testing.T, e Env) {
	key := recordPrefix + "rev.same"
	r1 := mustPut(t, e.Set.State, key, "same", lifetime)
	r2 := mustPut(t, e.Set.State, key, "same", lifetime)
	if r1 == r2 {
		t.Fatalf("a rewrite of identical bytes kept the revision %q", r1)
	}
}

func revisionsStaleUpdate(t *testing.T, e Env) {
	key := recordPrefix + "rev.stale"
	r1 := mustPut(t, e.Set.State, key, "one", lifetime)
	mustPut(t, e.Set.State, key, "two", lifetime)
	if _, err := e.Set.State.Update(ctx(), key, []byte("three"), lifetime, r1); !errors.Is(err, port.ErrConflict) {
		t.Fatalf("Update with a stale revision: %v, want ErrConflict", err)
	}
}

// expect reads events until one for key with the wanted kind arrives:
// at-least-once, unordered across keys, so others are tolerated.
func expect(t *testing.T, ch <-chan port.Event, key string, deleted bool, what string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("the watch closed while waiting for %s", what)
			}
			if ev.Err != nil {
				t.Fatalf("the watch failed waiting for %s: %v", what, ev.Err)
			}
			if ev.Key == key && ev.Deleted == deleted {
				return
			}
		case <-deadline:
			t.Fatalf("no event for %s", what)
		}
	}
}

func watchPutDelete(t *testing.T, e Env) {
	c, cancel := context.WithCancel(ctx())
	defer cancel()
	prefix := recordPrefix + "w."
	ch, err := e.Set.State.Watch(c, prefix)
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, e.Set.State, recordPrefix+"elsewhere", "x", lifetime)
	mustPut(t, e.Set.State, prefix+"a", "x", lifetime)
	expect(t, ch, prefix+"a", false, "a put")
	if err = e.Set.State.Delete(ctx(), prefix+"a"); err != nil {
		t.Fatal(err)
	}
	expect(t, ch, prefix+"a", true, "a delete")
}

func watchExpiry(t *testing.T, e Env) {
	c, cancel := context.WithCancel(ctx())
	defer cancel()
	prefix := recordPrefix + "we."
	ch, err := e.Set.State.Watch(c, prefix)
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, e.Set.State, prefix+"a", "x", lifetime)
	expect(t, ch, prefix+"a", false, "a put")
	e.Advance(2 * lifetime)
	expect(t, ch, prefix+"a", true, "an expiry")
}

func watchRecover(t *testing.T, e Env) {
	c, cancel := context.WithCancel(ctx())
	prefix := recordPrefix + "wr."
	ch, err := e.Set.State.Watch(c, prefix)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for ev := range ch { // the stream ends when its context does
		_ = ev
	}
	mustPut(t, e.Set.State, prefix+"a", "x", lifetime)
	if got := pageAll(t, e.Set.State, prefix, 0); len(got) != 1 {
		t.Fatalf("a watcher that resubscribes lists %v, want the record written while it was away", got)
	}
}

func limitsTooLarge(t *testing.T, e Env) {
	big := bytes.Repeat([]byte("x"), port.MaxValue+1)
	for name, write := range map[string]func() error{
		"Put":    func() error { _, err := e.Set.State.Put(ctx(), recordPrefix+"big", big, lifetime); return err },
		"Create": func() error { _, err := e.Set.State.Create(ctx(), recordPrefix+"big", big, lifetime); return err },
	} {
		if err := write(); !errors.Is(err, port.ErrTooLarge) {
			t.Fatalf("%s of %d bytes: %v, want ErrTooLarge", name, len(big), err)
		}
	}
	if _, err := e.Set.State.Put(ctx(), recordPrefix+"max", big[:port.MaxValue], lifetime); err != nil {
		t.Fatalf("a value of exactly the limit: %v", err)
	}
}

func limitsNoLifetime(t *testing.T, e Env) {
	if _, err := e.Set.State.Put(ctx(), recordPrefix+"nottl", []byte("x"), 0); !errors.Is(err, port.ErrNoLifetime) {
		t.Fatalf("Put with no lifetime to a key that needs one: %v, want ErrNoLifetime", err)
	}
	if _, err := e.Set.State.Create(ctx(), recordPrefix+"nottl", []byte("x"), 0); !errors.Is(err, port.ErrNoLifetime) {
		t.Fatalf("Create with no lifetime: %v, want ErrNoLifetime", err)
	}
}

func limitsPermanent(t *testing.T, e Env) {
	key := permanentPrefix + "acme"
	rev, err := e.Set.State.Put(ctx(), key, []byte(`{"org":"acme"}`), 0)
	if err != nil {
		t.Fatalf("Put of a permanent key: %v", err)
	}
	e.Advance(1000 * time.Hour)
	got, err := e.Set.State.Get(ctx(), key)
	if err != nil || string(got.Value) != `{"org":"acme"}` || got.Revision != rev {
		t.Fatalf("a permanent record: %v %q rev=%q want %q", err, got.Value, got.Revision, rev)
	}
	if _, err = e.Set.State.Create(ctx(), key, []byte("x"), 0); !errors.Is(err, port.ErrExists) {
		t.Fatalf("Create over a permanent record: %v, want ErrExists", err)
	}
	if _, err = e.Set.State.Update(ctx(), key, []byte(`{"org":"acme","owner":"x"}`), 0, rev); err != nil {
		t.Fatalf("Update of a permanent record: %v", err)
	}
	if got := pageAll(t, e.Set.State, permanentPrefix, 0); len(got) != 1 || got[0] != key {
		t.Fatalf("listing the permanent family: %v", got)
	}
	if err = e.Set.State.Delete(ctx(), key); err != nil {
		t.Fatal(err)
	}
}

func indexMembers(t *testing.T, e Env) {
	if e.Set.Index == nil {
		t.Skip("the adapter has no Index")
	}
	idx := e.Set.Index
	if got, err := idx.Members(ctx(), "idx:m"); err != nil || len(got) != 0 {
		t.Fatalf("a set nobody wrote: %v %v, want empty", got, err)
	}
	for _, m := range []string{"b", "a", "b"} {
		if err := idx.Add(ctx(), "idx:m", m, lifetime); err != nil {
			t.Fatal(err)
		}
	}
	got, err := idx.Members(ctx(), "idx:m")
	sort.Strings(got)
	if err != nil || fmt.Sprint(got) != "[a b]" {
		t.Fatalf("Members: %v %v, want [a b]", got, err)
	}
	if err = idx.Remove(ctx(), "idx:m", "a"); err != nil {
		t.Fatal(err)
	}
	if err = idx.Remove(ctx(), "idx:m", "absent"); err != nil {
		t.Fatalf("removing an absent member: %v", err)
	}
	if got, _ = idx.Members(ctx(), "idx:m"); fmt.Sprint(got) != "[b]" {
		t.Fatalf("Members after Remove: %v", got)
	}
}

func eachBlobPrefix(t *testing.T, e Env, f func(t *testing.T, prefix string)) {
	t.Helper()
	if len(e.BlobPrefixes)+len(e.TextBlobPrefixes) == 0 {
		t.Fatal("Env.BlobPrefixes is empty")
	}
	for _, prefix := range slices.Concat(e.BlobPrefixes, e.TextBlobPrefixes) {
		t.Run(prefix, func(t *testing.T) { f(t, prefix) })
	}
}

func blobRoundTrip(t *testing.T, e Env) {
	eachBlobPrefix(t, e, func(t *testing.T, prefix string) {
		b := e.Set.Blob
		if _, err := b.Read(ctx(), prefix+"rt"); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("Read of a blob never written: %v, want ErrNotFound", err)
		}
		body := []byte("{\"report\":\"\u00e9\x00 \xff binary\"}")
		if slices.Contains(e.TextBlobPrefixes, prefix) {
			body = []byte("{\"report\":\"\u00e9 text\"}")
		}
		v1, err := b.Write(ctx(), prefix+"rt", body)
		if err != nil {
			t.Fatal(err)
		}
		got, err := b.Read(ctx(), prefix+"rt")
		if err != nil || !bytes.Equal(got.Body, body) || got.Version != v1 {
			t.Fatalf("round trip: %v %q version %q (wrote %q)", err, got.Body, got.Version, v1)
		}
		v2, err := b.Write(ctx(), prefix+"rt", []byte("replaced"))
		if err != nil || v2 == v1 {
			t.Fatalf("a replacement kept the version: %q %v", v2, err)
		}
	})
}

func blobWriteIfVersion(t *testing.T, e Env) {
	eachBlobPrefix(t, e, func(t *testing.T, prefix string) {
		b := e.Set.Blob
		v1, err := b.Write(ctx(), prefix+"cas", []byte("one"))
		if err != nil {
			t.Fatal(err)
		}
		v2, err := b.WriteIfVersion(ctx(), prefix+"cas", []byte("two"), v1)
		if err != nil {
			t.Fatalf("WriteIfVersion with the current version: %v", err)
		}
		if _, err = b.WriteIfVersion(ctx(), prefix+"cas", []byte("three"), v1); !errors.Is(err, port.ErrConflict) {
			t.Fatalf("WriteIfVersion with a stale version: %v, want ErrConflict", err)
		}
		if got, _ := b.Read(ctx(), prefix+"cas"); string(got.Body) != "two" || got.Version != v2 {
			t.Fatalf("a losing write changed the blob: %q", got.Body)
		}
		if _, err = b.WriteIfVersion(ctx(), prefix+"absent", []byte("x"), v1); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("WriteIfVersion of a blob never written: %v, want ErrNotFound", err)
		}
		errs := race(racers, func(i int) error {
			_, err := b.WriteIfVersion(ctx(), prefix+"cas", []byte("r"+strconv.Itoa(i)), v2)
			return err
		})
		exactlyOne(t, errs, port.ErrConflict)
	})
}

func blobListDelete(t *testing.T, e Env) {
	eachBlobPrefix(t, e, func(t *testing.T, prefix string) {
		b := e.Set.Blob
		for _, n := range []string{"ld-b", "ld-a"} {
			if _, err := b.Write(ctx(), prefix+n, []byte(n)); err != nil {
				t.Fatal(err)
			}
		}
		names, err := b.List(ctx(), prefix+"ld-")
		if err != nil || fmt.Sprint(names) != fmt.Sprint([]string{prefix + "ld-a", prefix + "ld-b"}) {
			t.Fatalf("List: %v %v", names, err)
		}
		if err = b.Delete(ctx(), prefix+"ld-a"); err != nil {
			t.Fatal(err)
		}
		if err = b.Delete(ctx(), prefix+"ld-a"); err != nil {
			t.Fatalf("deleting an absent blob: %v", err)
		}
		if names, _ = b.List(ctx(), prefix+"ld-"); fmt.Sprint(names) != fmt.Sprint([]string{prefix + "ld-b"}) {
			t.Fatalf("List after Delete: %v", names)
		}
		if r, ok := b.(port.Replacer); ok {
			err = r.Replace(ctx(), prefix+"ld-", map[string][]byte{"c": []byte("c")})
			if errors.Is(err, port.ErrUnsupported) {
				t.Logf("Replace is not supported under %s: %v", prefix, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if names, _ = b.List(ctx(), prefix+"ld-"); fmt.Sprint(names) != fmt.Sprint([]string{prefix + "ld-c"}) {
				t.Fatalf("List after Replace: %v", names)
			}
		}
	})
}

func triggerNotify(t *testing.T, e Env) {
	got := make(chan string, 8)
	stop := e.Set.Trigger.Subscribe(func(target string) { got <- target })
	defer stop()
	if err := e.Set.Trigger.Notify(ctx(), "github.acme"); err != nil {
		t.Fatal(err)
	}
	select {
	case target := <-got:
		if target != "github.acme" {
			t.Fatalf("delivered %q", target)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a notification was not delivered to this process")
	}
}

func sealingContext(t *testing.T, e Env) {
	secret := []byte("an App key")
	sealed, err := port.Seal(ctx(), e.Set.Sealer, secret, "gh.org.acme")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("the sealed value contains the plaintext")
	}
	got, err := port.Open(ctx(), e.Set.Sealer, sealed, "gh.org.acme")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open under the same context: %v %q", err, got)
	}
	if _, err = port.Open(ctx(), e.Set.Sealer, sealed, "gh.org.other"); !errors.Is(err, port.ErrUnwrap) {
		t.Fatalf("Open under another context: %v, want ErrUnwrap", err)
	}
}

func identityVerify(t *testing.T, e Env) {
	if e.Proof == nil {
		t.Fatal("Env.Proof is nil: list identity/verify in Skips with the reason")
	}
	p := e.Proof()
	subject, err := e.Set.Identity.Verify(ctx(), p.Token, []string{p.Audience})
	if err != nil || subject != p.Subject {
		t.Fatalf("Verify: %q %v, want %q", subject, err, p.Subject)
	}
	if _, err = e.Set.Identity.Verify(ctx(), p.Token, []string{"another-audience"}); err == nil {
		t.Fatal("a token verified for an audience it was not minted for")
	}
	if _, err = e.Set.Identity.Verify(ctx(), "not-a-token", []string{p.Audience}); err == nil {
		t.Fatal("a token nobody minted verified")
	}
}
