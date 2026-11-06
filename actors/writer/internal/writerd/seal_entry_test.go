//go:build sluis_test

package writerd

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
)

// The tests in this file read the seal entry that ends every batch and the bounds that close a batch. Most of them
// drive the writer one batch at a time with processBatch, so that the batch contents are exact and the clocks are
// the ones the test injects: nothing here waits for a real window except the one test of the default window.

var deliverySeq atomic.Uint64

// deliveries wraps messages as the transport delivers them, from the emitter the fake transport names.
func deliveries(ms ...message) []*transportv2alpha1.Delivery {
	out := make([]*transportv2alpha1.Delivery, len(ms))
	for i, m := range ms {
		out[i] = &transportv2alpha1.Delivery{
			DeliveryId: deliverySeq.Add(1), Emitter: "key@" + testBoundary,
			Message: &transportv2alpha1.AuditMessage{Uid: m.uid, Record: m.rec},
		}
	}
	return out
}

// direct starts a writer that the test drives with processBatch instead of Run: it has read its documents and
// recovered its state, and nothing consumes the transport.
func (e *env) direct(t *testing.T) *Server {
	t.Helper()
	s := e.writer()
	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// process runs one batch of the messages to the end.
func process(t *testing.T, s *Server, ms ...message) {
	t.Helper()
	if err := s.processBatch(context.Background(), deliveries(ms...)); err != nil {
		t.Fatal(err)
	}
}

// emitterAt makes records the way an actor does, with the emitter's clock injected.
func emitterAt(t *testing.T, now func() time.Time) *audit.Emitter {
	t.Helper()
	em, err := audit.New(audit.Config{Actor: "key", Boundary: testBoundary, Release: "0.0.0-dev", Transport: dummyTransport{}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return em
}

// sealEntries returns the seal entries of a log, in order.
func sealEntries(es []map[string]any) []map[string]any {
	var out []map[string]any
	for _, e := range es {
		if e["entry"] == entrySeal {
			out = append(out, e)
		}
	}
	return out
}

// verifies: REQ-AUDIT-036
func TestASealRecordsTheClockOffsetObservedForItsBatch(t *testing.T) {
	e := newEnv(t)
	var obs atomic.Pointer[clockObservation]
	set := func(c clockObservation) { obs.Store(&c) }
	e.cfg.Clock = func() clockObservation { return *obs.Load() }
	em := emitterOf(t, e)

	s := e.direct(t)
	set(clockObservation{Observed: true, Synced: true, OffsetMicros: -345})
	process(t, s, newMessage(t, em, "key.sign", "acme"))
	set(clockObservation{Observed: true, Synced: false, OffsetMicros: 1_500_000})
	process(t, s, newMessage(t, em, "key.sign", "acme"))
	// The kernel may refuse the call (the unit's system-call filter): the writer still seals and says it saw nothing.
	set(clockObservation{})
	process(t, s, newMessage(t, em, "key.sign", "globex"))

	es := logEntries(t, e.logDir())
	seals := sealEntries(es)
	if len(seals) != 3 {
		t.Fatalf("%d seal entries, want 3 (one per batch)", len(seals))
	}
	want := []map[string]any{
		{"observed": true, "synced": true, "offset_us": float64(-345)},
		{"observed": true, "synced": false, "offset_us": float64(1_500_000)},
		{"observed": false},
	}
	for i, w := range want {
		if got := seals[i]["clock"]; !reflect.DeepEqual(got, w) {
			t.Fatalf("seal %d: clock = %v, want %v", i, got, w)
		}
	}
	if n := len(recordEntries(es)); n != 3 {
		t.Fatalf("%d record entries, want 3: a batch with no clock reading is still sealed", n)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-048
func TestEveryBatchEndsWithASealEntryInsideTheTree(t *testing.T) {
	const stampMS = 1_762_000_000_000
	e := newEnv(t)
	e.cfg.Now = func() time.Time { return time.UnixMilli(stampMS) }
	em := emitterOf(t, e)
	s := e.direct(t)

	a := newMessage(t, em, "key.sign", "acme")
	b := newMessage(t, em, "key.sign", "globex")
	bad := newMessage(t, em, "key.nothing", "acme") // not in the catalogue: refused, not a record
	process(t, s, a, a, b, bad)                     // two records, one repeat, one refusal
	process(t, s, newMessage(t, em, "key.sign", "acme"))
	process(t, s, newMessage(t, em, "key.sign", "acme"), newMessage(t, em, "key.sign", "acme"), newMessage(t, em, "key.sign", "acme"))

	es := logEntries(t, e.logDir())
	// The log is the records of each batch and then its seal entry: 2+1, 1+1, 3+1 entries.
	var batches [][]map[string]any
	var cur []map[string]any
	for _, en := range es {
		cur = append(cur, en)
		if en["entry"] == entrySeal {
			batches = append(batches, cur)
			cur = nil
		}
	}
	if len(cur) != 0 {
		t.Fatalf("%d entries after the last seal entry: a batch does not end with one", len(cur))
	}
	if len(batches) != 3 {
		t.Fatalf("%d batches, want 3", len(batches))
	}
	wantRecords := []int{2, 1, 3}
	wantDuplicates := []int{1, 0, 0}
	wantRefused := []int{1, 0, 0}
	for i, bt := range batches {
		seal := bt[len(bt)-1]
		recs := bt[:len(bt)-1]
		for _, r := range recs {
			if r["entry"] != entryRecord {
				t.Fatalf("batch %d holds an entry that is neither a record nor its seal: %v", i, r)
			}
		}
		if len(recs) != wantRecords[i] || seal["records"] != float64(wantRecords[i]) {
			t.Fatalf("batch %d: %d record entries and records=%v, want %d", i, len(recs), seal["records"], wantRecords[i])
		}
		if seal["duplicates"] != float64(wantDuplicates[i]) || seal["refused"] != float64(wantRefused[i]) {
			t.Fatalf("batch %d: duplicates=%v refused=%v", i, seal["duplicates"], seal["refused"])
		}
		w, _ := seal["writer"].(map[string]any)
		if w["instance"] != "node-1" || w["recorded_at"] != float64(stampMS) {
			t.Fatalf("batch %d: the seal entry names the writer %v", i, w)
		}
		clk, _ := seal["clock"].(map[string]any)
		if clk["observed"] != true || clk["offset_us"] != float64(12) {
			t.Fatalf("batch %d: the seal entry holds the clock %v", i, clk)
		}
		if _, sealedAway := seal["sealed"]; sealedAway {
			t.Fatalf("batch %d: the seal entry is sealed under a tenant key; it is in clear", i)
		}
	}

	// Inside the tree: the signed size counts the seal entries (6 records and 3 seal entries), and the CLI
	// recomputes the root from the tiles, which hold the seal entries, and finds the signed root.
	cp, err := os.ReadFile(filepath.Join(e.logDir(), "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(string(cp), "\n"); len(lines) < 2 || lines[1] != "9" {
		t.Fatalf("the checkpoint does not count 6 records and 3 seal entries: %q", cp)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-047
func TestTheBatchBoundsDefaultToTwoHundredFiftySixAndFiveSeconds(t *testing.T) {
	if DefaultBatchMax != 256 || DefaultBatchWindow != 5*time.Second {
		t.Fatalf("the defaults are %d records and %v, want 256 and 5s", DefaultBatchMax, DefaultBatchWindow)
	}
	// A writer configured with neither bound closes batches at the defaults.
	e := newEnv(t)
	e.cfg.BatchMax, e.cfg.BatchWindow = 0, 0
	s := e.writer()
	if s.cfg.BatchMax != 256 || s.cfg.BatchWindow != 5*time.Second {
		t.Fatalf("a writer with no bounds uses %d records and %v", s.cfg.BatchMax, s.cfg.BatchWindow)
	}
}

// verifies: REQ-AUDIT-047
func TestWithTheDefaultsABatchClosesAtTwoHundredFiftySixOrAfterFiveSeconds(t *testing.T) {
	e := newEnv(t)
	e.cfg.BatchMax, e.cfg.BatchWindow = 0, 0 // the defaults
	em := emitterOf(t, e)
	const total = 300
	msgs := make([]message, total)
	for i := range msgs {
		msgs[i] = newMessage(t, em, "key.sign", "acme")
	}
	e.start()
	for _, m := range msgs {
		e.push(m)
	}
	// The count closes the first batch long before its window: it is 256 records, not all 300.
	wait(t, "the first 256 to be acknowledged", func() bool { return e.tr.ackedCount() >= 256 })
	if n := e.tr.ackedCount(); n != 256 {
		t.Fatalf("%d acknowledged after the first batch, want 256", n)
	}
	closed := time.Now()
	// The other 44 wait for the window of their batch: 5 seconds after the first of them.
	wait(t, "the other 44 to be acknowledged", func() bool { return e.tr.ackedCount() == total })
	if d := time.Since(closed); d < 4500*time.Millisecond {
		t.Fatalf("the second batch closed %v after the first, before its 5 s window", d)
	}
	es := logEntries(t, e.logDir())
	seals := sealEntries(es)
	if len(seals) != 2 || seals[0]["records"] != float64(256) || seals[1]["records"] != float64(44) {
		t.Fatalf("seal entries = %v, want batches of 256 and 44", seals)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-047
func TestABatchOfRepeatsAndRefusalsIsNotSealed(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	s := e.direct(t)
	a := newMessage(t, em, "key.sign", "acme")
	process(t, s, a)

	cpBefore, err := os.ReadFile(filepath.Join(e.logDir(), "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	entriesBefore := len(logEntries(t, e.logDir()))
	signsBefore := countEvents(e, "key.sign")

	process(t, s, a, a)                                     // only repeats
	process(t, s, newMessage(t, em, "key.nothing", "acme")) // only a refusal
	process(t, s, a, newMessage(t, em, "key.nothing", "globex"))

	cpAfter, err := os.ReadFile(filepath.Join(e.logDir(), "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cpAfter) != string(cpBefore) {
		t.Fatalf("a batch with no new record moved the checkpoint:\n%s\nthen\n%s", cpBefore, cpAfter)
	}
	if n := len(logEntries(t, e.logDir())); n != entriesBefore {
		t.Fatalf("the log grew from %d to %d entries with no new record", entriesBefore, n)
	}
	if n := countEvents(e, "key.sign"); n != signsBefore || n != 1 {
		t.Fatalf("key@ signed %d times, was %d: a batch with no new record is not signed", n, signsBefore)
	}
	if n := e.tr.ackedCount(); n != 1+2+1+2 {
		t.Fatalf("%d acknowledged: a batch that seals nothing is still acknowledged", n)
	}
	e.mustVerify(t)
}

// countEvents counts the events the fakes saw that are exactly ev.
func countEvents(e *env, ev string) int {
	n := 0
	for _, s := range e.ev.all() {
		if s == ev {
			n++
		}
	}
	return n
}
