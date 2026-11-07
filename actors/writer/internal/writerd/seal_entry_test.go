//go:build sluis_test

package writerd

import (
	"context"
	"fmt"
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
	em, err := audit.New(audit.Config{Actor: "key", Boundary: testBoundary, Release: "0.0.0-dev", Transport: dummyTransport{}, Table: openAuditTable(t), Now: now})
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
	em := emitterAt(t, e.cfg.Now) // the records are made at the writer's time: it quarantines a year of difference
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
func TestWithTheDefaultBatchMaxABatchClosesAtTwoHundredFiftySix(t *testing.T) {
	e := newEnv(t)
	e.cfg.BatchMax = 0            // the default
	e.cfg.BatchWindow = time.Hour // only the count can close the batch
	em := emitterOf(t, e)
	e.start()
	for range 300 {
		e.push(newMessage(t, em, "key.sign", "acme"))
	}
	wait(t, "the first 256 to be acknowledged", func() bool { return e.tr.ackedCount() >= 256 })
	time.Sleep(200 * time.Millisecond)
	if n := e.tr.ackedCount(); n != 256 {
		t.Fatalf("%d acknowledged, want exactly 256: the rest waits for its window", n)
	}
	if seals := sealEntries(logEntries(t, e.logDir())); len(seals) != 1 || seals[0]["records"] != float64(256) {
		t.Fatalf("seal entries = %v, want one batch of 256", seals)
	}
}

// verifies: REQ-AUDIT-047
func TestABatchOfRepeatsOnlyIsNotSealed(t *testing.T) {
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

	process(t, s, a, a) // only repeats

	cpAfter, err := os.ReadFile(filepath.Join(e.logDir(), "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cpAfter) != string(cpBefore) {
		t.Fatalf("a batch with no new record and no refusal moved the checkpoint:\n%s\nthen\n%s", cpBefore, cpAfter)
	}
	if n := len(logEntries(t, e.logDir())); n != entriesBefore {
		t.Fatalf("the log grew from %d to %d entries with no new record", entriesBefore, n)
	}
	if n := countEvents(e, "key.sign"); n != signsBefore || n != 1 {
		t.Fatalf("key@ signed %d times, was %d: a batch of repeats is not signed", n, signsBefore)
	}
	if n := e.tr.ackedCount(); n != 1+2 {
		t.Fatalf("%d acknowledged: a batch that seals nothing is still acknowledged", n)
	}
	e.mustVerify(t)
}

// exampleUIDTime is the first two groups of a UUIDv7 made at 1793750400000 ms, the time of the examples.
const exampleUIDTime = "01a1a3da-fc00"

// refusalReasons reads the refused_by member of a seal entry as reason to count.
func refusalReasons(t *testing.T, seal map[string]any) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	list, _ := seal["refused_by"].([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		out[m["reason"].(string)] = m["count"].(float64)
	}
	return out
}

// verifies: REQ-AUDIT-047, REQ-AUDIT-048
//
// A batch that takes no record and refuses some is sealed: the seal entry, inside the tree and so signed, says how many
// and why. Without it a catalogue older than the emitters would refuse every record and leave no signed trace.
func TestABatchThatOnlyRefusesIsSealedWithTheCountAndTheReasons(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	s := e.direct(t)
	process(t, s, newMessage(t, em, "key.sign", "acme"), newMessage(t, em, "key.sign", "globex"))
	sealsBefore := len(sealEntries(logEntries(t, e.logDir())))

	// An emitter of a release newer than the catalogue's (REQ-AUDIT-146), one whose action the catalogue lacks, and one
	// whose record fails the schema of its action (REQ-AUDIT-113): three reasons, no record taken.
	newer, err := audit.New(audit.Config{Actor: "key", Boundary: testBoundary, Release: "9.0.0", Transport: dummyTransport{}, Table: openAuditTable(t)})
	if err != nil {
		t.Fatal(err)
	}
	process(t, s,
		newMessage(t, newer, "key.sign", "acme"), newMessage(t, newer, "key.sign", "acme"),
		newMessage(t, em, "key.nothing", "acme"),
	)
	seals := sealEntries(logEntries(t, e.logDir()))
	if len(seals) != sealsBefore+1 {
		t.Fatalf("%d seal entries, want %d: a batch that only refuses is sealed", len(seals), sealsBefore+1)
	}
	last := seals[len(seals)-1]
	if last["records"] != float64(0) || last["refused"] != float64(3) {
		t.Fatalf("seal entry = %v, want 0 records and 3 refused", last)
	}
	if got := refusalReasons(t, last); !reflect.DeepEqual(got, map[string]float64{reasonRelease: 2, reasonAction: 1}) {
		t.Fatalf("refused_by = %v", got)
	}
	if n := len(recordEntries(logEntries(t, e.logDir()))); n != 2 {
		t.Fatalf("%d record entries, want the 2 of the first batch", n)
	}
	// Every refused message is quarantined whole, and acknowledged.
	if q, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*")); len(q) != 3 {
		t.Fatalf("%d quarantine objects, want 3", len(q))
	}
	if n := e.tr.ackedCount(); n != 2+3 {
		t.Fatalf("%d acknowledged, want 5", n)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-113, REQ-AUDIT-146
//
// The same through processBatch for the two reasons of the catalogue, with the real schemas of the table: a record that
// fails the schema of its action, and a record of a newer release, are refused, quarantined and sealed into the log.
func TestABatchOfRecordsTheCatalogueRefusesIsQuarantinedAndSealed(t *testing.T) {
	e := newEnv(t)
	e.cfg.Now = func() time.Time { return time.UnixMilli(1_793_750_400_000) } // the time of the examples
	e.store.items["audit-catalogue"] = realCatalogue(t, "0.0.0")
	s := e.direct(t)
	var base exampleCase
	for _, ex := range exampleCases(t) {
		if ex.Name == "key.sign" {
			base = ex
		}
	}
	// A UUIDv7 whose time is the record's (the writer refuses an id of another time), n telling them apart.
	uidOf := func(n int) string { return fmt.Sprintf("%s-7000-8000-%012d", exampleUIDTime, n) }
	msg := func(n int, mut func(map[string]any)) message {
		v, err := parseStrict([]byte(base.Expected))
		if err != nil {
			t.Fatal(err)
		}
		r := v.(map[string]any)
		r["metadata"].(map[string]any)["uid"] = uidOf(n)
		mut(r)
		return message{uid: uidOf(n), rec: canonical(t, r)}
	}
	// The example is old enough for the catalogue (0.0.0-test is below 0.0.0) and valid.
	process(t, s, msg(1, func(map[string]any) {}))
	if n := len(recordEntries(logEntries(t, e.logDir()))); n != 1 {
		t.Fatalf("%d record entries, the example was not taken", n)
	}
	// A newer release, and a schema failure (a member the action lacks).
	newer := msg(2, func(r map[string]any) {
		r["metadata"].(map[string]any)["product"].(map[string]any)["version"] = "0.0.1"
	})
	bad := msg(3, func(r map[string]any) {
		r["unmapped"].(map[string]any)["sluis"].(map[string]any)["extra"] = "x"
	})
	process(t, s, newer, bad)
	seals := sealEntries(logEntries(t, e.logDir()))
	last := seals[len(seals)-1]
	if last["records"] != float64(0) || last["refused"] != float64(2) {
		t.Fatalf("seal entry = %v, want 0 records and 2 refused", last)
	}
	if got := refusalReasons(t, last); !reflect.DeepEqual(got, map[string]float64{reasonRelease: 1, reasonSchema: 1}) {
		t.Fatalf("refused_by = %v", got)
	}
	if q, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*")); len(q) != 2 {
		t.Fatalf("%d quarantine objects, want 2", len(q))
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

// verifies: REQ-AUDIT-113
//
// A slow moment does not take a legitimate record out of the log. The validation of the record stalls past its budget (the
// clock of a small board stalls under a re-sync or a loaded CPU): the batch is given back with an error, nothing is written,
// quarantined or acknowledged, the transport delivers it again, and the record, now validated at once, is taken.
func TestASlowValidationGivesTheBatchBackAndTheRecordIsTakenWhenItIsFast(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	s := e.direct(t)
	stalled := make(chan struct{})
	defer close(stalled)
	var calls atomic.Int32
	validate := s.chk.schemas.Validate
	s.chk.budget = 30 * time.Millisecond
	s.chk.valid = func(name string, rec []byte) error {
		if calls.Add(1) == 1 {
			<-stalled // the stall: this validation does not finish while the test runs
		}
		return validate(name, rec)
	}
	m := newMessage(t, em, "key.sign", "acme")

	if err := s.processBatch(context.Background(), deliveries(m)); err == nil {
		t.Fatal("a stalled validation was not given back")
	}
	if _, err := os.Stat(filepath.Join(e.logDir(), "checkpoint")); err == nil {
		t.Fatal("the log was written for a batch that was given back")
	}
	if q, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*")); len(q) != 0 {
		t.Fatalf("%d quarantine objects: a slow moment removed a legitimate record", len(q))
	}
	if n := e.tr.ackedCount(); n != 0 {
		t.Fatalf("%d acknowledged: the batch must be delivered again", n)
	}

	process(t, s, m) // the transport delivers it again, and the validation is quick now
	if n := len(recordEntries(logEntries(t, e.logDir()))); n != 1 {
		t.Fatalf("%d record entries, want the record taken", n)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-113
//
// A record whose validation times out every time is refused at the third: quarantined whole and counted in the seal entry as
// `schema`, so it cannot hold the log back for ever. The first two attempts give the batch back.
func TestARecordThatTimesOutEveryTimeIsRefusedAtTheThirdAttempt(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	s := e.direct(t)
	stalled := make(chan struct{})
	defer close(stalled)
	s.chk.budget = 20 * time.Millisecond
	s.chk.valid = func(string, []byte) error { <-stalled; return nil }
	m := newMessage(t, em, "key.sign", "acme")
	for attempt := 1; attempt < maxSlowAttempts; attempt++ {
		if err := s.processBatch(context.Background(), deliveries(m)); err == nil {
			t.Fatalf("attempt %d was not given back", attempt)
		}
	}
	process(t, s, m)
	seals := sealEntries(logEntries(t, e.logDir()))
	if len(seals) != 1 || seals[0]["records"] != float64(0) || seals[0]["refused"] != float64(1) {
		t.Fatalf("seal entries = %v, want one with 0 records and 1 refused", seals)
	}
	if got := refusalReasons(t, seals[0]); !reflect.DeepEqual(got, map[string]float64{reasonSchema: 1}) {
		t.Fatalf("refused_by = %v", got)
	}
	if q, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*")); len(q) != 1 {
		t.Fatalf("%d quarantine objects, want 1", len(q))
	}
	e.mustVerify(t)
}
