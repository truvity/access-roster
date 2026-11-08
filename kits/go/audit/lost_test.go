package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
)

// The tests below prove the note of best-effort facts that could not be delivered (0029 "Facts that are lost are
// counted"). A fake transport that fails stands for a full or absent spool. The Rust emitter is proved through the real
// spool in drivers/writer/spool; the Go record is proved through the real writer in actors/writer.

func (f *fakeTransport) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

var errFull = connect.NewError(connect.CodeUnavailable, errors.New("spool full"))

type noteOf struct {
	process      string
	total, since int64
}

// lostOf returns unmapped.sluis.lost of a request's record; ok is false when the record carries none.
func lostOf(t *testing.T, r *transportv2alpha1.EmitRequest) (n noteOf, ok bool) {
	t.Helper()
	var rec struct {
		Unmapped struct {
			Sluis map[string]json.RawMessage `json:"sluis"`
		} `json:"unmapped"`
	}
	if err := json.Unmarshal(r.GetMessage().GetRecord(), &rec); err != nil {
		t.Fatal(err)
	}
	raw, ok := rec.Unmapped.Sluis["lost"]
	if !ok {
		return noteOf{}, false
	}
	var l struct {
		Process string `json:"process"`
		Total   int64  `json:"total"`
		Since   int64  `json:"since"`
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return noteOf{l.Process, l.Total, l.Since}, true
}

// tickingEmitter is an emitter whose clock moves one second on each reading.
func tickingEmitter(t *testing.T, tr *fakeTransport) *Emitter {
	t.Helper()
	var mu sync.Mutex
	at := fixedNow
	e, err := New(Config{Actor: "key", Boundary: "dev", Release: "0.0.0-test", Transport: tr, Table: openTable(t), Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		at = at.Add(time.Second)
		return at
	}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func forTenant(t string) Event {
	ev := signEvent
	ev.Tenant = t
	return ev
}

// A failing transport, then a success: the record that gets through names the process, the running total and when the
// first loss was; the next record carries nothing, because a record that carried the total has been delivered.
//
// verifies: REQ-AUDIT-186
func TestTheNextDeliveredRecordCarriesTheTotalOfLostFactsAndThenStops(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	for range 3 {
		if err := e.Emit(ctx, signEvent); !errors.Is(err, errFull) {
			t.Fatalf("err = %v, want the transport's", err)
		}
	}
	if len(tr.reqs) != 3 {
		t.Fatalf("the transport saw %d emits, want 3 (no retry)", len(tr.reqs))
	}
	if _, ok := lostOf(t, tr.reqs[0]); ok {
		t.Fatal("the first emit carried a note although nothing was lost before it")
	}

	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	n, ok := lostOf(t, tr.reqs[3])
	if !ok || n.total != 3 {
		t.Fatalf("the delivered record carries %+v (present %v), want a total of 3", n, ok)
	}
	if len(n.process) != 16 || strings.Trim(n.process, "0123456789abcdef") != "" {
		t.Errorf("process = %q, want 16 lower-case hex digits", n.process)
	}
	// The clock reads once per record built and once per loss: the first loss is the second reading of the clock.
	if want := fixedNow.Add(2 * time.Second).UnixMilli(); n.since != want {
		t.Errorf("since = %d, want the time of the first loss %d", n.since, want)
	}
	if e.Lost() != 3 {
		t.Errorf("Lost() = %d, want 3", e.Lost())
	}

	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if _, ok := lostOf(t, tr.reqs[4]); ok {
		t.Error("the note was carried again after a record that carried it was delivered")
	}
	// Later losses start a new run: the total goes on from 3, and since is the time of the first of the new run.
	tr.fail(errFull)
	_ = e.Emit(ctx, signEvent)
	tr.fail(nil)
	_ = e.Emit(ctx, signEvent)
	n2, _ := lostOf(t, tr.reqs[6])
	if n2.process != n.process || n2.total != 4 || n2.since <= n.since {
		t.Fatalf("second run = %+v, first = %+v: want the same process, total 4 and a later since", n2, n)
	}
}

// A record that carries the note and does not get through leaves it owed: the next record carries it again. A repeat is
// harmless, because the total only grows and a reader takes the highest.
//
// verifies: REQ-AUDIT-186
func TestANoteStaysOwedUntilARecordThatCarriesItIsDelivered(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	_ = e.Emit(ctx, signEvent)
	_ = e.Emit(ctx, signEvent) // total 2
	_ = e.Emit(ctx, signEvent) // carries 2, fails: total 3
	if n, ok := lostOf(t, tr.reqs[2]); !ok || n.total != 2 {
		t.Fatalf("the third emit carried %+v (present %v), want a total of 2", n, ok)
	}
	_ = e.EmitBlocking(ctx, signEvent) // carries 3, fails; the caller fails its operation, so the total stays 3
	if n, ok := lostOf(t, tr.reqs[3]); !ok || n.total != 3 {
		t.Fatalf("the blocking emit carried %+v (present %v), want a total of 3", n, ok)
	}
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	n, _ := lostOf(t, tr.reqs[4])
	if n.total != 3 {
		t.Fatalf("the delivered record carries %d, want 3", n.total)
	}
	if want := fixedNow.Add(2 * time.Second).UnixMilli(); n.since != want {
		t.Errorf("since = %d, want %d: the time of the first loss of the run survives the retries", n.since, want)
	}
}

// A record that carries the note reaches the spool and the caller then times out or gets an error. The fact is counted
// again, so the next record says a larger total about the same losses: the log holds 2 and 3, a reader takes the highest
// and never sums, and nothing is counted twice.
//
// verifies: REQ-AUDIT-186
func TestARecordDeliveredButAnsweredWithAnErrorRepeatsTheTotalHarmlessly(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	_ = e.Emit(ctx, signEvent)
	_ = e.Emit(ctx, signEvent) // total 2
	// The next record carries 2 and the spool takes it; the answer is lost (fakeTransport keeps the request it fails).
	_ = e.Emit(ctx, signEvent)
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	var highest int64
	var process string
	for i, r := range tr.reqs {
		if n, ok := lostOf(t, r); ok {
			if process != "" && n.process != process {
				t.Fatalf("record %d: another process %q", i, n.process)
			}
			process, highest = n.process, max(highest, n.total)
		}
	}
	if highest != 3 {
		t.Fatalf("the highest total in the log is %d, want 3 (2 losses, and the fact whose answer was lost)", highest)
	}
	if e.Lost() != 3 {
		t.Fatalf("Lost() = %d, want 3", e.Lost())
	}
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if _, ok := lostOf(t, tr.reqs[len(tr.reqs)-1]); ok {
		t.Error("the note was carried after the current total was delivered")
	}
}

// A blocking emit's failure fails the operation it belongs to, so the fact is not lost and is not counted. A blocking
// emit that succeeds carries a note like any other record. The same holds for EmitRequired.
//
// verifies: REQ-AUDIT-186, REQ-AUDIT-187
func TestAFailureTheCallerFailsOnIsNotCountedAndASuccessCarriesTheNote(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*Emitter, context.Context, Event) error
	}{
		{"EmitBlocking", (*Emitter).EmitBlocking},
		{"EmitRequired", (*Emitter).EmitRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &fakeTransport{err: errFull}
			e := tickingEmitter(t, tr)
			ctx := context.Background()
			if err := tc.call(e, ctx, signEvent); err == nil {
				t.Fatal("an emit to a full spool succeeded")
			}
			if e.Lost() != 0 {
				t.Fatalf("Lost() = %d: a failure the caller fails on was counted", e.Lost())
			}
			tr.fail(nil)
			if err := e.Emit(ctx, signEvent); err != nil {
				t.Fatal(err)
			}
			if _, ok := lostOf(t, tr.reqs[1]); ok {
				t.Fatal("a failure the caller fails on was counted as a lost fact")
			}
			tr.fail(errFull)
			_ = e.Emit(ctx, signEvent)
			tr.fail(nil)
			if err := tc.call(e, ctx, signEvent); err != nil {
				t.Fatal(err)
			}
			if n, ok := lostOf(t, tr.reqs[3]); !ok || n.total != 1 {
				t.Fatalf("the record carries %+v (present %v), want a total of 1", n, ok)
			}
		})
	}
}

// A caller that carries on when a blocking emit fails (a revocation) loses the fact, so that failure is counted.
//
// verifies: REQ-AUDIT-186
func TestABlockingEmitTheCallerCarriesOnFromIsCounted(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	if err := e.EmitBlockingBestEffort(ctx, signEvent); err == nil {
		t.Fatal("the failure was swallowed")
	}
	if !tr.reqs[0].GetBlocking() {
		t.Error("the best-effort variant did not ask for durability")
	}
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if n, ok := lostOf(t, tr.reqs[1]); !ok || n.total != 1 {
		t.Fatalf("note = %+v (present %v), want a total of 1", n, ok)
	}
}

// An event the library refuses (before it reaches the transport) is a best-effort fact the caller cannot send, so it is
// counted, against its own tenant; the caller still gets the refusal.
//
// verifies: REQ-AUDIT-186
func TestAnEventRefusedBeforeTheTransportIsCountedWhenBestEffort(t *testing.T) {
	tr := &fakeTransport{}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	bad := Event{Action: Action{Name: "key.sign", ClassUID: 6003, ActivityID: 99}, Status: StatusSuccess, Tenant: "acme", Caller: "signer", Operation: "Sign"} // no activity_name
	if err := e.Emit(ctx, bad); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("err = %v", err)
	}
	if len(tr.reqs) != 0 {
		t.Fatal("a refused event reached the transport")
	}
	if err := e.Emit(ctx, forTenant("acme")); err != nil {
		t.Fatal(err)
	}
	if n, ok := lostOf(t, tr.reqs[0]); !ok || n.total != 1 {
		t.Fatalf("note = %+v (present %v), want a total of 1", n, ok)
	}
}

// One emitter serves many tenants. A loss belongs to the tenant of the lost event, and a record carries only its own
// tenant's note: another tenant's auditor must not see a signal of this tenant's activity, and this tenant's auditor must
// see its own loss. A fact with no tenant is the operator's own.
//
// verifies: REQ-AUDIT-186
func TestARecordCarriesOnlyItsOwnTenantsNote(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	_ = e.Emit(ctx, forTenant("acme")) // acme: 1
	_ = e.Emit(ctx, forTenant("acme")) // acme: 2
	_ = e.Emit(ctx, forTenant("globex"))
	_ = e.Emit(ctx, forTenant("")) // the operator's own
	tr.fail(nil)
	for _, tenant := range []string{"initech", "globex", "acme", "", "acme"} {
		if err := e.Emit(ctx, forTenant(tenant)); err != nil {
			t.Fatal(err)
		}
	}
	got := map[int]int64{}
	base := 4
	for i := range 5 {
		if n, ok := lostOf(t, tr.reqs[base+i]); ok {
			got[i] = n.total
		}
	}
	want := map[int]int64{1: 1, 2: 2, 3: 1} // initech none; globex 1; acme 2; operator 1; acme again none
	if len(got) != len(want) {
		t.Fatalf("notes by record = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("notes by record = %v, want %v", got, want)
		}
	}
	if e.Lost() != 4 {
		t.Errorf("Lost() = %d, want 4", e.Lost())
	}
}

// The tenants an emitter keeps a total for are bounded, so a caller cannot grow the map with tenants of its choosing.
// Past the bound a loss is counted in the operator's own bucket and shows only in a record with no tenant; a tenant that
// is past the bound sees no note.
//
// verifies: REQ-AUDIT-186
func TestTheTenantsAnEmitterKeepsATotalForAreBounded(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	over := 40
	for i := range maxLostTenants + over {
		_ = e.Emit(ctx, forTenant(fmt.Sprintf("t%d", i)))
	}
	long := forTenant(strings.Repeat("x", StringMax+1))
	if err := e.Emit(ctx, long); err == nil {
		t.Fatal("a tenant over the bound was taken")
	}
	e.mu.Lock()
	size := len(e.lost)
	e.mu.Unlock()
	if size > maxLostTenants+1 {
		t.Fatalf("%d tenants kept, bound %d (+ the operator's bucket)", size, maxLostTenants)
	}
	tr.fail(nil)
	last := fmt.Sprintf("t%d", maxLostTenants+over-1)
	n0 := len(tr.reqs)
	if err := e.Emit(ctx, forTenant(last)); err != nil {
		t.Fatal(err)
	}
	if _, ok := lostOf(t, tr.reqs[n0]); ok {
		t.Fatal("a tenant past the bound carries a note: another tenant's loss was shown to it")
	}
	if err := e.Emit(ctx, forTenant("")); err != nil {
		t.Fatal(err)
	}
	// The overflowed tenants, and the event whose tenant is too long to be one.
	if n, ok := lostOf(t, tr.reqs[n0+1]); !ok || n.total != int64(over)+1 {
		t.Fatalf("the operator's record carries %+v (present %v), want the %d overflowed losses", n, ok, over+1)
	}
}

// The note goes in unmapped.sluis next to the caller's own fields and never changes the caller's map; a caller cannot
// write the member itself.
//
// verifies: REQ-AUDIT-186
func TestTheNoteSitsBesideTheCallersFieldsAndTheCallersMapIsUntouched(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	_ = e.Emit(ctx, signEvent)
	tr.fail(nil)
	mine := map[string]any{"purpose": "token-signing"}
	ev := signEvent
	ev.Sluis = mine
	if err := e.Emit(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 {
		t.Fatalf("the caller's map was changed: %v", mine)
	}
	var rec struct {
		Unmapped struct {
			Sluis map[string]any `json:"sluis"`
		} `json:"unmapped"`
	}
	if err := json.Unmarshal(tr.reqs[1].GetMessage().GetRecord(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Unmapped.Sluis["purpose"] != "token-signing" || rec.Unmapped.Sluis["lost"] == nil {
		t.Fatalf("unmapped.sluis = %v", rec.Unmapped.Sluis)
	}

	ev.Sluis = map[string]any{"lost": map[string]any{"total": int64(0)}}
	err := e.Emit(ctx, ev)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a caller wrote unmapped.sluis.lost: %v", err)
	}
}

// Record builds a message and neither carries a note nor changes a total, so a test or the command line cannot disturb
// them.
//
// verifies: REQ-AUDIT-186
func TestRecordDoesNotCarryOrChangeTheNote(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	_ = e.Emit(ctx, signEvent)
	rec, _, err := e.Record(ctx, signEvent)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(rec, &v); err != nil {
		t.Fatal(err)
	}
	if _, has := v["unmapped"]; has {
		t.Fatal("Record carried the note")
	}
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if n, ok := lostOf(t, tr.reqs[1]); !ok || n.total != 1 {
		t.Fatalf("note = %+v (present %v)", n, ok)
	}
}

// Concurrent failures are all counted, and the total is delivered and then stops (run with -race).
//
// verifies: REQ-AUDIT-186
func TestConcurrentLossesAreAllCounted(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	const n = 50
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.Emit(ctx, signEvent)
		}()
	}
	wg.Wait()
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	last := len(tr.reqs)
	if got, ok := lostOf(t, tr.reqs[last-2]); !ok || got.total != n {
		t.Fatalf("note = %+v (present %v), want a total of %d", got, ok, n)
	}
	if _, ok := lostOf(t, tr.reqs[last-1]); ok {
		t.Error("the note was carried again after it was delivered")
	}
}

// The total stops at the largest integer a record may carry, so the record stays valid.
//
// verifies: REQ-AUDIT-186
func TestTheTotalIsBoundedByTheLargestIntegerOfARecord(t *testing.T) {
	e := tickingEmitter(t, &fakeTransport{})
	e.recordLoss("", 1, 1)
	e.lost[""].total, e.lost[""].reported = maxSafeInt, maxSafeInt
	e.recordLoss("", 2, 1)
	if got := e.lost[""].total; got != maxSafeInt {
		t.Fatalf("total = %d, want %d", got, maxSafeInt)
	}
}

// Two emitters of one actor have different process ids, so a reader tells their totals apart (a restart is a new one).
//
// verifies: REQ-AUDIT-186
func TestEachEmitterHasAProcessOfItsOwn(t *testing.T) {
	a, b := tickingEmitter(t, &fakeTransport{}), tickingEmitter(t, &fakeTransport{})
	if a.process == b.process || len(a.process) != 16 {
		t.Fatalf("process ids %q and %q", a.process, b.process)
	}
}

// A record that is within the bound only without the note is sent without it, and the note stays owed. The fact is not
// lost to the note, the note is not lost to a large fact, and the loop ends: the next smaller record carries it.
//
// verifies: REQ-AUDIT-186
func TestARecordTooLargeForTheNoteIsSentWithoutItAndTheNoteStaysOwed(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	_ = e.Emit(ctx, signEvent) // total 1
	tr.fail(nil)

	big := signEvent
	big.Sluis = map[string]any{}
	for i := range 15 {
		big.Sluis[fmt.Sprintf("k%02d", i)] = strings.Repeat("a", StringMax)
	}
	base, _, err := e.Record(ctx, big)
	if err != nil {
		t.Fatal(err)
	}
	// Grow one more field until the record is a few bytes under the bound: the note (about 70 bytes) no longer fits.
	pad := RecordMax - len(base) - 20
	big.Sluis["pad"] = strings.Repeat("b", pad-len(`,"pad":""`))
	if rec, _, err := e.Record(ctx, big); err != nil || len(rec) < RecordMax-40 {
		t.Fatalf("setup: record %d bytes, err %v", len(rec), err)
	}
	if err := e.Emit(ctx, big); err != nil {
		t.Fatalf("the large fact was lost to the note: %v", err)
	}
	last := tr.reqs[len(tr.reqs)-1]
	if _, ok := lostOf(t, last); ok {
		t.Fatal("the note was carried by a record it does not fit")
	}
	if e.Lost() != 1 {
		t.Fatalf("Lost() = %d: the large fact was counted as lost", e.Lost())
	}
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if n, ok := lostOf(t, tr.reqs[len(tr.reqs)-1]); !ok || n.total != 1 {
		t.Fatalf("the next record carries %+v (present %v), want the owed total of 1", n, ok)
	}
}

// The emitter returns the transport's failure and keeps no record for later: when the transport is back it is sent
// nothing until the next call, and the record that call sends is the new one.
//
// verifies: REQ-AUDIT-033
func TestAFailedRecordIsReturnedAndNotKeptInMemoryForLater(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	for _, call := range []func(context.Context, Event) error{e.Emit, e.EmitBlocking, e.EmitBlockingBestEffort, e.EmitRequired} {
		if err := call(ctx, signEvent); !errors.Is(err, errFull) {
			t.Fatalf("err = %v, want the transport's", err)
		}
	}
	tr.fail(nil)
	time.Sleep(200 * time.Millisecond)
	tr.mu.Lock()
	n := len(tr.reqs)
	tr.mu.Unlock()
	if n != 4 {
		t.Fatalf("the transport saw %d messages, want the 4 that failed and no resend", n)
	}
	if err := e.EmitBlocking(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	uids := map[string]bool{}
	for _, r := range tr.reqs {
		uids[r.GetMessage().GetUid()] = true
	}
	if len(uids) != 5 {
		t.Fatalf("%d distinct messages, want 5: a failed record was sent again", len(uids))
	}
}

// A summary of a limiter stands for the calls it folded in (unmapped.sluis.suppressed), and when it is lost they are lost:
// the total counts them, and not the one record that carried them. A fact that is one fact counts one.
//
// verifies: REQ-AUDIT-186
func TestALostSummaryCountsTheFactsItFoldedIn(t *testing.T) {
	// The table of these tests has one row, key.sign, and no schema to speak of; the count does not depend on the action.
	refuse := signEvent
	summary := func(n int64) Event {
		ev := signEvent
		ev.Sluis = map[string]any{"caller": "exchange", "op": "open", "code": "permission_denied", "suppressed": n, "window_s": int64(60)}
		return ev
	}
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	for _, c := range []struct {
		ev   Event
		want int64
	}{
		{refuse, 1},         // a fact: one
		{summary(7), 1 + 7}, // a summary of 7 calls: seven
		{summary(1), 8 + 1}, // a summary of one call is one fact
		{summary(500), 9 + 500},
	} {
		if err := e.Emit(ctx, c.ev); !errors.Is(err, errFull) {
			t.Fatalf("err = %v", err)
		}
		if got := e.Lost(); got != c.want {
			t.Fatalf("after %v: Lost() = %d, want %d", c.ev.Sluis["suppressed"], got, c.want)
		}
	}
	// The number is read whether the producer wrote it as an int64 or as an int (the record is refused for an int, and the
	// facts are lost all the same), and a number that is no count (zero, negative, another type) is one fact.
	for _, c := range []struct {
		v    any
		want int64
	}{{int(30), 509 + 30}, {0, 539 + 1}, {int64(-4), 540 + 1}, {"7", 541 + 1}} {
		ev := signEvent
		ev.Sluis = map[string]any{"suppressed": c.v}
		if err := e.Emit(ctx, ev); err == nil { // refused by the record's schema or by the spool: either way the fact is gone
			t.Fatalf("suppressed %#v: the emit succeeded", c.v)
		}
		if got := e.Lost(); got != c.want {
			t.Fatalf("after suppressed %#v: Lost() = %d, want %d", c.v, got, c.want)
		}
	}
	base := e.Lost()
	// A summary whose delivery the caller fails on is not lost, as a fact is not.
	if err := e.EmitRequired(ctx, summary(40)); err == nil {
		t.Fatal("the transport accepted")
	}
	if got := e.Lost(); got != base {
		t.Fatalf("Lost() = %d after a required emit failed, want %d", got, base)
	}
	// The next record that reaches the transport carries the total.
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if n, ok := lostOf(t, tr.reqs[len(tr.reqs)-1]); !ok || n.total != base {
		t.Fatalf("the delivered record carries %+v (present %v), want a total of %d", n, ok, base)
	}
}
