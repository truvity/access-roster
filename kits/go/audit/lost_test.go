package audit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
)

// The tests below prove the count of best-effort facts that could not be delivered (0029 "Facts that are lost are
// counted"). A fake transport that fails stands for a full or absent spool; the same is proved through the real Connect
// socket in transport_test.go and, for the Rust emitter, through the real spool in drivers/writer/spool.

func (f *fakeTransport) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

var errFull = connect.NewError(connect.CodeUnavailable, errors.New("spool full"))

// lostOf returns unmapped.sluis.lost of a request's record; ok is false when the record carries none.
func lostOf(t *testing.T, r *transportv2alpha1.EmitRequest) (count, since int64, ok bool) {
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
		return 0, 0, false
	}
	var l struct {
		Count int64 `json:"count"`
		Since int64 `json:"since"`
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l.Count, l.Since, true
}

// tickingEmitter is an emitter whose clock moves one second on each reading.
func tickingEmitter(t *testing.T, tr *fakeTransport) *Emitter {
	t.Helper()
	var mu sync.Mutex
	at := fixedNow
	e, err := New(Config{Actor: "key", Boundary: "dev", Release: "0.0.0-test", Transport: tr, Now: func() time.Time {
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

// A failing transport, then a success: the record that gets through names how many facts were given up on and when the
// first was; the next record carries nothing (the count resets after a delivery).
//
// verifies: REQ-AUDIT-186
func TestTheNextDeliveredRecordCarriesTheCountOfLostFactsAndTheCountResets(t *testing.T) {
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
	if _, _, ok := lostOf(t, tr.reqs[0]); ok {
		t.Fatal("the first emit carried a count although nothing was lost before it")
	}

	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	count, since, ok := lostOf(t, tr.reqs[3])
	if !ok || count != 3 {
		t.Fatalf("the delivered record carries count %d (present %v), want 3", count, ok)
	}
	// The clock reads once per record built and once per loss: the first loss is the second reading of the clock.
	if want := fixedNow.Add(2 * time.Second).UnixMilli(); since != want {
		t.Errorf("since = %d, want the time of the first loss %d", since, want)
	}

	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := lostOf(t, tr.reqs[4]); ok {
		t.Error("the count was carried twice: it did not reset after a delivery")
	}
}

// A blocking emit's failure fails the operation it belongs to, so the fact is not lost and is not counted. A blocking
// emit that succeeds carries a count the same as any other record.
//
// verifies: REQ-AUDIT-186
func TestABlockingFailureIsNotCountedAndABlockingSuccessCarriesTheCount(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	if err := e.EmitBlocking(ctx, signEvent); err == nil {
		t.Fatal("a blocking emit to a full spool succeeded")
	}
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := lostOf(t, tr.reqs[1]); ok {
		t.Fatal("a failed blocking emit was counted as a lost fact")
	}

	tr.fail(errFull)
	if err := e.Emit(ctx, signEvent); err == nil {
		t.Fatal("a non-blocking emit to a full spool succeeded")
	}
	tr.fail(nil)
	if err := e.EmitBlocking(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if count, _, ok := lostOf(t, tr.reqs[3]); !ok || count != 1 {
		t.Fatalf("the blocking record carries count %d (present %v), want 1", count, ok)
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
	if count, _, ok := lostOf(t, tr.reqs[1]); !ok || count != 1 {
		t.Fatalf("count = %d (present %v), want 1", count, ok)
	}
}

// A record that carries a count and does not get through puts the count back: nothing is forgotten until a record
// that carries it reaches the transport. A best-effort fact that is lost on the way adds one; a blocking one does not.
//
// verifies: REQ-AUDIT-186
func TestACountCarriedByARecordThatFailsIsKept(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	_ = e.Emit(ctx, signEvent)
	_ = e.Emit(ctx, signEvent) // 2 lost
	_ = e.Emit(ctx, signEvent) // carries 2, fails: 3 lost
	if count, _, ok := lostOf(t, tr.reqs[2]); !ok || count != 2 {
		t.Fatalf("the third emit carried %d (present %v), want 2", count, ok)
	}
	_ = e.EmitBlocking(ctx, signEvent) // carries 3, fails: still 3, the blocking fact is the caller's to fail
	if count, _, ok := lostOf(t, tr.reqs[3]); !ok || count != 3 {
		t.Fatalf("the blocking emit carried %d (present %v), want 3", count, ok)
	}
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	count, since, _ := lostOf(t, tr.reqs[4])
	if count != 3 {
		t.Fatalf("the delivered record carries %d, want 3", count)
	}
	if want := fixedNow.Add(2 * time.Second).UnixMilli(); since != want {
		t.Errorf("since = %d, want %d: the time of the first loss survives a retry of the carrier", since, want)
	}
}

// An event the library refuses (before it reaches the transport) is a best-effort fact the caller cannot send, so it
// is counted; the caller still gets the refusal.
//
// verifies: REQ-AUDIT-186
func TestAnEventRefusedBeforeTheTransportIsCountedWhenBestEffort(t *testing.T) {
	tr := &fakeTransport{}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	bad := Event{Action: Action{Name: "key.sign", ClassUID: 6003, ActivityID: 99}, Status: StatusSuccess} // no activity_name
	if err := e.Emit(ctx, bad); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("err = %v", err)
	}
	if len(tr.reqs) != 0 {
		t.Fatal("a refused event reached the transport")
	}
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if count, _, ok := lostOf(t, tr.reqs[0]); !ok || count != 1 {
		t.Fatalf("count = %d (present %v), want 1", count, ok)
	}
}

// The count goes in unmapped.sluis next to the caller's own fields and never changes the caller's map; a caller
// cannot write the member itself.
//
// verifies: REQ-AUDIT-186
func TestTheCountSitsBesideTheCallersFieldsAndTheCallersMapIsUntouched(t *testing.T) {
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

	ev.Sluis = map[string]any{"lost": map[string]any{"count": int64(0)}}
	err := e.Emit(ctx, ev)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a caller wrote unmapped.sluis.lost: %v", err)
	}
}

// Record builds a message and neither carries nor clears the count, so a test or the command line cannot lose it.
//
// verifies: REQ-AUDIT-186
func TestRecordDoesNotTakeTheCount(t *testing.T) {
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
		t.Fatal("Record carried the count")
	}
	tr.fail(nil)
	if err := e.Emit(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	if count, _, ok := lostOf(t, tr.reqs[1]); !ok || count != 1 {
		t.Fatalf("Record cleared the count: %d (present %v)", count, ok)
	}
}

// Concurrent failures are all counted, none twice, and the count is delivered once (run with -race).
//
// verifies: REQ-AUDIT-186
func TestConcurrentLossesAreAllCountedOnce(t *testing.T) {
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
	if count, _, ok := lostOf(t, tr.reqs[last-2]); !ok || count != n {
		t.Fatalf("count = %d (present %v), want %d", count, ok, n)
	}
	if _, _, ok := lostOf(t, tr.reqs[last-1]); ok {
		t.Error("the count was carried twice")
	}
}

// The count stops at the largest integer a record may carry, so the record stays valid.
//
// verifies: REQ-AUDIT-186
func TestTheCountIsBoundedByTheLargestIntegerOfARecord(t *testing.T) {
	l := lostNote{count: maxSafeInt - 1, since: 5}.plus(10, 9)
	if l.count != maxSafeInt || l.since != 5 {
		t.Fatalf("lostNote = %+v", l)
	}
}

// The emitter returns the transport's failure and keeps no record for later: when the transport is back it is sent
// nothing until the next call, and the record that call sends is the new one (the count of lost facts is a number, not a
// copy of the facts).
//
// verifies: REQ-AUDIT-033
func TestAFailedRecordIsReturnedAndNotKeptInMemoryForLater(t *testing.T) {
	tr := &fakeTransport{err: errFull}
	e := tickingEmitter(t, tr)
	ctx := context.Background()
	for _, call := range []func(context.Context, Event) error{e.Emit, e.EmitBlocking, e.EmitBlockingBestEffort} {
		if err := call(ctx, signEvent); !errors.Is(err, errFull) {
			t.Fatalf("err = %v, want the transport's", err)
		}
	}
	tr.fail(nil)
	time.Sleep(200 * time.Millisecond)
	tr.mu.Lock()
	n := len(tr.reqs)
	tr.mu.Unlock()
	if n != 3 {
		t.Fatalf("the transport saw %d messages, want the 3 that failed and no resend", n)
	}
	if err := e.EmitBlocking(ctx, signEvent); err != nil {
		t.Fatal(err)
	}
	uids := map[string]bool{}
	for _, r := range tr.reqs {
		uids[r.GetMessage().GetUid()] = true
	}
	if len(uids) != 4 {
		t.Fatalf("%d distinct messages, want 4: a failed record was sent again", len(uids))
	}
}
