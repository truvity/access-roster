//go:build sluis_test

package writerd

import (
	"strings"
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
)

// stateWrites counts the conditional puts of the writer's state that the fakes saw.
func stateWrites(e *env) int {
	n := 0
	for _, s := range e.ev.all() {
		if strings.HasPrefix(s, "blob.put:state/writer-state") {
			n++
		}
	}
	return n
}

// ackedIDs is the delivery ids the transport has been told are durable, in order.
func ackedIDs(e *env) []uint64 {
	e.tr.mu.Lock()
	defer e.tr.mu.Unlock()
	return append([]uint64(nil), e.tr.acked...)
}

// A batch is registered in one conditional put of the writer's state: the log's new size and root and the ids it
// sealed, and nothing else the writer decided is kept apart from it. The messages that were removed as repeats, in the
// batch or from an earlier one, are not sealed again, and the transport is told they are done only after the put and
// the checkpoint: the acknowledgement is the writer's transport cursor, and it moves after the state does. A batch of
// repeats alone writes no state and still moves the cursor, so the repeat is not delivered for ever.
//
// verifies: REQ-AUDIT-094
func TestABatchIsRegisteredInOneConditionalPutOfTheStateAndTheCursorMovesAfterIt(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	s := e.direct(t)
	a, b, c := newMessage(t, em, "key.sign", "acme"), newMessage(t, em, "key.sign", "acme"), newMessage(t, em, "key.sign", "globex")

	// One batch: a, a again in the same batch, and b. Two records and the seal entry make three entries.
	ds := deliveries(a, a, b)
	if err := s.processBatch(t.Context(), ds); err != nil {
		t.Fatal(err)
	}
	if n := stateWrites(e); n != 1 {
		t.Fatalf("%d puts of the state for one batch, want 1: %v", n, e.ev.all())
	}
	doc := readState(t, e)
	pos := doc.Logs["audit/main"]
	if pos.Size != 3 {
		t.Fatalf("the state holds size %d, want 3 (two records and the seal entry)", pos.Size)
	}
	size, root, err := s.state.position("audit/main")
	if err != nil || size != s.cur.size || root != s.cur.root {
		t.Fatalf("the state's position (%d, %x, %v) is not the log's (%d, %x)", size, root, err, s.cur.size, s.cur.root)
	}
	if got := strings.Join(doc.Hot, ","); got != a.uid+","+b.uid {
		t.Fatalf("the state registers %q, want the two ids once each", got)
	}
	// The cursor: the three deliveries are acknowledged, after the state and the pointer and in one call.
	if got := ackedIDs(e); len(got) != 3 || got[0] != ds[0].GetDeliveryId() || got[2] != ds[2].GetDeliveryId() {
		t.Fatalf("acknowledged %v, want the three deliveries %v %v %v", got, ds[0].GetDeliveryId(), ds[1].GetDeliveryId(), ds[2].GetDeliveryId())
	}
	put, ptr, ack := e.ev.index("blob.put:state/writer-state", 0), e.ev.index("blob.put:audit/main/checkpoint", 0), e.ev.index("transport.ack:3", 0)
	if put < 0 || ptr < 0 || ack < 0 || put >= ptr || ptr >= ack {
		t.Fatalf("the cursor did not move after the state and the pointer: %v", e.ev.all())
	}

	// A second batch: a, which was sealed before, and c. a is removed; the batch adds one record.
	ds = deliveries(a, c)
	if err := s.processBatch(t.Context(), ds); err != nil {
		t.Fatal(err)
	}
	if n := stateWrites(e); n != 2 {
		t.Fatalf("%d puts of the state for two batches, want 2", n)
	}
	doc = readState(t, e)
	if got := strings.Join(doc.Hot, ","); got != a.uid+","+b.uid+","+c.uid {
		t.Fatalf("the state registers %q, want a, b and c once each", got)
	}
	if recs := recordEntries(logEntries(t, e.logDir())); len(recs) != 3 {
		t.Fatalf("%d records in the log, want 3: a repeat of a sealed message was sealed again", len(recs))
	}

	// A batch of repeats alone seals nothing and writes no state, and its deliveries are still acknowledged.
	before := len(ackedIDs(e))
	ds = deliveries(a, b)
	if err := s.processBatch(t.Context(), ds); err != nil {
		t.Fatal(err)
	}
	if n := stateWrites(e); n != 2 {
		t.Fatalf("a batch of repeats wrote the state: %d puts", n)
	}
	if got := ackedIDs(e); len(got) != before+2 {
		t.Fatalf("the repeats were not acknowledged: %v", got)
	}
	e.mustVerify(t)
}

// The log store is declared with an explicit lock mode, and the writer starts on none of the others.
//
// verifies: REQ-AUDIT-008
func TestTheWriterStartsOnlyWithAnExplicitLockMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		ok   bool
	}{{"none", true}, {"removable", true}, {"compliance", true}, {"", false}, {"governance", false}, {"None", false}} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			e := newEnv(t)
			e.store.items["audit-log"].(*configv2alpha1.AuditLog).LockMode = tc.mode
			err := e.writer().Init(t.Context())
			if (err == nil) != tc.ok {
				t.Fatalf("Init with lock mode %q = %v, want ok=%v", tc.mode, err, tc.ok)
			}
		})
	}
}
