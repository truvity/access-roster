//go:build sluis_test

package writerd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// The tests in this file are about the writer's state: it held every id of 14 days in one object, which grew past the
// 4 MiB the blob driver takes in a request (a board, 2026-11-07: 4,178,767 bytes, 64,287 ids), so a batch and the
// recovery of a crash could no longer be committed.

// v1State writes the state object of format 1 that holds the committed position of doc and n filler ids made in the
// last three hours, with first among them, padded to fill bytes at most. It returns the ids.
func v1State(t *testing.T, e *env, doc stateDoc, first string, size int) []string {
	t.Helper()
	logs, err := json.Marshal(doc.Logs)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `{"format":1,"logs":%s,"seen":[`, logs)
	now := time.Now()
	ids := []string{first}
	fmt.Fprintf(&b, `{"id":%q,"at":%d}`, first, now.UnixMilli())
	for b.Len() < size-70 {
		id := uuidV7At(t, now.Add(-time.Duration(len(ids)%10_000)*time.Second*(3*3600/10_000)))
		ids = append(ids, id)
		fmt.Fprintf(&b, `,{"id":%q,"at":%d}`, id, now.UnixMilli())
	}
	b.WriteString("]}")
	if err := os.WriteFile(filepath.Join(e.root, "state", "writer-state"), []byte(b.String()), 0o640); err != nil { //nolint:gosec // a test file
		t.Fatal(err)
	}
	return ids
}

// overLimit is the board of 2026-11-07: a log with one committed batch, the bundles of a second batch that a crash
// left before its state was put, and a state of the old format that is almost 4 MiB.
type overLimit struct {
	e        *env
	first    message
	orphaned []message
	fillers  []string
}

func newOverLimit(t *testing.T) *overLimit {
	t.Helper()
	e := newEnv(t)
	em := emitterOf(t, e)
	o := &overLimit{e: e, first: newMessage(t, em, "key.sign", "acme")}
	process(t, e.direct(t), o.first)

	crashing := e.direct(t)
	e.blob.before = crashOnce(func(op, p string) bool { return op == "put" && strings.HasSuffix(p, "writer-state") })
	for range 4 {
		o.orphaned = append(o.orphaned, newMessage(t, em, "key.sign", "acme"))
	}
	var fatal *fatalError
	if err := crashing.processBatch(context.Background(), deliveries(o.orphaned...)); !errors.As(err, &fatal) {
		t.Fatalf("the batch = %v, want a fatal error at the put of the state", err)
	}
	e.blob.before = nil

	o.fillers = v1State(t, e, readState(t, e), o.first.uid, blobRequestMax-100)
	st, err := os.ReadFile(filepath.Join(e.root, "state", "writer-state"))
	if err != nil {
		t.Fatal(err)
	}
	// The reproduction: what the old writer committed after the adoption of the four orphans does not fit.
	more := append(st[:len(st):len(st)], make([]byte, 4*66)...)
	if _, err := e.writer().blob.put(context.Background(), "state/writer-state", more, "x"); connectCode(err) != "resource_exhausted" {
		t.Fatalf("a state of %d bytes was taken (%v); the fake must refuse a request over %d", len(more), err, blobRequestMax)
	}
	return o
}

func connectCode(err error) string {
	if err == nil {
		return ""
	}
	i := strings.Index(err.Error(), "resource_exhausted")
	if i < 0 {
		return "other"
	}
	return "resource_exhausted"
}

// idsIn counts the ids the state names in its segments and its hot set.
func idsIn(t *testing.T, e *env) (int, stateDoc) {
	t.Helper()
	doc := readState(t, e)
	n := len(doc.Hot)
	for _, r := range doc.Segs {
		n += r.N
	}
	return n, doc
}

// finished checks what must hold after a recovery of the scenario: the state is small, every id is remembered once,
// the entries are the committed one and the four, in order, once each, and the log verifies.
func (o *overLimit) finished(t *testing.T) {
	t.Helper()
	n, doc := idsIn(t, o.e)
	if doc.Format != stateFormat || len(doc.Seen) != 0 {
		t.Fatalf("the state is still of the old format: %+v", doc.Format)
	}
	want := len(o.fillers) + len(o.orphaned) // the first message is among the fillers
	if n != want {
		t.Fatalf("the state names %d ids, want %d", n, want)
	}
	fi, err := os.Stat(filepath.Join(o.e.root, "state", "writer-state"))
	if err != nil || fi.Size() > 200<<10 {
		t.Fatalf("the state is %v bytes (%v), want a small object", fi, err)
	}
	for _, uid := range append([]string{o.first.uid, o.fillers[len(o.fillers)/2], o.fillers[len(o.fillers)-1]}, uids(o.orphaned)...) {
		if !remembers(t, o.e, uid) {
			t.Fatalf("the id %s is not remembered", uid)
		}
	}
	got := recordUIDs(logEntries(t, o.e.logDir()))
	want2 := append([]string{o.first.uid}, uids(o.orphaned)...)
	if strings.Join(got, ",") != strings.Join(want2, ",") {
		t.Fatalf("records = %v, want %v", got, want2)
	}
	o.e.mustVerify(t)
}

func uids(ms []message) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.uid)
	}
	return out
}

// verifies: REQ-AUDIT-178
func TestAStateOfTheOldFormatOverTheLimitIsAdoptedAndSpilledAtStart(t *testing.T) {
	o := newOverLimit(t)
	o.e.direct(t) // the adoption of the four entries; the old writer died here on resource_exhausted
	o.finished(t)
	s := o.e.direct(t) // a later start, with no segment in memory

	// The transport delivers the four again: they are repeats, found in a segment, and nothing is added to the log.
	before := len(logEntries(t, o.e.logDir()))
	process(t, s, o.orphaned...)
	if after := len(logEntries(t, o.e.logDir())); after != before {
		t.Fatalf("the log grew from %d to %d entries on repeats", before, after)
	}
	if s.state.loads == 0 {
		t.Fatal("the repeats were not found in a segment")
	}
}

// verifies: REQ-AUDIT-178
func TestACrashAtAnyStepOfTheSpillAndTheCommitLosesNothingAndDoublesNothing(t *testing.T) {
	var creates atomic.Int32
	steps := map[string]func(op, p string) bool{
		"before the first segment": func(op, p string) bool { return op == "create" && strings.Contains(p, "state/seen/") },
		"between two segments": func(op, p string) bool {
			return op == "create" && strings.Contains(p, "state/seen/") && creates.Add(1) == 2
		},
		"between the segments and the state": func(op, p string) bool { return op == "put" && strings.HasSuffix(p, "writer-state") },
		"between the state and the checkpoint": func(op, p string) bool {
			return op == "create" && strings.Contains(p, "checkpoints/")
		},
	}
	for name, match := range steps {
		t.Run(name, func(t *testing.T) {
			creates.Store(0)
			o := newOverLimit(t)
			ctx := context.Background()
			o.e.blob.before = crashOnce(match)
			s := o.e.writer()
			if err := s.Init(ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.recover(ctx); err == nil {
				t.Fatal("the recovery went on past the crash")
			}
			o.e.blob.before = nil
			// The start after the crash finishes the adoption by itself, whatever segments the crash left.
			s2 := o.e.direct(t)
			process(t, s2, append([]message{o.first}, o.orphaned...)...)
			o.finished(t)
		})
	}
}

// verifies: REQ-AUDIT-179
func TestASegmentThatIsMissingOrDiffersStopsTheWriterAndTheIdIsNotTakenAsNew(t *testing.T) {
	for _, damage := range []string{"missing", "corrupt"} {
		t.Run(damage, func(t *testing.T) {
			o := newOverLimit(t)
			o.e.direct(t)
			doc := readState(t, o.e)
			ms, _ := uidTime(o.orphaned[0].uid)
			var victim segRef
			for _, r := range doc.Segs {
				if r.B == ms/bucketMS {
					victim = r
				}
			}
			path := filepath.Join(o.e.root, filepath.FromSlash(victim.path()))
			if damage == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, append([]byte("SSG1"), make([]byte, 20)...), 0o640); err != nil { //nolint:gosec // a test file
				t.Fatal(err)
			}
			before := len(logEntries(t, o.e.logDir()))

			s := o.e.direct(t) // a start reads no segment
			if s.state.loads != 0 {
				t.Fatalf("a start read %d segments", s.state.loads)
			}
			em := emitterOf(t, o.e)
			for _, m := range []message{o.orphaned[0], newMessage(t, em, "key.sign", "acme")} {
				err := s.processBatch(context.Background(), deliveries(m))
				var fatal *fatalError
				if !errors.As(err, &fatal) || !errors.Is(err, ErrSeenSegment) {
					t.Fatalf("processBatch = %v, want a fatal ErrSeenSegment", err)
				}
				if !strings.Contains(err.Error(), victim.path()) {
					t.Fatalf("the error does not name the segment: %v", err)
				}
			}
			if after := len(logEntries(t, o.e.logDir())); after != before {
				t.Fatalf("the log grew from %d to %d entries past a segment that cannot be read", before, after)
			}
		})
	}
}

// commitIDs commits a state that registers ids at the time now.
func commitIDs(t *testing.T, st *writerState, size int64, ids []string, now time.Time) {
	t.Helper()
	doc, err := st.next(context.Background(), "audit/main", size, tlog.Hash{}, ids, now.UnixMilli(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.commit(context.Background(), st.blob, doc); err != nil {
		t.Fatal(err)
	}
}

func smallSegs(st *writerState, b int64) int {
	n := 0
	for _, r := range st.byBucket[b] {
		if r.N < st.lim.seg {
			n++
		}
	}
	return n
}

// verifies: REQ-AUDIT-178
func TestSmallSegmentsAreMergedAndSegmentsPastTheWindowAreDropped(t *testing.T) {
	e := newEnv(t)
	st := newWriterState(e.writer().blob)
	st.lim = seenLimits{hot: 3, seg: 20, merge: 3}
	base := time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)
	b := base.UnixMilli() / bucketMS
	var all []string
	for i := range 40 { // an hour of 5-id batches
		var ids []string
		for range 5 {
			ids = append(ids, uuidV7At(t, base.Add(time.Duration(i)*time.Minute)))
		}
		all = append(all, ids...)
		commitIDs(t, st, int64(i+1), ids, base.Add(time.Duration(i)*time.Minute))
		if n := smallSegs(st, b); n > st.lim.merge {
			t.Fatalf("after batch %d the bucket holds %d small segments, want at most %d", i, n, st.lim.merge)
		}
	}
	// 200 ids at 20 a segment: the full segments stay, the small ones are joined.
	total := 0
	for _, r := range st.doc.Segs {
		total += r.N
	}
	if total+len(st.doc.Hot) != len(all) {
		t.Fatalf("%d ids named, want %d", total+len(st.doc.Hot), len(all))
	}
	for _, id := range all {
		if has, err := st.seenID(context.Background(), id); err != nil || !has {
			t.Fatalf("id %s lost by a merge (%v)", id, err)
		}
	}

	// Two hours after the bucket ended the small ones are one (a closed bucket is merged by the next spill into it).
	late := base.Add(3 * time.Hour)
	commitIDs(t, st, 100, []string{uuidV7At(t, base), uuidV7At(t, base), uuidV7At(t, base), uuidV7At(t, base)}, late)
	if n := smallSegs(st, b); n > 1 {
		t.Fatalf("a closed bucket holds %d small segments, want 1", n)
	}

	// Past the window the segments are dropped, once the newest sealed id says the time has passed.
	far := base.Add(15 * day)
	commitIDs(t, st, 101, []string{uuidV7At(t, far)}, far)
	if len(st.doc.Segs) != 0 || st.doc.Head != far.UnixMilli() {
		t.Fatalf("after 15 days: %d segments, head %d", len(st.doc.Segs), st.doc.Head)
	}
}

// verifies: REQ-AUDIT-178
func TestAnOldIdLoadsOneSegmentAndAStartLoadsNone(t *testing.T) {
	e := newEnv(t)
	st := newWriterState(e.writer().blob)
	st.lim = seenLimits{hot: 5, seg: 1000, merge: 8}
	now := time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)
	var oldest string
	for d := 13; d >= 0; d-- { // one batch of ids each day, 13 days back to now
		at := now.Add(-time.Duration(d) * day)
		var ids []string
		for range 6 {
			ids = append(ids, uuidV7At(t, at))
		}
		if d == 13 {
			oldest = ids[0]
		}
		commitIDs(t, st, int64(14-d), ids, at)
	}
	fresh, err := loadState(context.Background(), st.blob)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.loads != 0 {
		t.Fatalf("a start read %d segments, want none", fresh.loads)
	}
	if len(fresh.doc.Segs) < 13 {
		t.Fatalf("%d segments for 14 days", len(fresh.doc.Segs))
	}
	if has, err := fresh.seenID(context.Background(), oldest); err != nil || !has {
		t.Fatalf("the oldest id: %v %v", has, err)
	}
	if fresh.loads != 1 {
		t.Fatalf("an id of 13 days ago read %d segments, want 1", fresh.loads)
	}
	if has, _ := fresh.seenID(context.Background(), uuidV7At(t, now.Add(-6*day+5*time.Hour))); has || fresh.loads != 1 {
		t.Fatalf("an unknown id of a bucket with no segment read a segment (loads %d, found %v)", fresh.loads, has)
	}
}

// verifies: REQ-AUDIT-178
func TestTheStateAtTheTopRateOfTheDesignStaysSmall(t *testing.T) {
	// 51 messages a second for 14 days (0029): an hour holds 183,600 ids, which is one full segment of 131,072 and one
	// of 52,528 once merged. TestTheReferencesPerHourStayBoundedAtTheTopRateAtAHundredthOfTheScale runs the merges and
	// shows that a closed hour holds at most three references and an open one at most mergeAt+2. This is the size of
	// the real document at that bound, with the hot ids at their most.
	doc := stateDoc{Format: stateFormat, Logs: map[string]logSize{"audit/main": {Size: 1 << 40, Root: strings.Repeat("A", 44)}}}
	for b := range int64(14 * 24) {
		for i := range 3 {
			doc.Segs = append(doc.Segs, segRef{B: 490_000 + b, N: segMax - i, H: strings.Repeat("0", 31) + string(rune('0'+i))})
		}
	}
	for i := range 2 * (mergeAt + 2) {
		doc.Segs = append(doc.Segs, segRef{B: 491_000, N: 100 + i, H: strings.Repeat("1", 30) + fmt.Sprintf("%02d", i)})
	}
	for range hotMax + 256 {
		doc.Hot = append(doc.Hot, uuidV7At(t, time.Now()))
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the state at the top rate is %d bytes (%d segments, %d hot ids)", len(data), len(doc.Segs), len(doc.Hot))
	if len(data) > 128<<10 {
		t.Fatalf("the state is %d bytes, want under 128 KiB", len(data))
	}
	if idsBytes := segHeader + idSize*segMax; idsBytes > blobRequestMax-1<<20 {
		t.Fatalf("a full segment is %d bytes, too close to the blob request limit", idsBytes)
	}
}

// verifies: REQ-AUDIT-178
func TestAStateThatCannotFitStopsWithAClearErrorBeforeThePut(t *testing.T) {
	e := newEnv(t)
	st := newWriterState(e.writer().blob)
	doc := stateDoc{Format: stateFormat, Logs: map[string]logSize{}}
	for i := range 60_000 {
		doc.Segs = append(doc.Segs, segRef{B: int64(i), N: 1, H: strings.Repeat("a", 32)})
	}
	err := st.commit(context.Background(), st.blob, doc)
	if !errors.Is(err, ErrStateTooLarge) {
		t.Fatalf("commit = %v, want ErrStateTooLarge", err)
	}
	if e.ev.index("blob.put:state/writer-state", 0) >= 0 {
		t.Fatal("the put was sent")
	}
}

func TestTheOldFormatDropsAnIdThatIsNotAUUIDv7(t *testing.T) {
	e := newEnv(t)
	good := uuidV7At(t, time.Now())
	raw := fmt.Sprintf(`{"format":1,"logs":{},"seen":[{"id":%q,"at":1},{"id":"not-an-id","at":1},{"id":%q,"at":1}]}`, good, strings.ToUpper(good))
	if err := os.MkdirAll(filepath.Join(e.root, "state"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.root, "state", "writer-state"), []byte(raw), 0o640); err != nil { //nolint:gosec // a test file
		t.Fatal(err)
	}
	st, err := loadState(context.Background(), e.writer().blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.doc.Hot) != 1 || st.doc.Hot[0] != good || st.doc.Format != stateFormat {
		t.Fatalf("hot = %v format %d, want the one UUIDv7", st.doc.Hot, st.doc.Format)
	}
}
