//go:build sluis_test

package writerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The tests in this file are about the clocks: the writer forgets ids only on a clock it can trust, and a record or an
// id that is far from that clock is quarantined and never blocks the log.

// clockEnv is a writer on a clock the test moves, with every commit spilling to a segment.
func clockEnv(t *testing.T) (*env, *testClock, *Server, *atomic.Bool) {
	t.Helper()
	clk := &testClock{t: windowStart}
	e := newEnv(t)
	var synced atomic.Bool
	synced.Store(true)
	e.cfg.Now, e.cfg.Mono = clk.now, clk.mono
	e.cfg.Clock = func() clockObservation { return clockObservation{Observed: true, Synced: synced.Load()} }
	s := e.direct(t)
	s.state.lim.hot = 0
	return e, clk, s, &synced
}

func (e *env) reportReasons(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(e.root, "quarantine", "*"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		rep, _ := openQuarantine(t, e, f)
		out = append(out, rep["reason"].(string)+":"+rep["path"].(string))
	}
	return out
}

// verifies: REQ-AUDIT-178
func TestAClockThatJumpsAheadAndIsPutRightForgetsNothingAndBlocksNothing(t *testing.T) {
	e, clk, s, _ := clockEnv(t)
	em := emitterAt(t, clk.now)
	a := messageAt(t, em, "acme", clk.now())
	process(t, s, a)

	// The clock steps 20 days ahead (the wall clock only). The writer still seals what arrives, and forgets nothing.
	clk.jump(windowStart.Add(20 * day))
	b := messageAt(t, em, "acme", clk.now())
	process(t, s, b)
	if !remembers(t, e, a.uid) {
		t.Fatal("the id of a was forgotten on a clock that had jumped")
	}
	if st := readState(t, e); st.Head != windowStart.UnixMilli() {
		t.Fatalf("the head moved to %d on a clock that had jumped", st.Head)
	}

	// The clock is put right. Nothing was persisted from the jump that could hold the log: a fresh record is sealed
	// and a repeat of a is found.
	clk.jump(windowStart.Add(time.Minute))
	c := messageAt(t, em, "acme", clk.now())
	process(t, s, c, a)
	es := logEntries(t, e.logDir())
	if got := recordUIDs(es); strings.Join(got, ",") != strings.Join([]string{a.uid, b.uid, c.uid}, ",") {
		t.Fatalf("records = %v, want a, b and c once each", got)
	}
	if seals := sealEntries(es); seals[len(seals)-1]["duplicates"] != float64(1) {
		t.Fatalf("the repeat of a was not found: %v", seals[len(seals)-1])
	}
	if r := e.reportReasons(t); len(r) != 0 {
		t.Fatalf("quarantined: %v; no record was refused", r)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-178
func TestAClockThatJumpsBackQuarantinesTheRecordsOfAnotherClockAndNoMore(t *testing.T) {
	e, clk, s, _ := clockEnv(t)
	em := emitterAt(t, clk.now)
	remote := emitterAt(t, func() time.Time { return windowStart })
	a := messageAt(t, em, "acme", clk.now())
	process(t, s, a)

	clk.jump(windowStart.Add(-20 * day)) // a board that started with a clock of long ago
	own := messageAt(t, em, "acme", clk.now())
	ahead := messageAt(t, remote, "acme", windowStart) // made by a clock that is right
	process(t, s, own, ahead)
	if r := e.reportReasons(t); len(r) != 1 || r[0] != "future:time" {
		t.Fatalf("quarantined = %v, want the record of the clock that is right, as future", r)
	}
	if got := recordUIDs(logEntries(t, e.logDir())); strings.Join(got, ",") != strings.Join([]string{a.uid, own.uid}, ",") {
		t.Fatalf("records = %v", got)
	}

	// The clock is put right, and what was quarantined comes again: it is sealed, once.
	clk.jump(windowStart.Add(time.Minute))
	process(t, s, ahead, a)
	if got := recordUIDs(logEntries(t, e.logDir())); strings.Join(got, ",") != strings.Join([]string{a.uid, own.uid, ahead.uid}, ",") {
		t.Fatalf("records = %v, want a, own and ahead once each", got)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-178
func TestAJumpDuringTheAdoptionAtStartForgetsNothing(t *testing.T) {
	o := newOverLimit(t)
	clk := &testClock{t: time.Now()}
	o.e.cfg.Now, o.e.cfg.Mono = clk.now, clk.mono
	clk.jump(time.Now().Add(20 * day)) // the board starts with a clock 20 days ahead, and the kernel calls it synchronised
	s := o.e.direct(t)
	if s.state.doc.Head > time.Now().Add(time.Hour).UnixMilli() {
		t.Fatalf("the head is at %d, ahead of the evidence", s.state.doc.Head)
	}
	o.finished(t) // every filler and orphan id is remembered, the entries are adopted in order
}

// verifies: REQ-AUDIT-178
func TestNothingIsForgottenWhileTheKernelSaysTheClockIsNotSynchronised(t *testing.T) {
	e, clk, s, synced := clockEnv(t)
	em := emitterAt(t, clk.now)
	a := messageAt(t, em, "acme", clk.now())
	process(t, s, a)

	synced.Store(false)
	clk.set(windowStart.Add(20 * day)) // time passes, and the clock is not disciplined
	b := messageAt(t, em, "acme", clk.now())
	process(t, s, b)
	if !remembers(t, e, a.uid) {
		t.Fatal("an id was forgotten on a clock the kernel says is not synchronised")
	}

	synced.Store(true) // synchronised: the writer takes the clock as right, and the old hour goes
	c := messageAt(t, em, "acme", clk.now())
	process(t, s, c)
	if remembers(t, e, a.uid) {
		t.Fatal("the id of a is still remembered 20 days on, on a synchronised clock")
	}
	if !remembers(t, e, b.uid) || !remembers(t, e, c.uid) {
		t.Fatal("an id inside the window was forgotten")
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-178
func TestARecordFarAheadOrWithAnIdOfAnotherTimeIsQuarantinedAndTheLogGoesOn(t *testing.T) {
	e, clk, s, _ := clockEnv(t)
	em := emitterAt(t, clk.now)
	var bad []message
	for i := range 40 { // 40 different hours ahead
		bad = append(bad, messageAt(t, emitterAt(t, func() time.Time { return clk.now().Add(time.Duration(i+2) * time.Hour) }), "acme", clk.now().Add(time.Duration(i+2)*time.Hour)))
	}
	mismatch := messageAt(t, em, "acme", clk.now().Add(10*time.Minute)) // an id of another time than the record's
	good := messageAt(t, em, "acme", clk.now())
	process(t, s, append(append(bad, mismatch), good)...)
	if got := recordUIDs(logEntries(t, e.logDir())); strings.Join(got, ",") != good.uid {
		t.Fatalf("records = %v, want only the good one", got)
	}
	reasons := e.reportReasons(t)
	if len(reasons) != 41 {
		t.Fatalf("%d quarantined, want 41: %v", len(reasons), reasons)
	}
	if st := readState(t, e); len(st.Segs) != 1 || st.Head != clk.now().UnixMilli() {
		t.Fatalf("the state names %d segments, head %d: a refused record left a trace", len(st.Segs), st.Head)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-179
func TestAStaleRecordIsQuarantinedBeforeAnyLookupSoADamagedSegmentDoesNotStopIt(t *testing.T) {
	e, clk, s, _ := clockEnv(t)
	em := emitterAt(t, clk.now)
	a := messageAt(t, em, "acme", clk.now())
	process(t, s, a)
	doc := readState(t, e)
	if len(doc.Segs) != 1 {
		t.Fatalf("%d segments", len(doc.Segs))
	}
	if err := os.Remove(filepath.Join(e.root, filepath.FromSlash(doc.Segs[0].path()))); err != nil {
		t.Fatal(err)
	}
	// 14 days and ten minutes on, a is older than the window but its hour is still named (the head has not moved).
	clk.set(windowStart.Add(14*day + 10*time.Minute))
	s2 := e.direct(t)
	if err := s2.processBatch(context.Background(), deliveries(a)); err != nil {
		t.Fatalf("a stale repeat stopped the writer on a segment it need not read: %v", err)
	}
	if r := e.reportReasons(t); len(r) != 1 || r[0] != "stale:time" {
		t.Fatalf("quarantined = %v", r)
	}
}

// verifies: REQ-AUDIT-179
func TestASegmentNameThatExistsWithOtherBytesIsReportedAsThat(t *testing.T) {
	e := newEnv(t)
	st := newWriterState(e.writer().blob)
	ids := [][idSize]byte{{1}, {2}}
	data, ref := encodeSegment(7, ids)
	other := append([]byte{}, data...)
	other[len(other)-1] ^= 1
	if err := st.blob.create(context.Background(), ref.path(), other); err != nil {
		t.Fatal(err)
	}
	_, err := st.writeSegments(context.Background(), 7, ids)
	if !errors.Is(err, ErrSeenSegment) || errors.Is(err, ErrFence) || !strings.Contains(err.Error(), ref.path()) {
		t.Fatalf("writeSegments = %v, want ErrSeenSegment that names the segment", err)
	}
}

// verifies: REQ-AUDIT-178
func TestClosedHoursAreMergedWhetherOrNotASpillTouchesThemAndNotMoreThanSweepMaxAtOnce(t *testing.T) {
	e := newEnv(t)
	st := newWriterState(e.writer().blob)
	st.lim = seenLimits{hot: 0, seg: 1000, merge: 100} // no forced merge: only the sweep acts
	base := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	for h := range 6 { // six hours of three batches each, each batch its own small segment
		for k := range 3 {
			at := base.Add(time.Duration(h)*time.Hour + time.Duration(k)*time.Minute)
			commitIDs(t, st, int64(h*3+k+1), []string{uuidV7At(t, at), uuidV7At(t, at)}, at)
		}
	}
	// Hours 0 to 3 are closed (an hour over) at the clock of the last commit, hours 4 and 5 are not.
	small := func(h int) int { return smallSegs(st, base.Add(time.Duration(h)*time.Hour).UnixMilli()/bucketMS) }
	merged := 0
	for h := range 4 {
		if small(h) == 1 {
			merged++
		}
	}
	if small(4) != 3 || small(5) != 3 {
		t.Fatalf("open hours hold %d and %d small segments, want 3 each", small(4), small(5))
	}
	if merged == 0 || merged > 4*sweepMax {
		t.Fatalf("%d closed hours merged", merged)
	}
	// One more spill, far on: at most sweepMax hours are merged by it.
	before := 0
	for h := range 4 {
		before += small(h)
	}
	later := base.Add(8 * time.Hour)
	commitIDs(t, st, 100, []string{uuidV7At(t, later)}, later)
	after := 0
	for h := range 4 {
		after += small(h)
	}
	if after > before {
		t.Fatalf("closed hours grew from %d to %d small segments", before, after)
	}
}

// verifies: REQ-AUDIT-178
func TestTheReferencesPerHourStayBoundedAtTheTopRateAtAHundredthOfTheScale(t *testing.T) {
	// 51 messages a second is 183,600 ids an hour, batches of 256, a spill every 1,280 ids and 131,072 ids in a
	// full segment. At a hundredth: 1,836 an hour, batches of 3, a spill over 10 and 1,310 in a full segment.
	e := newEnv(t)
	st := newWriterState(e.writer().blob)
	st.lim = seenLimits{hot: 10, seg: 1310, merge: mergeAt}
	base := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	const hours, perHour, batch = 8, 1836, 3
	step := time.Hour / (perHour / batch)
	n := int64(0)
	for h := range hours {
		for k := 0; k < perHour/batch; k++ {
			at := base.Add(time.Duration(h)*time.Hour + time.Duration(k)*step)
			ids := make([]string, batch)
			for i := range ids {
				ids[i] = uuidV7At(t, at)
			}
			n++
			commitIDs(t, st, n, ids, at)
		}
	}
	perHourRefs := map[int64]int{}
	for _, r := range st.doc.Segs {
		perHourRefs[r.B]++
	}
	closed := 0
	for b, c := range perHourRefs {
		end := (b + 2) * bucketMS
		if end <= base.Add(hours*time.Hour).UnixMilli() {
			closed++
			if c > 2+1 { // one full, one small; one more while the last spills of the hour are swept
				t.Errorf("hour %d holds %d segments", b, c)
			}
		} else if c > mergeAt+2 {
			t.Errorf("the open hour %d holds %d segments", b, c)
		}
	}
	if closed < hours-3 {
		t.Fatalf("%d closed hours seen", closed)
	}
	total := 0
	for _, r := range st.doc.Segs {
		total += r.N
	}
	if total+len(st.doc.Hot) != hours*perHour {
		t.Fatalf("%d ids named, want %d", total+len(st.doc.Hot), hours*perHour)
	}
}
