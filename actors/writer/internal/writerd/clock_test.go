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

// madeAt is a message made by a clock that reads at.
func madeAt(t *testing.T, at time.Time) message {
	t.Helper()
	return messageAt(t, emitterAt(t, func() time.Time { return at }), "acme", at)
}

// lastTimeChecks is time_checks of the last seal entry of the log.
func lastTimeChecks(t *testing.T, e *env) map[string]any {
	t.Helper()
	seals := sealEntries(logEntries(t, e.logDir()))
	return seals[len(seals)-1]["time_checks"].(map[string]any)
}

// verifies: REQ-AUDIT-178
func TestAClockThatJumpsBackIsNotTrustedAndNothingIsQuarantinedByIt(t *testing.T) {
	e, clk, s, _ := clockEnv(t)
	em := emitterAt(t, clk.now)
	a := messageAt(t, em, "acme", clk.now())
	process(t, s, a)
	if tc := lastTimeChecks(t, e); tc["run"] != true {
		t.Fatalf("time_checks = %v on a clock that agrees", tc)
	}

	clk.jump(windowStart.Add(-20 * day)) // a step back
	remote := madeAt(t, windowStart)     // made by a clock that is right: 20 days ahead of the writer's
	own := messageAt(t, em, "acme", clk.now())
	process(t, s, remote, own)
	if r := e.reportReasons(t); len(r) != 0 {
		t.Fatalf("quarantined = %v on a clock the writer does not trust", r)
	}
	if tc := lastTimeChecks(t, e); tc["run"] != false || tc["why"] != whyStepped {
		t.Fatalf("time_checks = %v, want not run, stepped", tc)
	}

	// The clock is put right: the checks run again, a repeat is a repeat, and a record far ahead is refused.
	clk.jump(windowStart.Add(time.Minute))
	c := messageAt(t, em, "acme", clk.now())
	far := madeAt(t, windowStart.Add(3*time.Hour))
	process(t, s, remote, c, far)
	if got := recordUIDs(logEntries(t, e.logDir())); strings.Join(got, ",") != strings.Join([]string{a.uid, remote.uid, own.uid, c.uid}, ",") {
		t.Fatalf("records = %v, want a, remote, own and c once each", got)
	}
	if r := e.reportReasons(t); len(r) != 1 || r[0] != "future:time" {
		t.Fatalf("quarantined = %v, want the record 3 hours ahead", r)
	}
	if tc := lastTimeChecks(t, e); tc["run"] != true {
		t.Fatalf("time_checks = %v after the clock was put right", tc)
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-178
func TestAnUntrustedClockSealsASpoolBacklogOnceAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wall    time.Time
		obs     clockObservation
		wantWhy string
	}{
		{"a boot clock 2 days behind", windowStart.Add(-2 * day), clockObservation{Observed: true, Synced: false}, whyUnsynchronised},
		{"a boot clock 20 days ahead", windowStart.Add(20 * day), clockObservation{Observed: true, Synced: false}, whyUnsynchronised},
		{"the kernel refuses to say", windowStart.Add(-2 * day), clockObservation{}, whyUnobserved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, clk, s, _ := clockEnv(t)
			var obs atomic.Pointer[clockObservation]
			obs.Store(&tc.obs)
			s.clock = func() clockObservation { return *obs.Load() }
			clk.jump(tc.wall)
			// The spool holds what the emitters made with the right clock, before the board went down.
			var backlog []message
			for i := range 5 {
				backlog = append(backlog, madeAt(t, windowStart.Add(-time.Duration(5-i)*time.Minute)))
			}
			process(t, s, backlog...)
			if got := recordUIDs(logEntries(t, e.logDir())); strings.Join(got, ",") != strings.Join(uids(backlog), ",") {
				t.Fatalf("records = %v, want the backlog once each, in order", got)
			}
			if r := e.reportReasons(t); len(r) != 0 {
				t.Fatalf("quarantined = %v", r)
			}
			if c := lastTimeChecks(t, e); c["run"] != false || c["why"] != tc.wantWhy {
				t.Fatalf("time_checks = %v, want not run, %s", c, tc.wantWhy)
			}
			// Dedup still holds, and nothing was forgotten.
			before := len(logEntries(t, e.logDir()))
			process(t, s, backlog[1], backlog[3])
			if after := len(logEntries(t, e.logDir())); after != before {
				t.Fatalf("a repeat was sealed: %d entries, then %d", before, after)
			}
			if !remembers(t, e, backlog[0].uid) {
				t.Fatal("an id was forgotten on a clock that is not trusted")
			}

			// The clock comes right and the kernel says so: the normal checks apply again.
			clk.jump(windowStart)
			obs.Store(&clockObservation{Observed: true, Synced: true})
			late := madeAt(t, windowStart.Add(5*time.Hour))
			stale := madeAt(t, windowStart.Add(-15*day))
			good := madeAt(t, windowStart)
			process(t, s, late, stale, good)
			if r := e.reportReasons(t); len(r) != 2 {
				t.Fatalf("quarantined = %v, want the record 5 hours ahead and the one 15 days old", r)
			}
			if c := lastTimeChecks(t, e); c["run"] != true {
				t.Fatalf("time_checks = %v after the clock came right", c)
			}
			e.mustVerify(t)
		})
	}
}

// verifies: REQ-AUDIT-178
func TestAClockThatHasSteppedAndHoldsIsTrustedAgainWithoutARestartAndTheLogSaysSo(t *testing.T) {
	e, clk, s, _ := clockEnv(t)
	logs := logCapture(t)
	em := emitterAt(t, clk.now)
	process(t, s, messageAt(t, em, "acme", clk.now()))

	clk.jump(windowStart.Add(20 * day)) // an operator sets the clock, and it stays
	mk := func() message { return messageAt(t, em, "acme", clk.now()) }
	process(t, s, mk())
	if c := lastTimeChecks(t, e); c["why"] != whyStepped {
		t.Fatalf("time_checks = %v right after the step", c)
	}
	clk.set(clk.now().Add(clockSteady - time.Minute))
	process(t, s, mk())
	if c := lastTimeChecks(t, e); c["run"] != false {
		t.Fatalf("time_checks = %v before the new clock has held for %v", c, clockSteady)
	}
	clk.set(clk.now().Add(2 * time.Minute))
	process(t, s, mk())
	if c := lastTimeChecks(t, e); c["run"] != true {
		t.Fatalf("time_checks = %v after the new clock has held for %v", c, clockSteady)
	}
	out := logs.String()
	for _, want := range []string{"the clock is not trusted", "why=stepped", "the clock is trusted again"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the log lacks %q: %s", want, out)
		}
	}
	e.mustVerify(t)
}

// verifies: REQ-AUDIT-178
func TestTheStateWarnsWellBeforeItReachesTheLimit(t *testing.T) {
	e := newEnv(t)
	logs := logCapture(t)
	st := newWriterState(e.writer().blob)
	doc := stateDoc{Format: stateFormat, Logs: map[string]logSize{}}
	for i := range 20_000 { // about 1.3 MB: under half of the 3 MiB the writer puts
		doc.Segs = append(doc.Segs, segRef{B: int64(i), N: 1, H: strings.Repeat("a", 32)})
	}
	if err := st.commit(context.Background(), st.blob, doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "over half") {
		t.Fatalf("a warning at 40%% of the limit: %s", logs.String())
	}
	for i := 20_000; i < 30_000; i++ { // about 1.7 MB: over half
		doc.Segs = append(doc.Segs, segRef{B: int64(i), N: 1, H: strings.Repeat("a", 32)})
	}
	if err := st.commit(context.Background(), st.blob, doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "over half") {
		t.Fatalf("no warning at more than half of the limit: %s", logs.String())
	}
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
func TestASpillCompactsAtMostSweepMaxClosedHoursButMergesEveryHourOverTheBound(t *testing.T) {
	e := newEnv(t)
	st := newWriterState(e.writer().blob)
	st.lim = seenLimits{hot: 0, seg: 1000, merge: 100} // no forced merge while the hours are built
	base := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	n := int64(0)
	for range 3 { // six hours, three small segments each, built at a clock that has not closed any of them
		for h := range 6 {
			n++
			commitIDs(t, st, n, []string{uuidV7At(t, base.Add(time.Duration(h)*time.Hour))}, base)
		}
	}
	small := func(h int) int { return smallSegs(st, base.Add(time.Duration(h)*time.Hour).UnixMilli()/bucketMS) }
	for h := range 6 {
		if small(h) != 3 {
			t.Fatalf("hour %d holds %d small segments, want 3", h, small(h))
		}
	}
	// One spill far on, for an hour of its own: the six hours are closed, and it compacts the oldest sweepMax of them.
	later := base.Add(10 * time.Hour)
	commitIDs(t, st, 100, []string{uuidV7At(t, later)}, later)
	for h := range 6 {
		want := 3
		if h < sweepMax {
			want = 1
		}
		if small(h) != want {
			t.Fatalf("after one spill hour %d holds %d small segments, want %d", h, small(h), want)
		}
	}

	// The bound is not capped: a spill that touches more hours than sweepMax merges every one that is over it.
	// (Hours a month on, so none is closed at the clock of these commits.)
	hours := base.Add(30 * 24 * time.Hour)
	st.lim = seenLimits{hot: 0, seg: 1000, merge: 100}
	for range 3 {
		for h := range 6 {
			n++
			commitIDs(t, st, n, []string{uuidV7At(t, hours.Add(time.Duration(h)*time.Hour+time.Minute))}, base)
		}
	}
	st.lim.merge = 2
	var ids []string
	for h := range 6 {
		ids = append(ids, uuidV7At(t, hours.Add(time.Duration(h)*time.Hour+2*time.Minute)))
	}
	commitIDs(t, st, n+1, ids, base)
	for h := range 6 {
		if got := smallSegs(st, hours.Add(time.Duration(h)*time.Hour).UnixMilli()/bucketMS); got != 1 {
			t.Fatalf("hour %d holds %d small segments after a spill over the bound, want 1", h, got)
		}
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
