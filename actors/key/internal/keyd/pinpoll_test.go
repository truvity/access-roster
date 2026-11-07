//go:build sluis_test

package keyd

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// What these tests measure: the polling of the PIN release over a simulated period, on the fake store and fake drivers.
// The clock is simulated: a test replaces the wait between passes (Config.PinSleep) with a function that moves the
// test clock by the wait and counts it, so an hour takes milliseconds and no test sleeps.
//
// An audit fact that a lookup costs is counted on the fake store, which counts the Gets that find no item
// (fakeStore.absent). Each such Get is a refusal, and ADR 0005 says store@ audits every refusal; actors/store/src/service.rs
// (refuse_event) does it for the verb "get" as for any other. Before this change one pass with a request that this
// node could not answer made seven of them: one Get of the answer (PinRelease) and, for the node's own keys and then for the
// peer's, three Gets each of KeyRevocation (selfRevoked and peerRevoked), none of which was revoked. Those are the
// seven failure records within about 110 ms that a board wrote at every pass.

// pinAuditBoundPerHour is the bound of REQ-AUDIT-180 for what key@ adds on an idle, locked or waiting board in an hour.
const pinAuditBoundPerHour = 60

// sim is the simulated period of a test: a clock that moves by the waits of the loop, the waits it saw, and a hook
// that runs at each wait, where a test changes the world.
type sim struct {
	e       *testEnv
	start   time.Time
	until   time.Duration
	mu      sync.Mutex
	waits   []time.Duration
	elapsed time.Duration
	cancel  context.CancelFunc
	hook    func(elapsed time.Duration)
}

// install makes the wait of n's key@ the simulated one. The wait returns at once and moves the clock; it stops the loop
// when the simulated period is over. A signal already waiting on wake ends the wait before the clock moves, as it
// would end the real one.
func (m *sim) install(n *node) {
	n.srv.cfg.PinSleep = func(ctx context.Context, d time.Duration, w <-chan struct{}) (bool, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.hook != nil {
			m.hook(m.elapsed)
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if w != nil {
			select {
			case <-w:
				return true, nil
			default:
			}
		}
		m.waits = append(m.waits, d)
		m.elapsed += d
		m.e.clock.advance(d)
		if m.elapsed >= m.until {
			m.cancel()
			return false, context.Canceled
		}
		return false, nil
	}
}

func newSim(e *testEnv, until time.Duration) (*sim, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	return &sim{e: e, start: e.clock.now(), until: until, cancel: cancel}, ctx
}

// containsRun says whether want occurs in got as consecutive elements.
func containsRun(got, want []time.Duration) bool {
	for i := 0; i+len(want) <= len(got); i++ {
		if slices.Equal(got[i:i+len(want)], want) {
			return true
		}
	}
	return false
}

// auditFacts is what the board's lookups and key@ itself wrote: the refusals that store@ audits for the Gets that
// found nothing, and the audit facts of the key@ of each node.
func auditFacts(e *testEnv, ns ...*node) int {
	n := e.store.absentCount()
	for _, nd := range ns {
		n += len(nd.audit.all())
	}
	return n
}

// verifies: REQ-KEYS-229, REQ-KEYS-230, REQ-AUDIT-180
// One open request that this node cannot answer (its card driver is locked as well), for a simulated hour in which the
// request is made again every five minutes, as its life ends and the requester asks again. The loop looks at it, backs
// off to the longest wait, and the hour costs no refusal at store@ and no audit fact of key@: far below the bound.
func TestAnUnansweredPINRequestBacksOffAndWritesNoAuditFacts(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
	releaser, asker := bs[1], bs[2] // both locked: board-b cannot answer board-c
	m, ctx := newSim(e, time.Hour)
	m.install(releaser.n)
	releaser.n.srv.cfg.PinReleaseScale = 0 // the real periods
	var id string
	issue := time.Duration(-1)
	m.hook = func(elapsed time.Duration) {
		if issue < 0 || elapsed-issue >= 5*time.Minute { // the old request has expired; the requester asks again
			if id != "" {
				e.store.mu.Lock()
				delete(e.store.items, "|pin-release-request|"+id)
				e.store.mu.Unlock()
			}
			id, _ = request(t, e, asker, testBoundary, e.clock.now())
			issue = elapsed
		}
	}
	base := auditFacts(e, releaser.n, asker.n) // what the start cost, before the loop
	releaser.n.srv.releaseLoop(ctx)

	if got := releaser.d.sealCalls.Load(); got == 0 {
		t.Fatal("the releaser never tried the request")
	}
	got := auditFacts(e, releaser.n, asker.n) - base
	if got != 0 {
		t.Fatalf("the hour cost %d audit facts (refusals at store@ %d in all, key@ %d), want none for a request that is only waiting for an answer",
			got, e.store.absentCount(), len(releaser.n.audit.all()))
	}
	if got > pinAuditBoundPerHour {
		t.Fatalf("over the bound of %d an hour", pinAuditBoundPerHour)
	}
	// Back-off: after the pass that lists the new request (short wait) the passes that find nothing new double the wait,
	// up to pinLockedRecheck here because this node's own driver is locked (a person may unlock it unseen): 500 ms, 1 s,
	// 2 s, 2 s. The longest wait, 10 s, is for a request that is open and needs nothing from this node (the next test).
	seq := []time.Duration{pinPollFirst, 2 * pinPollFirst, pinLockedRecheck, pinLockedRecheck}
	if !containsRun(m.waits, seq) {
		t.Fatalf("the waits %v never run as the back-off %v", m.waits[:12], seq)
	}
	for _, w := range m.waits {
		if w > pinPollLongest {
			t.Fatalf("a wait of %v is over the longest %v", w, pinPollLongest)
		}
	}
	// At the short period of before (one pass per half second while a request is open) the hour made 7000 passes; the
	// bound here is one pass every 2 s (1800) plus the quick looks at the 12 requests. A pass costs no audit fact (above)
	// and the locked driver refuses before it reaches the card.
	if got, most := len(m.waits), 3600/2+12*8; got > most {
		t.Fatalf("%d passes in a simulated hour, want at most %d", got, most)
	}
	if got := releaser.d.sealCalls.Load(); got > 1900 {
		t.Fatalf("the locked driver was asked %d times in the hour, want about one try per pass", got)
	}
}

// verifies: REQ-KEYS-230
// A request that is open but needs nothing from this node, because a peer has answered it, is looked at once and then at
// the longest wait: 500 ms, 1 s, 2 s, 4 s, 8 s, 10 s, and no more than one pass every 10 s after.
func TestARequestAnsweredByAPeerBacksOffToTheLongestWait(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
	releaser, asker, other := bs[0], bs[2], bs[1] // board-a is unlocked
	_ = other
	m, ctx := newSim(e, 10*time.Minute)
	m.install(releaser.n)
	releaser.n.srv.cfg.PinReleaseScale = 0
	id, text := request(t, e, asker, testBoundary, e.clock.now())
	answerWith(t, e, "board-b", other.d, id, text, false) // a peer answered it already
	releaser.n.srv.releaseLoop(ctx)

	seq := []time.Duration{pinPollFirst, 2 * pinPollFirst, 4 * pinPollFirst, 8 * pinPollFirst, 16 * pinPollFirst, pinPollLongest, pinPollLongest}
	if !containsRun(m.waits, seq) {
		t.Fatalf("the waits %v never run as the back-off %v", m.waits[:12], seq)
	}
	if got := releaser.d.sealCalls.Load(); got != 0 {
		t.Fatalf("the driver sealed %d times for a request a peer had answered", got)
	}
	if got, most := len(m.waits), 600/10+8; got > most {
		t.Fatalf("%d passes in ten simulated minutes, want at most %d", got, most)
	}
}

// verifies: REQ-KEYS-230
// A pass that answers a request says so (PinPass.Answered), and that is progress: the next wait is the short one. The
// pass after it finds the request answered and nothing new, which is not.
func TestAnAnsweredRequestIsProgress(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
	pass, err := bs[0].n.srv.ReleasePins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !answered(e, id) || pass.Answered != 1 || !pass.Progress() {
		t.Fatalf("pass %+v: want the request answered and the pass progress", pass)
	}
	pass, err = bs[0].n.srv.ReleasePins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pass.Answered != 0 || pass.Progress() || pass.Locked {
		t.Fatalf("second pass %+v: want nothing answered, nothing new, and no progress", pass)
	}
}

// verifies: REQ-KEYS-229, REQ-AUDIT-180
// An idle board that holds its PIN: an hour of passes with no request at all costs no refusal at store@, no audit
// fact of key@ and no card signature, and the loop is at the longest wait.
func TestAnIdleUnlockedBoardWritesNoAuditFactsAndSignsNothing(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	a := bs[0] // unlocked
	m, ctx := newSim(e, time.Hour)
	m.install(a.n)
	a.n.srv.cfg.PinReleaseScale = 0
	before := a.d.signs.Load()
	base := auditFacts(e, a.n)
	a.n.srv.releaseLoop(ctx)

	if got := auditFacts(e, a.n) - base; got != 0 {
		t.Fatalf("an idle hour cost %d audit facts, want 0", got)
	}
	if got := a.d.signs.Load() - before; got != 0 {
		t.Fatalf("an idle hour made %d card signatures, want 0", got)
	}
	if got, most := len(m.waits), 3600/10+8; got > most {
		t.Fatalf("%d passes in an idle hour, want at most %d", got, most)
	}
	if last := m.waits[len(m.waits)-1]; last != pinPollLongest {
		t.Fatalf("the idle loop ends at a wait of %v, want %v", last, pinPollLongest)
	}
}

// verifies: REQ-KEYS-231
// The fast path stays. A request that arrives while the loop is in its longest wait is listed by the next pass and
// answered then: it waits no more than the longest wait, which is what an idle board always waited (a peer release of
// a few seconds). The answer comes from that pass, not from a pass a back-off later.
func TestARequestDuringALongWaitIsAnsweredWithinTheLongestWait(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	releaser, asker := bs[0], bs[1]
	m, ctx := newSim(e, 2*time.Hour)
	m.install(releaser.n)
	releaser.n.srv.cfg.PinReleaseScale = 0
	arrive := 30*time.Minute + 3*time.Second // long after the loop reached the longest wait
	var id string
	var arrived, answeredAt time.Duration
	m.hook = func(elapsed time.Duration) {
		if id == "" && elapsed >= arrive {
			id, _ = request(t, e, asker, testBoundary, e.clock.now())
			arrived = elapsed
		}
		if id != "" && answeredAt == 0 && answered(e, id) {
			answeredAt = elapsed
			m.cancel()
		}
	}
	absent0 := e.store.absentCount()
	releaser.n.srv.releaseLoop(ctx)

	if id == "" || answeredAt == 0 {
		t.Fatal("the request that arrived in the long wait was never answered")
	}
	if got := answeredAt - arrived; got > pinPollLongest {
		t.Fatalf("answered %v after it arrived, want within the longest wait %v", got, pinPollLongest)
	}
	// The release is the one audit fact, key.pin.release; no refusal at store@ for an answer that was not written yet.
	if got := releaser.n.audit.count(ActionPinRelease); got != 1 {
		t.Fatalf("%d audit facts of the release, want 1: %v", got, releaser.n.audit.all())
	}
	if got := e.store.absentCount() - absent0; got != 0 {
		t.Fatalf("%d refusals at store@ in two idle hours and one release, want none", got)
	}
}

// verifies: REQ-KEYS-232
// A node that could not answer a peer's request because it was locked too answers it at once when it can: the loop is
// woken by the unlock, with no wait of the back-off, so a board unlocked by one peer releases to the next without a
// wait of ten seconds.
func TestARequestLeftOpenIsAnsweredAtOnceWhenThisNodeUnlocks(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
	releaser, asker := bs[1], bs[2] // both locked
	m, ctx := newSim(e, time.Hour)
	m.install(releaser.n)
	releaser.n.srv.cfg.PinReleaseScale = 0
	id, _ := request(t, e, asker, testBoundary, e.clock.now())
	unlockAt := 5 * time.Minute
	var unlocked bool
	var unlockedAt, answeredAt time.Duration
	m.hook = func(elapsed time.Duration) {
		if !unlocked && elapsed >= unlockAt {
			unlocked, unlockedAt = true, elapsed
			releaser.d.mu.Lock()
			releaser.d.locked, releaser.d.held = false, []byte("123456")
			releaser.d.mu.Unlock()
			releaser.n.srv.wakeReleaser() // what the requester loop does when a PIN unlocked the node
		}
		if unlocked && answeredAt == 0 && answered(e, id) {
			answeredAt = elapsed
			m.cancel()
		}
	}
	releaser.n.srv.releaseLoop(ctx)

	if answeredAt == 0 {
		t.Fatal("the open request was not answered after the node unlocked")
	}
	if got := answeredAt - unlockedAt; got > time.Second {
		t.Fatalf("answered %v after the unlock, want at once (within the short wait)", got)
	}
}

// verifies: REQ-KEYS-229
// One pass over one open request that this node cannot answer costs no refusal at store@. Measured on the code before
// this change with the same set-up (a locked releaser, one open request of another locked board): every pass made seven
// Gets that found nothing, which store@ audits as seven failure records: the answer of the request (PinRelease), then three
// KeyRevocation ids for this node's own keys (selfRevoked) and three for the peer's (peerRevoked), none of them revoked.
func TestAPassOverAnUnanswerableRequestCostsNoRefusal(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
	request(t, e, bs[2], testBoundary, e.clock.now())
	for i := range 3 {
		before := e.store.absentCount()
		pass, err := bs[1].n.srv.ReleasePins(context.Background())
		if err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if got := e.store.absentCount() - before; got != 0 {
			t.Fatalf("pass %d made %d Gets that found nothing, each a refusal that store@ audits, want 0", i, got)
		}
		if pass.Seen != 1 || pass.Answered != 0 || (pass.New > 0) != (i == 0) {
			t.Fatalf("pass %d: %+v: want one request seen, none answered, and new only in the first pass", i, pass)
		}
	}
}
