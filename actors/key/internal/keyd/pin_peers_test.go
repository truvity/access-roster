//go:build sluis_test

package keyd

import (
	"context"
	"slices"
	"testing"
	"time"
)

// unlockedByHand gives a board's fake driver the PIN, as `sluis node unlock` would.
func unlockedByHand(b *board) {
	b.d.mu.Lock()
	defer b.d.mu.Unlock()
	b.d.locked = false
	b.d.held = []byte("123456")
}

// waitUnlocked waits for a board's driver to hold the PIN and says whether it did within the time.
func waitUnlocked(b *board, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for b.d.isLocked() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

// verifies: REQ-KEYS-117
// A locked key@ unlocks from the PinRelease of any one listed, unrevoked, unlocked peer that is reachable, and no peer in
// particular is required. Three boards are listed in the KeyPlan. In each run board-c is locked and restarts alone with
// the PIN given to nobody; of the other two, one is unlocked and one is not the one that answers: in the first run the
// unlocked board-a is down (its key@ never runs, as a board that is off), so board-b answers; in the second board-b is
// down, so board-a answers; in the third board-b is locked as well and can answer nobody, and board-a answers. In every
// run the PIN is tried once, the answer names the peer that gave it, the peer that was down gave none, and no fact holds
// the PIN.
//
// The locked board-b of the third run is not served. Served, its own request would be answered by board-a, and from
// then on it holds the PIN and is an unlocked peer like any other, which may answer board-c before board-a does (the
// test used to fail on that, about one run in six under load: board-b audited its unlock, then its release). What the
// run is about is the board that is locked: so a pass of its releasing side is made by hand, after board-c's request is
// written and before board-a runs, and must answer nothing: the driver is asked, refuses (locked), and the request is
// left to the peers. Then board-a runs and answers.
func TestALockedBoardUnlocksFromAnyOneUnlockedPeer(t *testing.T) {
	type run struct {
		name     string
		down     int // index of the board that is off, or -1
		unlocked []int
		byHand   int // index of a locked board that is listed and not served, or -1: see above
		releaser int // the board that must have answered
	}
	for _, r := range []run{
		{"board-a is off, board-b answers", 0, []int{0, 1}, -1, 1},
		{"board-b is off, board-a answers", 1, []int{0, 1}, -1, 0},
		{"board-b is locked and answers nobody, board-a answers", -1, []int{0}, 1, 0},
	} {
		t.Run(r.name, func(t *testing.T) {
			e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
			for _, i := range r.unlocked {
				unlockedByHand(bs[i])
			}
			serve := func(except ...int) {
				for i, b := range bs {
					if i != r.down && i != r.byHand && !slices.Contains(except, i) {
						b.n.start()
					}
				}
			}
			if r.byHand < 0 {
				serve()
			} else {
				// board-c asks while the only listed board that could answer is locked: it must answer nobody.
				bs[2].n.start()
				id, _ := waitRequest(t, e, bs[2].name)
				locked := bs[r.byHand]
				pass, err := locked.n.srv.ReleasePins(context.Background())
				if err != nil {
					t.Fatalf("the locked %s's pass: %v", locked.name, err)
				}
				if !pass.Locked || pass.Answered != 0 || answered(e, id) {
					t.Fatalf("the locked %s: pass %+v, request answered %v; want it to stop at the request and answer nothing", locked.name, pass, answered(e, id))
				}
				if got := locked.d.sealCalls.Load(); got != 1 {
					t.Fatalf("the locked %s's driver was asked to seal %d times, want 1 (asked, and refused)", locked.name, got)
				}
				serve(2)
			}
			if !waitUnlocked(bs[2], 15*time.Second) {
				t.Fatalf("board-c is still locked; refusals a=%v b=%v c=%v", refusedWhy(bs[0].n), refusedWhy(bs[1].n), refusedWhy(bs[2].n))
			}
			if got := bs[2].d.pinTries.Load(); got != 1 {
				t.Fatalf("%d PIN attempts, want 1", got)
			}
			deadline := time.Now().Add(5 * time.Second)
			for bs[2].n.audit.count(ActionPinUnlock) != 1 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			var unlock Event
			for _, ev := range bs[2].n.audit.all() {
				if ev.Action == ActionPinUnlock {
					unlock = ev
				}
			}
			if want := bs[r.releaser].name; unlock.Fields["releaser"] != want {
				t.Fatalf("board-c was unlocked by %v, want %s", unlock.Fields["releaser"], want)
			}
			if r.down >= 0 {
				if n := bs[r.down].n.audit.count(ActionPinRelease); n != 0 {
					t.Fatalf("the board that is off released %d PINs", n)
				}
			}
			if n := bs[r.releaser].n.audit.count(ActionPinRelease); n < 1 {
				t.Fatalf("the releaser audited %d releases", n)
			}
			if r.byHand >= 0 {
				if n := bs[r.byHand].n.audit.count(ActionPinRelease); n != 0 || !bs[r.byHand].d.isLocked() {
					t.Fatalf("the locked board audited %d releases and is locked: %v", n, bs[r.byHand].d.isLocked())
				}
			}
		})
	}
}

// verifies: REQ-KEYS-118
// A locked key@ keeps asking its peers for the PIN, with a bounded backoff, for as long as it is locked and no card has
// refused a released PIN. Board-c is locked, its two peers are listed and do not run. Over a simulated quarter of an hour
// (the request lives five minutes, so it is made three times) it stays locked and asks again: the waits inside one
// request double from 500 ms and stop at 10 s, and no wait is longer. Then a peer comes up unlocked and answers the
// request that is open: board-c unlocks with no restart and with one PIN attempt. The second half of the row, the one
// deliberate stop, is the test of a card that refuses a released PIN (TestARefusedReleasedPINIsNotAskedForAgain).
func TestALockedBoardKeepsAskingUntilAPeerAnswers(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
	asker := bs[2]
	m, ctx := newSim(e, 30*time.Minute)
	m.install(asker.n)
	asker.n.srv.cfg.PinReleaseScale = 0 // the real periods
	peerCame := false
	var requests int
	m.hook = func(elapsed time.Duration) {
		e.store.mu.Lock()
		requests = 0
		for k := range e.store.items {
			if len(k) > len("|pin-release-request|") && k[:len("|pin-release-request|")] == "|pin-release-request|" {
				requests++
			}
		}
		e.store.mu.Unlock()
		if elapsed >= 15*time.Minute && !peerCame {
			peerCame = true
			// A peer that was off comes up and answers what is open.
			if _, err := bs[0].n.srv.ReleasePins(context.Background()); err != nil {
				t.Errorf("the peer's pass: %v", err)
			}
		}
		if peerCame && !asker.d.isLocked() {
			m.cancel()
		}
	}
	asker.n.srv.requestLoop(ctx)

	if !peerCame {
		t.Fatalf("the simulated period ended before the quarter of an hour: %v", m.elapsed)
	}
	if asker.d.isLocked() {
		t.Fatalf("board-c is still locked after a peer answered; refusals %v", refusedWhy(asker.n))
	}
	if got := asker.d.pinTries.Load(); got != 1 {
		t.Fatalf("%d PIN attempts, want 1", got)
	}
	if requests < 3 {
		t.Fatalf("%d requests in a quarter of an hour, want it asked again at least three times", requests)
	}
	doubling := []time.Duration{pinPollFirst, 2 * pinPollFirst, 4 * pinPollFirst, 8 * pinPollFirst, 16 * pinPollFirst, pinPollLongest, pinPollLongest}
	if !containsRun(m.waits, doubling) {
		t.Fatalf("the waits %v never run as the backoff %v", m.waits[:12], doubling)
	}
	for _, w := range m.waits {
		if w > pinPollLongest {
			t.Fatalf("a wait of %v is over the longest %v", w, pinPollLongest)
		}
	}
}
