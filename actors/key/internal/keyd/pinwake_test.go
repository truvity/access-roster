//go:build sluis_test

package keyd

import (
	"context"
	"testing"
	"time"
)

// wakePending says whether the releasing loop has a wake-up waiting, and takes it.
func wakePending(n *node) bool {
	select {
	case <-n.srv.pins.wakeChan():
		return true
	default:
		return false
	}
}

// verifies: REQ-KEYS-232
// The requesting loop wakes the releasing loop on the production path, not through a call the test makes: when a peer's
// PIN has just unlocked the node (RequestPin returns nil), and when the driver is found unlocked, as after a person's
// unlock (ErrUnlocked), once and not again while it stays unlocked. The test runs the loop of pinLoops (requestLoop) on a
// locked board whose peer answers, with the waits replaced so that it stops after the first look.
func TestTheRequestingLoopWakesTheReleasingLoop(t *testing.T) {
	t.Run("a peer's PIN unlocked the node", func(t *testing.T) {
		_, bs := boards(t, []string{"board-a", "board-b"}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		bs[1].n.srv.cfg.PinSleep = func(ctx context.Context, _ time.Duration, _ <-chan struct{}) (bool, error) {
			calls++
			if calls == 1 { // the first poll for the answer: the unlocked peer answers
				release(t, bs[0])
				return false, nil
			}
			cancel() // the wait after RequestPin returned
			return false, ctx.Err()
		}
		bs[1].n.srv.requestLoop(ctx)
		if bs[1].d.isLocked() {
			t.Fatal("the peer's answer did not unlock the node")
		}
		if !wakePending(bs[1].n) {
			t.Fatal("the node was unlocked by a peer and the releasing loop was not woken")
		}
	})
	t.Run("found unlocked", func(t *testing.T) {
		_, bs := boards(t, []string{"board-a", "board-b"}, nil)
		bs[1].d.mu.Lock()
		bs[1].d.locked, bs[1].d.held = false, []byte("123456") // a person unlocked it
		bs[1].d.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		waits := 0
		bs[1].n.srv.cfg.PinSleep = func(ctx context.Context, _ time.Duration, _ <-chan struct{}) (bool, error) {
			waits++
			if waits == 1 {
				if !wakePending(bs[1].n) {
					t.Error("the driver was found unlocked and the releasing loop was not woken")
				}
				return false, nil // the recheck: still unlocked, and no second wake
			}
			cancel()
			return false, ctx.Err()
		}
		bs[1].n.srv.requestLoop(ctx)
		if wakePending(bs[1].n) {
			t.Fatal("a driver that stayed unlocked woke the releasing loop again")
		}
	})
}

// verifies: REQ-KEYS-234
// A board that a person unlocks by hand answers the requests that peers left open within the locked recheck, though
// nothing tells key@: its releasing loop stood at a locked driver and looks again every pinLockedRecheck, not every ten
// seconds. (The first board of a cold start is this case.)
func TestABoardUnlockedByHandAnswersWithinTheLockedRecheck(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
	releaser, asker := bs[1], bs[2] // both locked
	m, ctx := newSim(e, time.Hour)
	m.install(releaser.n)
	releaser.n.srv.cfg.PinReleaseScale = 0
	id, _ := request(t, e, asker, testBoundary, e.clock.now())
	unlockAt := 5 * time.Minute
	var unlockedAt, answeredAt time.Duration
	unlocked := false
	m.hook = func(elapsed time.Duration) {
		if !unlocked && elapsed >= unlockAt {
			unlocked, unlockedAt = true, elapsed
			releaser.d.mu.Lock() // the driver's admin socket does this; key@ is not told and nothing wakes the loop
			releaser.d.locked, releaser.d.held = false, []byte("123456")
			releaser.d.mu.Unlock()
		}
		if unlocked && answeredAt == 0 && answered(e, id) {
			answeredAt = elapsed
			m.cancel()
		}
	}
	releaser.n.srv.releaseLoop(ctx)

	if answeredAt == 0 {
		t.Fatal("the request was not answered after a person unlocked the board")
	}
	if got := answeredAt - unlockedAt; got > pinLockedRecheck {
		t.Fatalf("answered %v after the unlock, want within %v", got, pinLockedRecheck)
	}
}

// verifies: REQ-KEYS-230
// A store that never ends a listing cannot hang a pass or the requester: the listing stops at the page limit and the pass
// fails with an error (the releaser), or the wait goes on to its deadline (the requester), as for KeyRevocation.
func TestAListingOfThePINKindsThatDoesNotEndIsBounded(t *testing.T) {
	t.Run("the requests, in a releasing pass", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		request(t, e, bs[1], testBoundary, e.clock.now())
		e.store.mu.Lock()
		e.store.listKind, e.store.endless = "pin-release-request", true
		e.store.mu.Unlock()
		if _, err := bs[0].n.srv.ReleasePins(context.Background()); err == nil {
			t.Fatal("a pass over a listing that does not end reported no error")
		}
		if got := e.store.listCallCount(); got != maxPinPages {
			t.Fatalf("the pass read %d pages, want the limit %d", got, maxPinPages)
		}
	})
	t.Run("the answers, in the requester", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		e.store.mu.Lock()
		e.store.listKind, e.store.endless = "pin-release", true
		e.store.mu.Unlock()
		bs[1].n.srv.cfg.PinSleep = func(_ context.Context, d time.Duration, _ <-chan struct{}) (bool, error) {
			e.clock.advance(d + time.Minute) // the request's life runs out
			return false, nil
		}
		done := make(chan error, 1)
		go func() { done <- bs[1].n.srv.RequestPin(context.Background()) }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("RequestPin returned no error")
			}
		case <-time.After(20 * time.Second):
			t.Fatal("RequestPin hangs on a listing that does not end")
		}
	})
}

// verifies: REQ-KEYS-229
// One pass lists KeyRevocation once for all its checks, the node's own keys and the keys of every peer whose request it
// handles in the same second, and not once for each request.
func TestAPassListsTheRevocationsOnceForManyRequests(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	fill(e, 1)
	for range 5 {
		request(t, e, bs[1], testBoundary, e.clock.now())
	}
	before := e.store.listCallCount()
	pass, err := bs[0].n.srv.ReleasePins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pass.Answered != 5 {
		t.Fatalf("answered %d of 5 requests", pass.Answered)
	}
	if got := e.store.listCallCount() - before; got != 1 {
		t.Fatalf("5 requests made %d listings of KeyRevocation, want 1", got)
	}
	if got := e.store.weakListCount(); got != 0 {
		t.Fatalf("%d of them were not linearizable", got)
	}
	// The cache is the pass's own and lives one second: a pass a second later lists again.
	e.clock.advance(2 * revCacheLife)
	request(t, e, bs[1], testBoundary, e.clock.now())
	before = e.store.listCallCount()
	if _, err := bs[0].n.srv.ReleasePins(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.store.listCallCount() - before; got != 1 {
		t.Fatalf("the next pass made %d listings, want 1", got)
	}
}
