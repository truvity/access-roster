//go:build sluis_test

package keyd

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

// The revocation check reads KeyRevocation by listing it (revocation.go, revokedIDs), where it first did a Get of one id.
// These tests hold the listing to what the Get gave: a revocation anywhere in the kind is found, and a listing that
// cannot be read to the end refuses, for a Sign and for the PIN release on both sides.

// fill puts n filler revocations whose ids sort before any real kid (their label starts with 1, which the base32 of a
// kid never does at its start), so a real revocation is on the last page of the listing.
func fill(e *testEnv, n int) {
	e.store.mu.Lock()
	e.store.listKind = "key-revocation"
	e.store.mu.Unlock()
	for i := range n {
		e.store.put("key-revocation", "", fmt.Sprintf("kid/1%07d", i), &keyv2alpha1.KeyRevocation{
			TargetKind: targetKid, Target: fmt.Sprintf("filler-%d", i), ReasonCode: "compromise", RevokedAt: timestamppb.New(e.clock.now()),
		})
	}
}

// verifies: REQ-KEYS-109
// A Sign asks the index for its own key: one listing of at most one item, however many revocations the kind holds. With
// 10,000 revocations the first Sign also takes the full listing once (50 pages of 200) for the items that the index does not
// know, and every Sign after it makes one call. A revoked key is refused by the index at once, and a key that is not revoked
// is signed.
func TestASignAsksTheIndexAndTakesTheFullListingOnce(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	in := signContent(t, n, "token-signing")
	const revocations = 10000
	fill(e, revocations)

	before := e.store.listCallCount()
	if err := n.signFor("token-signing", in); err != nil {
		t.Fatalf("a key that is not revoked, among %d revocations, was refused: %v", revocations, err)
	}
	if got, want := e.store.listCallCount()-before, 1+revocations/revocationPage; got != want {
		t.Fatalf("the first Sign made %d list calls among %d revocations, want the index and the %d pages of the full listing", got, revocations, want-1)
	}
	before = e.store.listCallCount()
	for range 5 {
		if err := n.signFor("token-signing", in); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.store.listCallCount() - before; got != 5 {
		t.Fatalf("5 Signs made %d list calls, want one each", got)
	}
	e.revoke(targetKid, n.srv.keys["token-signing"].keyID)
	signed := n.driver.signs.Load()
	before = e.store.listCallCount()
	n.refusal(t, n.signFor("token-signing", in), connect.CodePermissionDenied, reasonRevoked, targetKid)
	if got := e.store.listCallCount() - before; got != 1 {
		t.Fatalf("a revoked key cost %d list calls, want the index alone", got)
	}
	if n.driver.signs.Load() != signed {
		t.Fatal("the driver signed with a revoked key")
	}
}

// verifies: REQ-KEYS-109
// An item with no entry in the index (one an earlier key@ wrote, or a board of an older build during a rollout, or a restore
// that did not write the entry) is not missed for good: the full listing, taken again at most every ten seconds off the
// path of the Sign, finds it. Until then the Sign goes on with the last one, and a kind too long to list in time cannot stop
// a signature.
func TestAnItemWithNoEntryInTheIndexIsSeenWithinTheInterval(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	in := signContent(t, n, "token-signing")
	fill(e, 250)
	if err := n.signFor("token-signing", in); err != nil { // takes the first full listing
		t.Fatal(err)
	}
	e.revokeUnindexed(targetKid, n.srv.keys["token-signing"].keyID)
	if err := n.signFor("token-signing", in); err != nil {
		t.Fatalf("an item with no entry in the index was seen before the listing was taken again: %v", err)
	}
	e.clock.advance(unindexedEvery + time.Second)
	// The Sign that finds the listing stale starts the refresh and goes on with the last one; the next sees the new.
	_ = n.signFor("token-signing", in)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := n.signFor("token-signing", in)
		if err != nil {
			n.refusal(t, err, connect.CodePermissionDenied, reasonRevoked, targetKid)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("an item with no entry in the index was not seen after the interval")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A listing that fails keeps the last one and signs: it is logged, and the index still decides for the keys it knows.
	e2 := newTestEnv(t, "development")
	n2 := e2.startedNode(nodeOpts{})
	in2 := signContent(t, n2, "audit-log")
	fill(e2, 250)
	if err := n2.signFor("audit-log", in2); err != nil {
		t.Fatal(err)
	}
	e2.store.mu.Lock()
	e2.store.failListAt = e2.store.listCalls + 2 // the second call of the next Sign is the full listing's first page
	e2.store.mu.Unlock()
	e2.clock.advance(unindexedEvery + time.Second)
	for range 20 {
		if err := n2.signFor("audit-log", in2); err != nil {
			t.Fatalf("a full listing that failed stopped a signature: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// verifies: REQ-KEYS-109
// A listing that fails or does not end is "cannot be read", never "not revoked": the Sign is refused with the reason of an
// unreadable KeyRevocation and the driver does not sign. The failure is on the second page, after one page was read
// without a revocation of the key; a listing that does not end is stopped at the page limit.
func TestAListingThatFailsHalfWayOrDoesNotEndRefusesTheSign(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(f *fakeStore)
	}{
		{"fails on the second page", func(f *fakeStore) { f.failListAt = f.listCalls + 2 }},
		{"does not end", func(f *fakeStore) { f.endless = true }},
		{"a linearizable read is refused", func(f *fakeStore) { f.refuseLinearizable = true }}, // a leader change
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			n := e.startedNode(nodeOpts{})
			in := signContent(t, n, "audit-log")
			fill(e, 450)
			e.revokeUnindexed(targetKid, n.srv.keys["audit-log"].keyID) // in the full listing, on the page that cannot be read
			e.store.mu.Lock()
			c.set(e.store)
			e.store.mu.Unlock()
			signed := n.driver.signs.Load()
			n.refusal(t, n.signFor("audit-log", in), connect.CodeUnavailable, reasonRevocationUnreadable, "")
			if n.driver.signs.Load() != signed {
				t.Fatal("the driver signed although the revocations could not be read to the end")
			}
		})
	}
}

// verifies: REQ-KEYS-109, REQ-KEYS-114
// The same on both sides of the PIN release. The releaser, whose listing fails on the second page, answers nothing and
// reports an error. The requester, whose peer's answer is there but whose listing fails on the second page, gives
// its driver nothing: no PIN attempt is made.
func TestAnUnreadableRevocationListingStopsBothSidesOfThePINRelease(t *testing.T) {
	t.Run("releaser", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		fill(e, 450)
		id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
		e.store.mu.Lock()
		e.store.failListAt = e.store.listCalls + 2
		e.store.mu.Unlock()
		if _, err := bs[0].n.srv.ReleasePins(context.Background()); err == nil {
			t.Fatal("a pass whose revocation listing failed half way reported no error")
		}
		if answered(e, id) || bs[0].d.sealCalls.Load() != 0 {
			t.Fatal("a PIN was released although the revocations could not be read to the end")
		}
	})
	t.Run("requester", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		fill(e, 450)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- bs[1].n.srv.RequestPin(ctx) }()
		id, text := waitRequest(t, e, "board-b")
		e.store.mu.Lock()
		e.store.failListAt = e.store.listCalls + 2
		e.store.mu.Unlock()
		answerWith(t, e, "board-a", bs[0].d, id, text, false)
		err := <-done
		if err == nil || errors.Is(err, errNoAnswer) {
			t.Fatalf("RequestPin = %v, want the error of an unreadable KeyRevocation", err)
		}
		if bs[1].d.finishCalls.Load() != 0 || bs[1].d.pinTries.Load() != 0 {
			t.Fatal("the driver was given an answer although the releaser's revocations could not be read to the end")
		}
	})
}

// verifies: REQ-KEYS-233
// Every read of KeyRevocation that decides something asks for a linearizable listing, as the Get it replaced was: the
// revocation check of a Sign, the releaser's check of the requester and of itself, and the requester's check of the
// releaser. The listing of PinRelease answers is not such a read (a stale one costs a poll, and a PIN is given only for
// an answer whose signature was verified), so it keeps the default. A store that refuses the linearizable read, as in a
// leader change, fails each of them closed (the cases above) and does not answer them at a weaker level.
func TestEveryRevocationListingAsksForALinearizableRead(t *testing.T) {
	t.Run("sign", func(t *testing.T) {
		e := newTestEnv(t, "development")
		n := e.startedNode(nodeOpts{})
		in := signContent(t, n, "token-signing")
		fill(e, 1)
		for range 3 {
			if err := n.signFor("token-signing", in); err != nil {
				t.Fatal(err)
			}
		}
		if e.store.listCallCount() < 3 || e.store.weakListCount() != 0 {
			t.Fatalf("%d revocation listings, %d of them not linearizable", e.store.listCallCount(), e.store.weakListCount())
		}
	})
	t.Run("both sides of the release", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		fill(e, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- bs[1].n.srv.RequestPin(ctx) }()
		id, _ := waitRequest(t, e, "board-b")
		release(t, bs[0]) // the releaser checks the requester's keys and its own
		if !answered(e, id) {
			t.Fatal("the request was not answered")
		}
		if err := <-done; err != nil { // the requester checks the releaser's keys
			t.Fatalf("RequestPin: %v", err)
		}
		if e.store.listCallCount() < 2 { // the releaser: its own keys and the requester's in one listing; the requester: the releaser's
			t.Fatalf("only %d revocation listings for both sides", e.store.listCallCount())
		}
		if got := e.store.weakListCount(); got != 0 {
			t.Fatalf("%d of the revocation listings were not linearizable", got)
		}
	})
}
