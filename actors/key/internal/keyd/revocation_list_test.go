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
// A revocation on the last page of a long listing is found. With 10,000 revocations, a page of 200, a key that is
// revoked is refused and a key that is not revoked is signed, and the Sign reads all 50 pages either way: this is the
// cost of the listing, one call per 200 revocations, where the Get cost one call.
func TestARevocationOnALaterPageIsFound(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	in := signContent(t, n, "token-signing")
	const revocations = 10000
	fill(e, revocations)

	before := e.store.listCallCount()
	if err := n.signFor("token-signing", in); err != nil {
		t.Fatalf("a key that is not revoked, among %d revocations, was refused: %v", revocations, err)
	}
	if got, want := e.store.listCallCount()-before, revocations/revocationPage; got != want {
		t.Fatalf("a Sign read %d pages of %d revocations, want %d", got, revocations, want)
	}
	e.revoke(targetKid, n.srv.keys["token-signing"].keyID) // sorts after the fillers: the last page
	signed := n.driver.signs.Load()
	n.refusal(t, n.signFor("token-signing", in), connect.CodePermissionDenied, reasonRevoked, targetKid)
	if n.driver.signs.Load() != signed {
		t.Fatal("the driver signed with a key that is revoked on the last page")
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
			e.revoke(targetKid, n.srv.keys["audit-log"].keyID) // on the page that cannot be read
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
		if e.store.listCallCount() < 3 { // the releaser: its own keys and the requester's; the requester: the releaser's
			t.Fatalf("only %d revocation listings for both sides", e.store.listCallCount())
		}
		if got := e.store.weakListCount(); got != 0 {
			t.Fatalf("%d of the revocation listings were not linearizable", got)
		}
	})
}
