//go:build sluis_test

package keyd

import (
	"context"
	"testing"
)

// note puts a refusal on the limiter as a handler's refuse does.
func note(l interface{ Note(string, any) }, caller string) {
	l.Note("rule", refusal1{ctx: context.Background(), caller: caller, op: "open", purpose: "chain", code: "PermissionDenied", reason: "rule"})
}

// verifies: REQ-AUDIT-186
// Serve closes the limiters of the refusals on its way out. A handler that had read a limiter before the close and notes its
// refusal after it used to hit a closed limiter, which dropped the call and counted it nowhere. The call is now a fact on its
// own (rpc.LimiterConfig.Late), so that the emitter counts it lost if that fails.
func TestARefusalNotedAfterTheLimitersWereClosedIsStillAFact(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	reg := n.srv.refusals.Load()
	held := reg.get("exchange") // the handler's: read before the close
	reg.close()

	before := n.audit.count(ActionRefuse)
	note(held, "exchange")
	if got := n.audit.count(ActionRefuse) - before; got != 1 {
		t.Fatalf("%d refusal facts after the close, want 1", got)
	}
	if held.Dropped() != 0 || held.Late() != 1 {
		t.Fatalf("Dropped() %d Late() %d, want 0 and 1", held.Dropped(), held.Late())
	}
}

// verifies: REQ-AUDIT-186
// The registry that Serve leaves is closed, and a caller that had no limiter when it closed gets none that is open: its limiter
// is made after the close and nobody would close it, so what it counted would be lost when the process ends. It gets the
// closed one, and its refusal is a fact on its own.
func TestACallerWithNoLimiterBeforeTheCloseGetsAClosedOne(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{refusalBurst: 1}) // an open limiter would report the first refusal and count the rest
	reg := n.srv.refusals.Load()
	reg.close()
	reg.close() // twice is once

	for _, caller := range []string{"signer", "policy", "admin", "not-a-caller"} {
		before := n.audit.count(ActionRefuse)
		l := reg.get(caller)
		for range 3 {
			note(l, caller)
		}
		if got := n.audit.count(ActionRefuse) - before; got != 3 {
			t.Fatalf("%s: %d refusal facts after the close, want 3 (each is a fact; a limiter that is open would keep one and count two that nobody reports)", caller, got)
		}
		if l.Dropped() != 0 {
			t.Fatalf("%s: Dropped() = %d", caller, l.Dropped())
		}
	}
}

// A Serve that follows one that ended starts with limiters that are open: a refusal is rate limited again.
func TestAServeAfterAServeStartsWithOpenLimiters(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	n.stop() // Serve ends and closes the registry
	if !n.srv.refusals.Load().isClosed() {
		t.Fatal("the registry is open after Serve ended")
	}
	n.start() // Init and Serve again
	if n.srv.refusals.Load().isClosed() {
		t.Fatal("the registry is closed in the second Serve")
	}
}
