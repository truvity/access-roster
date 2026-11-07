//go:build sluis_test

package keyd

import (
	"context"
	"testing"
)

// verifies: REQ-AUDIT-186
// Serve replaces the limiters of the refusals and closes the old ones on its way out. A handler that read the old limiter
// before the swap and notes its refusal after the close used to hit a closed limiter, which dropped the call and counted it
// nowhere. The call is now a fact on its own (rpc.LimiterConfig.Late), so that the emitter counts it lost if that fails.
func TestARefusalNotedAfterTheLimitersWereClosedIsStillAFact(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	held := n.srv.refusals.Load().get("exchange") // the handler's: read before the swap
	n.srv.refusals.Swap(n.srv.newRefusalLimiters()).close()

	before := n.audit.count(ActionRefuse)
	held.Note("rule", refusal1{ctx: context.Background(), caller: "exchange", op: "open", purpose: "chain", code: "PermissionDenied", reason: "rule"})
	if got := n.audit.count(ActionRefuse) - before; got != 1 {
		t.Fatalf("%d refusal facts after the close, want 1", got)
	}
	if held.Dropped() != 0 || held.Late() != 1 {
		t.Fatalf("Dropped() %d Late() %d, want 0 and 1", held.Dropped(), held.Late())
	}
}
