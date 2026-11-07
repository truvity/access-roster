//go:build sluis_test

package writerd

import (
	"os"
	"path/filepath"
	"testing"
)

// A measurement, not a requirement: the writer's own sealing feeds the next seal.
//
// Every seal asks policy for a grant (batch.go, grant), and policy writes one policy.decide record for every decision
// (actors/policy/src/service.rs; ADR 0007, "every decision is audited"). That record reaches the writer in the next batch,
// which asks for a grant again. So a log with no other input never goes quiet: one batch every BatchWindow, one policy
// decision and one audit-log signature for each. The test plays policy@'s part (one record per decision) and runs 50
// rounds from one record; ADR 0029 ("none when idle") and REQ-AUDIT-047 ("never seal an empty batch") are about an
// empty batch, and this batch is not empty. When a fix lands (a grant kept for its life, or a seal that is not needed
// for its own by-products), this test is the one to change.
//
// The test does not carry a verifies tag: it states what is, not what must be.
func TestThePolicyDecisionOfASealKeepsAnIdleWriterSealing(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	s := e.direct(t)
	const rounds = 50
	// The catalogue of the fakes lists key.sign, so it stands for the policy.decide record that policy@ writes.
	process(t, s, newMessage(t, em, "key.sign", "acme")) // the one record
	handled := 0
	for range rounds {
		decisions := len(e.pol.requests())
		var next []message
		for range decisions - handled { // what policy@ wrote for the decisions of the batch just sealed
			next = append(next, newMessage(t, em, "key.sign", "acme"))
		}
		handled = decisions
		if len(next) == 0 {
			t.Fatalf("the writer went quiet after %d rounds", handled)
		}
		process(t, s, next...)
	}
	cp, err := os.ReadFile(filepath.Join(e.logDir(), "checkpoint"))
	if err != nil || len(cp) == 0 {
		t.Fatalf("no checkpoint: %v", err)
	}
	if got := countEvents(e, "key.sign"); got != rounds+1 {
		t.Fatalf("%d audit-log signatures after %d rounds with no input but its own decisions, want %d: the loop is expected to sustain itself", got, rounds, rounds+1)
	}
	if got := len(e.pol.requests()); got != rounds+1 {
		t.Fatalf("%d decisions, want one per seal (%d)", got, rounds+1)
	}
}
