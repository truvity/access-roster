//go:build sluis_test

package keyd

import (
	"testing"
)

// verifies: REQ-AUDIT-180
// The first start of a node, and a restart, ask store@ for nothing that is absent. The node's own wrapping certificate is
// not there at its first start, which is expected, and store@ audits the refusal of a Get for it (ADR 0005); so key@
// reads it by listing. The fake store counts the Gets that found no item (absent), each of which is one `store.refused`
// record on a board, and the first start costs none.
func TestAStartAsksStoreForNothingThatIsAbsent(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	if got := e.store.absentCount(); got != 0 {
		t.Fatalf("the first start made %d Gets of an absent item, each a refusal that store@ audits, want none", got)
	}
	if _, ok := certItems(n)[certPrefix+n.srv.recipient]; !ok {
		t.Fatal("the first start did not publish the wrapping certificate")
	}
	n.stop()

	// A restart finds the certificate and leaves it alone.
	again := e.newNode(nodeOpts{driver: n.driver, stateDir: n.srv.cfg.StateDir})
	again.start()
	if got := e.store.absentCount(); got != 0 {
		t.Fatalf("the restart made %d Gets of an absent item, want none", got)
	}
}

// verifies: REQ-AUDIT-180
// The check command reads what a start reads and asks store@ for nothing that is absent either.
func TestTheCheckAsksStoreForNothingThatIsAbsent(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	n.stop()
	before := e.store.absentCount()
	if err := e.newNode(nodeOpts{driver: n.driver, stateDir: n.srv.cfg.StateDir}).srv.Check(t.Context()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := e.store.absentCount() - before; got != 0 {
		t.Fatalf("the check made %d Gets of an absent item, want none", got)
	}
}
