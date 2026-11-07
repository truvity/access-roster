//go:build sluis_test

package keyd

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

// verifies: REQ-ISO-066
// T-18, the holder's own check alone: a grant that policy sealed in one boundary is presented to key@ of another, and is
// refused, whoever presents it and whatever it is for. Two boundaries each have their own key@ and so their own grant
// data key. The grant is a real one: it opens in its own boundary, for its own holder, tenant and operation, which is the
// control; at the other boundary it is refused both where a signing actor opens it (OpenGrant) and where an actor spends
// it (the grant check of a Seal and an Open), because the other key@ cannot open it under its own boundary's grant data
// key. A grant that names the other boundary in its own text is refused when policy tries to seal it.
func TestAGrantOfAnotherBoundaryIsNotOpenedUnderThisBoundarysGrantKey(t *testing.T) {
	envA, envB := newTestEnv(t, "development"), newTestEnv(t, "development")
	a, b := envA.startedNode(nodeOpts{}), envB.startedNode(nodeOpts{})
	sealedInA := a.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	sealedInB := b.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)

	openGrant := func(n *node, actor string, sealed []byte) error {
		_, err := n.client(actor).OpenGrant(context.Background(), connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: sealed}))
		return err
	}
	// The control: each grant opens in the boundary that sealed it, for the actors that verify a grant.
	for _, actor := range []string{"signer", "store"} {
		if err := openGrant(a, actor, sealedInA); err != nil {
			t.Fatalf("%s: the grant of boundary A was refused in boundary A: %v", actor, err)
		}
		if err := openGrant(b, actor, sealedInB); err != nil {
			t.Fatalf("%s: the grant of boundary B was refused in boundary B: %v", actor, err)
		}
	}
	// The grant of A, presented to B.
	for _, actor := range []string{"signer", "store", "ca"} {
		wantRefusalNamed(t, actor+" opens A's grant in B", openGrant(b, actor, sealedInA), connect.CodePermissionDenied, "grant")
	}
	_, err := seal1(b.client("session"), "data", "person", "acme", vecID, []byte("x"), sealedInA)
	wantRefusalNamed(t, "a Seal in B with A's grant", err, connect.CodePermissionDenied, "grant")
	// Not a refusal of the holder or the tenant: the same Seal with B's own grant is let through.
	if _, err := seal1(b.client("session"), "data", "person", "acme", vecID, []byte("x"), sealedInB); err != nil {
		t.Fatalf("the Seal with B's own grant was refused: %v", err)
	}
	env, err := seal1(a.client("session"), "data", "person", "acme", vecID, []byte("x"), sealedInA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = open1(b.client("session"), "data", "person", "acme", vecID, env, sealedInA)
	wantRefusalNamed(t, "an Open in B with A's grant", err, connect.CodePermissionDenied, "grant")
	// A grant whose own text names another boundary is not sealed at all.
	g := grantProto("session", []string{"acme"}, a.e.clock.now(), time.Minute)
	g.Boundary = "env-b"
	_, err = a.client("policy").SealGrant(context.Background(), connect.NewRequest(&keyv2alpha1.SealGrantRequest{Grant: g}))
	wantRefusal(t, err, connect.CodeInvalidArgument, "schema")
}
