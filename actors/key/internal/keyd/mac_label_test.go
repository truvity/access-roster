//go:build sluis_test

package keyd

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The label of the refresh-token successor is session's alone. The input of that Mac is in the session chain, which
// other actors may read, so every actor that holds the rule to call Mac with the boundary key must still be refused
// this label, and keep every other.
func TestMacRefusesTheRefreshSuccessorLabelToEveryActorButSession(t *testing.T) {
	const label = "sluis-refresh-successor-v1"
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	mac := func(actor, label string) error {
		_, err := n.client(actor).Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{
			Purpose: "mac", Label: label, Input: []byte("tenant|sid|hash"),
		}))
		return err
	}
	if err := mac("session", label); err != nil {
		t.Fatalf("session: %v", err)
	}
	// The test must reach the label check for the other actors: each holds the rule for Mac on the boundary key.
	others := 0
	for _, actor := range []string{"entry", "ca", "exchange", "console", "signer", "policy", "reader", "indexer", "writer", "adapter-github"} {
		if !registry.KeyAllows(actor, registry.ScopeBoundary, "mac", "mac") {
			continue
		}
		others++
		t.Run(actor, func(t *testing.T) {
			wantRefusal(t, mac(actor, label), connect.CodePermissionDenied, "rule")
			if err := mac(actor, "link-id"); err != nil {
				t.Fatalf("another label: %v", err)
			}
		})
	}
	if others == 0 {
		t.Fatal("no other actor holds the rule for Mac on the boundary key: the test checks nothing")
	}
}
