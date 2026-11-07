//go:build sluis_test

package keyd

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

// verifies: REQ-KEYS-053
// A wrap that is copied to another address does not open there. key@ makes a data key of a tenant (a chain key) and the
// store holds its wrap. The same bytes are then put, as a flaw that lets an actor write to the store would put them,
// under the id of another tenant, under another purpose with the purpose field changed to match, and under the
// boundary: in each place key@ finds a wrap addressed to itself, tries to open it and fails, and no value is sealed or
// opened under it. The wrap at its own address still opens, which shows the refusals are about the address.
func TestAWrapCopiedToAnotherAddressDoesNotOpen(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	env, err := seal1(n.client("session"), "chain", "session-chain", "acme", vecID, []byte("facts"), nil)
	if err != nil {
		t.Fatal(err)
	}
	w := ownWrapOf(t, e, "acme", "chain", n.srv.recipient)
	id := wrapID("chain", 1, n.srv.recipient)

	// To another tenant, same purpose and id.
	e.store.put("data-key-wrap", "globex", id, w)
	_, err = seal1(n.client("session"), "chain", "session-chain", "globex", vecID, []byte("facts"), nil)
	if err == nil || connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("Seal under a wrap copied to another tenant: %v, want a refusal (internal/wrap)", err)
	}
	// Another purpose: the id and the purpose field are rewritten, as an actor that writes the store could.
	moved := proto.Clone(w).(*keyv2alpha1.DataKeyWrap)
	moved.Purpose = "pairwise"
	e.store.put("data-key-wrap", "acme", wrapID("pairwise", 1, n.srv.recipient), moved)
	_, err = n.client("session").Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "pairwise", Tenant: "acme", Label: "l", Input: []byte("x")}))
	if err == nil || connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("Mac under a wrap copied to another purpose: %v, want a refusal", err)
	}
	// To the boundary, as the cookie key.
	asCookie := proto.Clone(w).(*keyv2alpha1.DataKeyWrap)
	asCookie.Purpose = "cookie"
	e.store.put("data-key-wrap", "", wrapID("cookie", 1, n.srv.recipient), asCookie)
	_, err = seal1(n.client("session"), "cookie", "cookie", "", vecID, []byte("x"), nil)
	if err == nil || connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("Seal under a wrap copied to the boundary: %v, want a refusal", err)
	}
	// None of the three made a second key beside the copy: the wraps in the store are the four put there by the test
	// and the one key@ made.
	if got := e.store.wrapCount(); got != 4 {
		t.Fatalf("%d wraps in the store, want 4", got)
	}
	// Control: at its own address the wrap opens, after the cache is dropped so the wrap is read again.
	n.srv.cache.wipeAll()
	pt, err := open1(n.client("session"), "chain", "session-chain", "acme", vecID, env, nil)
	if err != nil || !strings.Contains(string(pt), "facts") {
		t.Fatalf("the wrap at its own address does not open: %q, %v", pt, err)
	}
}
