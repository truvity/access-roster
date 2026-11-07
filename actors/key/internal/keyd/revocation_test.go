//go:build sluis_test

package keyd

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// revoke puts a KeyRevocation item into the store as key@ would write it on an operator's declaration, at the time of
// the test's clock.
func (e *testEnv) revoke(kind, target string) {
	e.store.put("key-revocation", "", revocationID(kind, target), &keyv2alpha1.KeyRevocation{
		TargetKind: kind, Target: target, ReasonCode: "compromise", RevokedAt: timestamppb.New(e.clock.now()),
	})
}

func (n *node) signFor(purpose string, content []byte) error {
	actor := "signer"
	if purpose == "audit-log" {
		actor = "writer"
	}
	_, err := n.client(actor).Sign(context.Background(), signReq(purpose, content))
	return err
}

func signContent(t *testing.T, n *node, purpose string) []byte {
	t.Helper()
	if purpose == "audit-log" {
		return []byte("example.test/log\n7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	}
	_, kid := publicKey(t, n, "signer", purpose)
	return tokenInput(kid, "", "")
}

func (n *node) refusal(t *testing.T, err error, code connect.Code, reason, path string) {
	t.Helper()
	if connect.CodeOf(err) != code {
		t.Fatalf("Sign = %v, want code %v", err, code)
	}
	if got, _ := refusal.Reason(err); got != reason {
		t.Fatalf("reason = %q, want %q", got, reason)
	}
	if got, _ := refusal.FieldPath(err); got != path {
		t.Fatalf("path = %q, want %q", got, path)
	}
	for _, ev := range n.audit.all() {
		if ev.Action == ActionRefuse && ev.Reason == reason && ev.Fields["path"] == path {
			return
		}
	}
	t.Fatalf("the refusal (%s, %s) is not an audit fact", reason, path)
}

// verifies: REQ-KEYS-109
// key@ refuses a Sign with a key that KeyRevocation lists by its kid, for each signing purpose it serves, names the
// target in the refusal and audits it. A revocation of another key leaves the key alone.
func TestSignWithARevokedKeyIsRefused(t *testing.T) {
	for _, purpose := range []string{"token-signing", "audit-log"} {
		t.Run(purpose, func(t *testing.T) {
			e := newTestEnv(t, "development")
			n := e.startedNode(nodeOpts{})
			in := signContent(t, n, purpose)
			if err := n.signFor(purpose, in); err != nil {
				t.Fatalf("a key that is not revoked signs: %v", err)
			}
			// Another key does not touch it.
			e.revoke(targetKid, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			if err := n.signFor(purpose, in); err != nil {
				t.Fatalf("a revocation of another key stopped the key: %v", err)
			}
			signed := n.driver.signs.Load()
			e.revoke(targetKid, n.srv.keys[purpose].keyID)
			n.refusal(t, n.signFor(purpose, in), connect.CodePermissionDenied, reasonRevoked, targetKid)
			if got := n.driver.signs.Load(); got != signed {
				t.Fatalf("the driver signed after the revocation (%d, was %d): a revoked key must not reach it", got, signed)
			}
		})
	}
}

// verifies: REQ-KEYS-229
// A Sign of a key that is not revoked costs store@ no refusal. Before this change the check was a Get of the key's id in
// KeyRevocation, which finds nothing for nearly every Sign, and store@ audits every refusal (ADR 0005): each audit
// checkpoint the writer asked for left a failure record that the writer then had to seal in the next checkpoint.
func TestASignOfAKeyThatIsNotRevokedCostsNoRefusal(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	in := signContent(t, n, "audit-log")
	before := e.store.absentCount()
	for range 20 {
		if err := n.signFor("audit-log", in); err != nil {
			t.Fatalf("a key that is not revoked signs: %v", err)
		}
	}
	if got := e.store.absentCount() - before; got != 0 {
		t.Fatalf("20 Signs made %d Gets that found nothing, each a refusal that store@ audits, want 0", got)
	}
}

// verifies: REQ-KEYS-109
// A KeyRevocation that cannot be read refuses the Sign and the refusal is audited with its own reason: "not revoked" is
// verified, never assumed (fail closed), so a store@ outage stops token signing and audit checkpoints.
func TestSignRefusesWhenTheRevocationsCannotBeRead(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	in := signContent(t, n, "token-signing")
	e.store.mu.Lock()
	e.store.failKind = "key-revocation"
	e.store.mu.Unlock()
	err := n.signFor("token-signing", in)
	n.refusal(t, err, connect.CodeUnavailable, reasonRevocationUnreadable, "")
	if n.driver.signs.Load() != 0 {
		t.Fatal("the driver signed although the revocations could not be read")
	}
	// The outage ends and the key signs again.
	e.store.mu.Lock()
	e.store.failKind = ""
	e.store.mu.Unlock()
	if err := n.signFor("token-signing", in); err != nil {
		t.Fatalf("Sign after the outage: %v", err)
	}
}

// verifies: REQ-KEYS-109
// The id of a revocation item for a kid or a recipient is the lower-case base32 of its thumbprint, as the shared vectors
// say, which the readers in Rust (entry, exporter@, ca) derive the same way.
func TestRevocationIDsFollowTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/testdata/keyrevocation/ids.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		IDs []struct {
			TargetKind string `json:"target_kind"`
			Target     string `json:"target"`
			ID         string `json:"id"`
			IndexValue string `json:"index_value"`
		} `json:"ids"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.IDs) < 10 {
		t.Fatalf("%d vectors: a sweep over nothing proves nothing", len(f.IDs))
	}
	for _, v := range f.IDs {
		var got string
		switch v.TargetKind {
		case "kid", "recipient":
			got = v.TargetKind + "/" + recipientLabel(v.Target)
		default:
			got = v.TargetKind + "/" + v.Target
		}
		if got != v.ID || strings.ContainsAny(got, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Errorf("%s %s: id %q, want %q", v.TargetKind, v.Target, got, v.ID)
		}
		if iv := string(targetIndexValue(v.TargetKind, v.Target)); iv != v.IndexValue || v.IndexValue == "" {
			t.Errorf("%s %s: index value %q, want %q", v.TargetKind, v.Target, iv, v.IndexValue)
		}
	}
}
