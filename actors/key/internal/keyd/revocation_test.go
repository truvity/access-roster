//go:build sluis_test

package keyd

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

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
// key@ refuses a Sign with a key that KeyRevocation lists, by its kid or by its purpose, for each signing purpose it
// serves, names the target in the refusal and audits it. A revocation of another target leaves the key alone.
func TestSignWithARevokedKeyIsRefused(t *testing.T) {
	for _, purpose := range []string{"token-signing", "audit-log"} {
		for _, by := range []string{targetPurpose, targetKid} {
			t.Run(purpose+" by "+by, func(t *testing.T) {
				e := newTestEnv(t, "development")
				n := e.startedNode(nodeOpts{})
				in := signContent(t, n, purpose)
				if err := n.signFor(purpose, in); err != nil {
					t.Fatalf("a key that is not revoked signs: %v", err)
				}
				// Another target does not touch it.
				e.revoke(targetPurpose, "mac")
				e.revoke(targetKid, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
				if err := n.signFor(purpose, in); err != nil {
					t.Fatalf("a revocation of another target stopped the key: %v", err)
				}
				signed := n.driver.signs.Load()
				target := purpose
				if by == targetKid {
					target = n.srv.keys[purpose].keyID
				}
				e.revoke(by, target)
				n.refusal(t, n.signFor(purpose, in), connect.CodePermissionDenied, reasonRevoked, by)
				if got := n.driver.signs.Load(); got != signed {
					t.Fatalf("the driver signed after the revocation (%d, was %d): a revoked key must not reach it", got, signed)
				}
			})
		}
	}
}

// verifies: REQ-KEYS-109
// A revocation of a purpose refuses the keys made at or before the declaration and not a replacement made after it
// ("a replacement signs at once", ADR 0041): the old key is refused, a key the key store made later signs, and a key of
// an age the store cannot say is refused, because it cannot be shown to be a replacement.
func TestPurposeRevocationRefusesOldKeysAndNotTheReplacement(t *testing.T) {
	e := newTestEnv(t, "development")
	old := e.startedNode(nodeOpts{name: "node-1"})
	in := signContent(t, old, "token-signing")
	e.revoke(targetPurpose, "token-signing") // at the time the old key was made: not after it
	old.refusal(t, old.signFor("token-signing", in), connect.CodePermissionDenied, reasonRevoked, targetPurpose)

	// An hour later the key store has made a replacement: a node that starts with it signs, with the same revocation in force.
	e.clock.advance(time.Hour)
	repl := e.startedNode(nodeOpts{name: "node-2"})
	if err := repl.signFor("token-signing", signContent(t, repl, "token-signing")); err != nil {
		t.Fatalf("a replacement made after the revocation does not sign: %v", err)
	}
	// The old key still does not, however long after.
	e.clock.advance(24 * time.Hour)
	if err := old.signFor("token-signing", in); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("the old key signs after a day: %v", err)
	}
	// A key whose age the store cannot say is refused.
	unknown := newFakeDriver("software")
	unknown.noCreatedAt = true
	u := e.startedNode(nodeOpts{name: "node-3", driver: unknown})
	u.refusal(t, u.signFor("token-signing", signContent(t, u, "token-signing")), connect.CodePermissionDenied, reasonRevoked, targetPurpose)
	// ... but signs while nothing revokes its purpose.
	e2 := newTestEnv(t, "development")
	d2 := newFakeDriver("software")
	d2.noCreatedAt = true
	u2 := e2.startedNode(nodeOpts{driver: d2})
	if err := u2.signFor("token-signing", signContent(t, u2, "token-signing")); err != nil {
		t.Fatalf("a key of unknown age is refused although nothing is revoked: %v", err)
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
	}
}
