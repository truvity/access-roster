//go:build sluis_test

package keyd

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// revoke puts a KeyRevocation item into the store as key@ would write it on an operator's declaration.
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

// verifies: REQ-KEYS-109
// key@ refuses a Sign with a key that KeyRevocation lists, by the purpose or by the kid of the key, for each signing
// purpose it serves, and audits the refusal. A revocation of another target leaves the key alone.
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
				err := n.signFor(purpose, in)
				if connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Fatalf("Sign with a revoked key = %v, want permission_denied", err)
				}
				if reason, _ := refusal.Reason(err); reason != reasonRevoked {
					t.Fatalf("reason = %q, want %q", reason, reasonRevoked)
				}
				var audited bool
				for _, ev := range n.audit.all() {
					if ev.Action == ActionRefuse && ev.Reason == reasonRevoked && ev.Fields["purpose"] == purpose {
						audited = true
					}
				}
				if !audited {
					t.Fatal("the refusal is not an audit fact")
				}
				if got := n.driver.signs.Load(); got != signed {
					t.Fatalf("the driver signed after the revocation (%d, was %d): a revoked key must not reach it", got, signed)
				}
			})
		}
	}
}

// verifies: REQ-KEYS-109
// A KeyRevocation that cannot be read refuses the Sign: "not revoked" is verified, never assumed (fail closed).
func TestSignRefusesWhenTheRevocationsCannotBeRead(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	in := signContent(t, n, "token-signing")
	e.store.mu.Lock()
	e.store.failKind = "key-revocation"
	e.store.mu.Unlock()
	err := n.signFor("token-signing", in)
	if connect.CodeOf(err) != connect.CodeUnavailable || !strings.Contains(err.Error(), reasonStore) {
		t.Fatalf("Sign with an unreadable KeyRevocation = %v, want unavailable/%s", err, reasonStore)
	}
	if n.driver.signs.Load() != 0 {
		t.Fatal("the driver signed although the revocations could not be read")
	}
}
