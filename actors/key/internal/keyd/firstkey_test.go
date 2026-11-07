//go:build sluis_test

package keyd

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

// verifies: REQ-KEYS-260
// A name that is no tenant makes no key, however it is asked for (REQ-KEYS-260). The calls are the ones that used to make
// a key on their own: Seal under chain, which is checked by rule, and Mac under pairwise; data and evidence refuse
// before the key lookup, and are in the sweep for the same reason. The tenant is a name that no config knows.
func TestANameThatIsNoTenantGetsNoKey(t *testing.T) {
	e := newTestEnv(t, "development")
	rec := &recorder{}
	n := e.startedNode(nodeOpts{audit: rec})
	const ghost = "ghost-corp"
	good := time.Minute
	type call struct {
		name string
		do   func(grant []byte) error
		op   string
	}
	seal := func(actor, purpose, kind string) func([]byte) error {
		return func(grant []byte) error {
			_, err := seal1(n.client(actor), purpose, kind, ghost, vecID, []byte("x"), grant)
			return err
		}
	}
	mac := func(grant []byte) error {
		_, err := n.client("session").Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{
			Purpose: "pairwise", Tenant: ghost, Label: "l", Input: []byte("x"), Grant: grant,
		}))
		return err
	}
	calls := []call{
		{"chain", seal("session", "chain", "session-chain"), "seal"},
		{"pairwise", mac, "mac"},
		{"data", seal("session", "data", "person"), "seal"},
		{"evidence", seal("writer", "evidence", "usage"), "seal"},
	}
	holder := map[string]string{"chain": "session", "pairwise": "session", "data": "session", "evidence": "writer"}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			// Grants are made first: the identity of a client is read when it connects.
			other := n.grant(holder[c.name], []string{"acme"}, []string{c.op}, good)
			wrongHolder := n.grant("exchange", []string{ghost}, []string{c.op}, good)
			wrongOp := n.grant(holder[c.name], []string{ghost}, []string{map[string]string{"seal": "open", "mac": "seal"}[c.op]}, good)
			expired := n.grant(holder[c.name], []string{ghost}, []string{c.op}, 5*time.Second)
			e.clock.advance(6 * time.Second)
			before, wrapsBefore := rec.count(ActionRefuse), e.store.wrapCount()
			for name, grant := range map[string][]byte{
				"no grant": nil, "another tenant's": other, "another holder's": wrongHolder, "another operation's": wrongOp, "expired": expired,
				"garbage": []byte("not a grant at all, but long enough to hold a header ............"),
			} {
				err := c.do(grant)
				wantRefusalNamed(t, c.name+" with "+name, err, connect.CodePermissionDenied, "grant")
			}
			// One refusal each, and nothing made: the count of facts is bounded by the count of calls.
			if got := rec.count(ActionRefuse) - before; got != 6 {
				t.Errorf("%d refusals for 6 calls, want one each", got)
			}
			if got := e.store.wrapCount(); got != wrapsBefore {
				t.Errorf("the wraps went from %d to %d: a name that is no tenant got a key", wrapsBefore, got)
			}
			if got := wrapPurposes(t, e)[ghost]; len(got) != 0 {
				t.Errorf("the name has keys %v", got)
			}
		})
	}
	for _, ev := range rec.all() {
		if ev.Tenant == ghost && (ev.Action == ActionDataKeyMake || ev.Action == ActionWrapWrite) {
			t.Errorf("a %s fact for a name that is no tenant", ev.Action)
		}
	}
}

// verifies: REQ-KEYS-260
// Under a grant that names the tenant, for the caller and the operation, the first key is made. Once it exists, chain
// and pairwise are used by rule alone, as before: a refresh holds no grant to seal with, and opening needs none.
func TestAGrantThatNamesTheTenantMakesItsFirstKeyAndAnExistingKeyNeedsNone(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	const tenant = "acme"
	sealGrant := n.grant("session", []string{tenant}, []string{"seal"}, time.Minute)
	macGrant := n.grant("session", []string{tenant}, []string{"mac"}, time.Minute)
	if got := wrapPurposes(t, e)[tenant]; len(got) != 0 {
		t.Fatalf("keys before any call: %v", got)
	}
	env, err := seal1(n.client("session"), "chain", "session-chain", tenant, vecID, []byte("facts"), sealGrant)
	if err != nil {
		t.Fatalf("the first chain key under a grant: %v", err)
	}
	c := n.client("session")
	m1, err := c.Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "pairwise", Tenant: tenant, Label: "l", Input: []byte("x"), Grant: macGrant}))
	if err != nil {
		t.Fatalf("the first pairwise key under a grant: %v", err)
	}
	if got := wrapPurposes(t, e)[tenant]; len(got) != 2 {
		t.Fatalf("keys after two calls = %v, want chain and pairwise", got)
	}
	// With no grant at all: the key exists, so seal, open and mac go on by rule.
	if _, err := seal1(n.client("session"), "chain", "session-chain", tenant, vecID, []byte("more"), nil); err != nil {
		t.Errorf("a seal under an existing chain key with no grant: %v", err)
	}
	if pt, err := open1(n.client("exchange"), "chain", "session-chain", tenant, vecID, env, nil); err != nil || string(pt) != "facts" {
		t.Errorf("exchange opens the chain: %q, %v", pt, err)
	}
	m2, err := n.client("session").Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "pairwise", Tenant: tenant, Label: "l", Input: []byte("x")}))
	if err != nil || string(m1.Msg.GetMac()) != string(m2.Msg.GetMac()) {
		t.Errorf("pairwise with no grant under an existing key: %v", err)
	}
	// A node that comes up with the wraps in the store, as after a restart or a restore of the store with its wraps,
	// finds the keys and needs no grant either.
	n.srv.cache.wipeAll()
	if _, err := seal1(n.client("session"), "chain", "session-chain", tenant, vecID, []byte("again"), nil); err != nil {
		t.Errorf("a seal after the cache was dropped: %v", err)
	}
	// The pseudonym key is the one exception, and is stated as one: no grant is asked for it.
	if _, err := n.client("reader").Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "pseudonym", Tenant: "other-co", Label: "l", Input: []byte("x"), Epoch: "202611"})); err != nil {
		t.Errorf("a pseudonym with no grant: %v", err)
	}
}
