//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// eraseWrapsExcept deletes the wraps of the tenant whose purpose is not keep, as a tenant's exit does to the data,
// pseudonym, pairwise and chain wraps (ADR 0006, "Erasing a tenant"); the evidence wrap stays until the evidence
// retention ends. It returns how many it deleted. The exit itself is not built (REQ-KEYS-036): this is its effect on
// the store.
func (f *fakeStore) eraseWrapsExcept(tenant, keep string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, it := range f.items {
		a := it.GetAddress()
		if a.GetKind() != "data-key-wrap" || a.GetTenant() != tenant {
			continue
		}
		if p, _, _, ok := parseWrapID(a.GetId()); ok && p != keep {
			delete(f.items, k)
			n++
		}
	}
	return n
}

// sealBy and openBy make the client after the grant is made: the identity is read per connection, and a grant is
// made through policy's connection.
func sealBy(n *node, actor, purpose, kind, tenant, id string, pt, grant []byte) ([]byte, error) {
	return seal1(n.client(actor), purpose, kind, tenant, id, pt, grant)
}

func openBy(n *node, actor, purpose, kind, tenant, id string, env, grant []byte) ([]byte, error) {
	return open1(n.client(actor), purpose, kind, tenant, id, env, grant)
}

// Only the writer may use the key of an audit log (ADR 0029). The registry gives no other actor a right to it, in
// either scope and for any operation, and key@ refuses every other caller that can reach it, with the rule, before it
// looks at the content. The writer gets the public key and a signature over a checkpoint body.
//
// What this does not show is the "instance" of the statement: the rules name actors, so two writer instances on one
// key@ would share the key. A board has one key@ and one writer per node, and a cloud key is made per writer instance
// in its own account; neither is a rule of key@.
//
// verifies: REQ-AUDIT-041
func TestOnlyTheWriterMayUseTheAuditLogKey(t *testing.T) {
	ops := []string{"seal", "open", "sign", "mac", "public-key", "wrap", "unwrap"}
	var allowed []string
	seen := 0
	for _, act := range registry.Actors() {
		seen++
		for _, scope := range []string{registry.ScopeBoundary, registry.ScopeTenant} {
			for _, op := range ops {
				if !registry.KeyAllows(act.Name, scope, "audit-log", op) {
					continue
				}
				allowed = append(allowed, act.Name+" "+scope+" "+op)
				if act.Name != "writer" || scope != registry.ScopeBoundary || (op != "sign" && op != "public-key") {
					t.Errorf("registry: %s may %s the audit-log key in scope %s", act.Name, op, scope)
				}
			}
		}
	}
	if seen < 10 {
		t.Fatalf("%d actors: the sweep checked nothing", seen)
	}
	if len(allowed) != 2 {
		t.Fatalf("the writer's rights on the audit-log key = %v, want sign and public-key", allowed)
	}

	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	ctx := context.Background()
	body := []byte("example.com/log\n7\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	pub, kid := publicKey(t, n, "writer", "audit-log")
	if res, err := n.client("writer").Sign(ctx, signReq("audit-log", body)); err != nil || res.Msg.GetKeyId() != kid || pub == nil {
		t.Fatalf("the writer's Sign = %v, %v", res, err)
	}
	refused := 0
	for _, c := range registry.CallersOf("key") {
		if c == "writer" {
			continue
		}
		_, err := n.client(c).Sign(ctx, signReq("audit-log", body))
		wantRefusal(t, err, connect.CodePermissionDenied, "rule")
		_, err = n.client(c).PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "audit-log"}))
		wantRefusal(t, err, connect.CodePermissionDenied, "rule")
		refused++
	}
	if refused < 5 {
		t.Fatalf("%d other callers refused: the sweep checked nothing", refused)
	}
}

// The writer has key@ seal every audit entry under the tenant's evidence key, and never under its data key
// (ADR 0029). A tenant's data key does not open an entry, even when the header of the envelope is changed to say
// data, and the evidence key opens it. When the tenant exits, its personal wraps are deleted and the data sealed
// under them stops opening, and the entries still open under the evidence key.
//
// This is key@'s half of the row; the writer's half, that it asks for the evidence purpose for every record and for a
// refused message alike, is TestEveryEntryIsSealedUnderTheTenantsEvidenceKey in writerd. The retention end that
// finally deletes the evidence wrap is REQ-KEYS-037 and is not built, so the entries open here for as long as the
// wrap stays.
//
// verifies: REQ-AUDIT-150
func TestAnAuditEntryOpensUnderTheEvidenceKeyAndNeverTheDataKey(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	const uid = vecID
	record := []byte(`{"metadata":{"uid":"u1"}}`)

	// The writer seals the entry under the evidence key of the tenant, with its grant.
	entry, err := sealBy(a, "writer", "evidence", "audit-record", "acme", uid, record,
		a.grant("writer", []string{"acme"}, []string{"seal"}, time.Minute))
	if err != nil {
		t.Fatalf("the writer's Seal under evidence: %v", err)
	}
	if bytes.Contains(entry, record) || bytes.Contains(entry, []byte("u1")) {
		t.Fatal("the sealed entry holds the record in clear")
	}
	h, err := envelope.ParseHeader(entry)
	evCode, _ := envelope.Code("evidence")
	dataCode, _ := envelope.Code("data")
	if err != nil || h.Purpose != evCode || h.Purpose == dataCode {
		t.Fatalf("the entry's header says purpose %d (evidence %d, data %d): %v", h.Purpose, evCode, dataCode, err)
	}

	// The writer cannot seal under the data key, with a grant that names the tenant, and has no Open at all.
	_, err = sealBy(a, "writer", "data", "audit-record", "acme", uid, record,
		a.grant("writer", []string{"acme"}, []string{"seal"}, time.Minute))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	_, err = openBy(a, "writer", "evidence", "audit-record", "acme", uid, entry,
		a.grant("writer", []string{"acme"}, []string{"open"}, time.Minute))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")

	// The tenant's data key exists, and opens its own values.
	secret := []byte("a person's name")
	person, err := sealBy(a, "session", "data", "person", "acme", uid, secret,
		a.grant("session", []string{"acme"}, []string{"seal"}, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	dg := func() []byte { return a.grant("session", []string{"acme"}, []string{"open"}, time.Minute) }
	if pt, err := openBy(a, "session", "data", "person", "acme", uid, person, dg()); err != nil || !bytes.Equal(pt, secret) {
		t.Fatalf("the data key does not open its own value: %q, %v", pt, err)
	}
	// It does not open the entry: not as data, and not with the header of the entry changed to say data, which would
	// try the data key on the entry.
	_, err = openBy(a, "session", "data", "audit-record", "acme", uid, entry, dg())
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	forged := bytes.Clone(entry)
	forged[1] = dataCode
	_, err = openBy(a, "session", "data", "audit-record", "acme", uid, forged, dg())
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	// The entry's key is the evidence key: another reader of the evidence opens it under the evidence grant.
	eg := func() []byte { return a.grant("indexer", []string{"acme"}, []string{"open"}, time.Minute) }
	if pt, err := openBy(a, "indexer", "evidence", "audit-record", "acme", uid, entry, eg()); err != nil || !bytes.Equal(pt, record) {
		t.Fatalf("the evidence key does not open the entry: %q, %v", pt, err)
	}

	// The tenant exits: its data, pseudonym, pairwise and chain wraps are deleted, and the node starts again with an
	// empty cache. The person's value no longer opens; the entry still does.
	if got := e.store.eraseWrapsExcept("acme", "evidence"); got == 0 {
		t.Fatal("the tenant had no personal wraps to erase")
	}
	a.stop()
	b := e.startedNode(nodeOpts{name: "node-1", driver: a.driver})
	_, err = openBy(b, "session", "data", "person", "acme", uid, person,
		b.grant("session", []string{"acme"}, []string{"open"}, time.Minute))
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	if pt, err := openBy(b, "indexer", "evidence", "audit-record", "acme", uid, entry,
		b.grant("indexer", []string{"acme"}, []string{"open"}, time.Minute)); err != nil || !bytes.Equal(pt, record) {
		t.Fatalf("after the exit the entry does not open under the evidence key: %q, %v", pt, err)
	}
}

// The indexer opens a record at key@ only under a grant, and it only opens (ADR 0028): with no grant, with a grant that
// has expired, with a grant made for another holder or tenant or for another operation, key@ opens nothing and
// refuses with the grant; and a Seal by the indexer is refused by the rule, with a seal grant as well as without.
//
// key@ judges only the grant it is shown. That the indexer asks policy for it, and when, is the indexer's half (tests
// of actors/indexer): the grant is kept for its life and asked for again when key@ finds it expired.
//
// verifies: REQ-AUDIT-160
func TestTheIndexerOpensUnderAGrantAndSealsNothing(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	record := []byte("a record")
	entry, err := sealBy(n, "writer", "evidence", "audit-record", "acme", vecID, record,
		n.grant("writer", []string{"acme"}, []string{"seal"}, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	open := func(grant []byte) ([]byte, error) {
		return openBy(n, "indexer", "evidence", "audit-record", "acme", vecID, entry, grant)
	}
	if pt, err := open(n.grant("indexer", []string{"acme"}, []string{"open"}, time.Minute)); err != nil || !bytes.Equal(pt, record) {
		t.Fatalf("a good grant: %q, %v", pt, err)
	}
	short := n.grant("indexer", []string{"acme"}, []string{"open"}, 10*time.Second)
	if _, err := open(short); err != nil {
		t.Fatalf("a fresh short grant: %v", err)
	}
	for name, g := range map[string][]byte{
		"no grant":                        nil,
		"a grant for another tenant":      n.grant("indexer", []string{"globex"}, []string{"open"}, time.Minute),
		"a grant for seal only":           n.grant("indexer", []string{"acme"}, []string{"seal"}, time.Minute),
		"a grant made for the writer":     n.grant("writer", []string{"acme"}, []string{"open"}, time.Minute),
		"garbage in the place of a grant": []byte("not a grant"),
	} {
		pt, err := open(g)
		wantRefusalNamed(t, name, err, connect.CodePermissionDenied, "grant")
		if pt != nil {
			t.Errorf("%s: key@ opened the entry", name)
		}
	}
	e.clock.advance(10 * time.Second)
	pt, err := open(short)
	wantRefusalNamed(t, "an expired grant", err, connect.CodePermissionDenied, "grant")
	if pt != nil {
		t.Error("an expired grant opened the entry")
	}

	// The indexer never seals: the rule refuses, whatever grant it brings, for evidence and for data.
	for _, c := range []struct{ purpose, name string }{{"evidence", "evidence"}, {"data", "data"}} {
		for gname, g := range map[string][]byte{
			"no grant":   nil,
			"seal grant": n.grant("indexer", []string{"acme"}, []string{"seal"}, time.Minute),
		} {
			_, err := sealBy(n, "indexer", c.purpose, "audit-record", "acme", vecID, record, g)
			wantRefusalNamed(t, "seal under "+c.name+" with "+gname, err, connect.CodePermissionDenied, "rule")
		}
	}
}

// A value sealed under a tenant's data or evidence key is readable only when the store's rule and key@'s grant check
// both allow it (ADR 0007). The two checks are in different holders, so each is shown standing alone: the store's rule is
// satisfied (the actor reads the item and gets the sealed bytes, which hold no plaintext) and key@ still refuses a grant
// that is missing, expired or for another tenant; and key@'s grant is satisfied for a tenant while the envelope of
// another tenant does not open with it. The store's side, that it hands out the envelope and never opens it, is
// a_sealed_value_is_checked_for_its_envelope_and_never_opened in actors/store/tests.
//
// verifies: REQ-ISO-084
func TestASealedValueNeedsTheStoreRuleAndTheKeyGrant(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	secret := []byte("secret of acme")
	for _, u := range []struct {
		purpose, kind, sealer, reader string
	}{
		{"data", "person", "session", "exchange"},
		{"evidence", "audit-record", "writer", "indexer"},
	} {
		t.Run(u.purpose, func(t *testing.T) {
			g := func(holder, tenant, op string, life time.Duration) []byte {
				return n.grant(holder, []string{tenant}, []string{op}, life)
			}
			// acme's value and globex's value, each sealed under its own tenant's key.
			env, err := sealBy(n, u.sealer, u.purpose, u.kind, "acme", vecID, secret, g(u.sealer, "acme", "seal", time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			other, err := sealBy(n, u.sealer, u.purpose, u.kind, "globex", vecID, []byte("secret of globex"), g(u.sealer, "globex", "seal", time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(env, secret) {
				t.Fatal("the sealed value holds its plaintext: a reader with the store's rule alone would read it")
			}
			open := func(tenant string, env, grant []byte) ([]byte, error) {
				return openBy(n, u.reader, u.purpose, u.kind, tenant, vecID, env, grant)
			}
			// The reader has what the store's rule gives it, and the registry gives it the key rule for the purpose:
			// only the grant is left to refuse.
			if !registry.KeyAllows(u.reader, registry.ScopeTenant, u.purpose, "open") {
				t.Fatalf("the registry gives %s no open of tenant %s", u.reader, u.purpose)
			}
			if u.purpose == "data" && !registry.StoreAllows(u.reader, "person", "get") {
				t.Fatalf("the registry gives %s no get of person: the store's rule would refuse it", u.reader)
			}

			// The store's rule off, or satisfied: the sealed bytes are in the reader's hand. Without a grant for the tenant, key@ refuses.
			for name, grant := range map[string][]byte{
				"no grant":                   nil,
				"a grant for another tenant": g(u.reader, "globex", "open", time.Minute),
			} {
				pt, err := open("acme", env, grant)
				wantRefusalNamed(t, name, err, connect.CodePermissionDenied, "grant")
				if pt != nil {
					t.Errorf("%s: key@ gave plaintext", name)
				}
			}
			// A grant for globex opens globex's own value at globex's address, and not acme's envelope there.
			if pt, err := open("globex", other, g(u.reader, "globex", "open", time.Minute)); err != nil || string(pt) != "secret of globex" {
				t.Fatalf("globex's own grant and value: %q, %v", pt, err)
			}
			_, err = open("globex", env, g(u.reader, "globex", "open", time.Minute))
			wantRefusalNamed(t, "acme's envelope at globex's address with globex's grant", err, connect.CodePermissionDenied, "open")

			// Both allow: the value opens.
			if pt, err := open("acme", env, g(u.reader, "acme", "open", time.Minute)); err != nil || !bytes.Equal(pt, secret) {
				t.Fatalf("both checks allow, and the value did not open: %q, %v", pt, err)
			}
		})
	}
}
