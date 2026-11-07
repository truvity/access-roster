//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The vector of store-api.md, "The sealed envelope".
const (
	vecKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vecEnv = "010100000001a0a1a2a3a4a5a6a7a8a9aaab83601d4035a767333479d34abf5280916c787fad2fae39"
	vecID  = "q7x2m5nt4kz3c6vdp9ba8hwrfe"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func open1(c interface {
	Open(context.Context, *connect.Request[keyv2alpha1.OpenRequest]) (*connect.Response[keyv2alpha1.OpenResponse], error)
}, purpose, kind, tenant, id string, env, grant []byte) ([]byte, error) {
	res, err := c.Open(context.Background(), connect.NewRequest(&keyv2alpha1.OpenRequest{
		Items: []*keyv2alpha1.OpenItem{{Purpose: purpose, Address: addr(kind, tenant, id), Envelope: env}},
		Grant: grant,
	}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetPlaintexts()[0], nil
}

func seal1(c keyv2alpha1connectSealer, purpose, kind, tenant, id string, pt, grant []byte) ([]byte, error) {
	res, err := c.Seal(context.Background(), connect.NewRequest(&keyv2alpha1.SealRequest{
		Purpose: purpose, Address: addr(kind, tenant, id), Plaintext: pt, Grant: grant,
	}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetEnvelope(), nil
}

type keyv2alpha1connectSealer interface {
	Seal(context.Context, *connect.Request[keyv2alpha1.SealRequest]) (*connect.Response[keyv2alpha1.SealResponse], error)
}

// The envelope of store-api.md opens to "example" with the test data key put into the cache, and not under
// another tenant, even when that tenant's key is the same key; and not with a header byte changed.
func TestEnvelopeVector(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	key := unhex(t, vecKey)
	n.srv.cache.put(keyRef{"acme", "data", 1}, bytes.Clone(key))
	n.srv.cache.put(keyRef{"globex", "data", 1}, bytes.Clone(key))
	grant := n.grant("session", []string{"acme", "globex"}, []string{"open", "seal"}, time.Minute)
	env := unhex(t, vecEnv)

	pt, err := open1(n.client("session"), "data", "person", "acme", vecID, env, grant)
	if err != nil || string(pt) != "example" {
		t.Fatalf("Open = %q, %v; want example", pt, err)
	}
	_, err = open1(n.client("session"), "data", "person", "globex", vecID, env, grant)
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	for i := range 6 {
		bad := bytes.Clone(env)
		bad[i] ^= 1
		_, err = open1(n.client("session"), "data", "person", "acme", vecID, bad, grant)
		wantRefusal(t, err, connect.CodePermissionDenied, "open")
	}
}

// verifies: REQ-KEYS-033
func TestSealOpenRoundTripAndBinding(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	grant := n.grant("session", []string{"acme", "globex"}, []string{"open", "seal"}, time.Minute)

	env, err := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("hello"), grant)
	if err != nil {
		t.Fatal(err)
	}
	if env[0] != 1 || env[1] != 1 || len(env) != 6+12+5+16 {
		t.Fatalf("envelope header/length wrong: % x (%d)", env[:6], len(env))
	}
	pt, err := open1(n.client("session"), "data", "person", "acme", vecID, env, grant)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	// A sealed value copied to another id, kind or tenant does not open. (Another boundary has another key, and
	// the envelope tests cover the boundary in the AAD.)
	for name, c := range map[string]struct{ kind, tenant, id string }{
		"id":     {"person", "acme", "other"},
		"kind":   {"session", "acme", vecID},
		"tenant": {"person", "globex", vecID},
	} {
		_, err := open1(n.client("session"), "data", c.kind, c.tenant, c.id, env, grant)
		if err == nil {
			t.Errorf("an envelope copied to another %s opened", name)
		}
	}
	// The same value is sealed twice with two nonces.
	env2, _ := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("hello"), grant)
	if bytes.Equal(env, env2) {
		t.Error("two seals are identical")
	}
	// A batch is all or none: one bad item fails the whole call.
	res, err := n.client("session").Open(context.Background(), connect.NewRequest(&keyv2alpha1.OpenRequest{
		Items: []*keyv2alpha1.OpenItem{
			{Purpose: "data", Address: addr("person", "acme", vecID), Envelope: env},
			{Purpose: "data", Address: addr("person", "acme", "other"), Envelope: env},
		}, Grant: grant,
	}))
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	if res != nil {
		t.Error("a failed batch returned plaintexts")
	}
	// Empty and oversize batches.
	_, err = n.client("session").Open(context.Background(), connect.NewRequest(&keyv2alpha1.OpenRequest{}))
	wantRefusal(t, err, connect.CodeInvalidArgument, "items")
	big := make([]*keyv2alpha1.OpenItem, 65)
	for i := range big {
		big[i] = &keyv2alpha1.OpenItem{Purpose: "data", Address: addr("person", "acme", vecID), Envelope: env}
	}
	_, err = n.client("session").Open(context.Background(), connect.NewRequest(&keyv2alpha1.OpenRequest{Items: big, Grant: grant}))
	wantRefusal(t, err, connect.CodeInvalidArgument, "items")
}

func TestOlderGenerationStillOpens(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	// A cookie sealed under generation 3, whose key is in the cache, opens: the generation comes from the envelope.
	key := unhex(t, vecKey)
	n.srv.cache.put(keyRef{"", "cookie", 3}, bytes.Clone(key))
	env, err := sealAt(key, 3, "cookie", testBoundary, "-", "cookie", "s1", []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := open1(n.client("session"), "cookie", "cookie", "", "s1", env, nil)
	if err != nil || string(pt) != "c" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
}

func TestGrantChecks(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	seal := func(grant []byte) error {
		_, err := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("x"), grant)
		return err
	}
	good := n.grant("session", []string{"acme"}, []string{"seal"}, time.Minute)
	if err := seal(good); err != nil {
		t.Fatalf("a good grant was refused: %v", err)
	}
	if err := seal(n.grant("session", []string{"*"}, []string{"seal"}, time.Minute)); err != nil {
		t.Fatalf("a grant for every tenant was refused: %v", err)
	}
	cases := map[string][]byte{
		"no grant":          nil,
		"another tenant":    n.grant("session", []string{"globex"}, []string{"seal"}, time.Minute),
		"another holder":    n.grant("exchange", []string{"acme"}, []string{"seal"}, time.Minute),
		"another operation": n.grant("session", []string{"acme"}, []string{"open"}, time.Minute),
		"garbage":           []byte("not a grant at all, but long enough to hold a header ............"),
		"truncated":         good[:10],
		"flipped last byte": append(append([]byte{}, good[:len(good)-1]...), good[len(good)-1]^1),
	}
	for name, g := range cases {
		wantRefusalNamed(t, name, seal(g), connect.CodePermissionDenied, "grant")
	}
	// An expired grant: made now, used after its life.
	soon := n.grant("session", []string{"acme"}, []string{"seal"}, 30*time.Second)
	if err := seal(soon); err != nil {
		t.Fatalf("a fresh grant was refused: %v", err)
	}
	e.clock.advance(31 * time.Second)
	wantRefusalNamed(t, "expired", seal(soon), connect.CodePermissionDenied, "grant")

	// A boundary purpose needs the rule only: a cookie without a grant works.
	if _, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", []byte("c"), nil); err != nil {
		t.Fatalf("a cookie without a grant: %v", err)
	}
}

// verifies: REQ-AUDIT-181
// A grant is not single-use and is bound to no batch and no checkpoint: key@ checks the boundary, the holder, the
// tenant, the operation and the expiry, and nothing it remembers. The writer keeps the one grant it was given for a
// tenant until shortly before the grant expires (ADR 0007: "reusable for about 60 seconds"), so one grant must seal
// many records, over its whole life, for the tenant it names, and the first seal after its expiry must be refused.
func TestOneGrantSealsManyRecordsOverItsWholeLifeAndNotAfter(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	g := n.grant("writer", []string{"acme"}, []string{"seal"}, time.Minute)
	sealAt := func(id string) error {
		_, err := seal1(n.client("writer"), "evidence", "usage", "acme", id, []byte("record"), g)
		return err
	}
	var elapsed time.Duration
	for i, after := range []time.Duration{0, 0, 5 * time.Second, 20 * time.Second, 29 * time.Second, 50 * time.Second, 59 * time.Second} {
		e.clock.advance(after - elapsed)
		elapsed = after
		for j := range 3 { // three records of a batch under the same grant
			if err := sealAt(fmt.Sprintf("r%d-%d", i, j)); err != nil {
				t.Fatalf("seal %d.%d, %s into the grant's life: %v", i, j, after, err)
			}
		}
	}
	// Another tenant never opens with it, however early.
	if _, err := seal1(n.client("writer"), "evidence", "usage", "globex", "x", []byte("record"), g); err == nil {
		t.Fatal("a grant for one tenant sealed for another")
	}
	e.clock.advance(2 * time.Second) // 61 s after it was made
	wantRefusalNamed(t, "after its expiry", sealAt("late"), connect.CodePermissionDenied, "grant")
}

func wantRefusalNamed(t *testing.T, name string, err error, code connect.Code, reason string) {
	t.Helper()
	t.Run(name, func(t *testing.T) { wantRefusal(t, err, code, reason) })
}

// verifies: REQ-KEYS-029
func TestSealOpenRules(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	g := n.grant("signer", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	// signer has no seal rule for data, and policy none at all.
	_, err := seal1(n.client("signer"), "data", "person", "acme", vecID, []byte("x"), g)
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	// session has no rule for the evidence purpose.
	_, err = seal1(n.client("session"), "evidence", "usage", "acme", vecID, []byte("x"), g)
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	// The purposes a call does not take.
	for _, p := range []string{"grant", "mac", "pseudonym", "wrapping", "nonsense", ""} {
		_, err = seal1(n.client("session"), p, "person", "acme", vecID, []byte("x"), g)
		wantRefusal(t, err, connect.CodeInvalidArgument, "purpose")
	}
	// Addresses that do not fit.
	for name, a := range map[string][3]string{
		"upper-case id":  {"person", "acme", "ABC"},
		"empty id":       {"person", "acme", ""},
		"dash tenant":    {"person", "-", "x"},
		"slash in kind":  {"a/b", "acme", "x"},
		"cookie, tenant": {"cookie", "acme", "x"},
	} {
		purpose := "data"
		if name == "cookie, tenant" {
			purpose = "cookie"
		}
		_, err = seal1(n.client("session"), purpose, a[0], a[1], a[2], []byte("x"), g)
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: code = %v (%v), want invalid_argument", name, connect.CodeOf(err), err)
		}
	}
	// Evidence has a tenant.
	_, err = seal1(n.client("writer"), "evidence", "usage", "", "x", []byte("x"), nil)
	wantRefusal(t, err, connect.CodeInvalidArgument, "tenant")
	// No caller in the registry: indexer opens evidence but cannot seal it.
	_, err = seal1(n.client("indexer"), "evidence", "usage", "acme", "x", []byte("x"), g)
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
}

func TestBoundaryDataKeyNeedsNoGrant(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	// exchange seals and opens the boundary data key (keys.yaml lists exchange and console there), console opens it.
	env, err := seal1(n.client("exchange"), "data", "enrolment-token", "", "x", []byte("tok"), nil)
	if err != nil {
		t.Fatalf("boundary data without a grant: %v", err)
	}
	pt, err := open1(n.client("exchange"), "data", "enrolment-token", "", "x", env, nil)
	if err != nil || string(pt) != "tok" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	pt, err = open1(n.client("console"), "data", "enrolment-token", "", "x", env, nil)
	if err != nil || string(pt) != "tok" {
		t.Fatalf("console Open = %q, %v", pt, err)
	}
	// The tenant's data key and the boundary's are different keys: the envelope of one does not open as the other.
	if _, err := open1(n.client("exchange"), "data", "enrolment-token", "acme", "x", env, n.grant("exchange", []string{"acme"}, []string{"open"}, time.Minute)); err == nil {
		t.Error("a boundary value opened as a tenant's")
	}
}

// The rule check is about the key in its scope. An actor that may use the tenant data key, and has a grant for it,
// has no right to the boundary data key, which keys.yaml gives to exchange and console only (record 0006).
func TestTenantDataRuleIsNoRightToTheBoundaryDataKey(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	env, err := seal1(n.client("exchange"), "data", "enrolment-token", "", "x", []byte("tok"), nil)
	if err != nil {
		t.Fatalf("exchange seals boundary data: %v", err)
	}
	// console may open the boundary key but not seal under it.
	_, err = seal1(n.client("console"), "data", "enrolment-token", "", "x", []byte("tok"), nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	for _, actor := range []string{"session", "policy", "signer", "ca", "ssh-ca", "adapter-github", "exporter"} {
		g := n.grant(actor, []string{"acme"}, []string{"seal", "open"}, time.Minute)
		t.Run(actor, func(t *testing.T) {
			_, err := seal1(n.client(actor), "data", "enrolment-token", "", "x", []byte("tok"), g)
			wantRefusal(t, err, connect.CodePermissionDenied, "rule")
			_, err = open1(n.client(actor), "data", "enrolment-token", "", "x", env, g)
			wantRefusal(t, err, connect.CodePermissionDenied, "rule")
		})
	}
	// The tenant key still works for a tenant-data actor with a grant, and needs the grant.
	g := n.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	tenantEnv, err := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("x"), g)
	if err != nil {
		t.Fatalf("tenant data with a grant: %v", err)
	}
	if pt, err := open1(n.client("session"), "data", "person", "acme", vecID, tenantEnv, g); err != nil || string(pt) != "x" {
		t.Fatalf("tenant Open = %q, %v", pt, err)
	}
	_, err = seal1(n.client("session"), "data", "person", "acme", vecID, []byte("x"), nil)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("tenant data without a grant: code = %v, want permission_denied", connect.CodeOf(err))
	}
}

// verifies: REQ-POLICY-015
func TestSealGrantAndOpenGrant(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	now := e.clock.now()
	mk := func(life time.Duration) *keyv2alpha1.SealGrantRequest {
		return &keyv2alpha1.SealGrantRequest{Grant: grantProto("session", []string{"acme"}, now, life)}
	}
	// session may not seal a grant.
	_, err := n.client("session").SealGrant(context.Background(), connect.NewRequest(mk(time.Minute)))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	// policy may.
	res, err := n.client("policy").SealGrant(context.Background(), connect.NewRequest(mk(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	sealed := res.Msg.GetSealedGrant()
	// A grant of 61 s, an empty holder, an empty tenant list, a bad id and another boundary are refused.
	over := mk(61 * time.Second)
	noHolder := mk(time.Minute)
	noHolder.Grant.Holder = ""
	noTenants := mk(time.Minute)
	noTenants.Grant.Tenants = nil
	badID := mk(time.Minute)
	badID.Grant.DecisionId = "A/B"
	other := mk(time.Minute)
	other.Grant.Boundary = "dev"
	zero := mk(0)
	for name, r := range map[string]*keyv2alpha1.SealGrantRequest{
		"61 s": over, "no holder": noHolder, "no tenants": noTenants, "bad id": badID, "other boundary": other, "zero life": zero,
		"nil grant": {},
	} {
		_, err := n.client("policy").SealGrant(context.Background(), connect.NewRequest(r))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: code = %v (%v), want invalid_argument", name, connect.CodeOf(err), err)
		}
	}
	if _, err := n.client("policy").SealGrant(context.Background(), connect.NewRequest(mk(60*time.Second))); err != nil {
		t.Errorf("a grant of exactly 60 s was refused: %v", err)
	}
	// store opens it, and does not check the holder (the caller does).
	og, err := n.client("store").OpenGrant(context.Background(), connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: sealed}))
	if err != nil {
		t.Fatal(err)
	}
	if g := og.Msg.GetGrant(); g.GetHolder() != "session" || g.GetBoundary() != testBoundary || g.GetTenants()[0] != "acme" {
		t.Fatalf("grant = %v", g)
	}
	// policy has no rule to open one.
	_, err = n.client("policy").OpenGrant(context.Background(), connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: sealed}))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	// A damaged grant, then an expired one.
	_, err = n.client("store").OpenGrant(context.Background(), connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: sealed[:len(sealed)-1]}))
	wantRefusal(t, err, connect.CodePermissionDenied, "grant")
	e.clock.advance(time.Minute + time.Second)
	_, err = n.client("store").OpenGrant(context.Background(), connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: sealed}))
	wantRefusal(t, err, connect.CodeFailedPrecondition, "expired")
}

// sealGrantUnchecked seals a grant the way SealGrant would, but without its checks: what an older or a buggy
// policy could have made. checkGrant must hold on its own.
func sealGrantUnchecked(t *testing.T, n *node, g *typev2alpha1.Grant) []byte {
	t.Helper()
	pt, err := proto.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	id := g.GetDecisionId()
	var env []byte
	err = n.srv.withKey(context.Background(), keyRef{"", "grant", 1}, true, func(key []byte) error {
		var e error
		env, e = envelope.Seal(key, envelope.CodeGrant, 1, envelope.Address{Boundary: testBoundary, Tenant: "-", Kind: "grant", ID: id}, pt)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(id))) //nolint:gosec // a decision id is short
	return append(append(out, id...), env...)
}

// A grant lives 60 s from now, not 60 s from any issued_at: a window in the future is refused when it is sealed,
// and again when it is used.
func TestGrantWindowIsBoundedByNow(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	now := e.clock.now()
	seal := func(g *typev2alpha1.Grant) error {
		_, err := n.client("policy").SealGrant(context.Background(), connect.NewRequest(&keyv2alpha1.SealGrantRequest{Grant: g}))
		return err
	}
	for name, c := range map[string]struct {
		issued time.Time
		life   time.Duration
		path   string
	}{
		"issued a year ahead":         {now.AddDate(1, 0, 0), 30 * time.Second, "grant.issued_at"},
		"issued a minute ahead":       {now.Add(time.Minute), time.Second, "grant.issued_at"},
		"expires beyond now plus 60s": {now.Add(4 * time.Second), 60*time.Second + 2*time.Second, "grant.expires_at"},
	} {
		err := seal(grantProto("session", []string{"acme"}, c.issued, c.life))
		wantRefusalNamed(t, name, err, connect.CodeInvalidArgument, "schema")
		if p, _ := refusal.FieldPath(err); p != c.path {
			t.Errorf("%s: field path %q, want %q", name, p, c.path)
		}
	}
	// Inside the skew is fine, and so is a window that starts in the past.
	if err := seal(grantProto("session", []string{"acme"}, now.Add(4*time.Second), 60*time.Second)); err != nil {
		t.Errorf("a window 4 s ahead: %v", err)
	}
	if err := seal(grantProto("session", []string{"acme"}, now.Add(-30*time.Second), 60*time.Second)); err != nil {
		t.Errorf("a window that began 30 s ago: %v", err)
	}

	// checkGrant holds on its own: a grant sealed with a far window is no grant.
	far := sealGrantUnchecked(t, n, grantProto("session", []string{"acme"}, now.AddDate(1, 0, 0), 30*time.Second))
	late := sealGrantUnchecked(t, n, grantProto("session", []string{"acme"}, now, 5*time.Minute))
	for name, g := range map[string][]byte{"issued a year ahead": far, "expires beyond now plus 60s": late} {
		_, err := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("x"), g)
		wantRefusalNamed(t, "use: "+name, err, connect.CodePermissionDenied, "grant")
	}
	// OpenGrant refuses them too, so the store cannot be handed one.
	_, err := n.client("store").OpenGrant(context.Background(), connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: far}))
	wantRefusal(t, err, connect.CodePermissionDenied, "grant")
	// A grant inside the window still works.
	ok := sealGrantUnchecked(t, n, grantProto("session", []string{"acme"}, now, 60*time.Second))
	if _, err := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("x"), ok); err != nil {
		t.Errorf("a grant inside the window: %v", err)
	}
}

// REQ-KEYS-082: the chain key of a tenant is sealed by session alone and opened by session and exchange alone, by rule
// and with no grant (ADR 0006, "Data keys").
// verifies: REQ-KEYS-082
func TestChainKeySealedBySessionOpenedBySessionAndExchangeAlone(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	facts := []byte("chain facts")
	chainGrant := n.grant("session", []string{"acme"}, []string{"seal"}, time.Minute)
	env, err := seal1(n.client("session"), "chain", "session-chain", "acme", vecID, facts, chainGrant)
	if err != nil {
		t.Fatalf("session seals under chain: %v", err)
	}
	if h, err := envelope.ParseHeader(env); err != nil || h.Purpose != envelope.CodeChain {
		t.Errorf("header = %+v, %v; want the chain code", h, err)
	}
	// session opens it again, for a refresh, and exchange opens it for a token exchange; neither needs a grant.
	for _, who := range []string{"session", "exchange"} {
		pt, err := open1(n.client(who), "chain", "session-chain", "acme", vecID, env, nil)
		if err != nil || !bytes.Equal(pt, facts) {
			t.Fatalf("%s opens the chain facts: %q, %v", who, pt, err)
		}
	}
	// exchange cannot seal.
	_, err = seal1(n.client("exchange"), "chain", "session-chain", "acme", vecID, facts, nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	// No other actor seals or opens. Every actor of the registry is checked, not a list kept here: a grant added to any
	// actor in actors.yaml fails this test. An actor that may call key@ reaches the rule and is refused by it; one that
	// may not has no socket, and the registry says it has no rule.
	callers := map[string]bool{}
	for _, c := range registry.CallersOf("key") {
		callers[c] = true
	}
	refused := 0 // the calls the sweep saw refused by the rule
	for _, act := range registry.Actors() {
		for _, op := range []string{"seal", "open"} {
			allowed := act.Name == "session" || (act.Name == "exchange" && op == "open")
			if got := registry.KeyAllows(act.Name, registry.ScopeTenant, "chain", op); got != allowed {
				t.Errorf("registry: %s %s chain = %v, want %v", act.Name, op, got, allowed)
			}
			if registry.KeyAllows(act.Name, registry.ScopeBoundary, "chain", op) {
				t.Errorf("registry: %s %s the boundary's chain key, which does not exist", act.Name, op)
			}
			if allowed || !callers[act.Name] {
				continue
			}
			var err error
			if op == "seal" {
				_, err = seal1(n.client(act.Name), "chain", "session-chain", "acme", vecID, facts, nil)
			} else {
				_, err = open1(n.client(act.Name), "chain", "session-chain", "acme", vecID, env, nil)
			}
			if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodePermissionDenied || r != "rule" {
				t.Errorf("%s %ss under chain: %v, want permission_denied/rule", act.Name, op, err)
			}
			refused++
		}
	}
	// A sweep over an empty registry, or over actors that cannot call key@, would pass whatever the rule says.
	if refused == 0 {
		t.Fatal("the sweep refused no call: it checked nothing")
	}
	// The envelope does not open at another address, nor at another tenant's key. That key exists first (globex seals
	// a chain of its own), so the refusal comes from the address binding and the other key, not from a missing key.
	_, err = open1(n.client("exchange"), "chain", "session-chain", "acme", "other"+vecID[5:], env, nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	globex := n.grant("session", []string{"globex"}, []string{"seal"}, time.Minute)
	if _, err := seal1(n.client("session"), "chain", "session-chain", "globex", vecID, []byte("globex facts"), globex); err != nil {
		t.Fatalf("session seals under globex's chain key: %v", err)
	}
	_, err = open1(n.client("exchange"), "chain", "session-chain", "globex", vecID, env, nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	// A chain has a tenant: the key of the boundary does not exist.
	_, err = seal1(n.client("session"), "chain", "session-chain", "", vecID, facts, nil)
	wantRefusal(t, err, connect.CodeInvalidArgument, "tenant")
	_, err = open1(n.client("exchange"), "chain", "session-chain", "", vecID, env, nil)
	wantRefusal(t, err, connect.CodeInvalidArgument, "tenant")
}

// REQ-KEYS-082, REQ-KEYS-036: a tenant's exit deletes its chain wraps with the rest, so the facts of its chains no
// longer open, not even on a node that starts again with an empty cache; another tenant's chain still opens.
// verifies: REQ-KEYS-082
func TestTenantExitMakesChainFactsUnopenable(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	acmeGrant := a.grant("session", []string{"acme"}, []string{"seal"}, time.Minute)
	acme, err := seal1(a.client("session"), "chain", "session-chain", "acme", vecID, []byte("acme facts"), acmeGrant)
	if err != nil {
		t.Fatal(err)
	}
	globexGrant := a.grant("session", []string{"globex"}, []string{"seal"}, time.Minute)
	globex, err := seal1(a.client("session"), "chain", "session-chain", "globex", vecID, []byte("globex facts"), globexGrant)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := open1(a.client("exchange"), "chain", "session-chain", "acme", vecID, acme, nil); err != nil || string(pt) != "acme facts" {
		t.Fatalf("before the exit: %q, %v", pt, err)
	}
	// The exit: every wrap of the tenant is deleted, and the node starts again with an empty cache. This tests the
	// erasure of the wraps plus a restart; key@ has no watch on DataKeyWrap yet (ADR 0006, "The cache"), so a warm node
	// would still hold the key until its cache entry expires.
	if got := e.store.eraseWraps("acme"); got == 0 {
		t.Fatal("the tenant had no wraps to erase")
	}
	a.stop()
	b := e.startedNode(nodeOpts{name: "node-1", driver: a.driver})
	for _, who := range []string{"session", "exchange"} {
		_, err = open1(b.client(who), "chain", "session-chain", "acme", vecID, acme, nil)
		wantRefusal(t, err, connect.CodePermissionDenied, "open")
	}
	if pt, err := open1(b.client("exchange"), "chain", "session-chain", "globex", vecID, globex, nil); err != nil || string(pt) != "globex facts" {
		t.Fatalf("another tenant's chain after the exit: %q, %v", pt, err)
	}
}

// A Seal or an Open of a tenant's data or evidence key is refused by key@'s own grant check, whatever else is in
// the call: the envelope is real, the caller's rule allows the call, and the same call passes with a good grant.
// key@ has no store rule in these tests (the fake store serves wraps and config only), so the refusals below are
// the grant check standing alone, as the second verification line asks.
//
// verifies: REQ-KEYS-030
func TestTenantKeyCallsRefuseWithoutAMatchingGrant(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	refusals := func() int {
		c := 0
		for _, ev := range n.audit.all() {
			if ev.Action == ActionRefuse && ev.Reason == reasonGrant {
				c++
			}
		}
		return c
	}
	for _, u := range []struct{ purpose, kind, sealer, opener string }{
		{"data", "person", "session", "session"},
		{"evidence", "usage", "writer", "indexer"},
	} {
		t.Run(u.purpose, func(t *testing.T) {
			// Every actor named here has the rule it needs: the registry, not a grant, allows the call.
			if !registry.KeyAllows(u.sealer, registry.ScopeTenant, u.purpose, "seal") || !registry.KeyAllows(u.opener, registry.ScopeTenant, u.purpose, "open") {
				t.Fatalf("the registry gives %s no seal or %s no open of tenant %s", u.sealer, u.opener, u.purpose)
			}
			sealG := func(holder string, tenants, ops []string, life time.Duration) []byte {
				return n.grant(holder, tenants, ops, life)
			}
			seal := func(grant []byte) ([]byte, error) {
				return seal1(n.client(u.sealer), u.purpose, u.kind, "acme", vecID, []byte("secret"), grant)
			}
			open := func(env, grant []byte) ([]byte, error) {
				return open1(n.client(u.opener), u.purpose, u.kind, "acme", vecID, env, grant)
			}
			good, err := seal(sealG(u.sealer, []string{"acme"}, []string{"seal"}, time.Minute))
			if err != nil {
				t.Fatalf("a good grant was refused: %v", err)
			}
			if pt, err := open(good, sealG(u.opener, []string{"acme"}, []string{"open"}, time.Minute)); err != nil || string(pt) != "secret" {
				t.Fatalf("Open with a good grant = %q, %v", pt, err)
			}

			sealShort := sealG(u.sealer, []string{"acme"}, []string{"seal"}, 10*time.Second)
			openShort := sealG(u.opener, []string{"acme"}, []string{"open"}, 10*time.Second)
			sealKeep := sealG(u.sealer, []string{"acme"}, []string{"seal"}, time.Minute)
			openKeep := sealG(u.opener, []string{"acme"}, []string{"open"}, time.Minute)
			before, calls := refusals(), 0

			// key@ answers a refused call from the grant alone, before any lookup in the store. The tenant here has
			// no key yet and no wrap: were the grant checked after the key is loaded, a refused call would read the
			// store (and a Seal would make the key). The store counts every Get, List and Write on items. The Open
			// carries the envelope of acme, which the grant check never reads.
			const cold = "initech"
			coldSeal := func(grant []byte) ([]byte, error) {
				return seal1(n.client(u.sealer), u.purpose, u.kind, cold, vecID, []byte("secret"), grant)
			}
			coldOpen := func(grant []byte) ([]byte, error) {
				return open1(n.client(u.opener), u.purpose, u.kind, cold, vecID, good, grant)
			}
			coldSealShort := sealG(u.sealer, []string{cold}, []string{"seal"}, 10*time.Second)
			coldOpenShort := sealG(u.opener, []string{cold}, []string{"open"}, 10*time.Second)
			lookups, wraps := e.store.itemCallCount(), e.store.wrapCount()
			for name, g := range map[string][]byte{
				"cold seal, no grant":                   nil,
				"cold seal, a grant for another tenant": sealG(u.sealer, []string{"acme"}, []string{"seal"}, time.Minute),
				"cold seal, a grant for open only":      sealG(u.sealer, []string{cold}, []string{"open"}, time.Minute),
				"cold seal, a grant made for another":   sealG(u.opener+"x", []string{cold}, []string{"seal"}, time.Minute),
			} {
				_, err := coldSeal(g)
				wantRefusalNamed(t, name, err, connect.CodePermissionDenied, "grant")
				calls++
			}
			for name, g := range map[string][]byte{
				"cold open, no grant":                   nil,
				"cold open, a grant for another tenant": sealG(u.opener, []string{"acme"}, []string{"open"}, time.Minute),
				"cold open, a grant for seal only":      sealG(u.opener, []string{cold}, []string{"seal"}, time.Minute),
				"cold open, a grant made for another":   sealG(u.sealer+"x", []string{cold}, []string{"open"}, time.Minute),
			} {
				_, err := coldOpen(g)
				wantRefusalNamed(t, name, err, connect.CodePermissionDenied, "grant")
				calls++
			}
			if got := e.store.itemCallCount(); got != lookups {
				t.Errorf("%d store calls were made while key@ refused calls on the grant", got-lookups)
			}
			if got := e.store.wrapCount(); got != wraps {
				t.Errorf("a refused Seal made %d wraps", got-wraps)
			}

			sealCases := map[string][]byte{
				"seal, no grant":                   nil,
				"seal, a grant for another tenant": sealG(u.sealer, []string{"globex"}, []string{"seal"}, time.Minute),
				"seal, a grant for open only":      sealG(u.sealer, []string{"acme"}, []string{"open"}, time.Minute),
				"seal, a grant made for another":   sealG(u.opener+"x", []string{"acme"}, []string{"seal"}, time.Minute),
			}
			openCases := map[string][]byte{
				"open, no grant":                   nil,
				"open, a grant for another tenant": sealG(u.opener, []string{"globex"}, []string{"open"}, time.Minute),
				"open, a grant for seal only":      sealG(u.opener, []string{"acme"}, []string{"seal"}, time.Minute),
				"open, a grant made for another":   sealG(u.sealer+"x", []string{"acme"}, []string{"open"}, time.Minute),
			}
			for name, g := range sealCases {
				_, err := seal(g)
				wantRefusalNamed(t, name, err, connect.CodePermissionDenied, "grant")
				calls++
			}
			for name, g := range openCases {
				_, err := open(good, g)
				wantRefusalNamed(t, name, err, connect.CodePermissionDenied, "grant")
				calls++
			}
			// The grant is checked per item: one item of another tenant fails the whole batch, though the
			// first item alone is allowed by the grant.
			globexGrant := sealG(u.sealer, []string{"globex"}, []string{"seal"}, time.Minute) // before the client: the identity is read per connection
			other, err := seal1(n.client(u.sealer), u.purpose, u.kind, "globex", vecID, []byte("other"), globexGrant)
			if err != nil {
				t.Fatal(err)
			}
			_, err = n.client(u.opener).Open(context.Background(), connect.NewRequest(&keyv2alpha1.OpenRequest{
				Items: []*keyv2alpha1.OpenItem{
					{Purpose: u.purpose, Address: addr(u.kind, "acme", vecID), Envelope: good},
					{Purpose: u.purpose, Address: addr(u.kind, "globex", vecID), Envelope: other},
				}, Grant: openKeep,
			}))
			wantRefusalNamed(t, "open, a batch with an item of another tenant", err, connect.CodePermissionDenied, "grant")
			calls++

			// An expired grant: good until its second of expiry, and refused from it (not after it).
			if _, err := seal(sealShort); err != nil {
				t.Fatalf("a fresh grant was refused: %v", err)
			}
			if _, err := open(good, openShort); err != nil {
				t.Fatalf("a fresh grant was refused: %v", err)
			}
			e.clock.advance(10 * time.Second)
			_, err = seal(sealShort)
			wantRefusalNamed(t, "seal, an expired grant", err, connect.CodePermissionDenied, "grant")
			_, err = open(good, openShort)
			wantRefusalNamed(t, "open, an expired grant", err, connect.CodePermissionDenied, "grant")
			lookups = e.store.itemCallCount()
			_, err = coldSeal(coldSealShort)
			wantRefusalNamed(t, "cold seal, an expired grant", err, connect.CodePermissionDenied, "grant")
			_, err = coldOpen(coldOpenShort)
			wantRefusalNamed(t, "cold open, an expired grant", err, connect.CodePermissionDenied, "grant")
			if got := e.store.itemCallCount(); got != lookups {
				t.Errorf("%d store calls were made while key@ refused an expired grant", got-lookups)
			}
			calls += 4
			// The grants that were not expired still work, so each refusal above is the grant's fault alone.
			if _, err := seal(sealKeep); err != nil {
				t.Errorf("a grant that had not expired was refused: %v", err)
			}
			if _, err := open(good, openKeep); err != nil {
				t.Errorf("a grant that had not expired was refused: %v", err)
			}
			// The counter does see a lookup when the grant is good: the same cold Seal with a good grant reads the
			// store and makes the key.
			afterRefused, wrapsBefore := e.store.itemCallCount(), e.store.wrapCount()
			if _, err := coldSeal(sealG(u.sealer, []string{cold}, []string{"seal"}, time.Minute)); err != nil {
				t.Fatalf("a good grant on the cold tenant was refused: %v", err)
			}
			if e.store.itemCallCount() <= afterRefused || e.store.wrapCount() <= wrapsBefore {
				t.Error("a good Seal of a cold tenant made no store call or no wrap: the count proves nothing")
			}
			if got := refusals() - before; got != calls {
				t.Errorf("%d refusals audited for %d refused calls", got, calls)
			}
		})
	}
}

// A grant is sealed, not signed: it is an AES-256-GCM envelope of the purpose grant under the boundary's grant key,
// bound to the address (boundary, tenant "-", kind "grant", the decision id). The purpose byte is in the clear header
// and in the authenticated context, so a grant that is opened as another purpose, or an envelope of another purpose
// presented as a grant, or a grant with any byte changed, is refused.
//
// verifies: REQ-ISO-067
func TestGrantIsSealedUnderTheGrantKeyWithThePurposeInTheContext(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	g := grantProto("session", []string{"acme"}, e.clock.now(), time.Minute)
	res, err := n.client("policy").SealGrant(context.Background(), connect.NewRequest(&keyv2alpha1.SealGrantRequest{Grant: g}))
	if err != nil {
		t.Fatal(err)
	}
	sealed := res.Msg.GetSealedGrant()
	idLen := int(binary.BigEndian.Uint16(sealed))
	id, env := string(sealed[2:2+idLen]), sealed[2+idLen:]
	if id != g.GetDecisionId() {
		t.Fatalf("the sealed grant names decision %q, want %q", id, g.GetDecisionId())
	}
	if h, err := envelope.ParseHeader(env); err != nil || h.Purpose != envelope.CodeGrant || h.Generation != sealGeneration {
		t.Fatalf("header = %+v, %v; want purpose grant, generation %d", h, err, sealGeneration)
	}
	// The grant is not readable from the sealed form.
	for _, secret := range []string{"session", "acme", "token.issue"} {
		if bytes.Contains(sealed, []byte(secret)) {
			t.Errorf("the sealed grant holds %q in the clear", secret)
		}
	}
	// The grant key is the boundary's key of the purpose grant: the envelope opens under it at the grant address, and
	// the plaintext is the grant policy decided.
	var key []byte
	if err := n.srv.withKey(context.Background(), keyRef{"", "grant", sealGeneration}, false, func(k []byte) error {
		key = bytes.Clone(k)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	grantAddr := envelope.Address{Boundary: testBoundary, Tenant: envelope.NoTenant, Kind: "grant", ID: id}
	pt, err := envelope.Open(key, env, grantAddr)
	if err != nil {
		t.Fatalf("the grant does not open under the grant key at its address: %v", err)
	}
	var opened typev2alpha1.Grant
	if err := proto.Unmarshal(pt, &opened); err != nil || opened.GetHolder() != "session" || opened.GetDecisionId() != id {
		t.Fatalf("opened grant = %v, %v", &opened, err)
	}
	wire := func(id string, env []byte) []byte {
		out := binary.BigEndian.AppendUint16(nil, uint16(len(id))) //nolint:gosec // a decision id is short
		return append(append(out, id...), env...)
	}
	openGrant := func(sealed []byte) error {
		_, err := n.client("store").OpenGrant(context.Background(), connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: sealed}))
		return err
	}
	if err := openGrant(sealed); err != nil { // the control: every refusal below is the change made to it
		t.Fatalf("the untouched grant was refused: %v", err)
	}
	if got := wire(id, env); !bytes.Equal(got, sealed) {
		t.Fatal("the wire form of a sealed grant is not u16 length | decision id | envelope")
	}

	// The purpose in the context: the same grant plaintext sealed under the same key at the same address, but as the
	// data purpose, is no grant; nor is the grant's envelope with the purpose byte changed.
	asData, err := envelope.Seal(key, envelope.CodeData, sealGeneration, grantAddr, pt)
	if err != nil {
		t.Fatal(err)
	}
	relabelled := bytes.Clone(env)
	relabelled[1] = envelope.CodeData
	if _, err := envelope.Open(key, relabelled, grantAddr); !errors.Is(err, envelope.ErrOpen) {
		t.Errorf("a grant with the purpose byte changed opens at the envelope: %v", err)
	}
	// An envelope of the data purpose, sealed by key@ itself under the boundary's data key at the grant's address and
	// then labelled as a grant, is under another key.
	dataEnv, err := seal1(n.client("exchange"), "data", "grant", "", id, pt, nil)
	if err != nil {
		t.Fatalf("seal a boundary value at the address of the grant: %v", err)
	}
	labelled := bytes.Clone(dataEnv)
	labelled[1] = envelope.CodeGrant
	for name, bad := range map[string][]byte{
		"the grant plaintext sealed as data":      wire(id, asData),
		"the grant with its purpose byte changed": wire(id, relabelled),
		"a data envelope as it is":                wire(id, dataEnv),
		"a data envelope labelled as a grant":     wire(id, labelled),
		"the grant under another decision id":     wire("0192f4a0-0000-7000-8000-ffffffffffff", env),
		"the grant with a longer id length":       append(binary.BigEndian.AppendUint16(nil, uint16(idLen+1)), sealed[2:]...), //nolint:gosec // a decision id is short
		"the grant cut after its header":          wire(id, env[:envelope.HeaderLen]),
		"the grant with its tag cut":              wire(id, env[:len(env)-1]),
		"the grant with a byte appended":          wire(id, append(bytes.Clone(env), 0)),
		"the id alone":                            sealed[:2+idLen],
		"nothing":                                 nil,
		"zeroes":                                  make([]byte, envelope.MinLen),
	} {
		wantRefusalNamed(t, name, openGrant(bad), connect.CodePermissionDenied, "grant")
	}
	// The boundary is in the context too: the envelope does not open as the grant of another boundary.
	if _, err := envelope.Open(key, env, envelope.Address{Boundary: "other", Tenant: envelope.NoTenant, Kind: "grant", ID: id}); !errors.Is(err, envelope.ErrOpen) {
		t.Errorf("a grant opens at the address of another boundary: %v", err)
	}

	// Authenticated: a change of any byte of the envelope, in the header, the nonce, the ciphertext or the tag, is
	// refused by OpenGrant, and by the grant check of a Seal that carries it.
	for i := range env {
		bad := bytes.Clone(env)
		bad[i] ^= 1
		err := openGrant(wire(id, bad))
		if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodePermissionDenied || r != "grant" {
			t.Errorf("OpenGrant with byte %d of the envelope changed: %v, want permission_denied/grant", i, err)
		}
	}
	for _, i := range []int{1, envelope.HeaderLen, envelope.HeaderLen + 12, len(env) - 1} { // purpose, nonce, ciphertext, tag
		bad := bytes.Clone(env)
		bad[i] ^= 1
		_, err := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("x"), wire(id, bad))
		wantRefusalNamed(t, "use, byte "+fmtAny(i), err, connect.CodePermissionDenied, "grant")
	}
	// A grant that is a grant is still refused to the actor with no rule to seal one.
	_, err = n.client("session").SealGrant(context.Background(), connect.NewRequest(&keyv2alpha1.SealGrantRequest{Grant: g}))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
}

// verifies: REQ-ISO-066
// A grant that policy of one boundary sealed is no grant in another: key@ of the other boundary does not open it, whoever
// presents it and for whatever operation, and refuses with the reason "grant" (T-18, the holder's own check alone: key@
// refuses before anything the actor itself would check). The second installation has its own grant data key, as a second
// boundary does. The holder here is key@, which every actor that opens a grant asks; an actor that takes a grant and does
// not yet exist (the signer of artifacts) adds nothing to the check, since it opens through key@.
func TestAGrantOfAnotherBoundaryDoesNotOpen(t *testing.T) {
	a := newTestEnv(t, "development").startedNode(nodeOpts{})
	b := newTestEnv(t, "development").startedNode(nodeOpts{})
	foreign := a.grant("session", []string{"acme"}, []string{"seal"}, time.Minute)
	// The grant is good where it was made.
	if _, err := seal1(a.client("session"), "data", "person", "acme", vecID, []byte("x"), foreign); err != nil {
		t.Fatalf("a grant was refused in the boundary that made it: %v", err)
	}
	// And is nothing in the other: not to seal, not to open, not for the store that opens grants.
	_, err := seal1(b.client("session"), "data", "person", "acme", vecID, []byte("x"), foreign)
	wantRefusalNamed(t, "seal under a grant of another boundary", err, connect.CodePermissionDenied, "grant")
	_, err = b.client("store").OpenGrant(context.Background(), connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: foreign}))
	wantRefusalNamed(t, "OpenGrant of a grant of another boundary", err, connect.CodePermissionDenied, "grant")
	audited := false
	for _, ev := range b.audit.all() {
		audited = audited || ev.Action == ActionRefuse && ev.Reason == "grant"
	}
	if !audited {
		t.Fatal("the refusal is not an audit fact")
	}
	// The second layer, on its own: a grant that names another boundary, sealed with this boundary's own key (what a policy
	// of another boundary that held it, or a buggy one, could make), is no grant either.
	g := grantProto("session", []string{"acme"}, a.e.clock.now(), time.Minute)
	g.Boundary = "elsewhere"
	g.KeyOps = []string{"seal"}
	named := sealGrantUnchecked(t, a, g)
	_, err = seal1(a.client("session"), "data", "person", "acme", vecID, []byte("x"), named)
	wantRefusalNamed(t, "a grant that names another boundary", err, connect.CodePermissionDenied, "grant")
}

// REQ-KEYS-263: the credential key of a tenant is sealed and opened by session alone, by rule and with no grant, for the
// kind StaffPasskey and no other (ADR 0006, "Data keys").
// verifies: REQ-KEYS-263
func TestCredentialKeyIsSessionsAloneAndSealsOnlyStaffPasskey(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	const kind = "staff-passkey"
	value := []byte("a credential")
	// The first key of a tenant is made under a grant that names the tenant (REQ-KEYS-260); every later seal and every open
	// needs none, and the calls below carry none.
	first := n.grant("session", []string{"acme"}, []string{"seal"}, time.Minute)
	env, err := seal1(n.client("session"), "credential", kind, "acme", vecID, value, first)
	if err != nil {
		t.Fatalf("session seals the first credential key of a tenant under a grant: %v", err)
	}
	if _, err := seal1(n.client("session"), "credential", kind, "acme", vecID, value, nil); err != nil {
		t.Fatalf("session seals under an existing credential key with no grant: %v", err)
	}
	if h, err := envelope.ParseHeader(env); err != nil || h.Purpose != envelope.CodeCredential {
		t.Errorf("header = %+v, %v; want the credential code", h, err)
	}
	pt, err := open1(n.client("session"), "credential", kind, "acme", vecID, env, nil)
	if err != nil || !bytes.Equal(pt, value) {
		t.Fatalf("session opens it with no grant: %q, %v", pt, err)
	}
	// Every actor of the registry is checked, not a list kept here. An actor that may call key@ reaches the rule and is
	// refused by it; one that may not has no socket and the registry gives it no rule.
	callers := map[string]bool{}
	for _, c := range registry.CallersOf("key") {
		callers[c] = true
	}
	refused := 0
	for _, act := range registry.Actors() {
		for _, op := range []string{"seal", "open", "mac", "sign", "public-key", "wrap", "unwrap"} {
			allowed := act.Name == "session" && (op == "seal" || op == "open")
			if got := registry.KeyAllows(act.Name, registry.ScopeTenant, "credential", op); got != allowed {
				t.Errorf("registry: %s %s credential = %v, want %v", act.Name, op, got, allowed)
			}
			if registry.KeyAllows(act.Name, registry.ScopeBoundary, "credential", op) {
				t.Errorf("registry: %s %s the boundary's credential key, which does not exist", act.Name, op)
			}
		}
		if act.Name == "session" || !callers[act.Name] {
			continue
		}
		_, err := seal1(n.client(act.Name), "credential", kind, "acme", vecID, value, nil)
		if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodePermissionDenied || r != "rule" {
			t.Errorf("%s seals under credential: %v, want permission_denied/rule", act.Name, err)
		}
		_, err = open1(n.client(act.Name), "credential", kind, "acme", vecID, env, nil)
		if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodePermissionDenied || r != "rule" {
			t.Errorf("%s opens under credential: %v, want permission_denied/rule", act.Name, err)
		}
		// An envelope that is a credential does not open as `data` for an actor that holds the data rule either: the
		// header names the purpose.
		if registry.KeyAllows(act.Name, registry.ScopeTenant, "data", "open") {
			grant := n.grant(act.Name, []string{"acme"}, []string{"open"}, time.Minute)
			if _, err := open1(n.client(act.Name), "data", kind, "acme", vecID, env, grant); err == nil {
				t.Errorf("%s opened a credential envelope as data", act.Name)
			}
		}
		refused++
	}
	if refused == 0 {
		t.Fatal("the sweep refused no call: it checked nothing")
	}
	// The kind: the credential key seals StaffPasskey and nothing else, for the one actor that holds the rule.
	for _, other := range []string{"person", "session-chain", "upstream-link", "staff-passkeys", "Staff-Passkey"} {
		_, err := seal1(n.client("session"), "credential", other, "acme", vecID, value, nil)
		wantRefusal(t, err, connect.CodeInvalidArgument, "address")
		_, err = open1(n.client("session"), "credential", other, "acme", vecID, env, nil)
		wantRefusal(t, err, connect.CodeInvalidArgument, "address")
	}
	// A credential has a tenant. The key of the boundary does not exist.
	_, err = seal1(n.client("session"), "credential", kind, "", vecID, value, nil)
	wantRefusal(t, err, connect.CodeInvalidArgument, "tenant")
	// The address binds the envelope, and another tenant's key does not open it (that key exists first).
	_, err = open1(n.client("session"), "credential", kind, "acme", "other"+vecID[5:], env, nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	firstGlobex := n.grant("session", []string{"globex"}, []string{"seal"}, time.Minute)
	other, err := seal1(n.client("session"), "credential", kind, "globex", vecID, []byte("globex"), firstGlobex)
	if err != nil {
		t.Fatalf("session seals under globex's credential key: %v", err)
	}
	_, err = open1(n.client("session"), "credential", kind, "globex", vecID, env, nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
	// What rule-only access gives: session opens a credential of any tenant it names, if it holds the envelope. That is
	// the access of `chain`, and the reason the purpose is session's alone.
	if pt, err := open1(n.client("session"), "credential", kind, "globex", vecID, other, nil); err != nil || string(pt) != "globex" {
		t.Errorf("session opens globex's credential: %q, %v", pt, err)
	}
	// The StaffPasskey is sealed under the credential key and no other: an actor with the data rule (session and exchange both
	// hold it for the tenant) can neither seal a StaffPasskey under `data` nor open one as `data`, and a `data` envelope
	// does not open as a credential, because the header names the purpose.
	grant := n.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	_, err = seal1(n.client("session"), "data", kind, "acme", vecID, value, grant)
	wantRefusal(t, err, connect.CodeInvalidArgument, "address")
	egrant := n.grant("exchange", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	_, err = seal1(n.client("exchange"), "data", kind, "acme", vecID, value, egrant)
	wantRefusal(t, err, connect.CodeInvalidArgument, "address")
	_, err = open1(n.client("session"), "data", kind, "acme", vecID, env, grant)
	wantRefusal(t, err, connect.CodeInvalidArgument, "address")
	dataEnv, err := seal1(n.client("session"), "data", "person", "acme", vecID, value, grant)
	if err != nil {
		t.Fatal(err)
	}
	_, err = open1(n.client("session"), "credential", kind, "acme", vecID, dataEnv, nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "open")
}
