//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
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

func wantRefusalNamed(t *testing.T, name string, err error, code connect.Code, reason string) {
	t.Helper()
	t.Run(name, func(t *testing.T) { wantRefusal(t, err, code, reason) })
}

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
	env, err := seal1(n.client("session"), "data", "enrolment-token", "", "x", []byte("tok"), nil)
	if err != nil {
		t.Fatalf("boundary data without a grant: %v", err)
	}
	pt, err := open1(n.client("session"), "data", "enrolment-token", "", "x", env, nil)
	if err != nil || string(pt) != "tok" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	// The tenant's data key and the boundary's are different keys: the envelope of one does not open as the other.
	if _, err := open1(n.client("session"), "data", "enrolment-token", "acme", "x", env, n.grant("session", []string{"acme"}, []string{"open"}, time.Minute)); err == nil {
		t.Error("a boundary value opened as a tenant's")
	}
}

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
