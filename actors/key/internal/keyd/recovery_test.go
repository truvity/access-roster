//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	"github.com/truvity/sluis/v2/actors/key/internal/wrap"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

// verifies: REQ-KEYS-056
// The recovery recipient is a listed key whose private half is held outside sluis; key@ wraps every data key for it and
// has no key to open that wrap. The test lists such a recipient (a key the test holds, as the ceremony's holder
// would), lets key@ make a key, and shows: the recovery wrap exists and its holder opens it to the very key that
// sealed the value (so the wrap is real); key@, given that wrap, does not open it, both when asked directly and when the
// wrap is the only one left in the store, where every call is refused as unavailable and no new key is made beside it;
// the recovery key is not in the driver, which holds the KeyPlan's keys and no other, and the driver was asked for a
// shared secret only under the wrapping purpose; and no call of KeyService takes a wrap or a key to open.
//
// A negative about existence ("the private half does not exist inside sluis") cannot be shown by a run. What the test
// shows is that nothing in key@'s reach opens the wrap, and the tripwire on the API and on the driver's keys fails when
// a call or a key is added.
func TestKeyAtHasNoKeyToOpenTheRecoveryWrap(t *testing.T) {
	e := newTestEnv(t, "development")
	recovery := newOutsider(t)
	e.list(recovery.id)
	e.inject(recovery)
	n, spy := e.spiedNode("node-1")
	ctx := context.Background()

	env := e.cookieEnvelope(n, "s1")
	if got := e.wrapRecipients(); got[recovery.label] != 1 || got[n.srv.recipient] != 1 {
		t.Fatalf("wrap recipients = %v, want one wrap each for the node and the recovery recipient", got)
	}
	// The wrap made for the recovery recipient, and the key its holder gets from it.
	key := ownWrapOf(t, e, "", "cookie", recovery.label)
	eph, err := wrap.ParsePublic(key.GetEphemeralPublic())
	if err != nil {
		t.Fatal(err)
	}
	ek, err := recovery.priv.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := ek.ECDH(eph)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := wrap.Unwrap(wrap.Context{Boundary: testBoundary, Tenant: envelope.NoTenant, Purpose: "cookie", Generation: 1, Recipient: recovery.label}, secret, key.GetWrappedKey())
	if err != nil {
		t.Fatalf("the holder cannot open the recovery wrap: %v", err)
	}
	if pt, err := envelope.Open(dk, env, envelope.Address{Boundary: testBoundary, Tenant: envelope.NoTenant, Kind: "cookie", ID: "s1"}); err != nil || string(pt) != "a cookie" {
		t.Fatalf("the recovery key does not open the value: %q, %v", pt, err)
	}

	// key@, asked to open the recovery wrap, has no key to do it with.
	ref := keyRef{purpose: "cookie", generation: 1}
	if _, err := n.srv.unwrap(ctx, ref, key); err == nil {
		t.Fatal("key@ opened a wrap made for the recovery recipient")
	}
	// ...and not by relabelling it as its own: the wrap is still made for another key, so the node's wrapping key
	// derives another secret.
	relabelled := proto.Clone(key).(*keyv2alpha1.DataKeyWrap)
	relabelled.Recipient = n.srv.recipient
	if got, err := n.srv.unwrap(ctx, ref, relabelled); err == nil || got != nil {
		t.Fatalf("key@ opened the recovery wrap relabelled as its own: %v", err)
	}

	// Only the recovery wrap is left: the node's own is gone and its cache is dropped (as after a restart on a node
	// whose wrap was removed). key@ cannot open the key by the recovery wrap and does not make a second one.
	e.store.mu.Lock()
	for k, it := range e.store.items {
		if it.GetAddress().GetKind() == "data-key-wrap" && strings.HasSuffix(it.GetAddress().GetId(), "/"+n.srv.recipient) {
			delete(e.store.items, k)
		}
	}
	e.store.mu.Unlock()
	n.srv.cache.wipeAll()
	before := e.store.wrapWriteCount()
	_, err = open1(n.client("session"), "cookie", "cookie", "", "s1", env, nil)
	wantRefusal(t, err, connect.CodeUnavailable, "wrap")
	_, err = seal1(n.client("session"), "cookie", "cookie", "", "s2", []byte("x"), nil)
	wantRefusal(t, err, connect.CodeUnavailable, "wrap")
	if e.store.wrapWriteCount() != before {
		t.Fatal("key@ made a key beside the recovery wrap")
	}

	// The keys of the driver, and what it was asked to derive.
	if got := driverPurposes(n.driver); !slices.Equal(got, []string{"audit-log", "token-signing", "wrapping"}) {
		t.Fatalf("the driver holds %v: a key beyond the KeyPlan's", got)
	}
	spy.mu.Lock()
	defer spy.mu.Unlock()
	for _, r := range spy.ecdhs {
		if r.GetPurpose() != wrappingPurpose {
			t.Errorf("an ECDH under %q", r.GetPurpose())
		}
		if bytes.Equal(r.GetPeerPublic(), recovery.spki) {
			t.Error("the recovery key was used as a peer")
		}
	}

	// KeyService has no call that takes a wrap or a key to open with. The methods are listed so that a new one has to
	// be read; a field of a request that is a DataKeyWrap, or is named for a private key or a wrap, fails too.
	var methods []string
	svc := keyv2alpha1.File_sluis_key_v2alpha1_key_proto.Services().ByName("KeyService").Methods()
	for i := range svc.Len() {
		m := svc.Get(i)
		methods = append(methods, string(m.Name()))
		fs := m.Input().Fields()
		for j := range fs.Len() {
			f := fs.Get(j)
			name := strings.ToLower(string(f.Name()))
			if (f.Kind() == protoreflect.MessageKind && f.Message().Name() == "DataKeyWrap") || strings.Contains(name, "wrap") || strings.Contains(name, "private") {
				t.Errorf("%s takes %s", m.Name(), f.Name())
			}
		}
	}
	slices.Sort(methods)
	if want := []string{"Mac", "Open", "OpenGrant", "PublicKey", "Seal", "SealGrant", "Sign"}; !slices.Equal(methods, want) {
		t.Errorf("KeyService methods = %v, want %v: is the new one a way to open a wrap?", methods, want)
	}
}

// ownWrapOf is the wrap of a key for a recipient label.
func ownWrapOf(t *testing.T, e *testEnv, tenant, purpose, label string) *keyv2alpha1.DataKeyWrap {
	t.Helper()
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	it, ok := e.store.items[tenant+"|data-key-wrap|"+wrapID(purpose, 1, label)]
	if !ok {
		t.Fatalf("no wrap of %s/%s for %s", tenant, purpose, label)
	}
	w := &keyv2alpha1.DataKeyWrap{}
	if err := proto.Unmarshal(it.GetValue(), w); err != nil {
		t.Fatal(err)
	}
	return w
}
