//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	"github.com/truvity/sluis/v2/actors/key/internal/wrap"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
)

// spyDriver is the driver as key@ sees it, with a record of every message that crosses: the requests key@ sends and the
// responses it gets. The messages are kept as marshalled bytes, which is what a wire would carry.
type spyDriver struct {
	keystorev2alpha1connect.KeyStoreServiceClient
	mu      sync.Mutex
	traffic [][]byte
	signs   []*keystorev2alpha1.KeyStoreSignRequest
	ecdhs   []*keystorev2alpha1.EcdhRequest
	ensures []string // the purposes Ensure was asked for
}

func (s *spyDriver) note(m proto.Message) {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	s.traffic = append(s.traffic, b)
	s.mu.Unlock()
}

func (s *spyDriver) Ensure(ctx context.Context, req *connect.Request[keystorev2alpha1.EnsureRequest]) (*connect.Response[keystorev2alpha1.EnsureResponse], error) {
	s.note(req.Msg)
	s.mu.Lock()
	s.ensures = append(s.ensures, req.Msg.GetPurpose())
	s.mu.Unlock()
	res, err := s.KeyStoreServiceClient.Ensure(ctx, req)
	if err == nil {
		s.note(res.Msg)
	}
	return res, err
}

func (s *spyDriver) PublicKey(ctx context.Context, req *connect.Request[keystorev2alpha1.KeyStorePublicKeyRequest]) (*connect.Response[keystorev2alpha1.KeyStorePublicKeyResponse], error) {
	s.note(req.Msg)
	res, err := s.KeyStoreServiceClient.PublicKey(ctx, req)
	if err == nil {
		s.note(res.Msg)
	}
	return res, err
}

func (s *spyDriver) Sign(ctx context.Context, req *connect.Request[keystorev2alpha1.KeyStoreSignRequest]) (*connect.Response[keystorev2alpha1.KeyStoreSignResponse], error) {
	s.note(req.Msg)
	s.mu.Lock()
	s.signs = append(s.signs, proto.Clone(req.Msg).(*keystorev2alpha1.KeyStoreSignRequest))
	s.mu.Unlock()
	res, err := s.KeyStoreServiceClient.Sign(ctx, req)
	if err == nil {
		s.note(res.Msg)
	}
	return res, err
}

func (s *spyDriver) Ecdh(ctx context.Context, req *connect.Request[keystorev2alpha1.EcdhRequest]) (*connect.Response[keystorev2alpha1.EcdhResponse], error) {
	s.note(req.Msg)
	s.mu.Lock()
	s.ecdhs = append(s.ecdhs, proto.Clone(req.Msg).(*keystorev2alpha1.EcdhRequest))
	s.mu.Unlock()
	res, err := s.KeyStoreServiceClient.Ecdh(ctx, req)
	if err == nil {
		s.note(res.Msg)
	}
	return res, err
}

// spiedNode is a started node whose driver is wrapped in a spyDriver. The spy is put between key@ and its driver before
// the node starts, so the traffic of Init (the Ensure of each KeyPlan purpose) is in the record too.
func (e *testEnv) spiedNode(name string) (*node, *spyDriver) {
	e.t.Helper()
	n := e.newNode(nodeOpts{name: name})
	spy := &spyDriver{KeyStoreServiceClient: n.srv.driver}
	n.srv.driver = spy
	n.start()
	return n, spy
}

// secretForms are the forms in which a key could be written down by mistake.
func secretForms(key []byte) map[string][]byte {
	return map[string][]byte{
		"raw":            key,
		"hex":            []byte(hex.EncodeToString(key)),
		"HEX":            []byte(strings.ToUpper(hex.EncodeToString(key))),
		"base64":         []byte(base64.StdEncoding.EncodeToString(key)),
		"base64-raw":     []byte(base64.RawStdEncoding.EncodeToString(key)),
		"base64url":      []byte(base64.URLEncoding.EncodeToString(key)),
		"base64url-raw":  []byte(base64.RawURLEncoding.EncodeToString(key)),
		"decimal-bytes":  []byte(decimalList(key)),        // what fmt prints for a []byte in a log line or an audit field
		"go-syntax-hex":  []byte(fmt.Sprintf("%#v", key)), // []byte{0x1, ...}
		"hex-with-space": []byte(fmt.Sprintf("% x", key)), // % x
		"hex-with-colon": []byte(strings.Join(hexList(key), ":")),
	}
}

// decimalList is what fmt prints for a []byte: [1 2 3].
func decimalList(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = strconv.Itoa(int(c))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func hexList(b []byte) []string {
	out := make([]string, len(b))
	for i, c := range b {
		out[i] = fmt.Sprintf("%02x", c)
	}
	return out
}

// scan returns the sinks that hold the key in any of its forms, as "sink: form".
func scan(sinks map[string][]byte, key []byte) []string {
	var hits []string
	for name, data := range sinks {
		for form, needle := range secretForms(key) {
			if bytes.Contains(data, needle) {
				hits = append(hits, name+": "+form)
			}
		}
	}
	slices.Sort(hits)
	return hits
}

// recoverKeys opens every wrap of the node with the wrapping key of its driver, as the node itself does, and returns the
// data keys it holds. This is how the test learns the bytes it then looks for: the wrapping key is the driver's, in
// the test process.
func recoverKeys(t *testing.T, e *testEnv, n *node) map[keyRef][]byte {
	t.Helper()
	priv, err := n.driver.key(wrappingPurpose)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := priv.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	out := map[keyRef][]byte{}
	for _, it := range e.store.items {
		if it.GetAddress().GetKind() != "data-key-wrap" {
			continue
		}
		w := &keyv2alpha1.DataKeyWrap{}
		if err := proto.Unmarshal(it.GetValue(), w); err != nil {
			t.Fatal(err)
		}
		if w.GetRecipient() != n.srv.recipient {
			continue
		}
		eph, err := wrap.ParsePublic(w.GetEphemeralPublic())
		if err != nil {
			t.Fatal(err)
		}
		secret, err := ek.ECDH(eph)
		if err != nil {
			t.Fatal(err)
		}
		ref := keyRef{tenant: it.GetAddress().GetTenant(), purpose: w.GetPurpose(), generation: w.GetGeneration()}
		tenant := ref.tenant
		if tenant == "" {
			tenant = envelope.NoTenant
		}
		key, err := wrap.Unwrap(wrap.Context{Boundary: testBoundary, Tenant: tenant, Purpose: ref.purpose, Generation: ref.generation, Recipient: n.srv.recipient}, secret, w.GetWrappedKey())
		if err != nil {
			t.Fatalf("the node's own wrap of %v does not open: %v", ref, err)
		}
		out[ref] = key
	}
	return out
}

// exercised is what one run through the whole API of key@ produced: everything key@ said to its callers.
type exercised struct {
	responses [][]byte // each response message marshalled, and each refusal's text
	envs      map[string][]byte
	macs      map[string][]byte
}

func (x *exercised) say(m proto.Message) {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	x.responses = append(x.responses, b)
}

func (x *exercised) refused(err error) {
	if err != nil {
		x.responses = append(x.responses, []byte(err.Error()))
	}
}

// exercise calls every operation of KeyService for every purpose that it serves, for a tenant and for the boundary,
// and some that must be refused, and returns what key@ answered.
func exercise(t *testing.T, n *node) *exercised {
	t.Helper()
	ctx := context.Background()
	x := &exercised{envs: map[string][]byte{}, macs: map[string][]byte{}}
	mustSeal := func(name, actor, purpose, kind, tenant string, grant []byte) {
		t.Helper()
		res, err := n.client(actor).Seal(ctx, connect.NewRequest(&keyv2alpha1.SealRequest{
			Purpose: purpose, Address: addr(kind, tenant, vecID), Plaintext: []byte("plaintext of " + name), Grant: grant,
		}))
		if err != nil {
			t.Fatalf("Seal %s: %v", name, err)
		}
		x.say(res.Msg)
		x.envs[name] = res.Msg.GetEnvelope()
	}
	mustOpen := func(name, actor, purpose, kind, tenant string, grant []byte) {
		t.Helper()
		res, err := n.client(actor).Open(ctx, connect.NewRequest(&keyv2alpha1.OpenRequest{
			Items: []*keyv2alpha1.OpenItem{{Purpose: purpose, Address: addr(kind, tenant, vecID), Envelope: x.envs[name]}}, Grant: grant,
		}))
		if err != nil {
			t.Fatalf("Open %s: %v", name, err)
		}
		x.say(res.Msg)
		if string(res.Msg.GetPlaintexts()[0]) != "plaintext of "+name {
			t.Fatalf("Open %s gave %q", name, res.Msg.GetPlaintexts()[0])
		}
	}
	mustMac := func(name, actor, purpose, tenant, epoch string) {
		t.Helper()
		res, err := n.client(actor).Mac(ctx, connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: purpose, Tenant: tenant, Label: name, Input: []byte("input of " + name), Epoch: epoch}))
		if err != nil {
			t.Fatalf("Mac %s: %v", name, err)
		}
		x.say(res.Msg)
		x.macs[name] = res.Msg.GetMac()
	}
	sealer := n.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	writer := n.grant("writer", []string{"acme"}, []string{"seal"}, time.Minute)
	indexer := n.grant("indexer", []string{"acme"}, []string{"open"}, time.Minute)
	x.responses = append(x.responses, sealer, writer, indexer) // SealGrant answered with these
	for _, g := range [][]byte{sealer, writer, indexer} {
		og, err := n.client("signer").OpenGrant(ctx, connect.NewRequest(&keyv2alpha1.OpenGrantRequest{SealedGrant: g}))
		x.refused(err) // signer may not open a grant made for another holder: the refusal is a response too
		if err == nil {
			x.say(og.Msg)
		}
	}
	mustSeal("tenant-data", "session", "data", "person", "acme", sealer)
	mustOpen("tenant-data", "session", "data", "person", "acme", sealer)
	mustSeal("evidence", "writer", "evidence", "usage", "acme", writer)
	mustOpen("evidence", "indexer", "evidence", "usage", "acme", indexer)
	mustSeal("chain", "session", "chain", "session-chain", "acme", nil)
	mustOpen("chain", "exchange", "chain", "session-chain", "acme", nil)
	mustSeal("credential", "session", "credential", "staff-passkey", "acme", nil)
	mustOpen("credential", "session", "credential", "staff-passkey", "acme", nil)
	mustSeal("cookie", "session", "cookie", "cookie", "", nil)
	mustOpen("cookie", "session", "cookie", "cookie", "", nil)
	mustSeal("boundary-data", "exchange", "data", "person", "", nil)
	mustOpen("boundary-data", "exchange", "data", "person", "", nil)
	mustMac("mac", "session", "mac", "", "")
	mustMac("pairwise", "session", "pairwise", "acme", "")
	mustMac("pseudonym", "reader", "pseudonym", "acme", "202611")

	_, kid := publicKey(t, n, "signer", "token-signing")
	for _, c := range []struct{ actor, purpose string }{{"signer", "token-signing"}, {"writer", "audit-log"}} {
		res, err := n.client(c.actor).PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: c.purpose}))
		if err != nil {
			t.Fatalf("PublicKey %s: %v", c.purpose, err)
		}
		x.say(res.Msg)
	}
	signed, err := n.client("signer").Sign(ctx, signReq("token-signing", tokenInput(kid, "", "")))
	if err != nil {
		t.Fatal(err)
	}
	x.say(signed.Msg)
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	signed, err = n.client("writer").Sign(ctx, signReq("audit-log", []byte("example.com/log\n7\n"+root+"\n")))
	if err != nil {
		t.Fatal(err)
	}
	x.say(signed.Msg)

	// Refusals say what they refused and never more; their text is a response too.
	_, err = n.client("signer").Sign(ctx, signReq("release-signing", []byte("x")))
	x.refused(err)
	_, err = n.client("reader").Sign(ctx, signReq("token-signing", []byte("x")))
	x.refused(err)
	_, err = n.client("signer").PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "wrapping"}))
	x.refused(err)
	_, err = n.client("signer").Seal(ctx, connect.NewRequest(&keyv2alpha1.SealRequest{Purpose: "data", Address: addr("person", "acme", vecID), Plaintext: []byte("x")}))
	x.refused(err)
	_, err = n.client("session").Open(ctx, connect.NewRequest(&keyv2alpha1.OpenRequest{
		Items: []*keyv2alpha1.OpenItem{{Purpose: "cookie", Address: addr("cookie", "", vecID), Envelope: x.envs["cookie"][:10]}}}))
	x.refused(err)
	return x
}

// files reads every regular file under the directories.
func files(t *testing.T, dirs ...string) []byte {
	t.Helper()
	var all []byte
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.Type().IsRegular() {
				b, err := os.ReadFile(p) //nolint:gosec // a path under the directories the test names
				if err != nil {
					return err
				}
				all = append(all, []byte(p)...)
				all = append(all, b...)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return all
}

// storeBytes is every byte the fake store@ holds: ids, values and index values of every item of every kind.
func storeBytes(e *testEnv) []byte {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	var all []byte
	for k, it := range e.store.items {
		all = append(all, []byte(k)...)
		all = append(all, it.GetValue()...)
		for _, ix := range it.GetIndexes() {
			all = append(all, []byte(ix.GetName())...)
			all = append(all, ix.GetValue()...)
		}
	}
	for _, doc := range e.store.signed {
		all = append(all, doc...)
	}
	return all
}

// auditBytes is the audit facts a node made, in the two forms a transport could carry: JSON, and Go's own printing.
func auditBytes(t *testing.T, n *node) []byte {
	t.Helper()
	var all []byte
	for _, ev := range n.audit.all() {
		j, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, j...)
		all = append(all, []byte(fmt.Sprintf("%#v", ev))...)
	}
	return all
}

func trafficBytes(s *spyDriver) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Join(s.traffic, nil)
}

// verifies: REQ-KEYS-032, REQ-SUBJ-008
// The data key of a purpose exists, in the clear, only in the memory of key@: scanned for in every form it could be
// written in, it is in none of the places key@ writes or speaks to. The scan looks at the store (every item of every
// kind, indexes included, and the signed documents), at the audit facts, at the log, at every response of the whole
// API and every refusal's text, at the messages between key@ and its driver and at the files of its state
// directory. The test learns the bytes of each key by opening the node's own wrap, as the node does; every one of the
// nine keys (the five of a tenant that were used and the four of the boundary that were) is found, and the scan is
// shown to find a key where one is. What the scan cannot see is the memory of the process, and a place that this
// list does not name; the part of the claim about memory is the next test (the key is wiped when its time to live is
// over) and the tripwire on the API.
func TestNoDataKeyIsWrittenOrSaidOutsideItsWrap(t *testing.T) {
	log := captureLog(t)
	e := newTestEnv(t, "development")
	a, spyA := e.spiedNode("node-1")
	b, spyB := e.spiedNode("node-2")
	x := exercise(t, a)
	// The second node opens what the first sealed: it opens the same keys from its own wraps, in its own memory.
	res, err := b.client("session").Open(context.Background(), connect.NewRequest(&keyv2alpha1.OpenRequest{
		Items: []*keyv2alpha1.OpenItem{{Purpose: "cookie", Address: addr("cookie", "", vecID), Envelope: x.envs["cookie"]}}}))
	if err != nil || string(res.Msg.GetPlaintexts()[0]) != "plaintext of cookie" {
		t.Fatalf("node-2 opens the cookie: %v", err)
	}
	x.say(res.Msg)
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	keys := recoverKeys(t, e, a)
	want := []keyRef{
		{"acme", "data", 1}, {"acme", "evidence", 1}, {"acme", "chain", 1}, {"acme", "credential", 1}, {"acme", "pairwise", 1}, {"acme", "pseudonym", 202611},
		{"", "grant", 1}, {"", "cookie", 1}, {"", "mac", 1}, {"", "data", 1},
	}
	for _, ref := range want {
		if k, ok := keys[ref]; !ok || len(k) != 32 {
			t.Fatalf("the node holds no 32-byte key for %v (keys: %d); the scan would look for nothing", ref, len(keys))
		}
	}
	// The recovered key is the key that sealed: it opens a sealed value, and it is the one Mac answers with.
	pt, err := envelope.Open(keys[keyRef{"acme", "data", 1}], x.envs["tenant-data"], envelope.Address{Boundary: testBoundary, Tenant: "acme", Kind: "person", ID: vecID})
	if err != nil || string(pt) != "plaintext of tenant-data" {
		t.Fatalf("the recovered tenant data key does not open the tenant's value: %q, %v", pt, err)
	}
	if got := macTag(keys[keyRef{"", "mac", 1}], "mac", []byte("input of mac")); !bytes.Equal(got, x.macs["mac"]) {
		t.Fatal("the recovered mac key is not the key Mac answered with")
	}

	sinks := map[string][]byte{
		"store":         storeBytes(e),
		"audit node-1":  auditBytes(t, a),
		"audit node-2":  auditBytes(t, b),
		"log":           []byte(log.String()),
		"responses":     bytes.Join(x.responses, nil),
		"driver node-1": trafficBytes(spyA),
		"driver node-2": trafficBytes(spyB),
		"state node-1":  files(t, a.srv.cfg.StateDir),
		"state node-2":  files(t, b.srv.cfg.StateDir),
	}
	// Each sink must hold something, or an empty sink would pass any scan.
	for name, data := range sinks {
		if len(data) < 100 {
			t.Fatalf("sink %q holds %d bytes: the test collected nothing there", name, len(data))
		}
	}
	if len(x.responses) < 20 {
		t.Fatalf("%d responses collected", len(x.responses))
	}
	for ref, key := range keys {
		if hits := scan(sinks, key); len(hits) != 0 {
			t.Errorf("the data key %v (%d bytes) is written down: %v", ref, len(key), hits)
		}
	}

	// The control: the scan finds a key that is there, in each sink and in each form. Without it, an empty result
	// above could be a scan that sees nothing.
	probe := keys[keyRef{"acme", "data", 1}]
	for sink := range sinks {
		for form, needle := range secretForms(probe) {
			planted := map[string][]byte{sink: append([]byte("noise "), needle...)}
			if hits := scan(planted, probe); len(hits) == 0 {
				t.Errorf("the scan does not find a key planted in %s as %s", sink, form)
			}
		}
	}
	// The store does hold the key, wrapped: the wrap is there and is not the key.
	if !bytes.Contains(sinks["store"], []byte("data/1/")) {
		t.Error("no wrap of the tenant data key in the store")
	}
}

// verifies: REQ-KEYS-032
// A key opened for a call is wiped in key@'s memory when its time to live is over: the slice the cache held is zeroes,
// not merely unreferenced. This is the memory half of "open it only in its own memory"; Go gives no promise about
// copies (cache.go), so the test proves what key@ does and not that no copy remains.
func TestAnExpiredDataKeyIsZeroedInMemory(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	if _, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	ref := keyRef{"", "cookie", 1}
	ent := n.srv.cache.get(ref)
	if ent == nil {
		t.Fatal("the key is not in the cache after a Seal")
	}
	ent.mu.RLock()
	held := ent.key // the cache's own slice: its backing array is what must be zeroed
	live := bytes.Count(held, []byte{0}) != len(held)
	ent.mu.RUnlock()
	if !live || len(held) != 32 {
		t.Fatalf("the cached key is %d bytes and not a key", len(held))
	}
	copyOf := bytes.Clone(held)
	if got := recoverKeys(t, e, n)[ref]; !bytes.Equal(got, copyOf) {
		t.Fatal("the cached key is not the key of the wrap")
	}
	e.clock.advance(16 * time.Minute) // past the 15 minutes of the KeyPlan
	if n.srv.cache.get(ref) != nil {
		t.Fatal("an expired key was served from the cache")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ent.mu.RLock()
		zero := bytes.Count(held, []byte{0}) == len(held)
		ent.mu.RUnlock()
		if zero {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the key was dropped from the cache but its bytes were not zeroed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The next call opens it again from the wrap, in a new buffer.
	if _, err := seal1(n.client("session"), "cookie", "cookie", "", "s2", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	// The first Seal made the key in memory (no ECDH); the second opened it from its wrap (one), and made no new key.
	if n.driver.ecdhs.Load() != 1 || e.store.wrapCount() != 1 {
		t.Fatalf("ECDH calls = %d, wraps = %d, want 1 and 1: the key was not opened again from its wrap", n.driver.ecdhs.Load(), e.store.wrapCount())
	}
}

// bytesFields walks a message type and returns "Message.field" for every bytes field in it, nested messages included.
func bytesFields(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool, out *[]string) {
	if seen[md.FullName()] {
		return
	}
	seen[md.FullName()] = true
	fields := md.Fields()
	for i := range fields.Len() {
		f := fields.Get(i)
		switch f.Kind() {
		case protoreflect.BytesKind:
			*out = append(*out, string(md.Name())+"."+string(f.Name()))
		case protoreflect.MessageKind, protoreflect.GroupKind:
			bytesFields(f.Message(), seen, out)
		}
	}
}

// verifies: REQ-KEYS-032
// No call of key@ answers with a data key. This is a tripwire and not a proof: the response messages of KeyService and
// KeyAdminService are walked, and each bytes field in them must be one on the list below, with the reason it is not a
// data key. A new bytes field, in any response, fails the test until someone has read it and added it with a reason.
// A key written to a string field, or put in one of the bytes fields below, is not caught by this test (the scan of
// TestNoDataKeyIsWrittenOrSaidOutsideItsWrap looks at what the calls actually answered). The same is done for the
// DataKeyWrap, the one place key@ keeps a key, and for what key@ sends to its driver.
func TestNoResponseOfKeyAtHasAFieldThatCouldHoldADataKey(t *testing.T) {
	allowed := map[string]string{
		"SealResponse.envelope":          "the sealed value, AES-256-GCM under the data key",
		"OpenResponse.plaintexts":        "the caller's own plaintext",
		"SealGrantResponse.sealed_grant": "a grant sealed under the grant key",
		"SignResponse.signature_raw":     "a signature",
		"SignResponse.signature_der":     "a signature",
		"MacResponse.mac":                "HMAC-SHA384 of the input, not the key",
		"PublicKeyResponse.spki_der":     "a public key",
		"PublicKeyResponse.x5c":          "a certificate chain",
		// The hand-off calls of the admin socket (handoff.proto).
		"PrepareResponse.spki_der":          "a public key",
		"PrepareResponse.attestation":       "the attestation certificates of a card slot: public",
		"SignRequestResponse.signature_der": "a signature",
	}
	var got []string
	for _, svc := range []struct {
		file protoreflect.FileDescriptor
		name string
	}{
		{keyv2alpha1.File_sluis_key_v2alpha1_key_proto, "KeyService"},
		{keyv2alpha1.File_sluis_key_v2alpha1_key_proto, "KeyAdminService"},
		{keyv2alpha1.File_sluis_key_v2alpha1_handoff_proto, "KeyHandoffService"},
	} {
		sd := svc.file.Services().ByName(protoreflect.Name(svc.name))
		if sd == nil {
			t.Fatalf("service %s not found", svc.name)
		}
		methods := sd.Methods()
		for i := range methods.Len() {
			bytesFields(methods.Get(i).Output(), map[protoreflect.FullName]bool{}, &got)
		}
	}
	if len(got) < len(allowed) {
		t.Fatalf("the walk found %d bytes fields (%v), fewer than the %d allowed: it walked the wrong thing", len(got), got, len(allowed))
	}
	for _, f := range got {
		if _, ok := allowed[f]; !ok {
			t.Errorf("response field %s is bytes and is not on the list: is it a key?", f)
		}
	}
	for f := range allowed {
		if !slices.Contains(got, f) {
			t.Errorf("the list names %s, which no response has: the list is stale", f)
		}
	}
	// The kinds key@ keeps: a DataKeyWrap holds the wrapped key and the sender's public key, and nothing else in bytes.
	var wrapFields []string
	bytesFields(keyv2alpha1.File_sluis_key_v2alpha1_key_proto.Messages().ByName("DataKeyWrap"), map[protoreflect.FullName]bool{}, &wrapFields)
	slices.Sort(wrapFields)
	if !slices.Equal(wrapFields, []string{"DataKeyWrap.ephemeral_public", "DataKeyWrap.wrapped_key"}) {
		t.Errorf("DataKeyWrap bytes fields = %v, want the sender's public key and the wrapped key only", wrapFields)
	}
	// What key@ sends its driver for a data key's sake: the peer's public key, to derive the wrapping secret. And for
	// a signature: a digest. No request of the driver that key@ uses has a field for a data key.
	wantReq := map[string][]string{
		"Ensure":    nil,
		"PublicKey": nil,
		"Sign":      {"KeyStoreSignRequest.digest"},
		"Ecdh":      {"EcdhRequest.peer_public"},
	}
	ks := keystorev2alpha1.File_sluis_port_keystore_v2alpha1_keystore_proto.Services().ByName("KeyStoreService").Methods()
	for name, want := range wantReq {
		m := ks.ByName(protoreflect.Name(name))
		if m == nil {
			t.Fatalf("driver method %s not found", name)
		}
		var fields []string
		bytesFields(m.Input(), map[protoreflect.FullName]bool{}, &fields)
		if !slices.Equal(fields, want) {
			t.Errorf("driver %s request bytes fields = %v, want %v", name, fields, want)
		}
	}
}

// verifies: REQ-KEYS-061
// An authority key signs inside its key store: every signature key@ returns was made by the driver, over the digest
// of the content key@ had checked, and key@ has no other way to make one. The test puts a spy between key@ and its
// driver and shows that each Sign of key@ is exactly one Sign of the driver, with the digest of the content
// (SHA-384, or SHA-256 for the audit log), that the signature key@ returns is the driver's, and that a driver that
// signs wrongly gets no signature out of key@ (key@ does not fall back on a key of its own). It also shows that the
// private scalar of each authority key, which the test can read in the fake driver, is in none of the places the
// sibling test scans. What it cannot show is that key@ holds no key material that it should not: there is no
// export call in the driver port to leave open, which the allow-list of the sibling test pins down, and that
// the code never imports a private key is a statement about the code and not about a run.
func TestAnAuthorityKeySignsInsideItsKeyStore(t *testing.T) {
	log := captureLog(t)
	e := newTestEnv(t, "development")
	n, spy := e.spiedNode("node-1")
	ctx := context.Background()

	pub, kid := publicKey(t, n, "signer", "token-signing")
	tokenIn := tokenInput(kid, "", "")
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	checkpoint := []byte("example.com/log\n7\n" + root + "\n")

	var said [][]byte
	for _, c := range []struct {
		actor, purpose string
		content        []byte
		digest         []byte
		pub            *ecdsa.PublicKey
	}{
		{"signer", "token-signing", tokenIn, sum384(tokenIn), pub},
		{"writer", "audit-log", checkpoint, sum256(checkpoint), nil},
	} {
		before := len(spy.signs)
		driverSignsBefore := n.driver.signs.Load()
		res, err := n.client(c.actor).Sign(ctx, signReq(c.purpose, c.content))
		if err != nil {
			t.Fatalf("Sign %s: %v", c.purpose, err)
		}
		said = append(said, mustMarshal(res.Msg))
		if got := n.driver.signs.Load() - driverSignsBefore; got != 1 {
			t.Fatalf("%s: one Sign of key@ made %d signatures in the driver, want 1", c.purpose, got)
		}
		if len(spy.signs) != before+1 {
			t.Fatalf("%s: the driver saw %d new Sign requests, want 1", c.purpose, len(spy.signs)-before)
		}
		req := spy.signs[before]
		if req.GetPurpose() != c.purpose || !bytes.Equal(req.GetDigest(), c.digest) {
			t.Fatalf("%s: the driver was asked to sign %x for %q, want the digest %x of the content", c.purpose, req.GetDigest(), req.GetPurpose(), c.digest)
		}
		// The signature that came back is the driver's: it verifies under the driver's public key over the digest.
		priv, err := n.driver.key(c.purpose)
		if err != nil {
			t.Fatal(err)
		}
		if !ecdsa.VerifyASN1(&priv.PublicKey, c.digest, res.Msg.GetSignatureDer()) {
			t.Fatalf("%s: the signature is not one that the driver's key made over the digest", c.purpose)
		}
		// Authority keys are never opened by key@ for a wrap: ECDH is asked of the wrapping key alone.
		for _, r := range spy.ecdhs {
			if r.GetPurpose() != wrappingPurpose {
				t.Errorf("key@ asked the driver for an ECDH under %q", r.GetPurpose())
			}
		}
		// The private scalar of the key is nowhere key@ speaks.
		ek, err := priv.ECDH()
		if err != nil {
			t.Fatal(err)
		}
		d := ek.Bytes() // the private scalar, fixed width
		sinks := map[string][]byte{
			"response":       bytes.Join(said, nil),
			"store":          storeBytes(e),
			"audit":          auditBytes(t, n),
			"log":            []byte(log.String()),
			"driver traffic": trafficBytes(spy),
			"state":          files(t, n.srv.cfg.StateDir),
		}
		if hits := scan(sinks, d); len(hits) != 0 {
			t.Errorf("the private key of %s is written down: %v", c.purpose, hits)
		}
		if hits := scan(map[string][]byte{"planted": append([]byte("x"), d...)}, d); len(hits) == 0 {
			t.Fatal("the scan does not find a scalar planted in a sink")
		}
	}
	// A driver that signs wrongly gets no signature out of key@, and key@ makes none itself.
	bad := newFakeDriver("software")
	bad.badSignature = true
	e2 := newTestEnv(t, "development")
	n2 := e2.startedNode(nodeOpts{driver: bad})
	_, kid2 := publicKey(t, n2, "signer", "token-signing")
	res, err := n2.client("signer").Sign(ctx, signReq("token-signing", tokenInput(kid2, "", "")))
	if err == nil || res != nil {
		t.Fatalf("a signature came out of key@ although the driver's was wrong: %v", err)
	}
	// Content that key@ refuses never reaches the driver.
	before := n.driver.signs.Load()
	_, err = n.client("signer").Sign(ctx, signReq("token-signing", []byte("not a JWS signing input")))
	wantRefusal(t, err, connect.CodeInvalidArgument, "content")
	if n.driver.signs.Load() != before {
		t.Fatal("refused content was passed to the driver")
	}
}

func sum384(b []byte) []byte { d := sha512.Sum384(b); return d[:] }
func sum256(b []byte) []byte { d := sha256.Sum256(b); return d[:] }
