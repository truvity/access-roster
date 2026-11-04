//go:build sluis_test

package keyd

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// testBoundary is the boundary of the vector in store-api.md.
const testBoundary = "prod"

// clock is a settable clock.
type clock struct{ t atomic.Int64 }

func newClock() *clock {
	c := &clock{}
	c.t.Store(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC).UnixNano())
	return c
}
func (c *clock) now() time.Time          { return time.Unix(0, c.t.Load()).UTC() }
func (c *clock) advance(d time.Duration) { c.t.Add(int64(d)) }

// shortDir is a short temporary directory: a Unix socket path holds about 108 bytes.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// resolver names the one process of the tests: every connection is the actor in who, in uid block 0.
type resolver struct{ who atomic.Value }

func (r *resolver) set(name string) { r.who.Store(name) }
func (r *resolver) resolve(uid uint32) (string, uint32, bool) {
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	name, _ := r.who.Load().(string)
	return name, 0, uid == self && name != ""
}

// serveFake serves a handler on a socket of the tests, for any caller, and stops it with the test.
func serveFake(t *testing.T, socket, path string, h http.Handler) {
	t.Helper()
	r := &resolver{}
	r.set("key")
	cfg := rpc.WithNameResolver(rpc.ServerConfig{
		Actor: "store", Socket: socket, Allow: func(rpc.Peer, string) bool { return true },
	}, r.resolve)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, cfg, rpc.Handler{Path: path, H: h}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("fake Serve: %v", err)
		}
	})
	waitSocket(t, socket)
}

func waitSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket %s did not appear", path)
}

// fakeStore is an in-memory StoreServiceHandler with the batch atomicity and the indexes key@ relies on.
type fakeStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	mu         sync.Mutex
	items      map[string]*storev2alpha1.Item
	wrapWrites int // CREATE operations of data-key-wrap that were applied
	failWrites bool
	// failKind makes every Get of the kind (a segment) unavailable, as a store@ that is down for it.
	failKind string
	// signed holds the signed document of a config kind by its segment, as a config source would. A store@ that is
	// compromised serves whatever is here, so a test puts a forged document here.
	signed      map[string][]byte
	signedCalls int
}

func newFakeStore() *fakeStore {
	return &fakeStore{items: map[string]*storev2alpha1.Item{}, signed: map[string][]byte{}}
}

func itemKey(a *typev2alpha1.Address) string {
	return a.GetTenant() + "|" + a.GetKind() + "|" + a.GetId()
}

func (f *fakeStore) put(kind, tenant, id string, v proto.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := proto.Marshal(v)
	if err != nil {
		panic(err)
	}
	a := &typev2alpha1.Address{Kind: kind, Tenant: tenant, Id: id}
	f.items[itemKey(a)] = &storev2alpha1.Item{Address: a, Version: 1, Value: b}
}

func (f *fakeStore) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failKind != "" && req.Msg.GetAddress().GetKind() == f.failKind {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	it, ok := f.items[itemKey(req.Msg.GetAddress())]
	if !ok {
		return nil, refusal.New(connect.CodeNotFound, "absent", "")
	}
	return connect.NewResponse(&storev2alpha1.GetResponse{Item: it}), nil
}

func (f *fakeStore) GetSignedConfig(_ context.Context, req *connect.Request[storev2alpha1.GetSignedConfigRequest]) (*connect.Response[storev2alpha1.GetSignedConfigResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signedCalls++
	doc, ok := f.signed[req.Msg.GetKind()]
	if !ok {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	return connect.NewResponse(&storev2alpha1.GetSignedConfigResponse{Document: doc}), nil
}

func (f *fakeStore) List(_ context.Context, req *connect.Request[storev2alpha1.ListRequest]) (*connect.Response[storev2alpha1.ListResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var all []*storev2alpha1.Item
	for _, it := range f.items {
		a := it.GetAddress()
		if a.GetKind() != req.Msg.GetKind() || a.GetTenant() != req.Msg.GetTenant() {
			continue
		}
		if idx := req.Msg.GetIndex(); idx != "" {
			match := false
			for _, e := range it.GetIndexes() {
				if e.GetName() == idx && string(e.GetValue()) == string(req.Msg.GetIndexValue()) {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		all = append(all, it)
	}
	slices.SortFunc(all, func(a, b *storev2alpha1.Item) int {
		return strings.Compare(a.GetAddress().GetId(), b.GetAddress().GetId())
	})
	return connect.NewResponse(&storev2alpha1.ListResponse{Items: all}), nil
}

func (f *fakeStore) Write(_ context.Context, req *connect.Request[storev2alpha1.WriteRequest]) (*connect.Response[storev2alpha1.WriteResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrites {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	seen := map[string]bool{}
	for _, op := range req.Msg.GetOperations() { // all or none: check first
		k := itemKey(op.GetAddress())
		if op.GetVerb() == storev2alpha1.Verb_CREATE && (f.items[k] != nil || seen[k]) {
			return nil, refusal.New(connect.CodeAlreadyExists, "taken", "")
		}
		seen[k] = true
	}
	var out []*storev2alpha1.Item
	for _, op := range req.Msg.GetOperations() {
		k := itemKey(op.GetAddress())
		cur := f.items[k]
		it := &storev2alpha1.Item{Address: op.GetAddress(), Version: cur.GetVersion() + 1, Value: op.GetValue(), Indexes: op.GetIndexes()}
		f.items[k] = it
		out = append(out, it)
		if op.GetAddress().GetKind() == "data-key-wrap" && op.GetVerb() == storev2alpha1.Verb_CREATE {
			f.wrapWrites++
		}
	}
	return connect.NewResponse(&storev2alpha1.WriteResponse{Items: out}), nil
}

func (f *fakeStore) wrapCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, it := range f.items {
		if it.GetAddress().GetKind() == "data-key-wrap" {
			n++
		}
	}
	return n
}

// eraseWraps deletes every wrap of the tenant, as a tenant's exit does, and returns how many there were.
func (f *fakeStore) eraseWraps(tenant string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, it := range f.items {
		if it.GetAddress().GetKind() == "data-key-wrap" && it.GetAddress().GetTenant() == tenant {
			delete(f.items, k)
			n++
		}
	}
	return n
}

func (f *fakeStore) wrapWriteCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wrapWrites
}

// fakeDriver is a key-store driver that holds software keys in memory, one per purpose.
type fakeDriver struct {
	keystorev2alpha1connect.UnimplementedKeyStoreServiceHandler
	store string
	mu    sync.Mutex
	keys  map[string]*ecdsa.PrivateKey
	ecdhs atomic.Int64
	signs atomic.Int64
	// wrongCurve makes Ensure answer a P-384 key for an ES256 request, as a driver that does not enforce the pairing would.
	wrongCurve bool
	// badSignature makes Sign return a signature over the wrong digest.
	badSignature bool
	// now stamps the keys it makes, as a store reports their age; nil is time.Now.
	now  func() time.Time
	made map[string]time.Time
}

func newFakeDriver(storeName string) *fakeDriver {
	return &fakeDriver{store: storeName, keys: map[string]*ecdsa.PrivateKey{}}
}

// wrappingID makes the wrapping key if there is none and returns its RFC 7638 thumbprint: the id a KeyPlan lists.
func (d *fakeDriver) wrappingID() string {
	res, err := d.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "wrapping", Algorithm: "ECDH-P384"}))
	if err != nil {
		panic(err)
	}
	id, err := spkiThumbprint(res.Msg.GetSpkiDer())
	if err != nil {
		panic(err)
	}
	return id
}

func (d *fakeDriver) Capabilities(context.Context, *connect.Request[keystorev2alpha1.CapabilitiesRequest]) (*connect.Response[keystorev2alpha1.CapabilitiesResponse], error) {
	return connect.NewResponse(&keystorev2alpha1.CapabilitiesResponse{Store: d.store, Algorithms: []string{"ES384", "ES256", "ECDH-P384"}}), nil
}

func (d *fakeDriver) Ensure(_ context.Context, req *connect.Request[keystorev2alpha1.EnsureRequest]) (*connect.Response[keystorev2alpha1.EnsureResponse], error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k, ok := d.keys[req.Msg.GetPurpose()]
	if !ok {
		var err error
		curve := elliptic.P384()
		if req.Msg.GetAlgorithm() == "ES256" && !d.wrongCurve {
			curve = elliptic.P256()
		}
		if k, err = ecdsa.GenerateKey(curve, rand.Reader); err != nil {
			return nil, err
		}
		d.keys[req.Msg.GetPurpose()] = k
		if d.made == nil {
			d.made = map[string]time.Time{}
		}
		at := time.Now()
		if d.now != nil {
			at = d.now()
		}
		d.made[req.Msg.GetPurpose()] = at
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	res := &keystorev2alpha1.EnsureResponse{SpkiDer: der, Created: !ok, CreatedAt: timestamppb.New(d.made[req.Msg.GetPurpose()])}
	return connect.NewResponse(res), nil
}

func (d *fakeDriver) PublicKey(_ context.Context, req *connect.Request[keystorev2alpha1.KeyStorePublicKeyRequest]) (*connect.Response[keystorev2alpha1.KeyStorePublicKeyResponse], error) {
	k, err := d.key(req.Msg.GetPurpose())
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&keystorev2alpha1.KeyStorePublicKeyResponse{SpkiDer: der}), nil
}

func (d *fakeDriver) key(purpose string) (*ecdsa.PrivateKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k, ok := d.keys[purpose]
	if !ok {
		return nil, refusal.New(connect.CodeNotFound, "absent", "")
	}
	return k, nil
}

func (d *fakeDriver) Sign(_ context.Context, req *connect.Request[keystorev2alpha1.KeyStoreSignRequest]) (*connect.Response[keystorev2alpha1.KeyStoreSignResponse], error) {
	k, err := d.key(req.Msg.GetPurpose())
	if err != nil {
		return nil, err
	}
	d.signs.Add(1)
	digest := req.Msg.GetDigest()
	if d.badSignature {
		digest = make([]byte, len(digest))
	}
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&keystorev2alpha1.KeyStoreSignResponse{SignatureDer: sig}), nil
}

func (d *fakeDriver) Ecdh(_ context.Context, req *connect.Request[keystorev2alpha1.EcdhRequest]) (*connect.Response[keystorev2alpha1.EcdhResponse], error) {
	k, err := d.key(req.Msg.GetPurpose())
	if err != nil {
		return nil, err
	}
	d.ecdhs.Add(1)
	peer, err := ecdh.P384().NewPublicKey(req.Msg.GetPeerPublic())
	if err != nil {
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "peer_public")
	}
	ek, err := k.ECDH()
	if err != nil {
		return nil, err
	}
	secret, err := ek.ECDH(peer)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&keystorev2alpha1.EcdhResponse{SharedSecret: secret}), nil
}

// recorder is an Auditor that keeps the events; failing makes every emit an error.
type recorder struct {
	mu      sync.Mutex
	events  []Event
	failing bool
}

func (r *recorder) Emit(_ context.Context, ev Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	if r.failing {
		return errors.New("transport down")
	}
	return nil
}

func (r *recorder) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

func (r *recorder) count(action string) int {
	n := 0
	for _, e := range r.all() {
		if e.Action == action {
			n++
		}
	}
	return n
}

// testEnv is one boundary of the tests: one fake store, and any number of key@ nodes on it.
type testEnv struct {
	t     *testing.T
	clock *clock
	store *fakeStore
	sock  string // the store's socket

	// The publisher of the config: its key signs the KeyPlan, and the bootstrap file every node reads pins it.
	pub       *ecdsa.PrivateKey
	bootstrap string // the path of the bootstrap file
	seq       uint64 // the seq of the last KeyPlan signed
	plan      *configv2alpha1.KeyPlan
	seqB      uint64 // the seq of the last Boundary signed
	seqD      uint64 // the seq of the last key revocation declaration of nextSeq
	boundary  *configv2alpha1.Boundary
}

// defaultPlan is the KeyPlan of tonight.
func defaultPlan() *configv2alpha1.KeyPlan {
	return &configv2alpha1.KeyPlan{
		CacheTtl: durationpb.New(15 * time.Minute),
		Purposes: []*configv2alpha1.KeyPurposePlan{
			{Purpose: "wrapping", Algorithm: "ECDH-P384", Slot: "9d"},
			{Purpose: "token-signing", Algorithm: "ES384", Slot: "9a"},
			{Purpose: "audit-log", Algorithm: "ES256", Slot: "84"},
			{Purpose: "data", Algorithm: "AES-256-GCM"},
		},
	}
}

func newTestEnv(t *testing.T, environment string) *testEnv {
	t.Helper()
	e := &testEnv{t: t, clock: newClock(), store: newFakeStore()}
	e.pub = newPublisher(t)
	e.bootstrap = writeBootstrap(t, publisherEntry("publisher-1", &e.pub.PublicKey))
	e.putBoundary(&configv2alpha1.Boundary{Name: testBoundary, Kind: "environment", Level: "L2", Environment: environment,
		Issuer: "https://sluis.example.test", DefaultTenant: "acme"})
	e.putPlan(defaultPlan())
	e.sock = filepath.Join(shortDir(t), "st.sock")
	path, h := storev2alpha1connect.NewStoreServiceHandler(e.store)
	serveFake(t, e.sock, path, h)
	return e
}

// putPlan publishes a KeyPlan as the pipeline would: signed by the publisher, under a seq higher than the last. It
// is what store@ serves from then on.
func (e *testEnv) putPlan(plan *configv2alpha1.KeyPlan) {
	e.t.Helper()
	e.plan = plan
	e.seq++
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	e.store.signed["key-plan"] = e.sign("publisher-1", e.pub, e.seq, planPayload(e.t, plan))
}

// putBoundary publishes a Boundary as the pipeline would: signed by the publisher, under a seq higher than the last.
func (e *testEnv) putBoundary(b *configv2alpha1.Boundary) {
	e.t.Helper()
	e.boundary = b
	e.seqB++
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	e.store.signed["boundary"] = e.signKind("publisher-1", e.pub, e.seqB, boundaryKind, boundaryPayload(e.t, b))
}

// sign signs a payload under a key and seq, as a document of the KeyPlan kind.
func (e *testEnv) sign(kid string, key *ecdsa.PrivateKey, seq uint64, payload []byte) []byte {
	e.t.Helper()
	return e.signKind(kid, key, seq, keyPlanKind, payload)
}

// signKind signs a payload as a document that names the kind in its protected header.
func (e *testEnv) signKind(kid string, key *ecdsa.PrivateKey, seq uint64, kind string, payload []byte) []byte {
	e.t.Helper()
	doc, err := signedconfig.Sign(key, kid, seq, kind, payload)
	if err != nil {
		e.t.Fatal(err)
	}
	return doc
}

// list adds recipients to the KeyPlan, as a reviewed and signed commit would.
func (e *testEnv) list(ids ...string) {
	e.t.Helper()
	plan := proto.Clone(e.plan).(*configv2alpha1.KeyPlan)
	for _, id := range ids {
		if !slices.Contains(plan.Recipients, id) {
			plan.Recipients = append(plan.Recipients, id)
		}
	}
	e.putPlan(plan)
}

// node is one key@ with its driver, its auditor and its sockets.
type node struct {
	e      *testEnv
	srv    *Server
	driver *fakeDriver
	audit  *recorder // nil when the node has another Auditor
	runDir string
	who    *resolver
	cancel context.CancelFunc
	done   chan error
}

// nodeOpts are the options of a node.
type nodeOpts struct {
	name      string // the recipient label base
	driver    *fakeDriver
	audit     Auditor
	transport string // the emit socket, for the check command
	// unlisted leaves the node's wrapping key out of the KeyPlan, as a node is until a commit lists it.
	unlisted bool
	// stateDir is key@'s durable state; empty makes a new one, as a node with a new disk has.
	stateDir string
}

// newNode makes a key@ for the node, with its run directory and driver, but does not start it.
func (e *testEnv) newNode(o nodeOpts) *node {
	e.t.Helper()
	if o.name == "" {
		o.name = "node-1"
	}
	if o.driver == nil {
		o.driver = newFakeDriver("software")
	}
	if o.driver.now == nil {
		o.driver.now = e.clock.now // the keys are made at the time of the test's clock
	}
	if o.audit == nil {
		o.audit = &recorder{}
	}
	rec, _ := o.audit.(*recorder)
	if !o.unlisted {
		e.list(o.driver.wrappingID())
	}
	if o.stateDir == "" {
		o.stateDir = shortDir(e.t)
	}
	runDir := shortDir(e.t)
	for _, c := range registry.CallersOf("key") {
		if err := os.Mkdir(filepath.Join(runDir, c), 0o750); err != nil {
			e.t.Fatal(err)
		}
	}
	dsock := filepath.Join(shortDir(e.t), "d.sock")
	dpath, dh := keystorev2alpha1connect.NewKeyStoreServiceHandler(o.driver)
	serveFake(e.t, dsock, dpath, dh)

	srv, err := New(Config{
		Boundary: testBoundary, RunDir: runDir, StoreSocket: e.sock, DriverSocket: dsock, Node: o.name,
		Bootstrap: e.bootstrap, StateDir: o.stateDir, Auditor: o.audit, Now: e.clock.now, RewrapEvery: time.Hour, TransportSocket: o.transport,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	n := &node{e: e, srv: srv, driver: o.driver, audit: rec, runDir: runDir, who: &resolver{}}
	n.who.set("policy")
	srv.serverConfig = func(c rpc.ServerConfig) rpc.ServerConfig { return rpc.WithNameResolver(c, n.who.resolve) }
	// The admin socket serves root; the tests run as another user, which stands for root here.
	srv.adminAllow = func(uid uint32) bool { return int(uid) == os.Getuid() }
	return n
}

// start initialises the node and serves its sockets until the test ends.
func (n *node) start() {
	n.e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if err := n.srv.Init(ctx); err != nil {
		cancel()
		n.e.t.Fatalf("Init: %v", err)
	}
	n.cancel = cancel
	n.done = make(chan error, 1)
	go func() { n.done <- n.srv.Serve(ctx) }()
	for _, c := range registry.CallersOf("key") {
		waitSocket(n.e.t, filepath.Join(n.runDir, c, socketName))
	}
	waitSocket(n.e.t, filepath.Join(n.runDir, adminSocketName))
	n.e.t.Cleanup(n.stop)
}

func (n *node) stop() {
	if n.cancel == nil {
		return
	}
	n.cancel()
	n.cancel = nil
	if err := <-n.done; err != nil {
		n.e.t.Errorf("Serve: %v", err)
	}
}

// startedNode is newNode and start.
func (e *testEnv) startedNode(o nodeOpts) *node {
	e.t.Helper()
	n := e.newNode(o)
	n.start()
	return n
}

// as returns a client that reaches the socket of `socketOf` as the actor `who`. The identity is read once per
// connection, so every call gets a client of its own.
func (n *node) as(who, socketOf string) keyv2alpha1connect.KeyServiceClient {
	n.who.set(who)
	hc, url := rpc.Dial(filepath.Join(n.runDir, socketOf, socketName))
	return keyv2alpha1connect.NewKeyServiceClient(hc, url, rpc.ClientOptions()...)
}

// client is the client of an actor on its own socket.
func (n *node) client(actor string) keyv2alpha1connect.KeyServiceClient { return n.as(actor, actor) }

// grant has policy seal a grant and returns it sealed.
func (n *node) grant(holder string, tenants, ops []string, life time.Duration) []byte {
	n.e.t.Helper()
	g := grantProto(holder, tenants, n.e.clock.now(), life)
	g.KeyOps = ops
	res, err := n.client("policy").SealGrant(context.Background(), connect.NewRequest(&keyv2alpha1.SealGrantRequest{Grant: g}))
	if err != nil {
		n.e.t.Fatalf("SealGrant: %v", err)
	}
	return res.Msg.GetSealedGrant()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 2*n)
	for _, c := range b {
		out = append(out, hexd[c>>4], hexd[c&15])
	}
	return string(out)
}

func addr(kind, tenant, id string) *typev2alpha1.Address {
	return &typev2alpha1.Address{Kind: kind, Tenant: tenant, Id: id}
}

// wantRefusal checks the code and the reason of an error.
func wantRefusal(t *testing.T, err error, code connect.Code, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v/%s", code, reason)
	}
	got, _ := refusal.Reason(err)
	if connect.CodeOf(err) != code || got != reason {
		t.Fatalf("error = %v/%s (%v), want %v/%s", connect.CodeOf(err), got, err, code, reason)
	}
}

// sealAt seals with an explicit generation, as an older key@ would have.
func sealAt(key []byte, generation uint32, purpose, boundary, tenant, kind, id string, pt []byte) ([]byte, error) {
	code, _ := envelope.Code(purpose)
	return envelope.Seal(key, code, generation, envelope.Address{Boundary: boundary, Tenant: tenant, Kind: kind, ID: id}, pt)
}

// grantProto is a grant for the holder, valid from `issued` for `life`.
func grantProto(holder string, tenants []string, issued time.Time, life time.Duration) *typev2alpha1.Grant {
	return &typev2alpha1.Grant{
		Boundary: testBoundary, Tenants: tenants, Holder: holder, KeyOps: []string{"seal", "open"},
		IssuedAt: timestamppb.New(issued), ExpiresAt: timestamppb.New(issued.Add(life)),
		DecisionId: "0192f4a0-0000-7000-8000-" + randHex(6), Action: "token.issue",
	}
}

func fmtAny(v any) string { return fmt.Sprint(v) }
