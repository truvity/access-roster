//go:build sluis_test

package writerd

// The fakes below stand in for the services the writer calls: store@, key@, policy, the blob driver and the audit
// transport. They are test code only. Each is served over a Unix socket by the kit, so the writer reaches them with
// the Connect clients it uses in production; none is reached by a function call.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	blobv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/blob/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/blob/v2alpha1/blobv2alpha1connect"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// startServer serves one generated handler on cfg.Socket until the test ends.
func startServer(t *testing.T, cfg rpc.ServerConfig, path string, h http.Handler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, cfg, rpc.Handler{Path: path, H: h}) }()
	wait(t, "the socket of "+cfg.Actor, func() bool {
		if _, err := os.Stat(cfg.Socket); err == nil {
			return true
		}
		select {
		case err := <-done:
			t.Fatalf("serve %s: %v", cfg.Actor, err)
		default:
		}
		return false
	})
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve %s: %v", cfg.Actor, err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("%s did not stop", cfg.Actor)
		}
	})
}

// events is an ordered log of what the fakes saw, shared by all of them.
type events struct {
	mu sync.Mutex
	l  []string
}

func (e *events) add(format string, a ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.l = append(e.l, fmt.Sprintf(format, a...))
}

func (e *events) all() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.l)
}

// index returns the position of the first event with the prefix at or after from, or -1.
func (e *events) index(prefix string, from int) int {
	for i, s := range e.all() {
		if i >= from && strings.HasPrefix(s, prefix) {
			return i
		}
	}
	return -1
}

// ---- store@

type fakeStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	mu    sync.Mutex
	items map[string]proto.Message // by kind segment
}

func (f *fakeStore) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := req.Msg.GetAddress()
	m, ok := f.items[a.GetKind()]
	if !ok || a.GetId() != "default" || a.GetTenant() != "" {
		return nil, refusal.New(connect.CodeNotFound, "absent", "")
	}
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&storev2alpha1.GetResponse{Item: &storev2alpha1.Item{Address: a, Version: 1, Value: b}}), nil
}

// ---- policy

type fakePolicy struct {
	policyv2alpha1connect.UnimplementedPolicyServiceHandler
	ev *events
	mu sync.Mutex
	// mode: "" allows; "deny" denies; "fail" answers unavailable.
	mode string
	reqs []*policyv2alpha1.DecideRequest
}

func (f *fakePolicy) Decide(_ context.Context, req *connect.Request[policyv2alpha1.DecideRequest]) (*connect.Response[policyv2alpha1.DecideResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req.Msg)
	f.ev.add("policy.decide:%s", req.Msg.GetTenant())
	switch f.mode {
	case "fail":
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	case "deny":
		return connect.NewResponse(&policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY}), nil
	}
	return connect.NewResponse(&policyv2alpha1.DecideResponse{
		Decision: policyv2alpha1.Decision_ALLOW, SealedGrant: []byte("grant:" + req.Msg.GetTenant()), DecisionId: "d",
	}), nil
}

func (f *fakePolicy) requests() []*policyv2alpha1.DecideRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

// ---- key@

// fakeKey seals with AES-256-GCM bound to the address, as key@ does, and signs with a P-384 key made for the test.
// It accepts a Seal only with the grant "grant:<tenant>", which the fake policy gives.
type fakeKey struct {
	keyv2alpha1connect.UnimplementedKeyServiceHandler
	ev   *events
	priv *ecdsa.PrivateKey
	aead cipher.AEAD
	mu   sync.Mutex
	// failSign, when set, is returned by Sign.
	failSign error
	seals    int
}

func newFakeKey(t *testing.T, ev *events) *fakeKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKey{ev: ev, priv: priv, aead: aead}
}

func aad(tenant, kind, id string) []byte { return []byte(tenant + "|" + kind + "|" + id) }

func (f *fakeKey) PublicKey(_ context.Context, req *connect.Request[keyv2alpha1.PublicKeyRequest]) (*connect.Response[keyv2alpha1.PublicKeyResponse], error) {
	if req.Msg.GetPurpose() != "audit-log" {
		return nil, refusal.New(connect.CodeInvalidArgument, "purpose", "purpose")
	}
	spki, err := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&keyv2alpha1.PublicKeyResponse{SpkiDer: spki, KeyId: "k", Algorithm: "ES384"}), nil
}

func (f *fakeKey) Sign(_ context.Context, req *connect.Request[keyv2alpha1.SignRequest]) (*connect.Response[keyv2alpha1.SignResponse], error) {
	m := req.Msg
	if m.GetPurpose() != "audit-log" || m.GetAlgorithm() != "ES384" {
		return nil, refusal.New(connect.CodeInvalidArgument, "purpose", "purpose")
	}
	if f.failSign != nil {
		return nil, f.failSign
	}
	// key@ signs only a checkpoint body (actors/key/internal/content).
	if _, err := parseCheckpoint(string(m.GetContent())); err != nil {
		return nil, refusal.New(connect.CodeInvalidArgument, "content", "content")
	}
	d := sha512.Sum384(m.GetContent())
	der, err := ecdsa.SignASN1(rand.Reader, f.priv, d[:])
	if err != nil {
		return nil, err
	}
	f.ev.add("key.sign")
	return connect.NewResponse(&keyv2alpha1.SignResponse{SignatureDer: der, KeyId: "k"}), nil
}

func (f *fakeKey) Seal(_ context.Context, req *connect.Request[keyv2alpha1.SealRequest]) (*connect.Response[keyv2alpha1.SealResponse], error) {
	m := req.Msg
	a := m.GetAddress()
	if m.GetPurpose() != "evidence" || a.GetTenant() == "" {
		return nil, refusal.New(connect.CodeInvalidArgument, "purpose", "purpose")
	}
	if string(m.GetGrant()) != "grant:"+a.GetTenant() {
		return nil, refusal.New(connect.CodePermissionDenied, "grant", "grant")
	}
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.seals++
	f.mu.Unlock()
	return connect.NewResponse(&keyv2alpha1.SealResponse{
		Envelope: f.aead.Seal(nonce, nonce, m.GetPlaintext(), aad(a.GetTenant(), a.GetKind(), a.GetId())),
	}), nil
}

// open opens an envelope for the address, as the reader will.
func (f *fakeKey) open(env []byte, tenant, kind, id string) ([]byte, error) {
	n := f.aead.NonceSize()
	if len(env) < n {
		return nil, errors.New("short")
	}
	return f.aead.Open(nil, env[:n], env[n:], aad(tenant, kind, id))
}

func (f *fakeKey) sealCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seals
}

// verifier is the verifier key text an auditor would be given.
func (f *fakeKey) verifier(t *testing.T, origin string) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := newLogKey(origin, spki)
	if err != nil {
		t.Fatal(err)
	}
	return k.verifierKey()
}

// ---- the blob

// fakeBlob keeps the objects as files below root, in the layout of the fs driver, so that `sluis audit verify`
// reads them. It follows the port: create-if-absent through link, a conditional put only on the two pointers, and
// the entity tag the SHA-384 of the content.
type fakeBlob struct {
	blobv2alpha1connect.UnimplementedBlobServiceHandler
	ev   *events
	root string
	mu   sync.Mutex
	// before, when set, is called with the operation and the path before it is done; an error is the answer.
	before func(op, path string) error
}

func (f *fakeBlob) path(p string) (string, error) {
	parts := strings.Split(p, "/")
	for _, s := range parts {
		if s == "" || strings.HasPrefix(s, ".") {
			return "", refusal.New(connect.CodeInvalidArgument, "path", "path")
		}
	}
	return filepath.Join(append([]string{f.root}, parts...)...), nil
}

func etagOf(b []byte) string {
	d := sha512.Sum384(b)
	return hex.EncodeToString(d[:])
}

func (f *fakeBlob) hook(op, p string) error {
	if f.before != nil {
		return f.before(op, p)
	}
	return nil
}

func (f *fakeBlob) link(p string, data []byte) error {
	full, err := f.path(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), full); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return refusal.New(connect.CodeAlreadyExists, "taken", "path")
		}
		return err
	}
	return nil
}

func (f *fakeBlob) Create(_ context.Context, req *connect.Request[blobv2alpha1.CreateRequest]) (*connect.Response[blobv2alpha1.CreateResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.hook("create", req.Msg.GetPath()); err != nil {
		return nil, err
	}
	if err := f.link(req.Msg.GetPath(), req.Msg.GetData()); err != nil {
		return nil, err
	}
	f.ev.add("blob.create:%s", req.Msg.GetPath())
	return connect.NewResponse(&blobv2alpha1.CreateResponse{Etag: etagOf(req.Msg.GetData())}), nil
}

func (f *fakeBlob) Put(_ context.Context, req *connect.Request[blobv2alpha1.PutRequest]) (*connect.Response[blobv2alpha1.PutResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := req.Msg
	if err := f.hook("put", m.GetPath()); err != nil {
		return nil, err
	}
	name := m.GetPath()[strings.LastIndex(m.GetPath(), "/")+1:]
	if name != "checkpoint" && name != "writer-state" {
		return nil, refusal.New(connect.CodePermissionDenied, "rule", "path")
	}
	full, err := f.path(m.GetPath())
	if err != nil {
		return nil, err
	}
	if m.GetIfMatch() == "" {
		if err := f.link(m.GetPath(), m.GetData()); err != nil {
			if connect.CodeOf(err) == connect.CodeAlreadyExists {
				return nil, refusal.New(connect.CodeAborted, "version", "if_match")
			}
			return nil, err
		}
	} else {
		have, err := os.ReadFile(full) //nolint:gosec // a test path under a temporary directory
		if err != nil || etagOf(have) != m.GetIfMatch() {
			return nil, refusal.New(connect.CodeAborted, "version", "if_match")
		}
		tmp := full + ".new"
		if err := os.WriteFile(tmp, m.GetData(), 0o640); err != nil { //nolint:gosec // a test file
			return nil, err
		}
		if err := os.Rename(tmp, full); err != nil {
			return nil, err
		}
	}
	f.ev.add("blob.put:%s", m.GetPath())
	return connect.NewResponse(&blobv2alpha1.PutResponse{Etag: etagOf(m.GetData())}), nil
}

func (f *fakeBlob) Get(_ context.Context, req *connect.Request[blobv2alpha1.BlobGetRequest]) (*connect.Response[blobv2alpha1.BlobGetResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	full, err := f.path(req.Msg.GetPath())
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(full) //nolint:gosec // a test path under a temporary directory
	if err != nil {
		return nil, refusal.New(connect.CodeNotFound, "absent", "path")
	}
	return connect.NewResponse(&blobv2alpha1.BlobGetResponse{Data: b, Etag: etagOf(b)}), nil
}

func (f *fakeBlob) List(_ context.Context, req *connect.Request[blobv2alpha1.BlobListRequest]) (*connect.Response[blobv2alpha1.BlobListResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	_ = filepath.WalkDir(f.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") || strings.HasSuffix(d.Name(), ".new") {
			return nil
		}
		rel, _ := filepath.Rel(f.root, p)
		if rel = filepath.ToSlash(rel); strings.HasPrefix(rel, req.Msg.GetPrefix()) {
			out = append(out, rel)
		}
		return nil
	})
	slices.Sort(out)
	return connect.NewResponse(&blobv2alpha1.BlobListResponse{Paths: out}), nil
}

// ---- the transport

// fakeTransport is a spool: Emit appends a message, Receive streams the unacknowledged ones in order and, as the
// spool does, starts again from the oldest unacknowledged message on each new stream; one consumer at a time.
type fakeTransport struct {
	transportv2alpha1connect.UnimplementedTransportServiceHandler
	ev      *events
	emitter string
	mu      sync.Mutex
	next    uint64
	pending []*transportv2alpha1.Delivery
	acked   []uint64
	wake    chan struct{}
	busy    bool
	streams int
}

func newFakeTransport(ev *events, emitter string) *fakeTransport {
	return &fakeTransport{ev: ev, emitter: emitter, wake: make(chan struct{}, 1), next: 1}
}

func (f *fakeTransport) push(m *transportv2alpha1.AuditMessage) {
	f.mu.Lock()
	f.pending = append(f.pending, &transportv2alpha1.Delivery{DeliveryId: f.next, Emitter: f.emitter, Message: m})
	f.next++
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fakeTransport) Emit(_ context.Context, req *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	f.push(req.Msg.GetMessage())
	return connect.NewResponse(&transportv2alpha1.EmitResponse{}), nil
}

func (f *fakeTransport) Receive(ctx context.Context, _ *connect.Request[transportv2alpha1.ReceiveRequest], st *connect.ServerStream[transportv2alpha1.ReceiveResponse]) error {
	f.mu.Lock()
	if f.busy {
		f.mu.Unlock()
		return refusal.New(connect.CodeAlreadyExists, "taken", "")
	}
	f.busy = true
	f.streams++
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.busy = false; f.mu.Unlock() }()
	var sent uint64
	for {
		f.mu.Lock()
		var out []*transportv2alpha1.Delivery
		for _, d := range f.pending {
			if d.GetDeliveryId() > sent {
				out = append(out, d)
			}
		}
		f.mu.Unlock()
		if len(out) > 0 {
			sent = out[len(out)-1].GetDeliveryId()
			if err := st.Send(&transportv2alpha1.ReceiveResponse{Deliveries: out}); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-f.wake:
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (f *fakeTransport) Ack(_ context.Context, req *connect.Request[transportv2alpha1.AckRequest]) (*connect.Response[transportv2alpha1.AckResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ev.add("transport.ack:%d", len(req.Msg.GetDeliveryIds()))
	for _, id := range req.Msg.GetDeliveryIds() {
		f.pending = slices.DeleteFunc(f.pending, func(d *transportv2alpha1.Delivery) bool { return d.GetDeliveryId() == id })
		f.acked = append(f.acked, id)
	}
	return connect.NewResponse(&transportv2alpha1.AckResponse{}), nil
}

func (f *fakeTransport) ackedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.acked)
}

func (f *fakeTransport) pendingCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending)
}

// ---- the environment

const (
	testBoundary = "dev"
	testOrigin   = "sluis.local.test/dev/sluis/audit/main"
	testTenant   = "acme"
	testDefault  = "operator"
)

// env is one installation of fakes.
type env struct {
	t     *testing.T
	ev    *events
	store *fakeStore
	pol   *fakePolicy
	key   *fakeKey
	blob  *fakeBlob
	tr    *fakeTransport
	root  string // the blob's root directory
	cfg   Config
}

func asSelf() rpc.NameResolver {
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	return func(uid uint32) (string, uint32, bool) { return "writer", 0, uid == self }
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "w")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ev := &events{}
	dir := shortDir(t)
	e := &env{t: t, ev: ev, root: filepath.Join(dir, "blob")}
	if err := os.MkdirAll(e.root, 0o750); err != nil {
		t.Fatal(err)
	}
	e.store = &fakeStore{items: map[string]proto.Message{
		"audit-log": &configv2alpha1.AuditLog{Project: "sluis", LockMode: "none", Logs: []*configv2alpha1.LogDecl{
			{Kind: "audit", Id: "main", Origin: testOrigin},
			{Kind: "usage", Id: "main", Origin: "sluis.local.test/dev/sluis/usage/main"},
		}},
		"audit-catalogue": &configv2alpha1.AuditCatalogue{Release: "0.0.0", Actions: []string{"key.sign", "store.start"}},
		"boundary":        &configv2alpha1.Boundary{Name: testBoundary, DefaultTenant: testDefault},
	}}
	e.pol = &fakePolicy{ev: ev}
	e.key = newFakeKey(t, ev)
	e.blob = &fakeBlob{ev: ev, root: e.root}
	e.tr = newFakeTransport(ev, "key@"+testBoundary)

	sp := func(name string) string { return filepath.Join(dir, name+".sock") }
	serveOn := func(name string, path string, h http.Handler) {
		cfg := rpc.WithNameResolver(rpc.ServerConfig{
			Actor: name, Boundary: testBoundary, Socket: sp(name),
			Allow: func(rpc.Peer, string) bool { return true },
		}, asSelf())
		startServer(t, cfg, path, h)
	}
	p, h := storev2alpha1connect.NewStoreServiceHandler(e.store)
	serveOn("store", p, h)
	p, h = keyv2alpha1connect.NewKeyServiceHandler(e.key)
	serveOn("key", p, h)
	p, h = policyv2alpha1connect.NewPolicyServiceHandler(e.pol)
	serveOn("policy", p, h)
	p, h = blobv2alpha1connect.NewBlobServiceHandler(e.blob)
	serveOn("blob", p, h)
	p, h = transportv2alpha1connect.NewTransportServiceHandler(e.tr)
	serveOn("transport", p, h)

	e.cfg = Config{
		Boundary: testBoundary, Instance: "node-1",
		StoreSocket: sp("store"), KeySocket: sp("key"), PolicySocket: sp("policy"),
		BlobSocket: sp("blob"), TransportSocket: sp("transport"),
		BatchMax: 256, BatchWindow: 100 * time.Millisecond,
		Clock: func() clockObservation { return clockObservation{Observed: true, Synced: true, OffsetMicros: 12} },
	}
	return e
}

// writer builds a writer on the environment; cfg may be adjusted by the caller first.
func (e *env) writer() *Server {
	e.t.Helper()
	s, err := New(e.cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

// running is a writer that Run is serving.
type running struct {
	s        *Server
	cancel   context.CancelFunc
	finished chan struct{} // closed when Run has returned
	err      error         // what Run returned; valid after finished is closed
}

// start runs a writer until the test ends or stop is called.
func (e *env) start() *running {
	e.t.Helper()
	s := e.writer()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{s: s, cancel: cancel, finished: make(chan struct{})}
	go func() {
		r.err = s.Run(ctx)
		close(r.finished)
	}()
	e.t.Cleanup(func() { _ = r.stop(e.t) })
	return r
}

// stop ends the writer and returns what Run returned.
func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	return r.result(t)
}

// result waits for Run to return, and returns its error.
func (r *running) result(t *testing.T) error {
	t.Helper()
	select {
	case <-r.finished:
		return r.err
	case <-time.After(10 * time.Second):
		t.Error("the writer did not stop")
		return errors.New("timeout")
	}
}

// wait polls until cond holds or the time runs out.
func wait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// logDir is the directory of the audit log in the blob, which `sluis audit verify` takes.
func (e *env) logDir() string { return filepath.Join(e.root, "audit", "main") }

func (e *env) verifier() string { return e.key.verifier(e.t, testOrigin) }

// dummyTransport is the Transport the emitter library requires; Record, which the tests use, never calls it.
type dummyTransport struct {
	transportv2alpha1connect.TransportServiceClient
}
