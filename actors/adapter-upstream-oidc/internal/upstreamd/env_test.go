//go:build sluis_test

package upstreamd_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/truvity/sluis/v2/actors/adapter-upstream-oidc/internal/upstreamd"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1/integrationv2alpha1connect"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/version"
)

const testBoundary = "dev"

// shortDir is a short temporary directory: a Unix socket path holds about 108 bytes.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "u")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serve serves a handler on a socket as the registry actor `callee`, for the caller `who`, and stops it with the test.
// The test process has one uid; the resolver names it `who` for the server, so the call-graph check sees that caller.
func serve(t *testing.T, socket, callee, who string, allow func(rpc.Peer, string) bool, h rpc.Handler) {
	t.Helper()
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	resolve := func(uid uint32) (string, uint32, bool) { return who, 0, uid == self }
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: callee, Socket: socket, Allow: allow}, resolve)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, cfg, h) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %s did not appear", socket)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func anyone(rpc.Peer, string) bool { return true }

// fakeStore serves Get of the Boundary, the Upstream items and their UpstreamSecret, as store@ serves the config kinds
// and the secret kinds. It counts the gets of each segment.
type fakeStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	mu    sync.Mutex
	items map[string]proto.Message // "<segment>/<id>"
	gets  map[string]int
	fails map[string]error // a segment whose gets fail with the error
}

func (f *fakeStore) failOn(segment string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails == nil {
		f.fails = map[string]error{}
	}
	f.fails[segment] = err
}

func (f *fakeStore) set(k string, m proto.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m == nil {
		delete(f.items, k)
		return
	}
	f.items[k] = m
}

func (f *fakeStore) count(segment string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets[segment]
}

func (f *fakeStore) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	a := req.Msg.GetAddress()
	f.mu.Lock()
	if f.gets == nil {
		f.gets = map[string]int{}
	}
	f.gets[a.GetKind()]++
	m, ok := f.items[a.GetKind()+"/"+a.GetId()]
	fail := f.fails[a.GetKind()]
	f.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	if !ok {
		return nil, refusal.New(connect.CodeNotFound, "absent", "address")
	}
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&storev2alpha1.GetResponse{Item: &storev2alpha1.Item{
		Address: &typev2alpha1.Address{Kind: a.GetKind(), Id: a.GetId()}, Version: 1, Value: b,
	}}), nil
}

// List answers the items of one segment, in one page.
func (f *fakeStore) List(_ context.Context, req *connect.Request[storev2alpha1.ListRequest]) (*connect.Response[storev2alpha1.ListResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.items {
		if seg, _, _ := strings.Cut(k, "/"); seg == req.Msg.GetKind() {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := &storev2alpha1.ListResponse{}
	for _, k := range keys {
		b, err := proto.Marshal(f.items[k])
		if err != nil {
			return nil, err
		}
		_, id, _ := strings.Cut(k, "/")
		out.Items = append(out.Items, &storev2alpha1.Item{Address: &typev2alpha1.Address{Kind: req.Msg.GetKind(), Id: id}, Version: 1, Value: b})
	}
	return connect.NewResponse(out), nil
}

// fakeTransport records what the emitter hands over.
type fakeTransport struct {
	transportv2alpha1connect.UnimplementedTransportServiceHandler
	mu   sync.Mutex
	msgs []*transportv2alpha1.AuditMessage
	fail bool // Emit answers unavailable, as a full spool does
}

func (f *fakeTransport) Emit(_ context.Context, req *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("spool full"))
	}
	f.msgs = append(f.msgs, req.Msg.GetMessage())
	return connect.NewResponse(&transportv2alpha1.EmitResponse{}), nil
}

func (f *fakeTransport) records() []*transportv2alpha1.AuditMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*transportv2alpha1.AuditMessage(nil), f.msgs...)
}

// fakeKey answers Mac with an HMAC-SHA384 under a fixed test key, and keeps the requests.
type fakeKey struct {
	keyv2alpha1connect.UnimplementedKeyServiceHandler
	mu   sync.Mutex
	macs []*keyv2alpha1.MacRequest
}

func (f *fakeKey) Mac(_ context.Context, req *connect.Request[keyv2alpha1.MacRequest]) (*connect.Response[keyv2alpha1.MacResponse], error) {
	f.mu.Lock()
	f.macs = append(f.macs, req.Msg)
	f.mu.Unlock()
	h := hmac.New(sha512.New384, []byte("test pseudonym key"))
	h.Write(req.Msg.GetInput())
	return connect.NewResponse(&keyv2alpha1.MacResponse{Mac: h.Sum(nil)}), nil
}

func (f *fakeKey) requests() []*keyv2alpha1.MacRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*keyv2alpha1.MacRequest(nil), f.macs...)
}

// env is the adapter, served on a Unix socket, with its dependencies as Connect services on sockets of their own.
type env struct {
	client    integrationv2alpha1connect.UpstreamServiceClient
	transport *fakeTransport
	key       *fakeKey
	store     *fakeStore
	svc       *upstreamd.Service
	audit     *audit.Emitter
}

// envOptions describe the configuration of an env.
type envOptions struct {
	environment string // Boundary.environment
	upstream    *configv2alpha1.Upstream
	caller      string // the registry name the adapter sees as its caller; default "session"
	noSecret    bool
	secret      string
	now         func() time.Time
}

func newEnv(t *testing.T, o envOptions) *env {
	t.Helper()
	dir := shortDir(t)
	if o.caller == "" {
		o.caller = "session"
	}
	items := map[string]proto.Message{
		"boundary/default": &configv2alpha1.Boundary{Name: testBoundary, Environment: o.environment, DefaultTenant: "acme"},
	}
	if o.upstream != nil {
		items["upstream/"+o.upstream.GetName()] = o.upstream
		// The client secret is the UpstreamSecret store@ serves from the secret source, ending with the newline a tool
		// writes.
		if !o.noSecret {
			secret := o.secret
			if secret == "" {
				secret = "test-client-secret-value"
			}
			items["upstream-secret/"+o.upstream.GetName()] = &configv2alpha1.UpstreamSecret{Upstream: o.upstream.GetName(), Secret: []byte(secret + "\n")}
		}
	}
	fs := &fakeStore{items: items}
	storeSock := filepath.Join(dir, "store.sock")
	path, h := storev2alpha1connect.NewStoreServiceHandler(fs)
	serve(t, storeSock, "store", "adapter-upstream-oidc", anyone, rpc.Handler{Path: path, H: h})

	tr, key := &fakeTransport{}, &fakeKey{}
	trSock, keySock := filepath.Join(dir, "emit.sock"), filepath.Join(dir, "key.sock")
	path, h = transportv2alpha1connect.NewTransportServiceHandler(tr)
	serve(t, trSock, "transport", "adapter-upstream-oidc", anyone, rpc.Handler{Path: path, H: h})
	path, h = keyv2alpha1connect.NewKeyServiceHandler(key)
	serve(t, keySock, "key", "adapter-upstream-oidc", anyone, rpc.Handler{Path: path, H: h})

	dial := func(sock string) (connect.HTTPClient, string) { return rpc.Dial(sock) }
	sh, surl := dial(storeSock)
	cfg, err := upstreamd.NewConfig(storev2alpha1connect.NewStoreServiceClient(sh, surl, rpc.ClientOptions()...))
	if err != nil {
		t.Fatal(err)
	}
	th, turl := dial(trSock)
	kh, kurl := dial(keySock)
	em, err := audit.New(audit.Config{
		Actor: upstreamd.Actor, Boundary: testBoundary, Release: version.Version,
		Transport: transportv2alpha1connect.NewTransportServiceClient(th, turl, rpc.ClientOptions()...),
		Keys:      keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...),
	})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := upstreamd.New(upstreamd.Options{
		Boundary: testBoundary, Config: cfg, Audit: em, Now: o.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The adapter's own socket: the call-graph check of the kit is the one the product uses, and the caller is `session`.
	sock := filepath.Join(dir, "adapter.sock")
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	scfg := rpc.WithNameResolver(svc.ServerConfig(sock), func(uid uint32) (string, uint32, bool) { return o.caller, 0, uid == self })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, scfg, svc.Handler(scfg)) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the adapter's socket did not appear")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ah, aurl := rpc.Dial(sock)
	return &env{
		client:    integrationv2alpha1connect.NewUpstreamServiceClient(ah, aurl, rpc.ClientOptions()...),
		transport: tr, key: key, store: fs, svc: svc, audit: em,
	}
}

func (e *env) begin(ctx context.Context, r *integrationv2alpha1.BeginRequest) (*integrationv2alpha1.BeginResponse, error) {
	res, err := e.client.Begin(ctx, connect.NewRequest(r))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func (e *env) complete(ctx context.Context, r *integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
	res, err := e.client.Complete(ctx, connect.NewRequest(r))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetAssertion(), nil
}

// refused checks that err is a refusal with the reason, the Connect code of that reason, and the field path.
func refused(t *testing.T, err error, reason string, code connect.Code, path string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error; want %s at %q", reason, path)
	}
	got, _ := refusal.Reason(err)
	p, _ := refusal.FieldPath(err)
	if got != reason || connect.CodeOf(err) != code || p != path {
		t.Fatalf("got %v reason=%q path=%q; want %s %v at %q", connect.CodeOf(err), got, p, reason, code, path)
	}
}

// refusalPath returns the field path of a refusal.
func refusalPath(err error) (string, bool) { return refusal.FieldPath(err) }
