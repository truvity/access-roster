//go:build sluis_test

package upstreamd_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"os"
	"path/filepath"
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

// fakeStore serves Get of the Boundary and the Upstream items, as store@ serves the config kinds.
type fakeStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	items map[string]proto.Message // "<segment>/<id>"
}

func (f *fakeStore) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	a := req.Msg.GetAddress()
	m, ok := f.items[a.GetKind()+"/"+a.GetId()]
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

// fakeTransport records what the emitter hands over.
type fakeTransport struct {
	transportv2alpha1connect.UnimplementedTransportServiceHandler
	mu   sync.Mutex
	msgs []*transportv2alpha1.AuditMessage
}

func (f *fakeTransport) Emit(_ context.Context, req *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	secrets   string // the credential directory
	svc       *upstreamd.Service
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
	}
	storeSock := filepath.Join(dir, "store.sock")
	path, h := storev2alpha1connect.NewStoreServiceHandler(&fakeStore{items: items})
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

	secrets := filepath.Join(dir, "cred")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if !o.noSecret && o.upstream != nil {
		secret := o.secret
		if secret == "" {
			secret = "test-client-secret-value"
		}
		if err := os.WriteFile(filepath.Join(secrets, "upstream."+o.upstream.GetName()+".client-secret"), []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := upstreamd.New(upstreamd.Options{
		Boundary: testBoundary, Config: cfg, Secrets: upstreamd.CredentialDir(secrets), Audit: em, Now: o.now,
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
		transport: tr, key: key, secrets: secrets, svc: svc,
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
