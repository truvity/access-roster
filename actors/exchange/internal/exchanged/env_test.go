//go:build sluis_test

package exchanged_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/truvity/sluis/v2/actors/exchange/internal/exchanged"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	exchangev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1/exchangev2alpha1connect"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/version"
)

const (
	testBoundary = "dev"
	testIssuer   = "https://sluis.dev.local.test"
	testTenant   = "acme"
	testKID      = "test-key-1"
)

// t0 is the clock of every test: 2026-11-04T12:00:00Z.
var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// shortDir is a short temporary directory: a Unix socket path holds about 108 bytes.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serve serves a handler on a socket as the registry actor `callee`, for the caller `who`, and stops it with the test.
// The test process has one uid; the resolver names it `who` for the server, so the call-graph check sees that caller.
func serve(t *testing.T, socket string, who string, cfg rpc.ServerConfig, h rpc.Handler) {
	t.Helper()
	serveWith(t, socket, who, cfg, func(rpc.ServerConfig) rpc.Handler { return h })
}

// serveWith is serve for a handler that is built from the server's configuration, as the product's is: the interceptor
// of the handler and the server must see the same resolver.
func serveWith(t *testing.T, socket string, who string, cfg rpc.ServerConfig, handler func(rpc.ServerConfig) rpc.Handler) {
	t.Helper()
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	cfg.Socket = socket
	cfg = rpc.WithNameResolver(cfg, func(uid uint32) (string, uint32, bool) { return who, 0, uid == self })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, cfg, handler(cfg)) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); ; {
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

func fakeCfg(actor string) rpc.ServerConfig { return rpc.ServerConfig{Actor: actor, Allow: anyone} }

// ---- store@ ----------------------------------------------------------------------------------------------------

// fakeStore keeps the items of the kinds exchange reads and writes. A write is recorded with its TTL.
type fakeStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	mu     sync.Mutex
	items  map[string]*storev2alpha1.Item // "<kind>/<tenant>/<id>"
	ttls   map[string]time.Duration
	writes int
	fail   bool // Get and Write answer unavailable
}

func addr(a *typev2alpha1.Address) string { return a.GetKind() + "/" + a.GetTenant() + "/" + a.GetId() }

func (f *fakeStore) put(kind, id string, m proto.Message) {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	a := &typev2alpha1.Address{Kind: kind, Id: id}
	f.items[addr(a)] = &storev2alpha1.Item{Address: a, Version: 1, Value: b}
}

func (f *fakeStore) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	it, ok := f.items[addr(req.Msg.GetAddress())]
	if !ok {
		return nil, refusal.New(connect.CodeNotFound, "absent", "address")
	}
	return connect.NewResponse(&storev2alpha1.GetResponse{Item: it}), nil
}

func (f *fakeStore) Write(_ context.Context, req *connect.Request[storev2alpha1.WriteRequest]) (*connect.Response[storev2alpha1.WriteResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	var out []*storev2alpha1.Item
	for _, op := range req.Msg.GetOperations() {
		k := addr(op.GetAddress())
		old, exists := f.items[k]
		if op.GetVerb() == storev2alpha1.Verb_CREATE && exists {
			return nil, refusal.New(connect.CodeAlreadyExists, "exists", "address")
		}
		v := uint64(1)
		if exists {
			v = old.GetVersion() + 1
		}
		it := &storev2alpha1.Item{Address: op.GetAddress(), Version: v, Value: op.GetValue()}
		f.items[k] = it
		f.ttls[k] = op.GetTtl().AsDuration()
		f.writes++
		out = append(out, it)
	}
	return connect.NewResponse(&storev2alpha1.WriteResponse{Items: out}), nil
}

// ttl is the TTL of the last write of an item.
func (f *fakeStore) ttl(kind, id string) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.ttls[kind+"//"+id]
	return d, ok
}

// has says whether an item exists.
func (f *fakeStore) has(kind, id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.items[kind+"//"+id]
	return ok
}

// ---- the audit transport and key@ ---------------------------------------------------------------------------------

type fakeTransport struct {
	transportv2alpha1connect.UnimplementedTransportServiceHandler
	mu   sync.Mutex
	msgs []*transportv2alpha1.AuditMessage
	fail bool
}

func (f *fakeTransport) Emit(_ context.Context, req *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, refusal.New(connect.CodeUnavailable, "spool", "")
	}
	f.msgs = append(f.msgs, req.Msg.GetMessage())
	return connect.NewResponse(&transportv2alpha1.EmitResponse{}), nil
}

// records decodes what the emitter handed over.
func (f *fakeTransport) records(t *testing.T) []map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, m := range f.msgs {
		var r map[string]any
		if err := json.Unmarshal(m.GetRecord(), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// fakeKey answers Mac with an HMAC-SHA384 under a key per purpose and tenant, with the label bound in as key@ does, and
// keeps the requests.
type fakeKey struct {
	keyv2alpha1connect.UnimplementedKeyServiceHandler
	mu   sync.Mutex
	macs []*keyv2alpha1.MacRequest
	fail bool
}

func macOf(purpose, tenant, label string, input []byte) []byte {
	h := hmac.New(sha512.New384, []byte("test key "+purpose+" "+tenant))
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(label)))) //nolint:gosec // G115: a label of these tests is a few bytes
	h.Write([]byte(label))
	h.Write(input)
	return h.Sum(nil)
}

func (f *fakeKey) Mac(_ context.Context, req *connect.Request[keyv2alpha1.MacRequest]) (*connect.Response[keyv2alpha1.MacResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail && req.Msg.GetPurpose() == "pairwise" {
		return nil, refusal.New(connect.CodeUnavailable, "wrap", "")
	}
	f.macs = append(f.macs, proto.Clone(req.Msg).(*keyv2alpha1.MacRequest))
	m := req.Msg
	return connect.NewResponse(&keyv2alpha1.MacResponse{Mac: macOf(m.GetPurpose(), m.GetTenant(), m.GetLabel(), m.GetInput())}), nil
}

func (f *fakeKey) pairwise() []*keyv2alpha1.MacRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*keyv2alpha1.MacRequest
	for _, m := range f.macs {
		if m.GetPurpose() == "pairwise" {
			out = append(out, m)
		}
	}
	return out
}

// ---- policy and signer -------------------------------------------------------------------------------------------

type fakePolicy struct {
	policyv2alpha1connect.UnimplementedPolicyServiceHandler
	mu     sync.Mutex
	reqs   []*policyv2alpha1.DecideRequest
	decide func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error)
}

func (f *fakePolicy) Decide(_ context.Context, req *connect.Request[policyv2alpha1.DecideRequest]) (*connect.Response[policyv2alpha1.DecideResponse], error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, proto.Clone(req.Msg).(*policyv2alpha1.DecideRequest))
	f.mu.Unlock()
	res, err := f.decide(req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (f *fakePolicy) requests() []*policyv2alpha1.DecideRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*policyv2alpha1.DecideRequest(nil), f.reqs...)
}

// allow is the answer of a policy that allows and holds these grant names.
func allow(names ...string) func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
	return func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return &policyv2alpha1.DecideResponse{
			Decision: policyv2alpha1.Decision_ALLOW, GrantNames: names, Digest: "digest-1", DecisionId: "0192a000-0000-7000-8000-000000000001",
			SealedGrant: []byte("sealed-grant"), Reasons: []*policyv2alpha1.Reason{{PolicyId: "token-requires"}},
		}, nil
	}
}

// fakeSigner signs with a real ES384 key, as signer does, and publishes the key set. A test mints the subject tokens
// that "this boundary issued" with the same key.
type fakeSigner struct {
	signerv2alpha1connect.UnimplementedSignerServiceHandler
	mu      sync.Mutex
	key     *ecdsa.PrivateKey
	signed  []*signerv2alpha1.SignTokenRequest
	keysets int
	fail    bool
}

func newSigner(t *testing.T) *fakeSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSigner{key: k}
}

func signJWS(t *testing.T, key *ecdsa.PrivateKey, alg jose.SignatureAlgorithm, kid, typ string, claims []byte) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: &jose.JSONWebKey{Key: key, KeyID: kid}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	c, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeSigner) SignToken(_ context.Context, req *connect.Request[signerv2alpha1.SignTokenRequest]) (*connect.Response[signerv2alpha1.SignTokenResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, refusal.New(connect.CodeUnavailable, "key", "")
	}
	f.signed = append(f.signed, proto.Clone(req.Msg).(*signerv2alpha1.SignTokenRequest))
	// The fake has no *testing.T of its own; signing cannot fail with a valid key.
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(req.Msg.GetTyp()))
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: &jose.JSONWebKey{Key: f.key, KeyID: testKID}}, opts)
	if err != nil {
		return nil, err
	}
	jws, err := s.Sign(req.Msg.GetClaimsJson())
	if err != nil {
		return nil, err
	}
	c, err := jws.CompactSerialize()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&signerv2alpha1.SignTokenResponse{Token: c, KeyId: testKID}), nil
}

func (f *fakeSigner) KeySet(context.Context, *connect.Request[signerv2alpha1.KeySetRequest]) (*connect.Response[signerv2alpha1.KeySetResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keysets++
	if f.fail {
		return nil, refusal.New(connect.CodeUnavailable, "key", "")
	}
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: testKID, Algorithm: "ES384", Use: "sig"}}})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&signerv2alpha1.KeySetResponse{JwksJson: b}), nil
}

func (f *fakeSigner) requests() []*signerv2alpha1.SignTokenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*signerv2alpha1.SignTokenRequest(nil), f.signed...)
}

// ---- the directory -------------------------------------------------------------------------------------------------

type fakeDirectory struct {
	mu     sync.Mutex
	person exchanged.Person
	err    error
	seen   []*exchanged.Subject
	tenant string
}

func (d *fakeDirectory) Person(_ context.Context, tenant string, s *exchanged.Subject) (exchanged.Person, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = append(d.seen, s)
	d.tenant = tenant
	return d.person, d.err
}

// ---- the env -------------------------------------------------------------------------------------------------------

// envOptions describe the configuration of an env.
type envOptions struct {
	caller      string // the registry name exchange sees as its caller; default "entry"
	environment string // Boundary.environment; default "development"
	trust       *configv2alpha1.ExchangeTrust
	lifetime    time.Duration // TokenLifetime.access_token; 0 declares none
	clientCap   time.Duration // ttl_cap of example-app
	requires    []string      // requires of example-app
	unbound     bool          // the directory is Unbound
}

// env is exchange, served on a Unix socket as entry calls it, with its dependencies as Connect services on sockets
// of their own.
type env struct {
	t         *testing.T
	client    exchangev2alpha1connect.ExchangeServiceClient
	store     *fakeStore
	transport *fakeTransport
	key       *fakeKey
	policy    *fakePolicy
	signer    *fakeSigner
	dir       *fakeDirectory
	svc       *exchanged.Service
	cfg       *exchanged.Config
	signerCl  signerv2alpha1connect.SignerServiceClient
}

var testPerson = exchanged.Person{ID: "p-7f3a", Accounts: []string{"workforce/u-1001"}, State: "live", Org: testTenant}

func newEnv(t *testing.T, o envOptions) *env {
	t.Helper()
	d := shortDir(t)
	if o.caller == "" {
		o.caller = "entry"
	}
	if o.environment == "" {
		o.environment = "development"
	}
	if o.requires == nil {
		o.requires = []string{"dev:example-app:user"}
	}
	st := &fakeStore{items: map[string]*storev2alpha1.Item{}, ttls: map[string]time.Duration{}}
	st.put("boundary", "default", &configv2alpha1.Boundary{Name: testBoundary, Environment: o.environment, Issuer: testIssuer, DefaultTenant: testTenant})
	st.put("installation-client", "sluis-cli", &configv2alpha1.InstallationClient{Id: "sluis-cli", Kind: "public"})
	app := &configv2alpha1.InstallationClient{Id: "example-app", Kind: "confidential", Requires: o.requires}
	if o.clientCap > 0 {
		app.TtlCap = durationpb.New(o.clientCap)
	}
	st.put("installation-client", "example-app", app)
	if o.lifetime > 0 {
		st.put("token-lifetime", "default", &configv2alpha1.TokenLifetime{AccessToken: durationpb.New(o.lifetime)})
	}
	if o.trust != nil {
		st.put("exchange-trust", "default", o.trust)
	}
	tr, key, pol, sg := &fakeTransport{}, &fakeKey{}, &fakePolicy{decide: allow("dev:example-app:user")}, newSigner(t)
	dir := &fakeDirectory{person: testPerson}

	sock := func(n string) string { return filepath.Join(d, n+".sock") }
	path, h := storev2alpha1connect.NewStoreServiceHandler(st)
	serve(t, sock("store"), "exchange", fakeCfg("store"), rpc.Handler{Path: path, H: h})
	path, h = transportv2alpha1connect.NewTransportServiceHandler(tr)
	serve(t, sock("emit"), "exchange", fakeCfg("transport"), rpc.Handler{Path: path, H: h})
	path, h = keyv2alpha1connect.NewKeyServiceHandler(key)
	serve(t, sock("key"), "exchange", fakeCfg("key"), rpc.Handler{Path: path, H: h})
	path, h = policyv2alpha1connect.NewPolicyServiceHandler(pol)
	serve(t, sock("policy"), "exchange", fakeCfg("policy"), rpc.Handler{Path: path, H: h})
	path, h = signerv2alpha1connect.NewSignerServiceHandler(sg)
	serve(t, sock("signer"), "exchange", fakeCfg("signer"), rpc.Handler{Path: path, H: h})

	sh, surl := rpc.Dial(sock("store"))
	cfg, err := exchanged.NewConfig(storev2alpha1connect.NewStoreServiceClient(sh, surl, rpc.ClientOptions()...))
	if err != nil {
		t.Fatal(err)
	}
	th, turl := rpc.Dial(sock("emit"))
	kh, kurl := rpc.Dial(sock("key"))
	keys := keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...)
	em, err := audit.New(audit.Config{
		Actor: exchanged.Actor, Boundary: testBoundary, Release: version.Version,
		Transport: transportv2alpha1connect.NewTransportServiceClient(th, turl, rpc.ClientOptions()...), Keys: keys,
		Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	ph, purl := rpc.Dial(sock("policy"))
	gh, gurl := rpc.Dial(sock("signer"))
	var directory exchanged.Directory = dir
	if o.unbound {
		directory = exchanged.Unbound{}
	}
	svc, err := exchanged.New(exchanged.Options{
		Boundary: testBoundary, Config: cfg, Directory: directory,
		Policy: policyv2alpha1connect.NewPolicyServiceClient(ph, purl, rpc.ClientOptions()...),
		Signer: signerv2alpha1connect.NewSignerServiceClient(gh, gurl, rpc.ClientOptions()...),
		Keys:   keys, Audit: em, Now: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	// exchange's own socket: the call-graph check of the kit is the one the product uses, and the caller is entry.
	serveWith(t, sock("exchange"), o.caller, svc.ServerConfig(""), svc.Handler)
	ah, aurl := rpc.Dial(sock("exchange"))
	return &env{
		t: t, client: exchangev2alpha1connect.NewExchangeServiceClient(ah, aurl, rpc.ClientOptions()...),
		store: st, transport: tr, key: key, policy: pol, signer: sg, dir: dir, svc: svc,
		cfg: cfg, signerCl: signerv2alpha1connect.NewSignerServiceClient(gh, gurl, rpc.ClientOptions()...),
	}
}

// mint signs a token of this boundary's issuer, as session would have.
func (e *env) mint(claims map[string]any) string {
	e.t.Helper()
	return mintWith(e.t, e.signer.key, "at+jwt", claims)
}

func mintWith(t *testing.T, key *ecdsa.PrivateKey, typ string, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signJWS(t, key, jose.ES384, testKID, typ, b)
}

// subjectClaims are the claims of an access token that session gave the CLI: the audience is the client it was
// issued to. A test overrides what it needs.
func subjectClaims(over map[string]any) map[string]any {
	m := map[string]any{
		"iss": testIssuer, "sub": "pairwise-of-the-sign-in", "aud": "sluis-cli", "client_id": "sluis-cli",
		"iat": t0.Add(-5 * time.Minute).Unix(), "exp": t0.Add(30 * time.Minute).Unix(), "jti": "j-subject",
		"auth_time": t0.Add(-10 * time.Minute).Unix(), "acr": "urn:example:acr:mfa", "amr": []string{"pwd", "mfa"}, "sid": "sid-1",
		"groups": []string{"dev:example-app:user"},
	}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

const (
	accessType = "urn:ietf:params:oauth:token-type:access_token"
	grantType  = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// request is a request the endpoint accepts for this subject token.
func request(subject string) *exchangev2alpha1.TokenExchangeRequest {
	return &exchangev2alpha1.TokenExchangeRequest{
		GrantType: grantType, SubjectToken: subject, SubjectTokenType: accessType, RequestedTokenType: accessType, Audience: "example-app",
	}
}

// reply is the HttpReply of a call that must not be an error.
func (e *env) exchange(r *exchangev2alpha1.TokenExchangeRequest) *typev2alpha1.HttpReply {
	e.t.Helper()
	res, err := e.client.Token(context.Background(), connect.NewRequest(r))
	if err != nil {
		e.t.Fatalf("Token: %v", err)
	}
	return res.Msg
}

// body decodes the JSON body of a reply.
func body(t *testing.T, r *typev2alpha1.HttpReply) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.GetBody(), &m); err != nil {
		t.Fatalf("body %q: %v", r.GetBody(), err)
	}
	return m
}

// failure checks that the reply is an OAuth error with this code.
func failure(t *testing.T, r *typev2alpha1.HttpReply, code string) {
	t.Helper()
	if r.GetStatus() != 400 {
		t.Fatalf("status = %d, want 400 (%s)", r.GetStatus(), r.GetBody())
	}
	if got := body(t, r)["error"]; got != code {
		t.Fatalf("error = %v, want %s", got, code)
	}
	if _, ok := body(t, r)["access_token"]; ok {
		t.Fatal("a refusal carries a token")
	}
}

// claimsOf reads the claims of a compact JWS without checking it, and its header typ.
func claimsOf(t *testing.T, token string) (claims map[string]any, typ string) {
	t.Helper()
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims); err != nil {
		t.Fatal(err)
	}
	typ, _ = jws.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string)
	return claims, typ
}

// lastRecord is the newest audit record, and it must be the only new one.
func (e *env) lastRecord() map[string]any {
	e.t.Helper()
	recs := e.transport.records(e.t)
	if len(recs) == 0 {
		e.t.Fatal("no audit record")
	}
	return recs[len(recs)-1]
}

func get(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}
