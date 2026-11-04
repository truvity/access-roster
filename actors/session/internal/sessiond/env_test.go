//go:build sluis_test

package sessiond_test

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1connectpkg "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1/integrationv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1/sessionv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/version"
)

const (
	testBoundary = "dev"
	testTenant   = "acme"
	testIssuer   = "https://sluis.dev.local.test"
	testClient   = "sluis-cli"
	testRedirect = "http://127.0.0.1:43210/callback"
	testGroup    = "dev:example-app:user"
)

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func timestampOf(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serve serves a handler on a socket as the registry actor `callee` and stops it with the test. The test process has
// one uid; the resolver names it `who` for the server, so the call-graph check sees that caller.
func serve(t *testing.T, socket, callee, who string, h rpc.Handler) {
	t.Helper()
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	cfg := rpc.WithNameResolver(rpc.ServerConfig{
		Actor: callee, Socket: socket, Allow: func(rpc.Peer, string) bool { return true },
	}, func(uid uint32) (string, uint32, bool) { return who, 0, uid == self })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, cfg, h) }()
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

// env is session, served on a Unix socket as the registry runs it, with its dependencies as fake Connect services on
// sockets of their own. The test is entry: it calls session through the generated client.
type env struct {
	t         *testing.T
	clk       *clock
	svc       *sessiond.Service
	client    sessionv2alpha1connect.SessionServiceClient
	store     *fakeStore
	key       *fakeKey
	policy    *fakePolicy
	signer    *fakeSigner
	upstream  *fakeUpstream
	transport *fakeTransport
	cfg       *sessiond.Config
}

// options change an env before it starts.
type options struct {
	boundary *configv2alpha1.Boundary
	client   *configv2alpha1.InstallationClient
	extra    []*configv2alpha1.InstallationClient
	lifetime *configv2alpha1.TokenLifetime
	upstream *configv2alpha1.Upstream
	sectors  func(string) sessiond.Sector
	caller   string // the registry name session sees as its caller; default "entry"
}

func newEnv(t *testing.T, mutate func(*options)) *env {
	t.Helper()
	o := options{
		boundary: &configv2alpha1.Boundary{Name: testBoundary, Environment: "development", Issuer: testIssuer, DefaultTenant: testTenant},
		client: &configv2alpha1.InstallationClient{
			Id: testClient, Kind: "public", Redirects: []string{"http://127.0.0.1/callback"}, Requires: []string{testGroup},
		},
		lifetime: &configv2alpha1.TokenLifetime{
			IdToken: durationpb.New(10 * time.Minute), AccessToken: durationpb.New(10 * time.Minute),
			HumanSessionAbsolute: durationpb.New(12 * time.Hour), RefreshIdle: durationpb.New(8 * time.Hour),
		},
		upstream: &configv2alpha1.Upstream{
			Name: "workforce", Kind: "oidc", Issuer: "https://idp.example.test/realms/test", ClientId: "sluis-local", SubjectClaim: "preferred_username",
		},
		caller: "entry",
	}
	if mutate != nil {
		mutate(&o)
	}
	dir := shortDir(t)
	clk := &clock{t: time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)}
	e := &env{t: t, clk: clk}
	e.policy = &fakePolicy{clk: clk, grantNames: []string{testGroup}}
	e.store = &fakeStore{clk: clk, policy: e.policy, items: map[string]*storedItem{}}
	e.key = &fakeKey{clk: clk, policy: e.policy}
	e.signer = &fakeSigner{}
	e.upstream = &fakeUpstream{clk: clk}
	e.transport = &fakeTransport{}

	e.store.put("boundary", "", "default", o.boundary)
	e.store.put("installation-client", "", o.client.GetId(), o.client)
	for _, c := range o.extra {
		e.store.put("installation-client", "", c.GetId(), c)
	}
	e.store.put("token-lifetime", "", "default", o.lifetime)
	e.store.put("upstream", "", o.upstream.GetName(), o.upstream)

	sock := func(n string) string { return filepath.Join(dir, n+".sock") }
	path, h := storev2alpha1connect.NewStoreServiceHandler(e.store)
	serve(t, sock("store"), "store", "session", rpc.Handler{Path: path, H: h})
	path, h = keyv2alpha1connect.NewKeyServiceHandler(e.key)
	serve(t, sock("key"), "key", "session", rpc.Handler{Path: path, H: h})
	path, h = policyv2alpha1connect.NewPolicyServiceHandler(e.policy)
	serve(t, sock("policy"), "policy", "session", rpc.Handler{Path: path, H: h})
	path, h = signerv2alpha1connect.NewSignerServiceHandler(e.signer)
	serve(t, sock("signer"), "signer", "session", rpc.Handler{Path: path, H: h})
	path, h = integrationv2alpha1connectpkg.NewUpstreamServiceHandler(e.upstream)
	serve(t, sock("up"), "adapter-upstream-oidc", "session", rpc.Handler{Path: path, H: h})
	path, h = transportv2alpha1connect.NewTransportServiceHandler(e.transport)
	serve(t, sock("emit"), "driver-writer-spool", "session", rpc.Handler{Path: path, H: h})

	dial := func(n string) (connect.HTTPClient, string) { return rpc.Dial(sock(n)) }
	sh, surl := dial("store")
	st := storev2alpha1connect.NewStoreServiceClient(sh, surl, rpc.ClientOptions()...)
	cfg, err := sessiond.NewConfig(st)
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	kh, kurl := dial("key")
	keys := keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...)
	ph, purl := dial("policy")
	gh, gurl := dial("signer")
	uh, uurl := dial("up")
	th, turl := dial("emit")
	em, err := audit.New(audit.Config{
		Actor: sessiond.Actor, Boundary: testBoundary, Release: version.Version, Now: clk.now,
		Transport: transportv2alpha1connect.NewTransportServiceClient(th, turl, rpc.ClientOptions()...),
		Keys:      keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sessiond.New(sessiond.Options{
		Boundary: testBoundary, Config: cfg, Store: st, Keys: keys,
		Policy:   policyv2alpha1connect.NewPolicyServiceClient(ph, purl, rpc.ClientOptions()...),
		Signer:   signerv2alpha1connect.NewSignerServiceClient(gh, gurl, rpc.ClientOptions()...),
		Upstream: integrationv2alpha1connectpkg.NewUpstreamServiceClient(uh, uurl, rpc.ClientOptions()...),
		Audit:    em, Now: clk.now, Sectors: o.sectors,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	// session's own socket: the call-graph check of the kit is the one the product uses, and the caller is entry.
	own := sock("session")
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	scfg := rpc.WithNameResolver(svc.ServerConfig(own), func(uid uint32) (string, uint32, bool) { return o.caller, 0, uid == self })
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
		if _, err := os.Stat(own); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session's socket did not appear")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ch, curl := rpc.Dial(own)
	e.client = sessionv2alpha1connect.NewSessionServiceClient(ch, curl, rpc.ClientOptions()...)
	return e
}

// ---- what entry does ---------------------------------------------------------------------------------------------

// authorizeParams is a valid authorization request of the CLI, with the PKCE pair.
type authorizeParams struct {
	req      *sessionv2alpha1.AuthorizeRequest
	verifier string
}

func newAuthorize() authorizeParams {
	v := "client-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
	return authorizeParams{verifier: v, req: &sessionv2alpha1.AuthorizeRequest{
		ResponseType: "code", ClientId: testClient, RedirectUri: testRedirect, Scope: "openid",
		State: "client-state-1", Nonce: "client-nonce-1", CodeChallenge: s256(v), CodeChallengeMethod: "S256",
	}}
}

func (e *env) authorize(r *sessionv2alpha1.AuthorizeRequest) *typev2alpha1.HttpReply {
	e.t.Helper()
	res, err := e.client.Authorize(context.Background(), connect.NewRequest(r))
	if err != nil {
		e.t.Fatalf("Authorize: %v", err)
	}
	return res.Msg
}

func (e *env) callback(r *sessionv2alpha1.CallbackRequest) *typev2alpha1.HttpReply {
	e.t.Helper()
	res, err := e.client.Callback(context.Background(), connect.NewRequest(r))
	if err != nil {
		e.t.Fatalf("Callback: %v", err)
	}
	return res.Msg
}

func (e *env) token(r *sessionv2alpha1.TokenRequest) *typev2alpha1.HttpReply {
	e.t.Helper()
	res, err := e.client.Token(context.Background(), connect.NewRequest(r))
	if err != nil {
		e.t.Fatalf("Token: %v", err)
	}
	return res.Msg
}

func headerOf(r *typev2alpha1.HttpReply, name string) []string {
	var out []string
	for _, h := range r.GetHeaders() {
		if strings.EqualFold(h.GetName(), name) {
			out = append(out, h.GetValue())
		}
	}
	return out
}

// location parses the Location of a redirect.
func location(t *testing.T, r *typev2alpha1.HttpReply) *url.URL {
	t.Helper()
	if r.GetStatus() != http.StatusFound {
		t.Fatalf("status %d, want 302 (body %q)", r.GetStatus(), r.GetBody())
	}
	l := headerOf(r, "Location")
	if len(l) != 1 {
		t.Fatalf("%d Location headers", len(l))
	}
	u, err := url.Parse(l[0])
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// cookieValue is the value of the sign-in cookie a reply sets, "" when it sets none or clears it.
func cookieValue(t *testing.T, r *typev2alpha1.HttpReply) string {
	t.Helper()
	for _, c := range headerOf(r, "Set-Cookie") {
		name, rest, _ := strings.Cut(c, "=")
		if name != sessiond.SigninCookie {
			continue
		}
		v, _, _ := strings.Cut(rest, ";")
		return v
	}
	return ""
}

// signIn runs authorize and callback like a browser and entry do, and returns the code and the client's state.
func (e *env) signIn() (code string, p authorizeParams) {
	e.t.Helper()
	p = newAuthorize()
	a := e.authorize(p.req)
	up := location(e.t, a)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(e.t, a),
	})
	back := location(e.t, cb)
	code = back.Query().Get("code")
	if code == "" {
		e.t.Fatalf("no code in %s", back.String())
	}
	return code, p
}

// records parses the audit records.
func (e *env) records() []map[string]any {
	e.t.Helper()
	var out []map[string]any
	for _, b := range e.transport.records() {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func (e *env) eventCodes() []string {
	var out []string
	for _, r := range e.records() {
		md, _ := r["metadata"].(map[string]any)
		out = append(out, md["event_code"].(string))
	}
	return out
}

func secretIDForTest(s string) string {
	sum := sha512.Sum384([]byte(s))
	return hex.EncodeToString(sum[:])
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func protoOf[T proto.Message](t *testing.T, b []byte, m T) T {
	t.Helper()
	if err := proto.Unmarshal(b, m); err != nil {
		t.Fatal(err)
	}
	return m
}

// sealAsWinner seals an UpstreamLink for the subject, as the instance that won a race would have.
func sealAsWinner(e *env, tenant, id, subject string) ([]byte, error) {
	return e.key.sealForTest("data", &typev2alpha1.Address{Kind: "upstream-link", Tenant: tenant, Id: id}, &sessionv2alpha1.UpstreamLink{Subject: subject})
}

func clientOf(id string) *configv2alpha1.InstallationClient {
	return &configv2alpha1.InstallationClient{Id: id, Kind: "public", Redirects: []string{"http://127.0.0.1/callback"}}
}
