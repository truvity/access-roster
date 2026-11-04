// Package sessiond is session: the actor that serves the sign-in and token endpoints that entry routes to it
// (decision D-10: typed RPCs, not a mounted provider). It signs a person in at the upstream through
// adapter-upstream-oidc, keeps the person, the upstream link and the session chain in store@, asks policy for
// token.issue, and has signer sign the ID and access tokens.
//
// session holds no key. Everything sealed is sealed and opened at key@ (principle 18), and what session decides is
// only the flow: which redirect is allowed, which state matches, which code is spent, which chain is current.
package sessiond

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1/integrationv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1/sessionv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// Actor is the registry name of this actor.
const Actor = "session"

// Options are what a Service needs. Each client is the Connect client of an actor the call graph lets session reach.
type Options struct {
	Boundary string
	Config   *Config
	Store    storev2alpha1connect.StoreServiceClient
	Keys     keyv2alpha1connect.KeyServiceClient
	Policy   policyv2alpha1connect.PolicyServiceClient
	Signer   signerv2alpha1connect.SignerServiceClient
	Upstream integrationv2alpha1connect.UpstreamServiceClient
	Audit    *audit.Emitter
	// UpstreamName names the Upstream to sign people in at. Empty means the only one the boundary declares.
	UpstreamName string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Service is the session contract.
type Service struct {
	sessionv2alpha1connect.UnimplementedSessionServiceHandler
	opts   Options
	keys   keys
	sealed sealedStore

	codes *store.Client[*sessionv2alpha1.AuthCode]
}

// New returns the service.
func New(o Options) (*Service, error) {
	if o.Boundary == "" || o.Config == nil || o.Store == nil || o.Keys == nil || o.Policy == nil || o.Signer == nil ||
		o.Upstream == nil || o.Audit == nil {
		return nil, errors.New("sessiond: Boundary, Config, Store, Keys, Policy, Signer, Upstream and Audit are required")
	}
	s := &Service{opts: o, keys: keys{o.Keys}, sealed: sealedStore{c: o.Store, keys: keys{o.Keys}}}
	var err error
	if s.codes, err = store.New(o.Store, "AuthCode", func() *sessionv2alpha1.AuthCode { return &sessionv2alpha1.AuthCode{} }); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) now() time.Time {
	if s.opts.Now != nil {
		return s.opts.Now()
	}
	return time.Now()
}

// ServerConfig is the configuration of the server on socket: the actor's registry name and the call-graph check that
// registry.MayCall gives (the default of the kit). entry and console may call; nobody else.
func (s *Service) ServerConfig(socket string) rpc.ServerConfig {
	return rpc.ServerConfig{Actor: Actor, Boundary: s.opts.Boundary, Socket: socket, Mode: 0o660}
}

// Handler returns the handler of the contract under cfg's interceptor.
func (s *Service) Handler(cfg rpc.ServerConfig) rpc.Handler {
	path, h := sessionv2alpha1connect.NewSessionServiceHandler(s, rpc.HandlerOptions(cfg)...)
	return rpc.Handler{Path: path, H: h}
}

// Serve serves the contract on socket until ctx ends.
func (s *Service) Serve(ctx context.Context, socket string) error {
	cfg := s.ServerConfig(socket)
	return rpc.Serve(ctx, cfg, s.Handler(cfg))
}

// Check verifies the configuration session needs and its reach: the Boundary with a tenant, the token lifetimes and
// an upstream to sign in at. It returns the paths at fault.
func (s *Service) Check(ctx context.Context) []string {
	var bad []string
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		bad = append(bad, "boundary")
	} else if b.GetDefaultTenant() == "" || b.GetIssuer() == "" {
		bad = append(bad, "boundary.default_tenant")
	}
	if _, err := s.opts.Config.Lifetimes(ctx); err != nil {
		bad = append(bad, "token_lifetime")
	}
	if _, err := s.opts.Config.Upstream(ctx, s.opts.UpstreamName); err != nil {
		bad = append(bad, "upstream")
	}
	return bad
}

// unavailable is the error of a dependency that failed: session cannot answer, so it says so and fails closed. The
// cause is logged without any value of the request; the caller gets the code and a closed reason.
func unavailable(what string, cause error) error {
	slog.Error("dependency failed", "dependency", what, "code", connect.CodeOf(cause).String())
	if connect.CodeOf(cause) == connect.CodeDeadlineExceeded || connect.CodeOf(cause) == connect.CodeCanceled {
		return refusal.New(connect.CodeDeadlineExceeded, what, "")
	}
	return refusal.New(connect.CodeUnavailable, what, "")
}

// internal is a bug or an inconsistency inside session or its data: the caller learns nothing.
func internal(what string, cause error) error {
	slog.Error("internal error", "step", what, "error", fmt.Sprintf("%T", cause))
	return refusal.New(connect.CodeInternal, what, "")
}
