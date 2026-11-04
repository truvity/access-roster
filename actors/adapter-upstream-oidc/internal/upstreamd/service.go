package upstreamd

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/truvity/sluis/v2/actors/adapter-upstream-oidc/internal/oidc"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1/integrationv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// Actor is the registry name of this actor.
const Actor = "adapter-upstream-oidc"

// The bounds of what the adapter takes from a caller and from an upstream. The audit library bounds a string at 1024
// bytes, so an assertion that would not fit an audit record is refused before it is made.
const (
	maxParam   = 2048 // code, redirect_uri
	maxToken   = 512  // state, nonce
	maxClaim   = 256  // a claim the assertion carries
	maxAMR     = 16   // methods in amr
	pkceLenS   = 43   // an S256 challenge: 32 octets in base64url without padding (RFC 7636 section 4.2)
	verifierLo = 43   // RFC 7636 section 4.1
	verifierHi = 128
)

// verifierRE is the code verifier of RFC 7636 section 4.1: unreserved characters.
var verifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// challengeRE is an S256 challenge: base64url without padding.
var challengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Options are what a Service needs.
type Options struct {
	Boundary string
	Config   *Config
	Secrets  CredentialDir
	Audit    *audit.Emitter
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Service is the Upstream contract of adapter-upstream-oidc.
type Service struct {
	integrationv2alpha1connect.UnimplementedUpstreamServiceHandler
	opts Options
	dir  *oidc.Directory
}

// New returns the service.
func New(o Options) (*Service, error) {
	if o.Boundary == "" || o.Config == nil || o.Audit == nil {
		return nil, errors.New("upstreamd: Boundary, Config and Audit are required")
	}
	return &Service{opts: o, dir: oidc.NewDirectory(o.Now)}, nil
}

// ServerConfig is the configuration of the server on socket: the actor's registry name, and the call-graph check
// that registry.MayCall gives (the default of the kit). Mode 0660 lets the group of the process, to which session
// belongs, connect.
func (s *Service) ServerConfig(socket string) rpc.ServerConfig {
	return rpc.ServerConfig{Actor: Actor, Boundary: s.opts.Boundary, Socket: socket, Mode: 0o660}
}

// Handler returns the handler of the contract under cfg's interceptor.
func (s *Service) Handler(cfg rpc.ServerConfig) rpc.Handler {
	path, h := integrationv2alpha1connect.NewUpstreamServiceHandler(s, rpc.HandlerOptions(cfg)...)
	return rpc.Handler{Path: path, H: h}
}

// Serve serves the contract on socket until ctx ends.
func (s *Service) Serve(ctx context.Context, socket string) error {
	cfg := s.ServerConfig(socket)
	return rpc.Serve(ctx, cfg, s.Handler(cfg))
}

// target is an upstream, resolved for a call: its declaration, the floor of the boundary, and the provider.
type target struct {
	up       *configv2alpha1.Upstream
	boundary *configv2alpha1.Boundary
	dev      bool
}

// resolve reads the Boundary and the Upstream. The Boundary decides whether an http issuer is acceptable; if it cannot
// be read, the call fails and does not guess (fail closed).
func (s *Service) resolve(ctx context.Context, name string) (*target, error) {
	if name == "" || store.ValidateID(name) != nil {
		return nil, oidc.Invalid("upstream")
	}
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return nil, oidc.Unavailable("boundary")
	}
	up, err := s.opts.Config.Upstream(ctx, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, oidc.NotFound("upstream")
	case err != nil:
		return nil, oidc.Unavailable("upstream")
	}
	if up.GetKind() != "oidc" {
		return nil, oidc.Unsupported("upstream.kind")
	}
	return &target{up: up, boundary: b, dev: development(b)}, nil
}

// scopes are the scopes to ask for: the configured ones, and openid, which an OpenID Connect request must carry
// (Core 1.0 section 3.1.2.1).
func scopes(up *configv2alpha1.Upstream) []string {
	out := []string{"openid"}
	for _, sc := range up.GetScopes() {
		if sc != "" && sc != "openid" {
			out = append(out, sc)
		}
	}
	return out
}

// checkCallback accepts a callback URL that is absolute, has no fragment, and is https, or in a development boundary
// http on a loopback IP literal. The upstream holds the list of registered callbacks and decides; this is the shape.
func checkCallback(raw string, dev bool) error {
	if raw == "" || len(raw) > maxParam {
		return oidc.Invalid("redirect_uri")
	}
	if _, err := oidc.CheckURL(raw, dev); err != nil {
		return oidc.Invalid("redirect_uri")
	}
	return nil
}

func checkToken(v, path string) error {
	if v == "" || len(v) > maxToken {
		return oidc.Invalid(path)
	}
	for _, r := range v {
		if r < 0x21 || r > 0x7e {
			return oidc.Invalid(path)
		}
	}
	return nil
}

// Begin makes the authorization URL (ADR 0025, "The upstream contract"). The adapter keeps nothing about the sign-in:
// session keeps the state, the nonce and the verifier in its PendingSignIn.
func (s *Service) Begin(ctx context.Context, req *connect.Request[integrationv2alpha1.BeginRequest]) (*connect.Response[integrationv2alpha1.BeginResponse], error) {
	r := req.Msg
	t, err := s.resolve(ctx, r.GetUpstream())
	var u string
	if err == nil {
		u, err = s.begin(ctx, t, r)
	}
	if aerr := s.audit(ctx, actionBegin, nil, err); aerr != nil && err == nil {
		return nil, aerr
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&integrationv2alpha1.BeginResponse{AuthorizationUrl: u}), nil
}

func (s *Service) begin(ctx context.Context, t *target, r *integrationv2alpha1.BeginRequest) (string, error) {
	if err := checkCallback(r.GetRedirectUri(), t.dev); err != nil {
		return "", err
	}
	if err := checkToken(r.GetState(), "state"); err != nil {
		return "", err
	}
	if err := checkToken(r.GetNonce(), "nonce"); err != nil {
		return "", err
	}
	if c := r.GetCodeChallenge(); len(c) != pkceLenS || !challengeRE.MatchString(c) {
		// Only S256 is built (RFC 7636 section 4.2); a plain verifier is not a challenge.
		return "", oidc.Invalid("code_challenge")
	}
	p, err := s.dir.Provider(ctx, t.up.GetIssuer(), t.dev)
	if err != nil {
		return "", err
	}
	if !p.S256 {
		return "", oidc.Unsupported("discovery.code_challenge_methods_supported")
	}
	return p.AuthorizationURL(t.up.GetClientId(), r.GetRedirectUri(), r.GetState(), r.GetNonce(), r.GetCodeChallenge(), scopes(t.up))
}

// Complete exchanges the code and returns the verified assertion. It checks, in order: the request, the iss parameter
// of the callback (RFC 9207), the code exchange with the client credential and the verifier, the signature of the ID
// token, and its claims.
func (s *Service) Complete(ctx context.Context, req *connect.Request[integrationv2alpha1.CompleteRequest]) (*connect.Response[integrationv2alpha1.CompleteResponse], error) {
	r := req.Msg
	t, err := s.resolve(ctx, r.GetUpstream())
	var a *integrationv2alpha1.Assertion
	if err == nil {
		a, err = s.complete(ctx, t, r)
	}
	var who *audit.Subject
	var tenant string
	if err == nil {
		tenant = t.boundary.GetDefaultTenant()
		// The adapter has assigned no sluis subject: the identifier is the issuer and the upstream's subject, and the
		// pseudonym is a keyed hash of it (0029 "Pseudonyms"). The tenant is the boundary's one until Tenant items exist
		// (decision D-4).
		who = &audit.Subject{Tenant: tenant, Kind: subjectKind, Value: a.GetIssuer() + " " + a.GetSubject()}
	}
	if aerr := s.audit(ctx, actionComplete, who, err, assurance(a)); aerr != nil && err == nil {
		// A sign-in whose audit fact was not accepted does not leave the adapter (fail closed).
		return nil, aerr
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&integrationv2alpha1.CompleteResponse{Assertion: a}), nil
}

func (s *Service) complete(ctx context.Context, t *target, r *integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
	if err := checkCallback(r.GetRedirectUri(), t.dev); err != nil {
		return nil, err
	}
	if c := r.GetCode(); c == "" || len(c) > maxParam {
		return nil, oidc.Invalid("code")
	}
	if v := r.GetCodeVerifier(); len(v) < verifierLo || len(v) > verifierHi || !verifierRE.MatchString(v) {
		return nil, oidc.Invalid("code_verifier")
	}
	if err := checkToken(r.GetNonce(), "nonce"); err != nil {
		return nil, err
	}
	if len(r.GetIss()) > maxParam {
		return nil, oidc.Invalid("iss")
	}
	p, err := s.dir.Provider(ctx, t.up.GetIssuer(), t.dev)
	if err != nil {
		return nil, err
	}
	// RFC 9207 section 2.4: a client that is told the upstream sends iss refuses a response without it (REQ-FED-015),
	// and one that gets an iss other than the upstream's refuses it (REQ-FED-003). The comparison is simple string
	// comparison (RFC 3986 section 6.2.1).
	if (p.IssParameter && r.GetIss() == "") || (r.GetIss() != "" && r.GetIss() != p.Issuer) {
		return nil, oidc.Rejected("iss")
	}
	secret, err := s.opts.Secrets.ClientSecret(r.GetUpstream())
	if err != nil {
		// No credential, no sign-in: a public client is not assumed (fail closed).
		return nil, oidc.Unavailable("upstream.client_secret")
	}
	raw, err := s.dir.Exchange(ctx, p, t.dev, oidc.CodeRequest{
		ClientID: t.up.GetClientId(), ClientSecret: secret, Code: r.GetCode(), RedirectURI: r.GetRedirectUri(), CodeVerifier: r.GetCodeVerifier(),
	})
	if err != nil {
		return nil, err
	}
	claims, err := s.dir.VerifyIDToken(ctx, p, t.dev, raw, t.up.GetClientId(), r.GetNonce())
	if err != nil {
		return nil, err
	}
	return assertionOf(p.Issuer, t.up, claims)
}

// assertionOf reads the allow-list of claims out of a verified ID token (REQ-FED-005): the subject claim, the
// organisation claim if configured, and acr, amr and auth_time exactly as the upstream sent them (ADR 0025,
// "Facts"). Groups and roles are not read (REQ-FED-016), and an absent value is unknown, never a default.
func assertionOf(issuer string, up *configv2alpha1.Upstream, c oidc.Claims) (*integrationv2alpha1.Assertion, error) {
	claim := up.GetSubjectClaim()
	if claim == "" {
		// OpenID Connect Core 1.0 section 5.1: sub is the subject.
		claim = "sub"
	}
	subject, ok := c.String(claim)
	if !ok || subject == "" || len(subject) > maxClaim {
		return nil, oidc.Rejected("id_token." + claim)
	}
	a := &integrationv2alpha1.Assertion{Issuer: issuer, SubjectClaim: claim, Subject: subject}
	if _, present := c["acr"]; present {
		acr, ok := c.String("acr")
		if !ok || len(acr) > maxClaim {
			return nil, oidc.Rejected("id_token.acr")
		}
		a.Acr = &acr
	}
	amr, present, ok := c.Strings("amr")
	if !ok || len(amr) > maxAMR {
		return nil, oidc.Rejected("id_token.amr")
	}
	for _, m := range amr {
		if m == "" || len(m) > maxClaim {
			return nil, oidc.Rejected("id_token.amr")
		}
	}
	a.Amr, a.AmrPresent = amr, present
	at, present, ok := c.Int("auth_time")
	if !ok {
		return nil, oidc.Rejected("id_token.auth_time")
	}
	if present {
		a.AuthTime = timestamppb.New(time.Unix(at, 0))
	}
	if oc := up.GetOrgClaim(); oc != "" {
		if _, present := c[oc]; present {
			org, ok := c.String(oc)
			if !ok || len(org) > maxClaim {
				return nil, oidc.Rejected("id_token." + oc)
			}
			a.OrgId = org
		}
	}
	return a, nil
}

// assurance is the unmapped.sluis.assurance of a sign-in record (0030 "The fields at first"), or nil.
func assurance(a *integrationv2alpha1.Assertion) map[string]any {
	if a == nil || (a.Acr == nil && !a.GetAmrPresent()) {
		return nil
	}
	m := map[string]any{}
	if a.Acr != nil {
		m["acr"] = a.GetAcr()
	}
	if a.GetAmrPresent() {
		m["amr"] = append([]string{}, a.GetAmr()...)
	}
	return map[string]any{"assurance": m}
}

// audit records the outcome of a call (0025: "a sign-in with its outcome"). The reason of a refusal is the status
// code, a closed word, never a value. A failure of the audit itself is returned: the call fails closed, and the log
// line says only that.
func (s *Service) audit(ctx context.Context, a audit.Action, who *audit.Subject, callErr error, sluis ...map[string]any) error {
	ev := audit.Event{Action: a, Status: audit.StatusSuccess}
	if who != nil {
		ev.Tenant, ev.Subject = who.Tenant, who
	}
	for _, m := range sluis {
		if len(m) > 0 {
			ev.Sluis = m
		}
	}
	if callErr != nil {
		ev.Status, ev.StatusCode = audit.StatusFailure, reasonOf(callErr)
		ev.Subject, ev.Tenant, ev.Sluis = nil, "", nil
	}
	if err := s.opts.Audit.Emit(ctx, ev); err != nil {
		slog.Error("audit emit failed", "action", a.Name)
		return oidc.Unavailable("audit")
	}
	return nil
}

func reasonOf(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		switch ce.Code() {
		case connect.CodeUnavailable:
			return oidc.ReasonUnavailable
		case connect.CodeFailedPrecondition:
			return oidc.ReasonRejected
		case connect.CodeInvalidArgument:
			return oidc.ReasonInvalid
		case connect.CodeNotFound:
			return oidc.ReasonNotFound
		case connect.CodeResourceExhausted:
			return oidc.ReasonRateLimited
		case connect.CodeUnimplemented:
			return oidc.ReasonUnsupported
		}
	}
	return "INTERNAL"
}

// Check verifies the configuration and its reach: the Boundary reads, and every Upstream is of a kind this adapter
// serves, has a client secret, and answers discovery. It returns the paths at fault.
func (s *Service) Check(ctx context.Context) []string {
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return []string{"boundary"}
	}
	ups, err := s.opts.Config.Upstreams(ctx)
	if err != nil {
		return []string{"upstream"}
	}
	var bad []string
	for _, up := range ups {
		path := "upstream." + up.GetName()
		if up.GetKind() != "oidc" {
			bad = append(bad, path+".kind")
			continue
		}
		if _, err := s.opts.Secrets.ClientSecret(up.GetName()); err != nil {
			bad = append(bad, path+".client_secret")
		}
		if _, err := s.dir.Provider(ctx, up.GetIssuer(), development(b)); err != nil {
			bad = append(bad, path+".issuer")
		}
	}
	return bad
}
