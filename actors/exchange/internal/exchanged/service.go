package exchanged

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"connectrpc.com/connect"

	exchangev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1/exchangev2alpha1connect"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// Actor is the registry name of this actor.
const Actor = "exchange"

// maxField bounds a parameter of the request (the audience is a client id, at most 128 characters).
const maxField = 128

// Options are what a Service needs.
type Options struct {
	Boundary  string
	Config    *Config
	Directory Directory
	Policy    policyv2alpha1connect.PolicyServiceClient
	Signer    signerv2alpha1connect.SignerServiceClient
	// Keys is the client of key@ for this actor: the pairwise subject is a Mac under the tenant's key.
	Keys  keyv2alpha1connect.KeyServiceClient
	Audit *audit.Emitter
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Service is the ExchangeService.
type Service struct {
	exchangev2alpha1connect.UnimplementedExchangeServiceHandler
	opts     Options
	verifier *Verifier
	now      func() time.Time
}

// New returns the service.
func New(o Options) (*Service, error) {
	if o.Boundary == "" || o.Config == nil || o.Directory == nil || o.Policy == nil || o.Signer == nil || o.Keys == nil || o.Audit == nil {
		return nil, errors.New("exchanged: Boundary, Config, Directory, Policy, Signer, Keys and Audit are required")
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Service{opts: o, verifier: NewVerifier(o.Config, o.Signer, now), now: now}, nil
}

// ServerConfig is the configuration of the server on socket: the actor's registry name, and the call-graph check
// that registry.MayCall gives (the default of the kit). Mode 0660 lets the group of the process, to which entry
// belongs, connect.
func (s *Service) ServerConfig(socket string) rpc.ServerConfig {
	return rpc.ServerConfig{Actor: Actor, Boundary: s.opts.Boundary, Socket: socket, Mode: 0o660}
}

// Handler returns the handler of the contract under cfg's interceptor.
func (s *Service) Handler(cfg rpc.ServerConfig) rpc.Handler {
	path, h := exchangev2alpha1connect.NewExchangeServiceHandler(s, rpc.HandlerOptions(cfg)...)
	return rpc.Handler{Path: path, H: h}
}

// Serve serves the contract on socket until ctx ends.
func (s *Service) Serve(ctx context.Context, socket string) error {
	cfg := s.ServerConfig(socket)
	return rpc.Serve(ctx, cfg, s.Handler(cfg))
}

// Token is the token endpoint's exchange grant (RFC 8693). A request that is refused is answered in the form of the
// endpoint, with an OAuth error code; a dependency that does not answer is a Connect error, and no token is issued on
// a weaker basis. Every request is audited, and an exchange whose audit fact was not accepted does not leave.
func (s *Service) Token(ctx context.Context, req *connect.Request[exchangev2alpha1.TokenExchangeRequest]) (*connect.Response[typev2alpha1.HttpReply], error) {
	a := &attempt{audience: audienceForRecord(req.Msg.GetAudience())}
	out, err := s.run(ctx, req.Msg, a)
	if aerr := s.audit(ctx, a, err); aerr != nil && err == nil {
		return nil, aerr
	}
	var r *refused
	var o *outage
	switch {
	case err == nil:
		return connect.NewResponse(out), nil
	case errors.As(err, &r):
		return connect.NewResponse(errorReply(r.code)), nil
	case errors.As(err, &o):
		slog.Error("exchange: a dependency did not answer", "dependency", o.reason)
		return nil, refusal.New(connect.CodeUnavailable, o.reason, "")
	}
	slog.Error("exchange: internal error", "reason", reasonOf(err))
	return nil, refusal.New(connect.CodeInternal, "internal", "")
}

// audit records the outcome of a request (REQ-EXCH-009). A failure of the audit itself is returned: the call fails
// closed, and the log line says only that.
func (s *Service) audit(ctx context.Context, a *attempt, err error) error {
	ev := a.event(err)
	if aerr := s.opts.Audit.Emit(ctx, ev); aerr != nil {
		slog.Error("audit emit failed", "action", ev.Action.Name)
		return refusal.New(connect.CodeUnavailable, "audit", "")
	}
	return nil
}

// run carries out one exchange. It returns the reply, or an error that is a *refused (an answer), an *outage (a
// dependency) or anything else (a bug).
func (s *Service) run(ctx context.Context, r *exchangev2alpha1.TokenExchangeRequest, a *attempt) (*typev2alpha1.HttpReply, error) {
	if err := checkRequest(r); err != nil {
		return nil, err
	}
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return nil, unavailable("store", err)
	}
	tenant, err := TenantOf(b)
	if err != nil {
		return nil, unavailable("config", err)
	}
	a.tenant = tenant.ID
	accessLife, err := s.opts.Config.AccessLifetime(ctx)
	if err != nil {
		return nil, unavailable("store", err)
	}

	subject, err := s.verifier.Verify(ctx, r.GetSubjectToken(), b)
	if err != nil {
		return nil, err
	}
	a.subject = subject
	if subject.Kind != KindOwn {
		// A proof of a trusted issuer is verified above, and its replay guard is set. What a workload may have for it
		// is a decision about a Workload, and policy's contract has no facts for one yet.
		// planned: workload exchange, with the first workload consumer (#961)
		return nil, invalidRequest(reasonProofKind)
	}
	// The client of the request is the client the subject token was issued to. The contract has no field for client
	// authentication yet, so the token is the only thing that ties the request to a client (decision for the
	// maintainer, REQ-EXCH-007 and REQ-EXCH-011).
	if r.GetClientId() != "" && r.GetClientId() != subject.ClientID {
		return nil, invalidRequest(reasonClient)
	}

	// An unknown audience is the answer of a refused one (REQ-EXCH-003). The client is the audience's declaration.
	client, err := s.opts.Config.Client(ctx, r.GetAudience())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, invalidTarget(reasonAudience)
	case err != nil:
		return nil, unavailable("store", err)
	}

	person, err := s.opts.Directory.Person(ctx, tenant.ID, subject)
	switch {
	case errors.Is(err, ErrUnknownPerson):
		return nil, invalidRequest(reasonPerson)
	case errors.Is(err, ErrSessionEnded):
		return nil, invalidRequest(reasonSessionEnded)
	case err != nil:
		return nil, unavailable("directory", err)
	}
	a.person = &person

	verdict, err := s.decide(ctx, tenant, r.GetAudience(), client.GetRequires(), client.GetKind(), subject, &person)
	if err != nil {
		return nil, err
	}
	a.decision = &decision{
		id: verdict.GetDecisionId(), digest: verdict.GetDigest(), allowed: verdict.GetDecision() == policyv2alpha1.Decision_ALLOW,
	}
	for _, rs := range verdict.GetReasons() {
		a.decision.policies = append(a.decision.policies, rs.GetPolicyId())
	}
	if !a.decision.allowed {
		return nil, invalidTarget(reasonPolicy)
	}

	now := s.now()
	iat, exp, ok := lifetime(now, accessLife, client.GetTtlCap().AsDuration(), subject.Exp)
	if !ok {
		return nil, invalidRequest(reasonLifetime)
	}
	sub, err := s.subjectOf(ctx, tenant, person.ID, verdict.GetSealedGrant())
	if err != nil {
		return nil, err
	}
	jti, err := newJTI()
	if err != nil {
		return nil, err
	}
	claims, err := claimsOf(b.GetIssuer(), sub, r.GetAudience(), iat, exp, jti, subject, narrow(verdict.GetGrantNames(), client.GetRequires()))
	if err != nil {
		return nil, err
	}
	res, err := s.opts.Signer.SignToken(ctx, connect.NewRequest(&signerv2alpha1.SignTokenRequest{Typ: "at+jwt", ClaimsJson: claims}))
	if err != nil {
		slog.Error("exchange: signer refused or failed", "code", connect.CodeOf(err).String())
		return nil, unavailable("signer", err)
	}
	return successReply(res.Msg.GetToken(), exp-iat), nil
}

// checkRequest checks the parameters of RFC 8693 section 2.1 that need no other fact.
func checkRequest(r *exchangev2alpha1.TokenExchangeRequest) error {
	switch {
	case r.GetGrantType() != grantTokenExchange:
		return &refused{codeUnsupportedGrant, reasonGrantType}
	case r.GetActorToken() != "" || r.GetActorTokenType() != "":
		// REQ-EXCH-002: ignoring the parameter would imply delegation, which sluis does not provide (no `act`).
		return invalidRequest(reasonActorToken)
	case r.GetRequestedTokenType() != "" && r.GetRequestedTokenType() != tokenTypeAccess:
		// REQ-EXCH-008
		return invalidRequest(reasonRequestedType)
	case r.GetSubjectToken() == "":
		return invalidRequest(reasonSubjectToken)
	case r.GetSubjectTokenType() != tokenTypeAccess && r.GetSubjectTokenType() != tokenTypeJWT:
		return invalidRequest(reasonSubjectType)
	case r.GetScope() != "":
		// The claims of a token have no scope (ADR 0020), so a narrower scope has nothing to narrow.
		return &refused{codeInvalidScope, reasonScope}
	case r.GetResource() != "":
		// A resource indicator selects a registered client (ADR 0017), and a client declares no resource yet.
		// planned: resource indicators, with the first client that declares one
		return invalidTarget(reasonResource)
	case r.GetAudience() == "" || len(r.GetAudience()) > maxField:
		return invalidTarget(reasonAudience)
	}
	return nil
}

// decide asks policy whether the person's token may become a token for the audience (action token.exchange). The
// answer carries the full set of held grant names; exchange narrows it (policy.md, "How a person's grants are found").
func (s *Service) decide(ctx context.Context, t Tenant, audience string, requires []string, kind string, sub *Subject, p *Person) (*policyv2alpha1.DecideResponse, error) {
	amr := append([]string{}, sub.AMR...)
	res, err := s.opts.Policy.Decide(ctx, connect.NewRequest(&policyv2alpha1.DecideRequest{
		Action:    "token.exchange",
		Principal: &policyv2alpha1.EntityRef{Type: "Person", Id: p.ID},
		Resource:  &policyv2alpha1.EntityRef{Type: "Client", Id: audience},
		Tenant:    t.ID,
		Context: &policyv2alpha1.Authentication{
			Acr: sub.ACR, Amr: amr, AmrPresent: sub.AMRPresent, AuthAge: authAge(sub, s.now()),
		},
		Person: &policyv2alpha1.PersonFacts{Subject: p.ID, Accounts: p.Accounts, State: p.State, Org: p.Org},
		Client: &policyv2alpha1.ClientFacts{Id: audience, Requires: requires, Kind: kind},
		// The grant lets exchange ask key@ for the pairwise Mac.
		GrantKeyOps: []string{"mac"},
	}))
	if err != nil {
		path, _ := refusal.FieldPath(err)
		reason, _ := refusal.Reason(err)
		slog.Error("exchange: policy did not decide", "code", connect.CodeOf(err).String(), "reason", reason, "path", path)
		return nil, unavailable("policy", err)
	}
	return res.Msg, nil
}

// subjectOf is the `sub` of the new token: the subject of the target tenant's sector (ADR 0034, REQ-SUBJ-067), a Mac
// under the tenant's pairwise key, made at key@. An exchanged token never carries the subject of the token it was
// made from.
//
// planned: a tenant that declares the sector `public` gets the person's own id; that comes with the Tenant item
// (#1216), since until then every sector is pairwise (decision D-4).
func (s *Service) subjectOf(ctx context.Context, t Tenant, personID string, sealedGrant []byte) (string, error) {
	res, err := s.opts.Keys.Mac(ctx, connect.NewRequest(&keyv2alpha1.MacRequest{
		Purpose: "pairwise", Tenant: t.ID, Label: pairwiseLabel, Input: pairwiseInput(t.Sector, personID), Grant: sealedGrant,
	}))
	if err != nil {
		slog.Error("exchange: key@ did not make the subject", "code", connect.CodeOf(err).String())
		return "", unavailable("key", err)
	}
	if len(res.Msg.GetMac()) < subBytes {
		return "", unavailable("key", errors.New("short mac"))
	}
	return pairwiseSub(res.Msg.GetMac()), nil
}

// checker is a Directory that can say whether it is bound to the kinds it reads.
type checker interface {
	Check(ctx context.Context) error
}

// Check verifies the configuration and its reach: the Boundary reads and names a default tenant, the issuers of
// ExchangeTrust name keys at an acceptable URL, signer gives the key set, and the directory is bound. It returns the
// paths at fault.
func (s *Service) Check(ctx context.Context) []string {
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return []string{"boundary"}
	}
	var bad []string
	if _, err := TenantOf(b); err != nil {
		bad = append(bad, "boundary.default_tenant")
	}
	trust, err := s.opts.Config.Trust(ctx)
	if err != nil {
		return append(bad, "exchange_trust")
	}
	for i, ti := range trust.GetIssuers() {
		path := "exchange_trust.issuers[" + strconv.Itoa(i) + "]"
		if ti.GetIssuer() == "" || ti.GetProofKind() == "" || ti.GetProofKind() == KindOwn || len(ti.GetAudiences()) == 0 {
			bad = append(bad, path)
			continue
		}
		if _, err := CheckURL(ti.GetJwksUri(), development(b)); err != nil {
			bad = append(bad, path+".jwks_uri")
		}
	}
	if _, err := s.verifier.ownKeys(ctx, false); err != nil {
		bad = append(bad, "signer.key_set")
	}
	if c, ok := s.opts.Directory.(checker); ok {
		if err := c.Check(ctx); err != nil {
			bad = append(bad, "directory")
		}
	}
	return bad
}
