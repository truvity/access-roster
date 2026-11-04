package keyd

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// maxGrantLife is the longest a grant lives (ADR 0007, "Sealed grants": about 60 seconds).
const maxGrantLife = 60 * time.Second

// grantKind is the kind part of the address a grant is sealed at: tenant "-", kind "grant", id the decision id.
const grantKind = "grant"

// errBadGrant is a grant that does not open: malformed, or sealed by another key or at another address.
var errBadGrant = errors.New("keyd: the grant does not open")

// grantState holds a sealed grant and, once opened, the grant. An Open of many items opens it once.
type grantState struct {
	sealed []byte
	done   bool
	g      *typev2alpha1.Grant
	err    error
}

func newGrantState(sealed []byte) *grantState { return &grantState{sealed: sealed} }

func (s *Server) grantOf(ctx context.Context, st *grantState) (*typev2alpha1.Grant, error) {
	if !st.done {
		st.g, st.err = s.openGrant(ctx, st.sealed)
		st.done = true
	}
	return st.g, st.err
}

// checkGrant is the third check of ADR 0006: the grant must be sealed by this boundary, made for the caller,
// name the address's tenant (or every tenant), name the operation and not be expired (ADR 0007, "Two
// independent checks"). A refusal is permission_denied/grant.
func (s *Server) checkGrant(ctx context.Context, st *grantState, caller, op, purpose, tenant string) error {
	deny := func() error {
		return s.refuse(ctx, caller, op, purpose, tenant, connect.CodePermissionDenied, reasonGrant, "grant")
	}
	if len(st.sealed) == 0 {
		return deny()
	}
	g, err := s.grantOf(ctx, st)
	switch {
	case errors.Is(err, errBadGrant):
		return deny()
	case err != nil:
		return s.keyFailure(ctx, caller, op, purpose, tenant, err, false)
	}
	switch {
	case g.GetBoundary() != s.cfg.Boundary,
		g.GetHolder() != caller,
		!slices.Contains(g.GetTenants(), tenant) && !slices.Contains(g.GetTenants(), "*"),
		!slices.Contains(g.GetKeyOps(), op),
		g.GetExpiresAt() == nil || !g.GetExpiresAt().AsTime().After(s.now()):
		return deny()
	}
	return nil
}

// openGrant opens a sealed grant: the wire form is u16 length | decision_id | envelope, and the grant is bound to
// the address (tenant "-", kind "grant", id decision_id) of the boundary's grant key.
func (s *Server) openGrant(ctx context.Context, sealed []byte) (*typev2alpha1.Grant, error) {
	if len(sealed) < 2 {
		return nil, errBadGrant
	}
	n := int(binary.BigEndian.Uint16(sealed))
	if n == 0 || len(sealed) < 2+n+envelope.MinLen {
		return nil, errBadGrant
	}
	id, env := string(sealed[2:2+n]), sealed[2+n:]
	if strings.Contains(id, "/") || store.ValidateID(id) != nil {
		return nil, errBadGrant
	}
	h, err := envelope.ParseHeader(env)
	if err != nil || h.Purpose != envelope.CodeGrant {
		return nil, errBadGrant
	}
	var pt []byte
	err = s.withKey(ctx, keyRef{"", "grant", h.Generation}, false, func(key []byte) error {
		var e error
		pt, e = envelope.Open(key, env, envelope.Address{Boundary: s.cfg.Boundary, Tenant: envelope.NoTenant, Kind: grantKind, ID: id})
		return e
	})
	switch {
	case errors.Is(err, envelope.ErrOpen), errors.Is(err, errNoKey):
		return nil, errBadGrant
	case err != nil:
		return nil, err
	}
	defer clear(pt)
	g := &typev2alpha1.Grant{}
	if err := proto.Unmarshal(pt, g); err != nil {
		return nil, errBadGrant
	}
	return g, nil
}

// SealGrant seals a grant that policy decided. Only policy may call it (the registry's rule for purpose grant).
func (s *Server) SealGrant(ctx context.Context, req *connect.Request[keyv2alpha1.SealGrantRequest]) (*connect.Response[keyv2alpha1.SealGrantResponse], error) {
	caller, err := s.callerOf(ctx, "seal")
	if err != nil {
		return nil, err
	}
	if !registry.KeyAllows(caller, "grant", "seal") {
		return nil, s.refuse(ctx, caller, "seal", "grant", "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	bad := func(path string) error {
		return s.refuse(ctx, caller, "seal", "grant", "", connect.CodeInvalidArgument, reasonSchema, path)
	}
	in := req.Msg.GetGrant()
	if in == nil {
		return nil, bad("grant")
	}
	g := proto.Clone(in).(*typev2alpha1.Grant)
	switch {
	case g.GetHolder() == "":
		return nil, bad("grant.holder")
	case len(g.GetTenants()) == 0:
		return nil, bad("grant.tenants")
	case g.GetIssuedAt() == nil || g.GetExpiresAt() == nil:
		return nil, bad("grant.expires_at")
	}
	if life := g.GetExpiresAt().AsTime().Sub(g.GetIssuedAt().AsTime()); life <= 0 || life > maxGrantLife {
		return nil, bad("grant.expires_at")
	}
	for _, t := range g.GetTenants() {
		if t != "*" && !validTenant(t) {
			return nil, bad("grant.tenants")
		}
	}
	id := g.GetDecisionId()
	if strings.Contains(id, "/") || store.ValidateID(id) != nil || len(id) > 0xFFFF {
		return nil, bad("grant.decision_id")
	}
	switch g.GetBoundary() {
	case "":
		g.Boundary = s.cfg.Boundary
	case s.cfg.Boundary:
	default:
		return nil, bad("grant.boundary")
	}
	pt, err := proto.MarshalOptions{Deterministic: true}.Marshal(g)
	if err != nil {
		return nil, bad("grant")
	}
	defer clear(pt)
	var env []byte
	err = s.withKey(ctx, keyRef{"", "grant", sealGeneration}, true, func(key []byte) error {
		var e error
		env, e = envelope.Seal(key, envelope.CodeGrant, sealGeneration,
			envelope.Address{Boundary: s.cfg.Boundary, Tenant: envelope.NoTenant, Kind: grantKind, ID: id}, pt)
		return e
	})
	if err != nil {
		return nil, s.keyFailure(ctx, caller, "seal", "grant", "", err, false)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(id))) //nolint:gosec // bounded above
	out = append(out, id...)
	out = append(out, env...)
	return connect.NewResponse(&keyv2alpha1.SealGrantResponse{SealedGrant: out}), nil
}

// OpenGrant opens a sealed grant for the actors that verify one (store@, signer, ca, the minters). It refuses an
// expired grant. It does not check the holder: the caller checks that the grant was made for whom it says.
func (s *Server) OpenGrant(ctx context.Context, req *connect.Request[keyv2alpha1.OpenGrantRequest]) (*connect.Response[keyv2alpha1.OpenGrantResponse], error) {
	caller, err := s.callerOf(ctx, "open")
	if err != nil {
		return nil, err
	}
	if !registry.KeyAllows(caller, "grant", "open") {
		return nil, s.refuse(ctx, caller, "open", "grant", "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	g, err := s.openGrant(ctx, req.Msg.GetSealedGrant())
	switch {
	case errors.Is(err, errBadGrant):
		return nil, s.refuse(ctx, caller, "open", "grant", "", connect.CodePermissionDenied, reasonGrant, "sealed_grant")
	case err != nil:
		return nil, s.keyFailure(ctx, caller, "open", "grant", "", err, false)
	}
	if g.GetExpiresAt() == nil || !g.GetExpiresAt().AsTime().After(s.now()) {
		return nil, s.refuse(ctx, caller, "open", "grant", "", connect.CodeFailedPrecondition, reasonExpired, "sealed_grant")
	}
	return connect.NewResponse(&keyv2alpha1.OpenGrantResponse{Grant: g}), nil
}
