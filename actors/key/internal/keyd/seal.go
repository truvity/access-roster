package keyd

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// sealGeneration is the generation Seal uses tonight: every purpose but pseudonym is at generation 1. A rotation
// by count (ADR 0006, "Rotation") is not built yet; Open takes the generation from the envelope, so it will not
// have to change.
const sealGeneration = 1

// maxOpenItems is the most envelopes one Open takes.
const maxOpenItems = 64

// sealable returns the envelope code of a purpose that Seal and Open take. The purpose grant is not one: a
// grant is sealed by SealGrant, which checks what a grant may hold, and opened by OpenGrant.
func sealable(purpose string) (byte, bool) {
	if purpose == "grant" {
		return 0, false
	}
	return envelope.Code(purpose)
}

// tenantFits says whether the address's tenant ("" for none) fits the purpose: cookies are the boundary's, and
// evidence is a tenant's. Data is either (ADR 0006, "Data keys").
func tenantFits(purpose, tenant string) bool {
	switch purpose {
	case "cookie", "grant":
		return tenant == ""
	case "evidence":
		return tenant != ""
	}
	return true
}

// needsGrant says whether a call needs a grant (D-5): a tenant purpose on a tenant address. The boundary
// purposes are checked by rule only.
func needsGrant(purpose, tenant string) bool {
	return tenant != "" && (purpose == "data" || purpose == "evidence")
}

// addressOf validates the address of a request and returns its tenant ("" for none) and the form the envelope is
// bound to.
func (s *Server) addressOf(a *typev2alpha1.Address) (string, envelope.Address, bool) {
	if a == nil || a.GetTenant() == store.NoTenant {
		return "", envelope.Address{}, false
	}
	text := a.GetTenant()
	if text == "" {
		text = envelope.NoTenant
	}
	if err := store.ValidateAddress(s.cfg.Boundary, text, a.GetKind(), a.GetId()); err != nil {
		return "", envelope.Address{}, false
	}
	return a.GetTenant(), envelope.Address{Boundary: s.cfg.Boundary, Tenant: text, Kind: a.GetKind(), ID: a.GetId()}, true
}

// keyFailure turns the error of a key lookup into the refusal of a call. forOpen: a key that is not there means
// the value cannot open, which is the one answer for every cause.
func (s *Server) keyFailure(ctx context.Context, caller, op, purpose, tenant string, err error, forOpen bool) error {
	var ce *connect.Error
	switch {
	case errors.As(err, &ce):
		return ce
	case errors.Is(err, envelope.ErrOpen), errors.Is(err, errNoKey) && forOpen:
		return s.refuse(ctx, caller, op, purpose, tenant, connect.CodePermissionDenied, reasonOpen, "")
	case errors.Is(err, errNotWrapped):
		return unavailable(reasonWrap)
	}
	slog.Error("data key failure", "op", op, "purpose", purpose, "err", err)
	return refusal.New(connect.CodeInternal, reasonWrap, "")
}

// Seal seals a value under the data key of the purpose (ADR 0006, "Seal and open"). Three checks, in order: the
// caller from the transport, the caller's rule from the registry, and the grant where D-5 requires one.
func (s *Server) Seal(ctx context.Context, req *connect.Request[keyv2alpha1.SealRequest]) (*connect.Response[keyv2alpha1.SealResponse], error) {
	m := req.Msg
	caller, err := s.callerOf(ctx, "seal")
	if err != nil {
		return nil, err
	}
	code, ok := sealable(m.GetPurpose())
	if !ok {
		return nil, s.refuse(ctx, caller, "seal", m.GetPurpose(), "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if !registry.KeyAllows(caller, m.GetPurpose(), "seal") {
		return nil, s.refuse(ctx, caller, "seal", m.GetPurpose(), "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	tenant, addr, ok := s.addressOf(m.GetAddress())
	if !ok {
		return nil, s.refuse(ctx, caller, "seal", m.GetPurpose(), "", connect.CodeInvalidArgument, reasonAddress, "address")
	}
	if !tenantFits(m.GetPurpose(), tenant) {
		return nil, s.refuse(ctx, caller, "seal", m.GetPurpose(), "", connect.CodeInvalidArgument, reasonTenant, "address.tenant")
	}
	if needsGrant(m.GetPurpose(), tenant) {
		if err := s.checkGrant(ctx, newGrantState(m.GetGrant()), caller, "seal", m.GetPurpose(), tenant); err != nil {
			return nil, err
		}
	}
	var env []byte
	err = s.withKey(ctx, keyRef{tenant, m.GetPurpose(), sealGeneration}, true, func(key []byte) error {
		var e error
		env, e = envelope.Seal(key, code, sealGeneration, addr, m.GetPlaintext())
		return e
	})
	if err != nil {
		return nil, s.keyFailure(ctx, caller, "seal", m.GetPurpose(), tenant, err, false)
	}
	return connect.NewResponse(&keyv2alpha1.SealResponse{Envelope: env}), nil
}

// opening is one item of an Open that passed its checks.
type opening struct {
	ref  keyRef
	addr envelope.Address
	env  []byte
}

// Open opens a batch of envelopes, all or none, with the checks of Seal per item (the operation is "open"). The
// generation comes from the envelope, so an older generation still opens. Every failure to open is the one
// refusal permission_denied/open: it says nothing about which part failed.
func (s *Server) Open(ctx context.Context, req *connect.Request[keyv2alpha1.OpenRequest]) (*connect.Response[keyv2alpha1.OpenResponse], error) {
	m := req.Msg
	caller, err := s.callerOf(ctx, "open")
	if err != nil {
		return nil, err
	}
	if n := len(m.GetItems()); n == 0 || n > maxOpenItems {
		return nil, s.refuse(ctx, caller, "open", "", "", connect.CodeInvalidArgument, reasonItems, "items")
	}
	grant := newGrantState(m.GetGrant())
	jobs := make([]opening, 0, len(m.GetItems()))
	for _, it := range m.GetItems() {
		purpose := it.GetPurpose()
		code, ok := sealable(purpose)
		if !ok {
			return nil, s.refuse(ctx, caller, "open", purpose, "", connect.CodeInvalidArgument, reasonPurpose, "items.purpose")
		}
		if !registry.KeyAllows(caller, purpose, "open") {
			return nil, s.refuse(ctx, caller, "open", purpose, "", connect.CodePermissionDenied, reasonRule, "items.purpose")
		}
		tenant, addr, ok := s.addressOf(it.GetAddress())
		if !ok {
			return nil, s.refuse(ctx, caller, "open", purpose, "", connect.CodeInvalidArgument, reasonAddress, "items.address")
		}
		if !tenantFits(purpose, tenant) {
			return nil, s.refuse(ctx, caller, "open", purpose, "", connect.CodeInvalidArgument, reasonTenant, "items.address.tenant")
		}
		if needsGrant(purpose, tenant) {
			if err := s.checkGrant(ctx, grant, caller, "open", purpose, tenant); err != nil {
				return nil, err
			}
		}
		h, err := envelope.ParseHeader(it.GetEnvelope())
		if err != nil || h.Purpose != code {
			return nil, s.refuse(ctx, caller, "open", purpose, tenant, connect.CodePermissionDenied, reasonOpen, "")
		}
		jobs = append(jobs, opening{ref: keyRef{tenant, purpose, h.Generation}, addr: addr, env: it.GetEnvelope()})
	}
	plaintexts := make([][]byte, 0, len(jobs))
	for _, j := range jobs {
		var pt []byte
		err := s.withKey(ctx, j.ref, false, func(key []byte) error {
			var e error
			pt, e = envelope.Open(key, j.env, j.addr)
			return e
		})
		if err != nil {
			for _, p := range plaintexts {
				clear(p)
			}
			return nil, s.keyFailure(ctx, caller, "open", j.ref.purpose, j.ref.tenant, err, true)
		}
		plaintexts = append(plaintexts, pt)
	}
	return connect.NewResponse(&keyv2alpha1.OpenResponse{Plaintexts: plaintexts}), nil
}
