package keyd

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// The reasons key@ refuses with. The list is closed; a reason names the rule and never a value
// (docs/reference/contracts.md, "Errors").
const (
	reasonRule      = "rule"      // permission_denied: no rule of the registry allows the caller this purpose and operation
	reasonGrant     = "grant"     // permission_denied: the grant is missing, unreadable, for another holder, tenant or operation, or expired
	reasonOpen      = "open"      // permission_denied: the envelope does not open (one reason for every cause)
	reasonCaller    = "caller"    // permission_denied: the transport named no caller
	reasonPurpose   = "purpose"   // invalid_argument: a purpose this call does not take, or one the plan does not enable
	reasonAddress   = "address"   // invalid_argument
	reasonTenant    = "tenant"    // invalid_argument: a tenant that does not fit the purpose
	reasonItems     = "items"     // invalid_argument: no items, or more than 64
	reasonAlgorithm = "algorithm" // invalid_argument
	reasonContent   = "content"   // invalid_argument: the content is not what the purpose signs
	reasonLabel     = "label"     // invalid_argument
	reasonEpoch     = "epoch"     // invalid_argument
	reasonSchema    = "schema"    // invalid_argument: a request field is missing or malformed
	reasonExpired   = "expired"   // failed_precondition: the grant is past its expiry
	reasonRate      = "rate"      // resource_exhausted
	reasonStore     = "store"     // unavailable: store@ failed
	reasonDriver    = "driver"    // unavailable: the key-store driver failed
	reasonAudit     = "audit"     // unavailable: the audit fact of a signature could not be made durable
	reasonWrap      = "wrap"      // unavailable: the data key exists but this node holds no wrap of it yet
)

// refuse audits a refusal and returns it. The audit fact carries the caller, the operation, the purpose, the
// tenant and the reason, never a value.
func (s *Server) refuse(ctx context.Context, caller, op, purpose, tenant string, code connect.Code, reason, path string) error {
	slog.Info("refused", "caller", caller, "op", op, "purpose", purpose, "code", code.String(), "reason", reason, "path", path)
	s.audit(ctx, Event{
		Action: ActionRefuse, Failure: true, Reason: reason, Tenant: tenant,
		Fields: map[string]any{"caller": caller, "op": op, "purpose": purpose, "code": code.String(), "path": path},
	})
	return refusal.New(code, reason, path)
}

// callerOf is the caller of the call, from the transport only.
func (s *Server) callerOf(ctx context.Context, op string) (string, error) {
	p, ok := rpc.PeerFromContext(ctx)
	if !ok || p.Name == "" {
		return "", s.refuse(ctx, "", op, "", "", connect.CodePermissionDenied, reasonCaller, "")
	}
	return p.Name, nil
}

// unavailable is the error of a failed dependency. Its text says which dependency and nothing else.
func unavailable(reason string) error {
	return refusal.New(connect.CodeUnavailable, reason, "")
}
