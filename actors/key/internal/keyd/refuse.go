package keyd

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// The reasons key@ refuses with. The list is closed; a reason names the rule and never a value
// (docs/reference/contracts.md, "Errors").
const (
	reasonRule                 = "rule"                  // permission_denied: no rule of the registry allows the caller this purpose and operation
	reasonGrant                = "grant"                 // permission_denied: the grant is missing, unreadable, for another holder, tenant or operation, or expired
	reasonOpen                 = "open"                  // permission_denied: the envelope does not open (one reason for every cause)
	reasonCaller               = "caller"                // permission_denied: the transport named no caller
	reasonPurpose              = "purpose"               // invalid_argument: a purpose this call does not take, or one the plan does not enable
	reasonAddress              = "address"               // invalid_argument
	reasonTenant               = "tenant"                // invalid_argument: a tenant that does not fit the purpose
	reasonItems                = "items"                 // invalid_argument: no items, or more than 64
	reasonAlgorithm            = "algorithm"             // invalid_argument
	reasonContent              = "content"               // invalid_argument: the content is not what the purpose signs
	reasonLabel                = "label"                 // invalid_argument
	reasonEpoch                = "epoch"                 // invalid_argument
	reasonSchema               = "schema"                // invalid_argument: a request field is missing or malformed
	reasonExpired              = "expired"               // failed_precondition: the grant is past its expiry
	reasonRate                 = "rate"                  // resource_exhausted
	reasonStore                = "store"                 // unavailable: store@ failed
	reasonDriver               = "driver"                // unavailable: the key-store driver failed
	reasonAudit                = "audit"                 // unavailable: the audit fact of a signature could not be made durable
	reasonRevoked              = "revoked"               // permission_denied: the key is listed in KeyRevocation and signs nothing more (revocation.go)
	reasonRevocationUnreadable = "revocation-unreadable" // unavailable: KeyRevocation could not be read, so a Sign cannot be shown allowed
	reasonWrap                 = "wrap"                  // unavailable: the data key exists but this node holds no wrap of it yet
	// The reasons of a key revocation declaration (declaration.go).
	reasonDeclaration   = "declaration"    // permission_denied: not a declaration that a pinned publisher key signed
	reasonSeq           = "seq"            // failed_precondition: a seq below the highest declaration taken, or equal to it with another payload
	reasonOtherBoundary = "other-boundary" // permission_denied: the declaration is for another boundary
	reasonUnknownKid    = "unknown-kid"    // failed_precondition: a kid no source of key@ knows, in a declaration that does not allow it
	reasonState         = "state"          // unavailable: the mark of the declaration could not be saved in the state directory
	reasonPartial       = "partial"        // unavailable: a store@ failure stopped a taken declaration half way; deliver it again
	reasonWrappingKey   = "wrapping-key"   // failed_precondition: a kid is a wrapping key, which a declaration of signing keys never revokes
)

// refuse audits a refusal and returns it. The audit fact carries the caller, the operation, the purpose, the
// tenant and the reason, never a value.
func (s *Server) refuse(ctx context.Context, caller, op, purpose, tenant string, code connect.Code, reason, path string) error {
	purpose, tenant = safeName(purpose), safeName(tenant)
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

// procedureOps maps the full procedure name of each KeyService method to the operation name an audit fact carries. The
// procedure of a refused call is whatever the caller sent, and the guard refuses before it is checked: a fact with a path
// of 1 MiB, with bad UTF-8 or with a character the emitter rejects would be refused by the emitter and the refusal would
// leave no trace. A procedure outside this set is the operation "unknown".
var procedureOps = func() map[string]string {
	out := map[string]string{}
	sd := keyv2alpha1.File_sluis_key_v2alpha1_key_proto.Services().ByName("KeyService")
	for i := range sd.Methods().Len() {
		m := sd.Methods().Get(i)
		out["/"+string(sd.FullName())+"/"+string(m.Name())] = string(m.Name())
	}
	return out
}()

// opOf is the operation of a procedure a caller named, from the closed set, or "unknown".
func opOf(procedure string) string {
	if op, ok := procedureOps[procedure]; ok {
		return op
	}
	return "unknown"
}

// safeName is a purpose or a tenant as an audit fact may carry it: at most 64 bytes of lower-case letters, digits and the
// signs - _ . : *; anything else is the word "invalid". A caller chooses these strings before key@ has decided whether
// they are valid, and a refusal of a call with a long or odd one must still be a fact.
func safeName(v string) string {
	if len(v) > 64 {
		return "invalid"
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == ':', r == '*':
		default:
			return "invalid"
		}
	}
	return v
}

// auditTransportRefusal makes the audit fact of a call that the transport refused before any handler: a peer whose uid
// is not the caller of the socket it connected to (reason call_graph), or a peer the registry does not know or of another
// boundary (reason caller). The fact names the socket's caller, the peer as the transport read it and the operation, and
// no payload: the message was not read. The transport rate limits the hook (rpc.ServerConfig.OnRefused): past a burst
// per peer and reason, one fact at the end of the window carries the number folded in "suppressed". Every string in it
// is from a closed set or a number: the operation (opOf), the reason, the registry's name of the peer and of the socket;
// the uid of a peer the registry does not know is -1, since 0 would read as root.
func (s *Server) auditTransportRefusal(ctx context.Context, socket string, r rpc.Refused) {
	uid := int64(-1)
	if r.Known {
		uid = int64(r.Peer.UID)
	}
	fields := map[string]any{"caller": r.Peer.Name, "socket": socket, "uid": uid, "op": opOf(r.Procedure), "purpose": "",
		"code": connect.CodePermissionDenied.String(), "path": ""}
	if r.Suppressed > 0 {
		fields["op"] = ""
		fields["suppressed"] = int64(r.Suppressed)
		fields["window_s"] = int64(r.Window / time.Second)
	}
	slog.Info("refused", "caller", r.Peer.Name, "socket", socket, "op", fields["op"], "code", connect.CodePermissionDenied.String(), "reason", r.Reason, "suppressed", r.Suppressed)
	s.audit(ctx, Event{Action: ActionRefuse, Failure: true, Reason: r.Reason, Fields: fields})
}
