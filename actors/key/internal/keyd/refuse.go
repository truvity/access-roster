package keyd

import (
	"context"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
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
	// reasonUndecodable is a request that an allowed caller sent and Connect could not decode (undecodable.go).
	reasonUndecodable = "undecodable"
)

// refusal1 is a refusal of a handler as the limiter holds it. ctx is the request's, for the correlation id the fact carries
// (the fact is made on the request's goroutine); a summary has none.
type refusal1 struct {
	ctx                                             context.Context //nolint:containedctx // carried to the audit call made in the same Note
	caller, op, purpose, tenant, code, reason, path string
}

// refusalFields is the members of a key.refuse fact for a refusal, without the names that are empty. The table of facts
// (audit-actions.yaml) takes a caller, an operation, a purpose, a code or a socket only as a non-empty word, so one that is
// empty is left out and not sent as "". A path is text and may be empty.
func refusalFields(m map[string]any) map[string]any {
	for _, k := range []string{"caller", "op", "purpose", "code", "socket"} {
		if v, ok := m[k].(string); ok && v == "" {
			delete(m, k)
		}
	}
	return m
}

// adminCaller is the name the declarations on the root-only socket are refused under.
const adminCaller = "admin"

// refusalLimiters are the limiters of the handlers' refusals, one for each caller (and one for "admin", the root-only
// socket's declarations), made when the caller first has a refusal. One limiter for all callers would let a caller that
// reaches the total of an hour with a few reasons take the detail and the attribution from every other caller's refusals for
// the rest of the hour, which is when a second compromised actor must be seen; with one each, a caller can starve only
// itself. A name that is not a caller of the registry (the empty name of a peer the transport did not name) shares one.
type refusalLimiters struct {
	s  *Server
	mu sync.Mutex
	m  map[string]*rpc.Limiter
}

func (s *Server) newRefusalLimiters() *refusalLimiters {
	return &refusalLimiters{s: s, m: map[string]*rpc.Limiter{}}
}

// get is the limiter of a caller.
func (r *refusalLimiters) get(caller string) *rpc.Limiter {
	if caller != adminCaller && !slices.Contains(registry.CallersOf("key"), caller) {
		caller = ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	l := r.m[caller]
	if l == nil {
		l = r.s.newRefusalLimiter()
		r.m[caller] = l
	}
	return l
}

// close reports what every limiter still counts.
func (r *refusalLimiters) close() {
	r.mu.Lock()
	all := make([]*rpc.Limiter, 0, len(r.m))
	for _, l := range r.m {
		all = append(all, l)
	}
	r.mu.Unlock()
	for _, l := range all {
		l.Close()
	}
}

// newRefusalLimiter makes the limiter of one caller's refusals. A caller that holds a socket of its own can ask for what it
// has no rule for as often as it likes, and one fact for each would fill the shared spool and stop every signature, whose own
// fact must be durable. So, for each caller and reason, the first RefusalBurst refusals of a window are facts and the rest are
// one summary with their number (rpc.Limiter), with the caps of an hour of ADR 0005. The facts are made on the caller's
// goroutine, as before; a summary is made on the limiter's.
func (s *Server) newRefusalLimiter() *rpc.Limiter {
	return rpc.NewLimiter(rpc.LimiterConfig{Burst: s.cfg.RefusalBurst, Window: s.cfg.RefusalWindow, Hourly: s.cfg.RefusalHourly, Total: s.cfg.RefusalTotal},
		func(v any) {
			r := v.(refusal1)
			slog.Info("refused", "caller", r.caller, "op", r.op, "purpose", r.purpose, "code", r.code, "reason", r.reason, "path", r.path)
			s.audit(r.ctx, Event{
				Action: ActionRefuse, Failure: true, Reason: r.reason, Tenant: r.tenant,
				Fields: refusalFields(map[string]any{"caller": r.caller, "op": r.op, "purpose": r.purpose, "code": r.code, "path": r.path}),
			})
		},
		func(v any, f rpc.Fold) {
			r := v.(refusal1)
			fields := map[string]any{"caller": r.caller, "op": r.op, "code": r.code,
				"suppressed": int64(f.Suppressed), "window_s": int64(f.Window / time.Second)}
			if f.Overflow {
				delete(fields, "caller")
				delete(fields, "op")
				delete(fields, "code")
				fields["overflow"] = true
			}
			slog.Info("refusals folded", "caller", fields["caller"], "op", fields["op"], "reason", r.reason, "suppressed", f.Suppressed)
			s.audit(context.Background(), Event{Action: ActionRefuse, Failure: true, Reason: r.reason, Fields: refusalFields(fields)})
		})
}

// refuse audits a refusal and returns it. The audit fact carries the caller, the operation, the purpose, the
// tenant and the reason, never a value. It is rate limited per caller and reason (newRefusalLimiter); the refusal is
// answered whatever happens to its fact.
func (s *Server) refuse(ctx context.Context, caller, op, purpose, tenant string, code connect.Code, reason, path string) error {
	s.refusals.Load().get(caller).Note(reason, refusal1{ctx: ctx, caller: caller, op: op, purpose: safeName(purpose), tenant: safeTenant(tenant),
		code: code.String(), reason: reason, path: path})
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

// procedureOps maps the full procedure name of each KeyService method to the operation name an audit fact carries, in the
// words the handlers use ("seal", "public-key", "seal-grant"). The procedure of a refused call is whatever the caller sent,
// and the guard refuses before it is checked: a fact with a path of 64 KiB, with bad UTF-8 or with a character the table
// rejects would be refused by the emitter and the refusal would leave no trace. A procedure outside this set is the
// operation "unknown".
var procedureOps = func() map[string]string {
	out := map[string]string{}
	sd := keyv2alpha1.File_sluis_key_v2alpha1_key_proto.Services().ByName("KeyService")
	for i := range sd.Methods().Len() {
		m := sd.Methods().Get(i)
		name := regexp.MustCompile(`([a-z])([A-Z])`).ReplaceAllString(string(m.Name()), "${1}-${2}")
		out["/"+string(sd.FullName())+"/"+string(m.Name())] = strings.ToLower(name)
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

// safeName is a purpose as an audit fact may carry it: at most 64 bytes of lower-case letters, digits and the signs - _ . :,
// starting with a letter or a digit (the type "ident" of the action table); anything else is the word "invalid". A caller
// chooses these strings before key@ has decided whether they are valid, and a refusal of a call with a long or odd one must
// still be a fact.
func safeName(v string) string {
	return safeWord(v, "-_.:")
}

// safeTenant is the same for a tenant id (the type "tenant" of the table): letters, digits and - _ ., or "*".
func safeTenant(v string) string {
	if v == "*" {
		return v
	}
	return safeWord(v, "-_.")
}

func safeWord(v, signs string) string {
	if v == "" {
		return v
	}
	if len(v) > 64 {
		return "invalid"
	}
	for i, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && strings.ContainsRune(signs, r):
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
	fields := map[string]any{"caller": r.Peer.Name, "socket": socket, "uid": uid, "op": opOf(r.Procedure),
		"code": connect.CodePermissionDenied.String()}
	if r.Overflow {
		// The summary of every peer past the bound of counted peers (or past the total of the hour) names nobody.
		delete(fields, "caller")
		fields["uid"], fields["overflow"] = int64(-1), true
	}
	if r.Suppressed > 0 {
		delete(fields, "op")
		fields["suppressed"] = int64(r.Suppressed)
		fields["window_s"] = int64(r.Window / time.Second)
	}
	slog.Info("refused", "caller", r.Peer.Name, "socket", socket, "op", fields["op"], "code", connect.CodePermissionDenied.String(), "reason", r.Reason, "suppressed", r.Suppressed)
	s.audit(ctx, Event{Action: ActionRefuse, Failure: true, Reason: r.Reason, Fields: refusalFields(fields)})
}
