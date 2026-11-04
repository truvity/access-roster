package keyd

import (
	"context"
	"log/slog"
	"time"
)

// The actions key@ audits (ADR 0006: "Every signature is rate-limited and is an audit fact"; "A refusal is an audit
// fact"). The names are the metadata.event_code of the record.
const (
	ActionStart       = "key.start"
	ActionRefuse      = "key.refuse"
	ActionDataKeyMake = "key.data_key.make"
	ActionWrapWrite   = "key.wrap.write" //nolint:gosec // G101: an action name, not a credential
	ActionSign        = "key.sign"
)

// Event is one audit fact of key@. Fields hold names, counts and ids, never a key, a plaintext, a grant or an
// envelope.
type Event struct {
	Action  string
	Failure bool
	Reason  string // a closed reason, set on a refusal
	Tenant  string // "" for a boundary purpose
	Fields  map[string]any
}

// Auditor is where key@ sends its audit facts. The emitter library of the audit package satisfies it through a
// small adapter. An emit failure is logged by key@ and never changes the outcome of a call.
type Auditor interface {
	Emit(ctx context.Context, ev Event) error
}

// auditTimeout bounds one emit: a slow transport must not hold a seal or an open.
const auditTimeout = 2 * time.Second

// audit sends the event and logs a failure. It never returns one: an emit failure neither makes a call succeed
// nor fail.
func (s *Server) audit(ctx context.Context, ev Event) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := s.cfg.Auditor.Emit(ctx, ev); err != nil {
		slog.Warn("audit emit failed", "action", ev.Action, "err", err)
	}
}
