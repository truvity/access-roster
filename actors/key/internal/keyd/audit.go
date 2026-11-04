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
	Reason  string         // a closed reason, set on a refusal
	Tenant  string         // "" for a boundary purpose
	Fields  map[string]any // string, bool, int64, []string and nested maps only
	// Blocking asks for the fact to be durable before Emit returns (0029 "Sealing"). key@ uses it for a
	// signature, and fails the call when the fact is not durable.
	Blocking bool
}

// Auditor is where key@ sends its audit facts; the binary adapts the emitter library (kits/go/audit) to it. A
// fact is emitted once: a second Emit of the same event would carry a new metadata.uid and defeat the writer's
// dedup, so key@ never retries. An emit failure is logged and never changes the outcome of a seal, an open or
// a mac; a signature is the exception (auditBlocking).
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

// auditBlocking sends a fact that must be durable before the call goes on. The caller fails the call when it
// returns an error, so an effect without its audit fact does not happen (ADR 0024, "Every signature is an audit
// fact"; 0029 "Sealing").
func (s *Server) auditBlocking(ctx context.Context, ev Event) error {
	ev.Blocking = true
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := s.cfg.Auditor.Emit(ctx, ev); err != nil {
		slog.Error("blocking audit emit failed", "action", ev.Action, "err", err)
		return err
	}
	return nil
}
