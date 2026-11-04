package main

import (
	"context"
	"log/slog"

	"github.com/truvity/sluis/v2/actors/key/internal/keyd"
)

// logAuditor writes each audit fact of key@ to the log: the action, the outcome and the reason, never a field
// value. It stands in until the emitter library of the audit package (WP-10) is wired in, which sends the facts to
// the transport at transportSocket.
type logAuditor struct{ transportSocket string }

func auditor(transportSocket string) keyd.Auditor { return logAuditor{transportSocket} }

func (logAuditor) Emit(_ context.Context, ev keyd.Event) error {
	slog.Info("audit", "action", ev.Action, "failure", ev.Failure, "reason", ev.Reason, "tenant", ev.Tenant)
	return nil
}
