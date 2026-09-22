package server

import (
	"context"

	"github.com/truvity/audit/record"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
)

// record writes down something done through the console. A console
// assembled without a recorder — a test does it — records nothing, and
// recording must never be the thing to crash.
func (c *Console) record(ctx context.Context, r *record.Record) {
	if c == nil || c.deps.Audit == nil {
		return
	}
	c.deps.Audit.Record(ctx, r)
}

// recordDurable writes it down and answers only once it is kept. It is for
// the recovery sign-in, which does not happen without its record.
func (c *Console) recordDurable(ctx context.Context, r *record.Record) error {
	if c == nil || c.deps.Audit == nil {
		return nil
	}
	return c.deps.Audit.RecordDurable(ctx, r)
}

// actorOf is whoever the console's caller is, as the trail names them.
func actorOf(ctx context.Context) audit.Actor {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return audit.Anonymous()
	}
	return identityActor(id)
}

// identityActor is an identity as the trail names it: a workload by its
// service account, a recovery by the identity it completed as, and a
// person by their address.
func identityActor(id access.Identity) audit.Actor {
	switch {
	case id.Source == access.SourceWorkload:
		return audit.Workload(id.Subject)
	case id.Source == access.SourceRecovery:
		return audit.RecoveryIdentity(id.Who())
	case id.Email != "":
		return audit.Person(id.Email)
	default:
		return audit.Identified(id.Who())
	}
}
