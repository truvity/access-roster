package hub

import (
	"context"
	"time"
)

// Run drives the two background loops until ctx is done: a refresher that
// replaces each workspace's snapshot every RefreshInterval, and a prober
// that exercises each credential and re-reads its domain list every
// ProbeInterval.
//
// Within one process, concurrent refreshes of a workspace collapse into
// one. Across replicas the shared snapshot store carries a lease held for
// the whole interval, so that the backend is read once per interval
// however many replicas are running; the in-memory store has no lease and
// is therefore for development and a single replica only.
//
// Neither applies to a refresh somebody asked for. An operator pressing
// Refresh, or a caller passing max_age=0, is asking for a read now.
func (h *Hub) Run(ctx context.Context) error {
	refresh := time.NewTicker(h.cfg.RefreshInterval)
	defer refresh.Stop()
	probe := time.NewTicker(h.cfg.ProbeInterval)
	defer probe.Stop()

	h.log.InfoContext(ctx, "background loops started",
		"refresh", h.cfg.RefreshInterval, "probe", h.cfg.ProbeInterval, "freshness", h.cfg.FreshnessWindow)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-refresh.C:
			h.refreshAll(ctx)
		case <-probe.C:
			if _, err := h.Probe(ctx, ""); err != nil {
				h.log.WarnContext(ctx, "probe pass failed", "error", err)
			}
		}
	}
}

// Locker is a snapshot store that can also hold a short lease shared by
// every replica. A store that cannot — the in-memory one — simply does
// not implement it, and each process refreshes on its own, which is
// correct for one replica and wasteful for more.
type Locker interface {
	// Lock takes the lease for key, for at most ttl. It returns whether
	// the lease was taken and a release to call when the work is done;
	// release is safe to call on a lease that has already expired.
	Lock(ctx context.Context, key string, ttl time.Duration) (release func(context.Context), acquired bool, err error)
}

// refreshAll takes a new snapshot of every workspace. A workspace that
// fails keeps the snapshot it has: nothing partial is ever stored, and the
// staleness shows up as a loss of authority rather than as an outage.
//
// One replica does the reading. The snapshot is shared, so a second
// replica reading the same directory at the same moment buys nothing and
// costs a second helping of somebody's API quota — and Google's is per
// tenant, not per reader. The lease is held only for the scheduled pass:
// an operator pressing Refresh, or a caller asking for max_age=0, is
// asking for a read *now* and gets one.
func (h *Hub) refreshAll(ctx context.Context) {
	workspaces, err := h.store.List(ctx)
	if err != nil {
		h.log.WarnContext(ctx, "refresh pass could not list workspaces", "error", err)
		return
	}
	for i := range workspaces {
		h.refreshOne(ctx, workspaces[i].ID)
	}
}

// refreshOne refreshes a workspace unless another replica has already
// done it this interval.
//
// The lease is held for the interval, not for the work, and this is the
// whole of why it works. Replicas do not tick together: if the lease were
// let go the moment a refresh finished, the replica whose turn came four
// minutes later would take it and read the same directory again. So a
// successful pass leaves the lease to expire on its own, and only a
// failed one hands it straight back — because then somebody else should
// try, and a stale snapshot is exactly what the freshness window is for.
func (h *Hub) refreshOne(ctx context.Context, id string) {
	var release func(context.Context)
	if locker, shared := h.snapshots.(Locker); shared {
		taken, acquired, err := locker.Lock(ctx, "refresh:"+id, h.cfg.RefreshInterval)
		switch {
		case err != nil:
			// The lease could neither be taken nor refused. Refreshing
			// anyway is the safe way to be wrong: a duplicate read costs
			// quota, a skipped one costs freshness, and freshness is what
			// authority is made of.
			h.log.WarnContext(ctx, "refresh lease unavailable; refreshing anyway",
				"workspace", id, "error", err)
		case !acquired:
			return
		default:
			release = taken
		}
	}
	if _, err := h.Refresh(ctx, id); err != nil {
		h.log.WarnContext(ctx, "refresh failed", "workspace", id, "error", err)
		if release != nil {
			release(ctx)
		}
	}
}
