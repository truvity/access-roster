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

	h.catchUp(ctx)

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

// catchUp refreshes what is ALREADY stale, before the first tick.
//
// A ticker's first tick is a whole interval away, so a process that
// starts serves whatever the last one left for fifteen minutes — and a
// deployment rolling more often than that never reaches a tick at all.
// The stored snapshot then ages past the freshness window and every
// domain reads as *provisional*, which is a release cadence showing up
// to an operator as a loss of authority. Seen exactly that way on
// 2026-09-10, across an afternoon of pinning releases.
//
// Only what is already stale. A snapshot taken four minutes ago by the
// process this one replaced is fine, and re-reading it would spend
// somebody's API quota to learn nothing — Google's is per tenant, not
// per reader. The lease in refreshOne still applies, so replicas
// starting together still read once between them.
func (h *Hub) catchUp(ctx context.Context) {
	workspaces, err := h.store.List(ctx)
	if err != nil {
		h.log.WarnContext(ctx, "start-up refresh could not list workspaces", "error", err)

		return
	}

	now := time.Now()

	for i := range workspaces {
		id := workspaces[i].ID

		snap, err := h.snapshots.Get(ctx, id)
		if err != nil {
			h.log.WarnContext(ctx, "start-up refresh could not read the snapshot",
				"workspace", id, "error", err)

			continue
		}

		// Due, not merely STALE. Waiting for the freshness window leaves
		// a snapshot that is already older than the interval to sit until
		// this process's first tick, a whole interval later — so a
		// fourteen-minute-old snapshot on a pod that has just replaced
		// another is not read again until it is twenty-nine minutes old,
		// one rollout away from provisional. The schedule says fifteen
		// minutes; a restart should not extend it.
		if snap != nil && snap.Age(now) < h.cfg.RefreshInterval {
			continue
		}

		// `snap` is nil on a workspace that has never been read, which is
		// day one — and Age would dereference it.
		age := "never read"
		if snap != nil {
			age = snap.Age(now).String()
		}

		h.log.InfoContext(ctx, "the stored snapshot is due at start; refreshing now",
			"workspace", id, "age", age)
		h.refreshOne(ctx, id)
	}
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

// leaseFor is how long a successful pass keeps other replicas off a
// workspace: most of the interval, and deliberately NOT all of it.
//
// Holding it for the whole interval is what made two directories read
// *provisional · stale* on 2026-09-11. The lease and the ticker were the
// same length, so they beat against each other: a tick arriving a second
// before its predecessor's lease expired was refused, and the next
// chance came a whole interval later. The effective period doubled to
// thirty minutes, which is exactly the freshness window — so the
// snapshot aged out and every domain in it lost authority, on a service
// that was working perfectly.
//
// A quarter is margin enough. A replica whose turn comes four minutes
// after another is still refused, which is the point of the lease; a
// replica ticking ON SCHEDULE always finds it expired, which is the
// point of the schedule.
func leaseFor(interval time.Duration) time.Duration {
	return interval - interval/4
}

// refreshOne refreshes a workspace unless another replica has already
// done it this interval.
//
// The lease is held for most of the interval, not for the work. Replicas
// do not tick together: if it were let go the moment a refresh finished,
// the replica whose turn came four minutes later would take it and read
// the same directory again. So a successful pass leaves the lease to
// expire on its own, and only a failed one hands it straight back —
// because then somebody else should try, and a stale snapshot is exactly
// what the freshness window is for.
func (h *Hub) refreshOne(ctx context.Context, id string) {
	var release func(context.Context)
	if locker, shared := h.snapshots.(Locker); shared {
		taken, acquired, err := locker.Lock(ctx, "refresh:"+id, leaseFor(h.cfg.RefreshInterval))
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
