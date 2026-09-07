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
// one. Across replicas the shared snapshot store carries the lock, so that
// the backend is read once per interval however many replicas are running;
// the in-memory store has no such lock and is therefore for development
// and a single replica only.
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

// refreshAll takes a new snapshot of every workspace. A workspace that
// fails keeps the snapshot it has: nothing partial is ever stored, and the
// staleness shows up as a loss of authority rather than as an outage.
func (h *Hub) refreshAll(ctx context.Context) {
	workspaces, err := h.store.List(ctx)
	if err != nil {
		h.log.WarnContext(ctx, "refresh pass could not list workspaces", "error", err)
		return
	}
	for i := range workspaces {
		id := workspaces[i].ID
		if _, err = h.Refresh(ctx, id); err != nil {
			h.log.WarnContext(ctx, "refresh failed", "workspace", id, "error", err)
		}
	}
}
