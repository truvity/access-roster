package hub

import "context"

// RefreshAll runs one scheduled refresh pass. The pass is what takes the
// shared lease, so a test of "one replica reads, the others do not" has
// to drive it rather than the ticker that normally does.
func (h *Hub) RefreshAll(ctx context.Context) { h.refreshAll(ctx) }
