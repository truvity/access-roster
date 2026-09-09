package hub

import (
	"context"
	"time"
)

// RefreshAll runs one scheduled refresh pass. The pass is what takes the
// shared lease, so a test of "one replica reads, the others do not" has
// to drive it rather than the ticker that normally does.
func (h *Hub) RefreshAll(ctx context.Context) { h.refreshAll(ctx) }

// SetProbeBackoff shortens the wait between probe attempts, so a test of
// the retry policy costs no wall clock.
func SetProbeBackoff(d time.Duration) func() {
	previous := probeBackoff
	probeBackoff = d
	return func() { probeBackoff = previous }
}
