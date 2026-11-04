package minter

import (
	"context"
	"time"
)

// TestOnlyTrack records an id as if it had been minted as the preset's stored
// token (with no caller).
func (m *Minter) TestOnlyTrack(ctx context.Context, preset, id string, expires time.Time) error {
	return m.track(ctx, preset, id, "", expires)
}

// TestOnlySleep replaces how the minter waits: the hold of a rotated R2
// credential and the propagation of an on-demand one.
func (m *Minter) TestOnlySleep(f func(ctx context.Context, d time.Duration) error) {
	m.sleep = f
}
