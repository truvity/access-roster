package cloudflare

import (
	"context"
	"time"
)

// SetSleep replaces how a [StoredProvider] waits, for a test's clock.
func SetSleep(p *StoredProvider, f func(ctx context.Context, d time.Duration) error) { p.sleep = f }
