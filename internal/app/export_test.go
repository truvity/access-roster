package app

import (
	"context"
	"time"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/server"
)

// CappedSessionLifetimeForTest exposes cappedSessionLifetime to
// internal/app_test, following the export_test.go idiom the issuer
// package already uses (see internal/issuer/export_service_test.go):
// the black-box tests exercise the package through its real API
// everywhere else, and this is the one calculation with no API of its
// own to call through.
func CappedSessionLifetimeForTest(session, absolute time.Duration) time.Duration {
	return cappedSessionLifetime(session, absolute)
}

// OpenStoredForTest exposes openStored to internal/app_test, the same
// idiom: it is only ever wired in as a hub.Reopener, so there is no real
// API of its own for a black-box test to call through.
func OpenStoredForTest(
	ctx context.Context, connectors []server.Connector, kind string, cred backend.Credential,
) (backend.Backend, error) {
	return openStored(ctx, connectors, kind, cred)
}
