package app

import "time"

// CappedSessionLifetimeForTest exposes cappedSessionLifetime to
// internal/app_test, following the export_test.go idiom the issuer
// package already uses (see internal/issuer/export_service_test.go):
// the black-box tests exercise the package through its real API
// everywhere else, and this is the one calculation with no API of its
// own to call through.
func CappedSessionLifetimeForTest(session, absolute time.Duration) time.Duration {
	return cappedSessionLifetime(session, absolute)
}
