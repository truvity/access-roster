package app_test

import (
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/app"
)

// The console's own session cookie is issued once, at sign-in, with a
// fixed expiry that never slides -- so capping it at the absolute session
// limit is exactly capping the lifetime it is issued for. This is a
// mutation-minded test: with the cap removed (returning `session`
// unconditionally), the second case below fails.
func TestCappedSessionLifetime(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                    string
		session, absolute, want time.Duration
	}{
		{"the ordinary case: the configured session outlasts nothing shorter",
			12 * time.Hour, 24 * time.Hour, 12 * time.Hour},
		{"the absolute limit binds: a session cookie longer than it is cut down",
			30 * time.Hour, 24 * time.Hour, 24 * time.Hour},
		{"equal: either answer is correct, and the shorter path is taken",
			24 * time.Hour, 24 * time.Hour, 24 * time.Hour},
		{"no limit configured: the session's own lifetime stands",
			12 * time.Hour, 0, 12 * time.Hour},
		{"a negative limit is treated as none, the same as zero",
			12 * time.Hour, -time.Hour, 12 * time.Hour},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			if got := app.CappedSessionLifetimeForTest(c.session, c.absolute); got != c.want {
				t.Errorf("cappedSessionLifetime(%s, %s) = %s, want %s", c.session, c.absolute, got, c.want)
			}
		})
	}
}
