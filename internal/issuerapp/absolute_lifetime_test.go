package issuerapp

import (
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/config"
)

// lifetimes.absolute is refused, not defaulted, when it is set to
// something that could never bound a session: zero, negative, or shorter
// than lifetimes.token, which would mint a token already past the one
// limit it exists to outlive. lifetimes.token and lifetimes.refresh treat
// an unset (zero) value as "use the default" -- this is the one lifetime
// where zero is a deployment saying something specific and wrong, so it
// is caught here rather than silently becoming 24h.
func TestAbsoluteLifetimeIsRefused(t *testing.T) {
	d := func(v time.Duration) *config.Duration { c := config.Duration(v); return &c }
	for _, tc := range []struct {
		name      string
		token     *config.Duration
		absolute  *config.Duration
		wantError bool
	}{
		{"the default is left alone", nil, nil, false},
		{"a generous override is fine", d(time.Hour), d(48 * time.Hour), false},
		{"equal to the token lifetime is fine: a token can live exactly to the limit", d(time.Hour), d(time.Hour), false},
		{"zero is refused: a session cannot end before it begins", d(time.Hour), d(0), true},
		{"negative is refused the same way", d(time.Hour), d(-time.Hour), true},
		{"shorter than the token lifetime is refused", d(2 * time.Hour), d(time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromConfig(&config.Issuer{
				IssuerURL: "https://issuer.example",
				Lifetimes: &config.Lifetimes{Token: tc.token, Absolute: tc.absolute},
			})
			if tc.wantError && err == nil {
				t.Errorf("FromConfig() succeeded, want a refusal")
			}
			if !tc.wantError && err != nil {
				t.Errorf("FromConfig(): %v, want it to succeed", err)
			}
		})
	}
}

// Unset, lifetimes.absolute is 24 hours, wired into the issuer's config --
// the default this setting exists to change, and the value every
// existing deployment gets without touching a chart.
func TestAbsoluteLifetimeDefaultsToTwentyFourHours(t *testing.T) {
	cfg, err := FromConfig(&config.Issuer{IssuerURL: "https://issuer.example"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.absoluteLifetime != 24*time.Hour {
		t.Errorf("absoluteLifetime = %s, want 24h", cfg.absoluteLifetime)
	}
}
