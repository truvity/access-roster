package issuerapp

import (
	"testing"
	"time"
)

// ABSOLUTE_LIFETIME is refused, not defaulted, when it is set to
// something that could never bound a session: zero, negative, or shorter
// than TOKEN_LIFETIME, which would mint a token already past the one
// limit it exists to outlive. TOKEN_LIFETIME and REFRESH_LIFETIME treat
// an unset (zero) value as "use the default" -- this is the one lifetime
// where zero is a deployment saying something specific and wrong, so it
// is caught here rather than silently becoming 24h.
func TestAbsoluteLifetimeIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		token     string
		absolute  string
		wantError bool
	}{
		{"the default is left alone", "", "", false},
		{"a generous override is fine", "1h", "48h", false},
		{"equal to the token lifetime is fine: a token can live exactly to the limit", "1h", "1h", false},
		{"zero is refused: a session cannot end before it begins", "1h", "0", true},
		{"negative is refused the same way", "1h", "-1h", true},
		{"shorter than the token lifetime is refused", "2h", "1h", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ISSUER_URL", "https://issuer.example")
			if tc.token != "" {
				t.Setenv("TOKEN_LIFETIME", tc.token)
			}
			if tc.absolute != "" {
				t.Setenv("ABSOLUTE_LIFETIME", tc.absolute)
			}

			_, err := Load()
			if tc.wantError && err == nil {
				t.Errorf("Load() succeeded, want a refusal")
			}
			if !tc.wantError && err != nil {
				t.Errorf("Load(): %v, want it to succeed", err)
			}
		})
	}
}

// Unset, ABSOLUTE_LIFETIME is 24 hours, wired into the issuer's config --
// the default this setting exists to change, and the value every
// existing deployment gets without touching a chart.
func TestAbsoluteLifetimeDefaultsToTwentyFourHours(t *testing.T) {
	t.Setenv("ISSUER_URL", "https://issuer.example")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.absoluteLifetime != 24*time.Hour {
		t.Errorf("absoluteLifetime = %s, want 24h", cfg.absoluteLifetime)
	}
}
