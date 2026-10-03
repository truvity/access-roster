package issuerapp

import (
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/policy"
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
			_, err := FromConfig(&config.Serve{
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
	cfg, err := FromConfig(&config.Serve{IssuerURL: "https://issuer.example"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.absoluteLifetime != 24*time.Hour {
		t.Errorf("absoluteLifetime = %s, want 24h", cfg.absoluteLifetime)
	}
}

// A resource's absolute_cap longer than lifetimes.absolute needs the
// resource to say read_only: policy cannot know the limit, so the issuer
// refuses it at start, before it asks for anything else.
func TestAResourceCapLongerThanTheGlobalLimitNeedsReadOnly(t *testing.T) {
	cfg, err := FromConfig(&config.Serve{IssuerURL: "https://issuer.example"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, tc := range []struct {
		name    string
		row     string
		refused bool
	}{
		{"longer without read_only", "{ requires: [a], absolute_cap: 72h }", true},
		{"longer with read_only", "{ requires: [a], read_only: true, absolute_cap: 72h }", false},
		{"shorter without read_only", "{ requires: [a], absolute_cap: 2h }", false},
		{"no cap", "{ requires: [a] }", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declared, perr := policy.Parse([]byte("version: 1\ngroups: { a: { members: [g@h.example] } }\n" +
				"resources:\n  'https://a.example/': " + tc.row + "\n"))
			if perr != nil {
				t.Fatal(perr)
			}
			set, perr := policy.NewSet(declared)
			if perr != nil {
				t.Fatal(perr)
			}

			// No directory is supplied, so a row that passes stops there
			// instead, which tells the two outcomes apart.
			_, err := New(t.Context(), cfg, Deps{Policy: set}, nil)
			if err == nil {
				t.Fatal("New succeeded with no directory")
			}
			refused := strings.Contains(err.Error(), "read_only")
			if refused != tc.refused {
				t.Errorf("New: %v (refused for the cap = %v), want refused = %v", err, refused, tc.refused)
			}
		})
	}
}
