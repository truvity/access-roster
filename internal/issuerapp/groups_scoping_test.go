package issuerapp

import (
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/issuer"
)

// GROUPS_SCOPING defaults to report, accepts off, and refuses enforce by
// name -- this release's whole point is that the switch is visible and
// wired without being usable yet, so an installation that asks for it
// gets a reason rather than a silent downgrade to report.
func TestGroupsScopingIsValidatedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     string
		want      issuer.GroupsScopingMode
		wantError string
	}{
		{"unset defaults to report", "", issuer.GroupsScopingReport, ""},
		{"off is accepted", "off", issuer.GroupsScopingOff, ""},
		{"report is accepted explicitly", "report", issuer.GroupsScopingReport, ""},
		{"enforce is refused: it ships in a later release", "enforce", "", "later release"},
		{"an unknown value is refused", "sometimes", "", `is not one of "off", "report" or "enforce"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ISSUER_URL", "https://issuer.example")
			if tc.value != "" {
				t.Setenv("GROUPS_SCOPING", tc.value)
			}

			cfg, err := Load()
			if tc.wantError != "" {
				if err == nil {
					t.Fatalf("Load() succeeded, want a refusal containing %q", tc.wantError)
				}
				if !strings.Contains(err.Error(), tc.wantError) {
					t.Errorf("Load(): %q, want it to contain %q", err.Error(), tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load(): %v, want it to succeed", err)
			}
			if cfg.groupsScoping != tc.want {
				t.Errorf("groupsScoping = %q, want %q", cfg.groupsScoping, tc.want)
			}
		})
	}
}
