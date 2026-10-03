package policy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/policy"
)

const absoluteBase = "version: 1\n" +
	"groups: { a: { members: [g@h.example] } }\n"

func parseResources(t *testing.T, rows string) (policy.Policy, error) {
	t.Helper()

	declared, err := policy.Parse([]byte(absoluteBase + "resources:\n" + rows))
	if err != nil {
		return policy.Policy{}, err
	}

	return declared, declared.Validate()
}

// A read-only resource may carry an absolute cap up to seven days, and the
// row reads back as written.
func TestAReadOnlyResourceMayCarryALongerAbsoluteCap(t *testing.T) {
	t.Parallel()

	declared, err := parseResources(t,
		"  'https://a.example/': { requires: [a], read_only: true, absolute_cap: 168h }\n"+
			"  'https://b.example/': { requires: [a], read_only: true, absolute_cap: 72h }\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	row := declared.Resources["https://a.example/"]
	if got := row.AbsoluteCap.Duration(); got != policy.MaxAbsoluteCap {
		t.Errorf("absolute_cap = %s, want %s", got, policy.MaxAbsoluteCap)
	}
	if !row.ReadOnly {
		t.Error("read_only did not read back")
	}
	if err := row.CheckAbsoluteCap("https://a.example/", 24*time.Hour); err != nil {
		t.Errorf("a read-only 7d cap against a 24h global: %v, want accepted", err)
	}
}

// What is refused at load: a cap above seven days (read-only or not), a
// zero or negative value, and -- once the installation's own limit is
// known -- a longer cap on a resource that is not read-only.
func TestAbsoluteCapRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		row  string
		want string
	}{
		{"above seven days", "{ requires: [a], read_only: true, absolute_cap: 169h }", "longer than the 168h0m0s"},
		{"above seven days, not read-only", "{ requires: [a], absolute_cap: 200h }", "longer than the 168h0m0s"},
		{"zero", "{ requires: [a], read_only: true, absolute_cap: 0s }", "must be positive"},
		{"negative", "{ requires: [a], read_only: true, absolute_cap: -1h }", "must be positive"},
		{"not a duration", "{ requires: [a], read_only: true, absolute_cap: soon }", "duration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseResources(t, "  'https://a.example/': "+tc.row+"\n")
			if err == nil {
				t.Fatal("want an error, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}

	// A cap above the installation's absolute limit without read_only parses
	// (policy does not know the limit) and is refused where the limit is
	// known.
	declared, err := parseResources(t, "  'https://a.example/': { requires: [a], absolute_cap: 48h }\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	row := declared.Resources["https://a.example/"]
	err = row.CheckAbsoluteCap("https://a.example/", 24*time.Hour)
	if err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Errorf("CheckAbsoluteCap = %v, want a refusal naming read_only", err)
	}
	// Shortening needs no read_only.
	if err := row.CheckAbsoluteCap("https://a.example/", 72*time.Hour); err != nil {
		t.Errorf("a cap under the global limit: %v, want accepted", err)
	}
}

// The access document spells it camelCase, and means the same.
func TestAbsoluteCapInTheAccessDocument(t *testing.T) {
	t.Parallel()

	doc := "version: 1\n" +
		"access:\n" +
		"  groups:\n" +
		"    - { name: a, emails: [g@h.example] }\n" +
		"  resources:\n" +
		"    - { id: 'https://a.example/', requires: [a], readOnly: true, absoluteCap: 168h }\n"
	declared, err := policy.ParseAccess([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	row := declared.Resources["https://a.example/"]
	if !row.ReadOnly || row.AbsoluteCap.Duration() != policy.MaxAbsoluteCap {
		t.Errorf("row = %+v, want read_only with a 168h cap", row)
	}
}

// The minimum rule. A chain's absolute limit is the SHORTEST limit among
// the resources it has been used for; the client's own audience and any
// resource without a cap count as the installation's.
func TestEffectiveAbsoluteIsTheMinimumOverWhatTheChainTouched(t *testing.T) {
	t.Parallel()

	const global = 24 * time.Hour
	rows := map[string]policy.Resource{
		"week":    {AbsoluteCap: policy.Duration(168 * time.Hour), ReadOnly: true},
		"three":   {AbsoluteCap: policy.Duration(72 * time.Hour), ReadOnly: true},
		"plain":   {},
		"short":   {AbsoluteCap: policy.Duration(2 * time.Hour)},
		"sneaky":  {AbsoluteCap: policy.Duration(100 * time.Hour)}, // longer, not read-only
		"toolong": {AbsoluteCap: policy.Duration(500 * time.Hour), ReadOnly: true},
	}
	lookup := func(id string) (policy.Resource, bool) { r, ok := rows[id]; return r, ok }

	for _, tc := range []struct {
		name    string
		touched []string
		global  time.Duration
		want    time.Duration
	}{
		{"one extended resource", []string{"week"}, global, 168 * time.Hour},
		{"nothing touched is the client's own audience", nil, global, global},
		{"the client's own audience", []string{""}, global, global},
		{"a resource with no cap", []string{"plain"}, global, global},
		{"an undeclared resource", []string{"nowhere"}, global, global},
		{"mixed: extended and plain falls back", []string{"week", "plain"}, global, global},
		{"mixed: extended and the client's own", []string{"week", ""}, global, global},
		{"mixed: two extended takes the shorter", []string{"week", "three"}, global, 72 * time.Hour},
		{"order does not matter", []string{"three", "week"}, global, 72 * time.Hour},
		{"a shorter cap needs no read_only", []string{"short"}, global, 2 * time.Hour},
		{"extended plus shorter", []string{"week", "short"}, global, 2 * time.Hour},
		{"a longer cap without read_only is ignored", []string{"sneaky"}, global, global},
		{"a cap past seven days is clamped", []string{"toolong"}, global, policy.MaxAbsoluteCap},
		{"no installation limit adds none", []string{"week"}, 0, 0},
		{"a global past seven days is never lengthened or cut by an extension", []string{"toolong"}, 240 * time.Hour, 240 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := policy.EffectiveAbsolute(tc.global, tc.touched, lookup); got != tc.want {
				t.Errorf("EffectiveAbsolute(%s, %v) = %s, want %s", tc.global, tc.touched, got, tc.want)
			}
		})
	}
}
