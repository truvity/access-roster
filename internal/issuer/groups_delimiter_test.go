package issuer_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
)

// delimitedDemoPolicy is [demo.Policy] with `local-dev` pinning
// `groups_delimiter: "."` -- the same substitution
// docs/decisions/0015-a-per-audience-groups-delimiter-for-opkssh.md
// describes for opkssh, applied to the one client every other test in
// this package already signs in as.
var delimitedDemoPolicy = func() string {
	const from = "local-dev:\n    kind: public\n    redirects: [http://localhost:8000/callback]\n    requires: [devel:k8s:viewer]\n"
	widened := strings.Replace(demo.Policy, from, from+"    groups_delimiter: \".\"\n", 1)
	if widened == demo.Policy {
		panic("delimitedDemoPolicy: the replacement did not match; the fixture drifted")
	}
	return widened
}()

// delimited rewrites every `:` in each name to `.` and sorts the result --
// what ada's held groups ([wantScopingKept], [wantScopingDropped] in
// scoping_report_test.go) look like once local-dev's own
// `groups_delimiter` has been applied, under a mode that scopes nothing
// away.
func delimited(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = strings.ReplaceAll(name, ":", ".")
	}
	slices.Sort(out)
	return out
}

// The rewrite applies to the ID token, the access token AND `/userinfo`
// alike -- every place scoping_enforce_test.go's enforce tests already
// prove per-audience scoping reaches -- under GroupsScopingReport, this
// package's ordinary mode, which scopes nothing away and so proves the
// delimiter is not itself a scoping decision: every held group survives,
// merely re-spelled.
func TestGroupsDelimiterRewritesIDTokenAccessTokenAndUserinfo(t *testing.T) {
	t.Parallel()
	server, iss, _ := serveScoping(t, adaDirectory(), issuer.GroupsScopingReport, delimitedDemoPolicy)

	body := signedInTokens(t, server, iss, "local-dev")
	idToken, _ := body["id_token"].(string)
	accessToken, _ := body["access_token"].(string)
	if idToken == "" || accessToken == "" {
		t.Fatalf("no id_token or access_token in %v", body)
	}

	want := delimited(append(slices.Clone(wantScopingKept), wantScopingDropped...))

	if got := groupsOf(t, payloadOf(t, idToken)); !slices.Equal(got, want) {
		t.Errorf("id token groups = %v, want %v (every `:` rewritten to `.`)", got, want)
	}
	if got := groupsOf(t, claimsOf(t, server, accessToken)); !slices.Equal(got, want) {
		t.Errorf("access token groups = %v, want %v", got, want)
	}
	if got := groupsOf(t, userinfoOf(t, server, accessToken)); !slices.Equal(got, want) {
		t.Errorf("userinfo groups = %v, want %v", got, want)
	}

	// Not merely re-sorted: every name that ever appears carries no `:`
	// at all, and the shape taxonomy.md gives a grant -- three
	// dot-separated fields -- is exactly what opkssh's own splitting on
	// EVERY `:` could never produce from the original name.
	for _, name := range want {
		if strings.Contains(name, ":") {
			t.Errorf("group %q still contains a %q; the delimiter did not fully replace it", name, ":")
		}
	}
}

// A client that names no `groups_delimiter` -- every other row in the
// demonstration policy, and local-dev itself before this ADR -- is
// unaffected: `groups` still carries the grant's own `:`, byte for byte
// what every other test in this package already assumes.
func TestGroupsDelimiterLeavesUnconfiguredAudiencesUnchanged(t *testing.T) {
	t.Parallel()
	server, iss, _ := serveScoping(t, adaDirectory(), issuer.GroupsScopingReport, demo.Policy)

	body := signedInTokens(t, server, iss, "local-dev")
	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("no access_token in %v", body)
	}

	want := append(slices.Clone(wantScopingKept), wantScopingDropped...)
	slices.Sort(want)

	if got := groupsOf(t, claimsOf(t, server, accessToken)); !slices.Equal(got, want) {
		t.Errorf("groups = %v, want %v: an unconfigured audience must keep the grant's own `:`", got, want)
	}
}

// A token exchange builds its claims through [issuer.Issuer.Exchange], a
// path separate from an ordinary sign-in's -- the delimiter has to reach
// that one too, exactly as TestGroupsScopingEnforceScopesTheExchangeToken
// (scoping_enforce_test.go) proves scoping does. Report mode drops
// nothing, so the proof's GitHub identity ends up holding BOTH matchers
// exchangeScopingPolicy declares -- devel:svc:admin (repository and ref)
// and prod:svc:admin (owner alone) -- and both come back rewritten, not
// only the one target's own `requires` names.
func TestGroupsDelimiterRewritesTheExchangeToken(t *testing.T) {
	t.Parallel()

	const from = "  target: { kind: exchange, requires: [devel:svc:admin] }\n"
	widened := strings.Replace(exchangeScopingPolicy, from,
		"  target: { kind: exchange, requires: [devel:svc:admin], groups_delimiter: '.' }\n", 1)
	if widened == exchangeScopingPolicy {
		t.Fatal("the replacement did not match; the fixture drifted")
	}

	server, _, _ := serveScoping(t, &fakeDirectory{}, issuer.GroupsScopingReport, widened)

	status, body := exchange(t, server, "github:example-org/gitops@refs/heads/master", "target")
	if status != http.StatusOK {
		t.Fatalf("exchange: %d %v", status, body)
	}
	raw, _ := body["access_token"].(string)
	if raw == "" {
		t.Fatalf("no access token in %v", body)
	}

	got := groupsOf(t, claimsOf(t, server, raw))
	want := []string{"devel.svc.admin", "prod.svc.admin"}
	if !slices.Equal(got, want) {
		t.Errorf("exchanged token groups = %v, want %v", got, want)
	}
}
