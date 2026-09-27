package issuer

import (
	"reflect"
	"slices"
	"testing"

	"github.com/truvity/access-roster/policy"
)

// namesOfClaim reads a claims map's `groups` entry back into a sorted
// []string, the shape [scopeClaims] writes and [policy.Result.Claims]
// itself writes it in.
func namesOfClaim(t *testing.T, claims map[string]any) []string {
	t.Helper()
	raw, _ := claims["groups"].([]any)
	out := make([]string, 0, len(raw))
	for _, g := range raw {
		s, ok := g.(string)
		if !ok {
			t.Fatalf("groups entry %#v is not a string", g)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func anyGroups(names ...string) []any {
	out := make([]any, len(names))
	for i, name := range names {
		out[i] = name
	}
	return out
}

// scopeClaims is a no-op, returning the SAME map (never even a copy),
// under every mode besides enforce, and under enforce itself when there
// is no audience or nothing held — every one of which the doc comment
// promises so that a caller never pays an allocation for a mode that
// changes nothing.
func TestScopeClaimsIsANoOpOutsideEnforce(t *testing.T) {
	t.Parallel()

	declared := policy.Policy{Version: 1}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}

	claims := map[string]any{"groups": anyGroups("devel:k8s:admin")}
	held := []string{"devel:k8s:admin"}

	for _, tc := range []struct {
		name     string
		mode     GroupsScopingMode
		audience string
		held     []string
	}{
		{"off", GroupsScopingOff, "aud", held},
		{"report", GroupsScopingReport, "aud", held},
		{"enforce, no audience", GroupsScopingEnforce, "", held},
		{"enforce, nothing held", GroupsScopingEnforce, "aud", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scopeClaims(tc.mode, set, claims, tc.audience, tc.held)
			// The SAME map, by identity, never merely an equal one: the
			// doc comment promises claims is returned unchanged, "not
			// even copied", precisely so a caller pays no allocation for
			// a mode that changes nothing.
			if reflect.ValueOf(got).Pointer() != reflect.ValueOf(claims).Pointer() {
				t.Error("a no-op call returned a different map than it was given")
			}
		})
	}
}

// A self-described client, admitted through [policy.ClientDocuments]
// rather than a row of its own, is gated and scoped the same way a
// declared client or resource is -- [policy.Policy.audienceScope] reads
// its pairs from `client_documents.requires` instead of a `clients` or
// `resources` row, and [scopeClaims] does not care which of the three
// found them.
func TestScopeClaimsNarrowsASelfDescribedAudience(t *testing.T) {
	t.Parallel()

	declared := policy.Policy{
		Version: 1,
		Groups: map[string]policy.Group{
			"devel:grafana:viewer": {},
			"devel:grafana:editor": {},
			"devel:k8s:admin":      {},
		},
		ClientDocuments: policy.ClientDocuments{
			Origins:  []string{"mcp.example"},
			Requires: []string{"devel:grafana:viewer"},
		},
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}

	held := []string{"devel:grafana:editor", "devel:grafana:viewer", "devel:k8s:admin"}
	claims := map[string]any{"groups": anyGroups(held...), "sub": "ada@north.example"}

	got := scopeClaims(GroupsScopingEnforce, set, claims, "https://mcp.example/client", held)

	want := []string{"devel:grafana:editor", "devel:grafana:viewer"}
	if names := namesOfClaim(t, got); !slices.Equal(names, want) {
		t.Errorf("groups = %v, want %v: the client_documents gate's own pair", names, want)
	}
	if got["sub"] != "ada@north.example" {
		t.Error("a claim beyond groups was dropped")
	}

	// The map [scopeClaims] was handed is untouched: a caller reading
	// `claims` again after this call must still see the FULL set, because
	// more than one reader shares a [Grant]'s claims and only one of them
	// -- the one minting a token for THIS audience -- may narrow its own
	// copy.
	if names := namesOfClaim(t, claims); !slices.Equal(names, []string{"devel:grafana:editor", "devel:grafana:viewer", "devel:k8s:admin"}) {
		t.Errorf("the input map was mutated: groups = %v", names)
	}

	// An origin this installation does NOT admit is not a document client
	// [Policy.audienceScope] can place at all, so every held group is
	// dropped -- same as any other ungated audience.
	notAdmitted := scopeClaims(GroupsScopingEnforce, set, claims, "https://not-allowed.example/client", held)
	if _, present := notAdmitted["groups"]; present {
		t.Errorf("groups = %v, want the key removed: not-allowed.example admits no gate", notAdmitted["groups"])
	}
}
