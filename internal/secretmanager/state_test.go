package secretmanager_test

import (
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/secretmanager"
)

// stateOf is the four-way answer for one group, so that a test reads as
// the sentence it is asserting.
func stateOf(t *testing.T, views []secretmanager.GroupView, name string) secretmanager.GroupView {
	t.Helper()
	for i := range views {
		if views[i].Name == name {
			return views[i]
		}
	}
	t.Fatalf("%q is not among the %d groups the comparison returned", name, len(views))
	return secretmanager.GroupView{}
}

func TestTheFourStatesOfAGroup(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(
		secretmanager.Declared{Expected: []string{"devel:platform:viewer", "devel:platform:deployer"}},
		secretmanager.Live{
			Policies: []string{"devel:platform:viewer", "devel:leftover:deployer"},
			Groups: map[string]secretmanager.Group{
				// Declared and there: bound.
				"devel:platform:viewer": {
					Name: "devel:platform:viewer", Policies: []string{"devel:platform:viewer"}, Members: 3,
					Aliases: []secretmanager.GroupAlias{
						{Mount: "jwt-roster"}, {Mount: "oidc"},
					},
				},
				// There and declared by nobody: the interesting one.
				"devel:leftover:deployer": {Name: "devel:leftover:deployer"},
			},
		})

	if got := stateOf(t, views, "devel:platform:viewer"); got.State != secretmanager.StateBound {
		t.Errorf("a declared group the store holds is %q, want bound", got.State)
	} else if got.Doors[0] != "jwt-roster" || got.Doors[1] != "oidc" {
		t.Errorf("its doors are %v, want both", got.Doors)
	} else if !got.HasPolicy || got.Members != 3 {
		t.Errorf("it lost its policy or its members: %+v", got)
	}

	// Declared, not there: the apply has not run. Not drift — the
	// estate's answer is already right and the store has yet to hear it.
	if got := stateOf(t, views, "devel:platform:deployer"); got.State != secretmanager.StateAbsent {
		t.Errorf("a declared group the store does not hold is %q, want absent", got.State)
	}

	if got := stateOf(t, views, "devel:leftover:deployer"); got.State != secretmanager.StateUnexpected {
		t.Errorf("an undeclared group the store holds is %q, want unexpected", got.State)
	} else if got.Declared {
		t.Error("it is marked as declared")
	}

	counts := secretmanager.Count(views)
	if counts.Bound != 1 || counts.Absent != 1 || counts.Unexpected != 1 {
		t.Errorf("counts = %+v, want one of each", counts)
	}
}

// The distinction the page exists for: a reader that may not look must
// not be drawn as a store holding nothing. "Absent" reads as "the apply
// has not run" and sends somebody to look at a pipeline that is fine.
func TestAGroupInARefusedNamespaceIsUnreadableRatherThanAbsent(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(
		secretmanager.Declared{Expected: []string{"devel:platform:viewer"}},
		secretmanager.Live{GroupsUnreadable: true},
	)
	if got := stateOf(t, views, "devel:platform:viewer"); got.State != secretmanager.StateUnreadable {
		t.Fatalf("with the groups unreadable the state is %q, want unreadable", got.State)
	}
	if counts := secretmanager.Count(views); counts.Absent != 0 || counts.Unreadable != 1 {
		t.Errorf("counts = %+v, want nothing reported absent", counts)
	}
}

// A group bound to a policy that is not there grants nothing, and the
// store reports neither as an error: it is two objects that were applied
// separately and only one arrived.
func TestAGroupWhosePolicyIsMissingSaysSo(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(
		secretmanager.Declared{Expected: []string{"devel:platform:viewer"}},
		secretmanager.Live{
			Policies: []string{"default"},
			Groups:   map[string]secretmanager.Group{"devel:platform:viewer": {Name: "devel:platform:viewer"}},
		})
	got := stateOf(t, views, "devel:platform:viewer")
	if got.State != secretmanager.StateBound {
		t.Errorf("state = %q, want bound: the group IS there", got.State)
	}
	if got.HasPolicy {
		t.Error("it claims a policy the namespace does not hold")
	}
}

// Unreadable policies are not "the policy is missing": the page must not
// invent a fault out of a read it was refused.
func TestPoliciesItCouldNotListAreNotReportedMissing(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(
		secretmanager.Declared{Expected: []string{"devel:platform:viewer"}},
		secretmanager.Live{
			PoliciesUnreadable: true,
			Groups:             map[string]secretmanager.Group{"devel:platform:viewer": {Name: "devel:platform:viewer"}},
		})
	got := stateOf(t, views, "devel:platform:viewer")
	if got.State != secretmanager.StateBound || got.HasPolicy {
		t.Errorf("view = %+v, want bound with no claim about its policy", got)
	}
}

// The naming convention IS the mapping: `{environment}:{project}:{role}`.
// A group that spans environments belongs under none of them, so `all:`
// groups are not drawn in a namespace that does not own them.
func TestOnlyTheEnvironmentsOwnGroupsAreDeclaredForIt(t *testing.T) {
	t.Parallel()
	got := secretmanager.DeclaredFor("devel", []string{
		"devel:platform:viewer",
		"stage:platform:viewer",
		"all:openbao:operator",
		"devel:ssh:admin",
	})

	want := []string{"devel:platform:viewer", "devel:ssh:admin"}
	if len(got.Expected) != len(want) || got.Expected[0] != want[0] || got.Expected[1] != want[1] {
		t.Errorf("expected for devel = %v, want %v", got.Expected, want)
	}
	// An `all:` group is legitimate here and missing from nothing: it is
	// never reported absent, and never drawn as drift when it appears.
	if len(got.Optional) != 1 || got.Optional[0] != "all:openbao:operator" {
		t.Errorf("optional for devel = %v, want the all: group", got.Optional)
	}
	// Another environment's is neither.
	for _, list := range [][]string{got.Expected, got.Optional} {
		for _, name := range list {
			if strings.HasPrefix(name, "stage:") {
				t.Errorf("%s is drawn in devel's namespace", name)
			}
		}
	}
}

// A namespace nothing declares and nothing holds is a page that says so,
// not a failure.
func TestAnEmptyNamespaceIsEmpty(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(secretmanager.Declared{}, secretmanager.Live{})
	if len(views) != 0 {
		t.Fatalf("an empty namespace produced %d rows", len(views))
	}
	if counts := secretmanager.Count(views); counts != (secretmanager.Counts{}) {
		t.Errorf("counts = %+v, want all zero", counts)
	}
}

// THE BUG THE LIVE PAGE FOUND. A store holds one alias per identity
// group, so admitting one group at two doors takes two identity groups:
// the bare name, and `<name>@<door>` carrying the same policy. Drawn as
// separate rows, every group in the installation appeared twice — once
// as drift nobody declared — and the one row worth reading was buried in
// thirty that were not.
func TestADoorsTwinIsTheSameGroupRatherThanDrift(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(
		secretmanager.Declared{Expected: []string{"devel:platform:viewer"}},
		secretmanager.Live{
			Policies: []string{"devel:platform:viewer"},
			Groups: map[string]secretmanager.Group{
				"devel:platform:viewer": {
					Name: "devel:platform:viewer", Policies: []string{"devel:platform:viewer"}, Members: 4,
					Aliases: []secretmanager.GroupAlias{{Mount: "jwt-roster"}},
				},
				// The web door's twin: same policy, its own alias.
				"devel:platform:viewer@oidc": {
					Name: "devel:platform:viewer@oidc", Policies: []string{"devel:platform:viewer"},
					Aliases: []secretmanager.GroupAlias{{Mount: "oidc"}},
				},
			},
		})

	if len(views) != 1 {
		t.Fatalf("the twin was drawn as its own row: %+v", views)
	}

	got := stateOf(t, views, "devel:platform:viewer")
	if got.State != secretmanager.StateBound {
		t.Errorf("state = %q, want bound", got.State)
	}
	// Both doors on one row, which is what the page was for: a group
	// admitted at one and refused at the other is the thing to see.
	if len(got.Doors) != 2 || got.Doors[0] != "jwt-roster" || got.Doors[1] != "oidc" {
		t.Errorf("doors = %v, want both", got.Doors)
	}
	// The twin does not overwrite what the bare group says.
	if got.Members != 4 || !got.HasPolicy {
		t.Errorf("view = %+v, want the bare group's members and policy", got)
	}
}

// A twin whose bare group is gone is still one row, and still drift.
func TestATwinWithoutItsGroupIsOneUnexpectedRow(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(secretmanager.Declared{}, secretmanager.Live{
		Groups: map[string]secretmanager.Group{
			"devel:leftover:viewer@oidc": {Name: "devel:leftover:viewer@oidc", Aliases: []secretmanager.GroupAlias{{Mount: "oidc"}}},
		},
	})

	if len(views) != 1 {
		t.Fatalf("views = %+v, want one", views)
	}
	if views[0].Name != "devel:leftover:viewer" || views[0].State != secretmanager.StateUnexpected {
		t.Errorf("view = %+v, want the logical name, unexpected", views[0])
	}
}

// A name with an `@` that is not a door twin — an address, say — is not
// split into something else.
func TestOnlyAGroupWithADoorIsSplit(t *testing.T) {
	t.Parallel()
	for name, wantBase := range map[string]string{
		"devel:platform:viewer":      "devel:platform:viewer",
		"devel:platform:viewer@oidc": "devel:platform:viewer",
		"@oidc":                      "@oidc",
		"devel:platform:viewer@":     "devel:platform:viewer@",
	} {
		if base, _ := secretmanager.SplitDoor(name); base != wantBase {
			t.Errorf("SplitDoor(%q) = %q, want %q", name, base, wantBase)
		}
	}
}

// The installation's OWN reader is an `all:` group and the store holds
// it in every namespace. Reported as drift it would put a red row on
// every page — the console accusing itself.
func TestAnAllScopedGroupTheStoreHoldsIsNotDrift(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(
		secretmanager.Declared{
			Expected: []string{"devel:platform:viewer"},
			Optional: []string{"all:openbao:console"},
		},
		secretmanager.Live{
			Policies: []string{"all:openbao:console"},
			Groups: map[string]secretmanager.Group{
				"all:openbao:console": {Name: "all:openbao:console", Policies: []string{"all:openbao:console"}},
			},
		})

	if got := stateOf(t, views, "all:openbao:console"); got.State != secretmanager.StateBound || !got.Declared {
		t.Errorf("the installation's own reader is %q (declared=%v), want bound", got.State, got.Declared)
	}
}

// And an `all:` group the store does NOT hold is not drawn at all: its
// scope is no single namespace, so its absence here says nothing.
func TestAnAllScopedGroupTheStoreLacksIsNotReportedMissing(t *testing.T) {
	t.Parallel()
	views := secretmanager.Compare(
		secretmanager.Declared{Optional: []string{"all:openbao:operator"}},
		secretmanager.Live{},
	)

	if len(views) != 0 {
		t.Errorf("views = %+v, want none: an all: group missing here proves nothing", views)
	}
}
