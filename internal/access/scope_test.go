package access_test

import (
	"context"
	"testing"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/policy"
)

// A role over one workspace, so that connecting a second company's
// directory does not hand its administrator the first one.
//
// The hub is built for several companies and its two roles were not:
// every tenant's administrator administered every other tenant's
// directory, including disconnecting it and reading its credential state.
func TestARoleMayBeHeldOverOneWorkspace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	set, err := policy.Parse([]byte(`
version: 1
groups:
  hub-operators:
    matchers:
      - email: boss@north.example
  hub-operators@C0north:
    matchers:
      - email: ada@north.example
  hub-viewers@C0south:
    matchers:
      - email: ada@north.example
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, err := policy.NewSet(set)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	authorizer := access.NewAuthorizer(compiled, nil, 0)

	scoped, err := authorizer.Authorize(ctx, access.Principal{Email: "ada@north.example"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	global, err := authorizer.Authorize(ctx, access.Principal{Email: "boss@north.example"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// The scoped identity holds nothing over the installation. Everything
	// that changes the policy, the OAuth client or connects a directory
	// that does not exist yet asks exactly this.
	if scoped.Can(access.RoleViewer) {
		t.Error("a scoped identity holds an installation-wide role")
	}
	// It may act where it was named, and nowhere else.
	if !scoped.CanFor(access.RoleOperator, "C0north") {
		t.Error("the scoped operator cannot act on its own workspace")
	}
	if scoped.CanFor(access.RoleOperator, "C0south") {
		t.Error("a viewer scope was enough to operate")
	}
	if !scoped.CanFor(access.RoleViewer, "C0south") {
		t.Error("the scoped viewer cannot see its own workspace")
	}
	if scoped.CanFor(access.RoleViewer, "C0somebody-else") {
		t.Error("a scoped identity reached a workspace it was never named in")
	}
	if !scoped.CanAnywhere(access.RoleOperator) {
		t.Error("a scoped operator may reach no page at all")
	}

	// A global role is not a list of tenants and must never be turned
	// into one: nil means everything, and a filter that read it as an
	// empty allow-list would show an installation operator nothing.
	if got := global.Workspaces(access.RoleViewer); got != nil {
		t.Errorf("an installation-wide role listed workspaces: %v", got)
	}
	if !global.CanFor(access.RoleOperator, "C0anything") {
		t.Error("an installation operator was refused a workspace")
	}
	if got := scoped.Workspaces(access.RoleViewer); len(got) != 2 {
		t.Errorf("visible workspaces = %v, want both it is named in", got)
	}
	if got := scoped.Workspaces(access.RoleOperator); len(got) != 1 || got[0] != "C0north" {
		t.Errorf("operable workspaces = %v, want only C0north", got)
	}
}

// Recovery stays installation-wide by construction. It exists for the day
// the directory or the policy is what is broken, and a recovery scoped to
// one workspace could not repair the workspace whose absence caused it.
func TestRecoveryIsNotScoped(t *testing.T) {
	t.Parallel()
	compiled, err := policy.NewSet(policy.Policy{Version: 1})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	id, err := access.NewAuthorizer(compiled, nil, 0).Authorize(context.Background(), access.Principal{
		Subject: "system:serviceaccount:access-issuer:access-issuer-recovery",
		Source:  access.SourceRecovery,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !id.Can(access.RoleOperator) || len(id.Scopes) != 0 {
		t.Errorf("recovery = role %q, scopes %v, want installation-wide and unscoped", id.Role, id.Scopes)
	}
	if !id.CanFor(access.RoleOperator, "C0anything") {
		t.Error("recovery could not act on a workspace")
	}
}

// A group that merely contains the separator is not a scope. Only the two
// names the hub is a relying party of can carry one, so an installation
// may name a group `team@north.example` without accidentally granting
// anything over a workspace called north.example.
func TestOnlyTheHubsOwnGroupsCarryAScope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		group   string
		scoped  bool
		wants   string
		wantsWS string
	}{
		{"operators", policy.ScopedGroup(policy.GroupOperators, "C0north"), true, policy.GroupOperators, "C0north"},
		{"viewers", policy.ScopedGroup(policy.GroupViewers, "C0north"), true, policy.GroupViewers, "C0north"},
		{"an ordinary group", "platform", false, "", ""},
		{"an address-shaped group", "team@north.example", false, "", ""},
		{"a scope with no workspace", "hub-operators@", false, "", ""},
	} {
		group, workspace, scoped := policy.SplitScopedGroup(tc.group)
		if scoped != tc.scoped || group != tc.wants || workspace != tc.wantsWS {
			t.Errorf("%s: %q → (%q, %q, %v), want (%q, %q, %v)",
				tc.name, tc.group, group, workspace, scoped, tc.wants, tc.wantsWS, tc.scoped)
		}
	}
}
