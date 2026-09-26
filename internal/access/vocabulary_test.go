package access_test

import (
	"testing"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/policy"
)

// TestHoldersOfSeesInheritedGroups is the closest proof this repository
// has that GitHub team reconciliation sees a vocabulary's inheritance:
// internal/githubroster/controller.Controller's holders() asks "who holds
// this group" through the console's ListHolders RPC, which is exactly
// [access.Authorizer.HoldersOf] — the same function, not a stand-in for
// it. A team bound to `devel:k8s:viewer` alone must be fed by an account
// that holds only `devel:k8s:admin` directly.
func TestHoldersOfSeesInheritedGroups(t *testing.T) {
	t.Parallel()

	p, err := policy.Parse([]byte(`
version: 1
vocabulary:
  scopes:
    devel: {}
  things:
    k8s:
      scopes: [devel]
      roles: { viewer: [], operator: [viewer], admin: [operator] }
groups:
  devel:k8s:admin: { members: [alice@example.com] }
  devel:k8s:viewer: {}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	a := access.NewAuthorizer(set, nil, 0)

	people := []hub.Person{{
		Email:           "alice@example.com",
		Live:            true,
		Authoritative:   true,
		DirectoryGroups: []string{"alice@example.com"},
	}}

	holders := a.HoldersOf(people, "devel:k8s:viewer", "")
	if len(holders) != 1 || holders[0].Email != "alice@example.com" {
		t.Fatalf("HoldersOf(devel:k8s:viewer) = %v, want alice via her devel:k8s:admin membership", holders)
	}
}
