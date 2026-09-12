package server

import (
	"context"
	"slices"
	"testing"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/policy"
)

// The Rules page reads GitHub bindings from GetPolicy and nothing else,
// so what it cannot see here it cannot show: a maintainer role dropped on
// the way to the wire reads, in the console, as a lead demoted to member
// — and an organisation's own members, dropped, read as nobody being in
// the organisation without a team (INF-696).
func TestGetPolicyCarriesBothTeamRolesAndAnOrganisationsOwnMembers(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(`
version: 1
groups:
  all:platform:engineer: { members: [team-platform@truvity.com] }
  all:platform:lead: { members: [leads@truvity.com] }
  all:truvity:employee: { matchers: [{ email_domain: truvity.com }] }
github:
  truvity:
    members: [all:truvity:employee]
    teams:
      team-platform:
        members: [all:platform:engineer]
        maintainers: [all:platform:lead]
  trust-form:
    teams:
      team-platform:
        members: [all:platform:engineer]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	console := &Console{deps: ConsoleDeps{Authorizer: access.NewAuthorizer(set, nil, 0)}}
	ctx := WithIdentity(context.Background(), access.Identity{Role: access.RoleViewer})

	response, err := console.GetPolicy(ctx, connect.NewRequest(&directoryrosterv1.GetPolicyRequest{}))
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	got := response.Msg

	var platform *directoryrosterv1.PolicyTeam
	for _, team := range got.GetTeams() {
		if team.GetOrg() == "truvity" && team.GetTeam() == "team-platform" {
			platform = team
		}
	}
	if platform == nil {
		t.Fatalf("teams = %v, want truvity/team-platform", got.GetTeams())
	}
	if !slices.Equal(platform.GetMembers(), []string{"all:platform:engineer"}) {
		t.Errorf("members = %v", platform.GetMembers())
	}
	if !slices.Equal(platform.GetMaintainers(), []string{"all:platform:lead"}) {
		t.Errorf("maintainers = %v, want the lead group", platform.GetMaintainers())
	}

	// trust-form binds only teams, so it has nothing to say at the
	// organisation level and is absent from the list.
	orgs := got.GetOrgs()
	if len(orgs) != 1 || orgs[0].GetOrg() != "truvity" {
		t.Fatalf("orgs = %v, want truvity alone", orgs)
	}
	if !slices.Equal(orgs[0].GetMembers(), []string{"all:truvity:employee"}) {
		t.Errorf("org members = %v", orgs[0].GetMembers())
	}
}
