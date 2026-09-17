package githubapp_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/githubfake"
)

// Every read the controller makes: members across pages with their role
// and verified addresses, invitations, teams and each team's two roles.
func TestAnOrganisationReadsAsGitHubHoldsIt(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	fake.AddMember("excavador", true, "ada.lovelace@globex.example")
	fake.AddMember("ada", false, "ada@globex.example", "ADA@Globex.example ")
	fake.AddMember("bot", false)
	fake.AddTeam("team-platform", "excavador*", "ada")
	fake.Invitations["new@globex.example"] = &githubfake.Invitation{ID: 9, Email: "new@globex.example"}

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	ctx := context.Background()

	members, err := org.Members(ctx, fake.Token)
	if err != nil || len(members) != 3 {
		t.Fatalf("Members = %+v, %v; want three across two pages", members, err)
	}
	byLogin := map[string]githubapp.Member{}
	for _, m := range members {
		byLogin[m.Login] = m
	}
	if !byLogin["excavador"].Owner || byLogin["ada"].Owner {
		t.Errorf("owners = %+v", byLogin)
	}
	if !slices.Equal(byLogin["ada"].Emails, []string{"ada@globex.example", "ada@globex.example"}) {
		t.Errorf("ada's addresses = %v, want lower-cased and trimmed", byLogin["ada"].Emails)
	}

	invitations, err := org.Invitations(ctx, fake.Token)
	if err != nil || len(invitations) != 1 || invitations[0].Email != "new@globex.example" {
		t.Errorf("Invitations = %+v, %v", invitations, err)
	}
	teams, err := org.Teams(ctx, fake.Token)
	if err != nil || len(teams) != 1 || teams[0].Slug != "team-platform" || teams[0].ID == 0 {
		t.Errorf("Teams = %+v, %v", teams, err)
	}
	roles, err := org.TeamMembers(ctx, fake.Token, "team-platform")
	if err != nil || len(roles) != 2 {
		t.Fatalf("TeamMembers = %+v, %v", roles, err)
	}
	for _, m := range roles {
		if (m.Login == "excavador") != m.Maintainer {
			t.Errorf("%s maintainer = %v", m.Login, m.Maintainer)
		}
	}
}

// A GraphQL error arrives inside a 200. A members list with errors in it
// is refused whole: read as complete, it would look like everybody left.
func TestAMembersAnswerCarryingAnErrorIsRefusedWhole(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	fake.AddMember("ada", false, "ada@globex.example")
	fake.GraphQLError = "Resource not accessible by integration"

	_, err := githubapp.Org{HTTP: fake.Client(), Login: "globex"}.Members(context.Background(), fake.Token)
	if err == nil || !strings.Contains(err.Error(), "not accessible") {
		t.Errorf("Members = %v, want the GraphQL error", err)
	}
}

// Every write the controller makes, each checked by what the organisation
// looks like afterwards.
func TestEveryChangeLandsOnTheOrganisation(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	fake.AddMember("ada", false, "ada@globex.example")
	fake.AddMember("leaver", false, "leaver@globex.example")
	fake.AddTeam("team-platform", "leaver")
	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	ctx := context.Background()

	if err := org.Invite(ctx, fake.Token, "new@globex.example", []int64{fake.Teams["team-platform"].ID}); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if err := org.SetTeamRole(ctx, fake.Token, "team-platform", "ada", true); err != nil {
		t.Fatalf("SetTeamRole: %v", err)
	}
	if err := org.RemoveFromTeam(ctx, fake.Token, "team-platform", "leaver"); err != nil {
		t.Fatalf("RemoveFromTeam: %v", err)
	}
	if err := org.RemoveFromOrg(ctx, fake.Token, "leaver"); err != nil {
		t.Fatalf("RemoveFromOrg: %v", err)
	}
	want := []string{"invite new@globex.example", "add team-platform/ada as maintainer", "remove team-platform/leaver", "remove-from-org leaver"}
	if got := fake.Did(); !slices.Equal(got, want) {
		t.Errorf("actions = %v, want %v", got, want)
	}
	if !fake.Teams["team-platform"].Members["ada"] || fake.Members["leaver"] != nil {
		t.Error("the organisation does not look changed")
	}
	if invitation := fake.Invitations["new@globex.example"]; invitation == nil || len(invitation.Teams) != 1 {
		t.Errorf("the invitation did not carry its team: %+v", invitation)
	}

	// GitHub's refusal reaches the caller in its own words.
	fake.Refuse["invite x@globex.example"] = "already a part of this organization"
	if err := org.Invite(ctx, fake.Token, "x@globex.example", nil); err == nil || !strings.Contains(err.Error(), "already a part") {
		t.Errorf("a refused invite = %v", err)
	}
}

// An installation token is minted by the App, for one installation.
func TestAnInstallationTokenIsMintedForTheInstallation(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	token, expires, err := githubapp.InstallationToken(context.Background(), fake.Client(), "app-jwt", 7)
	if err != nil || token != fake.Token || expires.IsZero() {
		t.Errorf("InstallationToken = %q, %v, %v", token, expires, err)
	}
}

// A narrowed token asks GitHub for exactly the repositories and
// permissions named, and reports what GitHub says it granted; an
// unnarrowed one sends no body at all.
func TestAnInstallationTokenIsNarrowedInTheRequestBody(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	fake.Repositories = []string{"app", "infra"}
	narrowing := githubapp.Narrowing{Repositories: []string{"app"}, Permissions: map[string]string{"contents": "read"}}
	minted, err := githubapp.InstallationTokenFor(context.Background(), fake.Client(), "app-jwt", 7, narrowing)
	if err != nil {
		t.Fatalf("InstallationTokenFor: %v", err)
	}
	if minted.Token != fake.Token || minted.ExpiresAt.IsZero() ||
		!slices.Equal(minted.Repositories, []string{"app"}) || minted.Permissions["contents"] != "read" {
		t.Errorf("minted = %+v", minted)
	}
	if _, _, err = githubapp.InstallationToken(context.Background(), fake.Client(), "app-jwt", 7); err != nil {
		t.Fatalf("InstallationToken: %v", err)
	}
	if len(fake.TokenRequests) != 2 || fake.TokenRequests[0].Body == nil || fake.TokenRequests[1].Body != nil {
		t.Fatalf("requests = %+v, want one narrowed body and one without", fake.TokenRequests)
	}

	// A repository the installation cannot reach is GitHub's 422.
	_, err = githubapp.InstallationTokenFor(context.Background(), fake.Client(), "app-jwt", 7,
		githubapp.Narrowing{Repositories: []string{"elsewhere"}})
	var status *githubapp.StatusError
	if !errors.As(err, &status) || status.Code != 422 {
		t.Errorf("an unreachable repository = %v, want GitHub's 422", err)
	}
}
