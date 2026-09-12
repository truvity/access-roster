package reconcile_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/reconcile"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/policy"
)

// binding is truvity with one team fed in both roles, and the organisation
// itself fed by everyone.
var binding = policy.GitHubOrg{
	Members: []string{"all:truvity:employee"},
	Teams: map[string]policy.GitHubTeam{
		"team-platform": {Members: []string{"all:platform:engineer"}, Maintainers: []string{"all:platform:lead"}},
	},
}

func live(emails ...string) []reconcile.Holder {
	out := make([]reconcile.Holder, 0, len(emails))
	for _, email := range emails {
		out = append(out, reconcile.Holder{Email: email, Live: true})
	}
	return out
}

func actions(list []reconcile.Action) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.String())
	}
	return out
}

func findMember(t *testing.T, report status.Org, team, email string) status.Member {
	t.Helper()
	rows := report.Members
	if team != "" {
		rows = nil
		for _, tm := range report.Teams {
			if tm.Team == team {
				rows = tm.Members
			}
		}
	}
	for _, m := range rows {
		if m.Email == email {
			return m
		}
	}
	t.Fatalf("no row for %s in %q: %+v", email, team, report)
	return status.Member{}
}

// A member wanted in a team is added in the role wanted — maintainer when
// a lead group names them even if a member group does too — a wrong role
// is changed, and a right one is left alone.
func TestAMemberIsAddedInTheRoleWantedAndTheWiderRoleWins(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{
		"all:truvity:employee":  live("ada@truvity.com", "bob@truvity.com", "cy@truvity.com"),
		"all:platform:engineer": live("ada@truvity.com", "bob@truvity.com", "cy@truvity.com"),
		"all:platform:lead":     live("ada@truvity.com", "cy@truvity.com"),
	}
	state := reconcile.State{
		Members: []githubapp.Member{
			{Login: "ada", Emails: []string{"ada@truvity.com"}},
			{Login: "bob", Emails: []string{"bob@truvity.com"}},
			{Login: "cy", Emails: []string{"cy@truvity.com"}},
		},
		Teams:       []githubapp.Team{{ID: 1, Slug: "team-platform"}},
		TeamMembers: map[string][]githubapp.TeamMember{"team-platform": {{Login: "bob"}, {Login: "cy", Maintainer: true}}},
	}
	draft := reconcile.Derive("truvity", binding, holders, state)
	report, did := draft.Decide(nil)

	if want := []string{"add ada in team-platform"}; !slices.Equal(actions(did), want) {
		t.Errorf("actions = %v, want %v", actions(did), want)
	}
	if m := findMember(t, report, "team-platform", "ada@truvity.com"); m.Role != status.RoleMaintainer || m.State != status.StatePending {
		t.Errorf("ada = %+v, want a pending maintainer: a lead group names her", m)
	}
	if m := findMember(t, report, "team-platform", "cy@truvity.com"); m.State != status.StateSynced {
		t.Errorf("cy = %+v, want synced", m)
	}
	if m := findMember(t, report, "", "bob@truvity.com"); m.State != status.StateSynced {
		t.Errorf("bob in the organisation = %+v", m)
	}

	// A maintainer the policy now wants as a member is changed, not removed.
	holders["all:platform:lead"] = live("ada@truvity.com")
	_, did = reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	if !slices.Contains(actions(did), "set-role cy in team-platform") {
		t.Errorf("actions = %v, want cy's role changed", actions(did))
	}
}

// A joiner is invited once, straight into every team that wants them — and
// only at a domain some member has a verified address at, because an
// invitation accepted with an account that verifies nothing there is
// linked to nobody.
func TestAJoinerIsInvitedOnceIntoTheirTeamsOrHeldForAnUnverifiedDomain(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{
		"all:truvity:employee":  live("ada@truvity.com", "new@truvity.com", "partner@trustform.io"),
		"all:platform:engineer": live("new@truvity.com", "partner@trustform.io"),
	}
	state := reconcile.State{
		Members:     []githubapp.Member{{Login: "ada", Emails: []string{"ada@truvity.com"}}},
		Teams:       []githubapp.Team{{ID: 7, Slug: "team-platform"}},
		TeamMembers: map[string][]githubapp.TeamMember{"team-platform": {}},
	}
	report, did := reconcile.Derive("truvity", binding, holders, state).Decide(nil)

	if len(did) != 1 || did[0].Kind != status.ActionInvite || did[0].Email != "new@truvity.com" || !slices.Equal(did[0].Teams, []int64{7}) {
		t.Fatalf("actions = %+v, want one invitation for new@ into team 7", did)
	}
	if m := findMember(t, report, "team-platform", "new@truvity.com"); m.State != status.StatePending || m.Action != status.ActionInvite {
		t.Errorf("new@ in the team = %+v", m)
	}
	held := findMember(t, report, "team-platform", "partner@trustform.io")
	if held.State != status.StateHeld || !strings.Contains(held.Reason, "trustform.io") {
		t.Errorf("partner@ = %+v, want held on the unverified domain", held)
	}

	// Already invited: waiting, nothing sent again.
	state.Invitations = []githubapp.Invitation{{Email: "new@truvity.com"}}
	report, did = reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	if len(did) != 0 {
		t.Errorf("actions for an invited joiner = %v, want none", actions(did))
	}
	if m := findMember(t, report, "", "new@truvity.com"); m.State != status.StateInvited {
		t.Errorf("new@ = %+v, want invited", m)
	}
}

// Somebody who left a team but not the company leaves the team — after
// the directory confirms it — and stays in the organisation.
func TestLeavingATeamIsConfirmedAndLeavesTheOrganisationAlone(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{
		"all:truvity:employee":  live("ada@truvity.com", "moved@truvity.com"),
		"all:platform:engineer": live("ada@truvity.com"),
	}
	state := reconcile.State{
		Members:     []githubapp.Member{{Login: "ada", Emails: []string{"ada@truvity.com"}}, {Login: "moved", Emails: []string{"moved@truvity.com"}}},
		Teams:       []githubapp.Team{{ID: 1, Slug: "team-platform"}},
		TeamMembers: map[string][]githubapp.TeamMember{"team-platform": {{Login: "ada"}, {Login: "moved"}}},
	}
	draft := reconcile.Derive("truvity", binding, holders, state)
	if !slices.Equal(draft.Confirm(), []string{"moved@truvity.com"}) {
		t.Fatalf("confirm = %v, want only moved@", draft.Confirm())
	}

	report, did := draft.Decide(map[string]reconcile.Confirmation{
		"moved@truvity.com": {Authoritative: true, Found: true, Groups: []string{"all:truvity:employee"}},
	})
	if want := []string{"remove moved in team-platform"}; !slices.Equal(actions(did), want) {
		t.Errorf("actions = %v, want %v and nothing about the organisation", actions(did), want)
	}
	if m := findMember(t, report, "team-platform", "moved@truvity.com"); m.State != status.StateLeaving {
		t.Errorf("moved@ = %+v, want leaving", m)
	}
}

// Absence from a holders list is never evidence: the list may be
// incomplete, or a workspace unreadable. Nobody is removed unless the
// directory, asked about that one address, vouches for it.
func TestNobodyIsRemovedOnAnAnswerTheDirectoryCannotVouchFor(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{"all:platform:engineer": live()} // an unreadable workspace: nobody
	state := reconcile.State{
		Members:     []githubapp.Member{{Login: "ada", Emails: []string{"ada@truvity.com"}}},
		Teams:       []githubapp.Team{{ID: 1, Slug: "team-platform"}},
		TeamMembers: map[string][]githubapp.TeamMember{"team-platform": {{Login: "ada"}}},
	}
	draft := reconcile.Derive("truvity", binding, holders, state)

	for name, confirmation := range map[string]map[string]reconcile.Confirmation{
		"not asked":         nil,
		"not authoritative": {"ada@truvity.com": {Authoritative: false, Found: false}},
	} {
		report, did := draft.Decide(confirmation)
		if len(did) != 0 {
			t.Errorf("%s: actions = %v, want none", name, actions(did))
		}
		if m := findMember(t, report, "team-platform", "ada@truvity.com"); m.State != status.StateHeld || m.Reason == "" {
			t.Errorf("%s: ada = %+v, want held with a reason", name, m)
		}
	}

	// The list was merely incomplete: asked, the directory says she holds
	// the group. Synced, nothing to do.
	report, did := draft.Decide(map[string]reconcile.Confirmation{
		"ada@truvity.com": {Authoritative: true, Found: true, Groups: []string{"all:platform:engineer"}},
	})
	if len(did) != 0 || findMember(t, report, "team-platform", "ada@truvity.com").State != status.StateSynced {
		t.Errorf("an incomplete list confirmed = %v, %+v", actions(did), report)
	}
}

// A leaver the directory no longer has leaves the organisation, and so
// every team with it in one call — except an owner, who is held.
func TestALeaverLeavesTheOrganisationButAnOwnerIsHeld(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{"all:truvity:employee": live("ada@truvity.com")}
	state := reconcile.State{
		Members: []githubapp.Member{
			{Login: "ada", Emails: []string{"ada@truvity.com"}},
			{Login: "gone", Emails: []string{"gone@truvity.com"}},
			{Login: "boss", Owner: true, Emails: []string{"boss@truvity.com"}},
		},
		Teams:       []githubapp.Team{{ID: 1, Slug: "team-platform"}},
		TeamMembers: map[string][]githubapp.TeamMember{"team-platform": {{Login: "gone"}}},
	}
	report, did := reconcile.Derive("truvity", binding, holders, state).Decide(map[string]reconcile.Confirmation{
		"gone@truvity.com": {Authoritative: true, Found: true, Suspended: true},
		"boss@truvity.com": {Authoritative: true, Found: false},
	})
	if want := []string{"remove gone in the organisation"}; !slices.Equal(actions(did), want) {
		t.Errorf("actions = %v, want %v: the team removal rides on leaving the organisation", actions(did), want)
	}
	if m := findMember(t, report, "", "boss@truvity.com"); m.State != status.StateHeld || !strings.Contains(m.Reason, "owner") {
		t.Errorf("boss = %+v, want an owner held", m)
	}
}

// A suspended holder is not somebody a team should contain; a person with
// two accounts in two workspaces is one member through either address; and
// an address two accounts claim is linked to neither.
func TestLivenessTwoWorkspacesAndAnAmbiguousAddress(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{
		"all:truvity:employee": {
			{Email: "dual@trustform.io", Live: true},
			{Email: "suspended@truvity.com", Live: false},
			{Email: "shared@truvity.com", Live: true},
		},
	}
	state := reconcile.State{
		Members: []githubapp.Member{
			{Login: "dual", Emails: []string{"dual@truvity.com", "dual@trustform.io"}},
			{Login: "one", Emails: []string{"shared@truvity.com"}},
			{Login: "two", Emails: []string{"shared@truvity.com"}},
		},
		Teams: []githubapp.Team{{ID: 1, Slug: "team-platform"}},
	}
	draft := reconcile.Derive("truvity", binding, holders, state)
	report, did := draft.Decide(nil)

	if m := findMember(t, report, "", "dual@trustform.io"); m.Login != "dual" || m.State != status.StateSynced {
		t.Errorf("dual through the second workspace = %+v", m)
	}
	for _, row := range report.Members {
		if row.Email == "suspended@truvity.com" {
			t.Errorf("a suspended holder has a row: %+v", row)
		}
	}
	shared := findMember(t, report, "", "shared@truvity.com")
	if shared.Login != "" || shared.State != status.StateHeld {
		t.Errorf("an address two accounts claim = %+v, want linked to neither and held", shared)
	}
	if len(did) != 0 {
		t.Errorf("actions = %v, want none", actions(did))
	}
}

// What is never touched: a member with no verified address, even in a
// bound team; a team no binding names; and a team GitHub does not have is
// held rather than created.
func TestUnlinkedMembersUnboundTeamsAndMissingTeamsAreLeftAlone(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{"all:platform:engineer": live("ada@truvity.com")}
	state := reconcile.State{
		Members: []githubapp.Member{
			{Login: "ada", Emails: []string{"ada@truvity.com"}},
			{Login: "bot"},
		},
		// team-platform does not exist; robots is unbound.
		Teams:       []githubapp.Team{{ID: 9, Slug: "robots"}},
		TeamMembers: map[string][]githubapp.TeamMember{"robots": {{Login: "bot"}, {Login: "ada"}}},
	}
	draft := reconcile.Derive("truvity", binding, holders, state)
	report, did := draft.Decide(nil)

	if len(did) != 0 {
		t.Errorf("actions = %v, want none", actions(did))
	}
	if len(report.Unlinked) != 1 || report.Unlinked[0].Login != "bot" {
		t.Errorf("unlinked = %+v, want bot", report.Unlinked)
	}
	if m := findMember(t, report, "team-platform", "ada@truvity.com"); m.State != status.StateHeld || !strings.Contains(m.Reason, "no team team-platform") {
		t.Errorf("ada in a missing team = %+v", m)
	}
	for _, team := range report.Teams {
		if team.Team == "robots" {
			t.Error("an unbound team is in the report")
		}
	}
	if slices.Contains(draft.Confirm(), "") {
		t.Error("an unlinked member was asked about")
	}
}
