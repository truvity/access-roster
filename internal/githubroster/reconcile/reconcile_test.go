package reconcile_test

import (
	"slices"
	"strings"
	"testing"
	"time"

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
	for k := range list {
		out = append(out, list[k].String())
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

func findLogin(t *testing.T, report status.Org, login string, action status.Action) status.Member {
	t.Helper()
	for _, m := range report.Members {
		if m.Login == login && m.Action == action {
			return m
		}
	}
	t.Fatalf("no organisation row for @%s with %s: %+v", login, action, report.Members)
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

// A joiner who linked an account is invited once — as that account,
// straight into every team that wants them, however many addresses they
// linked. A joiner who linked nothing is waiting on themselves: nobody is
// invited, and nothing is held.
func TestAJoinerIsInvitedAsTheAccountTheyLinked(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{
		"all:truvity:employee":  live("ada@truvity.com", "new@truvity.com", "new@trustform.io", "partner@trustform.io"),
		"all:platform:engineer": live("new@truvity.com", "partner@trustform.io"),
	}
	state := reconcile.State{
		Members:     []githubapp.Member{{ID: 1, Login: "ada", Emails: []string{"ada@truvity.com"}}},
		Teams:       []githubapp.Team{{ID: 7, Slug: "team-platform"}},
		TeamMembers: map[string][]githubapp.TeamMember{"team-platform": {}},
		Links:       []reconcile.Link{{ID: 42, Login: "newbie", Emails: []string{"new@truvity.com", "new@trustform.io"}}},
	}
	report, did := reconcile.Derive("truvity", binding, holders, state).Decide(nil)

	if len(did) != 1 || did[0].Kind != status.ActionInvite || did[0].Account != 42 || !slices.Equal(did[0].Teams, []int64{7}) {
		t.Fatalf("actions = %+v, want one invitation for account 42 into team 7", did)
	}
	if m := findMember(t, report, "team-platform", "new@truvity.com"); m.State != status.StatePending || m.Login != "newbie" {
		t.Errorf("new@ in the team = %+v, want pending as @newbie", m)
	}
	waiting := findMember(t, report, "team-platform", "partner@trustform.io")
	if waiting.State != status.StateNotLinked || waiting.Action != "" {
		t.Errorf("partner@ = %+v, want not-linked with nothing to do", waiting)
	}

	// Already invited: waiting, nothing sent again.
	state.Invitations = []githubapp.Invitation{{Login: "newbie"}}
	report, did = reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	if len(did) != 0 {
		t.Errorf("actions for an invited joiner = %v, want none", actions(did))
	}
	if m := findMember(t, report, "", "new@trustform.io"); m.State != status.StateInvited {
		t.Errorf("new@trustform.io = %+v, want invited", m)
	}

	// Once they accept, the link is how they are recognised.
	state.Invitations = nil
	state.Members = append(state.Members, githubapp.Member{ID: 42, Login: "newbie"})
	report, did = reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	if !slices.Equal(actions(did), []string{"add newbie in team-platform"}) {
		t.Errorf("actions after accepting = %v, want newbie added to the team", actions(did))
	}
	if m := findMember(t, report, "", "new@truvity.com"); m.State != status.StateSynced {
		t.Errorf("new@ in the organisation = %+v, want synced", m)
	}
}

// A member whose link GitHub says is gone leaves the organisation at once,
// without asking the directory — the account is no longer shown to be
// anybody's. An owner is held. An account whose link could not be checked
// is simply unlinked, and nothing happens to it.
func TestALostLinkRemovesTheAccountAtOnce(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{
		"all:truvity:employee":  live("ada@truvity.com", "boss@truvity.com"),
		"all:platform:engineer": live("ada@truvity.com"),
	}
	state := reconcile.State{
		Members: []githubapp.Member{
			{ID: 1, Login: "ada"}, {ID: 2, Login: "boss", Owner: true}, {ID: 3, Login: "quiet"},
		},
		Teams:       []githubapp.Team{{ID: 7, Slug: "team-platform"}},
		TeamMembers: map[string][]githubapp.TeamMember{"team-platform": {{Login: "ada"}}},
		Links: []reconcile.Link{
			{ID: 1, Login: "ada", Emails: []string{"ada@truvity.com"}, Lost: true, Reason: "no linked work address is verified"},
			{ID: 2, Login: "boss", Emails: []string{"boss@truvity.com"}, Lost: true, Reason: "revoked"},
		},
	}
	report, did := reconcile.Derive("truvity", binding, holders, state).Decide(nil)

	if !slices.Equal(actions(did), []string{"remove ada in the organisation"}) {
		t.Fatalf("actions = %v, want ada removed from the organisation and nothing else", actions(did))
	}
	if did[0].Reason == "" {
		t.Error("the removal carries no reason")
	}
	ada := findLogin(t, report, "ada", status.ActionRemove)
	if ada.State != status.StateLeaving || !strings.Contains(ada.Reason, "no linked work address") {
		t.Errorf("ada = %+v, want leaving with the link's reason", ada)
	}
	boss := findLogin(t, report, "boss", "")
	if boss.State != status.StateReported || !strings.Contains(boss.Reason, "owner") {
		t.Errorf("boss = %+v, want reported as an owner", boss)
	}
	// The row that still wants ada says why she is not simply synced.
	if wanted := findMember(t, report, "team-platform", "ada@truvity.com"); wanted.State != status.StateNotLinked ||
		!strings.Contains(wanted.Reason, "@ada is gone") {
		t.Errorf("ada in the team = %+v, want not-linked naming the lost link", wanted)
	}
	for _, account := range report.Unlinked {
		if account.Login == "ada" || account.Login == "boss" {
			t.Errorf("%s is listed as unlinked; a lost link is not an unlinked member", account.Login)
		}
	}
	if len(report.Unlinked) != 1 || report.Unlinked[0].Login != "quiet" {
		t.Errorf("unlinked = %+v, want quiet alone", report.Unlinked)
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
		if m := findMember(t, report, "team-platform", "ada@truvity.com"); m.State != status.StateRetrying || m.Reason == "" {
			t.Errorf("%s: ada = %+v, want retrying with a reason", name, m)
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
// every team with it in one call — except an owner, who is reported: owners
// are managed outside.
func TestALeaverLeavesTheOrganisationButAnOwnerIsReported(t *testing.T) {
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
	if m := findLogin(t, report, "boss", ""); m.State != status.StateReported || m.Action != "" || !strings.Contains(m.Reason, "owner") {
		t.Errorf("boss = %+v, want an owner reported, with nothing to do", m)
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

// An account that let two invitations expire since it last linked is not
// invited a third time; linking again starts the count over.
func TestTwoExpiredInvitationsStopTheThird(t *testing.T) {
	t.Parallel()
	linkedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	holders := reconcile.Holders{"all:truvity:employee": live("new@truvity.com")}
	state := reconcile.State{
		Links: []reconcile.Link{{ID: 42, Login: "newbie", Emails: []string{"new@truvity.com"}, LinkedAt: linkedAt}},
	}
	guards := reconcile.Guards{
		Known: true, Plan: githubapp.Plan{Seats: 10, Filled: 1}, LinkedAt: map[int64]time.Time{42: linkedAt},
		Failed: []githubapp.FailedInvitation{
			{Login: "newbie", FailedAt: linkedAt.Add(8 * 24 * time.Hour)},
			{Login: "NEWBIE", FailedAt: linkedAt.Add(16 * 24 * time.Hour)},
		},
	}
	report, did := reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	did = reconcile.Guard(&report, did, guards)
	if len(did) != 0 {
		t.Errorf("actions = %v, want no third invitation", actions(did))
	}
	if m := findMember(t, report, "", "new@truvity.com"); m.State != status.StateIgnored || !strings.Contains(m.Reason, "linking the account again") {
		t.Errorf("new@ = %+v, want ignored, saying how to start over", m)
	}

	// Linked again after both expired: invited again.
	guards.LinkedAt[42] = linkedAt.Add(20 * 24 * time.Hour)
	report, did = reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	if did = reconcile.Guard(&report, did, guards); len(did) != 1 || did[0].Kind != status.ActionInvite {
		t.Errorf("after linking again, actions = %v, want one invitation", actions(did))
	}
}

// Nobody is invited past the last free seat, pending invitations taking one
// each, and nobody at all while the seats cannot be read.
func TestInvitationsStopAtTheLastFreeSeat(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{"all:truvity:employee": live("a@truvity.com", "b@truvity.com", "c@truvity.com")}
	state := reconcile.State{Links: []reconcile.Link{
		{ID: 1, Login: "a", Emails: []string{"a@truvity.com"}},
		{ID: 2, Login: "b", Emails: []string{"b@truvity.com"}},
		{ID: 3, Login: "c", Emails: []string{"c@truvity.com"}},
	}}
	report, did := reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	did = reconcile.Guard(&report, did, reconcile.Guards{Known: true, Plan: githubapp.Plan{Seats: 30, Filled: 28}, Pending: 1})
	if len(did) != 1 {
		t.Errorf("actions = %v, want exactly one invitation for the one free seat", actions(did))
	}
	if report.Seats == nil || report.Seats.Free != 1 || report.Seats.Short != 2 {
		t.Errorf("seats = %+v, want one free and two short", report.Seats)
	}
	held := 0
	for _, m := range report.Members {
		if m.State == status.StateHeld && strings.Contains(m.Reason, "no free seat") {
			held++
		}
	}
	if held != 2 {
		t.Errorf("rows held for a seat = %d, want 2: %+v", held, report.Members)
	}

	report, did = reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	if did = reconcile.Guard(&report, did, reconcile.Guards{Known: false}); len(did) != 0 {
		t.Errorf("with unreadable seats, actions = %v, want none", actions(did))
	}
	if m := findMember(t, report, "", "a@truvity.com"); !strings.Contains(m.Reason, "organisation administration") {
		t.Errorf("a@ = %+v, want held on the missing permission", m)
	}
}

// A pass removing more than half the organisation removes nobody until an
// operator confirms exactly that set; a different set needs confirming
// again. Half exactly is not more than half.
func TestMassRemovalWaitsForConfirmation(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{"all:truvity:employee": live("stay@truvity.com")}
	members := []githubapp.Member{{ID: 1, Login: "stay", Emails: []string{"stay@truvity.com"}}}
	confirmations := map[string]reconcile.Confirmation{}
	for _, login := range []string{"x", "y", "z"} {
		email := login + "@truvity.com"
		members = append(members, githubapp.Member{Login: login, Emails: []string{email}})
		confirmations[email] = reconcile.Confirmation{Authoritative: true, Found: false}
	}
	state := reconcile.State{Members: members}

	report, did := reconcile.Derive("truvity", binding, holders, state).Decide(confirmations)
	did = reconcile.Guard(&report, did, reconcile.Guards{Known: true, Plan: githubapp.Plan{Seats: 10}, Members: 4})
	if len(did) != 0 || report.Breaker == nil || report.Breaker.Affected != 3 || report.Breaker.Confirmed {
		t.Fatalf("actions = %v, breaker = %+v; want nothing removed and the breaker open", actions(did), report.Breaker)
	}
	if m := findLogin(t, report, "x", status.ActionRemove); m.State != status.StateHeld || !strings.Contains(m.Reason, "confirms") {
		t.Errorf("x = %+v, want held for confirmation", m)
	}
	fingerprint := report.Breaker.Fingerprint

	report, did = reconcile.Derive("truvity", binding, holders, state).Decide(confirmations)
	if did = reconcile.Guard(&report, did, reconcile.Guards{Known: true, Members: 4, Confirmed: fingerprint}); len(did) != 3 || !report.Breaker.Confirmed {
		t.Errorf("confirmed: actions = %v, want the three removals", actions(did))
	}

	// One more leaver changes the set: the old confirmation does not cover it.
	state.Members = append(state.Members, githubapp.Member{Login: "w", Emails: []string{"w@truvity.com"}})
	confirmations["w@truvity.com"] = reconcile.Confirmation{Authoritative: true, Found: false}
	report, did = reconcile.Derive("truvity", binding, holders, state).Decide(confirmations)
	if did = reconcile.Guard(&report, did, reconcile.Guards{Known: true, Members: 5, Confirmed: fingerprint}); len(did) != 0 {
		t.Errorf("a changed set went ahead on an old confirmation: %v", actions(did))
	}

	// Two of four is half, not more than half: no breaker.
	state.Members = members[:3]
	delete(confirmations, "z@truvity.com")
	report, did = reconcile.Derive("truvity", binding, holders, state).Decide(confirmations)
	if did = reconcile.Guard(&report, did, reconcile.Guards{Known: true, Members: 4}); len(did) != 2 || report.Breaker != nil {
		t.Errorf("half: actions = %v, breaker = %+v; want both removals and no breaker", actions(did), report.Breaker)
	}
}

// An owner is added to a team the policy wants them in and promoted in one,
// and never removed from a team or demoted: owners are managed outside, and
// a break-glass seat keeps what it has.
func TestAnOwnerIsAddedAndPromotedButNeverRemovedOrDemoted(t *testing.T) {
	t.Parallel()
	holders := reconcile.Holders{
		"all:truvity:employee":  live("boss@truvity.com", "it@truvity.com", "lead@truvity.com"),
		"all:platform:engineer": live("boss@truvity.com", "lead@truvity.com"),
		"all:platform:lead":     live("lead@truvity.com"),
	}
	state := reconcile.State{
		Members: []githubapp.Member{
			{Login: "boss", Owner: true, Emails: []string{"boss@truvity.com"}},
			{Login: "it", Owner: true, Emails: []string{"it@truvity.com"}},
			{Login: "lead", Owner: true, Emails: []string{"lead@truvity.com"}},
		},
		Teams: []githubapp.Team{{ID: 1, Slug: "team-platform"}},
		// boss maintains the team and the policy wants a member; it is in the
		// team and the policy does not want it there; lead is a member the
		// policy wants as maintainer.
		TeamMembers: map[string][]githubapp.TeamMember{"team-platform": {
			{Login: "boss", Maintainer: true}, {Login: "it", Maintainer: true}, {Login: "lead"},
		}},
	}
	report, did := reconcile.Derive("truvity", binding, holders, state).Decide(nil)

	if want := []string{"set-role lead in team-platform"}; !slices.Equal(actions(did), want) {
		t.Errorf("actions = %v, want only lead promoted", actions(did))
	}
	var boss, it status.Member
	for _, team := range report.Teams {
		for _, m := range team.Members {
			switch m.Login {
			case "boss":
				boss = m
			case "it":
				it = m
			}
		}
	}
	if boss.State != status.StateReported || boss.Role != status.RoleMaintainer || boss.Action != "" {
		t.Errorf("boss = %+v, want reported, still maintainer, nothing to do", boss)
	}
	if it.State != status.StateReported || it.Action != "" {
		t.Errorf("it = %+v, want reported and left in the team", it)
	}

	// An owner the policy wants in a team they are not in is added.
	state.TeamMembers = map[string][]githubapp.TeamMember{"team-platform": {}}
	_, did = reconcile.Derive("truvity", binding, holders, state).Decide(nil)
	if !slices.Contains(actions(did), "add boss in team-platform") {
		t.Errorf("actions = %v, want boss added", actions(did))
	}
}
