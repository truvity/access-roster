// Package reconcile is what the GitHub controller decides, with no network
// in it: from the policy's bindings, the holders of the groups they name,
// and what GitHub holds, what one organisation should look like and what
// to change to get there.
//
// It runs in two steps because removing somebody needs one more question
// than adding them. [Derive] works out everything the inputs settle, and
// names the addresses whose removal would rest on ABSENCE from a holders
// list — which is never evidence on its own: an unreadable workspace
// contributes no holders at all. [Decide] finishes once each of those
// addresses has been asked about one at a time, and removes only on an
// answer the directory vouches for.
//
// Who a GitHub account belongs to is what its person LINKED: they
// authorized the link App as that account, and GitHub verified the work
// addresses the link proves. GitHub discloses nothing else about a
// member's addresses outside its Enterprise Cloud plan, where the
// organisation's verified-domain addresses count as well.
//
// What is never touched, whatever the inputs: a member nobody linked
// (nobody can say who they are), a team no binding names, and an owner's
// place in the organisation. An owner is added to teams and promoted in
// them like anybody, and never removed from a team or demoted in one:
// owners are managed outside, and a break-glass seat keeps what it has. The one removal that does not ask the
// directory is an account whose link GitHub itself says is gone — the
// person removed the address, or revoked the authorization.
package reconcile

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/policy"
)

// Holder is one account holding a group, as the directory reports it.
type Holder struct {
	Email string
	// Live is false for a suspended account, which is not somebody a team
	// should contain.
	Live bool
}

// Holders are each bound group's holders.
type Holders map[string][]Holder

// State is what GitHub holds for one organisation.
type State struct {
	Members     []githubapp.Member
	Invitations []githubapp.Invitation
	Teams       []githubapp.Team
	// TeamMembers are each bound team's members, by slug. A bound team
	// missing here does not exist on GitHub.
	TeamMembers map[string][]githubapp.TeamMember
	// Links are the accounts people linked, as last checked. A link that
	// could not be checked is not here at all: it neither adds anybody nor
	// removes anybody.
	Links []Link
}

// Link is one linked GitHub account.
type Link struct {
	ID     int64
	Login  string
	Emails []string
	// Lost is GitHub's own answer that the link's proof is gone. The
	// account leaves the organisation.
	Lost   bool
	Reason string
	// LinkedAt is when the person last linked: invitations that expired
	// before it do not count against them.
	LinkedAt time.Time
}

// Confirmation is the directory's answer about one address, asked before
// anybody is removed on its account.
type Confirmation struct {
	// Authoritative is whether the directory can vouch for the answer. A
	// removal never rests on anything else.
	Authoritative bool
	Found         bool
	Suspended     bool
	// Groups are the internal groups the address holds.
	Groups []string
}

// Gone reports an address the directory authoritatively no longer has, or
// has suspended.
func (c Confirmation) Gone() bool { return c.Authoritative && (!c.Found || c.Suspended) }

// Action is one change to GitHub.
type Action struct {
	Kind status.Action
	// Team is the slug it concerns; empty for the organisation itself.
	Team  string
	Login string
	Email string
	Role  status.Role
	// Teams are the ids an invitation places the invitee in.
	Teams []int64
	// Account is the linked account an invitation is for.
	Account int64
	// Reason is why a removal happens, when it is not the directory's.
	Reason string
}

func (a Action) String() string {
	where := a.Team
	if where == "" {
		where = "the organisation"
	}
	who := a.Login
	if who == "" {
		who = a.Email
	}
	return fmt.Sprintf("%s %s in %s", a.Kind, who, where)
}

// Draft is an organisation derived as far as its inputs allow.
type Draft struct {
	org     string
	binding policy.GitHubOrg

	// desired: team slug ("" for the organisation) -> address -> role.
	desired map[string]map[string]status.Role
	// anywhere is every address desired somewhere in the organisation.
	anywhere map[string]bool

	loginOf   map[string]string // address -> login
	ambiguous map[string][]string
	emailsOf  map[string][]string // login -> addresses
	owner     map[string]bool
	invited   map[string]bool // addresses and lowercased logins with a pending invitation
	teamID    map[string]int64
	current   map[string]map[string]bool // slug -> login -> maintainer
	// outside are linked accounts that are not members, by address.
	outside map[string]Link
	// lost are members whose link GitHub says is gone: login -> the link.
	lost       map[string]Link
	unlinked   []status.Account
	candidates map[string]bool // addresses to confirm
}

// Confirm is the addresses whose removal needs asking about, sorted.
func (d *Draft) Confirm() []string { return slices.Sorted(maps.Keys(d.candidates)) }

// Derive works out one organisation from its binding, the holders of the
// groups it names, and what GitHub holds.
func Derive(org string, binding policy.GitHubOrg, holders Holders, state State) *Draft {
	d := &Draft{
		org: org, binding: binding,
		desired: map[string]map[string]status.Role{}, anywhere: map[string]bool{},
		loginOf: map[string]string{}, ambiguous: map[string][]string{}, emailsOf: map[string][]string{},
		owner: map[string]bool{}, invited: map[string]bool{}, teamID: map[string]int64{},
		current: map[string]map[string]bool{}, outside: map[string]Link{}, lost: map[string]Link{},
		candidates: map[string]bool{},
	}

	ignoredAddress, ignoredLogin := binding.IgnoredAddresses(), binding.IgnoredLogins()
	// kept filters an account's addresses down to the ones not ignored, and
	// says whether the account is to be left alone: its login is ignored,
	// or every address it had is.
	kept := func(login string, emails []string) ([]string, bool) {
		if ignoredLogin[strings.ToLower(login)] {
			return nil, true
		}
		out := make([]string, 0, len(emails))
		for _, email := range emails {
			if !ignoredAddress[strings.ToLower(email)] {
				out = append(out, email)
			}
		}
		return out, len(emails) > 0 && len(out) == 0
	}
	skipped := map[string]bool{}

	want := func(scope, email string, role status.Role) {
		if d.desired[scope] == nil {
			d.desired[scope] = map[string]status.Role{}
		}
		// The wider role wins: a lead is a lead even where a member group
		// also names them.
		if d.desired[scope][email] != status.RoleMaintainer {
			d.desired[scope][email] = role
		}
		d.anywhere[email] = true
	}
	live := func(group string, each func(string)) {
		for _, h := range holders[group] {
			if email := strings.ToLower(strings.TrimSpace(h.Email)); h.Live && !ignoredAddress[email] {
				each(email)
			}
		}
	}
	for _, group := range binding.Members {
		live(group, func(email string) { want("", email, status.RoleMember) })
	}
	for _, slug := range slices.Sorted(maps.Keys(binding.Teams)) {
		team := binding.Teams[slug]
		for _, group := range team.Members {
			live(group, func(email string) { want(slug, email, status.RoleMember) })
		}
		for _, group := range team.Maintainers {
			live(group, func(email string) { want(slug, email, status.RoleMaintainer) })
		}
	}

	links := map[int64]Link{}
	for _, l := range state.Links {
		links[l.ID] = l
	}
	members := map[int64]bool{}
	for _, member := range state.Members {
		members[member.ID] = true
		emails := slices.Clone(member.Emails)
		l, linked := links[member.ID]
		if linked {
			emails = append(emails, l.Emails...)
		}
		// Left alone: not in the report, not a candidate for anything.
		if rest, alone := kept(member.Login, emails); alone {
			skipped[member.Login] = true
			continue
		} else if linked && !l.Lost {
			emails = rest
		} else {
			emails, _ = kept(member.Login, member.Emails)
		}
		d.owner[member.Login] = member.Owner
		if len(emails) == 0 {
			if linked && l.Lost {
				d.lost[member.Login] = l
				continue
			}
			d.unlinked = append(d.unlinked, status.Account{
				Login: member.Login, Reason: "has not linked this account to a work address",
			})
			continue
		}
		for _, email := range emails {
			email = strings.ToLower(email)
			if slices.Contains(d.emailsOf[member.Login], email) {
				continue
			}
			d.emailsOf[member.Login] = append(d.emailsOf[member.Login], email)
			if other, taken := d.loginOf[email]; taken && other != member.Login {
				d.ambiguous[email] = appendUnique(appendUnique(d.ambiguous[email], other), member.Login)
				continue
			}
			d.loginOf[email] = member.Login
		}
	}
	// An address two accounts claim is linked to neither: acting on one of
	// them is a guess about which person it is.
	for email := range d.ambiguous {
		delete(d.loginOf, email)
	}
	// Linked accounts that are not members yet: who an invitation goes to.
	for _, l := range state.Links {
		if l.Lost || members[l.ID] {
			continue
		}
		emails, alone := kept(l.Login, l.Emails)
		if alone {
			continue
		}
		for _, email := range emails {
			email = strings.ToLower(email)
			if other, taken := d.outside[email]; taken && other.ID != l.ID {
				d.ambiguous[email] = appendUnique(appendUnique(d.ambiguous[email], other.Login), l.Login)
				continue
			}
			d.outside[email] = l
		}
	}
	for _, invitation := range state.Invitations {
		if invitation.Email != "" {
			d.invited[strings.ToLower(invitation.Email)] = true
		}
		if invitation.Login != "" {
			d.invited["@"+strings.ToLower(invitation.Login)] = true
		}
	}
	for _, team := range state.Teams {
		d.teamID[team.Slug] = team.ID
	}
	for slug, members := range state.TeamMembers {
		d.current[slug] = map[string]bool{}
		for _, m := range members {
			if skipped[m.Login] || ignoredLogin[strings.ToLower(m.Login)] {
				continue
			}
			d.current[slug][m.Login] = m.Maintainer
		}
	}

	// Removal candidates: members of a bound team none of whose addresses
	// that team wants, and members none of whose addresses the
	// organisation wants anywhere. Each is asked about before anything
	// happens to them.
	for slug := range binding.Teams {
		for login := range d.current[slug] {
			emails := d.emailsOf[login]
			if len(emails) == 0 || d.owner[login] || d.wantsAny(slug, emails) {
				continue
			}
			for _, email := range emails {
				d.candidates[email] = true
			}
		}
	}
	for _, emails := range d.emailsOf {
		if !d.wantsAnywhere(emails) {
			for _, email := range emails {
				d.candidates[email] = true
			}
		}
	}
	return d
}

func (d *Draft) wantsAny(scope string, emails []string) bool {
	for _, email := range emails {
		if _, ok := d.desired[scope][email]; ok {
			return true
		}
	}
	return false
}

func (d *Draft) wantsAnywhere(emails []string) bool {
	for _, email := range emails {
		if d.anywhere[email] {
			return true
		}
	}
	return false
}

// Decide finishes the organisation: its report, and the changes to make.
// Every change is returned whether or not the organisation is enabled —
// the report of a disabled one says what WOULD happen — and held changes
// are in the report and not in the list.
func (d *Draft) Decide(confirmations map[string]Confirmation) (status.Org, []Action) {
	out := status.Org{Org: d.org, Unlinked: slices.Clone(d.unlinked)}
	var actions []Action
	hold := func(member *status.Member, action status.Action, reason string) {
		member.State, member.Action, member.Reason = status.StateHeld, action, reason
	}

	// Somebody wanted who is not a member is invited once — as the account
	// they linked, into every team that wants them, however many team rows
	// and addresses show it. Somebody who linked no account is waiting on
	// themselves, not held: there is nobody to invite yet.
	var invites []*Action
	// lostBy says, for an address whose link is gone, which account it was
	// and why — so the row that wants them says more than "not linked".
	lostBy := map[string]string{}
	for login, l := range d.lost {
		for _, email := range l.Emails {
			lostBy[strings.ToLower(email)] = "the link to @" + login + " is gone (" + l.Reason + ")"
		}
	}
	inviting := map[int64]*Action{}
	inviteHeld := map[string]string{}
	notLinked := map[string]bool{}
	for _, email := range slices.Sorted(maps.Keys(d.anywhere)) {
		if _, linked := d.loginOf[email]; linked || d.invited[email] {
			continue
		}
		if logins, clash := d.ambiguous[email]; clash {
			inviteHeld[email] = fmt.Sprintf("%s is linked to more than one account (%s)", email, strings.Join(logins, ", "))
			continue
		}
		account, has := d.outside[email]
		if !has {
			notLinked[email] = true
			continue
		}
		if d.invited["@"+strings.ToLower(account.Login)] {
			continue
		}
		invite, started := inviting[account.ID]
		if !started {
			invite = &Action{Kind: status.ActionInvite, Email: email, Login: account.Login, Account: account.ID, Role: status.RoleMember}
			inviting[account.ID] = invite
			invites = append(invites, invite)
		}
		for _, slug := range slices.Sorted(maps.Keys(d.binding.Teams)) {
			if _, wanted := d.desired[slug][email]; wanted {
				if id, exists := d.teamID[slug]; exists && !slices.Contains(invite.Teams, id) {
					invite.Teams = append(invite.Teams, id)
				}
			}
		}
	}
	for _, invite := range invites {
		slices.Sort(invite.Teams)
		actions = append(actions, *invite)
	}

	row := func(scope, email string, role status.Role) status.Member {
		member := status.Member{Email: email, Role: role}
		login, linked := d.loginOf[email]
		member.Login = login
		account, outside := d.outside[email]
		if !linked && outside {
			member.Login = account.Login
		}
		switch {
		case !linked && (d.invited[email] || (outside && d.invited["@"+strings.ToLower(account.Login)])):
			member.State = status.StateInvited
		case !linked && inviteHeld[email] != "":
			hold(&member, status.ActionInvite, inviteHeld[email])
		case !linked && notLinked[email] && lostBy[email] != "":
			member.State, member.Reason = status.StateNotLinked, lostBy[email]+": link the account again"
		case !linked && notLinked[email]:
			member.State, member.Reason = status.StateNotLinked, email+" has not linked a GitHub account"
		case !linked:
			member.State, member.Action = status.StatePending, status.ActionInvite
		case scope == "":
			member.State = status.StateSynced
		default:
			current, in := d.current[scope][login]
			switch {
			case !in:
				member.State, member.Action = status.StatePending, status.ActionAdd
				actions = append(actions, Action{Kind: status.ActionAdd, Team: scope, Login: login, Email: email, Role: role})
			case d.owner[login] && current && role != status.RoleMaintainer:
				// An owner is never demoted: owners are managed outside, and a
				// break-glass seat keeps whatever it was given.
				member.State, member.Role = status.StateReported, status.RoleMaintainer
				member.Reason = "an owner, kept as maintainer: owners are added and promoted, never demoted"
			case current != (role == status.RoleMaintainer):
				member.State, member.Action = status.StatePending, status.ActionSetRole
				actions = append(actions, Action{Kind: status.ActionSetRole, Team: scope, Login: login, Email: email, Role: role})
			default:
				member.State = status.StateSynced
			}
		}
		return member
	}

	for _, email := range slices.Sorted(maps.Keys(d.desired[""])) {
		out.Members = append(out.Members, row("", email, d.desired[""][email]))
	}

	for _, slug := range slices.Sorted(maps.Keys(d.binding.Teams)) {
		team := status.Team{Team: slug}
		if _, exists := d.teamID[slug]; !exists {
			// The structure engine creates teams; this never does. Every
			// member of a team that is not there is held on that.
			for _, email := range slices.Sorted(maps.Keys(d.desired[slug])) {
				member := status.Member{Email: email, Login: d.loginOf[email], Role: d.desired[slug][email]}
				hold(&member, status.ActionAdd, fmt.Sprintf("%s has no team %s", d.org, slug))
				team.Members = append(team.Members, member)
			}
			out.Teams = append(out.Teams, team)
			continue
		}
		for _, email := range slices.Sorted(maps.Keys(d.desired[slug])) {
			team.Members = append(team.Members, row(slug, email, d.desired[slug][email]))
		}
		// The team's members nothing wants: confirmed, then removed.
		for _, login := range slices.Sorted(maps.Keys(d.current[slug])) {
			emails := d.emailsOf[login]
			if len(emails) == 0 || d.wantsAny(slug, emails) {
				continue
			}
			member := status.Member{Login: login, Email: emails[0], Role: roleOf(d.current[slug][login])}
			if d.owner[login] {
				// Never removed from a team, for the reason an owner is never
				// demoted in one.
				member.State, member.Reason = status.StateReported, "an owner, left in the team: owners are added and promoted, never removed"
				team.Members = append(team.Members, member)
				continue
			}
			switch reason, remove := d.confirmTeamRemoval(slug, emails, confirmations); {
			case remove:
				member.State, member.Action = status.StateLeaving, status.ActionRemove
				actions = append(actions, Action{Kind: status.ActionRemove, Team: slug, Login: login, Email: emails[0]})
			case reason != "":
				// The directory could not be asked, or could not vouch: that
				// clears on its own, and the removal is tried again.
				member.State, member.Action, member.Reason = status.StateRetrying, status.ActionRemove, reason
			default:
				// Absent from the holders and confirmed as holding the group:
				// the holders list was incomplete. Nothing to do.
				member.State = status.StateSynced
			}
			team.Members = append(team.Members, member)
		}
		out.Teams = append(out.Teams, team)
	}

	// The organisation itself: only somebody the directory authoritatively
	// no longer has leaves it, and never an owner.
	for _, login := range slices.Sorted(maps.Keys(d.emailsOf)) {
		emails := d.emailsOf[login]
		if d.wantsAnywhere(emails) || !d.allGone(emails, confirmations) {
			continue
		}
		member := status.Member{Login: login, Email: emails[0], Role: status.RoleMember}
		if d.owner[login] {
			member.State, member.Reason = status.StateReported, "an owner, managed outside: the directory no longer has them"
		} else {
			member.State, member.Action = status.StateLeaving, status.ActionRemove
			actions = append(actions, Action{Kind: status.ActionRemove, Login: login, Email: emails[0]})
		}
		out.Members = append(out.Members, member)
	}

	// An account whose link GitHub says is gone leaves at once: the person
	// removed the work address from it or revoked the authorization, and
	// either way it is no longer shown to be theirs.
	for _, login := range slices.Sorted(maps.Keys(d.lost)) {
		l := d.lost[login]
		member := status.Member{Login: login, Role: status.RoleMember, Reason: "the link is gone: " + l.Reason}
		if len(l.Emails) > 0 {
			member.Email = l.Emails[0]
		}
		if d.owner[login] {
			member.State, member.Reason = status.StateReported, "an owner, managed outside: the link is gone ("+l.Reason+")"
		} else {
			member.State, member.Action = status.StateLeaving, status.ActionRemove
			actions = append(actions, Action{Kind: status.ActionRemove, Login: login, Email: member.Email, Reason: member.Reason})
		}
		out.Members = append(out.Members, member)
	}

	return out, dropTeamWorkForLeavers(actions)
}

// confirmTeamRemoval says whether a member leaves a team, or why not.
func (d *Draft) confirmTeamRemoval(slug string, emails []string, confirmations map[string]Confirmation) (reason string, remove bool) {
	groups := d.binding.Teams[slug].Groups()
	for _, email := range emails {
		c, asked := confirmations[email]
		switch {
		case !asked:
			return "the directory was not asked about " + email, false
		case !c.Authoritative:
			return "the directory cannot vouch for " + email + " right now", false
		case c.Found && !c.Suspended && holdsAny(c.Groups, groups):
			return "", false
		}
	}
	return "", true
}

// allGone reports whether every address of a member is one the directory
// authoritatively no longer has.
func (d *Draft) allGone(emails []string, confirmations map[string]Confirmation) bool {
	for _, email := range emails {
		if c, asked := confirmations[email]; !asked || !c.Gone() {
			return false
		}
	}
	return true
}

// dropTeamWorkForLeavers removes team changes for somebody leaving the
// organisation: leaving it takes them out of every team at once, and a
// team removal first would only be a second call to the same end.
func dropTeamWorkForLeavers(actions []Action) []Action {
	leaving := map[string]bool{}
	for k := range actions {
		if a := &actions[k]; a.Kind == status.ActionRemove && a.Team == "" {
			leaving[a.Login] = true
		}
	}
	out := actions[:0]
	for k := range actions {
		if actions[k].Team != "" && leaving[actions[k].Login] {
			continue
		}
		out = append(out, actions[k])
	}
	return out
}

func roleOf(maintainer bool) status.Role {
	if maintainer {
		return status.RoleMaintainer
	}
	return status.RoleMember
}

func holdsAny(held, wanted []string) bool {
	for _, group := range wanted {
		if slices.Contains(held, group) {
			return true
		}
	}
	return false
}

func appendUnique(list []string, value string) []string {
	if slices.Contains(list, value) {
		return list
	}
	return append(list, value)
}
