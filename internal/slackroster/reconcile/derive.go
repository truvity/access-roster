package reconcile

import (
	"fmt"
	"maps"
	"slices"

	"github.com/truvity/access-roster/internal/slackroster/status"
)

type resKind int

const (
	resOK resKind = iota
	resCreate
	resJoin
	resAccept
	resHeld
	resWaiting
)

// resolved is what the inputs say about one channel's existence.
type resolved struct {
	kind   resKind
	reason string
	// adopted marks a bound channel that exists, was not made by the bot and
	// is being managed: taken over by name or by `adopt`.
	adopted bool
	// change names what a hold is about: create, adopt, share.
	change string
	ch     *Channel
	invite *Invite
}

// usable says people can be invited: the channel exists, or this pass
// makes it exist.
func (r resolved) usable() bool {
	return r.kind == resOK || r.kind == resCreate || r.kind == resJoin || r.kind == resAccept
}

// extra is a member of a channel the bindings do not name.
type extra struct {
	member Member
	key    string
	addrs  []string
	// inDomain: the address is one of this workspace's own.
	inDomain bool
}

// plan is one channel's derived state.
type plan struct {
	lc  layoutChannel
	res resolved
	// notes are share-level remarks; heldShare makes them a hold.
	notes     []string
	heldShare bool

	rows       []status.Member
	chanActs   []Action
	shareActs  []Action
	inviteActs []Action
	held       []Held

	// members is the set of user ids in the channel, when usable and read.
	members map[string]bool
	extras  []extra
}

// Draft is everything the inputs settle, waiting for the directory's
// answers about [Draft.Confirm] before removal is decided.
type Draft struct {
	in    Input
	r     resolver
	plans []*plan
}

func visibility(private bool) string {
	if private {
		return "private"
	}
	return "public"
}

func (d *Draft) byID(id string) *Channel {
	for i := range d.in.Observed.Channels {
		if d.in.Observed.Channels[i].ID == id {
			return &d.in.Observed.Channels[i]
		}
	}
	return nil
}

func (d *Draft) byName(name string) *Channel {
	for i := range d.in.Observed.Channels {
		if d.in.Observed.Channels[i].Name == name {
			return &d.in.Observed.Channels[i]
		}
	}
	return nil
}

// ready checks an existing channel the bot is to manage: visibility agrees,
// the bot is in or can join.
func ready(ch *Channel, private bool, joinable bool) resolved {
	switch {
	case ch.Private != private:
		return resolved{kind: resHeld, ch: ch, change: "adopt",
			reason: fmt.Sprintf("the channel is %s in Slack but the policy says %s; change one of them, the roster never changes visibility",
				visibility(ch.Private), visibility(private))}
	case !ch.BotIn && ch.Private:
		return resolved{kind: resHeld, ch: ch, change: "adopt", reason: "the bot is not in this private channel: invite the bot first"}
	case !ch.BotIn && joinable:
		return resolved{kind: resJoin, ch: ch}
	case !ch.BotIn:
		return resolved{kind: resHeld, ch: ch, change: "adopt", reason: "the bot is not in this channel"}
	}
	return resolved{kind: resOK, ch: ch}
}

// resolveBound is where a bound channel stands: an idempotent upsert. It is
// created when no channel of that name is visible, and otherwise taken over
// BY NAME (or by `adopt`, which only disambiguates). Visibility is never
// converted, an archived channel is never unarchived, and a channel the bot
// cannot see is found out when creating it is refused (see package apply).
func (d *Draft) resolveBound(lc layoutChannel) resolved {
	var ch *Channel
	if id := lc.binding.Adopt; id != "" {
		ch = d.byID(id)
		switch {
		case ch == nil:
			return resolved{kind: resHeld, change: "adopt",
				reason: "adopt " + id + ": the bot cannot see that channel; if it is private, invite the bot first, otherwise check the id"}
		case ch.Shared:
			return resolved{kind: resHeld, ch: ch, change: "adopt",
				reason: "adopt " + id + " is a Slack Connect channel; it is managed as a shared channel, not bound here"}
		}
	} else if ch = d.byName(lc.name); ch == nil {
		return resolved{kind: resCreate}
	} else if ch.Shared {
		return resolved{kind: resHeld, ch: ch, change: "adopt",
			reason: "a channel named " + lc.name + " (" + ch.ID + ") is a Slack Connect channel; it is managed as a shared channel, not bound here"}
	}
	if ch.Archived {
		return resolved{kind: resHeld, ch: ch, change: "adopt",
			reason: archivedReason(lc.name, ch.ID)}
	}
	res := ready(ch, lc.private, true)
	res.adopted = res.usable() && ch.Creator != d.in.Observed.BotUserID
	return res
}

// archivedReason is why an archived channel of a bound name is held.
func archivedReason(name, id string) string {
	return "the channel " + name + " (" + id + ") is archived: unarchive it in Slack or rename it; the roster never unarchives"
}

// resolveHost is where the host's side of a shared channel stands. With a
// recorded channel id it takes over exactly that channel; without one, the
// channel of the declared name the bot made, or one that is already shared
// (it is the channel the record means). A channel of that name that is
// neither, which the roster did not make, is held, never taken over.
func (d *Draft) resolveHost(lc layoutChannel) resolved {
	var ch *Channel
	if id := lc.shared.ChannelID; id != "" {
		if ch = d.byID(id); ch == nil {
			return resolved{kind: resHeld, change: "adopt",
				reason: "the recorded channel " + id + " is not visible to the bot; if it is private, invite the bot to it first, otherwise check the id"}
		}
	} else if ch = d.byName(lc.name); ch == nil {
		return resolved{kind: resCreate}
	}
	if ch.Archived {
		// Archived channels keep their name: never join, unarchive or
		// create a second one beside it.
		return resolved{kind: resHeld, ch: ch, change: "create", reason: archivedReason(lc.name, ch.ID)}
	}
	madeHere := ch.Creator == d.in.Observed.BotUserID
	if lc.shared.ChannelID == "" && !madeHere && !ch.Shared {
		return resolved{kind: resHeld, ch: ch, change: "create",
			reason: "a channel named " + lc.name + " already exists here (" + ch.ID + ") and this roster did not create it"}
	}
	res := ready(ch, lc.private, true)
	res.adopted = res.usable() && !madeHere
	return res
}

// resolveGuest is where a guest side stands: the channel is visible here
// already (by the recorded id, else by name) and is taken over, joined when
// it is public and the bot is not in it; or the host's invitation is
// accepted; or this side waits.
func (d *Draft) resolveGuest(lc layoutChannel) resolved {
	obs := d.in.Observed
	id := lc.shared.ChannelID
	var ch *Channel
	if id != "" {
		ch = d.byID(id)
	} else {
		ch = d.byName(lc.name)
	}
	if ch != nil {
		if ch.Archived {
			return resolved{kind: resHeld, ch: ch, change: "share", reason: archivedReason(lc.name, ch.ID)}
		}
		if !ch.Shared {
			return resolved{kind: resHeld, ch: ch, change: "share",
				reason: "a channel named " + lc.name + " already exists here and is not the shared channel"}
		}
		res := ready(ch, lc.private, true)
		res.adopted = res.kind == resJoin
		return res
	}
	host := d.in.Facts[lc.shared.Host].Team
	for i := range obs.Invites {
		inv := &obs.Invites[i]
		if host == "" || !inv.Incoming || inv.HostTeamID != host || inv.RecipientUserID != obs.BotUserID {
			continue
		}
		if (id != "" && inv.ChannelID == id) || (id == "" && inv.ChannelName == lc.name) {
			return resolved{kind: resAccept, invite: inv}
		}
	}
	if id != "" {
		return resolved{kind: resWaiting, reason: "the channel " + id + " is not visible to this workspace's bot: waiting for " + lc.shared.Host +
			" to invite this workspace, or, if it is already shared and private on this side, invite the bot to it"}
	}
	return resolved{kind: resWaiting, reason: "waiting for " + lc.shared.Host + " to invite this workspace"}
}

// Derive works out everything the inputs settle. It fails with
// [ErrIncomplete] when the read behind the inputs was not whole.
func Derive(in Input) (*Draft, error) {
	if _, ok := in.Workspaces[in.Workspace]; !ok {
		return nil, fmt.Errorf("reconcile: workspace %q is not declared", in.Workspace)
	}
	d := &Draft{in: in, r: newResolver(in)}
	layout := d.r.layout()
	for i := range layout {
		p, err := d.derive(layout[i])
		if err != nil {
			return nil, err
		}
		d.plans = append(d.plans, p)
	}
	return d, nil
}

func (d *Draft) derive(lc layoutChannel) (*plan, error) {
	obs := d.in.Observed
	p := &plan{lc: lc}
	switch {
	case lc.shared == nil:
		p.res = d.resolveBound(lc)
	case lc.shared.Host == d.in.Workspace:
		p.res = d.resolveHost(lc)
	default:
		p.res = d.resolveGuest(lc)
	}
	ch := p.res.ch
	switch p.res.kind {
	case resCreate:
		p.chanActs = append(p.chanActs, Action{Kind: status.ActionCreate, Channel: lc.name, Private: lc.private, Shared: lc.shared != nil,
			Reason: "the policy binds a channel that does not exist"})
	case resJoin:
		p.chanActs = append(p.chanActs, Action{Kind: status.ActionAdopt, Channel: lc.name, ChannelID: ch.ID, Private: lc.private, Shared: lc.shared != nil,
			Reason: "the bot joins a public channel to manage it"})
	case resAccept:
		p.chanActs = append(p.chanActs, Action{Kind: status.ActionShareAccept, Channel: lc.name, Private: lc.private, Shared: true,
			Host: lc.shared.Host, Guest: d.in.Workspace, InviteID: p.res.invite.ID, Reason: "the host invited this workspace"})
	case resHeld:
		p.held = append(p.held, Held{Channel: lc.name, Change: p.res.change, Reason: p.res.reason})
	}

	// The members of an existing channel must have been read whole.
	exists := ch != nil && p.res.usable()
	if exists {
		if !ch.MembersKnown {
			return nil, incomplete("the members of %s (%s) were not read", lc.name, ch.ID)
		}
		p.members = map[string]bool{}
		for _, id := range ch.Members {
			p.members[id] = true
		}
	}

	if lc.shared != nil && lc.shared.Host == d.in.Workspace {
		d.shareActions(p)
	}
	if p.res.usable() {
		if err := d.people(p, exists); err != nil {
			return nil, err
		}
	} else if p.res.kind == resHeld {
		for _, s := range lc.slots {
			p.rows = append(p.rows, status.Member{Person: s.person.key, Email: rowEmail(s), State: status.StateHeld, Reason: p.res.reason})
		}
	}
	if exists {
		if err := d.findExtras(p, obs); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func rowEmail(s slot) string {
	if s.addr != "" {
		return s.addr
	}
	if len(s.person.addrs) > 0 {
		return s.person.addrs[0]
	}
	return ""
}

// shareActions is the host's half of a Slack Connect channel: invite each
// guest workspace's bot, once, and wait for it to accept.
func (d *Draft) shareActions(p *plan) {
	lc, obs := p.lc, d.in.Observed
	if !p.res.usable() {
		return
	}
	for _, g := range lc.shared.With {
		team, bot := d.in.Facts[g].Team, d.in.Bots[g]
		invite := Action{Kind: status.ActionShareInvite, Channel: lc.name, Private: lc.private, Host: d.in.Workspace, Guest: g, GuestBot: bot, Shared: true,
			Reason: "the channel is shared with " + g}
		ch := p.res.ch
		if ch != nil {
			invite.ChannelID = ch.ID
			if team != "" && (slices.Contains(ch.SharedTeamIDs, team) || slices.Contains(ch.Teams, team)) {
				// Already shared with that workspace: nothing to invite or wait for.
				continue
			}
			pending := false
			for _, inv := range obs.Invites {
				if !inv.Incoming && inv.ChannelID == ch.ID && inv.RecipientUserID == bot && bot != "" {
					pending = true
				}
			}
			if pending {
				p.notes = append(p.notes, "waiting for "+g+" to accept")
				continue
			}
		}
		if bot == "" {
			reason := g + " is not connected: its bot user id is unknown, so it cannot be invited"
			p.notes = append(p.notes, reason)
			p.heldShare = true
			p.held = append(p.held, Held{Channel: lc.name, Change: "share-invite", Reason: reason})
			continue
		}
		p.shareActs = append(p.shareActs, invite)
	}
}

// people evaluates each wanted person this workspace handles: invite,
// already in, or held with a reason.
func (d *Draft) people(p *plan, exists bool) error {
	obs := d.in.Observed
	for _, s := range p.lc.slots {
		row := status.Member{Person: s.person.key, Email: rowEmail(s)}
		hold := func(reason string) {
			row.State, row.Reason = status.StateHeld, reason
			p.held = append(p.held, Held{Channel: p.lc.name, Person: s.person.key, Email: row.Email, Change: "invite", Reason: reason})
		}
		if s.addr == "" {
			hold(s.reason)
			p.rows = append(p.rows, row)
			continue
		}
		acct, asked := obs.Accounts[s.addr]
		if !asked {
			return incomplete("%s was never looked up", s.addr)
		}
		row.UserID = acct.ID
		switch {
		case !acct.Found:
			row.UserID = ""
			hold("no Slack account yet")
		case acct.Deleted:
			hold("the Slack account is deactivated")
		case acct.Bot:
			hold("that address belongs to a bot")
		case acct.Guest:
			row.State, row.Reason = status.StateReported, "a guest account: guests are never invited or removed"
		case acct.TeamID != "" && obs.TeamID != "" && acct.TeamID != obs.TeamID:
			hold("the account belongs to another workspace")
		case exists && p.members[acct.ID]:
			row.State = status.StateOK
		default:
			row.State, row.Action = status.StateWillInvite, status.ActionInvite
			act := Action{Kind: status.ActionInvite, Channel: p.lc.name, Private: p.lc.private, User: acct.ID, Person: s.person.key, Email: s.addr,
				Groups: slices.Clone(s.person.groups), Shared: p.lc.shared != nil,
				Reason: "holds " + joinGroups(s.person.groups)}
			if p.res.ch != nil {
				act.ChannelID = p.res.ch.ID
			}
			p.inviteActs = append(p.inviteActs, act)
		}
		p.rows = append(p.rows, row)
	}
	return nil
}

func joinGroups(groups []string) string {
	out := ""
	for i, g := range groups {
		if i > 0 {
			out += ", "
		}
		out += g
	}
	return out
}

// findExtras lists the members of an existing channel the bindings do not
// name, each identified; one nobody identified is an incomplete read.
func (d *Draft) findExtras(p *plan, obs Observed) error {
	wantedKeys := map[string]bool{}
	for _, w := range p.lc.all {
		wantedKeys[w.key] = true
	}
	wantedIDs := map[string]bool{}
	for _, s := range p.lc.slots {
		if a, ok := obs.Accounts[s.addr]; ok && s.addr != "" && a.Found {
			wantedIDs[a.ID] = true
		}
	}
	domains := d.r.domains[d.in.Workspace]
	for _, id := range p.res.ch.Members {
		if id == obs.BotUserID || wantedIDs[id] {
			continue
		}
		m, ok := obs.Members[id]
		if !ok {
			return incomplete("member %s of %s was not identified", id, p.lc.name)
		}
		if m.Bot || m.Deleted {
			continue
		}
		e := extra{member: m}
		if m.Email != "" {
			e.key = d.r.personKey(m.Email)
			e.addrs = d.r.addressesOf(m.Email)
			e.inDomain = inDomains(normalise(m.Email), domains)
		}
		if e.key != "" && wantedKeys[e.key] {
			continue
		}
		p.extras = append(p.extras, e)
	}
	return nil
}

// foreign is a member of another workspace, in a channel that reaches more
// than one.
func (d *Draft) foreign(m Member) bool {
	return m.TeamID != "" && d.in.Observed.TeamID != "" && m.TeamID != d.in.Observed.TeamID
}

func (d *Draft) ignored(p *plan, e extra) bool {
	if p.lc.shared != nil || !p.lc.strict {
		return false
	}
	for _, entry := range p.lc.binding.Ignore {
		entry = normalise(entry)
		if entry == normalise(e.member.ID) {
			return true
		}
		if slices.Contains(e.addrs, entry) {
			return true
		}
	}
	return false
}

// strictRemovable is an extra a strict channel may remove, pending the
// directory.
func (d *Draft) strictRemovable(p *plan, e extra) bool {
	return p.lc.strict && p.lc.shared == nil && !e.member.Guest && !d.foreign(e.member) && e.member.Email != "" && !d.ignored(p, e)
}

// leaverCandidate is an extra whose address the directory should be asked
// about only to report it gone.
func (d *Draft) leaverCandidate(e extra) bool {
	return !e.member.Guest && !d.foreign(e.member) && e.member.Email != "" && e.inDomain
}

// Confirm lists the addresses the directory must be asked about before
// [Draft.Decide]: those of every member a strict channel might remove, and
// of every in-domain member of a managed channel nobody names, to tell
// whether they left. Sorted, without duplicates.
func (d *Draft) Confirm() []string {
	set := map[string]bool{}
	for _, p := range d.plans {
		for _, e := range p.extras {
			if d.strictRemovable(p, e) || d.leaverCandidate(e) {
				for _, a := range e.addrs {
					set[a] = true
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}
