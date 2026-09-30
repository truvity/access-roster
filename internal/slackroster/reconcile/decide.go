package reconcile

import (
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// removal is one member a strict channel would remove.
type removal struct {
	channel string
	key     string
	member  Member
	email   string
	groups  []string
	row     int
}

func (r removal) line() string { return r.channel + "|" + r.key }

// gone reports whether the directory authoritatively no longer has any
// address of the person.
func gone(addrs []string, vouches map[string]rails.Vouch) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		v, asked := vouches[a]
		if !asked || !v.Gone() {
			return false
		}
	}
	return true
}

type leaverAcc struct {
	email    string
	channels []string
	reason   string
}

// Decide finishes the pass with the directory's answers: which members are
// removed, which are only reported, the breakers, and the ordered actions.
// It changes nothing; it is pure. vouches are [Directory.Vouch] answers for
// the addresses [Draft.Confirm] named, and confirmed what an operator
// confirmed.
func (d *Draft) Decide(vouches map[string]rails.Vouch, confirmed Confirmed) Decision {
	var (
		removals []removal
		leavers  = map[string]*leaverAcc{}
	)
	rowsOf := map[*plan][]status.Member{}
	for _, p := range d.plans {
		rows := slices.Clone(p.rows)
		for _, e := range p.extras {
			strict := d.strictRemovable(p, e)
			switch {
			case d.ignored(p, e):
				rows = append(rows, status.Member{Person: e.key, Email: e.member.Email, UserID: e.member.ID, State: status.StateIgnored,
					Reason: "on the channel's ignore list; never removed"})
				if d.leaverCandidate(e) && gone(e.addrs, vouches) {
					d.leaver(leavers, e, p.lc.name)
				}
			case p.lc.strict && p.lc.shared == nil && e.member.Guest:
				rows = append(rows, status.Member{Person: e.key, Email: e.member.Email, UserID: e.member.ID, State: status.StateReported,
					Reason: "a guest account: guests are never invited or removed"})
			case p.lc.strict && p.lc.shared == nil && d.foreign(e.member):
				rows = append(rows, status.Member{Person: e.key, Email: e.member.Email, UserID: e.member.ID, State: status.StateReported,
					Reason: "an account of another workspace; never removed"})
			case p.lc.strict && p.lc.shared == nil && e.member.Email == "":
				rows = append(rows, status.Member{UserID: e.member.ID, State: status.StateReported,
					Reason: "no address on the account, so the directory cannot vouch for it; never removed"})
			case strict:
				reason, remove := rails.Removal(e.addrs, vouches, p.lc.groups)
				switch {
				case remove:
					removals = append(removals, removal{channel: p.lc.name, key: e.key, member: e.member, email: e.member.Email, row: len(rows)})
					rows = append(rows, status.Member{Person: e.key, Email: e.member.Email, UserID: e.member.ID,
						State: status.StateWillRemove, Action: status.ActionRemove})
				case reason != "":
					rows = append(rows, status.Member{Person: e.key, Email: e.member.Email, UserID: e.member.ID, State: status.StateRetrying, Reason: reason})
				default:
					// The directory still finds them in a wanted group, so the
					// holders list was incomplete: nothing to do, nothing to say.
					rows = append(rows, status.Member{Person: e.key, Email: e.member.Email, UserID: e.member.ID, State: status.StateOK})
				}
			case d.leaverCandidate(e) && gone(e.addrs, vouches):
				d.leaver(leavers, e, p.lc.name)
				rows = append(rows, status.Member{Person: e.key, Email: e.member.Email, UserID: e.member.ID, State: status.StateReported,
					Reason: "no longer in the directory and still in this channel"})
			}
		}
		rowsOf[p] = rows
	}

	// Breakers: each channel's removal set, then the workspace's, both over
	// the same candidates so neither fingerprint depends on the other.
	byChannel := map[string][]int{}
	for i, r := range removals {
		byChannel[r.channel] = append(byChannel[r.channel], i)
	}
	held := []Held{}
	chBreaker := map[string]*rails.Breaker{}
	chBlocked := map[string]bool{}
	for _, p := range d.plans {
		idx := byChannel[p.lc.name]
		if len(idx) == 0 || p.lc.shared != nil {
			continue
		}
		people, lines := map[string]bool{}, []string{}
		for _, i := range idx {
			people[removals[i].key] = true
			lines = append(lines, removals[i].line())
		}
		b := rails.CheckBreaker(len(people), lines, d.managedMembers(p), confirmed.Channels[p.lc.name])
		chBreaker[p.lc.name] = b
		if b != nil && !b.Confirmed {
			chBlocked[p.lc.name] = true
			held = append(held, Held{Channel: p.lc.name, Change: "remove", Reason: fmt.Sprintf(
				"over the removal limit: %d of %d members of %s; an operator confirms this set", b.Affected, b.Total, p.lc.name)})
		}
	}
	var wsBreaker *rails.Breaker
	wsBlocked := false
	if len(removals) > 0 {
		people, lines := map[string]bool{}, []string{}
		for _, r := range removals {
			people[r.key] = true
			lines = append(lines, r.line())
		}
		distinct := len(people)
		managed := map[string]bool{}
		for _, p := range d.plans {
			if p.res.ch != nil && p.members != nil {
				for id := range p.members {
					if id != d.in.Observed.BotUserID {
						managed[id] = true
					}
				}
			}
		}
		wsBreaker = rails.CheckBreaker(distinct, lines, len(managed), confirmed.Workspace)
		if wsBreaker != nil && !wsBreaker.Confirmed {
			wsBlocked = true
			held = append(held, Held{Change: "remove", Reason: fmt.Sprintf(
				"over the removal limit: %d of %d managed members of the workspace; an operator confirms this set", wsBreaker.Affected, wsBreaker.Total)})
		}
	}

	// Rows of blocked removals become held; the rest are actions.
	var removeActs []Action
	for _, r := range removals {
		p := d.planNamed(r.channel)
		rows := rowsOf[p]
		switch {
		case chBlocked[r.channel]:
			rows[r.row] = status.Member{Person: r.key, Email: r.email, UserID: r.member.ID, State: status.StateHeld,
				Reason: "this channel's removals are over the limit and wait for an operator's confirmation"}
		case wsBlocked:
			rows[r.row] = status.Member{Person: r.key, Email: r.email, UserID: r.member.ID, State: status.StateHeld,
				Reason: "the workspace's removals are over the limit and wait for an operator's confirmation"}
		default:
			removeActs = append(removeActs, Action{Kind: status.ActionRemove, Channel: r.channel, ChannelID: p.res.ch.ID, Private: p.lc.private, User: r.member.ID,
				Person: r.key, Email: r.email, Groups: slices.Clone(p.lc.groups),
				Reason: "the directory vouches that they no longer hold " + joinGroups(p.lc.groups)})
		}
	}

	// Assemble.
	var dec Decision
	var phase0, phase1, phase2 []Action
	for _, p := range d.plans {
		ch := status.Channel{Name: p.lc.name, Private: p.lc.private, Mode: modeOf(p), Members: rowsOf[p], Breaker: status.BreakerOf(chBreaker[p.lc.name])}
		if p.lc.shared != nil {
			ch.Shared, ch.Host = true, p.lc.shared.Host
		}
		if p.res.ch != nil {
			ch.ID, ch.Private = p.res.ch.ID, p.res.ch.Private
		}
		ch.State, ch.Reason = channelState(p)
		phase0 = append(phase0, p.chanActs...)
		phase1 = append(phase1, p.shareActs...)
		phase2 = append(phase2, p.inviteActs...)
		held = append(held, p.held...)
		dec.Report.Channels = append(dec.Report.Channels, ch)
		if ch.State == status.ChannelWaiting {
			dec.Report.Tick.Waiting++
		}
	}
	dec.Actions = slices.Concat(phase0, phase1, phase2, removeActs)
	dec.Held = held
	for _, key := range slices.Sorted(maps.Keys(leavers)) {
		l := leavers[key]
		slices.Sort(l.channels)
		dec.Report.Leavers = append(dec.Report.Leavers, status.Leaver{Email: l.email, UserID: key, Channels: l.channels, Reason: l.reason})
	}
	dec.Report.Workspace = d.in.Workspace
	dec.Report.Breaker = status.BreakerOf(wsBreaker)
	dec.Report.Tick.Changes = len(dec.Actions)
	dec.Report.Tick.Held = len(dec.Held)
	for _, p := range d.plans {
		for _, m := range rowsOf[p] {
			if m.State == status.StateRetrying {
				dec.Report.Tick.Retrying++
			}
		}
	}
	sort.SliceStable(dec.Held, func(i, j int) bool { return dec.Held[i].Key() < dec.Held[j].Key() })
	return dec
}

// managedMembers counts a channel's members other than the bot itself.
func (d *Draft) managedMembers(p *plan) int {
	n := 0
	for id := range p.members {
		if id != d.in.Observed.BotUserID {
			n++
		}
	}
	return n
}

func (d *Draft) planNamed(name string) *plan {
	for _, p := range d.plans {
		if p.lc.name == name && p.lc.shared == nil {
			return p
		}
	}
	return nil
}

func (d *Draft) leaver(into map[string]*leaverAcc, e extra, channel string) {
	l := into[e.member.ID]
	if l == nil {
		l = &leaverAcc{email: e.member.Email, reason: "no longer in the directory and still active in a managed channel"}
		into[e.member.ID] = l
	}
	if !slices.Contains(l.channels, channel) {
		l.channels = append(l.channels, channel)
	}
}

func modeOf(p *plan) string {
	if p.lc.strict && p.lc.shared == nil {
		return "strict"
	}
	return "extend"
}

// channelState is the one word for a channel, and why.
func channelState(p *plan) (status.ChannelState, string) {
	switch {
	case p.res.kind == resHeld:
		return status.ChannelHeld, p.res.reason
	case p.heldShare:
		return status.ChannelHeld, joinNotes(p.notes)
	case p.res.kind == resCreate:
		return status.ChannelWillCreate, joinNotes(p.notes)
	case p.res.kind == resJoin:
		return status.ChannelWillAdopt, joinNotes(p.notes)
	case p.res.kind == resAccept:
		return status.ChannelWillAccept, joinNotes(p.notes)
	case p.res.kind == resWaiting:
		return status.ChannelWaiting, p.res.reason
	case len(p.notes) > 0:
		return status.ChannelWaiting, joinNotes(p.notes)
	}
	return status.ChannelOK, ""
}

func joinNotes(notes []string) string {
	out := ""
	for i, n := range notes {
		if i > 0 {
			out += "; "
		}
		out += n
	}
	return out
}
