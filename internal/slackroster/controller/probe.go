package controller

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// probeGuestSides adds the sides a workspace's bot does not list. A bot lists
// a Slack Connect channel that is public on its side only sometimes, and one
// it has not joined often not at all, so a channel one workspace discovered
// can look "not listed" on another that has it. Only a channel a console
// shared-channel record manages is probed; an unmanaged one is never asked
// about. For such a channel, each connected workspace that did not list it
// is asked once, by id, with conversations.info: an answer is that side
// (public or private as it says, bot not joined), and Slack's
// channel_not_found (a private side the bot is not in) leaves the side
// unknown, logged at debug. When Slack names a connected workspace other than
// the host and the reporters among a channel's teams (host, shared, connected,
// pending, internal), only the named ones are asked. A bot is often told
// nothing but its own team, though: with no such guest named, exactly the
// workspaces the record names as sides (host and with) are asked. One call
// per channel per workspace per pass, the transport's own rate-limit retry,
// and a failure only logs: it never fails the pass.
func (c *Controller) probeGuestSides(ctx context.Context, p *pass, reports map[string]status.Workspace) {
	// channel id -> first sighting (by workspace key order), and who listed it.
	first := map[string]status.Discovered{}
	managed := map[string]bool{}
	listed := map[string]map[string]bool{}
	for _, key := range slices.Sorted(maps.Keys(reports)) {
		for _, d := range reports[key].DiscoveredShared {
			if _, ok := first[d.ID]; !ok {
				first[d.ID] = d
			}
			managed[d.ID] = managed[d.ID] || d.Managed
			if listed[d.ID] == nil {
				listed[d.ID] = map[string]bool{}
			}
			listed[d.ID][key] = true
		}
	}
	// channel id -> the teams any report says are in it: only those are asked.
	inChannel := map[string]map[string]bool{}
	for _, key := range slices.Sorted(maps.Keys(reports)) {
		for _, d := range reports[key].DiscoveredShared {
			if inChannel[d.ID] == nil {
				inChannel[d.ID] = map[string]bool{}
			}
			if d.HostTeam != "" {
				inChannel[d.ID][d.HostTeam] = true
			}
			for _, team := range d.Teams {
				inChannel[d.ID][team] = true
			}
		}
	}
	// connected workspace key -> its team id, as far as a report or a record knows.
	teamOf := map[string]string{}
	for key := range c.deps.Policy.Slack.Workspaces {
		team := reports[key].Team
		if team == "" {
			team = p.store.recorded[key].team
		}
		teamOf[key] = team
	}
	// channel id -> whether Slack named a connected guest workspace: a team
	// in the channel that is neither its host nor a workspace that listed it.
	named := map[string]bool{}
	for id := range first {
		for key, team := range teamOf {
			if team != "" && inChannel[id][team] && !listed[id][key] && team != first[id].HostTeam {
				named[id] = true
			}
		}
	}
	// channel id -> the workspaces its record names as sides, for a managed
	// channel: the record matches by channel id, else by host team and name.
	sides := map[string]map[string]bool{}
	valid := p.shared
	for id, d := range first {
		if !managed[id] {
			continue
		}
		for i := range valid {
			rec := &valid[i]
			if rec.ChannelID != "" {
				if rec.ChannelID != id {
					continue
				}
			} else {
				if !rec.NamesChannel(d.Name, d.HostTeam, teamOf[rec.Host], listed[id][rec.Host]) {
					continue
				}
			}
			if sides[id] == nil {
				sides[id] = map[string]bool{}
			}
			sides[id][rec.Host] = true
			for _, w := range rec.With {
				sides[id][w] = true
			}
		}
	}
	var probed, visible, invisible int
	defer func() {
		if probed > 0 {
			c.deps.Log.InfoContext(ctx, "guest-side probe", "probed", probed, "visible", visible, "invisible", invisible)
		}
	}()
	clients := map[string]*slackapp.Client{}
	for _, id := range slices.Sorted(maps.Keys(first)) {
		if !managed[id] {
			continue
		}
		for _, key := range slices.Sorted(maps.Keys(c.deps.Policy.Slack.Workspaces)) {
			if listed[id][key] {
				continue
			}
			// When Slack named the guests, a workspace it did not name has no
			// side to find: skip it without a call. When it named none, only
			// the workspaces the record names as sides are asked.
			if named[id] {
				if !inChannel[id][teamOf[key]] {
					continue
				}
			} else if !sides[id][key] {
				continue
			}
			client, ok := clients[key]
			if !ok {
				if token, err := p.store.token(key); err == nil {
					client = c.deps.Slack(token)
				}
				clients[key] = client
			}
			if client == nil {
				continue
			}
			probed++
			info, err := client.ProbeChannel(ctx, id)
			if err != nil {
				invisible++
				if errors.Is(err, slackapp.ErrChannelNotFound) || errors.Is(err, slackapp.ErrNotInChannel) {
					// Expected: the side is private to a bot that is not in it,
					// or the workspace is not in the channel at all.
					c.deps.Log.DebugContext(ctx, "a workspace's side of a shared channel is not visible to its bot",
						"workspace", logsafe.Value(key), "channel", logsafe.Value(id), "error", logsafe.Error(err))
				} else {
					c.deps.Log.WarnContext(ctx, "probing a workspace for a shared channel failed; its side stays unknown",
						"workspace", logsafe.Value(key), "channel", logsafe.Value(id), "error", logsafe.Error(err))
				}
				continue
			}
			if info.ID != id || !info.IsExtShared || info.IsArchived {
				invisible++
				continue
			}
			visible++
			host := info.ConversationHostID
			if host == "" {
				host = first[id].HostTeam
			}
			report := reports[key]
			report.DiscoveredShared = append(slices.Clone(report.DiscoveredShared), status.Discovered{
				ID: id, Name: info.Name, Private: info.IsPrivate, Members: info.NumMembers, HostTeam: host,
				Teams: info.Teams(), Managed: managed[id],
			})
			reports[key] = report
		}
	}
}
