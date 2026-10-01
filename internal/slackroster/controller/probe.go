package controller

import (
	"context"
	"maps"
	"slices"

	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// probeGuestSides adds the sides a workspace's bot does not list. A bot lists
// a Slack Connect channel that is public on its side only sometimes, and one
// it has not joined often not at all, so a channel one workspace discovered
// can look "not listed" on another that has it. For every Slack Connect
// channel any report discovered, each other connected workspace that did not
// list it is asked once, by id, with conversations.info: an answer is that
// side (public or private as it says, bot not joined), and Slack's
// channel_not_found (a private side the bot is not in, or no such side) leaves
// the side unknown. One call per channel per workspace per pass, the transport's
// own rate-limit retry, and a failure only logs: it never fails the pass.
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
	clients := map[string]*slackapp.Client{}
	for _, id := range slices.Sorted(maps.Keys(first)) {
		for _, key := range slices.Sorted(maps.Keys(c.deps.Policy.Slack.Workspaces)) {
			if listed[id][key] {
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
			info, err := client.ProbeChannel(ctx, id)
			if err != nil {
				if !slackapp.ErrChannelNotFound.Is(err) {
					c.deps.Log.WarnContext(ctx, "probing a workspace for a shared channel failed; its side stays unknown",
						"workspace", logsafe.Value(key), "channel", logsafe.Value(id), "error", logsafe.Error(err))
				}
				continue
			}
			if info.ID != id || !info.IsExtShared || info.IsArchived {
				continue
			}
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
