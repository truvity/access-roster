package server

import (
	"maps"
	"slices"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// The privacy words of a discovered side.
const (
	privacyPublic  = "public"
	privacyPrivate = "private"
	// privacyUnknown is a side whose bot cannot see the channel: it is not
	// shared with that workspace, or it is private there and the bot is not
	// in it. Slack does not say which.
	privacyUnknown = "unknown"
)

// discoveredRow is one channel while the workspaces' reports are merged.
type discoveredRow struct {
	hostTeam string
	teams    map[string]bool
	// reporters are the workspaces whose own report lists the channel,
	// found or probed: each is a side whether or not its team id is known.
	reporters map[string]bool
	seen      map[string]status.Discovered // by workspace key
	managed   bool
}

// discoveredChannels merges every connected workspace's discovered shared
// channels into one row per channel. A caller sees the channels at least one
// workspace they may view can see, and the details only of the sides they
// may view. A team that is not a connected workspace is counted, never
// named, and a channel it hosts cannot be managed.
func discoveredChannels(
	id access.Identity, book slackBook, p policy.Policy, reports map[string]status.Workspace, records []kube.SharedRecord, available bool,
) []*directoryrosterv1.SlackDiscoveredChannel {
	// Which connected workspace a team id is: what was recorded at its first
	// install, else what its own report says.
	workspaceOfTeam := map[string]string{}
	for key := range p.Slack.Workspaces {
		if team := book.team(key); team != "" {
			workspaceOfTeam[team] = key
		}
		// The report's own team names the workspace too, so a team recorded
		// differently at install does not turn a connected side external.
		if team := reports[key].Team; team != "" {
			if _, claimed := workspaceOfTeam[team]; !claimed {
				workspaceOfTeam[team] = key
			}
		}
	}
	rows := map[string]*discoveredRow{}
	for _, key := range slices.Sorted(maps.Keys(reports)) {
		if _, declared := p.Slack.Workspaces[key]; !declared || !book.may(id, access.RoleViewer, key) {
			continue
		}
		for _, d := range reports[key].DiscoveredShared {
			row := rows[d.ID]
			if row == nil {
				row = &discoveredRow{teams: map[string]bool{}, reporters: map[string]bool{}, seen: map[string]status.Discovered{}}
				rows[d.ID] = row
			}
			row.seen[key] = d
			row.reporters[key] = true
			if row.hostTeam == "" {
				row.hostTeam = d.HostTeam
			}
			for _, team := range d.Teams {
				row.teams[team] = true
			}
			if team := reports[key].Team; team != "" {
				row.teams[team] = true
			}
			row.managed = row.managed || d.Managed
		}
	}

	var out []*directoryrosterv1.SlackDiscoveredChannel
	for _, channelID := range slices.Sorted(maps.Keys(rows)) {
		row := rows[channelID]
		host := workspaceOfTeam[row.hostTeam]
		view := &directoryrosterv1.SlackDiscoveredChannel{ChannelId: channelID, HostWorkspace: host, HostTeam: row.hostTeam}
		// A workspace whose report lists the channel is a side by that fact,
		// whatever its team id says.
		placed := maps.Clone(row.reporters)
		for _, team := range slices.Sorted(maps.Keys(row.teams)) {
			if key, connected := workspaceOfTeam[team]; connected {
				placed[key] = true
			} else {
				view.ExternalTeams++
			}
		}
		for _, key := range slices.Sorted(maps.Keys(placed)) {
			side := &directoryrosterv1.SlackDiscoveredSide{Workspace: key, Privacy: privacyUnknown, Listed: true}
			if d, ok := row.seen[key]; ok {
				side.Seen, side.Name, side.Members = true, d.Name, int32(d.Members) //nolint:gosec // a member count
				side.Privacy = privacyPublic
				if d.Private {
					side.Privacy = privacyPrivate
				}
			}
			view.Sides = append(view.Sides, side)
		}
		// Every other connected workspace the caller may view is a side too,
		// unknown: nothing says the channel reaches it, and nothing says it
		// does not. A guest side's bot lists a private channel only once it
		// is in it, and Slack's own team lists on the host's row name the
		// host alone, so a side nobody saw is invisible, which is not absent.
		// The form starts from the listed sides and lets the operator add
		// the rest.
		for _, key := range slices.Sorted(maps.Keys(p.Slack.Workspaces)) {
			present := slices.ContainsFunc(view.Sides, func(s *directoryrosterv1.SlackDiscoveredSide) bool { return s.Workspace == key })
			if book.may(id, access.RoleViewer, key) && !present {
				view.Sides = append(view.Sides, &directoryrosterv1.SlackDiscoveredSide{Workspace: key, Privacy: privacyUnknown})
			}
		}
		// The host first, then the listed sides, then the rest, each by key.
		slices.SortStableFunc(view.Sides, func(a, b *directoryrosterv1.SlackDiscoveredSide) int {
			switch {
			case a.Workspace == host && b.Workspace != host:
				return -1
			case b.Workspace == host && a.Workspace != host:
				return 1
			case a.Listed && !b.Listed:
				return -1
			case b.Listed && !a.Listed:
				return 1
			}
			return compareStrings(a.Workspace, b.Workspace)
		})
		view.ManagedAs = managedAs(records, channelID, host, hostName(view, host))
		view.Managed = row.managed || view.ManagedAs != ""
		view.CanManage = available && !view.Managed && host != "" && book.mayAct(id, host)
		out = append(out, view)
	}
	return out
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// hostName is the channel's name on the host's side, empty when the host's
// bot cannot see it.
func hostName(view *directoryrosterv1.SlackDiscoveredChannel, host string) string {
	for _, side := range view.Sides {
		if side.Workspace == host {
			return side.Name
		}
	}
	return ""
}

// managedAs is the record that manages a channel: the one that names its id,
// else the one hosted by the same workspace under the host side's name.
func managedAs(records []kube.SharedRecord, channelID, host, name string) string {
	for i := range records {
		if records[i].Err == nil && records[i].Channel.ChannelID == channelID {
			return records[i].Name
		}
	}
	for i := range records {
		rec := &records[i]
		if rec.Err == nil && rec.Channel.ChannelID == "" && host != "" && rec.Channel.Host == host && name != "" && rec.Channel.Name == name {
			return rec.Name
		}
	}
	return ""
}

// discoveredIn is the host workspace's own sighting of a channel id, and
// whether its bot saw it at all.
func discoveredIn(reports map[string]status.Workspace, workspace, channelID string) (status.Discovered, bool) {
	for _, d := range reports[workspace].DiscoveredShared {
		if d.ID == channelID {
			return d, true
		}
	}
	return status.Discovered{}, false
}
