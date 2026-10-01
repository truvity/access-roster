package audit

import (
	"maps"
	"slices"
	"strings"

	"github.com/truvity/audit/record"
)

// SlackSharedChannel is a Slack Connect channel's definition as the trail
// names it: by the host workspace and channel name, with the workspaces it
// is shared with, the directory groups that feed it and its visibility.
type SlackSharedChannel struct {
	Name string
	Host string
	With []string
	// Sources are the directory groups, by address: carried as targets, because
	// an address is an identifier and never data.
	Sources []string
	// Members are the individual addresses listed beside the groups: targets
	// too, never data.
	Members []string
	// Private is one visibility for every side, unless PerSide is set.
	Private bool
	// PerSide is a visibility per workspace key, for a channel whose sides
	// differ.
	PerSide map[string]bool
}

func (c SlackSharedChannel) targets() []*record.Target {
	out := append([]*record.Target{targetSlackWorkspace(c.Host), targetSlackChannel(c.Host, c.Name)}, directoryGroupTargets(c.Sources)...)
	return append(out, directoryUserTargets(c.Members)...)
}

// Privacy is the visibility in one word, or as workspace=word pairs in key
// order for a channel whose sides differ.
func (c SlackSharedChannel) Privacy() string {
	if len(c.PerSide) == 0 {
		return visibility(c.Private)
	}
	parts := make([]string, 0, len(c.PerSide))
	for _, side := range slices.Sorted(maps.Keys(c.PerSide)) {
		parts = append(parts, side+"="+visibility(c.PerSide[side]))
	}
	return strings.Join(parts, ",")
}

func visibility(private bool) string {
	if private {
		return "private"
	}
	return "public"
}

func (c SlackSharedChannel) data(changes string) data {
	return data{
		"name": c.Name, "with": strings.Join(c.With, ","),
		"privacy": c.Privacy(), "members": len(c.Members), "changes": changes,
	}
}

// SlackSharedChannelCreated is a shared channel defined from the console.
func SlackSharedChannelCreated(actor Actor, c SlackSharedChannel) *record.Record {
	return build("roster.slack_shared_channel.created", actor, Succeeded(), nil, c.targets(), c.data(""))
}

// SlackSharedChannelUpdated is a shared channel's definition changed from
// the console; changes says what, as 'field: before -> after' parts.
func SlackSharedChannelUpdated(actor Actor, c SlackSharedChannel, changes string) *record.Record {
	return build("roster.slack_shared_channel.updated", actor, Succeeded(), nil, c.targets(), c.data(changes))
}

// SlackSharedChannelDeleted is a shared channel's definition deleted from
// the console. The channel itself stays in Slack.
func SlackSharedChannelDeleted(actor Actor, c SlackSharedChannel) *record.Record {
	return build("roster.slack_shared_channel.deleted", actor, Succeeded(), nil, c.targets(), c.data(""))
}
