package audit

import (
	"slices"
	"strings"

	"github.com/truvity/audit/sdk/record"
)

// SlackConsoleChannel is an ordinary channel managed from the console as the
// trail names it: by workspace and channel name, with the directory groups
// that feed it (targets, because an address is an identifier and never data)
// and how it is reconciled.
type SlackConsoleChannel struct {
	Workspace string
	Name      string
	Private   bool
	// Mode is extend or strict.
	Mode    string
	Sources []string
	// Members are the individual addresses listed beside the groups: targets
	// too, never data.
	Members []string
}

func (c SlackConsoleChannel) targets() []*record.Target {
	out := append([]*record.Target{targetSlackWorkspace(c.Workspace), targetSlackChannel(c.Workspace, c.Name)}, directoryGroupTargets(c.Sources)...)
	return append(out, directoryUserTargets(c.Members)...)
}

func (c SlackConsoleChannel) data(changes string) data {
	mode := c.Mode
	if mode == "" {
		mode = "extend"
	}
	// The schema still declares `reason`, which records written under
	// catalogue 1.3.0 to 1.5.0 carry: it is read, never written.
	return data{
		"name": c.Name, "privacy": visibility(c.Private), "mode": mode,
		"sources": len(c.Sources), "members": len(c.Members), "changes": changes,
	}
}

// SlackConsoleChannelCreated is an ordinary channel put under management
// from the console.
func SlackConsoleChannelCreated(actor Actor, c SlackConsoleChannel) *record.Record {
	return build("roster.slack_console_channel.created", actor, Succeeded(), nil, c.targets(), c.data(""))
}

// SlackConsoleChannelUpdated is a console channel's record changed from the
// console; changes says what, as 'field: before -> after' parts.
func SlackConsoleChannelUpdated(actor Actor, c SlackConsoleChannel, changes string) *record.Record {
	return build("roster.slack_console_channel.updated", actor, Succeeded(), nil, c.targets(), c.data(changes))
}

// SlackConsoleChannelDeleted is a console channel's record deleted from the
// console. The channel itself stays in Slack.
func SlackConsoleChannelDeleted(actor Actor, c SlackConsoleChannel) *record.Record {
	return build("roster.slack_console_channel.deleted", actor, Succeeded(), nil, c.targets(), c.data(""))
}

// directoryGroupTargets are the groups that feed a channel, as targets, in
// address order without repeats.
func directoryGroupTargets(groups []string) []*record.Target {
	out := make([]*record.Target, 0, len(groups))
	for _, g := range slices.Compact(slices.Sorted(slices.Values(groups))) {
		out = append(out, &record.Target{Type: "directory_group", Id: strings.ToLower(strings.TrimSpace(g))})
	}
	return out
}

// directoryUserTargets are the individually listed people of a channel, as
// targets, in address order without repeats.
func directoryUserTargets(members []string) []*record.Target {
	out := make([]*record.Target, 0, len(members))
	for _, m := range slices.Compact(slices.Sorted(slices.Values(members))) {
		out = append(out, &record.Target{Type: "directory_user", Id: strings.ToLower(strings.TrimSpace(m))})
	}
	return out
}
