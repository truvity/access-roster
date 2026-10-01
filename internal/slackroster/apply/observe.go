// Package apply is the part of the Slack reconciler that touches Slack: it
// reads a workspace whole ([Observe]) and carries out what
// [reconcile.Decision] decided ([Apply]).
//
// Reading is all or nothing. A scope the token lacks, a rate limit that
// outlasts every retry, a page that fails: each fails the whole workspace's
// read with an error, and nothing is decided on it. A partial read must never
// look like a workspace in which nobody has an account.
package apply

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/policy"
)

// ErrWrongWorkspace is a bot token that belongs to another workspace than
// the team recorded for the key when it was first installed (or to one
// with no team recorded at all).
var ErrWrongWorkspace = errors.New("apply: the bot token belongs to a different Slack workspace than the team recorded at the first install")

func normalise(address string) string { return strings.ToLower(strings.TrimSpace(address)) }

// Observe reads what the workspace in.Workspace holds: who the token is, the
// channels the bot can see and the members of those the decision may touch,
// the account for each address in [reconcile.Lookups], who every other
// member is, and pending Slack Connect invitations. in.Observed is ignored
// and the returned value replaces it.
func Observe(ctx context.Context, client *slackapp.Client, in reconcile.Input) (reconcile.Observed, error) {
	cfg, ok := in.Workspaces[in.Workspace]
	if !ok {
		return reconcile.Observed{}, fmt.Errorf("apply: workspace %q is not declared", in.Workspace)
	}
	who, err := client.AuthTest(ctx)
	if err != nil {
		return reconcile.Observed{}, fmt.Errorf("apply: ask who the bot token is: %w", err)
	}
	if recorded := in.Facts[in.Workspace].Team; recorded == "" || who.TeamID != recorded {
		return reconcile.Observed{}, ErrWrongWorkspace
	}
	obs := reconcile.Observed{
		TeamID: who.TeamID, BotUserID: who.UserID,
		Accounts: map[string]reconcile.Account{}, Members: map[string]reconcile.Member{},
	}

	// Accounts: one lookup per address, each all-or-error.
	for _, address := range reconcile.Lookups(in) {
		user, found, err := client.LookupByEmail(ctx, address)
		if err != nil {
			return reconcile.Observed{}, fmt.Errorf("apply: look up a person by address: %w", err)
		}
		if !found {
			obs.Accounts[address] = reconcile.Account{}
			continue
		}
		obs.Accounts[address] = reconcile.Account{
			ID: user.ID, Found: true, Deleted: user.Deleted, Guest: user.IsGuest(), Bot: user.IsAutomated(), TeamID: user.TeamID,
		}
		obs.Members[user.ID] = reconcile.Member{
			ID: user.ID, Email: address, TeamID: user.TeamID, Bot: user.IsAutomated(), Deleted: user.Deleted, Guest: user.IsGuest(),
		}
	}

	// Channels, and members of those a binding names.
	// Archived ones included: a name an archived channel keeps is taken, and
	// the roster must say so rather than try to create it again.
	channels, err := client.AllChannels(ctx)
	if err != nil {
		return reconcile.Observed{}, fmt.Errorf("apply: list channels: %w", err)
	}
	names, ids := named(in, cfg)
	for i := range channels {
		ch := &channels[i]
		c := reconcile.Channel{
			ID: ch.ID, Name: ch.Name, Creator: ch.Creator, Private: ch.IsPrivate, BotIn: ch.IsMember, Archived: ch.IsArchived,
			Shared: ch.IsExtShared, SharedTeamIDs: slices.Clone(ch.SharedTeamIDs),
			HostTeamID: ch.ConversationHostID, Teams: ch.Teams(), NumMembers: ch.NumMembers,
		}
		if !ch.IsArchived && (names[ch.Name] || ids[ch.ID]) && (ch.IsMember || !ch.IsPrivate) {
			members, err := client.Members(ctx, ch.ID)
			if err != nil {
				return reconcile.Observed{}, fmt.Errorf("apply: read the members of a channel: %w", err)
			}
			c.Members, c.MembersKnown = members, true
		}
		obs.Channels = append(obs.Channels, c)
	}

	// Everyone else in those channels: who are they?
	for i := range obs.Channels {
		for _, id := range obs.Channels[i].Members {
			if id == obs.BotUserID {
				continue
			}
			if _, known := obs.Members[id]; known {
				continue
			}
			user, err := client.UserInfo(ctx, id)
			if err != nil {
				return reconcile.Observed{}, fmt.Errorf("apply: identify a channel member: %w", err)
			}
			obs.Members[id] = reconcile.Member{
				ID: id, Email: normalise(user.Email()), TeamID: user.TeamID, Bot: user.IsAutomated(), Deleted: user.Deleted, Guest: user.IsGuest(),
			}
		}
	}

	// Pending Slack Connect invitations, only where a shared channel needs them.
	if involved(in) {
		invites, err := client.ConnectInvites(ctx)
		if err != nil {
			return reconcile.Observed{}, fmt.Errorf("apply: list Slack Connect invitations: %w", err)
		}
		for i := range invites {
			inv := &invites[i]
			obs.Invites = append(obs.Invites, reconcile.Invite{
				ID: inv.Invite.ID, Incoming: inv.Direction == "incoming", HostTeamID: inv.Invite.InvitingTeam.ID,
				ChannelID: inv.Channel.ID, ChannelName: inv.Channel.Name, RecipientUserID: inv.Invite.RecipientUserID,
			})
		}
	}
	return obs, nil
}

// named are the channel names and ids a decision may need members of: the
// channels bound in the workspace (by name, or by the id adopted) and the
// shared channels it takes part in.
func named(in reconcile.Input, cfg policy.SlackWorkspace) (names, ids map[string]bool) {
	names, ids = map[string]bool{}, map[string]bool{}
	for name, ch := range cfg.Channels {
		if ch.Adopt != "" {
			ids[ch.Adopt] = true
		} else {
			names[name] = true
		}
	}
	for _, s := range in.Shared {
		if s.Host == in.Workspace || slices.Contains(s.With, in.Workspace) {
			names[s.Name] = true
			if s.ChannelID != "" {
				ids[s.ChannelID] = true
			}
		}
	}
	return names, ids
}

// involved reports whether the workspace takes part in any shared channel.
func involved(in reconcile.Input) bool {
	for _, s := range in.Shared {
		if s.Host == in.Workspace || slices.Contains(s.With, in.Workspace) {
			return true
		}
	}
	return false
}
