package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/truvity/audit/record"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// Options say how a decision is carried out.
type Options struct {
	// Workspace is the policy key of the workspace acted in, for the audit
	// records.
	Workspace string
	// DryRun returns what would be done and calls Slack for nothing,
	// recording nothing.
	DryRun bool
	// Audit receives one record per action taken, success or failure. Nil
	// records nothing.
	Audit audit.Recorder
	// ExternalLimited is passed to conversations.inviteShared.
	ExternalLimited bool
}

// Outcome is what became of one action.
type Outcome struct {
	Action reconcile.Action
	// Done is true when Slack accepted it.
	Done bool
	// Err is why it was not done, in Slack's words.
	Err error
	// Skipped says why nothing was tried: a dry run, or the channel it
	// depends on was not made.
	Skipped string
	// Held is set when Slack refused the action in a way that is a hold, not
	// a failure to retry: a person has to act. It is the reason, and the
	// refusal is not recorded as a failed change every pass; the controller
	// records the hold once.
	Held string
}

// TakenReason is why a channel could not be created under a name Slack says
// is taken although no channel of that name is visible to the bot: a private
// channel it is not in, or an archived one. The roster never creates a
// duplicate under another name, converts a channel or unarchives one.
func TakenReason(name string) string {
	return "a private channel named " + name + " exists that the bot cannot see; invite the bot to it " +
		"(or, if it is archived, unarchive it in Slack or rename it): the roster never creates a second channel under another name"
}

// Result is a decision carried out.
type Result struct {
	Outcomes []Outcome
	// ChannelIDs are the ids, by channel name, of channels created, joined
	// or accepted in this pass.
	ChannelIDs map[string]string
}

// Done counts the actions Slack accepted.
func (r Result) Done() int {
	n := 0
	for i := range r.Outcomes {
		if r.Outcomes[i].Done {
			n++
		}
	}
	return n
}

// Failed counts the actions Slack refused or that could not be tried.
func (r Result) Failed() int {
	n := 0
	for i := range r.Outcomes {
		if r.Outcomes[i].Err != nil {
			n++
		}
	}
	return n
}

// Apply carries out the decision's actions in order, in one workspace, and
// records each in the audit trail. A failed action does not stop the ones
// that do not depend on it: a channel that could not be created skips its
// invitations, and the rest go on. Every failure is in the result.
func Apply(ctx context.Context, client *slackapp.Client, dec reconcile.Decision, opt Options) Result {
	res := Result{ChannelIDs: map[string]string{}}
	ids := map[string]string{}
	for i := range dec.Actions {
		a := dec.Actions[i]
		out := Outcome{Action: a}
		if opt.DryRun {
			out.Skipped = "dry run"
			res.Outcomes = append(res.Outcomes, out)
			continue
		}
		id := a.ChannelID
		if id == "" {
			id = ids[a.Channel]
		}
		channel := audit.SlackChannel{Workspace: opt.Workspace, Name: a.Channel, ID: id, Private: a.Private}
		switch a.Kind {
		case status.ActionCreate:
			var ch slackapp.Channel
			ch, out.Err = client.CreateChannel(ctx, a.Channel, a.Private)
			if out.Err == nil {
				ids[a.Channel], res.ChannelIDs[a.Channel] = ch.ID, ch.ID
				channel.ID = ch.ID
			}
			out.Done = out.Err == nil
			if errors.Is(out.Err, slackapp.ErrNameTaken) {
				// The name is taken by a channel the bot cannot see. That is a
				// hold, found by asking, and not a change that failed.
				out.Held = TakenReason(a.Channel)
				break
			}
			emit(ctx, opt, audit.SlackChannelCreated(channel, outcomeOf(out.Err)))
		case status.ActionAdopt:
			_, out.Err = client.JoinChannel(ctx, a.ChannelID)
			if out.Err == nil {
				ids[a.Channel], res.ChannelIDs[a.Channel] = a.ChannelID, a.ChannelID
			}
			out.Done = out.Err == nil
			emit(ctx, opt, audit.SlackChannelAdopted(channel, outcomeOf(out.Err)))
		case status.ActionShareAccept:
			var accepted string
			accepted, out.Err = client.AcceptSharedInvite(ctx, slackapp.AcceptParams{InviteID: a.InviteID, ChannelName: a.Channel, IsPrivate: a.Private})
			if out.Err == nil {
				ids[a.Channel], res.ChannelIDs[a.Channel] = accepted, accepted
			}
			out.Done = out.Err == nil
			shared := audit.SlackShared{Host: a.Host, Guest: a.Guest, Channel: a.Channel, ID: accepted, Invite: a.InviteID}
			emit(ctx, opt, audit.SlackSharedAccepted(shared, outcomeOf(out.Err)))
		case status.ActionShareInvite:
			if id == "" {
				out.Skipped, out.Err = "the channel was not made", errNoChannel
				break
			}
			var invite string
			invite, out.Err = client.InviteShared(ctx, id, slackapp.ConnectTarget{UserID: a.GuestBot}, opt.ExternalLimited)
			out.Done = out.Err == nil
			emit(ctx, opt, audit.SlackSharedInvited(audit.SlackShared{Host: a.Host, Guest: a.Guest, Channel: a.Channel, ID: id, Invite: invite}, outcomeOf(out.Err)))
		case status.ActionInvite:
			if id == "" {
				out.Skipped, out.Err = "the channel was not made", errNoChannel
				break
			}
			out.Err = client.Invite(ctx, id, []string{a.User})
			out.Done = out.Err == nil
			emit(ctx, opt, audit.SlackMemberInvited(member(a, channel, id), outcomeOf(out.Err)))
		case status.ActionRemove:
			out.Err = client.Kick(ctx, id, a.User)
			out.Done = out.Err == nil
			emit(ctx, opt, audit.SlackMemberRemoved(member(a, channel, id), outcomeOf(out.Err)))
		default:
			out.Err = fmt.Errorf("apply: unknown action %q", a.Kind)
		}
		res.Outcomes = append(res.Outcomes, out)
	}
	return res
}

var errNoChannel = errors.New("apply: the channel this depends on does not exist")

func member(a reconcile.Action, ch audit.SlackChannel, id string) audit.SlackMember {
	ch.ID = id
	return audit.SlackMember{Person: a.Email, Channel: ch, User: a.User, Groups: a.Groups, Reason: a.Reason}
}

// outcomeOf is the audit outcome for a Slack call's error.
func outcomeOf(err error) audit.Outcome {
	if err == nil {
		return audit.Succeeded()
	}
	return audit.Failed(err.Error())
}

func emit(ctx context.Context, opt Options, r *record.Record) {
	if opt.Audit != nil {
		opt.Audit.Record(ctx, r)
	}
}

// HeldRecord is the audit record for a hold, to be emitted once when it
// becomes held (see [rails.Ledger]).
func HeldRecord(workspace string, h reconcile.Held) *record.Record {
	var channel *audit.SlackChannel
	if h.Channel != "" {
		channel = &audit.SlackChannel{Workspace: workspace, Name: h.Channel}
	}
	var m *audit.SlackMember
	if h.Person != "" && channel != nil {
		m = &audit.SlackMember{Person: h.Email, Channel: *channel}
		if h.Email == "" {
			m.Person = h.Person
		}
	}
	return audit.SlackActionHeld(workspace, channel, m, heldChange(h.Change), h.Reason)
}

// LeaverRecord is the audit record for a leaver report, to be emitted once.
func LeaverRecord(workspace string, l status.Leaver) *record.Record {
	return audit.SlackLeaverReported(workspace, l.Email, l.UserID, l.Reason)
}

// heldChange is the catalogue's word for the kind of change a hold is on:
// the decision says "share-invite" and "share-accept" where the catalogue
// says "share" and "accept".
func heldChange(change string) string {
	switch change {
	case "share-invite":
		return "share"
	case "share-accept":
		return "accept"
	}
	return change
}
