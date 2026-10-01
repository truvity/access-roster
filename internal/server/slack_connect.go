package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// SlackSharedRecords is where Slack Connect channel definitions are kept:
// the records the Slack controller reads.
type SlackSharedRecords interface {
	List(ctx context.Context) ([]kube.SharedRecord, error)
	// Apply reads one record (nil when there is none), asks decide what it
	// becomes (nil deletes it) and writes that under the object's version.
	Apply(ctx context.Context, name string, decide func(current *reconcile.SharedChannel) (*reconcile.SharedChannel, error)) error
}

// SlackStatusReports is what the Slack controller last reported, one
// document per workspace.
type SlackStatusReports interface {
	Reports(ctx context.Context) (map[string]string, error)
}

// The states a shared channel is shown in.
const (
	sharedNotReported = "not_reported"
	sharedPending     = "pending"
	sharedWaiting     = "waiting"
	sharedActive      = "active"
	sharedHeld        = "held"
	sharedInvalid     = "invalid"
)

// errSharedImmutable is what a change of host or name is answered with.
func errSharedImmutable(what, was, got string) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
		"a shared channel's %s cannot change (it is %q, the request says %q): create a new channel with the %s you want, "+
			"and delete this record if the old channel should no longer be managed", what, was, got, what))
}

func (c *Console) slackSharedStore() (SlackSharedRecords, error) {
	if c.deps.SlackShared == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no state in Kubernetes, so a shared channel's record would not survive a restart"))
	}
	return c.deps.SlackShared, nil
}

// ListSlackSharedChannels is every record the caller may see, with where
// the controller has each.
func (c *Console) ListSlackSharedChannels(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListSlackSharedChannelsRequest],
) (*connect.Response[directoryrosterv1.ListSlackSharedChannelsResponse], error) {
	id, book, err := c.requireAnySlack(ctx, access.RoleViewer)
	if err != nil {
		return nil, err
	}
	set := c.deps.Authorizer.Policy()
	p := set.Declared()
	out := &directoryrosterv1.ListSlackSharedChannelsResponse{Available: c.deps.SlackShared != nil}
	anyOperate := false
	for _, key := range set.SlackWorkspaceKeys() {
		if !book.may(id, access.RoleViewer, key) {
			continue
		}
		operate := book.mayAct(id, key)
		anyOperate = anyOperate || operate
		out.Workspaces = append(out.Workspaces, &directoryrosterv1.SlackConnectWorkspace{Key: key, CanOperate: operate, Owner: book.owner(key)})
	}
	if anyOperate {
		// Any connected directory's groups: a Slack Connect channel is not
		// bound to one directory.
		out.SourceDirectories = c.sourceDirectories(ctx)
	}
	if c.deps.SlackShared == nil {
		return connect.NewResponse(out), nil
	}
	records, err := c.deps.SlackShared.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	reports := c.slackReports(ctx)
	for i := range records {
		rec := &records[i]
		if rec.Err != nil && !errors.Is(rec.Err, connection.ErrLegacySources) {
			// Whose it is cannot be read: only the installation-wide role
			// sees it, to fix or delete it.
			if id.Can(access.RoleViewer) {
				out.Channels = append(out.Channels, &directoryrosterv1.SlackSharedChannel{
					Channel: &directoryrosterv1.SlackSharedChannelDefinition{Name: rec.Name},
					State:   sharedInvalid, Reason: rec.Err.Error(), CanOperate: id.Can(access.RoleOperator),
				})
			}
			continue
		}
		if !maySeeShared(id, book, rec.Channel) {
			continue
		}
		view := sharedView(rec.Channel)
		view.State, view.Reason = sharedState(rec.Channel, p, reports)
		if rec.Err != nil {
			// Fed by internal groups, as an old record was: it says whose it
			// is, so it is shown to them and can be edited, and acts on nothing.
			view.State, view.Reason = sharedInvalid, rec.Err.Error()
		}
		view.CanOperate = book.mayAct(id, rec.Channel.Host)
		out.Channels = append(out.Channels, view)
	}
	out.Discovered = discoveredChannels(id, book, p, reports, records, true)
	return connect.NewResponse(out), nil
}

// maySeeShared is whether the caller may view the host workspace or any
// workspace the channel is shared with.
func maySeeShared(id access.Identity, book slackBook, ch reconcile.SharedChannel) bool {
	return slices.ContainsFunc(append([]string{ch.Host}, ch.With...), func(w string) bool {
		return book.may(id, access.RoleViewer, w)
	})
}

// slackReports are the controller's documents by workspace. Unreadable or
// absent is an empty answer: the list then says "not reported".
func (c *Console) slackReports(ctx context.Context) map[string]status.Workspace {
	out := map[string]status.Workspace{}
	if c.deps.SlackStatus == nil {
		return out
	}
	raw, err := c.deps.SlackStatus.Reports(ctx)
	if err != nil {
		return out
	}
	for key, doc := range raw {
		workspace, ok := status.WorkspaceOfKey(key)
		if !ok {
			continue
		}
		if report, err := status.Decode(doc); err == nil {
			out[workspace] = report
		}
	}
	return out
}

// sharedState is where a record stands: first whether the policy in force
// still accepts it, then what the host's controller reported for it.
func sharedState(ch reconcile.SharedChannel, p policy.Policy, reports map[string]status.Workspace) (state, reason string) {
	if err := ch.Validate(p); err != nil {
		return sharedInvalid, err.Error()
	}
	report, ok := reports[ch.Host]
	if !ok {
		return sharedNotReported, "the host workspace's controller has reported nothing yet"
	}
	for i := range report.Channels {
		rep := &report.Channels[i]
		if rep.Name != ch.Name || !rep.Shared || rep.Host != ch.Host {
			continue
		}
		switch rep.State {
		case status.ChannelOK:
			return sharedActive, ""
		case status.ChannelWaiting:
			return sharedWaiting, orDefault(rep.Reason, "a guest workspace has not accepted the invitation yet")
		case status.ChannelHeld:
			if strings.Contains(rep.Reason, "definition is refused") {
				return sharedInvalid, rep.Reason
			}
			return sharedHeld, rep.Reason
		default:
			return sharedPending, orDefault(rep.Reason, "the controller will act on it on its next pass")
		}
	}
	return sharedNotReported, "the host workspace's report does not list this channel yet"
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func sharedView(ch reconcile.SharedChannel) *directoryrosterv1.SlackSharedChannel {
	def := &directoryrosterv1.SlackSharedChannelDefinition{
		Name: ch.Name, Host: ch.Host, With: slices.Clone(ch.With), From: slices.Clone(ch.Sources), Private: ch.Private.All, ChannelId: ch.ChannelID,
	}
	if len(ch.Private.PerSide) > 0 {
		def.PrivatePerSide = maps.Clone(ch.Private.PerSide)
	}
	return &directoryrosterv1.SlackSharedChannel{Channel: def}
}

// sharedOf is a request's definition as the reconciler's: trimmed, sources
// lowercased and without repeats.
func sharedOf(def *directoryrosterv1.SlackSharedChannelDefinition) reconcile.SharedChannel {
	ch := reconcile.SharedChannel{
		Name: strings.TrimSpace(def.GetName()), Host: strings.TrimSpace(def.GetHost()),
		With: trimmed(def.GetWith(), false), Sources: trimmed(def.GetFrom(), true), ChannelID: strings.TrimSpace(def.GetChannelId()),
	}
	if per := def.GetPrivatePerSide(); len(per) > 0 {
		ch.Private.PerSide = maps.Clone(per)
	} else {
		ch.Private.All = def.GetPrivate()
	}
	return ch
}

// trimmed is a request's list without blanks and repeats; lower folds case,
// for addresses.
func trimmed(in []string, lower bool) []string {
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if lower {
			s = strings.ToLower(s)
		}
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func auditShared(ch reconcile.SharedChannel) audit.SlackSharedChannel {
	return audit.SlackSharedChannel{
		Name: ch.Name, Host: ch.Host, With: ch.With, Sources: ch.Sources, Private: ch.Private.All, PerSide: ch.Private.PerSide,
	}
}

// sharedError is a store's failure as the caller sees it.
func sharedError(err error) error {
	var connectErr *connect.Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &connectErr):
		return err
	case errors.Is(err, kube.ErrSharedConflict):
		return connect.NewError(connect.CodeAborted,
			errors.New("the shared channel records were changed by someone else while this was written: reload and try again"))
	default:
		return connect.NewError(connect.CodeUnavailable, err)
	}
}

// CreateSlackSharedChannel defines a channel: operator of the host
// workspace's owner, or of the installation.
func (c *Console) CreateSlackSharedChannel(
	ctx context.Context, req *connect.Request[directoryrosterv1.CreateSlackSharedChannelRequest],
) (*connect.Response[directoryrosterv1.CreateSlackSharedChannelResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackSharedStore()
	if err != nil {
		return nil, err
	}
	want := sharedOf(req.Msg.GetChannel())
	if _, err = c.requireSlack(ctx, access.RoleOperator, want.Host); err != nil {
		return nil, err
	}
	if err = want.Validate(c.deps.Authorizer.Policy().Declared()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err = c.checkSources(ctx, want.Sources, "", false); err != nil {
		return nil, err
	}
	if err = c.sharedClashesWithConsole(ctx, want); err != nil {
		return nil, err
	}
	if want.ChannelID != "" {
		reports := c.slackReports(ctx)
		seen, found := discoveredIn(reports, want.Host, want.ChannelID)
		switch {
		case !found:
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"the channel %s has not been discovered in the host workspace %s: only a channel its bot can see is taken under management; "+
					"if it is private there, invite the bot and refresh", want.ChannelID, want.Host))
		case seen.HostTeam != "" && reports[want.Host].Team != "" && seen.HostTeam != reports[want.Host].Team:
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"the channel %s is hosted by another Slack team, not by %s: it can be managed only from a connected workspace that hosts it", want.ChannelID, want.Host))
		}
	}
	err = store.Apply(ctx, want.Name, func(current *reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
		if current != nil {
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf(
				"a shared channel named %s already exists, hosted by %s: edit it, or pick another name", want.Name, current.Host))
		}
		return &want, nil
	})
	if err != nil {
		return nil, sharedError(err)
	}
	c.record(ctx, audit.SlackSharedChannelCreated(actorOf(ctx), auditShared(want)))
	view := sharedView(want)
	view.State, view.Reason = sharedState(want, c.deps.Authorizer.Policy().Declared(), c.slackReports(ctx))
	view.CanOperate = true
	return connect.NewResponse(&directoryrosterv1.CreateSlackSharedChannelResponse{Channel: view}), nil
}

// UpdateSlackSharedChannel changes with, from (directory groups) and private. The caller's
// role is asked about the STORED host, which a request cannot change.
func (c *Console) UpdateSlackSharedChannel(
	ctx context.Context, req *connect.Request[directoryrosterv1.UpdateSlackSharedChannelRequest],
) (*connect.Response[directoryrosterv1.UpdateSlackSharedChannelResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackSharedStore()
	if err != nil {
		return nil, err
	}
	want := sharedOf(req.Msg.GetChannel())
	var changes string
	err = store.Apply(ctx, want.Name, func(current *reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
		if current == nil {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("there is no shared channel named %s", want.Name))
		}
		if _, err := c.requireSlack(ctx, access.RoleOperator, current.Host); err != nil {
			return nil, err
		}
		if want.Host != current.Host {
			return nil, errSharedImmutable("host", current.Host, want.Host)
		}
		if want.ChannelID != current.ChannelID {
			return nil, errSharedImmutable("channel id", current.ChannelID, want.ChannelID)
		}
		if err := want.Validate(c.deps.Authorizer.Policy().Declared()); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		if err := c.checkSources(ctx, want.Sources, "", false); err != nil {
			return nil, err
		}
		changes = sharedChanges(*current, want)
		return &want, nil
	})
	if err != nil {
		return nil, sharedError(err)
	}
	if changes != "" {
		c.record(ctx, audit.SlackSharedChannelUpdated(actorOf(ctx), auditShared(want), changes))
	}
	view := sharedView(want)
	view.State, view.Reason = sharedState(want, c.deps.Authorizer.Policy().Declared(), c.slackReports(ctx))
	view.CanOperate = true
	return connect.NewResponse(&directoryrosterv1.UpdateSlackSharedChannelResponse{Channel: view}), nil
}

// sourcesChange says how a channel's directory groups changed, by count: the
// groups themselves are the audit record's targets, and an address is never
// carried as data. Empty when they did not change.
func sourcesChange(before, after []string) string {
	if slices.Equal(slices.Sorted(slices.Values(before)), slices.Sorted(slices.Values(after))) {
		return ""
	}
	added, removed := 0, 0
	for _, s := range after {
		if !slices.Contains(before, s) {
			added++
		}
	}
	for _, s := range before {
		if !slices.Contains(after, s) {
			removed++
		}
	}
	return fmt.Sprintf("sources: %d -> %d groups (%d added, %d removed)", len(before), len(after), added, removed)
}

// sharedChanges says what an edit changed, as 'field: before -> after'
// parts in a fixed order; empty when nothing did.
func sharedChanges(before, after reconcile.SharedChannel) string {
	var parts []string
	if !slices.Equal(before.With, after.With) {
		parts = append(parts, "with: "+strings.Join(before.With, ",")+" -> "+strings.Join(after.With, ","))
	}
	if part := sourcesChange(before.Sources, after.Sources); part != "" {
		parts = append(parts, part)
	}
	was, is := auditShared(before).Privacy(), auditShared(after).Privacy()
	if was != is {
		parts = append(parts, "private: "+was+" -> "+is)
	}
	return strings.Join(parts, "; ")
}

// DeleteSlackSharedChannel forgets the record. The channel stays in Slack.
func (c *Console) DeleteSlackSharedChannel(
	ctx context.Context, req *connect.Request[directoryrosterv1.DeleteSlackSharedChannelRequest],
) (*connect.Response[directoryrosterv1.DeleteSlackSharedChannelResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackSharedStore()
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Msg.GetName())
	var gone reconcile.SharedChannel
	err = store.Apply(ctx, name, func(current *reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
		if current == nil {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("there is no shared channel named %s", name))
		}
		if _, err := c.requireSlack(ctx, access.RoleOperator, current.Host); err != nil {
			return nil, err
		}
		gone = *current
		return nil, nil
	})
	if err != nil {
		return nil, sharedError(err)
	}
	c.record(ctx, audit.SlackSharedChannelDeleted(actorOf(ctx), auditShared(gone)))
	return connect.NewResponse(&directoryrosterv1.DeleteSlackSharedChannelResponse{Note: fmt.Sprintf(
		"The record of %s is deleted. The channel itself stays in Slack, archived by nobody, and the reconciler no longer manages its members: "+
			"people who were added stay until someone removes them in Slack.", name)}), nil
}
