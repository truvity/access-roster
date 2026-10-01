package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// SlackChannelRecords is where console channels' records are kept: the
// records the Slack controller reads.
type SlackChannelRecords interface {
	List(ctx context.Context) ([]kube.ChannelRecord, error)
	// Apply reads one record (nil when there is none), asks decide what it
	// becomes (nil deletes it) and writes that under the object's version.
	// decide is given every record as read, for a check across records.
	Apply(ctx context.Context, workspace, name string,
		decide func(current *reconcile.ConsoleChannel, all []kube.ChannelRecord) (*reconcile.ConsoleChannel, error)) error
}

func (c *Console) slackChannelStore() (SlackChannelRecords, error) {
	if c.deps.SlackChannels == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no state in Kubernetes, so a channel's record would not survive a restart"))
	}
	return c.deps.SlackChannels, nil
}

// channelError is a store's failure as the caller sees it.
func channelError(err error) error {
	var connectErr *connect.Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &connectErr):
		return err
	case errors.Is(err, kube.ErrChannelConflict):
		return connect.NewError(connect.CodeAborted,
			errors.New("the console channel records were changed by someone else while this was written: reload and try again"))
	default:
		return connect.NewError(connect.CodeUnavailable, err)
	}
}

// consoleOf is a request's definition as the reconciler's: trimmed, sources
// lowercased and without repeats.
func consoleOf(def *directoryrosterv1.SlackChannelDefinition) reconcile.ConsoleChannel {
	mode := strings.TrimSpace(def.GetMode())
	if mode == policy.SlackModeExtend {
		mode = "" // the default is stored as nothing
	}
	return reconcile.ConsoleChannel{
		Workspace: strings.TrimSpace(def.GetWorkspace()), Name: strings.TrimSpace(def.GetName()),
		ChannelID: strings.TrimSpace(def.GetChannelId()), Private: def.GetPrivate(), Mode: mode,
		Ignore: trimmed(def.GetIgnore(), false), Sources: trimmed(def.GetSources(), true),
		SupersedesPolicy: def.GetSupersedesPolicy(),
	}
}

func consoleDefinition(ch reconcile.ConsoleChannel) *directoryrosterv1.SlackChannelDefinition {
	mode := ch.Mode
	if mode == "" {
		mode = policy.SlackModeExtend
	}
	return &directoryrosterv1.SlackChannelDefinition{
		Workspace: ch.Workspace, Name: ch.Name, ChannelId: ch.ChannelID, Private: ch.Private, Mode: mode,
		Ignore: slices.Clone(ch.Ignore), Sources: slices.Clone(ch.Sources), SupersedesPolicy: ch.SupersedesPolicy,
	}
}

func consoleView(ch reconcile.ConsoleChannel) *directoryrosterv1.SlackChannelRecord {
	out := &directoryrosterv1.SlackChannelRecord{Channel: consoleDefinition(ch), CreatedBy: ch.CreatedBy, UpdatedBy: ch.UpdatedBy}
	if !ch.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(ch.CreatedAt)
	}
	if !ch.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(ch.UpdatedAt)
	}
	return out
}

func auditConsole(ch reconcile.ConsoleChannel) audit.SlackConsoleChannel {
	return audit.SlackConsoleChannel{Workspace: ch.Workspace, Name: ch.Name, Private: ch.Private, Mode: ch.Mode, Sources: ch.Sources}
}

// checkTakeover is what a record that takes over a policy channel must also
// satisfy: it covers exactly one policy channel (Validate has refused two),
// shows the same visibility, and names the channel the policy and the latest
// report know it by, so the takeover can never land on another channel.
func (c *Console) checkTakeover(want reconcile.ConsoleChannel, reports map[string]status.Workspace) error {
	ws := c.deps.Authorizer.Policy().Declared().Slack.Workspaces[want.Workspace]
	covered := want.CoveredPolicy(ws)
	if len(covered) != 1 {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"supersedes_policy is set but %s defines no policy channel called %s or with channel id %q to take over",
			want.Workspace, want.Name, want.ChannelID))
	}
	b := ws.Channels[covered[0]]
	if b.Private != want.Private {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"the policy channel %s is %s and the record says %s: the roster never changes a channel's visibility",
			covered[0], visibilityWord(b.Private), visibilityWord(want.Private)))
	}
	expected := b.Adopt
	if expected == "" {
		for i := range reports[want.Workspace].Channels {
			rep := &reports[want.Workspace].Channels[i]
			if rep.Name == covered[0] && !rep.Console && !rep.Shared {
				expected = rep.ID
			}
		}
	}
	if expected != "" && want.ChannelID != expected {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
			"the policy channel %s is the Slack channel %s: a takeover must name that channel id, not %q", covered[0], expected, want.ChannelID))
	}
	return nil
}

// consoleState is where a record stands: first whether the policy in force
// still accepts it, then what the workspace's controller reported for it.
func consoleState(ch reconcile.ConsoleChannel, p policy.Policy, reports map[string]status.Workspace) (state, reason string) {
	if err := ch.Validate(p); err != nil {
		return sharedInvalid, err.Error()
	}
	report, ok := reports[ch.Workspace]
	if !ok {
		return sharedNotReported, "the workspace's controller has reported nothing yet"
	}
	for i := range report.Channels {
		rep := &report.Channels[i]
		if rep.Name != ch.Name || !rep.Console || rep.Shared {
			continue
		}
		switch rep.State {
		case status.ChannelOK:
			return sharedActive, ""
		case status.ChannelHeld:
			if strings.Contains(rep.Reason, "record is refused") {
				return sharedInvalid, rep.Reason
			}
			return sharedHeld, rep.Reason
		default:
			return sharedPending, orDefault(rep.Reason, "the controller will act on it on its next pass")
		}
	}
	return sharedNotReported, "the workspace's report does not list this channel yet"
}

// ListSlackChannels is every record the caller may see, the channels the
// bots see that nothing manages, and the choices a form offers.
func (c *Console) ListSlackChannels(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListSlackChannelsRequest],
) (*connect.Response[directoryrosterv1.ListSlackChannelsResponse], error) {
	id, book, err := c.requireAnySlack(ctx, access.RoleViewer)
	if err != nil {
		return nil, err
	}
	set := c.deps.Authorizer.Policy()
	p := set.Declared()
	reports := c.slackReports(ctx)
	out := &directoryrosterv1.ListSlackChannelsResponse{Available: c.deps.SlackChannels != nil}
	var owners []string
	for _, key := range set.SlackWorkspaceKeys() {
		if !book.may(id, access.RoleViewer, key) {
			continue
		}
		operate := book.mayAct(id, key)
		if operate && book.owner(key) != "" {
			owners = append(owners, book.owner(key))
		}
		out.Workspaces = append(out.Workspaces, &directoryrosterv1.SlackChannelWorkspace{
			Key: key, CanOperate: operate, Owner: book.owner(key), DiscoveredMore: int32(reports[key].DiscoveredMore), //nolint:gosec // a count
		})
	}
	if len(owners) > 0 {
		out.SourceDirectories = c.sourceDirectories(ctx, owners...)
	}
	var records []kube.ChannelRecord
	if c.deps.SlackChannels != nil {
		if records, err = c.deps.SlackChannels.List(ctx); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
	}
	for i := range records {
		rec := &records[i]
		if rec.Err != nil {
			// Whose it is cannot be read: only the installation-wide role sees
			// it, to fix or delete it.
			if id.Can(access.RoleViewer) {
				out.Channels = append(out.Channels, &directoryrosterv1.SlackChannelRecord{
					Channel: &directoryrosterv1.SlackChannelDefinition{Workspace: rec.Workspace, Name: rec.Name},
					State:   sharedInvalid, Reason: rec.Err.Error(), CanOperate: id.Can(access.RoleOperator),
				})
			}
			continue
		}
		if !book.may(id, access.RoleViewer, rec.Workspace) {
			continue
		}
		view := consoleView(rec.Channel)
		view.State, view.Reason = consoleState(rec.Channel, p, reports)
		view.CanOperate = book.mayAct(id, rec.Workspace)
		out.Channels = append(out.Channels, view)
	}
	for _, key := range slices.Sorted(maps.Keys(reports)) {
		if _, declared := p.Slack.Workspaces[key]; !declared || !book.may(id, access.RoleViewer, key) {
			continue
		}
		for _, d := range reports[key].Discovered {
			if managedOrdinary(records, key, d) {
				continue
			}
			out.Discovered = append(out.Discovered, &directoryrosterv1.SlackDiscoveredOrdinary{
				Workspace: key, ChannelId: d.ID, Name: d.Name, Private: d.Private, Members: int32(d.Members), //nolint:gosec // a member count
				CanManage: c.deps.SlackChannels != nil && book.mayAct(id, key),
			})
		}
	}
	return connect.NewResponse(out), nil
}

// managedOrdinary reports whether a record already covers a discovered
// channel: a report can be a pass behind a record just written.
func managedOrdinary(records []kube.ChannelRecord, workspace string, d status.Discovered) bool {
	for i := range records {
		rec := &records[i]
		if rec.Err != nil || rec.Workspace != workspace {
			continue
		}
		if rec.Channel.ChannelID == d.ID || (rec.Channel.ChannelID == "" && rec.Channel.Name == d.Name) {
			return true
		}
	}
	return false
}

// sharedClashesWithConsole refuses a Slack Connect record for a channel the
// host workspace already manages as a console channel: one channel is
// managed one way.
func (c *Console) sharedClashesWithConsole(ctx context.Context, want reconcile.SharedChannel) error {
	if c.deps.SlackChannels == nil {
		return nil
	}
	records, err := c.deps.SlackChannels.List(ctx)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	for i := range records {
		rec := &records[i]
		if rec.Err != nil || rec.Workspace != want.Host {
			continue
		}
		if rec.Name == want.Name || (want.ChannelID != "" && rec.Channel.ChannelID == want.ChannelID) {
			return connect.NewError(connect.CodeAlreadyExists, fmt.Errorf(
				"the channel %s is already managed in %s as an ordinary console channel: delete that record first, a channel is managed one way", rec.Name, want.Host))
		}
	}
	return nil
}

// consoleClashesWithShared is the other direction: an ordinary record for a
// channel a Slack Connect record of the same workspace already manages.
func (c *Console) consoleClashesWithShared(ctx context.Context, want reconcile.ConsoleChannel) error {
	if c.deps.SlackShared == nil {
		return nil
	}
	records, err := c.deps.SlackShared.List(ctx)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	for i := range records {
		rec := &records[i]
		if rec.Err != nil || rec.Channel.Host != want.Workspace {
			continue
		}
		if rec.Name == want.Name || (want.ChannelID != "" && rec.Channel.ChannelID == want.ChannelID) {
			return connect.NewError(connect.CodeAlreadyExists, fmt.Errorf(
				"the channel %s is already managed in %s as a Slack Connect channel: delete that record first, a channel is managed one way", rec.Name, want.Workspace))
		}
	}
	return nil
}

// validateConsole is every check a record must pass before it is written,
// the same the controller makes at each pass.
func (c *Console) validateConsole(ctx context.Context, want reconcile.ConsoleChannel, book slackBook) error {
	if err := want.Validate(c.deps.Authorizer.Policy().Declared()); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return c.checkSources(ctx, want.Sources, book.owner(want.Workspace), true)
}

// CreateSlackChannel puts a channel under management: operator of the
// workspace's owner, or of the installation.
func (c *Console) CreateSlackChannel(
	ctx context.Context, req *connect.Request[directoryrosterv1.CreateSlackChannelRequest],
) (*connect.Response[directoryrosterv1.CreateSlackChannelResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackChannelStore()
	if err != nil {
		return nil, err
	}
	want := consoleOf(req.Msg.GetChannel())
	if _, err = c.requireSlack(ctx, access.RoleOperator, want.Workspace); err != nil {
		return nil, err
	}
	book, err := c.slackBook(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.validateConsole(ctx, want, book); err != nil {
		return nil, err
	}
	if err = c.consoleClashesWithShared(ctx, want); err != nil {
		return nil, err
	}
	reports := c.slackReports(ctx)
	if want.SupersedesPolicy {
		// A policy channel is not "discovered": it is managed, by git.
		if err = c.checkTakeover(want, reports); err != nil {
			return nil, err
		}
	} else if want.ChannelID != "" {
		seen, found := discoveredOrdinaryIn(reports, want.Workspace, want.ChannelID)
		switch {
		case !found:
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"the channel %s has not been discovered in %s: only a channel its bot can see is taken under management; "+
					"if it is private there, invite the bot and refresh", want.ChannelID, want.Workspace))
		case seen.Private != want.Private:
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"the channel %s is %s in Slack and the record says %s: the roster never changes a channel's visibility",
				want.ChannelID, visibilityWord(seen.Private), visibilityWord(want.Private)))
		}
	}
	actor := identityName(ctx)
	now := time.Now().UTC()
	want.CreatedBy, want.CreatedAt, want.UpdatedBy, want.UpdatedAt = actor, now, actor, now
	err = store.Apply(ctx, want.Workspace, want.Name, func(current *reconcile.ConsoleChannel, all []kube.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		if current != nil {
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf(
				"a console channel named %s already exists in %s: edit it, or pick another name", want.Name, want.Workspace))
		}
		for i := range all {
			if all[i].Err == nil && want.ChannelID != "" && all[i].Workspace == want.Workspace && all[i].Channel.ChannelID == want.ChannelID {
				return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf(
					"the channel %s is already managed in %s as %s", want.ChannelID, want.Workspace, all[i].Name))
			}
		}
		return &want, nil
	})
	if err != nil {
		return nil, channelError(err)
	}
	created := auditConsole(want)
	created.Takeover = want.SupersedesPolicy
	c.record(ctx, audit.SlackConsoleChannelCreated(actorOf(ctx), created))
	view := consoleView(want)
	view.State, view.Reason = consoleState(want, c.deps.Authorizer.Policy().Declared(), reports)
	view.CanOperate = true
	return connect.NewResponse(&directoryrosterv1.CreateSlackChannelResponse{Channel: view}), nil
}

func visibilityWord(private bool) string {
	if private {
		return privacyPrivate
	}
	return privacyPublic
}

// identityName is who the caller is, for the page: the address, else the
// subject.
func identityName(ctx context.Context) string {
	id, ok := IdentityFrom(ctx)
	switch {
	case !ok:
		return ""
	case id.Email != "":
		return id.Email
	}
	return id.Subject
}

// discoveredOrdinaryIn is the workspace's own sighting of a channel id.
func discoveredOrdinaryIn(reports map[string]status.Workspace, workspace, channelID string) (status.Discovered, bool) {
	for _, d := range reports[workspace].Discovered {
		if d.ID == channelID {
			return d, true
		}
	}
	return status.Discovered{}, false
}

// errConsoleImmutable is what a change of workspace, name, id or visibility
// is answered with.
func errConsoleImmutable(what, was, got string) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
		"a console channel's %s cannot change (it is %q, the request says %q): create a new record with the %s you want, "+
			"and delete this one if the old channel should no longer be managed", what, was, got, what))
}

// UpdateSlackChannel changes mode, ignore and sources. The caller's role is
// asked about the STORED workspace, which a request cannot change.
func (c *Console) UpdateSlackChannel(
	ctx context.Context, req *connect.Request[directoryrosterv1.UpdateSlackChannelRequest],
) (*connect.Response[directoryrosterv1.UpdateSlackChannelResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackChannelStore()
	if err != nil {
		return nil, err
	}
	want := consoleOf(req.Msg.GetChannel())
	if _, err = c.requireSlack(ctx, access.RoleOperator, want.Workspace); err != nil {
		return nil, err
	}
	book, err := c.slackBook(ctx)
	if err != nil {
		return nil, err
	}
	var changes string
	var written reconcile.ConsoleChannel
	err = store.Apply(ctx, want.Workspace, want.Name, func(current *reconcile.ConsoleChannel, _ []kube.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		if current == nil {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("there is no console channel named %s in %s", want.Name, want.Workspace))
		}
		if want.ChannelID != current.ChannelID {
			return nil, errConsoleImmutable("channel id", current.ChannelID, want.ChannelID)
		}
		if want.Private != current.Private {
			return nil, errConsoleImmutable("visibility", visibilityWord(current.Private), visibilityWord(want.Private))
		}
		if want.SupersedesPolicy != current.SupersedesPolicy {
			return nil, errConsoleImmutable("supersedes_policy", fmt.Sprint(current.SupersedesPolicy), fmt.Sprint(want.SupersedesPolicy))
		}
		if err := c.validateConsole(ctx, want, book); err != nil {
			return nil, err
		}
		want.CreatedBy, want.CreatedAt = current.CreatedBy, current.CreatedAt
		changes = consoleChanges(*current, want)
		if changes == "" {
			written = *current
			return current, nil
		}
		want.UpdatedBy, want.UpdatedAt = identityName(ctx), time.Now().UTC()
		written = want
		return &want, nil
	})
	if err != nil {
		return nil, channelError(err)
	}
	if changes != "" {
		c.record(ctx, audit.SlackConsoleChannelUpdated(actorOf(ctx), auditConsole(written), changes))
	}
	view := consoleView(written)
	view.State, view.Reason = consoleState(written, c.deps.Authorizer.Policy().Declared(), c.slackReports(ctx))
	view.CanOperate = true
	return connect.NewResponse(&directoryrosterv1.UpdateSlackChannelResponse{Channel: view}), nil
}

// consoleChanges says what an edit changed, as 'field: before -> after'
// parts in a fixed order; empty when nothing did. An address is never
// written out: the ignore list is counted, the sources are counted.
func consoleChanges(before, after reconcile.ConsoleChannel) string {
	var parts []string
	if was, is := modeWord(before.Mode), modeWord(after.Mode); was != is {
		parts = append(parts, "mode: "+was+" -> "+is)
	}
	if part := sourcesChange(before.Sources, after.Sources); part != "" {
		parts = append(parts, part)
	}
	if !slices.Equal(slices.Sorted(slices.Values(before.Ignore)), slices.Sorted(slices.Values(after.Ignore))) {
		parts = append(parts, fmt.Sprintf("ignore: %d -> %d entries", len(before.Ignore), len(after.Ignore)))
	}
	return strings.Join(parts, "; ")
}

func modeWord(mode string) string {
	if mode == "" {
		return policy.SlackModeExtend
	}
	return mode
}

// DeleteSlackChannel forgets the record. The channel stays in Slack.
func (c *Console) DeleteSlackChannel(
	ctx context.Context, req *connect.Request[directoryrosterv1.DeleteSlackChannelRequest],
) (*connect.Response[directoryrosterv1.DeleteSlackChannelResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackChannelStore()
	if err != nil {
		return nil, err
	}
	workspace, name := strings.TrimSpace(req.Msg.GetWorkspace()), strings.TrimSpace(req.Msg.GetName())
	if _, err = c.requireSlack(ctx, access.RoleOperator, workspace); err != nil {
		return nil, err
	}
	var gone reconcile.ConsoleChannel
	err = store.Apply(ctx, workspace, name, func(current *reconcile.ConsoleChannel, _ []kube.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		if current == nil {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("there is no console channel named %s in %s", name, workspace))
		}
		gone = *current
		return nil, nil
	})
	if err != nil {
		return nil, channelError(err)
	}
	c.record(ctx, audit.SlackConsoleChannelDeleted(actorOf(ctx), auditConsole(gone)))
	return connect.NewResponse(&directoryrosterv1.DeleteSlackChannelResponse{Note: fmt.Sprintf(
		"The record of %s in %s is deleted. The channel itself stays in Slack, and the reconciler no longer manages its members: "+
			"people who were added stay until someone removes them in Slack.", name, workspace)}), nil
}
