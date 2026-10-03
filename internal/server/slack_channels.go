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
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// SlackChannelRecords is where console channels' records are kept: the
// records the Slack controller reads.
type SlackChannelRecords interface {
	List(ctx context.Context) ([]connection.ChannelRecord, error)
	// Apply reads one record (nil when there is none), asks decide what it
	// becomes (nil deletes it) and writes that under the object's version.
	// decide is given every record as read, for a check across records.
	Apply(ctx context.Context, workspace, name string,
		decide func(current *reconcile.ConsoleChannel, all []connection.ChannelRecord) (*reconcile.ConsoleChannel, error)) error
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
	case errors.Is(err, connection.ErrChannelConflict):
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
		Ignore: trimmed(def.GetIgnore(), false), Sources: trimmed(def.GetSources(), true), Members: addresses(def.GetMembers()),
	}
}

func consoleDefinition(ch reconcile.ConsoleChannel) *directoryrosterv1.SlackChannelDefinition {
	mode := ch.Mode
	if mode == "" {
		mode = policy.SlackModeExtend
	}
	return &directoryrosterv1.SlackChannelDefinition{
		Workspace: ch.Workspace, Name: ch.Name, ChannelId: ch.ChannelID, Private: ch.Private, Mode: mode,
		Ignore: slices.Clone(ch.Ignore), Sources: slices.Clone(ch.Sources), Members: slices.Clone(ch.Members),
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
	return audit.SlackConsoleChannel{Workspace: ch.Workspace, Name: ch.Name, Private: ch.Private, Mode: ch.Mode, Sources: ch.Sources, Members: ch.Members}
}

// consoleState is where a record stands: first whether the policy in force
// still accepts it, then what the workspace's controller reported for it.
func consoleState(ch reconcile.ConsoleChannel, p policy.Policy, reports map[string]status.Workspace) (state, reason string) {
	if err := ch.Validate(p); err != nil {
		if errors.Is(err, reconcile.ErrDefinedInGit) {
			// Held, as the controller reports it on both rows: not an invalid record.
			return sharedHeld, reconcile.DefinedTwice
		}
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
			Acting: reports[key].Enabled,
		})
	}
	if len(owners) > 0 {
		out.SourceDirectories, out.SourceDirectoriesError = c.sourceDirectories(ctx, owners...)
	}
	var records []connection.ChannelRecord
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
func managedOrdinary(records []connection.ChannelRecord, workspace string, d status.Discovered) bool {
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
	return c.checkSources(ctx, want.Sources, want.Members, book.owner(want.Workspace), true)
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
	if want.ChannelID != "" {
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
	err = store.Apply(ctx, want.Workspace, want.Name, func(current *reconcile.ConsoleChannel, all []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
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
	c.record(ctx, audit.SlackConsoleChannelCreated(actorOf(ctx), auditConsole(want)))
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
	err = store.Apply(ctx, want.Workspace, want.Name, func(current *reconcile.ConsoleChannel, _ []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		if current == nil {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("there is no console channel named %s in %s", want.Name, want.Workspace))
		}
		if want.ChannelID != current.ChannelID {
			return nil, errConsoleImmutable("channel id", current.ChannelID, want.ChannelID)
		}
		if want.Private != current.Private {
			return nil, errConsoleImmutable("visibility", visibilityWord(current.Private), visibilityWord(want.Private))
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
	if part := membersChange(before.Members, after.Members); part != "" {
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

// DeleteSlackChannel forgets the record. The channel stays in Slack, unless
// the request asks for it to be archived too.
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
	var target archiveTarget
	if req.Msg.GetArchive() {
		// Every check comes before anything is changed: a refusal leaves the
		// record where it was.
		if target, err = c.checkArchive(ctx, store, workspace, name); err != nil {
			return nil, err
		}
	}
	var gone reconcile.ConsoleChannel
	err = store.Apply(ctx, workspace, name, func(current *reconcile.ConsoleChannel, _ []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
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
	if req.Msg.GetArchive() {
		archived, note := c.archiveForgotten(ctx, gone, target)
		return connect.NewResponse(&directoryrosterv1.DeleteSlackChannelResponse{Note: note, Archived: archived}), nil
	}
	return connect.NewResponse(&directoryrosterv1.DeleteSlackChannelResponse{Note: fmt.Sprintf(
		"The record of %s in %s is deleted. The channel itself stays in Slack, and the reconciler no longer manages its members: "+
			"people who were added stay until someone removes them in Slack.", gone.Name, gone.Workspace)}), nil
}

// archiveTarget is what checkArchive resolved: the channel's Slack id and the
// token of the bot that acts on it.
type archiveTarget struct{ id, token string }

// byHand is the refusal that sends the operator to Slack: nothing was changed.
func byHand(format string, args ...any) error {
	return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(format+"; nothing was changed", args...))
}

// slackShared reports whether Slack says a channel is shared beyond its own
// workspace: one of Slack's sharing flags, or any team id other than own in the
// teams it lists (Slack may list a workspace's own team for an ordinary
// channel, which is not sharing). With own unknown, any listed id counts.
func slackShared(ch slackapp.Channel, own string) bool {
	if ch.IsExtShared || ch.IsShared || ch.IsOrgShared {
		return true
	}
	listed := slices.Concat(ch.SharedTeamIDs, ch.ConnectedTeamIDs, ch.PendingSharedTeamIDs, ch.PendingConnectedTeamIDs, ch.InternalTeamIDs,
		[]string{ch.ConversationHostID})
	return slices.ContainsFunc(listed, func(id string) bool { return id != "" && (own == "" || id != own) })
}

// checkArchive is everything an archiving delete asks before it changes
// anything: the workspace acts (its controller reports it enabled; a dry run,
// or no report, means archive it by hand), the channel is not shared (Slack is
// asked, not the report), and the bot can see it. Only an ordinary channel is
// archived from here: archiving a Slack Connect channel closes it for every
// organisation in it.
func (c *Console) checkArchive(ctx context.Context, store SlackChannelRecords, workspace, name string) (archiveTarget, error) {
	report, ok := c.slackReport(ctx, workspace)
	if !ok || !report.Enabled {
		return archiveTarget{}, byHand("the workspace is a dry run (or has no report yet): archive %s in Slack by hand", name)
	}
	id := ""
	for i := range report.Channels {
		ch := &report.Channels[i]
		if ch.Name != name {
			continue
		}
		if ch.Shared {
			return archiveTarget{}, byHand("%s is a Slack Connect channel: archiving closes it for every organisation in it; archive it in Slack by hand", name)
		}
		if ch.Console {
			id = ch.ID
		}
	}
	records, err := store.List(ctx)
	if err != nil {
		return archiveTarget{}, connect.NewError(connect.CodeUnavailable, err)
	}
	for i := range records {
		if rec := &records[i]; rec.Err == nil && rec.Workspace == workspace && rec.Name == name && rec.Channel.ChannelID != "" {
			id = rec.Channel.ChannelID
		}
	}
	if id == "" {
		return archiveTarget{}, byHand("the controller has not seen %s yet, so its Slack id is unknown: archive it in Slack by hand", name)
	}
	ws, err := c.slackWorkspaceStore()
	if err != nil {
		return archiveTarget{}, byHand("this deployment keeps no Slack connections: archive %s in Slack by hand", name)
	}
	record, credential, found, err := ws.Get(ctx, workspace)
	if err != nil {
		return archiveTarget{}, connect.NewError(connect.CodeUnavailable, err)
	}
	if !found || credential.BotToken == "" {
		return archiveTarget{}, byHand("the workspace has no bot token to act with: archive %s in Slack by hand", name)
	}
	callCtx, cancel := context.WithTimeout(ctx, slackTimeout)
	defer cancel()
	info, err := slackapp.New(credential.BotToken, c.deps.SlackAPI...).ChannelInfo(callCtx, id)
	switch {
	case errors.Is(err, slackapp.ErrChannelNotFound), errors.Is(err, slackapp.ErrNotInChannel):
		return archiveTarget{}, byHand("the bot cannot see %s (a private channel it is not in): archive it in Slack by hand", name)
	case err != nil:
		return archiveTarget{}, connect.NewError(connect.CodeUnavailable, fmt.Errorf(
			"no answer from Slack about %s, so it was not archived and nothing was changed: %w", name, err))
	case slackShared(info, orDefault(record.TeamID, report.Team)):
		return archiveTarget{}, byHand("%s is a Slack Connect channel: archiving closes it for every organisation in it; archive it in Slack by hand", name)
	}
	return archiveTarget{id: id, token: credential.BotToken}, nil
}

// archiveForgotten archives, in Slack, the channel whose record was just
// forgotten, and says plainly what happened. checkArchive has already asked
// Slack that the channel is ordinary and visible; when the archive itself
// still fails the record is gone and the note says to archive it by hand.
func (c *Console) archiveForgotten(ctx context.Context, gone reconcile.ConsoleChannel, to archiveTarget) (archived bool, note string) {
	kept := fmt.Sprintf("The record of %s in %s is deleted and the reconciler no longer manages its members.", gone.Name, gone.Workspace)
	by := func(why string) string {
		return kept + " It was not archived: " + why + ". Archive it in Slack by hand."
	}
	id := to.id
	callCtx, cancel := context.WithTimeout(ctx, slackTimeout)
	defer cancel()
	err := slackapp.New(to.token, c.deps.SlackAPI...).Archive(callCtx, id)
	target := audit.SlackChannel{Workspace: gone.Workspace, Name: gone.Name, ID: id, Private: gone.Private}
	if err != nil {
		c.record(ctx, audit.SlackChannelArchived(actorOf(ctx), target, audit.Failed(slackErrorWord(err))))
		return false, by(slackErrorWord(err))
	}
	c.record(ctx, audit.SlackChannelArchived(actorOf(ctx), target, audit.Succeeded()))
	return true, fmt.Sprintf("The record of %s in %s is deleted and the channel is archived in Slack.", gone.Name, gone.Workspace)
}

// slackErrorWord says why Slack would not archive a channel, in words.
func slackErrorWord(err error) string {
	switch {
	case errors.Is(err, slackapp.ErrNotInChannel), errors.Is(err, slackapp.ErrChannelNotFound):
		return "the bot is not in the channel (a private channel it cannot see)"
	case errors.Is(err, slackapp.ErrMissingScope):
		return "the App lacks the scope to archive"
	case errors.Is(err, slackapp.ErrRestricted):
		return "the workspace's settings forbid a bot archiving it"
	}
	return "Slack refused: " + err.Error()
}
