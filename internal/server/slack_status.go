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

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// GetSlackStatus is every Slack workspace the caller may view: the ones the
// policy declares, and any the controller reports on or a connection
// exists for that it no longer does (which only the installation-wide role
// sees, for want of an owner). A workspace's owner and team are the ones its
// connection recorded.
func (c *Console) GetSlackStatus(
	ctx context.Context, _ *connect.Request[directoryrosterv1.GetSlackStatusRequest],
) (*connect.Response[directoryrosterv1.GetSlackStatusResponse], error) {
	id, book, err := c.requireAnySlack(ctx, access.RoleViewer)
	if err != nil {
		return nil, err
	}
	dirs, err := c.directories(ctx)
	if err != nil {
		return nil, err
	}
	domains := ownerDomains(dirs)
	out := &directoryrosterv1.GetSlackStatusResponse{
		ReportsAvailable:    c.deps.SlackStatus != nil,
		ConnectingAvailable: c.deps.SlackWorkspaces != nil,
		BotScopes:           slices.Clone(connection.BotScopes),
		RedirectUrl:         c.slackWorkspaceRedirect(),
	}
	out.OwnerChoices, out.MayConnectWithoutOwner = ownerChoices(id, dirs)

	reports := map[string]string{}
	if c.deps.SlackStatus != nil {
		read, err := c.deps.SlackStatus.Reports(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
		for key, document := range read {
			if workspace, ok := status.WorkspaceOfKey(key); ok {
				reports[workspace] = document
			}
		}
	}
	connections := map[string]connection.Record(book)
	confirmations := map[string]connection.Confirmation{}
	if c.deps.SlackWorkspaces != nil {
		if confirmations, err = c.deps.SlackWorkspaces.Confirmations(ctx); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
	}

	passes := map[string]connection.PassRequest{}
	if c.deps.SlackWorkspaces != nil {
		if passes, err = c.deps.SlackWorkspaces.PassRequests(ctx); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
	}

	seen, declared := map[string]bool{}, map[string]bool{}
	for _, workspace := range c.deps.Authorizer.Policy().SlackWorkspaceKeys() {
		seen[workspace], declared[workspace] = true, true
	}
	for workspace := range reports {
		seen[workspace] = true
	}
	for workspace := range connections {
		seen[workspace] = true
	}
	now := time.Now()
	for _, workspace := range slices.Sorted(maps.Keys(seen)) {
		// A key nothing declares and nothing is connected for (a stale
		// report) is nobody's to connect: the installation-wide role sees it.
		_, connected := connections[workspace]
		mayView, mayOperate := book.may(id, access.RoleViewer, workspace), book.may(id, access.RoleOperator, workspace)
		if !connected && !declared[workspace] {
			mayView, mayOperate = id.Can(access.RoleViewer), id.Can(access.RoleOperator)
		}
		if !mayView {
			continue
		}
		row := c.slackWorkspaceView(workspace, reports[workspace], confirmations, now)
		row.Declared = declared[workspace]
		if record, connected := connections[workspace]; connected {
			c.slackConnectionView(row, record)
			row.Owner, row.TeamId = record.Owner, record.TeamID
			row.OwnerDomain = domains[record.Owner]
			row.CanChangeOwner = id.Can(access.RoleOperator)
		}
		row.CanOperate = mayOperate
		row.PassRequestedAt = timestampOf(passes[workspace].At)
		out.Workspaces = append(out.Workspaces, row)
	}
	return connect.NewResponse(out), nil
}

// slackConnectionView says where a connection stands, from its record.
func (c *Console) slackConnectionView(row *directoryrosterv1.SlackWorkspaceStatus, record connection.Record) {
	row.ConnectionState = slackCreated
	row.Connection = &directoryrosterv1.SlackConnection{
		AppId: record.AppID, AppSettingsUrl: slackAppSettingsURL(record.AppID),
		ConnectedAt: timestampOf(record.ConnectedAt), ConnectedBy: record.ConnectedBy,
	}
	row.NeedsConfigurationToken = len(slackapp.MissingScopes(strings.Join(record.ManifestScopes, ","), connection.BotScopes)) > 0
	if !record.Installed() {
		return
	}
	row.ConnectionState = slackInstalled
	row.Connection.BotUserId = record.BotUserID
	row.Connection.GrantedScopes = slices.Clone(record.Scopes)
	if missing := slackapp.MissingScopes(strings.Join(record.Scopes, ","), connection.BotScopes); len(missing) > 0 {
		row.ConnectionState, row.MissingScopes = slackAppScopesMissing, missing
	}
}

// slackWorkspaceView is one workspace's row: its key, and the
// controller's report. A report that cannot be read is shown as a failed
// pass with the reason, not as no report: a page that says nothing about a
// workspace looks like one that has nothing to say.
func (c *Console) slackWorkspaceView(
	workspace, document string, confirmations map[string]connection.Confirmation, now time.Time,
) *directoryrosterv1.SlackWorkspaceStatus {
	row := &directoryrosterv1.SlackWorkspaceStatus{
		Workspace: workspace, ConnectionState: slackNotConnected,
	}
	if document == "" {
		return row
	}
	report, err := status.Decode(document)
	if err != nil {
		row.Reported = true
		row.Tick = &directoryrosterv1.SlackTick{Outcome: string(status.OutcomeFailed), Error: "the controller's report could not be read: " + err.Error()}
		return row
	}
	row.Reported, row.Acting = true, report.Enabled
	row.Tick = &directoryrosterv1.SlackTick{
		At: timestampOf(report.Tick.At), Outcome: string(report.Tick.Outcome), Error: report.Tick.Error,
		Changes: int32(report.Tick.Changes), Held: int32(report.Tick.Held),
		Retrying: int32(report.Tick.Retrying), Waiting: int32(report.Tick.Waiting),
	}
	row.Breaker = slackBreakerView(report.Breaker)
	row.RemovalConfirmation = slackConfirmationView(confirmations, workspace, "", now)
	for i := range report.Leavers {
		leaver := &report.Leavers[i]
		row.Leavers = append(row.Leavers, &directoryrosterv1.SlackLeaver{
			Email: leaver.Email, UserId: leaver.UserID, Channels: slices.Clone(leaver.Channels), Reason: leaver.Reason,
		})
	}
	for i := range report.Channels {
		ch := &report.Channels[i]
		view := &directoryrosterv1.SlackChannelStatus{
			Name: ch.Name, Id: ch.ID, Private: ch.Private, Mode: ch.Mode, Shared: ch.Shared, Host: ch.Host, Console: ch.Console,
			State: string(ch.State), Reason: ch.Reason, Breaker: slackBreakerView(ch.Breaker),
			RemovalConfirmation: slackConfirmationView(confirmations, workspace, ch.Name, now),
		}
		for j := range ch.Members {
			m := &ch.Members[j]
			view.Members = append(view.Members, &directoryrosterv1.SlackMemberStatus{
				Person: m.Person, Email: m.Email, UserId: m.UserID, State: string(m.State), Action: string(m.Action), Reason: m.Reason,
			})
		}
		row.Channels = append(row.Channels, view)
	}
	return row
}

func slackBreakerView(b *status.Breaker) *directoryrosterv1.SlackBreaker {
	if b == nil {
		return nil
	}
	return &directoryrosterv1.SlackBreaker{
		Affected: int32(b.Affected), Total: int32(b.Total), Fingerprint: b.Fingerprint, Confirmed: b.Confirmed,
	}
}

// slackConfirmationView is the confirmation for a gate, while it has not
// lapsed.
func slackConfirmationView(
	all map[string]connection.Confirmation, workspace, channel string, now time.Time,
) *directoryrosterv1.SlackRemovalConfirmation {
	confirmation, ok := all[connection.ConfirmationKey(workspace, channel)]
	if !ok || !confirmation.Current(now) {
		return nil
	}
	return &directoryrosterv1.SlackRemovalConfirmation{
		Fingerprint: confirmation.Fingerprint, ConfirmedBy: confirmation.By, ConfirmedAt: timestampOf(confirmation.At),
	}
}

// ConfirmSlackRemovals lets exactly the removal set the operator saw go
// ahead. The fingerprint must be the one the latest report shows for that
// gate — the workspace's, or the named channel's: confirming a set that has
// since changed would confirm people nobody looked at.
func (c *Console) ConfirmSlackRemovals(
	ctx context.Context, req *connect.Request[directoryrosterv1.ConfirmSlackRemovalsRequest],
) (*connect.Response[directoryrosterv1.ConfirmSlackRemovalsResponse], error) {
	workspace, channel := strings.TrimSpace(req.Msg.GetWorkspace()), strings.TrimSpace(req.Msg.GetChannel())
	fingerprint := strings.TrimSpace(req.Msg.GetFingerprint())
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	id, err := c.requireSlack(ctx, access.RoleOperator, workspace)
	if err != nil {
		return nil, err
	}
	switch {
	case !status.ValidWorkspace(workspace) || fingerprint == "" || strings.Contains(channel, "."):
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a workspace and a fingerprint are required, and a channel name has no dot"))
	case c.deps.SlackStatus == nil || c.deps.SlackWorkspaces == nil:
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this deployment keeps no reports or confirmations"))
	}
	reports, err := c.deps.SlackStatus.Reports(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	report, err := status.Decode(reports[status.Key(workspace)])
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("%s has no readable report: %w", workspace, err))
	}
	gate := report.Breaker
	if channel != "" {
		gate = nil
		for i := range report.Channels {
			if report.Channels[i].Name == channel && report.Channels[i].Breaker != nil {
				gate = report.Channels[i].Breaker
				break
			}
		}
	}
	if gate == nil || gate.Fingerprint != fingerprint {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the removals in %s have changed since that page was loaded: reload and look again", slackGate(workspace, channel)))
	}
	if err = c.deps.SlackWorkspaces.PutConfirmation(ctx, connection.Confirmation{
		Workspace: workspace, Channel: channel, Fingerprint: fingerprint, By: id.Who(), At: time.Now().UTC(),
	}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	c.record(ctx, audit.SlackRemovalsConfirmed(identityActor(id), workspace, channel, fingerprint, gate.Affected))
	return connect.NewResponse(&directoryrosterv1.ConfirmSlackRemovalsResponse{}), nil
}

func slackGate(workspace, channel string) string {
	if channel == "" {
		return workspace
	}
	return workspace + "/" + channel
}
