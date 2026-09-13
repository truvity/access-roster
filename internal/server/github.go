package server

import (
	"context"
	"maps"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/policy"
)

// GitHubReports is where the console reads what the GitHub controller
// last reported: the documents of the status contract, keyed as written.
type GitHubReports interface {
	Reports(ctx context.Context) (map[string]string, error)
}

// GetGitHubStatus implements the GitHub page: every organisation the
// policy binds or the controller reports on, its bindings beside its
// report.
//
// The join happens here rather than in the browser so that the page has
// one answer to render. Bindings come from the policy in force and
// reports from the controller's ConfigMap; neither is authoritative for
// the other, and the page shows where they disagree — a bound team the
// controller has not reported, a report for a team the policy no longer
// binds — rather than hiding either side.
//
// Installation-wide viewer, not a viewer anywhere. A report names the
// members of every bound team across every company the installation
// serves, which is more than a tenant-scoped viewer may see of anybody.
func (c *Console) GetGitHubStatus(
	ctx context.Context, _ *connect.Request[directoryrosterv1.GetGitHubStatusRequest],
) (*connect.Response[directoryrosterv1.GetGitHubStatusResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	out := &directoryrosterv1.GetGitHubStatusResponse{
		ReportsAvailable:    c.deps.GitHub != nil,
		ConnectingAvailable: c.deps.GitHubOrgs != nil,
	}

	reports := map[string]string{}
	if c.deps.GitHub != nil {
		read, err := c.deps.GitHub.Reports(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
		for key, document := range read {
			if org, ok := status.OrgOfKey(key); ok {
				reports[org] = document
			}
		}
	}

	connections := map[string]connection.Record{}
	if c.deps.GitHubOrgs != nil {
		records, err := c.deps.GitHubOrgs.List(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
		for _, record := range records {
			connections[record.Org] = record
		}
	}

	confirmations := map[string]connection.Confirmation{}
	if c.deps.GitHubConfirmations != nil {
		read, err := c.deps.GitHubConfirmations.Confirmations(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
		confirmations = read
	}

	set := c.deps.Authorizer.Policy()
	bound := boundOrganisations(set)
	seen := map[string]bool{}
	for org := range bound {
		seen[org] = true
	}
	for org := range reports {
		seen[org] = true
	}
	for org := range connections {
		seen[org] = true
	}

	for _, org := range slices.Sorted(maps.Keys(seen)) {
		row := organisationProto(org, bound[org], reports[org])
		if record, connected := connections[org]; connected {
			row.Connection = connectionProto(record)
		}
		if confirmation, ok := confirmations[org]; ok && confirmation.Current(time.Now()) {
			row.RemovalConfirmation = &directoryrosterv1.GitHubRemovalConfirmation{
				Fingerprint: confirmation.Fingerprint, ConfirmedBy: confirmation.By, ConfirmedAt: timestampOf(confirmation.At),
			}
		}
		out.Organisations = append(out.Organisations, row)
	}
	if err := c.linkStatus(ctx, out); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if err := c.runnerStatus(ctx, out); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(out), nil
}

// linkStatus adds the link App and every link, never with a token.
func (c *Console) linkStatus(ctx context.Context, out *directoryrosterv1.GetGitHubStatusResponse) error {
	if c.deps.GitHubLinkApp == nil || c.deps.GitHubLinks == nil {
		return nil
	}
	out.LinkingAvailable = true
	out.LinkUrl = c.githubRoot() + githubLinkPath
	app, connected, err := c.deps.GitHubLinkApp.LinkApp(ctx)
	if err != nil {
		return err
	}
	if connected {
		out.LinkApp = &directoryrosterv1.GitHubLinkApp{
			AppId: app.AppID, AppSlug: app.AppSlug, Owner: app.Owner, HtmlUrl: app.HTMLURL, ConnectedBy: app.ConnectedBy,
		}
		if !app.ConnectedAt.IsZero() {
			out.LinkApp.ConnectedAt = timestamppb.New(app.ConnectedAt)
		}
	}
	links, err := c.deps.GitHubLinks.List(ctx)
	if err != nil {
		return err
	}
	for k := range links {
		l := links[k].Public()
		out.Links = append(out.Links, linkProto(&l))
	}
	return nil
}

// linkProto is a link as the page shows it. Pass it a Public link: this
// copies no token, and the caller never hands it one either.
func linkProto(l *link.Link) *directoryrosterv1.GitHubLink {
	source := l.Source
	if source == "" {
		source = link.SourceSelf
	}
	return &directoryrosterv1.GitHubLink{
		AccountId: l.ID, Login: l.Login, Emails: l.Emails, State: string(l.State), Reason: l.Reason,
		LinkedAt: timestampOf(l.LinkedAt), CheckedAt: timestampOf(l.CheckedAt), ChangedAt: timestampOf(l.ChangedAt),
		Source: string(source), Note: l.Note,
	}
}

// timestampOf is a time for the page, absent when it never happened.
func timestampOf(at time.Time) *timestamppb.Timestamp {
	if at.IsZero() {
		return nil
	}
	return timestamppb.New(at)
}

// connectionProto is a record as the page shows it: never the key, which
// is not in a record to begin with.
func connectionProto(record connection.Record) *directoryrosterv1.GitHubConnection {
	out := &directoryrosterv1.GitHubConnection{
		AppId:       record.AppID,
		AppSlug:     record.AppSlug,
		Installed:   record.Installed(),
		HtmlUrl:     record.HTMLURL,
		ConnectedBy: record.ConnectedBy,
	}
	if !record.ConnectedAt.IsZero() {
		out.ConnectedAt = timestamppb.New(record.ConnectedAt)
	}
	return out
}

// binding is one organisation's side of the policy.
type binding struct {
	members []string
	ignore  []string
	teams   map[string]policy.TeamView
}

// boundOrganisations collects the policy's GitHub table by organisation.
// An organisation binding only teams has no org-level row, so both views
// are read.
func boundOrganisations(set *policy.Set) map[string]*binding {
	out := map[string]*binding{}
	get := func(org string) *binding {
		if out[org] == nil {
			out[org] = &binding{teams: map[string]policy.TeamView{}}
		}
		return out[org]
	}
	for _, team := range set.GitHubTeams() {
		get(team.Org).teams[team.Team] = team
	}
	for _, org := range set.GitHubOrgs() {
		get(org.Org).members = org.Members
		get(org.Org).ignore = org.Ignore
	}
	return out
}

// organisationProto joins one organisation's binding, which may be nil,
// with its report, which may be empty.
func organisationProto(org string, bound *binding, document string) *directoryrosterv1.GitHubOrganisation {
	out := &directoryrosterv1.GitHubOrganisation{Org: org, Bound: bound != nil}
	if bound != nil {
		out.MemberGroups = bound.members
		out.Ignored = bound.ignore
	}

	var report status.Org
	if document != "" {
		out.Reported = true
		decoded, err := status.Decode(document)
		if err != nil {
			// The bindings still show. A report the console cannot read is
			// a fact about the report, not a reason to hide what the policy
			// says the organisation should look like.
			out.ReportError = err.Error()
		} else {
			report = decoded
		}
	}
	if out.GetReportError() == "" && out.GetReported() {
		out.Enabled = report.Enabled
		out.Tick = &directoryrosterv1.GitHubTick{
			Outcome:  string(report.Tick.Outcome),
			Error:    report.Tick.Error,
			Changes:  int32(report.Tick.Changes),  //nolint:gosec // a tick's action count never overflows
			Held:     int32(report.Tick.Held),     //nolint:gosec // nor its held count
			Waiting:  int32(report.Tick.Waiting),  //nolint:gosec // nor its waiting count
			Retrying: int32(report.Tick.Retrying), //nolint:gosec // nor its retrying count
		}
		if !report.Tick.At.IsZero() {
			out.Tick.At = timestamppb.New(report.Tick.At)
		}
		out.Members = membersProto(report.Members)
		for _, account := range report.Unlinked {
			out.Unlinked = append(out.Unlinked, &directoryrosterv1.GitHubAccount{
				Login: account.Login, Reason: account.Reason,
			})
		}
		for _, account := range report.OutsideCollaborators {
			out.OutsideCollaborators = append(out.OutsideCollaborators, &directoryrosterv1.GitHubAccount{
				Login: account.Login, Reason: account.Reason,
			})
		}
		if seats := report.Seats; seats != nil {
			out.Seats = &directoryrosterv1.GitHubSeats{
				Known: seats.Known, Total: int32(seats.Total), Filled: int32(seats.Filled), //nolint:gosec // seat counts are small
				Pending: int32(seats.Pending), Free: int32(seats.Free), Short: int32(seats.Short), //nolint:gosec // likewise
			}
		}
		if breaker := report.Breaker; breaker != nil {
			out.Breaker = &directoryrosterv1.GitHubBreaker{
				Affected: int32(breaker.Affected), Members: int32(breaker.Members), //nolint:gosec // member counts are small
				Fingerprint: breaker.Fingerprint, Confirmed: breaker.Confirmed,
			}
		}
	}

	reported := map[string][]status.Member{}
	for _, team := range report.Teams {
		reported[team.Team] = team.Members
	}
	teams := map[string]bool{}
	if bound != nil {
		for team := range bound.teams {
			teams[team] = true
		}
	}
	for team := range reported {
		teams[team] = true
	}
	for _, team := range slices.Sorted(maps.Keys(teams)) {
		row := &directoryrosterv1.GitHubTeamStatus{Team: team, Members: membersProto(reported[team])}
		if bound != nil {
			if view, ok := bound.teams[team]; ok {
				row.Bound = true
				row.MemberGroups = view.Members
				row.MaintainerGroups = view.Maintainers
			}
		}
		out.Teams = append(out.Teams, row)
	}
	return out
}

func membersProto(members []status.Member) []*directoryrosterv1.GitHubMember {
	out := make([]*directoryrosterv1.GitHubMember, 0, len(members))
	for _, member := range members {
		out = append(out, &directoryrosterv1.GitHubMember{
			Email:  member.Email,
			Login:  member.Login,
			Role:   string(member.Role),
			State:  string(member.State),
			Action: string(member.Action),
			Reason: member.Reason,
		})
	}
	return out
}
