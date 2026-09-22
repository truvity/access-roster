package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/status"
)

// GitHubConfirmations is where operators' confirmations of removal sets
// are kept.
type GitHubConfirmations interface {
	PutConfirmation(ctx context.Context, confirmation connection.Confirmation) error
	Confirmations(ctx context.Context) (map[string]connection.Confirmation, error)
}

// importLimit bounds one import. The records this exists for number in the
// tens.
const importLimit = 500

// ConfirmGitHubRemovals lets exactly the removal set the operator saw go
// ahead. The fingerprint must be the one the organisation's latest report
// shows: confirming a set that has since changed would confirm people
// nobody looked at.
func (c *Console) ConfirmGitHubRemovals(
	ctx context.Context, req *connect.Request[directoryrosterv1.ConfirmGitHubRemovalsRequest],
) (*connect.Response[directoryrosterv1.ConfirmGitHubRemovalsResponse], error) {
	id, err := requireRole(ctx, access.RoleOperator)
	if err != nil {
		return nil, err
	}
	org, fingerprint := strings.TrimSpace(req.Msg.GetOrg()), strings.TrimSpace(req.Msg.GetFingerprint())
	switch {
	case !status.ValidOrg(org) || fingerprint == "":
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("an organisation and a fingerprint are required"))
	case c.deps.GitHub == nil || c.deps.GitHubConfirmations == nil:
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this deployment keeps no reports or confirmations"))
	}
	reports, err := c.deps.GitHub.Reports(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	report, err := status.Decode(reports[status.Key(org)])
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("%s has no readable report: %w", org, err))
	}
	if report.Breaker == nil || report.Breaker.Fingerprint != fingerprint {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the removals in %s have changed since that page was loaded: reload and look again", org))
	}
	if err = c.deps.GitHubConfirmations.PutConfirmation(ctx, connection.Confirmation{
		Org: org, Fingerprint: fingerprint, By: id.Who(), At: time.Now().UTC(),
	}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	c.record(ctx, audit.GitHubRemovalsConfirmed(identityActor(id), org, fingerprint,
		report.Breaker.Affected, report.Breaker.Members))
	return connect.NewResponse(&directoryrosterv1.ConfirmGitHubRemovalsResponse{}), nil
}

// ImportGitHubLinks adopts approved pairings as links, after three checks
// each: somebody approved the pairing, an address is a live account the
// directory vouches for, and the account is a member of a connected
// organisation. A link the person made is never displaced.
func (c *Console) ImportGitHubLinks(
	ctx context.Context, req *connect.Request[directoryrosterv1.ImportGitHubLinksRequest],
) (*connect.Response[directoryrosterv1.ImportGitHubLinksResponse], error) {
	id, err := requireRole(ctx, access.RoleOperator)
	if err != nil {
		return nil, err
	}
	records := req.Msg.GetRecords()
	origin := strings.TrimSpace(req.Msg.GetOrigin())
	switch {
	case len(records) == 0 || len(records) > importLimit:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("between 1 and %d records, please", importLimit))
	case origin == "":
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("say where the records come from"))
	case c.deps.GitHubOrgs == nil || c.deps.GitHubLinks == nil:
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this deployment keeps no links"))
	}
	members, err := c.memberCheck(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}

	out := &directoryrosterv1.ImportGitHubLinksResponse{}
	skip := func(login, reason string) {
		out.Skipped = append(out.Skipped, &directoryrosterv1.GitHubAccount{Login: login, Reason: reason})
	}
	now := time.Now().UTC()
	var candidates []link.Link
	logins := map[int64]string{}
	for _, record := range records {
		login := strings.TrimSpace(record.GetLogin())
		switch {
		case login == "":
			skip("", "a record with no login")
			continue
		case strings.TrimSpace(record.GetApprovedBy()) == "":
			skip(login, "nobody approved the pairing")
			continue
		}
		accepted, refused := c.linkableAddresses(ctx, record.GetEmails())
		if len(accepted) == 0 {
			skip(login, "no address is a live account the directory vouches for"+reasons(refused))
			continue
		}
		account, token, member, err := members(ctx, login)
		switch {
		case err != nil:
			skip(login, "GitHub could not be asked: "+err.Error())
			continue
		case !member:
			skip(login, "not a member of any connected organisation")
			continue
		}
		accountID, err := githubapp.UserID(ctx, c.githubHTTP(), token, account)
		if err != nil {
			skip(login, err.Error())
			continue
		}
		note := origin + ": approved by " + record.GetApprovedBy()
		if at := record.GetApprovedAt(); at != nil {
			note += " on " + at.AsTime().UTC().Format("2006-01-02")
		}
		logins[accountID] = login
		candidates = append(candidates, link.Link{
			ID: accountID, Login: account, Emails: accepted, State: link.StateLinked,
			Source: link.SourceImported, Note: note, LinkedAt: now, CheckedAt: now, ChangedAt: now,
		})
	}
	if len(candidates) == 0 {
		return connect.NewResponse(out), nil
	}
	adopted, skipped, err := c.deps.GitHubLinks.Adopt(ctx, candidates)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	for accountID, reason := range skipped {
		skip(logins[accountID], reason)
	}
	for i := range adopted {
		l := adopted[i].Public()
		out.Imported = append(out.Imported, linkProto(&l))
		c.record(ctx, audit.GitHubLinkImported(identityActor(id), l.Emails[0], l.Login, l.Note))
	}
	return connect.NewResponse(out), nil
}

// memberCheck returns a function answering whether a login is a member of
// any connected organisation, with the canonical login and a token to
// read the account with. Installation tokens are minted once per call.
func (c *Console) memberCheck(ctx context.Context) (func(context.Context, string) (string, string, bool, error), error) {
	records, err := c.deps.GitHubOrgs.List(ctx)
	if err != nil {
		return nil, err
	}
	type installed struct {
		org   githubapp.Org
		token string
	}
	var orgs []installed
	for _, record := range records {
		if !record.Installed() {
			continue
		}
		credential, found, err := c.deps.GitHubOrgs.Credential(ctx, record.Org)
		if err != nil || !found {
			continue
		}
		appToken, err := githubapp.AppToken(credential.AppID, credential.PrivateKey, time.Now())
		if err != nil {
			continue
		}
		token, _, err := githubapp.InstallationToken(ctx, c.githubHTTP(), appToken, credential.InstallationID)
		if err != nil {
			continue
		}
		orgs = append(orgs, installed{org: githubapp.Org{HTTP: c.githubHTTP(), Login: record.Org}, token: token})
	}
	if len(orgs) == 0 {
		return nil, errors.New("no connected organisation can be asked who its members are")
	}
	return func(ctx context.Context, login string) (string, string, bool, error) {
		for _, o := range orgs {
			member, err := o.org.IsMember(ctx, o.token, login)
			if err != nil {
				return "", "", false, err
			}
			if member {
				return login, o.token, true, nil
			}
		}
		return "", "", false, nil
	}, nil
}

func reasons(refused []string) string {
	if len(refused) == 0 {
		return ""
	}
	return " (" + strings.Join(refused, "; ") + ")"
}
