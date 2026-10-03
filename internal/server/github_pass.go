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
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/logsafe"
)

// RequestGitHubPass asks the GitHub controller to pass over now. The request
// is a marker the controller notices within its poll (see the controller's
// watch); a second one under a minute after the first is refused, so the
// button cannot be leaned on. It is recorded as a configuration change.
func (c *Console) RequestGitHubPass(
	ctx context.Context, req *connect.Request[directoryrosterv1.RequestGitHubPassRequest],
) (*connect.Response[directoryrosterv1.RequestGitHubPassResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	org := strings.TrimSpace(req.Msg.GetOrg())
	if !status.ValidOrg(org) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not an organisation login", org))
	}
	if c.deps.GitHubOrgs == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this deployment keeps no state in Kubernetes, so there is no controller to ask"))
	}
	who, err := c.requireOrg(ctx, access.RoleOperator, org)
	if err != nil {
		return nil, err
	}
	records, err := c.deps.GitHubOrgs.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if record, connected := recordOf(records, org); !connected || !record.Installed() {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("GitHub organisation %s is not installed: there is nothing for a pass to act with", org))
	}
	now := time.Now().UTC()
	kept, last, err := c.deps.GitHubOrgs.RequestPass(ctx, connection.PassRequest{Org: org, At: now, By: who.Who()})
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !kept {
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Errorf(
			"a pass over %s was asked for %s ago: the controller notices a request within a minute, so wait for it",
			org, now.Sub(last).Round(time.Second)))
	}
	c.record(ctx, audit.GitHubPassRequested(identityActor(who), org))
	c.notify(ctx, org)
	c.log().InfoContext(ctx, "a GitHub pass was requested", "org", logsafe.Value(org), "by", logsafe.Value(who.Who()))
	return connect.NewResponse(&directoryrosterv1.RequestGitHubPassResponse{RequestedAt: timestampOf(now)}), nil
}
