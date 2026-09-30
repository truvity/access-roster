package server

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/internal/access"
)

// slackOwner is the directory workspace that owns a Slack workspace, from
// the policy in force ("" when it names none).
func (c *Console) slackOwner(workspace string) string {
	return c.deps.Authorizer.Policy().SlackOwner(workspace)
}

// requireSlack is [requireOwner] for one Slack workspace: the operator of
// its owning directory, or the installation-wide role.
func (c *Console) requireSlack(ctx context.Context, want access.Role, workspace string) (access.Identity, error) {
	return requireOwner(ctx, want, c.slackOwner(workspace), workspace)
}

// maySlack reports whether an identity holds a role over one Slack
// workspace, by the same rule as [Console.requireSlack].
func (c *Console) maySlack(id access.Identity, want access.Role, workspace string) bool {
	if owner := c.slackOwner(workspace); owner != "" {
		return id.CanFor(want, owner)
	}
	return id.Can(want)
}

// requireAnySlack is the gate on a page that lists Slack Apps and then
// shows only the ones the caller may see: the installation-wide role, or
// the role over the directory that owns at least one Slack workspace. A
// scoped role over a directory that owns none has nothing here to see, and
// is refused rather than shown an empty page that looks like an answer.
func (c *Console) requireAnySlack(ctx context.Context, want access.Role) (access.Identity, error) {
	id, err := requireAnywhere(ctx, want)
	if err != nil {
		return id, err
	}
	if id.Can(want) {
		return id, nil
	}
	for _, workspace := range c.deps.Authorizer.Policy().SlackWorkspaceKeys() {
		if c.maySlack(id, want, workspace) {
			return id, nil
		}
	}
	return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
		fmt.Errorf("this needs the %s role, installation-wide or over a directory that owns a Slack workspace", want))
}

// slackWorkspaceOfBind is the Slack workspace a signed catalogue state
// binds, so the callback can ask the role question again, now.
func (c *Console) slackWorkspaceOfBind(bind string) string {
	id, ok := strings.CutPrefix(bind, slackCatalogueBind)
	if !ok || c.deps.SlackCatalogue == nil {
		return ""
	}
	entry, _ := c.deps.SlackCatalogue.Get(id)
	return entry.Workspace
}
