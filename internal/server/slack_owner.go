package server

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// slackBook is every connected Slack workspace's record by key. What the
// policy leaves out of a workspace — which team it is, which directory owns
// it — is read here, from what connecting it recorded.
type slackBook map[string]connection.Record

// slackBook reads the records. A deployment that keeps none has an empty
// book: nothing is connected, so nothing has an owner.
func (c *Console) slackBook(ctx context.Context) (slackBook, error) {
	book := slackBook{}
	if c.deps.SlackWorkspaces == nil {
		return book, nil
	}
	records, err := c.deps.SlackWorkspaces.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	for i := range records {
		book[records[i].Workspace] = records[i]
	}
	return book, nil
}

// owner is the directory workspace recorded as a workspace's owner, "" when
// it has none or is not connected.
func (b slackBook) owner(workspace string) string { return b[workspace].Owner }

// team is the Slack team id recorded at the workspace's first install, ""
// before it.
func (b slackBook) team(workspace string) string { return b[workspace].TeamID }

// may reports whether an identity holds a role over one Slack workspace:
// by the recorded owner once it is connected. A workspace nobody has
// connected has no owner to be a viewer or an operator of; the one thing to
// do with it is connect it, so whoever could ([resolveOwner]) is let in.
func (b slackBook) may(id access.Identity, want access.Role, workspace string) bool {
	if record, connected := b[workspace]; connected {
		return mayOwned(id, want, record.Owner)
	}
	return id.Can(want) || id.CanAnywhere(access.RoleOperator)
}

// mayAct is whether the caller passes [Console.requireSlack] for the
// workspace: the operator of its recorded owner, or installation-wide, which
// is all anyone but the installation-wide operator can be of a workspace
// that has no owner.
func (b slackBook) mayAct(id access.Identity, workspace string) bool {
	return mayOwned(id, access.RoleOperator, b.owner(workspace))
}

// requireSlack is [requireOwner] for one Slack workspace: the operator of
// its recorded owning directory, or the installation-wide role.
func (c *Console) requireSlack(ctx context.Context, want access.Role, workspace string) (access.Identity, error) {
	book, err := c.slackBook(ctx)
	if err != nil {
		return access.Identity{}, err
	}
	return requireOwner(ctx, want, book.owner(workspace), workspace)
}

// requireAnySlack is the gate on a page that lists Slack workspaces and
// then shows only the ones the caller may see: the installation-wide role,
// or the role over the directory that owns at least one Slack workspace, or
// the operator role over any directory when a declared workspace is still
// to be connected (the caller may be the one to connect it). A scoped role
// over a directory that owns none has nothing here to see, and is refused
// rather than shown an empty page that looks like an answer.
func (c *Console) requireAnySlack(ctx context.Context, want access.Role) (access.Identity, slackBook, error) {
	id, err := requireAnywhere(ctx, want)
	if err != nil {
		return id, nil, err
	}
	book, err := c.slackBook(ctx)
	if err != nil {
		return id, nil, err
	}
	if id.Can(want) {
		return id, book, nil
	}
	for _, workspace := range c.slackKeys(book) {
		if book.may(id, want, workspace) {
			return id, book, nil
		}
	}
	return access.Identity{}, nil, connect.NewError(connect.CodePermissionDenied,
		fmt.Errorf("this needs the %s role, installation-wide or over a directory that owns a Slack workspace", want))
}

// slackKeys are every workspace the policy declares or a record exists for.
func (c *Console) slackKeys(book slackBook) []string {
	seen := map[string]bool{}
	for _, key := range c.deps.Authorizer.Policy().SlackWorkspaceKeys() {
		seen[key] = true
	}
	for key := range book {
		seen[key] = true
	}
	return slices.Sorted(maps.Keys(seen))
}

// slackWorkspaceOfBind is the Slack workspace a signed state binds, so the
// callback can ask the role question again, now: the workspace itself for a
// workspace connect, the catalogue entry's for a catalogue App.
func (c *Console) slackWorkspaceOfBind(bind string) string {
	if workspace, ok := strings.CutPrefix(bind, slackWorkspaceBind); ok {
		return workspace
	}
	id, ok := strings.CutPrefix(bind, slackCatalogueBind)
	if !ok || c.deps.SlackCatalogue == nil {
		return ""
	}
	entry, _ := c.deps.SlackCatalogue.Get(id)
	return entry.Workspace
}
