package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/emailaddr"
	"github.com/truvity/access-roster/internal/hub"
)

// An OWNER is the connected directory a Slack workspace or a GitHub
// organisation belongs to. It is recorded in the connection's own record
// when the connection is made, never declared in the policy: access-roster
// already knows which directories are connected and which domains each
// serves, and a second copy in a file would only drift from the first.
//
// One rule decides who may connect something not yet connected and what
// that records, for Slack workspaces and GitHub organisations alike
// ([resolveOwner]); another decides who may change it afterwards
// ([Console.requireOwnerChange]).

// mayOwned reports whether an identity holds a role over a thing owned by
// owner: the installation-wide role always does, and the same role held over
// the owning directory. With no owner only the installation-wide role does.
func mayOwned(id access.Identity, want access.Role, owner string) bool {
	if owner != "" {
		return id.CanFor(want, owner)
	}
	return id.Can(want)
}

// connectedDirectory is one connected directory as an owner is chosen and shown.
type connectedDirectory struct {
	id      string
	primary string
	served  []string
}

// primaryDomain is the domain people know a directory by: its admin
// account's domain when the directory serves it, else the first domain it
// serves, else its id.
func primaryDomain(ws *hub.Workspace, served []string) string {
	if domain, ok := emailaddr.Domain(strings.ToLower(ws.Admin)); ok && slices.Contains(served, domain) {
		return domain
	}
	if len(served) > 0 {
		return served[0]
	}
	return ws.ID
}

// directories are every connected directory, sorted by id, with what each
// serves now.
func (c *Console) directories(ctx context.Context) ([]connectedDirectory, error) {
	if c.deps.Hub == nil {
		return nil, nil
	}
	views, err := c.deps.Hub.WorkspaceViews(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	out := make([]connectedDirectory, 0, len(views))
	for i := range views {
		served := views[i].Workspace.Served()
		slices.Sort(served)
		out = append(out, connectedDirectory{id: views[i].Workspace.ID, primary: primaryDomain(&views[i].Workspace, served), served: served})
	}
	return out, nil
}

// ownerDomains maps a directory id to the domain it is known by.
func ownerDomains(dirs []connectedDirectory) map[string]string {
	out := make(map[string]string, len(dirs))
	for i := range dirs {
		out[dirs[i].id] = dirs[i].primary
	}
	return out
}

// ownerChoices are the directories the caller may name as an owner when it
// connects something, and whether it may name none. The installation-wide
// operator may name any connected directory, or none; a scoped operator only
// the connected directories it operates.
func ownerChoices(id access.Identity, dirs []connectedDirectory) (refs []*directoryrosterv1.DirectoryRef, mayNone bool) {
	scope := id.Workspaces(access.RoleOperator)
	mayNone = id.Can(access.RoleOperator)
	for i := range dirs {
		if !mayNone && !slices.Contains(scope, dirs[i].id) {
			continue
		}
		refs = append(refs, &directoryrosterv1.DirectoryRef{WorkspaceId: dirs[i].id, PrimaryDomain: dirs[i].primary})
	}
	return refs, mayNone
}

// resolveOwner is THE connect-time rule: who the owner of a thing about to
// be connected is, given who is connecting it and what they asked for.
//
//   - The installation-wide operator chooses: any connected directory, or
//     none (an empty request).
//   - An operator scoped to exactly one connected directory is that
//     directory's operator for this: the owner is it, whether they name it
//     or leave the choice empty.
//   - An operator scoped to several chooses among them, and must.
//   - Anything else is refused: a directory the caller does not operate, or
//     one that is not connected, is never recorded.
func resolveOwner(id access.Identity, requested string, dirs []connectedDirectory) (string, error) {
	connected := make([]string, 0, len(dirs))
	for i := range dirs {
		connected = append(connected, dirs[i].id)
	}
	requested = strings.TrimSpace(requested)
	if id.Can(access.RoleOperator) {
		if requested != "" && !slices.Contains(connected, requested) {
			return "", connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("%q is not a connected directory, so it cannot own anything", requested))
		}
		return requested, nil
	}
	mine := slices.DeleteFunc(slices.Clone(id.Workspaces(access.RoleOperator)), func(w string) bool { return !slices.Contains(connected, w) })
	switch {
	case requested != "":
		if !slices.Contains(mine, requested) {
			return "", connect.NewError(connect.CodePermissionDenied,
				fmt.Errorf("this needs the operator role over %s's directory, which names it as the owner", requested))
		}
		return requested, nil
	case len(mine) == 1:
		return mine[0], nil
	case len(mine) == 0:
		return "", connect.NewError(connect.CodePermissionDenied,
			errors.New("this needs the installation-wide operator role, or the operator role over a connected directory that would own it"))
	default:
		return "", connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("you operate more than one directory: choose which of them owns it (%s)", strings.Join(mine, ", ")))
	}
}

// requireOwnerChange is the gate on changing a recorded owner: the
// installation-wide operator alone, and only to a connected directory or to
// none.
func (c *Console) requireOwnerChange(ctx context.Context, owner string) (access.Identity, error) {
	id, err := requireRole(ctx, access.RoleOperator)
	if connect.CodeOf(err) == connect.CodePermissionDenied {
		return id, connect.NewError(connect.CodePermissionDenied,
			errors.New("only the installation-wide operator changes an owner"))
	}
	if err != nil {
		return id, err
	}
	if owner == "" {
		return id, nil
	}
	dirs, err := c.directories(ctx)
	if err != nil {
		return id, err
	}
	for i := range dirs {
		if dirs[i].id == owner {
			return id, nil
		}
	}
	return id, connect.NewError(connect.CodeInvalidArgument,
		fmt.Errorf("%q is not a connected directory, so it cannot own anything", owner))
}

// ListServedDomains implements the controllers' read: for each connected
// directory the caller may view, the domains the hub serves for it now.
func (c *Console) ListServedDomains(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListServedDomainsRequest],
) (*connect.Response[directoryrosterv1.ListServedDomainsResponse], error) {
	id, err := requireAnywhere(ctx, access.RoleViewer)
	if err != nil {
		return nil, err
	}
	dirs, err := c.directories(ctx)
	if err != nil {
		return nil, err
	}
	// A nil list is every directory: an installation-wide role is not a list
	// of tenants and must not be turned into one.
	visible := id.Workspaces(access.RoleViewer)
	out := &directoryrosterv1.ListServedDomainsResponse{}
	for i := range dirs {
		if visible != nil && !slices.Contains(visible, dirs[i].id) {
			continue
		}
		out.Directories = append(out.Directories, &directoryrosterv1.DirectoryDomains{
			WorkspaceId: dirs[i].id, PrimaryDomain: dirs[i].primary, Domains: slices.Clone(dirs[i].served),
		})
	}
	return connect.NewResponse(out), nil
}
