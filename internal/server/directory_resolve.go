package server

import (
	"context"
	"errors"
	"slices"
	"strings"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
)

// The bounds of one resolution: how many groups one call may ask about, and
// how far and how wide nested groups are followed. Past either bound the
// answer says it is not whole, and a consumer removes nobody on it.
const (
	resolveMaxGroups = 200
	resolveMaxDepth  = 8
	resolveMaxNested = 500
)

// ResolveDirectoryGroups implements the operator contract: the members of
// each directory group asked, nested groups expanded.
func (c *Console) ResolveDirectoryGroups(
	ctx context.Context, req *connect.Request[directoryrosterv1.ResolveDirectoryGroupsRequest],
) (*connect.Response[directoryrosterv1.ResolveDirectoryGroupsResponse], error) {
	caller, err := requireAnywhere(ctx, access.RoleViewer)
	if err != nil {
		return nil, err
	}
	asked := req.Msg.GetGroups()
	users := req.Msg.GetUsers()
	if len(asked) > resolveMaxGroups || len(users) > resolveMaxGroups {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("ask about at most 200 groups and 200 users at a time"))
	}
	groups, err := c.deps.Hub.ResolveGroups(ctx, asked, resolveMaxDepth, resolveMaxNested)
	if err != nil {
		return nil, rpcError(err)
	}
	visible := caller.Workspaces(access.RoleViewer) // nil: every directory
	out := &directoryrosterv1.ResolveDirectoryGroupsResponse{
		PolicyDigest: c.deps.Authorizer.Policy().Digest(),
		Groups:       make([]*directoryrosterv1.ResolvedDirectoryGroup, 0, len(groups)),
	}
	for i := range groups {
		g := &groups[i]
		resolved := &directoryrosterv1.ResolvedDirectoryGroup{Email: strings.ToLower(strings.TrimSpace(asked[i]))}
		out.Groups = append(out.Groups, resolved)
		// A directory the caller may not view is never revealed: it reads as
		// a group that is not there.
		if !g.Found || (visible != nil && !slices.Contains(visible, g.Workspace)) {
			continue
		}
		resolved.Found, resolved.Authoritative, resolved.WorkspaceId = true, g.Authoritative, g.Workspace
		resolved.Nested, resolved.Truncated = g.Nested, g.Truncated
		for _, m := range g.Members {
			resolved.Members = append(resolved.Members, &directoryrosterv1.DirectoryGroupMember{
				Email: m.Email, GivenName: m.GivenName, FamilyName: m.FamilyName, Known: m.Known, Live: m.Live,
			})
		}
	}
	for _, address := range users {
		resolved, err := c.resolveUser(ctx, address, visible)
		if err != nil {
			return nil, err
		}
		out.Users = append(out.Users, resolved)
	}
	return connect.NewResponse(out), nil
}

// resolveUser answers for one individually listed address: the directory
// that serves its domain and whether that directory holds an active account.
// A directory the caller may not view reads as no directory, like a group.
func (c *Console) resolveUser(ctx context.Context, address string, visible []string) (*directoryrosterv1.ResolvedDirectoryUser, error) {
	email := strings.ToLower(strings.TrimSpace(address))
	out := &directoryrosterv1.ResolvedDirectoryUser{Email: email}
	got, err := c.deps.Hub.ResolveUser(ctx, email, nil)
	switch {
	case errors.Is(err, hub.ErrInvalidAddress):
		return out, nil
	case err != nil:
		return nil, rpcError(err)
	case got.Workspace == "" || (visible != nil && !slices.Contains(visible, got.Workspace)):
		return out, nil
	}
	out.WorkspaceId, out.Found, out.Live = got.Workspace, got.Found, got.Found && !got.Suspended
	return out, nil
}
