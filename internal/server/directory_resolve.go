package server

import (
	"context"
	"errors"
	"slices"
	"strings"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
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
	if len(asked) > resolveMaxGroups {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("ask about at most 200 groups at a time"))
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
	return connect.NewResponse(out), nil
}
