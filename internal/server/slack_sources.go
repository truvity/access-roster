package server

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
)

// checkSources is the console's side of the rule on a channel's sources:
// every one is a group of a connected directory the hub holds a snapshot of
// and, for an ordinary channel, of the directory that OWNS the workspace.
// A Slack Connect channel takes groups of any connected directory. The
// controller asks the same again at every pass, because a directory can be
// disconnected and an owner changed after the record is written.
func (c *Console) checkSources(ctx context.Context, sources []string, owner string, ordinary bool) error {
	if c.deps.Hub == nil {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("this deployment reads no directory, so no source can be checked"))
	}
	if ordinary && owner == "" {
		return connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the workspace has no owning directory yet: set the owner on the console before a channel there is fed by a directory group"))
	}
	for _, source := range sources {
		group, err := c.deps.Hub.DirectoryGroup(ctx, source)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("source %q is not a group address: %w", source, err))
		}
		switch {
		case !group.Found:
			return connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("source %s is not a group of a connected directory: pick it from the list", source))
		case ordinary && group.Workspace != owner:
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"source %s belongs to another directory than the one that owns this workspace (%s): "+
					"an ordinary channel is fed by its own directory's groups only; a Slack Connect channel takes any", source, owner))
		}
	}
	return nil
}

// sourceDirectories are the connected directories and their groups, as a
// picker lists them, sorted. only, when set, keeps the one directory.
func (c *Console) sourceDirectories(ctx context.Context, only ...string) []*directoryrosterv1.SlackSourceDirectory {
	if c.deps.Hub == nil {
		return nil
	}
	groups, served, err := c.deps.Hub.ListGroups(ctx, "", nil)
	if err != nil {
		return nil
	}
	byDomain := map[string]string{}
	domains := map[string][]string{}
	for _, s := range served {
		byDomain[s.Name] = s.Workspace
		if s.Authoritative {
			domains[s.Workspace] = append(domains[s.Workspace], s.Name)
		}
	}
	dirs := map[string]*directoryrosterv1.SlackSourceDirectory{}
	for _, g := range groups {
		ws := byDomain[g.Domain]
		if ws == "" || (len(only) > 0 && !slices.Contains(only, ws)) {
			continue
		}
		dir := dirs[ws]
		if dir == nil {
			dir = &directoryrosterv1.SlackSourceDirectory{WorkspaceId: ws, Domains: slices.Sorted(slices.Values(domains[ws]))}
			dirs[ws] = dir
		}
		dir.Groups = append(dir.Groups, &directoryrosterv1.SlackSourceGroup{Email: g.Email, Members: int32(len(g.Members))}) //nolint:gosec // a membership count
	}
	out := make([]*directoryrosterv1.SlackSourceDirectory, 0, len(dirs))
	for _, ws := range slices.Sorted(maps.Keys(dirs)) {
		slices.SortFunc(dirs[ws].Groups, func(a, b *directoryrosterv1.SlackSourceGroup) int { return compareStrings(a.Email, b.Email) })
		out = append(out, dirs[ws])
	}
	return out
}
