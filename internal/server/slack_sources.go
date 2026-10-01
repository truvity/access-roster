package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

// checkSources is the console's side of the rule on a channel's sources and
// individual members: every source is a group of a connected directory the
// hub holds a snapshot of and, for an ordinary channel, of the directory that
// OWNS the workspace; every member is an active user of such a directory. A
// Slack Connect channel takes groups and users of any connected directory.
// The controller asks the same again at every pass, because a directory can
// be disconnected and an owner changed after the record is written.
func (c *Console) checkSources(ctx context.Context, sources, members []string, owner string, ordinary bool) error {
	if c.deps.Hub == nil {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("this deployment reads no directory, so no source can be checked"))
	}
	if ordinary && owner == "" {
		return connect.NewError(connect.CodeFailedPrecondition,
			errors.New(reconcile.NoOwner))
	}
	for _, source := range sources {
		group, err := c.deps.Hub.DirectoryGroup(ctx, source)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("source %q is not a group address: %w", source, err))
		}
		switch {
		case !group.Found && c.isDirectoryUser(ctx, source):
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"%s is a person's address, not a group: enter it under Individual addresses", source))
		case !group.Found:
			return connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("source %s is not a group of a connected directory: pick it from the list", source))
		case ordinary && group.Workspace != owner:
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"source %s belongs to another directory than the one that owns this workspace (%s): "+
					"an ordinary channel is fed by its own directory's groups only; a Slack Connect channel takes any", source, owner))
		}
	}
	return c.checkMembers(ctx, members, owner, ordinary)
}

// isDirectoryUser reports whether an address is an account the hub holds.
func (c *Console) isDirectoryUser(ctx context.Context, address string) bool {
	got, err := c.deps.Hub.ResolveUser(ctx, address, nil)
	return err == nil && got.Workspace != "" && got.Found
}

// checkMembers is the rule on individual addresses: each is an active user
// of the directory that owns the workspace (an ordinary channel) or of any
// connected directory (a Slack Connect channel), and none is a group.
func (c *Console) checkMembers(ctx context.Context, members []string, owner string, ordinary bool) error {
	const where = "individual addresses come from the directories this channel draws from"
	for _, member := range members {
		group, err := c.deps.Hub.DirectoryGroup(ctx, member)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("member %q is not an email address: %w", member, err))
		}
		if group.Found {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"%s is a group, not a person: enter it under Directory groups", member))
		}
		user, err := c.deps.Hub.ResolveUser(ctx, member, nil)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("member %q is not an email address: %w", member, err))
		}
		dir := "a connected directory"
		if ordinary {
			dir = "the directory that owns this workspace (" + owner + ")"
		}
		switch {
		case user.Workspace == "" || (ordinary && user.Workspace != owner):
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%s is not a user of %s — %s", member, dir, where))
		case !user.Found:
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"%s is not a user of %s: the directory does not know that address — %s", member, dir, where))
		case user.Suspended:
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"%s is suspended in %s: only an active user can be listed", member, dir))
		}
	}
	return nil
}

// sourceDirectories are the connected directories and their groups, as a
// picker lists them, sorted. only, when set, keeps the one directory. When the
// groups cannot be read the second result says so, so that the picker shows
// the failure rather than an empty list that reads as "no group exists".
func (c *Console) sourceDirectories(ctx context.Context, only ...string) ([]*directoryrosterv1.SlackSourceDirectory, string) {
	if c.deps.Hub == nil {
		return nil, ""
	}
	groups, served, err := c.deps.Hub.ListGroups(ctx, "", nil)
	if err != nil {
		return nil, "the directories' groups could not be read just now: reload to try again"
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
	return out, ""
}
