package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

// resolveBatch is how many directory groups one question asks about, which
// is the console's own ceiling.
const resolveBatch = 200

// dirGroup is what the console said of one directory group.
type dirGroup struct {
	found, authoritative, truncated bool
	// owner is the directory workspace id the group belongs to.
	owner  string
	nested []string
}

// directoryGroups is the console's answer about every directory group a
// pass needs: who is in each, and where each comes from.
type directoryGroups struct {
	groups  map[string]dirGroup
	holders reconcile.Holders
	// users are the individual addresses asked about, and what the console
	// said of each.
	users map[string]dirUser
}

// dirUser is what the console said of one individually listed address.
type dirUser struct {
	// owner is the directory workspace that serves the address's domain;
	// empty when no connected directory does.
	owner string
	// live is true when that directory holds the account and it is active.
	live bool
}

// holdersOf are the users as holders, which a reconcile reads them as.
func (d directoryGroups) holdersOf() map[string]reconcile.Holder {
	out := make(map[string]reconcile.Holder, len(d.users))
	for email, u := range d.users {
		out[email] = reconcile.Holder{Email: email, Live: u.live}
	}
	return out
}

// resolveDirectory asks the console about each group, in batches. Any
// error, or an answer under another policy ([rails.ErrPolicyDiffers]),
// fails the whole question, like the holders of an internal group: what is
// added rests on a complete read of the groups asked, and nothing else.
func (c *Controller) resolveDirectory(ctx context.Context, groups, users []string) (directoryGroups, error) {
	out := directoryGroups{groups: map[string]dirGroup{}, holders: reconcile.Holders{}, users: map[string]dirUser{}}
	users = slices.Compact(slices.Sorted(slices.Values(users)))
	groups = slices.Compact(slices.Sorted(slices.Values(groups)))
	for len(groups) > 0 {
		n := min(len(groups), resolveBatch)
		batch := groups[:n]
		groups = groups[n:]
		response, err := c.deps.Access.ResolveDirectoryGroups(ctx, connect.NewRequest(&directoryrosterv1.ResolveDirectoryGroupsRequest{Groups: batch}))
		if err != nil {
			return directoryGroups{}, fmt.Errorf("ask who is in the directory groups: %w", err)
		}
		if err = c.directory().Guard.Check(response.Msg.GetPolicyDigest()); err != nil {
			return directoryGroups{}, fmt.Errorf("ask who is in the directory groups: %w", err)
		}
		for _, g := range response.Msg.GetGroups() {
			email := strings.ToLower(g.GetEmail())
			out.groups[email] = dirGroup{
				found: g.GetFound(), authoritative: g.GetAuthoritative(), truncated: g.GetTruncated(),
				owner: g.GetWorkspaceId(), nested: g.GetNested(),
			}
			for _, m := range g.GetMembers() {
				// A member the hub has never seen is neither live nor gone,
				// and is not invited.
				out.holders[email] = append(out.holders[email], rails.Holder{Email: m.GetEmail(), Live: m.GetKnown() && m.GetLive()})
			}
		}
	}
	for len(users) > 0 {
		n := min(len(users), resolveBatch)
		batch := users[:n]
		users = users[n:]
		response, err := c.deps.Access.ResolveDirectoryGroups(ctx, connect.NewRequest(&directoryrosterv1.ResolveDirectoryGroupsRequest{Users: batch}))
		if err != nil {
			return directoryGroups{}, fmt.Errorf("ask about the individually listed users: %w", err)
		}
		if err = c.directory().Guard.Check(response.Msg.GetPolicyDigest()); err != nil {
			return directoryGroups{}, fmt.Errorf("ask about the individually listed users: %w", err)
		}
		for _, u := range response.Msg.GetUsers() {
			out.users[strings.ToLower(u.GetEmail())] = dirUser{owner: u.GetWorkspaceId(), live: u.GetFound() && u.GetLive()}
		}
	}
	return out, nil
}

// checkSources is why a record's sources cannot be acted on, empty when they
// can: every one is a group of a directory the console knows, resolved
// whole, and, when owner is set (an ordinary channel), of that directory.
// The console checks the same when the record is written; the controller
// asks again because a directory can be disconnected, a group deleted and
// an owner changed since.
func (d directoryGroups) checkSources(sources, members []string, owner string, ordinary bool) string {
	for _, m := range members {
		u, ok := d.users[m]
		switch {
		case !ok || u.owner == "":
			return "member " + m + " is not a user of a connected directory"
		case ordinary && owner == "":
			return reconcile.NoOwner
		case ordinary && u.owner != owner:
			return "member " + m + " belongs to another directory than the one that owns this workspace"
		}
	}
	for _, s := range sources {
		g, ok := d.groups[s]
		switch {
		case !ok || !g.found:
			return "source " + s + " is not a group of a connected directory"
		case g.truncated:
			return "source " + s + " nests too deeply to resolve whole, so nobody is added or removed on it"
		case ordinary && owner == "":
			return reconcile.NoOwner
		case ordinary && g.owner != owner:
			return "source " + s + " belongs to another directory than the one that owns this workspace"
		}
	}
	return ""
}

// nestedOf are the nested groups each source's members come through, for
// the sources named.
func (d directoryGroups) nestedOf(sources []string) map[string][]string {
	out := map[string][]string{}
	for _, s := range sources {
		if g, ok := d.groups[s]; ok && len(g.nested) > 0 {
			out[s] = g.nested
		}
	}
	return out
}
