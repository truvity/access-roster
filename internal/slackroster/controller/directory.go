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
}

// resolveDirectory asks the console about each group, in batches. Any
// error, or an answer under another policy ([rails.ErrPolicyDiffers]),
// fails the whole question, like the holders of an internal group: what is
// added rests on a complete read of the groups asked, and nothing else.
func (c *Controller) resolveDirectory(ctx context.Context, groups []string) (directoryGroups, error) {
	out := directoryGroups{groups: map[string]dirGroup{}, holders: reconcile.Holders{}}
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
	return out, nil
}

// checkSources is why a record's sources cannot be acted on, empty when they
// can: every one is a group of a directory the console knows, resolved
// whole, and, when owner is set (an ordinary channel), of that directory.
// The console checks the same when the record is written; the controller
// asks again because a directory can be disconnected, a group deleted and
// an owner changed since.
func (d directoryGroups) checkSources(sources []string, owner string, ordinary bool) string {
	for _, s := range sources {
		g, ok := d.groups[s]
		switch {
		case !ok || !g.found:
			return "source " + s + " is not a group of a connected directory"
		case g.truncated:
			return "source " + s + " nests too deeply to resolve whole, so nobody is added or removed on it"
		case ordinary && owner == "":
			return "the workspace has no owning directory yet: set the owner on the console"
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
