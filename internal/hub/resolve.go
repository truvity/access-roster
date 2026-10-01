package hub

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/emailaddr"
)

// ResolvedGroup is one directory group with its members resolved through
// nested groups.
type ResolvedGroup struct {
	DirectoryGroup
	// Nested are the addresses of the groups the members came through.
	Nested []string
	// Truncated is true when the expansion stopped at a bound: the members
	// are then not whole.
	Truncated bool
}

// ResolveGroups resolves each group's members the way an audit asks: a
// member that is itself a snapshotted group is a group, not a person, and
// is expanded, each group once however many reach it (so a cycle ends), to
// at most maxDepth levels and maxNested groups. Everything is read from
// memory once: one view, and each workspace's snapshot at most once.
//
// The backends keep membership flat and do not expand nested groups (see
// [backend.Group]); this is where an address that names a group stops being
// read as a person.
func (h *Hub) ResolveGroups(ctx context.Context, emails []string, maxDepth, maxNested int) ([]ResolvedGroup, error) {
	v, err := h.view(ctx)
	if err != nil {
		return nil, err
	}
	snaps := map[string]*Snapshot{}
	snapOf := func(id string) *Snapshot {
		if s, loaded := snaps[id]; loaded {
			return s
		}
		s, err := h.snapshots.Get(ctx, id)
		if err != nil {
			h.log.WarnContext(ctx, "snapshot unreadable", "workspace", id, "error", err)
			s = nil
		}
		snaps[id] = s
		return s
	}
	type found struct {
		group         backend.Group
		workspace     string
		authoritative bool
	}
	lookup := func(email string) (found, bool) {
		domain, ok := emailaddr.Domain(email)
		if !ok {
			return found{}, false
		}
		res, routed := v.routing[domain]
		if !routed {
			return found{}, false
		}
		ws := v.workspaces[res.workspace]
		snap := snapOf(ws.ID)
		if snap == nil {
			return found{}, false
		}
		g, ok := snap.Groups[email]
		return found{group: g, workspace: ws.ID, authoritative: h.authoritative(ws, res, snap)}, ok
	}
	// Who an address is, across every snapshot, read once and only if some
	// group is found.
	var accounts map[string]backend.Account
	accountOf := func(email string) (backend.Account, bool) {
		if accounts == nil {
			accounts = map[string]backend.Account{}
			for _, id := range slices.Sorted(maps.Keys(v.workspaces)) {
				if snap := snapOf(id); snap != nil {
					maps.Copy(accounts, snap.Accounts)
				}
			}
		}
		a, ok := accounts[email]
		return a, ok
	}

	out := make([]ResolvedGroup, 0, len(emails))
	for _, asked := range emails {
		email := strings.ToLower(strings.TrimSpace(asked))
		domain, _ := emailaddr.Domain(email)
		resolved := ResolvedGroup{DirectoryGroup: DirectoryGroup{GroupResult: GroupResult{Email: email, Domain: domain}}}
		root, ok := lookup(email)
		if !ok {
			out = append(out, resolved)
			continue
		}
		resolved.Found, resolved.Authoritative, resolved.Workspace = true, root.authoritative, root.workspace
		resolved.SnapshotAt = snapshotAt(snapOf(root.workspace))

		people := map[string]bool{}
		visited := map[string]bool{email: true}
		type step struct {
			group backend.Group
			depth int
		}
		queue := []step{{root.group, 0}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, m := range cur.group.Members {
				m = strings.ToLower(m)
				if nested, isGroup := lookup(m); isGroup {
					switch {
					case visited[m]:
					case cur.depth+1 > maxDepth || len(visited) > maxNested:
						resolved.Truncated = true
					default:
						visited[m] = true
						resolved.Nested = append(resolved.Nested, m)
						queue = append(queue, step{nested.group, cur.depth + 1})
					}
					continue
				}
				people[m] = true
			}
		}
		slices.Sort(resolved.Nested)
		for _, m := range slices.Sorted(maps.Keys(people)) {
			member := GroupMember{Email: m}
			if account, known := accountOf(m); known {
				member.Known, member.Live = true, account.Live
				member.GivenName, member.FamilyName = account.GivenName, account.FamilyName
			}
			resolved.Members = append(resolved.Members, member)
		}
		out = append(out, resolved)
	}
	return out, nil
}
