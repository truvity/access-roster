package hub

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/backend"
)

// Snapshot is the hub's copy of one workspace at one moment: every account
// with its liveness, every group with its flat membership, and the reverse
// index from a member to the groups it belongs to.
//
// Every read is answered from a snapshot and says which one, so a consumer
// always knows how old its answer is.
type Snapshot struct {
	// Workspace is the tenant this snapshot is of.
	Workspace string
	// TakenAt is when the read that produced it completed.
	TakenAt time.Time
	// Accounts is keyed by lower-cased address.
	Accounts map[string]backend.Account
	// Groups is keyed by lower-cased group address.
	Groups map[string]backend.Group
	// MemberOf maps a lower-cased address to the groups it is in.
	MemberOf map[string][]string
	// Discovered is every group address the directory returned on this
	// pass, before narrowing — the list an operator picks from when
	// choosing which groups to sync. Names only: it is what a chooser
	// needs and nothing more, so keeping it costs a line per group rather
	// than a membership.
	Discovered []string
}

// NewSnapshot indexes a full read into a snapshot. Discovered is every
// group the directory returned before narrowing; passing nil means the
// kept groups are all there were.
func NewSnapshot(
	workspace string, takenAt time.Time,
	accounts []backend.Account, groups []backend.Group, discovered []string,
) *Snapshot {
	s := &Snapshot{
		Workspace:  workspace,
		TakenAt:    takenAt,
		Accounts:   make(map[string]backend.Account, len(accounts)),
		Groups:     make(map[string]backend.Group, len(groups)),
		MemberOf:   map[string][]string{},
		Discovered: normaliseGroups(discovered),
	}
	if len(s.Discovered) == 0 {
		names := make([]string, 0, len(groups))
		for _, g := range groups {
			names = append(names, g.Email)
		}
		s.Discovered = normaliseGroups(names)
	}
	for _, a := range accounts {
		a.Email = strings.ToLower(a.Email)
		s.Accounts[a.Email] = a
	}
	for _, g := range groups {
		g.Email = strings.ToLower(g.Email)
		g.Members = slices.Clone(g.Members)
		s.Groups[g.Email] = g
		for _, m := range g.Members {
			m = strings.ToLower(m)
			s.MemberOf[m] = append(s.MemberOf[m], g.Email)
		}
	}
	for m := range s.MemberOf {
		slices.Sort(s.MemberOf[m])
	}
	return s
}

// normaliseGroups lower-cases, trims, de-duplicates and sorts group
// addresses, so that two reads of one tenant compare equal.
func normaliseGroups(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	for _, g := range in {
		g = strings.ToLower(strings.TrimSpace(g))
		if g != "" {
			seen[g] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(seen))
}

// restrict drops from a full read everything a workspace has no business
// keeping — narrowed to a subset of its domains, of its groups, or both.
//
// Domains first. An account is kept when its address is at a served
// domain: nothing routes to the others, so holding their names and
// liveness is a liability with no reader. A group is kept when it is *at*
// a served domain — a served group must be answerable in full, and one
// dropped for having no served member today would come back as
// "found: false", which a consumer reads as gone — or when it holds at
// least one served member, because that group is part of a served
// person's answer even though it lives at another domain.
//
// Then groups. A named sync list is an operator saying which groups this
// installation's policy actually speaks about, and everything else is
// noise a directory happens to contain: a company with hundreds of
// mailing lists has no reason to have them cached, listed and offered in
// a picker. It is a subtraction from what the domains already allowed,
// never an addition.
//
// Members are never filtered. A group returned short is a partial list
// presented as a whole, which is the one thing this hub never does.
func restrict(
	accounts []backend.Account, groups []backend.Group, serve, sync []string,
) ([]backend.Account, []backend.Group) {
	if len(serve) > 0 {
		served := make(map[string]struct{}, len(serve))
		for _, d := range serve {
			served[strings.ToLower(d)] = struct{}{}
		}
		inServed := func(address string) bool {
			at := strings.LastIndex(address, "@")
			if at < 0 {
				return false
			}
			_, ok := served[strings.ToLower(address[at+1:])]
			return ok
		}

		keptAccounts := make([]backend.Account, 0, len(accounts))
		for _, a := range accounts {
			if inServed(a.Email) {
				keptAccounts = append(keptAccounts, a)
			}
		}
		keptGroups := make([]backend.Group, 0, len(groups))
		for _, g := range groups {
			keep := inServed(g.Email)
			for i := 0; !keep && i < len(g.Members); i++ {
				keep = inServed(g.Members[i])
			}
			if keep {
				keptGroups = append(keptGroups, g)
			}
		}
		accounts, groups = keptAccounts, keptGroups
	}

	if len(sync) > 0 {
		wanted := make(map[string]struct{}, len(sync))
		for _, g := range sync {
			wanted[strings.ToLower(strings.TrimSpace(g))] = struct{}{}
		}
		keptGroups := make([]backend.Group, 0, len(sync))
		for _, g := range groups {
			if _, ok := wanted[strings.ToLower(g.Email)]; ok {
				keptGroups = append(keptGroups, g)
			}
		}
		groups = keptGroups
	}
	return accounts, groups
}

// narrow returns the snapshot as it would have been read under a smaller
// served list. It touches no directory: narrowing is a subtraction, and
// what an operator has just excluded must stop being answerable now
// rather than whenever the next read completes.
//
// TakenAt is carried over unchanged. The snapshot is no fresher for
// holding less, and pretending otherwise would buy back authority that
// the directory has not been asked about.
func (s *Snapshot) narrow(serve []string) *Snapshot {
	if len(serve) == 0 {
		return s
	}
	accounts := make([]backend.Account, 0, len(s.Accounts))
	for _, key := range slices.Sorted(maps.Keys(s.Accounts)) {
		accounts = append(accounts, s.Accounts[key])
	}
	groups := make([]backend.Group, 0, len(s.Groups))
	for _, key := range slices.Sorted(maps.Keys(s.Groups)) {
		groups = append(groups, s.Groups[key])
	}
	accounts, groups = restrict(accounts, groups, serve, nil)
	return NewSnapshot(s.Workspace, s.TakenAt, accounts, groups, s.Discovered)
}

// narrowGroups drops the groups a newly narrowed sync list no longer
// covers. Like narrow, it touches no directory and carries TakenAt over.
func (s *Snapshot) narrowGroups(sync []string) *Snapshot {
	if len(sync) == 0 {
		return s
	}
	accounts := make([]backend.Account, 0, len(s.Accounts))
	for _, key := range slices.Sorted(maps.Keys(s.Accounts)) {
		accounts = append(accounts, s.Accounts[key])
	}
	groups := make([]backend.Group, 0, len(s.Groups))
	for _, key := range slices.Sorted(maps.Keys(s.Groups)) {
		groups = append(groups, s.Groups[key])
	}
	_, groups = restrict(accounts, groups, nil, sync)
	return NewSnapshot(s.Workspace, s.TakenAt, accounts, groups, s.Discovered)
}

// Age reports how old the snapshot is at now.
func (s *Snapshot) Age(now time.Time) time.Duration { return now.Sub(s.TakenAt) }

// GroupsOf returns the groups an address is in, sorted.
func (s *Snapshot) GroupsOf(email string) []string {
	return slices.Clone(s.MemberOf[strings.ToLower(email)])
}

// clone returns a deep copy, so that a patch never mutates what another
// reader is holding.
func (s *Snapshot) clone() *Snapshot {
	out := &Snapshot{
		Workspace:  s.Workspace,
		TakenAt:    s.TakenAt,
		Accounts:   maps.Clone(s.Accounts),
		Groups:     make(map[string]backend.Group, len(s.Groups)),
		MemberOf:   make(map[string][]string, len(s.MemberOf)),
		Discovered: slices.Clone(s.Discovered),
	}
	for k, g := range s.Groups {
		g.Members = slices.Clone(g.Members)
		out.Groups[k] = g
	}
	for k, v := range s.MemberOf {
		out.MemberOf[k] = slices.Clone(v)
	}
	return out
}

// patchAccount replaces one account and its group membership from a live
// read, so that a point lookup makes the snapshot a little fresher without
// a full pass. TakenAt is deliberately NOT advanced: the snapshot as a
// whole is no younger than it was.
func (s *Snapshot) patchAccount(email string, account backend.Account, found bool, groups []string) {
	email = strings.ToLower(email)
	if found {
		account.Email = email
		s.Accounts[email] = account
	} else {
		delete(s.Accounts, email)
	}
	for _, g := range s.MemberOf[email] {
		if grp, ok := s.Groups[g]; ok {
			grp.Members = slices.DeleteFunc(slices.Clone(grp.Members), func(m string) bool { return m == email })
			s.Groups[g] = grp
		}
	}
	delete(s.MemberOf, email)
	if !found {
		return
	}
	lowered := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.ToLower(g)
		lowered = append(lowered, g)
		grp, ok := s.Groups[g]
		if !ok {
			grp = backend.Group{Email: g}
		}
		if !slices.Contains(grp.Members, email) {
			grp.Members = append(slices.Clone(grp.Members), email)
			slices.Sort(grp.Members)
		}
		s.Groups[g] = grp
	}
	slices.Sort(lowered)
	if len(lowered) > 0 {
		s.MemberOf[email] = lowered
	}
}

// SnapshotStore keeps one snapshot per workspace. The prototype and a
// single replica use [MemorySnapshots]; more than one replica shares a
// Valkey, so that they answer from the same snapshot and one refresher
// reads the backend for all of them.
type SnapshotStore interface {
	// Get returns the snapshot, or nil when there is none.
	Get(ctx context.Context, workspace string) (*Snapshot, error)
	// Put replaces the snapshot.
	Put(ctx context.Context, snap *Snapshot) error
	// Delete removes it.
	Delete(ctx context.Context, workspace string) error
}

// MemorySnapshots is a SnapshotStore in process memory.
type MemorySnapshots struct {
	mu   sync.RWMutex
	byWS map[string]*Snapshot
}

var _ SnapshotStore = (*MemorySnapshots)(nil)

// NewMemorySnapshots returns an empty snapshot store.
func NewMemorySnapshots() *MemorySnapshots {
	return &MemorySnapshots{byWS: map[string]*Snapshot{}}
}

// Get implements [SnapshotStore].
func (m *MemorySnapshots) Get(_ context.Context, workspace string) (*Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snap, ok := m.byWS[workspace]
	if !ok {
		return nil, nil //nolint:nilnil // absence is not an error: there is simply no snapshot yet
	}
	return snap.clone(), nil
}

// Put implements [SnapshotStore].
func (m *MemorySnapshots) Put(_ context.Context, snap *Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byWS[snap.Workspace] = snap.clone()
	return nil
}

// Delete implements [SnapshotStore].
func (m *MemorySnapshots) Delete(_ context.Context, workspace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byWS, workspace)
	return nil
}
