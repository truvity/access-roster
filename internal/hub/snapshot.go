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
}

// NewSnapshot indexes a full read into a snapshot.
func NewSnapshot(workspace string, takenAt time.Time, accounts []backend.Account, groups []backend.Group) *Snapshot {
	s := &Snapshot{
		Workspace: workspace,
		TakenAt:   takenAt,
		Accounts:  make(map[string]backend.Account, len(accounts)),
		Groups:    make(map[string]backend.Group, len(groups)),
		MemberOf:  map[string][]string{},
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
		Workspace: s.Workspace,
		TakenAt:   s.TakenAt,
		Accounts:  maps.Clone(s.Accounts),
		Groups:    make(map[string]backend.Group, len(s.Groups)),
		MemberOf:  make(map[string][]string, len(s.MemberOf)),
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
