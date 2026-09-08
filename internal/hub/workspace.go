// Package hub is the directory hub: the workspaces it holds credentials
// for, the snapshots it keeps of them, the routing from an email address to
// the workspace that serves it, and the freshness policy that decides
// whether a read is answered from a snapshot or from the backend.
//
// One rule runs through all of it: a consumer removes access only on an
// authoritative answer. A failed probe, a stale snapshot, a domain claimed
// twice or an unreachable cache all read as "not authoritative", never as
// "gone".
package hub

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned for a workspace id no store knows.
var ErrNotFound = errors.New("hub: workspace not found")

// CredentialType is how the hub authenticates to a workspace.
type CredentialType string

// The credential kinds.
const (
	// CredentialOAuth is a refresh token minted by admin consent; it acts
	// as the consenting account.
	CredentialOAuth CredentialType = "oauth"
	// CredentialServiceAccountKey is a key with domain-wide delegation,
	// impersonating the workspace's admin.
	CredentialServiceAccountKey CredentialType = "service-account-key"
)

// Health is the outcome of the last probe of a workspace.
type Health struct {
	// ProbedAt is when the probe ran; zero before the first one.
	ProbedAt time.Time
	// OK reports whether the credential worked.
	OK bool
	// Error carries the failure reason when OK is false.
	Error string
}

// Workspace is one directory tenant the hub holds a credential for.
//
// Domains are discovered from the backend and re-read on every probe; they
// are never configured, so a domain moving between tenants is followed
// without an edit.
type Workspace struct {
	// ID is the backend's tenant identifier.
	ID string
	// Backend names the implementation reading it: "google", "fake".
	Backend string
	// Domains are the discovered domains, lower-cased and sorted.
	Domains []string
	// Serve narrows which of those domains the hub actually answers for.
	// Empty means all of them, which is the ordinary case; a subset is
	// how an installation takes one domain out of a tenant that holds
	// several it has no business reading. See [Workspace.Served].
	Serve []string
	// SyncGroups narrows which of the workspace's groups the hub keeps.
	// Empty means all of them, which is the ordinary case; a subset is
	// how an installation reads a directory with hundreds of groups and
	// keeps the handful its policy actually names. See
	// [Workspace.SyncesGroup].
	//
	// It narrows what is KEPT, not what is read: the hub still lists the
	// directory's groups, because that list is what an operator picks
	// from. The saving is in what is stored, cached and shown -- not in
	// the directory's API quota.
	SyncGroups []string
	// Admin is the account the credential acts as.
	Admin string
	// Credential is how the hub authenticates.
	Credential CredentialType
	// ConnectedBy is the console identity that connected it; empty for a
	// workspace the deployment declared.
	ConnectedBy string
	// ConnectedAt is when it was connected or declared.
	ConnectedAt time.Time
	// Health is the last probe's outcome.
	Health Health
	// Declared marks a workspace the deployment owns: read-only in the
	// console, and the winner when two workspaces claim one domain.
	Declared bool
}

// Served returns the domains the hub routes to this workspace: the
// discovered domains, narrowed by Serve when it is set.
//
// The intersection, rather than Serve as written, is what makes a domain
// moving between tenants safe. The old tenant stops serving it the moment
// the directory stops listing it — no edit, no window in which two
// workspaces both claim it — and the stale Serve entry is surfaced to an
// operator by [Workspace.Unowned] as something to tidy, not as an outage.
func (w Workspace) Served() []string {
	if len(w.Serve) == 0 {
		return slices.Clone(w.Domains)
	}
	out := make([]string, 0, len(w.Serve))
	for _, d := range w.Domains {
		if slices.Contains(w.Serve, d) {
			out = append(out, d)
		}
	}
	return out
}

// SyncesGroup reports whether a group address is kept. Empty SyncGroups
// keeps everything, exactly as an empty Serve serves every domain.
func (w Workspace) SyncesGroup(address string) bool {
	if len(w.SyncGroups) == 0 {
		return true
	}
	address = strings.ToLower(address)
	for _, g := range w.SyncGroups {
		if strings.ToLower(g) == address {
			return true
		}
	}
	return false
}

// Unowned returns the entries of Serve the tenant does not (or no longer)
// own. They route nothing; they are shown so that an operator can see why
// a domain they asked for is not being served.
func (w Workspace) Unowned() []string {
	var out []string
	for _, d := range w.Serve {
		if !slices.Contains(w.Domains, d) {
			out = append(out, d)
		}
	}
	return out
}

// clone returns a copy that shares no slice with the original.
func (w Workspace) clone() Workspace {
	w.Domains = slices.Clone(w.Domains)
	w.Serve = slices.Clone(w.Serve)
	return w
}

// Store keeps the workspace records. Credentials live beside them, in the
// implementation's own storage; this interface carries only the record.
type Store interface {
	// List returns every workspace, sorted by id.
	List(ctx context.Context) ([]Workspace, error)
	// Get returns one workspace, or ErrNotFound.
	Get(ctx context.Context, id string) (Workspace, error)
	// Put creates or replaces a workspace.
	Put(ctx context.Context, ws Workspace) error
	// Delete removes a workspace. Deleting an unknown id is not an error.
	Delete(ctx context.Context, id string) error
}

// MemoryStore is a Store in process memory: the prototype's store, and the
// fake behind every test of the ones that persist.
type MemoryStore struct {
	mu   sync.RWMutex
	byID map[string]Workspace
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byID: map[string]Workspace{}}
}

// List implements [Store].
func (s *MemoryStore) List(_ context.Context) ([]Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Workspace, 0, len(s.byID))
	for _, id := range slices.Sorted(maps.Keys(s.byID)) {
		out = append(out, s.byID[id].clone())
	}
	return out, nil
}

// Get implements [Store].
func (s *MemoryStore) Get(_ context.Context, id string) (Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ws, ok := s.byID[id]
	if !ok {
		return Workspace{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return ws.clone(), nil
}

// Put implements [Store].
func (s *MemoryStore) Put(_ context.Context, ws Workspace) error {
	if ws.ID == "" {
		return errors.New("hub: workspace id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[ws.ID] = ws.clone()
	return nil
}

// Delete implements [Store].
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
	return nil
}

// normaliseDomains lower-cases, trims, de-duplicates and sorts a domain
// list, so that two reads of the same tenant compare equal.
func normaliseDomains(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			seen[d] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(seen))
}
