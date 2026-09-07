// Package fake is a directory backend held in memory, with a scriptable
// failure for every operation.
//
// It exists so that the hub's behaviour under a revoked credential, a
// half-read directory, a moved domain or a suspended account can be tested
// and demonstrated without a real tenant. It reaches no network and holds
// no credential.
package fake

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/truvity/access-roster/backend"
)

// Op names an operation, so a test can fail exactly one of them.
type Op string

// The operations a [Backend] can be told to fail.
const (
	OpTenant   Op = "tenant"
	OpProbe    Op = "probe"
	OpAccounts Op = "accounts"
	OpGroups   Op = "groups"
	OpAccount  Op = "account"
	OpGroupsOf Op = "groupsOf"
	OpRevoke   Op = "revoke"
)

// ErrScripted is the default error a failing operation returns.
var ErrScripted = errors.New("fake: scripted failure")

// Backend is an in-memory directory. The zero value is not usable; call
// [New]. Every method is safe for concurrent use.
type Backend struct {
	mu       sync.Mutex
	tenant   backend.Tenant
	accounts map[string]backend.Account
	groups   map[string]backend.Group
	fail     map[Op]error
	calls    map[Op]int
	revoked  bool
}

var _ backend.Backend = (*Backend)(nil)

// New returns a fake tenant with the given id and domains.
func New(tenantID string, domains ...string) *Backend {
	return &Backend{
		tenant:   backend.Tenant{ID: tenantID, Domains: lowerAll(domains)},
		accounts: map[string]backend.Account{},
		groups:   map[string]backend.Group{},
		fail:     map[Op]error{},
		calls:    map[Op]int{},
	}
}

// WithAccount adds a live account and returns the backend, so fixtures read
// as one expression.
func (b *Backend) WithAccount(email, given, family string) *Backend {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := strings.ToLower(email)
	b.accounts[e] = backend.Account{Email: e, Live: true, GivenName: given, FamilyName: family}
	return b
}

// WithGroup adds a group with the given members.
func (b *Backend) WithGroup(email string, members ...string) *Backend {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := strings.ToLower(email)
	b.groups[e] = backend.Group{Email: e, Members: lowerAll(members)}
	return b
}

// Suspend marks an account not live, the way a leaver is suspended.
func (b *Backend) Suspend(email string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := strings.ToLower(email)
	if a, ok := b.accounts[e]; ok {
		a.Live = false
		b.accounts[e] = a
	}
}

// Restore marks an account live again.
func (b *Backend) Restore(email string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := strings.ToLower(email)
	if a, ok := b.accounts[e]; ok {
		a.Live = true
		b.accounts[e] = a
	}
}

// Remove deletes an account, the way a deleted account disappears.
func (b *Backend) Remove(email string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.accounts, strings.ToLower(email))
}

// SetDomains replaces the tenant's domain list, the way a domain moves
// between tenants between two probes.
func (b *Backend) SetDomains(domains ...string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tenant.Domains = lowerAll(domains)
}

// Fail makes op return err until [Backend.Heal]. A nil err means
// [ErrScripted].
func (b *Backend) Fail(op Op, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		err = ErrScripted
	}
	b.fail[op] = err
}

// Heal stops op from failing.
func (b *Backend) Heal(op Op) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fail, op)
}

// Calls reports how often op was called, so a test can prove that a read
// was served from a snapshot rather than from the backend.
func (b *Backend) Calls(op Op) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls[op]
}

// Revoked reports whether Revoke was called.
func (b *Backend) Revoked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.revoked
}

// enter records the call and returns the scripted error, if any.
func (b *Backend) enter(op Op) error {
	b.calls[op]++
	return b.fail[op]
}

// Kind implements [backend.Backend].
func (b *Backend) Kind() string { return "fake" }

// Tenant implements [backend.Backend].
func (b *Backend) Tenant(_ context.Context) (backend.Tenant, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.enter(OpTenant); err != nil {
		return backend.Tenant{}, err
	}
	return backend.Tenant{ID: b.tenant.ID, Domains: slices.Clone(b.tenant.Domains)}, nil
}

// Probe implements [backend.Backend].
func (b *Backend) Probe(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enter(OpProbe)
}

// Accounts implements [backend.Backend].
func (b *Backend) Accounts(_ context.Context) ([]backend.Account, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.enter(OpAccounts); err != nil {
		return nil, err
	}
	out := slices.Collect(maps.Values(b.accounts))
	slices.SortFunc(out, func(x, y backend.Account) int { return strings.Compare(x.Email, y.Email) })
	return out, nil
}

// Groups implements [backend.Backend].
func (b *Backend) Groups(_ context.Context) ([]backend.Group, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.enter(OpGroups); err != nil {
		return nil, err
	}
	out := make([]backend.Group, 0, len(b.groups))
	for _, key := range slices.Sorted(maps.Keys(b.groups)) {
		g := b.groups[key]
		out = append(out, backend.Group{Email: g.Email, Members: slices.Clone(g.Members)})
	}
	return out, nil
}

// Account implements [backend.Backend].
func (b *Backend) Account(_ context.Context, email string) (backend.Account, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.enter(OpAccount); err != nil {
		return backend.Account{}, false, err
	}
	a, ok := b.accounts[strings.ToLower(email)]
	return a, ok, nil
}

// GroupsOf implements [backend.Backend].
func (b *Backend) GroupsOf(_ context.Context, email string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.enter(OpGroupsOf); err != nil {
		return nil, err
	}
	e := strings.ToLower(email)
	var out []string
	for _, key := range slices.Sorted(maps.Keys(b.groups)) {
		if slices.Contains(b.groups[key].Members, e) {
			out = append(out, key)
		}
	}
	return out, nil
}

// Revoke implements [backend.Backend].
func (b *Backend) Revoke(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.enter(OpRevoke); err != nil {
		return err
	}
	b.revoked = true
	return nil
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}
