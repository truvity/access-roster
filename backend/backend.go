// Package backend is the contract a directory backend implements:
// read-only access to one tenant's accounts, groups and domains, plus the
// credential handling that gets there.
//
// Every read is a read. A backend never writes to the directory; the one
// mutating call is [Backend.Revoke], which invalidates the hub's own
// credential at the backend when a workspace is disconnected.
//
// Google Workspace is the first implementation. A second backend
// (Microsoft Entra) implements this same interface, and nothing above this
// package knows which one it is talking to — see
// docs/development/extending.md.
package backend

import (
	"context"
	"errors"
)

// ErrUnsupported is returned by an operation a backend cannot perform:
// revoking a service-account key, for instance, which is retired at the
// backend's own console rather than through an API.
var ErrUnsupported = errors.New("backend: unsupported operation")

// Account is one address's standing in a directory.
//
// A suspended account is present with Live false. A deleted account is
// absent — the distinction matters, because both are "gone" to a consumer
// but only the first can come back.
type Account struct {
	// Email is the primary address, lower-cased.
	Email string
	// Live is false for a suspended account.
	Live bool
	// GivenName and FamilyName are empty when the backend cannot supply
	// them; callers must tolerate that.
	GivenName  string
	FamilyName string
}

// Group is one group and its flat membership. Nested groups are NOT
// expanded: a member that is itself a group appears as its address.
type Group struct {
	// Email is the group's address, lower-cased.
	Email string
	// Members are addresses, lower-cased. A group read is atomic: a
	// backend returns every member or an error, never a partial list.
	Members []string
}

// Tenant identifies the directory a credential reaches, and the domains it
// claims. Domains are discovered on every probe, never configured, so a
// domain moving between tenants is followed without an edit anywhere.
type Tenant struct {
	// ID is the backend's own tenant identifier (Google: the customer id).
	ID string
	// Domains are lower-cased and include every domain of the tenant.
	Domains []string
}

// Backend reads one tenant.
//
// Implementations must be safe for concurrent use: the hub probes,
// refreshes and answers point reads from different goroutines.
type Backend interface {
	// Kind names the implementation: "google", "entra", "fake".
	Kind() string

	// Tenant returns the tenant id and its current domain list.
	Tenant(ctx context.Context) (Tenant, error)

	// Probe exercises the credential now. A nil error means reads are
	// working at this moment; anything else makes the tenant's domains
	// non-authoritative until a later probe succeeds.
	Probe(ctx context.Context) error

	// Accounts returns every account in the tenant. All or an error.
	Accounts(ctx context.Context) ([]Account, error)

	// Groups returns every group with its flat membership. All or an
	// error, and atomic per group.
	Groups(ctx context.Context) ([]Group, error)

	// Account returns one account. found=false is an authoritative
	// absence: the backend answered not-found. A non-nil error means the
	// read failed and nothing may be concluded from it.
	Account(ctx context.Context, email string) (account Account, found bool, err error)

	// GroupsOf returns the addresses of the groups one account belongs to.
	GroupsOf(ctx context.Context, email string) ([]string, error)

	// Revoke invalidates the hub's credential at the backend. It returns
	// [ErrUnsupported] when the credential kind cannot be revoked, which a
	// caller treats as "deleted locally, retire the credential yourself".
	Revoke(ctx context.Context) error
}
