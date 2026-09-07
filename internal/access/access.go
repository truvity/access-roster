// Package access decides who is at the console and what they may do.
//
// It never proves who anyone is. A principal arrives already authenticated
// — by a bearer an authenticating gateway forwarded, by a sign-in the hub
// delegated to a connected directory or an external issuer, or by the
// break-glass admin account — and this package turns that principal into
// an identity with a role, by asking the directory for the caller's groups
// and running the rules.
package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/rules"
)

// ErrSuspended is returned when the directory says, authoritatively, that
// the account signing in is not live.
var ErrSuspended = errors.New("access: the account is not live")

// Source says how a principal was established.
type Source string

// The sources, in the order an installation usually meets them.
const (
	// SourceForwarded is a bearer an authenticating gateway forwarded —
	// the normal path where a proxy fronts every console.
	SourceForwarded Source = "forwarded"
	// SourceDirectory is the hub's own sign-in with a connected directory,
	// for a standalone installation.
	SourceDirectory Source = "directory"
	// SourceOIDC is the hub's own sign-in against an external issuer.
	SourceOIDC Source = "oidc"
	// SourceAdmin is the break-glass account.
	SourceAdmin Source = "admin"
)

// Principal is an authenticated caller, before the rules have run.
type Principal struct {
	// Email of the caller; empty for the admin account.
	Email string
	// Subject is the issuer's stable identifier, or "admin".
	Subject string
	// Source is how the caller was established.
	Source Source
	// Issuer of the token, for claim rules.
	Issuer string
	// Claims of that token.
	Claims map[string][]string
}

// Identity is an authorized caller: a principal plus what the rules gave it.
type Identity struct {
	Email     string
	Subject   string
	Source    Source
	Role      rules.Role
	Matched   []string
	ExpiresAt time.Time
}

// Can reports whether the identity holds at least the given role.
func (i Identity) Can(role rules.Role) bool { return i.Role.Implies(role) }

// Directory is the part of the hub this package needs: the groups an
// address is in, and whether that answer may be acted on.
type Directory interface {
	ResolveUser(ctx context.Context, email string, maxAge *time.Duration) (hub.UserResult, error)
}

// Authorizer turns principals into identities.
type Authorizer struct {
	dir Directory
	now func() time.Time

	mu     sync.Mutex
	policy rules.Policy
	held   map[string]heldGrant
}

// heldGrant is the last result an identity was granted while the directory
// was authoritative, kept so that a spell of uncertainty does not lock
// people out of the console that fixes it.
type heldGrant struct {
	result rules.Result
	at     time.Time
}

// NewAuthorizer returns an authorizer over a policy and a directory.
func NewAuthorizer(policy rules.Policy, dir Directory) *Authorizer {
	return &Authorizer{dir: dir, now: time.Now, policy: policy, held: map[string]heldGrant{}}
}

// SetClock replaces the clock. For tests.
func (a *Authorizer) SetClock(now func() time.Time) { a.now = now }

// SetPolicy replaces the rules, so that a console-added rule takes effect
// without a restart.
func (a *Authorizer) SetPolicy(p rules.Policy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.policy = p
}

// Policy returns the rules in force.
func (a *Authorizer) Policy() rules.Policy {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.policy
}

// Authorize resolves a principal into an identity.
//
// The break-glass account is an operator by construction: it exists for
// the day the rules or the directory are what is broken. Everyone else is
// resolved through the directory and the rules, and an authoritative
// "not live" is a refusal rather than an empty role — a suspended account
// must not reach the console at all.
func (a *Authorizer) Authorize(ctx context.Context, p Principal) (Identity, error) {
	if p.Source == SourceAdmin {
		return Identity{
			Email:   p.Email,
			Subject: "admin",
			Source:  SourceAdmin,
			Role:    rules.RoleOperator,
			Matched: []string{"break-glass admin"},
		}, nil
	}

	in := rules.Input{
		Email:  strings.ToLower(strings.TrimSpace(p.Email)),
		Issuer: p.Issuer,
		Claims: p.Claims,
	}

	if in.Email != "" && a.dir != nil {
		resolved, err := a.dir.ResolveUser(ctx, in.Email, nil)
		if err != nil {
			return Identity{}, fmt.Errorf("resolve %s: %w", in.Email, err)
		}
		if resolved.Authoritative && resolved.InDomain && (!resolved.Found || resolved.Suspended) {
			return Identity{}, fmt.Errorf("%w: %s", ErrSuspended, in.Email)
		}
		in.Groups = resolved.Groups
		in.Authoritative = resolved.Authoritative
	}

	result := a.evaluate(in)
	return Identity{
		Email:   p.Email,
		Subject: p.Subject,
		Source:  p.Source,
		Role:    result.Role,
		Matched: result.Matched,
	}, nil
}

// evaluate runs the rules and applies the hold window: while the directory
// is not authoritative, an identity keeps what it last held, and one that
// was never seen gets only what rules independent of the directory grant.
func (a *Authorizer) evaluate(in rules.Input) rules.Result {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := a.policy.Evaluate(in)
	if in.Email == "" {
		return result
	}

	if in.Authoritative {
		a.held[in.Email] = heldGrant{result: result, at: a.now()}
		return result
	}

	window := a.policy.Defaults.HoldWindow.Duration()
	if window <= 0 {
		return result
	}
	previous, ok := a.held[in.Email]
	if !ok || a.now().Sub(previous.at) > window {
		return result
	}
	if previous.result.Role.Implies(result.Role) {
		return previous.result
	}
	return result
}
