// Package access decides who is at the console and what they may do.
//
// It never proves who anyone is. A principal arrives already
// authenticated — by a bearer an authenticating gateway forwarded, by a
// sign-in the hub delegated to a connected directory or an external
// issuer, or by the break-glass admin account — and this package turns
// that principal into an identity, by asking the directory which groups
// the account is in and running the policy.
//
// The hub holds no role vocabulary of its own: an identity is an operator
// because the policy puts it in the operators group, exactly as any other
// relying party's roles work.
package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/emailaddr"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/policy"
)

// ErrSuspended is returned when the directory says, authoritatively, that
// the account signing in is not live.
var ErrSuspended = errors.New("access: the account is not live")

// Role is what an identity may do in this console.
type Role string

// The roles. Operator implies viewer.
const (
	RoleNone     Role = ""
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
)

func (r Role) rank() int {
	switch r {
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	case RoleNone:
		return 0
	default:
		return 0
	}
}

// Implies reports whether holding r also confers other.
func (r Role) Implies(other Role) bool { return r.rank() >= other.rank() }

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

// Principal is an authenticated caller, before the policy has run.
type Principal struct {
	Email   string
	Subject string
	Source  Source
	Issuer  string
	Claims  map[string][]string
}

// Identity is an authorized caller: a principal, the internal groups the
// policy puts it in, and what those groups grant.
type Identity struct {
	Email      string
	Subject    string
	GivenName  string
	FamilyName string
	Source     Source
	Role       Role
	// Groups are the internal groups held.
	Groups []string
	// Held carries the same with the reason for each.
	Held []policy.Held
	// Claims is what a token for this identity would carry.
	Claims map[string]any
	// Lifetime is how long such a token would live.
	Lifetime time.Duration
}

// Can reports whether the identity holds at least the given role.
func (i Identity) Can(role Role) bool { return i.Role.Implies(role) }

// Name is the person's name as the directory has it, or the address when
// it has none.
func (i Identity) Name() string {
	name := strings.TrimSpace(i.GivenName + " " + i.FamilyName)
	if name == "" {
		return i.Email
	}
	return name
}

// Directory is the part of the hub this package needs: the groups an
// address is in, whether the account is live, and whether that answer may
// be acted on.
type Directory interface {
	ResolveUser(ctx context.Context, email string, maxAge *time.Duration) (hub.UserResult, error)
}

// Authorizer turns principals into identities.
type Authorizer struct {
	dir        Directory
	set        *policy.Set
	holdWindow time.Duration
	now        func() time.Time

	mu   sync.Mutex
	held map[string]heldGrant
}

// heldGrant is the last result an identity was granted while the
// directory was authoritative, kept so that a spell of uncertainty does
// not lock people out of the console that fixes it.
type heldGrant struct {
	result policy.Result
	at     time.Time
}

// NewAuthorizer returns an authorizer over a policy and a directory.
func NewAuthorizer(set *policy.Set, dir Directory, holdWindow time.Duration) *Authorizer {
	return &Authorizer{
		dir:        dir,
		set:        set,
		holdWindow: holdWindow,
		now:        time.Now,
		held:       map[string]heldGrant{},
	}
}

// SetClock replaces the clock. For tests.
func (a *Authorizer) SetClock(now func() time.Time) { a.now = now }

// Policy returns the policy in force.
func (a *Authorizer) Policy() *policy.Set { return a.set }

// Authorize resolves a principal into an identity.
//
// The break-glass account is an operator by construction: it exists for
// the day the policy or the directory is what is broken. Everyone else is
// resolved through the directory and the policy, and an authoritative
// "not live" is a refusal rather than an empty role — a suspended account
// must not reach the console at all.
func (a *Authorizer) Authorize(ctx context.Context, p Principal) (Identity, error) {
	if p.Source == SourceAdmin {
		return Identity{
			Email:   p.Email,
			Subject: "admin",
			Source:  SourceAdmin,
			Role:    RoleOperator,
			Held:    []policy.Held{{Group: "break-glass admin", Via: []string{"the admin account"}}},
		}, nil
	}

	explained, err := a.explain(ctx, Proof{Email: p.Email}, true)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		Email:      p.Email,
		Subject:    p.Subject,
		GivenName:  explained.GivenName,
		FamilyName: explained.FamilyName,
		Source:     p.Source,
		Role:       explained.Role,
		Groups:     explained.Result.Groups,
		Held:       explained.Result.Held,
		Claims:     explained.Result.Claims,
		Lifetime:   explained.Result.Lifetime,
	}, nil
}

// Proof is what to explain: a person by address, a CI job, or a cluster
// workload. Exactly the three kinds the policy can resolve, so the same
// page answers what a pipeline is entitled to as well as what a person is.
type Proof struct {
	Email          string
	GitHub         *policy.GitHubClaims
	ServiceAccount *policy.ServiceAccountRef
}

// IsPerson reports whether the proof is an address.
func (p Proof) IsPerson() bool { return p.GitHub == nil && p.ServiceAccount == nil }

// ClientAdmission is one relying party and whether a proof reaches it.
type ClientAdmission struct {
	ID       string
	Kind     string
	Requires []string
	Admitted bool
	Lifetime time.Duration
}

// Explanation is what a proof effectively gets, and why.
type Explanation struct {
	Email           string
	Workspace       string
	GivenName       string
	FamilyName      string
	InDomain        bool
	Found           bool
	Suspended       bool
	Authoritative   bool
	DirectoryGroups []string
	Result          policy.Result
	Role            Role
	Clients         []ClientAdmission
}

// Explain answers what a proof would effectively get. Unlike Authorize it
// never refuses: a suspended account is reported as suspended, which is
// the whole point of looking.
func (a *Authorizer) Explain(ctx context.Context, proof Proof) (Explanation, error) {
	return a.explain(ctx, proof, false)
}

func (a *Authorizer) explain(ctx context.Context, proof Proof, refuseSuspended bool) (Explanation, error) {
	email := strings.ToLower(strings.TrimSpace(proof.Email))
	out := Explanation{Email: email}
	in := policy.Input{Email: email, GitHub: proof.GitHub, ServiceAccount: proof.ServiceAccount}

	// The break-glass admin has no address, so there is nothing to resolve
	// and nothing to look up: it holds its role by construction, not by
	// membership, and saying so is more useful than an error.
	_, routable := emailaddr.Domain(email)
	if routable && proof.IsPerson() && a.dir != nil {
		resolved, err := a.dir.ResolveUser(ctx, email, nil)
		if err != nil {
			return Explanation{}, fmt.Errorf("resolve %s: %w", email, err)
		}
		if refuseSuspended && resolved.Authoritative && resolved.InDomain &&
			(!resolved.Found || resolved.Suspended) {
			return Explanation{}, fmt.Errorf("%w: %s", ErrSuspended, email)
		}
		out.Workspace = resolved.Workspace
		out.InDomain, out.Found, out.Suspended = resolved.InDomain, resolved.Found, resolved.Suspended
		out.Authoritative, out.DirectoryGroups = resolved.Authoritative, resolved.Groups
		out.GivenName, out.FamilyName = resolved.GivenName, resolved.FamilyName
		in.DirectoryGroups, in.Authoritative = resolved.Groups, resolved.Authoritative
	}

	out.Result = a.evaluate(in)
	out.Role = roleOf(out.Result)
	out.Clients = a.admissions(out.Result)
	return out, nil
}

// admissions reports, for every declared client, whether this result
// reaches it and how long the token would live once the client's cap is
// applied. It is what makes the whole model observable from one page:
// groups are the vocabulary, clients are what the vocabulary buys.
func (a *Authorizer) admissions(result policy.Result) []ClientAdmission {
	clients := a.set.Clients()
	out := make([]ClientAdmission, 0, len(clients))
	for i := range clients {
		client := &clients[i]
		admission := ClientAdmission{
			ID:       client.ID,
			Kind:     client.Kind,
			Requires: client.Requires,
			Admitted: client.Admits(result),
		}
		if admission.Admitted {
			admission.Lifetime = client.Cap(result.Lifetime)
		}
		out = append(out, admission)
	}
	return out
}

// roleOf reads the console's two roles off the policy: an identity is an
// operator because it is in the operators group.
func roleOf(result policy.Result) Role {
	switch {
	case result.Has(policy.GroupOperators):
		return RoleOperator
	case result.Has(policy.GroupViewers):
		return RoleViewer
	default:
		return RoleNone
	}
}

// evaluate runs the policy and applies the hold window: while the
// directory is not authoritative, an identity keeps what it last held,
// and one that was never seen gets only what matchers grant.
func (a *Authorizer) evaluate(in policy.Input) policy.Result {
	result := a.set.Evaluate(in)
	if in.Email == "" {
		return result
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if in.Authoritative {
		a.held[in.Email] = heldGrant{result: result, at: a.now()}
		return result
	}
	if a.holdWindow <= 0 {
		return result
	}
	previous, ok := a.held[in.Email]
	if !ok || a.now().Sub(previous.at) > a.holdWindow {
		return result
	}
	if roleOf(previous.result).Implies(roleOf(result)) {
		return previous.result
	}
	return result
}

// Holder is one account that holds a group or reaches a client, and why.
type Holder struct {
	Email         string
	GivenName     string
	FamilyName    string
	Live          bool
	Authoritative bool
	Via           []string
	Lifetime      time.Duration
}

// HoldersOf resolves an internal group, or a client, to the people who
// hold it right now.
//
// The policy says which directory groups count; only the directory knows
// who is in them. Answering that is what makes an access review possible
// at all, and it is a read over snapshots already in memory.
//
// A suspended account still appears, marked: seeing that a leaver is
// still counted somewhere is the whole point of looking.
func (a *Authorizer) HoldersOf(people []hub.Person, group, client string) []Holder {
	var wanted policy.Client
	if client != "" {
		found, ok := a.set.Client(client)
		if !ok {
			return nil
		}
		wanted = found
	}

	out := make([]Holder, 0, len(people))
	for i := range people {
		person := &people[i]
		result := a.set.Evaluate(policy.Input{
			Email:           person.Email,
			DirectoryGroups: person.DirectoryGroups,
			Authoritative:   person.Authoritative,
		})

		holder := Holder{
			Email:         person.Email,
			GivenName:     person.GivenName,
			FamilyName:    person.FamilyName,
			Live:          person.Live,
			Authoritative: person.Authoritative,
		}
		switch {
		case group != "":
			if !result.Has(group) {
				continue
			}
			for _, held := range result.Held {
				if held.Group == group {
					holder.Via = held.Via
				}
			}
		case client != "":
			if !wanted.Admits(result) {
				continue
			}
			for _, name := range wanted.Requires {
				if result.Has(name) {
					holder.Via = append(holder.Via, name)
				}
			}
			holder.Lifetime = wanted.Cap(result.Lifetime)
		default:
			continue
		}
		out = append(out, holder)
	}
	return out
}
