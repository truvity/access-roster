package issuer

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/policy"
)

// Directory is what the issuer needs from the hub, and all it needs: is
// this account live, which directory groups is it in, and may that answer
// be acted on. The issuer never reads a directory itself — one place
// holds the credentials, and it is not this service.
type Directory interface {
	ResolveUser(ctx context.Context, email string) (Standing, error)
}

// Standing is the hub's answer about one address.
type Standing struct {
	Found         bool
	Suspended     bool
	Groups        []string
	Authoritative bool
}

// lastKnown is what the issuer remembers about an identity so that a hub
// it cannot reach does not immediately lock everyone out.
type lastKnown struct {
	groups []string
	at     time.Time
}

// Resolver turns an address into the directory groups the policy should
// see, and implements the hold window: when the hub cannot vouch for its
// answer, an identity keeps the groups it last had, for a while.
//
// The window is the whole reason this type exists. A directory that goes
// unreachable must not read as "everyone lost their groups", because that
// is indistinguishable from a mass revocation and would take down every
// login at once. Equally it must not last forever, or a real removal
// would never take effect. So: last-known groups, for a bounded time, and
// only for identities already seen.
type Resolver struct {
	dir    Directory
	window time.Duration

	mu   sync.Mutex
	seen map[string]lastKnown
	now  func() time.Time
}

// NewResolver returns a resolver over dir, holding last-known groups for
// window.
func NewResolver(dir Directory, window time.Duration) *Resolver {
	return &Resolver{dir: dir, window: window, seen: map[string]lastKnown{}, now: time.Now}
}

// SetClock replaces the clock, for tests.
func (r *Resolver) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

// Resolution is what the issuer decided about an address, and why.
type Resolution struct {
	Groups []string
	// Held is true when the groups come from the hold window rather than
	// from a fresh authoritative answer. A token is still issued; the
	// distinction is for the audit trail and for the console.
	Held bool
}

// Refused reports that no token may be issued, with the reason.
type Refused struct{ Reason string }

func (e *Refused) Error() string { return "refused: " + e.Reason }

// Resolve answers what groups an address should be evaluated with.
//
// The rules, in order: a suspended account gets nothing, because that is
// the whole point of asking the hub at all; an authoritative answer is
// taken and remembered; a non-authoritative answer falls back to what was
// last known, if that is recent enough; an identity never seen before
// gets nothing, because there is nothing to hold.
func (r *Resolver) Resolve(ctx context.Context, email string) (Resolution, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	standing, err := r.dir.ResolveUser(ctx, email)

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()

	if err == nil && standing.Authoritative {
		if !standing.Found || standing.Suspended {
			delete(r.seen, email)
			return Resolution{}, &Refused{Reason: "the directory says this account is not live"}
		}
		r.seen[email] = lastKnown{groups: standing.Groups, at: now}
		return Resolution{Groups: standing.Groups}, nil
	}

	// Either the hub could not be reached, or it answered without being
	// able to vouch for the answer. Both are the same situation from here:
	// act on what was last known, or on nothing.
	known, ok := r.seen[email]
	if !ok || now.Sub(known.at) > r.window {
		if err != nil {
			return Resolution{}, err
		}
		return Resolution{}, &Refused{Reason: "the directory cannot be vouched for and this identity has no recent answer"}
	}
	return Resolution{Groups: known.groups, Held: true}, nil
}

// Forget drops what is remembered about an address, so that revoking
// someone also stops the hold window from keeping them alive through an
// unreachable hub.
func (r *Resolver) Forget(email string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.seen, strings.ToLower(strings.TrimSpace(email)))
}

// Input builds the policy input for a person, given what the hub said.
func (res Resolution) Input(email string) policy.Input {
	return policy.Input{
		Email:           email,
		DirectoryGroups: res.Groups,
		// A held answer still counts as authoritative to the policy: the
		// window has already decided that acting on it is acceptable, and
		// the policy's own Authoritative flag means "may membership grant
		// anything at all", which within the window it may.
		Authoritative: true,
	}
}
