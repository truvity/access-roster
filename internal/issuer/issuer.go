// Package issuer is the token service: it verifies proofs produced
// elsewhere, applies the shared policy, and issues tokens. It never
// authenticates anyone and holds no user records — the line the design
// draws around it is in docs/design/access-issuer.md.
package issuer

import (
	"context"
	"time"

	"github.com/truvity/audit/record"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/policy"
)

// Config is what the issuer needs to run beyond its policy and the hub.
type Config struct {
	// URL is the public issuer URL. It must be stable for the life of an
	// installation: it is baked into every relying party's trust.
	URL string
	// TokenLifetime caps how long an access token lives when the policy
	// asks for longer.
	TokenLifetime time.Duration
	// RefreshLifetime is how long a session lives without being refreshed.
	RefreshLifetime time.Duration
	// AbsoluteLifetime is the global timeout: no per-client session, and
	// no access or ID token, outlives auth_time by more than this, no
	// matter how often it is refreshed. It is what turns "signs in once
	// and never has to again" from a possibility into a bound.
	//
	// It may be shorter OR longer than RefreshLifetime; either way the
	// session's actual end is the EARLIER of the two, measured from
	// auth_time rather than from the last refresh -- see
	// [Sessions.Record] and [Sessions.Refreshed]. A deployment that wants
	// the refresh window to be the only limit in practice sets this
	// generously longer than it; one that wants a hard daily sign-in sets
	// it shorter. Neither is refused: only a value that could never bound
	// anything (zero, negative, or shorter than TokenLifetime, which
	// would mint tokens already past the one limit meant to outlive them)
	// is, and that refusal happens where this is loaded from the
	// environment, not here -- see issuerapp.Load.
	AbsoluteLifetime time.Duration
	// HoldWindow is how long an identity keeps its last-known groups while
	// the hub cannot be vouched for.
	HoldWindow time.Duration
	// AllowInsecure permits an http:// issuer URL. The library refuses
	// one by default and is right to: every token this service signs is
	// bearer credential, and an issuer reached over plaintext can be
	// impersonated by anyone on the path. It exists for a local run and a
	// test, and a deployment that sets it has misconfigured itself.
	AllowInsecure bool
}

// Defaults for the durations a deployment does not set.
const (
	DefaultTokenLifetime    = time.Hour
	DefaultRefreshLifetime  = 12 * time.Hour
	DefaultAbsoluteLifetime = 24 * time.Hour
	DefaultHoldWindow       = 4 * time.Hour
)

func (c Config) withDefaults() Config {
	if c.TokenLifetime <= 0 {
		c.TokenLifetime = DefaultTokenLifetime
	}
	if c.RefreshLifetime <= 0 {
		c.RefreshLifetime = DefaultRefreshLifetime
	}
	if c.AbsoluteLifetime <= 0 {
		c.AbsoluteLifetime = DefaultAbsoluteLifetime
	}
	if c.HoldWindow <= 0 {
		c.HoldWindow = DefaultHoldWindow
	}
	return c
}

// Issuer applies the policy to verified proofs. It is the part of the
// token service that decides; the OpenID protocol around it comes from a
// library, and the storage that library needs is a thin shell over this.
type Issuer struct {
	cfg      Config
	set      *policy.Set
	resolver *Resolver
	sessions *Sessions
	sso      *SSO
	audit    audit.Recorder
	// githubApps are the catalogue Apps installation tokens are minted
	// for. Nil refuses every such request.
	githubApps *GitHubApps
}

// UseAudit gives the issuer the service's recorder. The directory half
// opens the one stream, so this is handed in after construction rather
// than built here.
func (i *Issuer) UseAudit(r audit.Recorder) { i.audit = r }

// record writes one record down, or nothing where no recorder was given.
// What it keeps of the request that caused it arrives in the context, put
// there by the middleware in front (emit.Middleware), because the storage
// an OpenID library calls is handed nothing else.
func (i *Issuer) record(ctx context.Context, r *record.Record) {
	if i == nil || i.audit == nil {
		return
	}
	i.audit.Record(ctx, r)
}

// recordDurable writes one record down and answers only once it is kept:
// for a recovery sign-in, which does not complete without it.
func (i *Issuer) recordDurable(ctx context.Context, r *record.Record) error {
	if i == nil || i.audit == nil {
		return nil
	}
	return i.audit.RecordDurable(ctx, r)
}

// New returns an issuer over a policy set, a directory and the shared
// store its session index lives in. The store is not optional: an index
// per process lists what one replica happened to record and revokes only
// there, which is a security control that reports success and leaves
// access in place.
func New(cfg Config, set *policy.Set, dir Directory, state State) *Issuer {
	cfg = cfg.withDefaults()

	return &Issuer{
		cfg:      cfg,
		set:      set,
		resolver: NewResolver(dir, cfg.HoldWindow),
		sessions: NewSessions(state, cfg.RefreshLifetime, cfg.AbsoluteLifetime),
		sso:      NewSSO(state, cfg.RefreshLifetime),
	}
}

// Sessions is the index of what this issuer has outstanding: what the
// console lists on a person's page and a client's, and revokes.
func (i *Issuer) Sessions() *Sessions { return i.sessions }

// SSO is the browser's session with this issuer -- what makes a second
// console cost no login, and the parent of the sessions above.
func (i *Issuer) SSO() *SSO { return i.sso }

// Policy is the set in force, shared with the hub.
func (i *Issuer) Policy() *policy.Set { return i.set }

// Config returns the durations and the issuer URL in force.
func (i *Issuer) Config() Config { return i.cfg }

// Revoke ends every session an identity holds and forgets its last-known
// groups, so that an unreachable hub cannot keep a revoked person alive
// through the hold window. It returns how many sessions ended.
//
// This is the operator's lever between the two halves of sign-out: the
// proxy ending its own session, and the issuer refusing the next refresh
// once the directory catches up. Without it, cutting someone off means
// waiting for a refresh that may be minutes away.
func (i *Issuer) Revoke(ctx context.Context, identity string) (int, error) {
	i.resolver.Forget(identity)

	return i.sessions.Revoke(ctx, Query{Identity: identity})
}
