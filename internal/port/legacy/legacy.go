// Package legacy is the TEMPORARY adapter that implements the ports by
// wrapping today's storage exactly: the Kubernetes ConfigMaps and Secrets of
// internal/kube and the Valkey of internal/valkey. It exists so that the
// service can depend on the ports before the data moves (ADR 0031); it is
// deleted when the migration has run and the NATS and DynamoDB adapters
// carry the layout of docs/design/ports.md.
//
// Nothing here changes what is written where. The data model today is
// per-domain objects, not a key-value store, so each port key is mapped onto
// the object it already lives in, byte for byte:
//
//	State, Valkey families (issuer's logins in progress, the hub's leases)
//	  req.<id>        issuer:request:<id>           code.<id>   issuer:code:<id>
//	  codesess.<id>   issuer:code-session:<id>      tok.<jti>   issuer:token:<jti>
//	  sso.<id>        issuer:sso:<id>               rt.<hash>   issuer:session-token:<hash>
//	  rtrot.<hash>    issuer:session-rotated:<hash> keyring.<alg>:<kid>
//	                                                      issuer:keyring:entry:<alg>:<kid>
//	  lease.<kind>:<ws>  {<ws>}:lease:<kind>       (lease.<name>  lease:<name>)
//	  any key containing ':'  itself -- the legacy namespace the issuer writes in today
//	State, ConfigMap families
//	  gh.org.<org>    entry <org>.json of the <release>-github-orgs ConfigMap
//	Blob
//	  snapshots/<ws>          {<ws>}:snapshot in Valkey (the same gzip bytes)
//	  reports/github/<key>    entry <key> of the <release>-github-status ConfigMap
//	  reports/slack/<key>     entry <key> of the <release>-slack-status ConfigMap
//
// Every other key of the layout (ses., sid., ws., gh.link., app., gate.,
// share., cache., dedupe., notify.) has no object of its own today and is
// [port.ErrUnsupported]: its data is kept inside a domain store (a session is
// one Valkey value without its person; a link is a Secret entry keyed by
// account id), which the legacy adapter cannot present as that key without
// writing different bytes.
//
// # Gaps against the port semantics
//
//   - Revisions are the SHA-1 of the stored bytes. Neither Valkey nor a
//     ConfigMap entry has a per-key version, and adding one would change what
//     is written. So a rewrite of identical bytes keeps its revision, and a
//     compare-and-swap cannot tell a record that went A, B, A from one that
//     never moved. The swap itself is atomic: a Lua script in Valkey, the
//     ConfigMap's own resourceVersion for an entry, which is the closest safe
//     behaviour and what every domain store already relies on.
//   - Watch polls: it lists the prefix every [Options.WatchEvery] and reports
//     differences. There is no push, and an expiry is seen as a delete when a
//     poll next finds the record gone.
//   - A ConfigMap entry has no lifetime, so the kube families accept only the
//     permanent writes the layout allows, and a lifetime there is
//     [port.ErrUnsupported].
//   - Report and App-key entries are text: a ConfigMap cannot hold arbitrary
//     bytes, so a Blob write of invalid UTF-8 to reports/ is
//     [port.ErrUnsupported].
//   - gh.org.<org> is the record only. The organisation's credential is a
//     separate Secret the domain store writes, so the layout's "record with its
//     sealed App key" is two objects here.
//   - Trigger delivers within this process only. Cross-process ticks are the
//     controllers' own polling interval, as today.
//   - Sealer is [port.ErrUnsupported]: nothing is sealed today (the
//     credentials are Secrets), and a process-local key would produce
//     envelopes no other process or restart could open.
//   - Index (a set) is carried by the port only for this adapter and the
//     in-memory one; see [port.Index].
package legacy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/valkey"
)

// Backend is today's storage as it has been opened: either part may be
// absent, as it is today (no Valkey configured, not in a cluster), and what
// is absent is [port.ErrUnsupported] rather than quietly somewhere else.
type Backend struct {
	// Kube is the namespace's ConfigMaps and Secrets; nil outside a cluster.
	Kube *kube.Client
	// Valkey is the shared cache; nil when no Valkey is configured.
	Valkey *valkey.State
	// ReviewToken is the cluster's TokenReview, for [port.Identity].
	ReviewToken func(ctx context.Context, token string, audiences []string) (string, error)
}

// Options tunes the adapter.
type Options struct {
	// SnapshotTTL is how long a snapshot outlives its last write
	// ([valkey.DefaultTTL] when zero).
	SnapshotTTL time.Duration
	// WatchEvery is the poll interval of Watch (2s when zero).
	WatchEvery time.Duration
}

// Ports returns every port over the backend.
func (b *Backend) Ports(o Options) port.Set {
	if o.SnapshotTTL <= 0 {
		o.SnapshotTTL = valkey.DefaultTTL
	}
	if o.WatchEvery <= 0 {
		o.WatchEvery = 2 * time.Second
	}
	state := &State{b: b, every: o.WatchEvery}
	return port.Set{
		State:    state,
		Index:    Index{b: b},
		Blob:     &Blob{b: b, ttl: o.SnapshotTTL},
		Trigger:  memory.NewTrigger(),
		Sealer:   Sealer{},
		Identity: Identity{review: b.ReviewToken},
	}
}

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s", port.ErrUnsupported, fmt.Sprintf(format, args...))
}

func unavailable(err error) error {
	if err == nil || errors.Is(err, port.ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", port.ErrUnavailable, err)
}

// Sealer is [port.Sealer] where nothing is sealed.
type Sealer struct{}

// Wrap implements [port.Sealer].
func (Sealer) Wrap(context.Context, []byte, string) (port.Wrapped, error) {
	return port.Wrapped{}, unsupported("the legacy storage seals nothing: credentials are Secrets")
}

// Unwrap implements [port.Sealer].
func (Sealer) Unwrap(context.Context, port.Wrapped, string) ([]byte, error) {
	return nil, unsupported("the legacy storage seals nothing: credentials are Secrets")
}

// Identity is [port.Identity] over the cluster's TokenReview.
type Identity struct {
	review func(ctx context.Context, token string, audiences []string) (string, error)
}

// Verify implements [port.Identity].
func (i Identity) Verify(ctx context.Context, token string, audiences []string) (string, error) {
	if i.review == nil {
		return "", unsupported("this process is not in a cluster, so there is no TokenReview")
	}
	subject, err := i.review(ctx, token, audiences)
	switch {
	case errors.Is(err, kube.ErrTokenRejected):
		return "", fmt.Errorf("%w: %w", port.ErrUnauthenticated, err)
	case err != nil:
		return "", unavailable(err)
	}
	return subject, nil
}
