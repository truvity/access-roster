// Package port is the storage, signalling and identity edge of the
// service: small interfaces with the semantics in docs/design/ports.md,
// and nothing else.
//
// Business code names a port and never an adapter, and an adapter holds no
// business rule (ADR 0024: a port, not a framework). The adapters are
// internal/port/memory (tests, the demonstration) and internal/port/legacy
// (today's ConfigMaps, Secrets and Valkey, until the migration of ADR 0031
// has run). internal/port/porttest is the conformance suite every adapter
// passes.
package port

import (
	"context"
	"errors"
	"time"
)

// The errors every adapter maps its engine's errors to. Anything else is
// [ErrUnavailable], which a caller on the sign-in path treats as "the store
// is down" and refuses the request.
var (
	// ErrNotFound is a key that is absent or has expired.
	ErrNotFound = errors.New("port: not found")
	// ErrExists is a Create over a live record.
	ErrExists = errors.New("port: already exists")
	// ErrConflict is a conditional write whose revision or version moved.
	ErrConflict = errors.New("port: revision moved")
	// ErrBadPage is a page token that was issued for another prefix.
	ErrBadPage = errors.New("port: page token is not for this prefix")
	// ErrTooLarge is a value over [MaxValue].
	ErrTooLarge = errors.New("port: value is too large")
	// ErrUnavailable is the store being down or answering something this
	// package has no name for. Adapters wrap the cause.
	ErrUnavailable = errors.New("port: store unavailable")
	// ErrUnwrap is a wrapped key that this key-encryption key did not wrap,
	// opened under a wrong context, or whose key is revoked.
	ErrUnwrap = errors.New("port: cannot unwrap")
	// ErrNoLifetime is a write with no lifetime to a key the layout does not
	// mark permanent.
	ErrNoLifetime = errors.New("port: the key needs a lifetime")
	// ErrUnsupported is an operation or a key an adapter cannot honour
	// exactly. It is never returned silently where a weaker behaviour would
	// do: an adapter documents each one, and the conformance suite names it.
	ErrUnsupported = errors.New("port: not supported by this adapter")
)

// MaxValue is the largest value State accepts: the smaller of the two
// engines' limits, with headroom. Larger content is a blob.
const MaxValue = 256 << 10

// Revision is opaque and changes on every write. Callers compare it for
// equality and never order it.
type Revision string

// Record is one State entry as read.
type Record struct {
	Key      string
	Value    []byte
	Revision Revision
}

// Page is one page of a listing. Next is empty on the last page.
type Page struct {
	Records []Record
	Next    string
}

// Event is a change under a watched prefix. Err, when set, is the last
// event of the stream; the channel closes after it and the caller
// resubscribes (and lists, to reconcile).
type Event struct {
	Key      string
	Revision Revision
	Deleted  bool
	Err      error
}

// State is a key-value store with a lifetime on every record, a revision on
// every write and no relations. Keys are strings of the form a.b.c and a
// prefix ends at a dot. A ttl of 0 is permanent and is allowed only for the
// keys the layout marks so.
type State interface {
	// Get returns the live record: ErrNotFound if absent or expired.
	Get(ctx context.Context, key string) (Record, error)
	// Put writes unconditionally and returns the new revision.
	Put(ctx context.Context, key string, value []byte, ttl time.Duration) (Revision, error)
	// Create writes only if the key is absent; an expired record is absent.
	Create(ctx context.Context, key string, value []byte, ttl time.Duration) (Revision, error)
	// Update writes only if the revision is still rev: ErrConflict if it
	// moved, ErrNotFound if the key is gone.
	Update(ctx context.Context, key string, value []byte, ttl time.Duration, rev Revision) (Revision, error)
	// Delete removes the key; an absent key is not an error.
	Delete(ctx context.Context, key string) error
	// DeleteIfRevision removes the key only if the revision is still rev.
	DeleteIfRevision(ctx context.Context, key string, rev Revision) error
	// List returns the live records under a prefix in key order, at most
	// limit of them (0 is the adapter's default), continuing from page, the
	// Next of the previous call.
	List(ctx context.Context, prefix, page string, limit int) (Page, error)
	// Watch streams changes under a prefix from now: at-least-once and
	// unordered across keys, ending with an Event carrying Err when the
	// adapter fails and closing when ctx ends.
	Watch(ctx context.Context, prefix string) (<-chan Event, error)
}

// Index is an unordered set of members under one key, with the set's own
// expiry refreshed on every Add.
//
// It is a TRANSITIONAL part of the port: the issuer's session index is a
// Valkey set today, and ports.md replaces it with prefix listing (`ses.<person>.`).
// Until the migration has run, the legacy adapter must keep writing sets, so
// the port carries them. A new feature does not use it.
type Index interface {
	// Add records a member and refreshes the set's expiry when ttl > 0.
	Add(ctx context.Context, key, member string, ttl time.Duration) error
	// Remove drops a member; removing what is absent is not an error.
	Remove(ctx context.Context, key, member string) error
	// Members lists them in no order. A set nobody wrote is empty.
	Members(ctx context.Context, key string) ([]string, error)
}

// Object is a blob as read.
type Object struct {
	Body    []byte
	Version string
}

// Blob is whole-object storage for what is too large for a State item and
// read whole: a target's status report, a directory snapshot. Names are
// slash-separated (`reports/<target>`, `snapshots/<directory>`). A reader
// treats a missing blob as "not yet written".
type Blob interface {
	// Read returns the object: ErrNotFound if absent.
	Read(ctx context.Context, name string) (Object, error)
	// Write replaces the object and returns its version.
	Write(ctx context.Context, name string, body []byte) (string, error)
	// WriteIfVersion replaces it only if the version is unchanged:
	// ErrConflict if it moved, ErrNotFound if it is gone.
	WriteIfVersion(ctx context.Context, name string, body []byte, version string) (string, error)
	// Delete removes it; an absent object is not an error.
	Delete(ctx context.Context, name string) error
	// List returns the names under a prefix, sorted.
	List(ctx context.Context, prefix string) ([]string, error)
}

// Replacer is an optional Blob capability: replace every object under a
// prefix with exactly the given ones (name relative to the prefix), the
// way a reconciler replaces its report. An adapter that can do it in one
// write does, and a caller falls back to Write and Delete without it.
type Replacer interface {
	Replace(ctx context.Context, prefix string, objects map[string][]byte) error
}

// Trigger turns "this target has work" into a tick without a poll. A
// notification is a hint and may be duplicated or lost; the lease and the
// periodic backstop make both harmless.
type Trigger interface {
	// Notify asks for a tick of the target; it coalesces with one waiting.
	Notify(ctx context.Context, target string) error
	// Subscribe runs handler for every notification delivered to this
	// process, until stop is called.
	Subscribe(handler func(target string)) (stop func())
}

// Wrapped is a data key wrapped by a key-encryption key.
type Wrapped struct {
	KeyID string
	Blob  []byte
}

// Sealer wraps and unwraps the data key of a sealed secret. The binding
// (the record's key and kind) is authenticated, so a sealed value copied
// under another key does not open.
type Sealer interface {
	Wrap(ctx context.Context, dataKey []byte, binding string) (Wrapped, error)
	Unwrap(ctx context.Context, wrapped Wrapped, binding string) ([]byte, error)
}

// Identity proves a workload to the service: it verifies a bearer token
// minted for one of the audiences and returns the subject it proves. It is
// the seam over the existing verifiers (ServiceAccount TokenReview, the
// federated clusters' key sets, AWS federation); a token that proves
// nothing is an error.
type Identity interface {
	Verify(ctx context.Context, token string, audiences []string) (subject string, err error)
}

// Set is every port, built once from configuration and passed down.
type Set struct {
	State    State
	Index    Index
	Blob     Blob
	Trigger  Trigger
	Sealer   Sealer
	Identity Identity
}
