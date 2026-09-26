package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// KeyRingConfig governs how a [KeyRing] adopts a rotated signing key.
type KeyRingConfig struct {
	// ActivationDelay is how long a newly observed key sits in the JWKS,
	// published but not yet used to sign, before this replica will sign
	// with it.
	//
	// It exists because rotation is not instantaneous across replicas. A
	// mounted Secret is updated by the kubelet on its own periodic sync —
	// Kubernetes documents that as roughly a minute, and two pods on two
	// nodes can be a sync or two apart — so a replica that signs with a
	// key the instant IT notices one can hand out a `kid` a slower
	// replica does not publish yet. A verifier that fetches the JWKS from
	// that slower replica then rejects a perfectly good token. Waiting
	// past the slowest realistic sync before ANY replica signs is what
	// keeps every replica able to verify what every other one mints.
	ActivationDelay time.Duration

	// Overlap is how long a key that stopped signing stays in the JWKS
	// after being superseded, once the schedule says so.
	//
	// It has to cover the longest a token minted with it can still be
	// presented — the deployment's access/ID token lifetime — because a
	// client's or a resource's `ttl_cap` only ever SHORTENS a token's
	// life, never lengthens it, so the deployment-wide lifetime is the
	// true ceiling on how long a token signed a moment before rotation
	// can still turn up asking to be verified.
	Overlap time.Duration
}

const (
	// DefaultKeyActivationDelay is used where a deployment names none.
	// Set with margin above the kubelet propagation window this type's
	// docs describe, plus the longest verifier cache that might reject
	// tokens signed with a newly activated key. Envoy's jwt_authn
	// RemoteJwks.cache_duration defaults to 10 minutes and does not
	// refetch on an unknown `kid`, so a key must be published for longer
	// than that cache plus Secret projection delay (~1–2 minutes) before
	// anything signs with it. Rotation happens rarely — a certificate's
	// `renewBefore` is measured in weeks — so the longer delay costs
	// nothing an operator would notice.
	DefaultKeyActivationDelay = 15 * time.Minute

	// KeyOverlapSkew is additional time a key stays published past a
	// token's lifetime to account for clock differences between the issuer
	// and verifiers. A verifier accepts tokens with an expiry leeway, and
	// clocks differ, so a key must stay published a bit longer than the
	// longest token it signed.
	KeyOverlapSkew = 5 * time.Minute

	// DefaultKeyOverlap is used where neither a deployment nor its own
	// token lifetime is known to the ring. A deployment should pass its
	// OWN lifetime instead (see [KeyRingConfig]) — a hardcoded default
	// cannot know a longer one was configured. It includes KeyOverlapSkew
	// to account for clock skew between the issuer and verifiers.
	DefaultKeyOverlap = DefaultTokenLifetime + KeyOverlapSkew

	// DefaultKeyPollInterval is how often a replica re-reads the mounted
	// key file. Kubernetes swaps a projected Secret's contents with an
	// atomic rename of the `..data` symlink, so reading the file's
	// content on an interval sees either the whole old key or the whole
	// new one, never a partial write — there is no torn read to guard
	// against, which is what makes polling sufficient and an inotify
	// watch unneeded complexity for a file that changes a handful of
	// times a year.
	DefaultKeyPollInterval = 30 * time.Second
)

func (c KeyRingConfig) withDefaults() KeyRingConfig {
	if c.ActivationDelay <= 0 {
		c.ActivationDelay = DefaultKeyActivationDelay
	}
	if c.Overlap <= 0 {
		c.Overlap = DefaultKeyOverlap
	}
	return c
}

// keyRingIndexKey lists every key id a KeyRing has ever recorded, so that
// a replica can learn of one it never read from its own file — see
// [KeyRing.absorb]. keyRingEntryKey holds one key's own record.
func keyRingIndexKey() string          { return "issuer:keyring:index" }
func keyRingEntryKey(id string) string { return "issuer:keyring:entry:" + id }

// keyRingEntryTTL bounds how long a record outlives every replica that
// knew of it. It is refreshed on every poll — [KeyRing.refresh] re-writes
// what this replica already knows, every ~30 seconds — so it is only ever
// reached when every replica sharing this store has been gone for that
// long, at which point there is nobody left signing tokens for it to
// matter to.
const keyRingEntryTTL = 30 * 24 * time.Hour

// ringEntry is one key this installation has published, at some point.
//
// ActivateAt is decided ONCE, by whichever replica first records the id
// (see [KeyRing.record]), and never recomputed: every replica that later
// learns of the same id — whether it read the key itself or only heard of
// it from the shared store — reads back the SAME value, so every replica
// starts signing with it at the same moment regardless of which one
// noticed the rotation first.
type ringEntry struct {
	ID         string                  `json:"id"`
	JWK        jose.JSONWebKey         `json:"jwk"`
	Algorithm  jose.SignatureAlgorithm `json:"alg"`
	SeenAt     time.Time               `json:"seenAt"`
	ActivateAt time.Time               `json:"activateAt"`

	// signer is set only where THIS replica holds the private half: the
	// key it read from its own mounted file. An entry learned of only
	// through the shared store carries none, and this replica can publish
	// it but can never sign with it.
	signer *SigningKey `json:"-"`
}

// KeyRing is every signing key this installation has published, live or
// retiring, and the one currently in use to sign.
//
// It is what makes rotation safe with no restart and more than one
// replica. Three things have to be true at once: a verifier must be able
// to check a token signed a moment ago even if it fetches the JWKS from a
// replica that has not signed with the new key yet (PUBLISH BEFORE SIGN —
// [KeyRingConfig.ActivationDelay]); a token signed the instant before
// rotation must still verify for as long as it is valid (OVERLAP —
// [KeyRingConfig.Overlap]); and a replica that restarts after every OTHER
// replica has moved on to a new key must not forget the previous one
// while tokens it signed can still be presented — which is why the
// schedule lives in the shared [State] and not only in memory.
//
// Every accessor recomputes which keys are active and published from
// [ringEntry.ActivateAt] and the clock at the moment it is called, rather
// than keeping a separately mutated "current" flag — the schedule is a
// pure function of what has been recorded and how much time has passed,
// which is what makes [KeyRing.Observe] idempotent and the whole type
// testable with an injected clock instead of real sleeps.
type KeyRing struct {
	mu    sync.Mutex
	state State
	log   *slog.Logger
	now   func() time.Time
	cfg   KeyRingConfig

	entries map[string]*ringEntry

	// activeID and published are the LAST computed answer, kept only so
	// that a transition (seen, activated, retired) is logged and counted
	// once, on the poll where it happens, rather than on every poll that
	// finds nothing new.
	activeID  string
	published map[string]bool

	metrics keyRingInstruments
}

// NewKeyRing returns a ring with nothing published yet. state is where
// the schedule is shared with every other replica; nil keeps it in this
// process alone, which is right for a single replica and a local run and
// wrong for more — the same trade [State] itself documents.
func NewKeyRing(state State, cfg KeyRingConfig, log *slog.Logger) *KeyRing {
	if state == nil {
		state = NewMemoryState()
	}
	if log == nil {
		log = slog.Default()
	}
	return &KeyRing{
		state:     state,
		log:       log,
		now:       time.Now,
		cfg:       cfg.withDefaults(),
		entries:   map[string]*ringEntry{},
		published: map[string]bool{},
		metrics:   newKeyRingInstruments(),
	}
}

// SetClock replaces the clock. For tests, matching [MemoryState.SetClock].
func (r *KeyRing) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

// Configure overrides the delays after construction, once a deployment's
// own settings — its token lifetime, chiefly — are known. Meant to be
// called once, before the ring serves any traffic: changing it while
// replicas are actively rotating is not a case this type defends against.
func (r *KeyRing) Configure(cfg KeyRingConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = cfg.withDefaults()
}

// Observe feeds the key this replica just read from its own file. It is
// the only place a new key enters the ring, and it is idempotent: called
// with the same key every ~30 seconds, which is the ordinary case, it
// re-derives the same schedule and does nothing new.
//
// State-store failures here are logged and never returned: a Valkey that
// is briefly unreachable must not stop this replica signing with the key
// it can already read from disk, nor block it starting in the first
// place. [KeyRing.refresh] retries the write on every later poll, so the
// shared record catches up once the store answers again.
func (r *KeyRing) Observe(ctx context.Context, key *SigningKey) error {
	if key == nil {
		return errors.New("issuer: no signing key to observe")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()

	if existing, known := r.entries[key.id]; known {
		// The same id: keep the private half fresh. [SigningKey] carries
		// no way to compare two instances for equality, and re-parsing
		// the file on every poll is cheaper than caching that comparison.
		existing.signer = key
	} else {
		r.entries[key.id] = r.record(ctx, now, key)
	}

	r.absorb(ctx)
	r.refresh(ctx)
	r.recompute(ctx, now)

	return nil
}

// record decides one new key's schedule and writes it to the shared
// store, first-writer-wins: whichever replica gets here first for a given
// id sets its SeenAt and ActivateAt, and every replica after it — this
// one on a later restart, or another replica entirely — reads the SAME
// values back rather than computing its own. That is what lets "wait
// until every replica has seen it" mean something: there is exactly one
// schedule, not one per replica's clock.
func (r *KeyRing) record(ctx context.Context, now time.Time, key *SigningKey) *ringEntry {
	// The very FIRST key this installation has ever published needs no
	// delay: there is no previous key signing anything for it to race
	// against, and no other replica to give time to catch up. Every key
	// after it does.
	var immediate bool
	if members, err := r.state.Members(ctx, keyRingIndexKey()); err != nil {
		r.log.WarnContext(ctx, "could not tell whether this is the installation's first signing key; "+
			"assuming it is only if this replica knows of none itself",
			"error", err)
		immediate = len(r.entries) == 0
	} else {
		immediate = len(members) == 0
	}

	activateAt := now
	if !immediate {
		activateAt = now.Add(r.cfg.ActivationDelay)
	}

	entry := &ringEntry{
		ID:         key.id,
		JWK:        jose.JSONWebKey{Key: key.key.Public(), KeyID: key.id, Algorithm: string(key.alg), Use: "sig"},
		Algorithm:  key.alg,
		SeenAt:     now,
		ActivateAt: activateAt,
	}

	encoded, err := json.Marshal(entry)
	if err != nil {
		// Cannot happen for a value built entirely of our own types with
		// no cycles; kept as a log rather than a panic because a signing
		// key is not worth crashing the process over a defect elsewhere.
		r.log.ErrorContext(ctx, "could not encode a signing key for the shared store", "kid", key.id, "error", err)
	} else if won, err := r.state.SetIfAbsent(ctx, keyRingEntryKey(key.id), encoded, keyRingEntryTTL); err != nil {
		r.log.WarnContext(ctx, "could not record the signing key in the shared store; "+
			"this replica keeps its own schedule for it and will retry", "kid", key.id, "error", err)
	} else if !won {
		// Another replica — or an earlier run of this one — already
		// recorded this id. ITS schedule is canonical.
		if stored, err := getJSON[ringEntry](ctx, r.state, keyRingEntryKey(key.id)); err != nil {
			r.log.WarnContext(ctx, "could not read the recorded schedule for a signing key another "+
				"replica already published; keeping this replica's own guess", "kid", key.id, "error", err)
		} else if stored != nil {
			entry = stored
		}
	}

	if err := r.state.Add(ctx, keyRingIndexKey(), key.id, keyRingEntryTTL); err != nil {
		r.log.WarnContext(ctx, "could not index a signing key in the shared store", "kid", key.id, "error", err)
	}

	entry.signer = key

	r.log.InfoContext(ctx, "a signing key was seen",
		"kid", key.id, "algorithm", string(key.alg),
		"seenAt", entry.SeenAt, "activateAt", entry.ActivateAt, "immediate", entry.ActivateAt.Equal(entry.SeenAt))
	r.metrics.recordTransition(ctx, "seen", string(key.alg))

	return entry
}

// absorb learns of every key id the shared store knows that this
// replica's own file read never told it about. It is how a restarted
// replica does not forget a key another replica is still publishing —
// requirement four of live rotation — and how every replica converges on
// the SAME published set rather than each publishing only what it has
// personally read off disk.
//
// An absorbed entry carries no private key: this replica can publish it
// in its own JWKS, but [KeyRing.Active] will never choose it to sign
// with, because this replica cannot.
func (r *KeyRing) absorb(ctx context.Context) {
	ids, err := r.state.Members(ctx, keyRingIndexKey())
	if err != nil {
		r.log.WarnContext(ctx, "could not read what other replicas have published; "+
			"this replica's own view of the key ring is unaffected", "error", err)
		return
	}

	for _, id := range ids {
		if _, known := r.entries[id]; known {
			continue
		}

		stored, err := getJSON[ringEntry](ctx, r.state, keyRingEntryKey(id))
		if err != nil {
			r.log.WarnContext(ctx, "could not read a signing key another replica indexed", "kid", id, "error", err)
			continue
		}
		if stored == nil {
			// Indexed, but its own record already expired or was removed
			// — cleaning the index entry is next poll's job (see
			// [KeyRing.recompute]), not an error this one raises.
			continue
		}

		r.entries[id] = stored
		r.log.InfoContext(ctx, "a signing key published by another replica was seen",
			"kid", id, "algorithm", string(stored.Algorithm),
			"seenAt", stored.SeenAt, "activateAt", stored.ActivateAt)
		r.metrics.recordTransition(ctx, "seen", string(stored.Algorithm))
	}
}

// refresh re-writes every key this replica currently knows about, local
// or absorbed, so that [keyRingEntryTTL] never lapses while at least one
// replica is still polling. It is deliberately not limited to entries
// this replica itself created: responsibility for keeping a record alive
// is shared by every replica that knows of it, not pinned to whichever
// one happened to write it first.
func (r *KeyRing) refresh(ctx context.Context) {
	for id, entry := range r.entries {
		encoded, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		if err := r.state.Set(ctx, keyRingEntryKey(id), encoded, keyRingEntryTTL); err != nil {
			r.log.WarnContext(ctx, "could not refresh a published signing key's record", "kid", id, "error", err)
		}
		if err := r.state.Add(ctx, keyRingIndexKey(), id, keyRingEntryTTL); err != nil {
			r.log.WarnContext(ctx, "could not refresh the signing key index", "kid", id, "error", err)
		}
	}
}

// recompute derives which keys are published and which one is active,
// purely from `now` and every entry's own ActivateAt — see the type doc.
// It logs and counts each transition exactly once, prunes a key once it
// retires, and never lets the active key be one of them.
func (r *KeyRing) recompute(ctx context.Context, now time.Time) {
	all := make([]*ringEntry, 0, len(r.entries))
	for _, e := range r.entries {
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ActivateAt.Before(all[j].ActivateAt) })

	var activated []*ringEntry
	published := map[string]bool{}
	retired := map[string]bool{}

	for _, e := range all {
		if e.ActivateAt.After(now) {
			// Not active yet, but published from the moment it was seen —
			// publish before sign is what lets every replica already show
			// it before any of them signs with it.
			published[e.ID] = true
			continue
		}
		activated = append(activated, e)
	}

	var activeID string
	if len(activated) > 0 {
		activeID = activated[len(activated)-1].ID
		for i, e := range activated {
			if i == len(activated)-1 {
				// The active key. Never retired, whatever the clock says.
				published[e.ID] = true
				continue
			}
			retireAt := activated[i+1].ActivateAt.Add(r.cfg.Overlap)
			if now.After(retireAt) {
				retired[e.ID] = true
				continue
			}
			published[e.ID] = true
		}
	}

	if activeID != "" && activeID != r.activeID {
		if e, ok := r.entries[activeID]; ok {
			r.log.InfoContext(ctx, "the active signing key changed",
				"kid", activeID, "algorithm", string(e.Algorithm), "previous", r.activeID)
			r.metrics.recordTransition(ctx, "activated", string(e.Algorithm))
		}
	}

	for id, e := range r.entries {
		if !retired[id] {
			continue
		}
		r.log.InfoContext(ctx, "a signing key retired", "kid", id, "algorithm", string(e.Algorithm))
		r.metrics.recordTransition(ctx, "retired", string(e.Algorithm))
		delete(r.entries, id)
		// Best-effort: leaving the record would only cost a little space
		// in the shared store until keyRingEntryTTL, and a failure here
		// must not stop this replica computing its own schedule.
		_ = r.state.Delete(ctx, keyRingEntryKey(id))
		_ = r.state.Remove(ctx, keyRingIndexKey(), id)
	}

	r.activeID = activeID
	r.published = published
	r.metrics.recordPublished(ctx, int64(len(published)))
}

// Active is the key this replica currently signs with.
//
// It falls back to the newest key this replica CAN sign with — one it has
// read from its own file — when the schedule's chosen key is one this
// replica has only heard of from another replica and has not read for
// itself yet. That is the guarantee in requirement six: never sign with a
// key this replica has not itself published. It is an anomaly, not the
// ordinary path, logged when it happens; the ordinary path is that a
// replica reads the same file every other replica does and reaches the
// scheduled key at the same activation time they do.
//
// nil only before the very first [KeyRing.Observe], which every
// constructor of a [Storage] calls before returning.
func (r *KeyRing) Active() *SigningKey {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.entries[r.activeID]; ok && entry.signer != nil {
		return entry.signer
	}

	var best *ringEntry
	for _, e := range r.entries {
		if e.signer == nil {
			continue
		}
		if best == nil || e.ActivateAt.After(best.ActivateAt) {
			best = e
		}
	}
	if best == nil {
		return nil
	}
	if best.ID != r.activeID {
		r.log.Warn("signing with a key that is not yet the schedule's active one: "+
			"this replica has not read the active key's private half from its own file yet",
			"kid", best.ID, "scheduled", r.activeID)
	}
	return best.signer
}

// Published is every key currently in the JWKS: the active one, every key
// waiting out its activation delay, and every retiring one still inside
// its overlap.
func (r *KeyRing) Published() []op.Key {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]op.Key, 0, len(r.published))
	for id := range r.published {
		e, ok := r.entries[id]
		if !ok {
			continue
		}
		out = append(out, publishedKey{id: e.ID, alg: e.Algorithm, pub: e.JWK.Key})
	}
	return out
}

// Algorithms is every algorithm among the currently published keys, for
// discovery's `id_token_signing_alg_values_supported` — see
// [Storage.SignatureAlgorithms] and [signingAlgorithms] for why the
// issuer's OWN verifiers use a different, static list instead.
func (r *KeyRing) Algorithms() []jose.SignatureAlgorithm {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := map[jose.SignatureAlgorithm]bool{}
	var out []jose.SignatureAlgorithm
	for id := range r.published {
		e, ok := r.entries[id]
		if !ok || seen[e.Algorithm] {
			continue
		}
		seen[e.Algorithm] = true
		out = append(out, e.Algorithm)
	}
	return out
}

// KeyRingStatus is a snapshot for a health detail or a debug log: the key
// currently signing and how many are published. There is no metrics
// library in this service beyond the OpenTelemetry counters and gauges in
// [keyRingInstruments], which carry no free-text, so a key id belongs in
// a log line or here, never in a metric label.
type KeyRingStatus struct {
	ActiveKeyID    string
	PublishedCount int
}

// Status reports the ring's current answer.
func (r *KeyRing) Status() KeyRingStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return KeyRingStatus{ActiveKeyID: r.activeID, PublishedCount: len(r.published)}
}
