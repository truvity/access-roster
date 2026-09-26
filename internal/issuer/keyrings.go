package issuer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// KeyRings is every algorithm this installation signs with at once, each
// on its own [KeyRing] and its own rotation schedule.
//
// It is what lets [Storage.SigningKey] answer "sign THIS token" by the
// audience's chosen algorithm rather than by whatever one key happens to
// be active installation-wide: RS256 for a relying party that lags (EKS,
// Kargo — see docs/decisions/0009-a-default-signing-algorithm-and-per-audience-exceptions.md),
// ES384 for everything else, at the same time, from the same process,
// with rotating one never touching another's schedule — because each
// lives in its own [KeyRing], namespaced in the shared store by its own
// algorithm (see [keyRingIndexKey]).
//
// Built once, from the keys a deployment was given, and never grown or
// shrunk afterward: which algorithms exist is a fact about the Secrets
// this installation was handed, decided where policy and keys meet (see
// [NewStorage]), not something a running process can be told mid-flight —
// a replica that never mounted a file for a new algorithm could not
// publish its key even if told to expect one.
type KeyRings struct {
	rings   map[jose.SignatureAlgorithm]*KeyRing
	primary jose.SignatureAlgorithm
}

// NewKeyRings builds one KeyRing per algorithm among primary and
// additional, sharing state and cfg.
//
// primary decides the installation's DEFAULT algorithm: what a client or
// a resource that names no `signing_alg` of its own is signed with (see
// [Client.SigningAlg]) — exactly the algorithm of today's one key, when
// there is only one, which is what keeps every existing deployment's
// tokens signed exactly as before this existed.
//
// Two keys naming the same algorithm is refused: [KeyRings.Active] can
// return only one key per algorithm, so a second one would be a key this
// installation minted and never published — the [charts/access-issuer]
// values render the same refusal at the chart layer, but a value coming
// from anywhere else (a test, a future caller) gets the same guarantee
// here.
func NewKeyRings(primary *SigningKey, additional []*SigningKey, state State, cfg KeyRingConfig, log *slog.Logger) (*KeyRings, error) {
	if primary == nil {
		return nil, errors.New("issuer: no primary signing key")
	}
	if log == nil {
		log = slog.Default()
	}

	out := &KeyRings{rings: map[jose.SignatureAlgorithm]*KeyRing{}, primary: primary.SignatureAlgorithm()}

	for _, key := range append([]*SigningKey{primary}, additional...) {
		if key == nil {
			continue
		}
		alg := key.SignatureAlgorithm()
		if _, clash := out.rings[alg]; clash {
			return nil, fmt.Errorf(
				"issuer: two signing keys both sign %s; each configured algorithm needs exactly one key", alg)
		}
		ring := NewKeyRing(alg, state, cfg, log)
		if err := ring.Observe(context.Background(), key); err != nil {
			return nil, fmt.Errorf("issuer: adopt the %s signing key: %w", alg, err)
		}
		out.rings[alg] = ring
	}

	return out, nil
}

// Default is the installation's own algorithm: what a client or a
// resource that names no `signing_alg` is signed with.
func (k *KeyRings) Default() jose.SignatureAlgorithm { return k.primary }

// Has reports whether a key is configured for alg. It is what
// [NewStorage] uses to refuse, loudly and at start, a policy naming an
// algorithm nothing here can ever sign with — never a silent fall back to
// the default, which would mean an operator's `signing_alg: RS256` quietly
// producing ES384 tokens because the RS256 Secret was never mounted.
func (k *KeyRings) Has(alg jose.SignatureAlgorithm) bool {
	_, ok := k.rings[alg]
	return ok
}

// Configured is every algorithm a key exists for, sorted — for a startup
// log line and for the refusal message when a policy names one that is
// not among them.
func (k *KeyRings) Configured() []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, 0, len(k.rings))
	for alg := range k.rings {
		out = append(out, alg)
	}
	slices.Sort(out)
	return out
}

// Active is the key currently signing for one algorithm, or nil when none
// is configured for it.
//
// nil here is not the refusal a caller might expect: that refusal
// belongs at issuer START (see [NewStorage] and requirement 2), against
// the POLICY that named the algorithm, where an operator can read why.
// By the time a request reaches this method the policy has already been
// checked against exactly these rings, so nil here means the request
// asked for something the ring itself has never held — [Storage.SigningKey]
// falls back to [KeyRings.Default] rather than fail a token over it.
func (k *KeyRings) Active(alg jose.SignatureAlgorithm) *SigningKey {
	ring, ok := k.rings[alg]
	if !ok {
		return nil
	}
	return ring.Active()
}

// Rotate feeds a freshly re-read key to the ring for ITS OWN algorithm —
// one file, one algorithm, one track (requirement six of live rotation).
//
// An algorithm nothing was configured for at start is refused: a
// deployment that starts polling a file for an algorithm [NewStorage] was
// never told about has changed its signing shape without a restart, which
// is exactly the moment every replica must NOT quietly start publishing a
// key some of them do not expect and cannot verify against yet.
func (k *KeyRings) Rotate(ctx context.Context, key *SigningKey) error {
	alg := key.SignatureAlgorithm()
	ring, ok := k.rings[alg]
	if !ok {
		return fmt.Errorf("issuer: no key ring is configured for %s; adding an algorithm needs a restart", alg)
	}
	return ring.Observe(ctx, key)
}

// Configure applies the same activation delay and overlap to every ring:
// one schedule shape, decided once a deployment's own token lifetime is
// known, applied per algorithm exactly as [KeyRing.Configure] applies it
// to one.
func (k *KeyRings) Configure(cfg KeyRingConfig) {
	for _, ring := range k.rings {
		ring.Configure(cfg)
	}
}

// Published is every key published by every ring. The JWKS is their
// union: a relying party fetches ONE key set and has to find whichever
// algorithm its own token carries in it, whether that token came from the
// RS256 ring or the ES384 one.
func (k *KeyRings) Published() []op.Key {
	var out []op.Key
	for _, ring := range k.rings {
		out = append(out, ring.Published()...)
	}
	return out
}

// Algorithms is every algorithm with at least one currently PUBLISHED
// key, sorted — discovery's `id_token_signing_alg_values_supported`, the
// union across rings rather than one ring's own view. See
// [KeyRing.Algorithms] for why this stays dynamic while the issuer's own
// verifiers do not.
func (k *KeyRings) Algorithms() []jose.SignatureAlgorithm {
	seen := map[jose.SignatureAlgorithm]bool{}
	var out []jose.SignatureAlgorithm
	for _, ring := range k.rings {
		for _, alg := range ring.Algorithms() {
			if !seen[alg] {
				seen[alg] = true
				out = append(out, alg)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Status is every ring's own status, keyed by algorithm, for a health
// detail or a debug log.
func (k *KeyRings) Status() map[jose.SignatureAlgorithm]KeyRingStatus {
	out := make(map[jose.SignatureAlgorithm]KeyRingStatus, len(k.rings))
	for alg, ring := range k.rings {
		out[alg] = ring.Status()
	}
	return out
}
