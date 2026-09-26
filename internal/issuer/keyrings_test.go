package issuer_test

import (
	"context"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/truvity/access-roster/internal/issuer"
)

// The installation default is the PRIMARY key's own algorithm -- today's
// single key, unchanged -- and stays that even once other algorithms are
// configured beside it.
func TestKeyRingsDefaultIsThePrimaryAlgorithm(t *testing.T) {
	t.Parallel()

	primary, err := issuer.NewSigningKey() // P-384 / ES384
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := rsaSigningKey(t) // RS256

	rings, err := issuer.NewKeyRings(primary, []*issuer.SigningKey{rsaKey}, issuer.NewMemoryState(), issuer.KeyRingConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := rings.Default(); got != jose.ES384 {
		t.Errorf("default = %s, want ES384, the primary key's own algorithm", got)
	}
	if !rings.Has(jose.ES384) || !rings.Has(jose.RS256) {
		t.Errorf("configured = %v, want both ES384 and RS256", rings.Configured())
	}
	if rings.Has(jose.ES256) {
		t.Error("a ring reported configured for ES256, which was never given a key")
	}
}

// Two keys naming the same algorithm is refused: [KeyRings.Active] can
// answer for only one per algorithm, so a second key of the same kind
// would be one this installation minted and could never publish.
func TestKeyRingsRefusesTwoKeysOfTheSameAlgorithm(t *testing.T) {
	t.Parallel()

	primary, err := issuer.NewSigningKey() // ES384
	if err != nil {
		t.Fatal(err)
	}
	second, err := issuer.NewSigningKey() // also ES384
	if err != nil {
		t.Fatal(err)
	}

	if _, err := issuer.NewKeyRings(primary, []*issuer.SigningKey{second},
		issuer.NewMemoryState(), issuer.KeyRingConfig{}, nil); err == nil {
		t.Fatal("two ES384 keys were both accepted; each algorithm needs exactly one")
	}
}

// The central property of requirement 1: rotating ONE algorithm's key
// must never touch another's schedule. Advancing the ES384 key through
// its whole rotation -- published, activated, the old one retired -- must
// leave the RS256 ring exactly as it was found, because a relying party
// pinned to RS256 (EKS, Kargo) has no reason to expect its key to ever
// change on this installation's own schedule for a DIFFERENT algorithm.
func TestKeyRingsRotatingOneAlgorithmLeavesAnotherUntouched(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	esKey1, err := issuer.NewSigningKey() // ES384
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := rsaSigningKey(t) // RS256, the one key this installation will ever have for it

	rings, err := issuer.NewKeyRings(esKey1, []*issuer.SigningKey{rsaKey}, issuer.NewMemoryState(),
		issuer.KeyRingConfig{ActivationDelay: time.Minute, Overlap: time.Hour}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := rings.Active(jose.RS256); got == nil || got.ID() != rsaKey.ID() {
		t.Fatalf("RS256 active = %v, want %s before any ES384 rotation", got, rsaKey.ID())
	}

	// Rotate ES384 through a full cycle: a second key seen, then adopted.
	esKey2, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := rings.Rotate(ctx, esKey2); err != nil {
		t.Fatal(err)
	}
	if err := rings.Rotate(ctx, rsaKey); err != nil { // the RS256 poller's own, unrelated tick
		t.Fatal(err)
	}

	if got := rings.Active(jose.ES384); got == nil || got.ID() != esKey1.ID() {
		t.Fatalf("ES384 active = %v, want it to keep signing with the first key before activation", got)
	}

	// RS256 must not have moved at all: same active key, same one
	// published key, entirely unaware ES384 rotated.
	if got := rings.Active(jose.RS256); got == nil || got.ID() != rsaKey.ID() {
		t.Fatalf("RS256 active = %v, want %s untouched by the ES384 rotation", got, rsaKey.ID())
	}
	published := rings.Published()
	rs256Count, es384Count := 0, 0
	for _, key := range published {
		switch key.Algorithm() {
		case jose.RS256:
			rs256Count++
		case jose.ES384:
			es384Count++
		}
	}
	if rs256Count != 1 {
		t.Errorf("RS256 keys published = %d, want exactly 1 (the ES384 rotation must not have published a second)", rs256Count)
	}
	if es384Count != 2 {
		t.Errorf("ES384 keys published = %d, want 2 (published before sign, mid-rotation)", es384Count)
	}
}

// Rotate refuses an algorithm nothing was configured for at start: adding
// one is a restart (a fresh [issuer.KeyRings]), never a poll tick, because
// every OTHER replica shares no track for it to land on.
func TestKeyRingsRotateRefusesAnUnconfiguredAlgorithm(t *testing.T) {
	t.Parallel()

	primary, err := issuer.NewSigningKey() // ES384 only
	if err != nil {
		t.Fatal(err)
	}
	rings, err := issuer.NewKeyRings(primary, nil, issuer.NewMemoryState(), issuer.KeyRingConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey := rsaSigningKey(t)
	if err := rings.Rotate(context.Background(), rsaKey); err == nil {
		t.Fatal("rotating in an RS256 key with no RS256 ring configured was accepted")
	}
	if got := rings.Active(jose.RS256); got != nil {
		t.Errorf("RS256 active = %v, want nil: nothing was ever configured for it", got)
	}
}
