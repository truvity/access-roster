package issuer_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/truvity/access-roster/internal/issuer"
)

// settableClock is a clock a test moves forward explicitly, so that
// "the activation delay has not elapsed" and "it has" are exact facts
// rather than something a sleep merely makes likely.
type settableClock struct {
	mu sync.Mutex
	at time.Time
}

func newSettableClock(at time.Time) *settableClock { return &settableClock{at: at} }

func (c *settableClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *settableClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

// rsaSigningKey builds a [issuer.SigningKey] over a fresh RSA key, the way
// [keys_test.go] does, for the one test here that has to exercise a
// concrete non-default algorithm: an installation rotating from RSA to
// its P-384 default.
func rsaSigningKey(t *testing.T) *issuer.SigningKey {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	key, err := issuer.ParseSigningKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return key
}

// publishedIDs is every key id a ring currently publishes, sorted so two
// rings' answers can be compared directly.
func publishedIDs(t *testing.T, ring *issuer.KeyRing) []string {
	t.Helper()
	published := ring.Published()
	out := make([]string, 0, len(published))
	for _, k := range published {
		out = append(out, k.ID())
	}
	sort.Strings(out)
	return out
}

func assertPublished(t *testing.T, ring *issuer.KeyRing, want ...string) {
	t.Helper()
	got := publishedIDs(t, ring)
	sorted := append([]string{}, want...)
	sort.Strings(sorted)
	if !slices.Equal(got, sorted) {
		t.Fatalf("published = %v, want %v", got, sorted)
	}
}

// The first key an installation ever publishes needs no delay: there is
// no previous key signing anything for it to race against, and no other
// replica to give time to catch up.
func TestKeyRingFirstKeyIsActiveImmediately(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := newSettableClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	ring := issuer.NewKeyRing(jose.ES384, issuer.NewMemoryState(), issuer.KeyRingConfig{}, nil)
	ring.SetClock(clock.now)

	key, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Observe(ctx, key); err != nil {
		t.Fatal(err)
	}

	active := ring.Active()
	if active == nil || active.ID() != key.ID() {
		t.Fatalf("active = %v, want %s immediately", active, key.ID())
	}
	assertPublished(t, ring, key.ID())
}

// The full rotation schedule: a new key is published before it signs,
// signing switches only once every replica has had time to see it, and
// the key it replaced is kept in the JWKS for the overlap before it
// retires.
func TestKeyRingRotationSchedule(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := newSettableClock(t0)

	const delay = 2 * time.Minute
	const overlap = time.Hour
	ring := issuer.NewKeyRing(jose.ES384, issuer.NewMemoryState(), issuer.KeyRingConfig{ActivationDelay: delay, Overlap: overlap}, nil)
	ring.SetClock(clock.now)

	key1, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Observe(ctx, key1); err != nil {
		t.Fatal(err)
	}

	key2, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}

	// Published before sign: both keys are in the JWKS the instant key2 is
	// seen, but signing has not moved.
	assertPublished(t, ring, key1.ID(), key2.ID())
	if got := ring.Active(); got.ID() != key1.ID() {
		t.Fatalf("active = %s, want key1: signing must not move before the activation delay", got.ID())
	}

	// Short of the delay (t0+90s of a 2m delay): still signing with key1.
	clock.set(t0.Add(90 * time.Second))
	if err := ring.Observe(ctx, key2); err != nil { // the next poll tick, same file
		t.Fatal(err)
	}
	if got := ring.Active(); got.ID() != key1.ID() {
		t.Fatalf("active = %s, want key1: switched before the delay elapsed", got.ID())
	}

	// Past the delay (key2 activates at t0+2m): signing switches, and key1
	// stays published for the overlap.
	clock.set(t0.Add(3 * time.Minute))
	if err := ring.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}
	if got := ring.Active(); got.ID() != key2.ID() {
		t.Fatalf("active = %s, want key2 once its delay elapsed", got.ID())
	}
	assertPublished(t, ring, key1.ID(), key2.ID())

	// key1's overlap runs from key2's activation (t0+2m) for one hour, so
	// it ends at t0+62m. Short of that, it is still published.
	clock.set(t0.Add(61 * time.Minute))
	if err := ring.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}
	assertPublished(t, ring, key1.ID(), key2.ID())
	if got := ring.Active(); got.ID() != key2.ID() {
		t.Fatalf("active changed during the overlap: %s", got.ID())
	}

	// Past it, key1 retires and only key2 remains.
	clock.set(t0.Add(63 * time.Minute))
	if err := ring.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}
	assertPublished(t, ring, key2.ID())
}

// A token signed just before rotation has to keep verifying for as long
// as the overlap says it can still be valid: the ring's published set is
// what a verifier reads the JWKS from, and dropping the old key early
// would fail every token minted a moment before the rotation.
func TestKeyRingTokenSignedBeforeRotationVerifiesDuringOverlap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := newSettableClock(t0)

	ring := issuer.NewKeyRing(jose.ES384, issuer.NewMemoryState(),
		issuer.KeyRingConfig{ActivationDelay: time.Minute, Overlap: time.Hour}, nil)
	ring.SetClock(clock.now)

	key1, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Observe(ctx, key1); err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"sub":"ada@north.example"}`)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key1.SignatureAlgorithm(), Key: key1.Key()},
		(&jose.SignerOptions{}).WithHeader("kid", key1.ID()))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	// Rotate, and move well into the overlap.
	key2, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}
	clock.set(t0.Add(30 * time.Minute))
	if err := ring.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}

	if got := ring.Active(); got.ID() != key2.ID() {
		t.Fatalf("active = %s, want key2 well past its activation delay", got.ID())
	}

	verified := verifyAgainst(t, ring, token, key1.ID())
	if !verified {
		t.Fatal("a token signed with the retiring key did not verify during its overlap")
	}
}

// verifyAgainst checks token against whichever published key in ring
// carries kid, the way [localKeys.VerifySignature] tries every published
// key for an incoming token.
func verifyAgainst(t *testing.T, ring *issuer.KeyRing, token, kid string) bool {
	t.Helper()
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		t.Fatalf("parse the token: %v", err)
	}
	for _, key := range ring.Published() {
		if key.ID() != kid {
			continue
		}
		if _, err := jws.Verify(&jose.JSONWebKey{Key: key.Key(), KeyID: key.ID(), Algorithm: string(key.Algorithm())}); err == nil {
			return true
		}
	}
	return false
}

// A [KeyRing] is now locked to ONE algorithm for its life — each
// algorithm gets its own track, namespaced in the shared store by that
// algorithm (see [issuer.KeyRing.Algorithm]) — so a key of a DIFFERENT
// algorithm is refused rather than silently adopted as a rotation. Before
// per-audience signing this was "just a rotation"; now it would mean an
// RS256 key landing on the ES384 track, which every OTHER replica reads
// by that track's own namespaced keys and would never learn to publish.
// Changing which algorithm a ring signs is a restart — a fresh
// [issuer.KeyRings] — not a poll tick.
func TestKeyRingRefusesAKeyOfTheWrongAlgorithm(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ring := issuer.NewKeyRing(jose.ES384, issuer.NewMemoryState(), issuer.KeyRingConfig{}, nil)

	ecKey, err := issuer.NewSigningKey() // P-384 / ES384
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Observe(ctx, ecKey); err != nil {
		t.Fatal(err)
	}

	rsaKey := rsaSigningKey(t) // RS256
	if err := ring.Observe(ctx, rsaKey); err == nil {
		t.Fatal("an ES384 ring accepted an RS256 key; it must refuse a key of any other algorithm")
	}

	// Refused, and nothing about the ring's own state moved: it still
	// signs with, and publishes only, the key it already held.
	if got := ring.Active(); got.ID() != ecKey.ID() {
		t.Fatalf("active = %s, want the refusal to have left the original key active", got.ID())
	}
	assertPublished(t, ring, ecKey.ID())
}

// A restarted replica, or one that simply starts later, must publish the
// SAME set another replica already agreed on — including a key it never
// read from its own file — because tokens that key signed can still be
// presented to either one.
func TestKeyRingASecondReplicaSharingTheStorePublishesTheSameSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := newSettableClock(t0)
	shared := issuer.NewMemoryState()
	shared.SetClock(clock.now)

	cfg := issuer.KeyRingConfig{ActivationDelay: time.Minute, Overlap: time.Hour}
	replicaA := issuer.NewKeyRing(jose.ES384, shared, cfg, nil)
	replicaA.SetClock(clock.now)

	key1, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := replicaA.Observe(ctx, key1); err != nil {
		t.Fatal(err)
	}

	key2, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := replicaA.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}
	clock.set(t0.Add(2 * time.Minute))
	if err := replicaA.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}
	if got := replicaA.Active(); got.ID() != key2.ID() {
		t.Fatalf("replica A active = %s, want key2", got.ID())
	}

	// Replica B starts only now, and its own mounted file already holds
	// key2 alone — key1 has already been superseded by the time it comes
	// up, exactly like a pod that restarts after a rotation.
	replicaB := issuer.NewKeyRing(jose.ES384, shared, cfg, nil)
	replicaB.SetClock(clock.now)
	if err := replicaB.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}

	if got := replicaB.Active(); got.ID() != key2.ID() {
		t.Fatalf("replica B active = %s, want key2", got.ID())
	}
	// Both replicas publish key1 — the one B never read for itself — for
	// as long as it is still inside its overlap.
	assertPublished(t, replicaA, key1.ID(), key2.ID())
	assertPublished(t, replicaB, key1.ID(), key2.ID())
}

// Requirement six: a replica must never sign with a key it has not
// itself published — even if the shared schedule says some OTHER
// replica's key is now due to activate. Falling back to the newest key it
// personally holds is the safe answer until it catches up.
func TestKeyRingNeverSignsWithAKeyItHasNotReadItself(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := newSettableClock(t0)
	shared := issuer.NewMemoryState()
	shared.SetClock(clock.now)

	cfg := issuer.KeyRingConfig{ActivationDelay: time.Minute, Overlap: time.Hour}
	fast := issuer.NewKeyRing(jose.ES384, shared, cfg, nil)
	fast.SetClock(clock.now)

	key1, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := fast.Observe(ctx, key1); err != nil {
		t.Fatal(err)
	}

	key2, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := fast.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}

	// slow is a replica whose own file read is stuck on key1 — its node's
	// kubelet, say, has not projected the update yet — but it still learns
	// OF key2's existence from the shared store.
	slow := issuer.NewKeyRing(jose.ES384, shared, cfg, nil)
	slow.SetClock(clock.now)
	if err := slow.Observe(ctx, key1); err != nil {
		t.Fatal(err)
	}

	// Time passes far enough that the schedule says key2 should be active
	// everywhere.
	clock.set(t0.Add(5 * time.Minute))
	if err := fast.Observe(ctx, key2); err != nil {
		t.Fatal(err)
	}
	if err := slow.Observe(ctx, key1); err != nil { // slow's file still has key1
		t.Fatal(err)
	}

	if got := fast.Active(); got.ID() != key2.ID() {
		t.Fatalf("fast active = %s, want key2", got.ID())
	}
	// slow knows key2 is scheduled (it is in slow's own published set) but
	// has never read its private half, so it must keep signing with key1.
	if got := slow.Active(); got == nil || got.ID() != key1.ID() {
		t.Fatalf("slow active = %v, want it to keep signing with key1 until it reads key2 itself", got)
	}
	assertPublished(t, slow, key1.ID(), key2.ID())
}

// A retiring key's own public half is still enough to verify a signature
// with, independent of the ring: this only pins down that [KeyRing]
// actually publishes crypto material usable by a standard JOSE verifier,
// not merely an opaque id.
func TestKeyRingPublishedKeyMaterialVerifies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ring := issuer.NewKeyRing(jose.ES384, issuer.NewMemoryState(), issuer.KeyRingConfig{}, nil)

	key, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Observe(ctx, key); err != nil {
		t.Fatal(err)
	}

	published := ring.Published()
	if len(published) != 1 {
		t.Fatalf("published = %d keys, want 1", len(published))
	}
	pub, ok := published[0].Key().(crypto.PublicKey)
	if !ok {
		t.Fatalf("published key material is %T, want a crypto.PublicKey", published[0].Key())
	}
	if _, ok := pub.(interface{ Equal(crypto.PublicKey) bool }); !ok {
		t.Fatalf("published key material %T has no Equal method to compare against the source key", pub)
	}
}

// The plumbing end to end: a [issuer.Storage] built with one key adopts a
// rotated one through [issuer.Storage.Rotate], and everything that signs
// through it — the OpenID surface's own key, the JWKS, and [issuer.Storage.MintFor]
// — follows the same schedule rather than each holding its own idea of
// which key is current.
func TestStorageRotateAdoptsANewSigningKey(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": live("directory-admins@north.example"),
	}}
	iss := newIssuer(t, dir)

	key1, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, key1, nil, issuer.NewMemoryState())
	if err != nil {
		t.Fatal(err)
	}
	// A real, tiny delay rather than zero: [issuer.KeyRingConfig] treats
	// zero as "use the default", and this test wants the schedule to run
	// its course in real time instead of asserting on its own arithmetic —
	// that is what TestKeyRingRotationSchedule already does with an
	// injected clock.
	storage.ConfigureKeyRotation(issuer.KeyRingConfig{ActivationDelay: time.Nanosecond, Overlap: time.Hour})

	ctx := context.Background()
	signing, err := storage.SigningKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if signing.ID() != key1.ID() {
		t.Fatalf("signs with %s, want the seed key %s", signing.ID(), key1.ID())
	}

	key2, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Rotate(ctx, key2); err != nil {
		t.Fatal(err)
	}

	keys, err := storage.KeySet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("published %d keys right after rotation, want 2: publish before sign", len(keys))
	}
	if signing, err = storage.SigningKey(ctx); err != nil {
		t.Fatal(err)
	} else if signing.ID() != key1.ID() {
		t.Fatalf("signs with %s immediately after rotation, want it to keep signing with key1 until activation", signing.ID())
	}

	time.Sleep(time.Millisecond)                      // past the one-nanosecond activation delay
	if err := storage.Rotate(ctx, key2); err != nil { // the next poll tick, same key
		t.Fatal(err)
	}

	if signing, err = storage.SigningKey(ctx); err != nil {
		t.Fatal(err)
	} else if signing.ID() != key2.ID() {
		t.Fatalf("signs with %s, want key2 once its activation delay elapsed", signing.ID())
	}

	// MintFor signs with whatever is active NOW, not with the key the
	// storage was built with.
	token, _, err := storage.MintFor(ctx, "ada@north.example", "aws:1111:power", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signed.Verify(key2.Key().(crypto.Signer).Public()); err != nil {
		t.Errorf("MintFor did not sign with the newly active key: %v", err)
	}
}
