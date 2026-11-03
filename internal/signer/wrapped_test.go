package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/internal/port/memory"
	"github.com/truvity/sluis/internal/rails"
	"github.com/truvity/sluis/storage/keys"
	"github.com/truvity/sluis/storage/keys/local"
)

// spyKeys is a key backend that counts what the wrapped ring asks of it, over
// the local backend (which refuses a wrong context, as KMS does).
type spyKeys struct {
	keys.Backend
	mu sync.Mutex
	// Generated and Decrypted count the calls that succeeded.
	Generated, Decrypted int
	// DenyDecrypt and DenyGenerate make the calls fail.
	DenyDecrypt, DenyGenerate bool
	// Contexts are the encryption contexts of every encrypt call, in order.
	Contexts []map[string]string
	// Plaintexts are every private key ever wrapped (PKCS#8 DER).
	Plaintexts [][]byte
}

func (s *spyKeys) Encrypt(ctx context.Context, key string, pt []byte, ec map[string]string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.DenyGenerate {
		return nil, errors.New("not authorized to encrypt")
	}
	out, err := s.Backend.Encrypt(ctx, key, pt, ec)
	if err == nil {
		s.Generated++
		s.Contexts = append(s.Contexts, ec)
		s.Plaintexts = append(s.Plaintexts, append([]byte(nil), pt...))
	}
	return out, err
}

func (s *spyKeys) Decrypt(ctx context.Context, key string, ct []byte, ec map[string]string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.DenyDecrypt {
		return nil, errors.New("not authorized to decrypt")
	}
	out, err := s.Backend.Decrypt(ctx, key, ct, ec)
	if err == nil {
		s.Decrypted++
	}
	return out, err
}

const testInstance = "acme"

// openSign opens `keys.sign` over backend with the given context.
func openSign(t *testing.T, backend keys.Backend, ctx keys.ContextSpec) *keys.Key {
	t.Helper()
	set, err := keys.Open(keys.Config{Adapter: "local", Keys: map[keys.Purpose]keys.Entry{
		keys.Sign: {Key: "sluis-sign", Context: ctx}}}, keys.Options{Backend: backend, Instance: testInstance})
	if err != nil {
		t.Fatal(err)
	}
	k, err := set.For(keys.Sign)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newSpy(t *testing.T) *spyKeys {
	t.Helper()
	b, err := local.New(local.RandomRoot())
	if err != nil {
		t.Fatal(err)
	}
	return &spyKeys{Backend: b}
}

const (
	testRotate     = 24 * time.Hour
	testPrepublish = DefaultWrappedPrepublish
	testRetain     = time.Hour + KeyOverlapSkew
)

// The rings are built on the real clock (NewKeyRings takes none) and then moved
// to the test clock, so the test clock starts at the real time.
var wrapT0 = time.Now().UTC().Truncate(time.Second)

type wrapClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *wrapClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *wrapClock) set(t time.Time)         { c.mu.Lock(); defer c.mu.Unlock(); c.t = t }
func (c *wrapClock) advance(d time.Duration) { c.set(c.now().Add(d)) }

// replica is one process: its own KeyRings and WrappedSigning over the shared
// state, KMS and lease store.
type replica struct {
	ws    *WrappedSigning
	rings *KeyRings
}

type wrapEnv struct {
	kms    *spyKeys
	key    *keys.Key
	state  *memState
	leases *memory.Store
	clock  *wrapClock
	algs   []jose.SignatureAlgorithm
	deny   bool // the lease is always held by someone else
	// retain replaces testRetain when set.
	retain time.Duration
	// failWrites makes the shared state refuse the key ring's entry writes.
	failWrites bool
}

// flakyState is the shared state with writes of key ring entries that can fail.
type flakyState struct {
	*memState
	env *wrapEnv
}

func (f flakyState) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if f.env.failWrites && strings.HasPrefix(key, "issuer:keyring:entry:") {
		return false, errors.New("state unavailable")
	}
	return f.memState.SetIfAbsent(ctx, key, value, ttl)
}

func (e *wrapEnv) shared() State { return flakyState{memState: e.state, env: e} }

func newWrapEnv(t *testing.T, algs ...jose.SignatureAlgorithm) *wrapEnv {
	t.Helper()
	if len(algs) == 0 {
		algs = []jose.SignatureAlgorithm{jose.ES384}
	}
	clock := &wrapClock{t: wrapT0}
	state := newMemState()
	state.SetClock(clock.now)
	spy := newSpy(t)
	return &wrapEnv{kms: spy, key: openSign(t, spy, keys.ContextSpec{}), state: state, leases: memory.New(), clock: clock, algs: algs}
}

func (e *wrapEnv) config() WrappedConfig {
	retain := testRetain
	if e.retain > 0 {
		retain = e.retain
	}
	return WrappedConfig{
		Algorithms:  e.algs,
		RotateEvery: testRotate, Prepublish: testPrepublish, Retain: retain, Interval: 30 * time.Second,
	}
}

func (e *wrapEnv) start(t *testing.T) *replica {
	t.Helper()
	leases := &rails.Leases{State: e.leases, Holder: rails.NewHolder()}
	lease := func(ctx context.Context, alg jose.SignatureAlgorithm, fn func(context.Context) error) (bool, error) {
		if e.deny {
			return false, nil
		}
		var inner error
		ran, err := leases.Do(ctx, "signing-keygen", string(alg), func(c context.Context) { inner = fn(c) })
		if err != nil {
			return false, err
		}
		return ran, inner
	}
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	ws, err := NewWrappedSigning(e.config(), e.key, seed, lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	ws.SetClock(e.clock.now)
	primary, more, err := ws.Bootstrap(context.Background(), e.shared())
	if err != nil {
		t.Fatal(err)
	}
	rings, err := NewKeyRings(primary, more, e.shared(), ws.ringConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rings.rings {
		r.SetClock(e.clock.now)
	}
	rings.UseWrapped(ws)
	return &replica{ws: ws, rings: rings}
}

func (r *replica) maintain() { r.rings.Maintain(context.Background()) }

func (r *replica) published(alg jose.SignatureAlgorithm) []string {
	var out []string
	for _, k := range r.rings.rings[alg].Published() {
		out = append(out, k.KID)
	}
	return out
}

func contains(ids []string, id string) bool {
	for _, i := range ids {
		if i == id {
			return true
		}
	}
	return false
}

// signAndVerify signs with the ring's active key and verifies the token with
// the PUBLISHED key of its kid, as a relying party does.
func signAndVerify(t *testing.T, r *replica, alg jose.SignatureAlgorithm) string {
	t.Helper()
	active := r.rings.Active(alg)
	if active == nil {
		t.Fatalf("%s: no active key", alg)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: active.Key()},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", active.ID()))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte(`{"sub":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	token, _ := jws.CompactSerialize()
	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{alg})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Signatures[0].Header.KeyID; got != active.ID() {
		t.Fatalf("kid %q, want %q", got, active.ID())
	}
	for _, k := range r.rings.Published() {
		if k.KID == active.ID() {
			if _, err := parsed.Verify(k.Key); err != nil {
				t.Fatalf("%s token does not verify with the published key: %v", alg, err)
			}
			return active.ID()
		}
	}
	t.Fatalf("%s: the active key %s is not published", alg, active.ID())
	return ""
}

func TestWrappedFirstStartGeneratesActiveKeysForEveryAlgorithm(t *testing.T) {
	env := newWrapEnv(t, jose.ES384, jose.RS256)
	r := env.start(t)
	if env.kms.Generated != 2 {
		t.Fatalf("generated %d key pairs, want one per algorithm", env.kms.Generated)
	}
	if got := r.rings.Default(); got != jose.ES384 {
		t.Errorf("default %s", got)
	}
	for _, alg := range env.algs {
		signAndVerify(t, r, alg)
		if n := len(r.published(alg)); n != 1 {
			t.Errorf("%s: %d keys published", alg, n)
		}
	}
	// New entries are wrapped under the sign key's default context, and
	// record it.
	for _, c := range env.kms.Contexts {
		if len(c) != 2 || c[keys.ContextPurpose] != "sign" || c[keys.ContextInstance] != testInstance {
			t.Errorf("encryption context %v", c)
		}
	}
	for _, e := range r.rings.rings[jose.ES384].entries {
		if e.WrapContext == nil || (*e.WrapContext)[keys.ContextPurpose] != "sign" {
			t.Errorf("entry %s records no context: %v", e.ID, e.WrapContext)
		}
	}
	// The JWKS carries public keys only, of the right shape.
	for _, k := range r.rings.Published() {
		if _, ok := k.Key.(interface{ Public() any }); ok {
			t.Errorf("%s publishes a private key", k.KID)
		}
	}
}

func TestWrappedNoPlaintextPrivateKeyIsStored(t *testing.T) {
	env := newWrapEnv(t, jose.ES384, jose.RS256)
	r := env.start(t)
	// Rotate once, so entries of two generations exist.
	env.clock.advance(testRotate)
	r.maintain()
	if env.kms.Generated != 4 {
		t.Fatalf("generated %d", env.kms.Generated)
	}
	env.state.mu.Lock()
	defer env.state.mu.Unlock()
	checked := 0
	for key, v := range env.state.values {
		for _, plain := range env.kms.Plaintexts {
			// The key is DER; the state holds JSON, so base64 is how it would appear.
			for _, needle := range [][]byte{plain, []byte(base64.StdEncoding.EncodeToString(plain)),
				[]byte(base64.RawURLEncoding.EncodeToString(plain)), plain[len(plain)-40:]} {
				if bytes.Contains(v.data, needle) {
					t.Fatalf("%s holds plaintext private key material", key)
				}
			}
		}
		if strings.Contains(string(v.data), "PRIVATE KEY") {
			t.Fatalf("%s holds a PEM private key", key)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("the state holds nothing: the check proves nothing")
	}
}

func TestWrappedRotationFollowsTheSchedule(t *testing.T) {
	env := newWrapEnv(t, jose.ES384, jose.RS256)
	r := env.start(t)
	first := map[jose.SignatureAlgorithm]string{}
	for _, alg := range env.algs {
		first[alg] = signAndVerify(t, r, alg)
	}

	// Before rotateEvery: nothing new, however often it runs.
	env.clock.advance(testRotate - time.Minute)
	r.maintain()
	if env.kms.Generated != 2 {
		t.Fatalf("a key was generated early: %d", env.kms.Generated)
	}

	// At rotateEvery: a new key per algorithm, published at once, not yet signing.
	env.clock.advance(time.Minute)
	r.maintain()
	if env.kms.Generated != 4 {
		t.Fatalf("generated %d, want 4 after one period", env.kms.Generated)
	}
	for _, alg := range env.algs {
		if n := len(r.published(alg)); n != 2 {
			t.Fatalf("%s: %d keys published, want the old and the new", alg, n)
		}
		if got := r.rings.Active(alg).ID(); got != first[alg] {
			t.Errorf("%s: signs with %s before the pre-publish ended", alg, got)
		}
	}

	// Just short of the pre-publish: still the old key.
	env.clock.advance(testPrepublish - time.Minute)
	r.maintain()
	for _, alg := range env.algs {
		if got := r.rings.Active(alg).ID(); got != first[alg] {
			t.Errorf("%s: switched %s early", alg, got)
		}
	}
	// After it: the new key signs, and the old one is still published.
	env.clock.advance(time.Minute)
	r.maintain()
	second := map[jose.SignatureAlgorithm]string{}
	for _, alg := range env.algs {
		second[alg] = signAndVerify(t, r, alg)
		if second[alg] == first[alg] {
			t.Errorf("%s: still signing with the first key", alg)
		}
		if !contains(r.published(alg), first[alg]) {
			t.Errorf("%s: the replaced key left the JWKS at once", alg)
		}
	}

	// The replaced key is kept for the retention, then dropped.
	env.clock.advance(testRetain - time.Minute)
	r.maintain()
	for _, alg := range env.algs {
		if !contains(r.published(alg), first[alg]) {
			t.Errorf("%s: dropped before the retention ended", alg)
		}
	}
	env.clock.advance(2 * time.Minute)
	r.maintain()
	for _, alg := range env.algs {
		if contains(r.published(alg), first[alg]) {
			t.Errorf("%s: still published after the retention", alg)
		}
		if !contains(r.published(alg), second[alg]) {
			t.Errorf("%s: the signing key vanished", alg)
		}
	}
}

func TestWrappedAnotherReplicaLearnsAndUnwrapsTheRotatedKey(t *testing.T) {
	env := newWrapEnv(t, jose.ES384)
	a := env.start(t)
	b := env.start(t)
	first := signAndVerify(t, b, jose.ES384)
	if env.kms.Generated != 1 {
		t.Fatalf("two cold starts generated %d keys", env.kms.Generated)
	}

	env.clock.advance(testRotate)
	a.maintain() // A generates
	b.maintain() // B learns; nothing to generate
	if env.kms.Generated != 2 {
		t.Fatalf("generated %d, want 2", env.kms.Generated)
	}
	if n := len(b.published(jose.ES384)); n != 2 {
		t.Fatalf("B publishes %d keys, want the new one too", n)
	}
	decrypts := env.kms.Decrypted
	env.clock.advance(testPrepublish)
	b.maintain()
	got := signAndVerify(t, b, jose.ES384)
	if got == first {
		t.Fatal("B did not move to the rotated key")
	}
	if env.kms.Decrypted != decrypts+1 {
		t.Errorf("B unwrapped the key with %d calls, want 1", env.kms.Decrypted-decrypts)
	}
	_ = a
}

func TestWrappedALostLeaseRaceIsHarmless(t *testing.T) {
	env := newWrapEnv(t, jose.ES384)
	a, b := env.start(t), env.start(t)
	env.clock.advance(testRotate)

	// Both are due at once, and run together: the lease serialises them and the
	// loser re-reads before it generates.
	var wg sync.WaitGroup
	for _, r := range []*replica{a, b, a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); r.maintain() }()
	}
	wg.Wait()
	if env.kms.Generated > 3 {
		t.Fatalf("generated %d keys for one rotation", env.kms.Generated)
	}
	// Whatever interleaving: both replicas converge on one signing key that
	// verifies, and the old one is still published.
	env.clock.advance(testPrepublish + time.Minute)
	a.maintain()
	b.maintain()
	ida, idb := signAndVerify(t, a, jose.ES384), signAndVerify(t, b, jose.ES384)
	if ida != idb {
		t.Errorf("the replicas sign with different keys: %s and %s", ida, idb)
	}

	// A lease another runner holds: nothing is generated, and signing goes on.
	env2 := newWrapEnv(t, jose.ES384)
	r := env2.start(t)
	env2.deny = true
	env2.clock.advance(testRotate + time.Hour)
	r.maintain()
	if env2.kms.Generated != 1 {
		t.Errorf("generated without the lease: %d", env2.kms.Generated)
	}
	signAndVerify(t, r, jose.ES384)
}

func TestWrappedRefusesAContextMismatch(t *testing.T) {
	env := newWrapEnv(t, jose.ES384)
	r := env.start(t)
	ring := r.rings.rings[jose.ES384]
	var e *ringEntry
	for _, x := range ring.entries {
		e = x
	}
	if _, err := r.ws.unwrap(context.Background(), jose.ES384, e.ID, e.JWK.Key, e.Wrapped, e.WrapContext); err != nil {
		t.Fatalf("the recorded context: %v", err)
	}
	other := map[string]string{keys.ContextInstance: "another", keys.ContextPurpose: "sign"}
	none := map[string]string{}
	for name, try := range map[string]func() error{
		"another instance's context": func() error {
			_, err := r.ws.unwrap(context.Background(), jose.ES384, e.ID, e.JWK.Key, e.Wrapped, &other)
			return err
		},
		"no context": func() error {
			_, err := r.ws.unwrap(context.Background(), jose.ES384, e.ID, e.JWK.Key, e.Wrapped, &none)
			return err
		},
		"the old context, for an entry made under the new": func() error {
			_, err := r.ws.unwrap(context.Background(), jose.ES384, e.ID, e.JWK.Key, e.Wrapped, nil)
			return err
		},
		"a blob nothing made": func() error {
			_, err := r.ws.unwrap(context.Background(), jose.ES384, e.ID, e.JWK.Key, []byte("not a ciphertext"), e.WrapContext)
			return err
		},
	} {
		if err := try(); err == nil {
			t.Errorf("%s: unwrapped", name)
		}
	}

	// A blob from another key service does not open here, whatever the entry
	// says about it.
	foreign := newWrapEnv(t, jose.ES384)
	ws2, err := NewWrappedSigning(foreign.config(), foreign.key, make([]byte, 32), noLease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws2.unwrap(context.Background(), jose.ES384, e.ID, e.JWK.Key, e.Wrapped, e.WrapContext); err == nil {
		t.Error("a blob from another key service unwrapped")
	}
}

// legacyEntry records a ring entry the way the release before contexts were
// recorded did: wrapped under {purpose: sluis-signing, alg, kid}, with no
// context in the record.
func legacyEntry(t *testing.T, env *wrapEnv, alg jose.SignatureAlgorithm) *SigningKey {
	t.Helper()
	kid, err := newKid()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := newPair(alg)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(pair)
	if err != nil {
		t.Fatal(err)
	}
	old := openSign(t, env.kms, keys.ContextSpec{Mode: keys.ContextMap, Map: EncryptionContext(alg, kid)})
	blob, err := old.Encrypt(context.Background(), der)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := NewWrappedSigning(env.config(), env.key, make([]byte, 32), noLease, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ws.unwrap(context.Background(), alg, kid, pair.Public(), blob, nil)
	if err != nil {
		t.Fatalf("the old entry does not open with its old context: %v", err)
	}
	key.activateNow = true
	ring := NewKeyRing(alg, env.state, KeyRingConfig{ActivationDelay: testPrepublish, Overlap: testRetain}, nil)
	ring.SetClock(env.clock.now)
	if err := ring.Observe(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestWrappedRingWithOldAndNewEntriesSignsAndVerifies(t *testing.T) {
	env := newWrapEnv(t, jose.ES384, jose.RS256)
	olds := map[jose.SignatureAlgorithm]*SigningKey{}
	for _, alg := range env.algs {
		olds[alg] = legacyEntry(t, env, alg)
	}
	env.clock.advance(time.Minute)
	env.kms.Generated = 0 // the setup's own encrypts

	// A restart on a state that holds only old entries signs with them, with no
	// re-wrap: nothing new is encrypted.
	r := env.start(t)
	if env.kms.Generated != 0 {
		t.Fatalf("the old entries were replaced or re-wrapped: %d encrypts", env.kms.Generated)
	}
	for _, alg := range env.algs {
		if got := signAndVerify(t, r, alg); got != olds[alg].ID() {
			t.Errorf("%s: signs with %s, not the old entry %s", alg, got, olds[alg].ID())
		}
	}

	// The next rotation wraps under the sign key's own context and records it;
	// the old entry stays published and keeps its (absent) record.
	env.clock.advance(testRotate)
	r.maintain()
	env.clock.advance(testPrepublish + time.Minute)
	r.maintain()
	for _, alg := range env.algs {
		got := signAndVerify(t, r, alg)
		if got == olds[alg].ID() {
			t.Fatalf("%s: still signing with the old entry after a rotation", alg)
		}
		if !contains(r.published(alg), olds[alg].ID()) {
			t.Errorf("%s: the old entry left the JWKS at once", alg)
		}
		var fresh, old *ringEntry
		for _, e := range r.rings.rings[alg].entries {
			if e.ID == got {
				fresh = e
			}
			if e.ID == olds[alg].ID() {
				old = e
			}
		}
		if fresh == nil || fresh.WrapContext == nil || (*fresh.WrapContext)[keys.ContextPurpose] != "sign" {
			t.Errorf("%s: the new entry records no context", alg)
		}
		if old == nil || old.WrapContext != nil {
			t.Errorf("%s: the old entry's record changed", alg)
		}
		// Another replica starting now opens both generations: the active
		// (new) one, and the old one by its legacy context.
		if _, err := r.ws.unwrap(context.Background(), alg, old.ID, old.JWK.Key, old.Wrapped, old.WrapContext); err != nil {
			t.Errorf("%s: the old entry no longer opens: %v", alg, err)
		}
	}
	if b := env.start(t); b == nil {
		t.Fatal("a replica could not start on a ring of old and new entries")
	} else {
		for _, alg := range env.algs {
			signAndVerify(t, b, alg)
		}
	}
}

func TestWrappedUnwrapRefusesAPublicKeyThatIsNotItsPair(t *testing.T) {
	env := newWrapEnv(t, jose.ES384)
	r := env.start(t)
	stranger := newWrapEnv(t, jose.ES384).start(t)
	var mine, theirs *ringEntry
	for _, x := range r.rings.rings[jose.ES384].entries {
		mine = x
	}
	for _, x := range stranger.rings.rings[jose.ES384].entries {
		theirs = x
	}
	if _, err := r.ws.unwrap(context.Background(), jose.ES384, mine.ID, theirs.JWK.Key, mine.Wrapped, mine.WrapContext); err == nil ||
		!strings.Contains(err.Error(), "not the pair") {
		t.Errorf("a published key that is not the pair: %v", err)
	}
}

func TestWrappedMissingPermissionsAreNamed(t *testing.T) {
	env := newWrapEnv(t, jose.ES384)
	env.kms.DenyGenerate = true
	ws, _ := NewWrappedSigning(env.config(), env.key, make([]byte, 32), alwaysLease, nil)
	_, _, err := ws.Bootstrap(context.Background(), env.state)
	if err == nil || !strings.Contains(err.Error(), "encrypt with keys.sign") {
		t.Errorf("a denied generate: %v", err)
	}

	env = newWrapEnv(t, jose.ES384)
	env.start(t)
	env.kms.DenyDecrypt = true
	ws, _ = NewWrappedSigning(env.config(), env.key, make([]byte, 32), alwaysLease, nil)
	_, _, err = ws.Bootstrap(context.Background(), env.state)
	if err == nil || !strings.Contains(err.Error(), "decrypt with keys.sign") {
		t.Errorf("a denied decrypt must stop the start, not mint a second key: %v", err)
	}
	if env.kms.Generated != 1 {
		t.Errorf("a second key was generated: %d", env.kms.Generated)
	}
}

func TestWrappedCoexistsWithKeysOfOtherSources(t *testing.T) {
	env := newWrapEnv(t, jose.ES384)
	// A key another source recorded: public half only, long active, no private
	// key this process can use (a file or KMS key of the previous deployment).
	foreign, err := NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	old := NewKeyRing(jose.ES384, env.state, KeyRingConfig{ActivationDelay: testPrepublish, Overlap: testRetain}, nil)
	old.SetClock(env.clock.now)
	if err := old.Observe(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	env.clock.advance(time.Hour)

	r := env.start(t)
	// The foreign key cannot sign here, so the wrapped key is active at once
	// (waiting behind a key nobody can sign with would leave no signer), and
	// the foreign key stays in the JWKS for tokens it already signed.
	id := signAndVerify(t, r, jose.ES384)
	if id == foreign.ID() {
		t.Fatal("signed with a key it holds no private half of")
	}
	if !contains(r.published(jose.ES384), foreign.ID()) {
		t.Error("the other source's key left the JWKS")
	}
	// It retires on the normal schedule.
	env.clock.advance(testRetain + time.Minute)
	r.maintain()
	if contains(r.published(jose.ES384), foreign.ID()) {
		t.Error("the other source's key was never retired")
	}
}

// Unset, the pre-publish is half the rotation, so a key is in the key set for
// half a day before it signs, and never shorter than the activation delay.
func TestWrappedPrepublishDefaultsToHalfTheRotation(t *testing.T) {
	if DefaultWrappedPrepublish != 12*time.Hour {
		t.Errorf("DefaultWrappedPrepublish = %s, want 12h", DefaultWrappedPrepublish)
	}
	for _, tc := range []struct{ rotate, floor, want time.Duration }{
		{24 * time.Hour, DefaultKeyActivationDelay, 12 * time.Hour},
		{MaxWrappedRotateEvery, DefaultKeyActivationDelay, 84 * time.Hour},
		{time.Hour, DefaultKeyActivationDelay, 30 * time.Minute},
		{20 * time.Minute, DefaultKeyActivationDelay, DefaultKeyActivationDelay},
		{24 * time.Hour, 13 * time.Hour, 13 * time.Hour},
	} {
		got := WrappedPrepublishDefault(tc.rotate, tc.floor)
		if got != tc.want {
			t.Errorf("WrappedPrepublishDefault(%s, %s) = %s, want %s", tc.rotate, tc.floor, got, tc.want)
		}
		c := WrappedConfig{Algorithms: []jose.SignatureAlgorithm{jose.ES384}, RotateEvery: tc.rotate, Prepublish: got, Retain: testRetain}
		if err := c.Validate(DefaultTokenLifetime); err != nil {
			t.Errorf("rotateEvery %s with the default pre-publish %s: %v", tc.rotate, got, err)
		}
	}
}

// Over days of daily rotation with the default schedule, every key is in the
// key set for the whole pre-publish before it signs, a replaced key stays for
// the whole retention, and the key set holds at most two keys per algorithm
// (three while the retention is longer than the other half of the period).
func TestWrappedKeySetOverManyRotations(t *testing.T) {
	const step = 10 * time.Minute
	for _, tc := range []struct {
		retain time.Duration
		most   int
	}{
		{testRetain, 2},
		{25 * time.Hour, 3},
	} {
		t.Run(tc.retain.String(), func(t *testing.T) {
			env := newWrapEnv(t, jose.ES384)
			env.retain = tc.retain
			r := env.start(t)
			firstSeen := map[string]time.Time{}
			replacedAt := map[string]time.Time{}
			active := r.rings.Active(jose.ES384).ID()
			most := 0
			for elapsed := time.Duration(0); elapsed <= 5*testRotate; elapsed += step {
				r.maintain()
				now := env.clock.now()
				published := r.published(jose.ES384)
				most = max(most, len(published))
				for _, id := range published {
					if _, ok := firstSeen[id]; !ok {
						firstSeen[id] = now
					}
				}
				for id, at := range replacedAt {
					if !contains(published, id) {
						if gone := now.Sub(at); gone < tc.retain {
							t.Errorf("%s left the key set %s after it was replaced, within the retention", id, gone)
						}
						delete(replacedAt, id)
					}
				}
				if id := r.rings.Active(jose.ES384).ID(); id != active {
					if ahead := now.Sub(firstSeen[id]); ahead < testPrepublish {
						t.Errorf("%s signs %s after it was published, under the pre-publish", id, ahead)
					}
					replacedAt[active] = now
					active = id
				}
				env.clock.advance(step)
			}
			if most != tc.most {
				t.Errorf("at most %d keys published at once, want %d", most, tc.most)
			}
			if env.kms.Generated < 5 {
				t.Errorf("generated %d keys in five periods", env.kms.Generated)
			}
		})
	}
}

func TestWrappedConfigValidation(t *testing.T) {
	ok := WrappedConfig{Algorithms: []jose.SignatureAlgorithm{jose.ES384, jose.RS256},
		RotateEvery: testRotate, Prepublish: testPrepublish, Retain: testRetain}
	if err := ok.Validate(DefaultTokenLifetime); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*WrappedConfig)
		want   string
	}{
		"no algorithms":      {func(c *WrappedConfig) { c.Algorithms = nil }, "at least one"},
		"EdDSA":              {func(c *WrappedConfig) { c.Algorithms = []jose.SignatureAlgorithm{jose.EdDSA} }, "EdDSA is not supported"},
		"ES256":              {func(c *WrappedConfig) { c.Algorithms = []jose.SignatureAlgorithm{jose.ES256} }, "not supported"},
		"twice":              {func(c *WrappedConfig) { c.Algorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS256} }, "twice"},
		"retain too short":   {func(c *WrappedConfig) { c.Retain = DefaultTokenLifetime }, "retain"},
		"rotate<=prepublish": {func(c *WrappedConfig) { c.RotateEvery = testPrepublish }, "longer than prepublish"},
		"rotate too long":    {func(c *WrappedConfig) { c.RotateEvery = 30 * 24 * time.Hour }, "at most"},
		"zero":               {func(c *WrappedConfig) { c.Prepublish = 0 }, "positive"},
	} {
		c := ok
		tc.mutate(&c)
		if err := c.Validate(DefaultTokenLifetime); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if err := (WrappedConfig{}).Validate(0); err == nil {
		t.Error("an empty configuration is valid")
	}
}

func noLease(context.Context, jose.SignatureAlgorithm, func(context.Context) error) (bool, error) {
	return false, nil
}

func alwaysLease(ctx context.Context, _ jose.SignatureAlgorithm, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

// A key whose record cannot be written is discarded, not used: it would sign
// tokens no other replica publishes a key for.
func TestWrappedAKeyThatCannotBeRecordedIsNotUsed(t *testing.T) {
	env := newWrapEnv(t, jose.ES384)
	env.failWrites = true
	ws, _ := NewWrappedSigning(env.config(), env.key, make([]byte, 32), alwaysLease, nil)
	if _, _, err := ws.Bootstrap(context.Background(), env.shared()); err == nil || !strings.Contains(err.Error(), "record the signing key") {
		t.Fatalf("a first key that could not be recorded: %v", err)
	}

	env = newWrapEnv(t, jose.ES384)
	r := env.start(t)
	first := signAndVerify(t, r, jose.ES384)
	env.failWrites = true
	env.clock.advance(testRotate)
	r.maintain()
	if n := len(r.published(jose.ES384)); n != 1 {
		t.Errorf("an unrecorded key is published: %d keys", n)
	}
	env.clock.advance(testPrepublish + time.Minute)
	r.maintain()
	if got := signAndVerify(t, r, jose.ES384); got != first {
		t.Errorf("signing with %s, a key that was never recorded", got)
	}
	// Once the state answers again the next pass rotates.
	env.failWrites = false
	env.clock.advance(time.Minute)
	r.maintain()
	if n := len(r.published(jose.ES384)); n != 2 {
		t.Errorf("rotation did not resume: %d keys", n)
	}
}

type lines struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lines) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *lines) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// Rotation that keeps failing is an error in the log once the active key is far
// older than the rotation period, and not before.
func TestWrappedAStuckRotationIsLoggedAsAnError(t *testing.T) {
	var out lines
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
	defer slog.SetDefault(prev)

	env := newWrapEnv(t, jose.ES384)
	r := env.start(t)
	env.deny = true // the lease is never obtained: rotation cannot happen
	env.clock.advance(time.Duration(1.4 * float64(testRotate)))
	r.maintain()
	if strings.Contains(out.String(), "far older") {
		t.Fatal("logged before the key is 1.5 rotation periods old")
	}
	env.clock.advance(time.Duration(0.2 * float64(testRotate)))
	r.maintain()
	if got := out.String(); !strings.Contains(got, "level=ERROR") || !strings.Contains(got, "far older") {
		t.Fatalf("no error for a stuck rotation: %s", got)
	}
	signAndVerify(t, r, jose.ES384) // it keeps signing
}
