// Package driver is the YubiKey PIV key driver of key@: the key-store port, sluis.port.keystore.v2alpha1, served
// over the keys of a board's card (ADR 0006 "The slot plan", "Touch and PIN", "Exclusive card access"; ADR 0012, the
// R4 exception; ADR 0013, packaging).
//
// The card holds the keys and they never leave it. The driver holds the card exclusively, from start to stop. It
// starts locked: it has no PIN, so a key that needs one is refused with the reason "locked" until an administrator
// delivers the PIN on the local admin socket (admin.go). A wrong PIN is tried once and never retried.
//
// The driver is private to its owner, key. It has no audit emitter: key@ audits what it asks for.
package driver

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/pinrelease"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
	"github.com/truvity/sluis/v2/kits/go/slotplan"
)

// Name is the registry name of the driver's user; its owner is key.
const Name = "driver-key-yubikey-piv"

// StoreName is what Capabilities says the store is.
const StoreName = slotplan.CardStore

// The environments of an installation. The flag is required: nothing defaults to development.
const (
	Development = "development"
	Staging     = "staging"
	Production  = "production"
)

// Floor checks the environment. It returns a usage error for a value that is not an environment. Unlike the software
// driver, this one runs in every environment: what differs is that only development makes a key with the factory
// management key (Ensure); a staging or production card is provisioned by its owners' ceremony.
func Floor(environment string) error {
	switch environment {
	case Development, Staging, Production:
		return nil
	default:
		return cli.Usage(errors.New("--environment must be development, staging or production"))
	}
}

// Owner returns the actor that owns the driver: key. The driver's socket serves nobody else.
func Owner() string {
	owner, _ := registry.DriverOwner(Name)
	return owner
}

// Options are what the driver needs besides the server configuration.
type Options struct {
	Environment string
	// Node is the node whose card this is; the admin socket reports it so that an unlock for another node is caught.
	// The PIN release names it too: the driver writes it into its own request and seals to no request of its own.
	Node string
	// Boundary is the boundary of the node, which the PIN release names; Run takes it from the server configuration.
	Boundary string
	// Publishers are the publisher keys of the bootstrap file, the same pinned anchor key@ verifies the KeyPlan with.
	// The driver verifies the KeyPlan of a PIN release with them itself (keyplan.go). None refuses every PIN release.
	Publishers []signedconfig.Publisher
	// StateDir is the driver's own durable state: the highest KeyPlan seq it verified (keyplan.mark), so that a
	// restart does not take an older KeyPlan. Empty keeps the mark in memory only (the check command).
	StateDir string
	// Serial binds the driver to one card. Outside development it is required: without it any genuine YubiKey whose
	// attestations match the slot map would be adopted. In development, 0 means the only card.
	Serial uint32
	// Open opens the card; card.Open when nil. Tests pass a fake.
	Open card.Opener
	// ManagementKey is what Ensure generates keys with in development; the factory default when nil.
	ManagementKey []byte
	// RSAQueue is how many RSA signatures the driver admits at once, the one on the card and those waiting for it; the default is
	// rsaQueueDefault when 0. The rest are refused as busy at once. Another call (ES384, ECDH, a checkpoint, a PIN release) can
	// wait for all that are admitted, so for this many times 0.17 s at most; it is not queued ahead of them.
	RSAQueue int
}

// rsaQueueDefault is the default of Options.RSAQueue: the burst of key@'s bucket for the RS256 purpose on a card (cardRSABurst in
// actors/key/internal/keyd/rsalimit.go), so that a burst that key@ lets through is signed one after the other and not refused:
// the last of four waits about 4 x 0.17 s (measured, firmware 5.8). A call of another key that comes meanwhile can wait as long.
const rsaQueueDefault = 4

// slotKey is the key of one purpose after its attestation was verified.
type slotKey struct {
	entry
	pub    *ecdsa.PublicKey // the EC key of the slot; nil for the RSA key
	rsaPub *rsa.PublicKey   // the RSA key of the slot; nil for an EC key
	spki   []byte
}

// Service implements the key-store port over a card.
type Service struct {
	keystorev2alpha1connect.UnimplementedKeyStoreServiceHandler

	env     string
	node    string
	mgmtKey []byte

	// The KeyPlan check of the PIN release (keyplan.go).
	boundary   string
	publishers []signedconfig.Publisher
	plan       planState
	// refused is set when the card refused a released PIN: the driver then tries no released PIN until a person
	// unlocks it on the admin socket (refused.go). The caller holds mu.
	refused refusedMark

	mu      sync.Mutex // one conversation with the card at a time
	card    card.Card
	serial  uint32
	attCert *x509.Certificate
	keys    map[string]*slotKey

	// The journal lines of the busy refusals (busy).
	busyMu   sync.Mutex
	busyLast time.Time
	busyHeld int

	// rsaTickets admits the RSA signatures (signRS256): a send takes a place, a receive gives it back.
	rsaTickets chan struct{}

	pin pinMemory
	// oneTime is the one-time key of this driver's PIN release request in flight, if any (pinrelease.go).
	oneTime *oneTime

	dead     chan struct{} // closed when the card is gone, or a stop cannot be saved: the driver must exit
	deadOnce sync.Once
	deadWhy  error // why the driver exits, set before dead is closed
}

// New opens the card, checks its firmware, and verifies the attestation of every key it already holds. It
// returns a *Problems error when the card or one of its keys is refused. The caller closes the service.
func New(opts Options) (*Service, error) {
	if err := Floor(opts.Environment); err != nil {
		return nil, err
	}
	if opts.Environment != Development && opts.Serial == 0 {
		return nil, cli.Usage(errors.New("--serial is required outside development: the driver is bound to one card"))
	}
	open := opts.Open
	if open == nil {
		open = card.Open
	}
	c, err := open(opts.Serial)
	if err != nil {
		return nil, err
	}
	queue := opts.RSAQueue
	if queue <= 0 {
		queue = rsaQueueDefault
	}
	s := &Service{env: opts.Environment, node: opts.Node, mgmtKey: opts.ManagementKey, card: c, keys: map[string]*slotKey{}, dead: make(chan struct{}),
		rsaTickets: make(chan struct{}, queue),
		boundary:   opts.Boundary, publishers: opts.Publishers, plan: planState{dir: opts.StateDir}, refused: refusedMark{dir: opts.StateDir}}
	if err := s.refused.restore(); err != nil {
		_ = c.Close()
		return nil, err
	}
	if err := s.plan.restore(); err != nil {
		_ = c.Close()
		return nil, err
	}
	if s.mgmtKey == nil {
		s.mgmtKey = card.DefaultManagementKey
	}
	if err := s.start(opts.Serial); err != nil {
		_ = c.Close()
		return nil, err
	}
	return s, nil
}

// Problems is a card or a key that the driver refuses. Each problem is a path and a word, never a value.
type Problems struct{ List []string }

func (p *Problems) Error() string { return "card refused: " + fmt.Sprint(p.List) }

// freshSession puts the card in a known state: logged out. An earlier driver that ended without a reset (a restart that
// did not restart pcscd, a crash, a kill) leaves the card PIN-verified, and the card then answers to anything that reaches
// its reader while this driver says it is locked. The session is reset (SCARD_RESET_CARD: no key, no PIN and no counter
// changes), and the PIN counter is read to prove it: a card that is still verified, or that cannot be reset because
// another process holds it, is refused (fail closed).
func (s *Service) freshSession() error {
	// Ask before the reset whether the card is logged in, for the journal: an empty VERIFY, which sends no PIN and costs no attempt.
	was := s.loginState()
	if err := s.card.ResetSession(); err != nil {
		word := "reset_failed"
		if errors.Is(err, card.ErrSharing) {
			word = "held_elsewhere"
		}
		slog.Error("the card session cannot be reset at start", "where", resetStart, "card", was, "error", err.Error())
		return &Problems{[]string{"card.session: " + word}}
	}
	s.logReset(resetStart, was, false)
	if _, err := s.card.PINRetries(); errors.Is(err, card.ErrVerified) {
		slog.Error("the card is still PIN-verified after a reset of its session")
		return &Problems{[]string{"card.session: still_verified"}}
	}
	return nil
}

// The places where the driver resets the card session, for the journal line of each reset (logReset).
const (
	resetStart  = "start"  // the driver starts
	resetUnlock = "unlock" // an unlock (or a peer's release) meets a card that is logged in while the driver holds no PIN
	resetStatus = "status" // Status meets the same
	resetExit   = "exit"   // the driver ends cleanly
)

// What the driver knew of the login of the card when it reset the session.
const (
	cardLoggedIn  = "logged_in"
	cardLoggedOut = "logged_out"
	cardUnknown   = "unknown" // the card could not be asked
)

// loginState asks the card whether it is logged in: an empty VERIFY, which carries no PIN and changes no counter. The caller
// holds mu, or the service is not shared yet.
func (s *Service) loginState() string {
	_, err := s.card.PINRetries()
	switch {
	case errors.Is(err, card.ErrVerified):
		return cardLoggedIn
	case err == nil:
		return cardLoggedOut
	default:
		return cardUnknown
	}
}

// logReset writes the one journal line of a reset of the card session: where it was made (resetStart, resetUnlock,
// resetStatus, resetExit) and whether the card was logged in before it. A card that was found logged in while the driver
// held no PIN is a warning, as it is a security event: something logged it in, or an earlier driver ended without a reset.
// The line holds no PIN and nothing derived from it, and says whether the driver holds one only as a fact (held).
func (*Service) logReset(where, was string, held bool) {
	if was == cardLoggedIn && !held {
		slog.Warn("card session reset: the card was found PIN-verified and the driver held no PIN", "where", where, "card", was, "driver_holds_pin", held)
		return
	}
	slog.Info("card session reset", "where", where, "card", was, "driver_holds_pin", held)
}

func (s *Service) start(wantSerial uint32) error {
	if err := s.freshSession(); err != nil {
		return err
	}
	v := s.card.Version()
	if !v.AtLeast(FirmwareFloor.Major, FirmwareFloor.Minor, FirmwareFloor.Patch) {
		return &Problems{[]string{"card.firmware: below the floor of " + FirmwareFloor.String()}}
	}
	serial, err := s.card.Serial()
	if err != nil {
		return fmt.Errorf("card serial: %w", err)
	}
	if wantSerial != 0 && serial != wantSerial {
		return &Problems{[]string{"card.serial: not the card that was named"}}
	}
	s.serial = serial
	att, err := s.card.AttestationCertificate()
	if err != nil {
		return &Problems{[]string{"card.attestation: the card has no attestation certificate"}}
	}
	s.attCert = att
	var problems []string
	for _, e := range slotPlan {
		k, err := s.adopt(e)
		switch {
		case errors.Is(err, card.ErrNoKey):
			continue
		case err != nil && e.optional():
			// The RS256 key is the one of a purpose that only some installations use: a card with a key in its slot that is
			// not the plan's does not stop the driver from serving the other keys. The purpose stays absent (Sign and
			// PublicKey answer absent, and Ensure never replaces a key), and the journal says why.
			slog.Warn("the key in the slot of an optional purpose is not the plan's: the purpose is left absent", "purpose", e.purpose, "slot", e.slot.String(), "reason", err.Error())
			continue
		case err != nil:
			problems = append(problems, fmt.Sprintf("slots.%s.attestation: %v", e.slot, err))
			continue
		}
		s.keys[e.purpose] = k
	}
	if len(problems) > 0 {
		return &Problems{problems}
	}
	return nil
}

// Close releases the card and wipes the PIN.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The card is reset by its Close (it leaves the card logged out). Whether it was logged in is read before: an empty
	// VERIFY, which sends no PIN.
	was := s.loginState()
	held := s.pin.held()
	s.pin.release()
	s.oneTime = nil
	err := s.card.Close()
	if err != nil {
		slog.Error("the card session cannot be reset at exit", "where", resetExit, "card", was, "driver_holds_pin", held, "error", err.Error())
		return err
	}
	// held was read before the PIN was wiped: a card that the driver itself logged in is logged out here, as expected.
	s.logReset(resetExit, was, held)
	return nil
}

// Present returns the purposes that have a verified key, for the start-up log.
func (s *Service) Present() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.keys))
	for _, e := range slotPlan {
		if _, ok := s.keys[e.purpose]; ok {
			out = append(out, e.purpose)
		}
	}
	return out
}

// attestationError says what was wrong with an attestation, by a word that names the check.
type attestationError string

func (e attestationError) Error() string { return string(e) }

// adopt reads the key of a slot and verifies its attestation against the Yubico root: the key was born on this
// card, the card runs firmware at or above the floor, and the slot, the PIN policy and the touch policy are those
// of the plan. card.ErrNoKey is a slot with no key.
func (s *Service) adopt(e entry) (*slotKey, error) {
	cert, err := s.card.Attest(e.slot)
	if errors.Is(err, card.ErrImportedKey) {
		return nil, attestationError("origin: the key was imported and not generated on the card")
	}
	if err != nil {
		return nil, err
	}
	a, err := s.card.VerifyAttestation(s.attCert, cert)
	if err != nil {
		// The reason is the x509 error, which names a certificate and never a key; the refusal itself names none.
		slog.Warn("attestation refused", "slot", e.slot.String(), "error", err.Error())
		return nil, attestationError("chain: the attestation does not chain to the Yubico root")
	}
	switch {
	case !a.Version.AtLeast(FirmwareFloor.Major, FirmwareFloor.Minor, FirmwareFloor.Patch):
		return nil, attestationError("firmware: below the floor")
	case a.Serial != s.serial:
		return nil, attestationError("serial: the key was not made by this card")
	case a.Slot != e.slot:
		return nil, attestationError("slot: the attestation is of another slot")
	case a.PIN != e.spec.PIN:
		return nil, attestationError("pin_policy: not the policy of the plan")
	case a.Touch != e.spec.Touch:
		return nil, attestationError("touch_policy: not the policy of the plan")
	}
	if e.spec.Algorithm == card.RSA2048 {
		rp, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || rp.N.BitLen() != 2048 || rp.E != 65537 {
			return nil, attestationError("algorithm: not the RSA-2048 key of the plan")
		}
		spki, err := x509.MarshalPKIXPublicKey(rp)
		if err != nil {
			return nil, attestationError("key: cannot be encoded")
		}
		return &slotKey{entry: e, rsaPub: rp, spki: spki}, nil
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != curveOf(e.curveBits) {
		return nil, attestationError("algorithm: not the curve of the plan")
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, attestationError("key: cannot be encoded")
	}
	return &slotKey{entry: e, pub: pub, spki: spki}, nil
}

// samePublic says whether the key a card returned from Generate is the key the slot's attestation certifies.
func samePublic(pub crypto.PublicKey, k *slotKey) bool {
	switch got := pub.(type) {
	case *ecdsa.PublicKey:
		return k.pub != nil && got.Equal(k.pub)
	case *rsa.PublicKey:
		return k.rsaPub != nil && got.Equal(k.rsaPub)
	}
	return false
}

func curveOf(bits int) elliptic.Curve {
	if bits == 256 {
		return elliptic.P256()
	}
	return elliptic.P384()
}

// The reasons of the refusals of the port (a closed list). "locked" is the board that has no PIN yet.
const (
	reasonPurpose   = "purpose"
	reasonAlgorithm = "algorithm"
	reasonDigest    = "digest"
	reasonPeer      = "peer_public"
	reasonAbsent    = "absent"
	reasonLocked    = "locked"
	reasonBusy      = "busy"     // resource_exhausted: the card is doing the RSA signatures it is allowed to queue
	reasonCanceled  = "canceled" // canceled: the caller went while its RSA signature waited for the card
	reasonCard      = "card"
	reasonStore     = "store"
)

// refuse logs a refusal, with the method and the reason and no value, and returns it.
func refuse(ctx context.Context, method string, code connect.Code, reason, field string) *connect.Error {
	return refuseAt(ctx, slog.LevelWarn, method, code, reason, field)
}

// refuseAt is refuse with the level of the journal line. The refusal itself is the same at any level; only an answer that is
// the expected one of a poll is logged below a warning (BeginPinRelease on an unlocked driver).
func refuseAt(ctx context.Context, level slog.Level, method string, code connect.Code, reason, field string) *connect.Error {
	caller := ""
	if p, ok := rpc.PeerFromContext(ctx); ok {
		caller = p.Name
	}
	slog.Log(ctx, level, "refused", "method", method, "code", code.String(), "reason", reason, "field", field, "caller", caller)
	return refusal.New(code, reason, field)
}

// Capabilities says what the store can do.
func (*Service) Capabilities(context.Context, *connect.Request[keystorev2alpha1.CapabilitiesRequest]) (*connect.Response[keystorev2alpha1.CapabilitiesResponse], error) {
	return connect.NewResponse(&keystorev2alpha1.CapabilitiesResponse{
		Store: StoreName, Attests: true, Algorithms: []string{ES384, ES256, RS256, ECDHP384},
	}), nil
}

// Ensure returns the public key of a purpose. A key that the card holds was verified at start (or when it was
// made), so it is returned as it is. An absent key is made on the card in development, with the factory
// management key, and refused as absent in every other environment: a staging or production card is provisioned
// by its owners, and a management key does not sit on a board.
func (s *Service) Ensure(ctx context.Context, req *connect.Request[keystorev2alpha1.EnsureRequest]) (*connect.Response[keystorev2alpha1.EnsureResponse], error) {
	purpose, algorithm := req.Msg.GetPurpose(), req.Msg.GetAlgorithm()
	e, ok := planFor(purpose)
	if !ok {
		return nil, refuse(ctx, "Ensure", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if algorithm != ES384 && algorithm != ES256 && algorithm != RS256 && algorithm != ECDHP384 {
		return nil, refuse(ctx, "Ensure", connect.CodeInvalidArgument, reasonAlgorithm, "algorithm")
	}
	if algorithm != e.algorithm {
		// The slot holds another algorithm, or the purpose is not for this one: a key is never replaced.
		return nil, refuse(ctx, "Ensure", connect.CodeFailedPrecondition, reasonAlgorithm, "algorithm")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[purpose]; ok {
		return connect.NewResponse(&keystorev2alpha1.EnsureResponse{SpkiDer: k.spki}), nil
	}
	if s.env != Development {
		return nil, refuse(ctx, "Ensure", connect.CodeNotFound, reasonAbsent, "purpose")
	}
	k, err := s.generate(e)
	if err != nil {
		slog.Error("key generation failed", "purpose", purpose, "error", err.Error())
		return nil, refuse(ctx, "Ensure", connect.CodeFailedPrecondition, reasonCard, "purpose")
	}
	s.keys[purpose] = k
	slog.Info("key made on the card", "purpose", purpose, "slot", e.slot.String(), "algorithm", e.algorithm)
	return connect.NewResponse(&keystorev2alpha1.EnsureResponse{SpkiDer: k.spki, Created: true}), nil
}

// generate makes the key of a slot on the card and verifies its attestation before it is used. The caller holds mu.
func (s *Service) generate(e entry) (*slotKey, error) {
	if _, err := s.card.Attest(e.slot); err == nil {
		// A key that the start did not adopt would have failed it; one that appears now is not ours to trust.
		return nil, errors.New("the slot holds a key that was not adopted")
	} else if !errors.Is(err, card.ErrNoKey) { // an imported key is not ErrNoKey: it is never replaced
		return nil, err
	}
	pub, err := s.card.Generate(s.mgmtKey, e.slot, e.spec)
	if err != nil {
		return nil, err
	}
	k, err := s.adopt(e)
	if err != nil {
		return nil, fmt.Errorf("attestation of the new key: %w", err)
	}
	if !samePublic(pub, k) {
		return nil, errors.New("the key the card returned is not the key it attests")
	}
	return k, nil
}

// key returns the verified key of a purpose.
func (s *Service) key(purpose string) (*slotKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[purpose]
	return k, ok
}

// PublicKey returns the public key of a purpose.
func (s *Service) PublicKey(ctx context.Context, req *connect.Request[keystorev2alpha1.KeyStorePublicKeyRequest]) (*connect.Response[keystorev2alpha1.KeyStorePublicKeyResponse], error) {
	purpose := req.Msg.GetPurpose()
	if _, ok := planFor(purpose); !ok {
		return nil, refuse(ctx, "PublicKey", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	k, ok := s.key(purpose)
	if !ok {
		return nil, refuse(ctx, "PublicKey", connect.CodeNotFound, reasonAbsent, "purpose")
	}
	return connect.NewResponse(&keystorev2alpha1.KeyStorePublicKeyResponse{SpkiDer: k.spki}), nil
}

// pinSource is what the card asks when it is logged out and the key needs the PIN. It runs inside a card call, which
// holds mu. It never reads the PIN of a request, only the one the administrator delivered.
func (s *Service) pinSource() ([]byte, error) {
	if pin, ok := s.pin.get(); ok {
		return pin, nil
	}
	return nil, errLocked
}

var errLocked = errors.New("driver: locked")

// usable reports whether the key can be used now: a key that needs the PIN needs the driver unlocked.
func (s *Service) usable(k *slotKey) bool {
	return k.spec.PIN == card.PINNever || s.pin.held()
}

// failed maps an error of the card to its refusal. A PIN that the card refuses (the held PIN stopped working) locks
// the driver again and is never retried.
func (s *Service) failed(ctx context.Context, method string, err error) *connect.Error {
	var pe *card.PINError
	if errors.As(err, &pe) {
		s.pin.wipe()
		slog.Error("the card refused the held PIN: locked again; it is not tried again", "method", method, "retries", pe.Retries)
		return refuse(ctx, method, connect.CodeFailedPrecondition, reasonLocked, "")
	}
	if errors.Is(err, errLocked) {
		return refuse(ctx, method, connect.CodeFailedPrecondition, reasonLocked, "")
	}
	if errors.Is(err, card.ErrCardGone) {
		s.cardGone(method)
		return refuse(ctx, method, connect.CodeUnavailable, reasonCard, "")
	}
	slog.Error("card failed", "method", method, "error", err.Error())
	return refusal.New(connect.CodeInternal, reasonStore, "")
}

// cardGone wipes the PIN and tells Run to exit. The connection to a card that was removed, reset or powered off is dead
// (piv-go does not reconnect), and the driver must not go on holding a PIN it can no longer use: it exits non-zero, and
// systemd starts it again locked. Not tested on a card; the tests use a fake that fails the way the real one is
// expected to.
func (s *Service) cardGone(method string) {
	s.pin.wipe()
	slog.Error("the card is gone: the PIN is wiped and the driver exits", "method", method)
	s.exit(errors.New("the card is gone (removed, reset or powered off): exiting to be started again locked"))
}

// exit tells Run to end the driver non-zero with why; systemd starts it again. The first reason is kept.
func (s *Service) exit(why error) {
	s.deadOnce.Do(func() {
		s.deadWhy = why
		close(s.dead)
	})
}

// Sign signs a digest with the key of a purpose, on the card.
func (s *Service) Sign(ctx context.Context, req *connect.Request[keystorev2alpha1.KeyStoreSignRequest]) (*connect.Response[keystorev2alpha1.KeyStoreSignResponse], error) {
	purpose := req.Msg.GetPurpose()
	e, ok := planFor(purpose)
	if !ok {
		return nil, refuse(ctx, "Sign", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	// The pin-release key signs while the board is locked (PIN never), so it signs only the texts the driver writes
	// itself, in BeginPinRelease and SealPin: a digest from key@ could be of a request with a key of key@'s own.
	if purpose == pinrelease.PurposePinRelease {
		return nil, refuse(ctx, "Sign", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	// The algorithm must be the purpose's own: ES256 (SHA-256) for audit-log, RS256 (SHA-256) for the RS256 purpose, ES384
	// (SHA-384) for the rest. The key-agreement key does not sign.
	if a := req.Msg.GetAlgorithm(); e.algorithm == ECDHP384 || a != e.algorithm {
		return nil, refuse(ctx, "Sign", connect.CodeInvalidArgument, reasonAlgorithm, "algorithm")
	}
	digest := req.Msg.GetDigest()
	if len(digest) != e.digestLen() {
		return nil, refuse(ctx, "Sign", connect.CodeInvalidArgument, reasonDigest, "digest")
	}
	if e.algorithm == RS256 {
		return s.signRS256(ctx, purpose, digest)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[purpose]
	if !ok {
		return nil, refuse(ctx, "Sign", connect.CodeNotFound, reasonAbsent, "purpose")
	}
	if !s.usable(k) {
		return nil, refuse(ctx, "Sign", connect.CodeFailedPrecondition, reasonLocked, "")
	}
	start := time.Now()
	sig, err := s.card.Sign(k.slot, k.pub, k.spec.PIN, s.pinSource, digest)
	if err != nil {
		return nil, s.failed(ctx, "Sign", err)
	}
	slog.Debug("signed on the card", "purpose", purpose, "ms", time.Since(start).Milliseconds())
	// A card that signs wrongly is caught here, before the signature leaves the driver.
	if !ecdsa.VerifyASN1(k.pub, digest, sig) {
		slog.Error("the card's signature does not verify with its public key", "purpose", purpose)
		return nil, refusal.New(connect.CodeInternal, reasonStore, "")
	}
	return connect.NewResponse(&keystorev2alpha1.KeyStoreSignResponse{SignatureDer: sig}), nil
}

// busy refuses an RSA signature that finds the card's places taken. A flood of them must not flood the journal as well: the
// first is a warning, and then one line a minute says how many came between.
func (s *Service) busy() *connect.Error {
	s.busyMu.Lock()
	s.busyHeld++
	log := s.busyLast.IsZero() || time.Since(s.busyLast) >= busyLogEvery
	held := s.busyHeld
	if log {
		s.busyLast, s.busyHeld = time.Now(), 0
	}
	s.busyMu.Unlock()
	if log {
		slog.Warn("RSA signatures are refused as busy: the card is doing the one it admits", "refused_since_last_line", held)
	}
	return refusal.New(connect.CodeResourceExhausted, reasonBusy, "")
}

// busyLogEvery is how often busy writes a line.
const busyLogEvery = time.Minute

// signRS256 signs a SHA-256 digest with the RSA key of the RS256 purpose, on the card.
//
// A private-key operation of an RSA-2048 key takes about 0.17 s on a YubiKey 5 (measured 2026-11-08), and the driver holds one
// conversation with the card at a time, so every other call (an ES384 signature, an ECDH unwrap, an audit checkpoint) waits for
// the RSA signature on the card. The driver admits at most rsaQueueDefault RSA signatures at once and refuses the rest at once as
// busy, without touching the card (REQ-KEYS-276). The admitted ones are signed one at a time. Go's mutex is not a strict queue,
// so a call of another key that comes meanwhile waits for the one on the card and for some of the others, up to all of them:
// about one to two RSA signatures when measured (0.47 s, one sample), and 4 x 0.17 s as the bound. A caller that is cancelled
// while its signature is queued keeps its place until the signature gets the lock and sees the cancellation (at most about
// 0.7 s), so a fifth request that comes meanwhile can be refused as busy.
func (s *Service) signRS256(ctx context.Context, purpose string, digest []byte) (*connect.Response[keystorev2alpha1.KeyStoreSignResponse], error) {
	select {
	case s.rsaTickets <- struct{}{}:
		defer func() { <-s.rsaTickets }()
	default:
		return nil, s.busy()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The caller may have gone while this signature waited for the card (a deadline, a cancelled request): the card is not
	// made to spend its time on a signature nobody waits for.
	if err := ctx.Err(); err != nil {
		return nil, refuse(ctx, "Sign", connect.CodeCanceled, reasonCanceled, "")
	}
	k, ok := s.keys[purpose]
	if !ok || k.rsaPub == nil {
		return nil, refuse(ctx, "Sign", connect.CodeNotFound, reasonAbsent, "purpose")
	}
	if !s.usable(k) {
		return nil, refuse(ctx, "Sign", connect.CodeFailedPrecondition, reasonLocked, "")
	}
	start := time.Now()
	sig, err := s.card.SignRSA(k.slot, k.rsaPub, k.spec.PIN, s.pinSource, digest)
	if err != nil {
		return nil, s.failed(ctx, "Sign", err)
	}
	slog.Info("signed on the card", "purpose", purpose, "algorithm", RS256, "ms", time.Since(start).Milliseconds())
	// A card that signs wrongly is caught here, before the signature leaves the driver.
	if len(sig) != 256 || rsa.VerifyPKCS1v15(k.rsaPub, crypto.SHA256, digest, sig) != nil {
		slog.Error("the card's RSA signature does not verify with its public key", "purpose", purpose)
		return nil, refusal.New(connect.CodeInternal, reasonStore, "")
	}
	return connect.NewResponse(&keystorev2alpha1.KeyStoreSignResponse{SignatureDer: sig}), nil
}

// Ecdh derives the shared secret of the key-agreement key (slot 9d) with a peer.
func (s *Service) Ecdh(ctx context.Context, req *connect.Request[keystorev2alpha1.EcdhRequest]) (*connect.Response[keystorev2alpha1.EcdhResponse], error) {
	purpose := req.Msg.GetPurpose()
	e, ok := planFor(purpose)
	if !ok {
		return nil, refuse(ctx, "Ecdh", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if e.algorithm != ECDHP384 {
		return nil, refuse(ctx, "Ecdh", connect.CodeFailedPrecondition, reasonAlgorithm, "purpose")
	}
	peer, err := ecdh.P384().NewPublicKey(req.Msg.GetPeerPublic()) // SEC1 uncompressed; the point is checked to be on the curve
	if err != nil {
		return nil, refuse(ctx, "Ecdh", connect.CodeInvalidArgument, reasonPeer, "peer_public")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[purpose]
	if !ok {
		return nil, refuse(ctx, "Ecdh", connect.CodeNotFound, reasonAbsent, "purpose")
	}
	if !s.usable(k) {
		return nil, refuse(ctx, "Ecdh", connect.CodeFailedPrecondition, reasonLocked, "")
	}
	secret, err := s.card.ECDH(k.slot, k.pub, k.spec.PIN, s.pinSource, peer)
	if err != nil {
		return nil, s.failed(ctx, "Ecdh", err)
	}
	return connect.NewResponse(&keystorev2alpha1.EcdhResponse{SharedSecret: secret}), nil
}

// Run applies the floor, opens the card and serves the key-store port on cfg, and the unlock service on admin,
// until ctx ends. The card is closed and the PIN wiped on the way out.
func Run(ctx context.Context, opts Options, cfg rpc.ServerConfig, admin AdminConfig) error {
	if err := Floor(opts.Environment); err != nil {
		return err
	}
	if err := hardenProcess(); err != nil {
		return err
	}
	opts.Boundary = cfg.Boundary
	svc, err := New(opts)
	if err != nil {
		var pe *Problems
		if errors.As(err, &pe) {
			return cli.Refused(pe.List...)
		}
		return err
	}
	defer func() { _ = svc.Close() }()
	slog.Info("yubikey-piv key driver starting, locked", "environment", opts.Environment, "boundary", cfg.Boundary,
		"purposes", svc.Present())
	path, h := keystorev2alpha1connect.NewKeyStoreServiceHandler(svc, rpc.HandlerOptions(cfg)...)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- ServeAdmin(ctx, admin, svc) }()
	go func() { errc <- rpc.Serve(ctx, cfg, rpc.Handler{Path: path, H: h}) }()
	// The first server to end ends the driver; so does a card that is gone, which wipes the PIN first (cardGone).
	var first error
	received, gone := 0, false
	select {
	case first = <-errc:
		received = 1
	case <-svc.dead:
		gone = true
	}
	cancel()
	for ; received < 2; received++ {
		if e := <-errc; first == nil {
			first = e
		}
	}
	if gone {
		return svc.deadWhy
	}
	return first
}

// Check opens the card and verifies it as the start does: the firmware floor, and the attestation of every key it
// holds. It writes nothing, and a problem is a refusal that names a path and a word.
func Check(opts Options) error {
	svc, err := New(opts)
	if err != nil {
		var pe *Problems
		if errors.As(err, &pe) {
			return cli.Refused(pe.List...)
		}
		return err
	}
	defer func() { _ = svc.Close() }()
	slog.Info("card checked", "purposes", svc.Present())
	return nil
}
