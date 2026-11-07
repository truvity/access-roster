// Package cardtest is a card in memory for the tests of the driver. It behaves like a YubiKey PIV applet to the
// extent the driver relies on: keys made in slots with their policies, attestation certificates in the Yubico
// layout, a PIN with a retry counter and a logged-in state, and a management key.
//
// Its attestation root is made for each fake and marked TEST ONLY; it is not Yubico's root, and no product code
// imports this package.
package cardtest

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
)

// The object identifiers of the Yubico attestation extensions (developers.yubico.com, PIV attestation).
var (
	oidFirmware  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidKeyPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

type slotKey struct {
	priv     *ecdsa.PrivateKey
	imported bool
	spec     card.KeySpec
	// shown is the policy the attestation states; it differs from spec only when a test makes a card lie.
	shown card.KeySpec
}

// Card is the fake. The exported fields are the knobs of a test; set them before the card is opened.
type Card struct {
	Firmware card.Version
	SerialNo uint32
	// PIN is the PIN the card accepts. Retries is what it allows; it counts down on a wrong PIN and a blocked card
	// (0) refuses every PIN.
	PIN     string
	Retries int
	// ManagementKey is the key Generate wants.
	ManagementKey []byte
	// AttestedFirmware is the firmware the attestation certificates state; the Firmware when zero.
	AttestedFirmware card.Version
	// RogueRoot makes the attestation certificates chain to a root that is not the one the card verifies against.
	RogueRoot bool
	// AttestedSerial is the serial the attestation certificates state; the SerialNo when zero.
	AttestedSerial uint32
	// NoAttestationCert makes AttestationCertificate fail, as a card without one does.
	NoAttestationCert bool
	// LoginAttempts counts the PINs the card was sent, right or wrong.
	LoginAttempts int
	// Signs counts the signatures made.
	Signs int
	// Loggedin is the PIN state of the powered card.
	Loggedin bool
	// ResetErr makes ResetSession fail with it, as a card that another process holds does (card.ErrSharing).
	ResetErr error
	// ResetKeepsVerified makes ResetSession succeed and leave the card logged in, as a reset that did not take.
	ResetKeepsVerified bool
	// Resets counts the calls of ResetSession.
	Resets int
	// PKI makes this card a sibling of another fake: its attestation certificate is signed by that card's TEST ONLY
	// intermediate, so each card verifies the other's attestations, as two YubiKeys both chain to Yubico's root.
	PKI *Card

	mu       sync.Mutex
	root     *x509.Certificate
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	attKey   *ecdsa.PrivateKey
	attCert  *x509.Certificate
	slots    map[card.Slot]*slotKey
	closed   bool
	gone     bool
	rootHash string
}

// New returns a card in factory state with firmware 5.8.0, the factory PIN and management key.
func New() *Card {
	return &Card{
		Firmware: card.Version{Major: 5, Minor: 8, Patch: 0}, SerialNo: 12345678,
		PIN: "123456", Retries: 3, ManagementKey: card.DefaultManagementKey,
	}
}

func (c *Card) init() error {
	if c.root != nil {
		return nil
	}
	c.slots = map[card.Slot]*slotKey{}
	if c.PKI != nil {
		c.PKI.mu.Lock()
		err := c.PKI.init()
		root, inter, interKey, hash := c.PKI.root, c.PKI.inter, c.PKI.interKey, c.PKI.rootHash
		c.PKI.mu.Unlock()
		if err != nil {
			return err
		}
		c.root, c.inter, c.interKey, c.rootHash = root, inter, interKey, hash
		return c.makeAttestationKey(interKey, inter)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST ONLY attestation root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	if c.root, err = x509.ParseCertificate(der); err != nil {
		return err
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "Yubico PIV Attestation TEST ONLY 1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err = x509.CreateCertificate(rand.Reader, interTmpl, c.root, &interKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	if c.inter, err = x509.ParseCertificate(der); err != nil {
		return err
	}
	c.interKey = interKey
	sum := sha256.Sum256(c.root.Raw)
	c.rootHash = hex.EncodeToString(sum[:])
	signerKey, signerCert := interKey, c.inter
	if c.RogueRoot {
		rogue, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		rogueTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "TEST ONLY rogue root"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		rder, err := x509.CreateCertificate(rand.Reader, rogueTmpl, rogueTmpl, &rogue.PublicKey, rogue)
		if err != nil {
			return err
		}
		if signerCert, err = x509.ParseCertificate(rder); err != nil {
			return err
		}
		signerKey = rogue
	}
	return c.makeAttestationKey(signerKey, signerCert)
}

// makeAttestationKey makes the card's attestation key and its certificate, signed by the key and certificate given.
func (c *Card) makeAttestationKey(signerKey *ecdsa.PrivateKey, signerCert *x509.Certificate) error {
	var err error
	if c.attKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return err
	}
	attTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "TEST ONLY YubiKey PIV Attestation F9"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, attTmpl, signerCert, &c.attKey.PublicKey, signerKey)
	if err != nil {
		return err
	}
	c.attCert, err = x509.ParseCertificate(der)
	return err
}

// Opener returns an opener that gives this card, and counts nothing else.
func (c *Card) Opener() card.Opener {
	return func(serial uint32) (card.Card, error) {
		if serial != 0 && serial != c.SerialNo {
			return nil, card.ErrNoCard
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if err := c.init(); err != nil {
			return nil, err
		}
		c.closed = false
		return c, nil
	}
}

// Anchors are what a real attestation verifier needs to trust this card: its root (PEM), the bundle of intermediates (PEM)
// and the SHA-256 of the root (hex). The fake's own VerifyAttestation does not use them; a test that runs the real code
// (card.NewVerifier, card.VerifyWith, under the tag sluis_card) does.
func (c *Card) Anchors() (rootPEM, bundlePEM []byte, rootSHA256 string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err = c.init(); err != nil {
		return nil, nil, "", err
	}
	enc := func(cs ...*x509.Certificate) (b []byte) {
		for _, x := range cs {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.Raw})...)
		}
		return b
	}
	return enc(c.root), enc(c.inter), c.rootHash, nil
}

// Unplug makes every later call fail as a card that was removed does.
func (c *Card) Unplug() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gone = true
}

// PutImportedKey puts a key into a slot as if it had been imported: the card holds it and cannot attest it.
func (c *Card) PutImportedKey(s card.Slot, spec card.KeySpec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.init(); err != nil {
		return err
	}
	if _, err := c.generate(s, spec); err != nil {
		return err
	}
	c.slots[s].imported = true
	return nil
}

func (c *Card) dead() error {
	if c.gone {
		return fmt.Errorf("%w: the card was removed", card.ErrCardGone)
	}
	return nil
}

// Closed reports whether the driver closed the card.
func (c *Card) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// PutKey puts a key into a slot as if a ceremony had generated it, with the policies given.
func (c *Card) PutKey(s card.Slot, spec card.KeySpec) (*ecdsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.init(); err != nil {
		return nil, err
	}
	return c.generate(s, spec)
}

// Lie makes the attestation of a slot state other policies than the key has.
func (c *Card) Lie(s card.Slot, shown card.KeySpec) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.slots[s].shown = shown
}

func (c *Card) generate(s card.Slot, spec card.KeySpec) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch spec.Algorithm {
	case card.EC256:
		curve = elliptic.P256()
	case card.EC384:
		curve = elliptic.P384()
	default:
		return nil, errors.New("cardtest: algorithm")
	}
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	c.slots[s] = &slotKey{priv: k, spec: spec, shown: spec}
	return &k.PublicKey, nil
}

// Serial implements card.Card.
// PrivateScalars is the private scalar of every key the card holds, as the big-endian bytes of D. It is for a test that
// scans what a driver answered for a key that must not have left the card.
func (c *Card) PrivateScalars() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out [][]byte
	for _, k := range c.slots {
		out = append(out, k.priv.D.Bytes())
	}
	return out
}

func (c *Card) Serial() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.SerialNo, c.dead()
}

// Version implements card.Card.
func (c *Card) Version() card.Version { return c.Firmware }

// AttestationCertificate implements card.Card.
func (c *Card) AttestationCertificate() (*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.dead(); err != nil {
		return nil, err
	}
	if c.NoAttestationCert {
		return nil, errors.New("cardtest: the card holds no attestation certificate")
	}
	return c.attCert, nil
}

func policyBytes(spec card.KeySpec) []byte {
	var p, t byte
	switch spec.PIN {
	case card.PINNever:
		p = 0x01
	case card.PINOnce:
		p = 0x02
	}
	switch spec.Touch {
	case card.TouchNever:
		t = 0x01
	case card.TouchAlways:
		t = 0x02
	case card.TouchCached:
		t = 0x03
	}
	return []byte{p, t}
}

// Attest implements card.Card: a certificate for the key of the slot, signed by the card's attestation key, with the
// firmware, the serial and the policies in the Yubico extensions.
func (c *Card) Attest(s card.Slot) (*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.dead(); err != nil {
		return nil, err
	}
	k, ok := c.slots[s]
	if !ok {
		return nil, card.ErrNoKey
	}
	if k.imported {
		return nil, card.ErrImportedKey
	}
	fw := c.AttestedFirmware
	if fw == (card.Version{}) {
		fw = c.Firmware
	}
	attested := c.AttestedSerial
	if attested == 0 {
		attested = c.SerialNo
	}
	serial, err := asn1.Marshal(int64(attested))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "YubiKey PIV Attestation " + s.String()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidFirmware, Value: []byte{byte(fw.Major), byte(fw.Minor), byte(fw.Patch)}}, //nolint:gosec // small version numbers,
			{Id: oidSerial, Value: serial},
			{Id: oidKeyPolicy, Value: policyBytes(k.shown)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.attCert, &k.priv.PublicKey, c.attKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// VerifyAttestation implements card.Card against the fake's own root.
func (c *Card) VerifyAttestation(attCert, slotCert *x509.Certificate) (card.Attestation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	roots := x509.NewCertPool()
	roots.AddCert(c.root)
	inter := x509.NewCertPool()
	inter.AddCert(attCert)
	inter.AddCert(c.inter)
	if _, err := slotCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return card.Attestation{}, err
	}
	var a card.Attestation
	for _, e := range slotCert.Extensions {
		switch {
		case e.Id.Equal(oidFirmware) && len(e.Value) == 3:
			a.Version = card.Version{Major: int(e.Value[0]), Minor: int(e.Value[1]), Patch: int(e.Value[2])}
		case e.Id.Equal(oidSerial):
			var n int64
			if _, err := asn1.Unmarshal(e.Value, &n); err != nil {
				return card.Attestation{}, err
			}
			a.Serial = uint32(n) //nolint:gosec // a serial number fits
		case e.Id.Equal(oidKeyPolicy) && len(e.Value) == 2:
			switch e.Value[0] {
			case 0x01:
				a.PIN = card.PINNever
			case 0x02:
				a.PIN = card.PINOnce
			}
			switch e.Value[1] {
			case 0x01:
				a.Touch = card.TouchNever
			case 0x02:
				a.Touch = card.TouchAlways
			case 0x03:
				a.Touch = card.TouchCached
			}
		}
	}
	var slot byte
	if _, err := fmt.Sscanf(slotCert.Subject.CommonName, "YubiKey PIV Attestation %02x", &slot); err != nil {
		return card.Attestation{}, err
	}
	a.Slot = card.Slot(slot)
	return a, nil
}

// Generate implements card.Card. It refuses a slot that holds a key: the real card would replace it, and the
// driver must never ask.
func (c *Card) Generate(managementKey []byte, s card.Slot, spec card.KeySpec) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.dead(); err != nil {
		return nil, err
	}
	if !bytes.Equal(managementKey, c.ManagementKey) {
		return nil, card.ErrManagementKey
	}
	if _, ok := c.slots[s]; ok {
		return nil, errors.New("cardtest: the slot holds a key and Generate would replace it")
	}
	return c.generate(s, spec)
}

func (c *Card) login(pin string) error {
	if err := c.dead(); err != nil {
		return err
	}
	c.LoginAttempts++
	if c.Retries == 0 {
		return &card.PINError{Retries: 0}
	}
	if pin != c.PIN {
		c.Retries--
		c.Loggedin = false
		return &card.PINError{Retries: c.Retries}
	}
	c.Retries = 3
	c.Loggedin = true
	return nil
}

// Login implements card.Card.
func (c *Card) Login(pin []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login(string(pin))
}

// PINRetries implements card.Card. A card that is logged in answers the empty VERIFY with success, so the counter cannot
// be read: card.ErrVerified, as the real one. The call changes no counter.
func (c *Card) PINRetries() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.dead(); err != nil {
		return 0, err
	}
	if c.Loggedin {
		return 0, card.ErrVerified
	}
	return c.Retries, nil
}

// ResetSession implements card.Card: a reset of the session logs the card out and changes nothing else, not the keys,
// the PIN, the retry counter or the management key.
func (c *Card) ResetSession() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Resets++
	if err := c.dead(); err != nil {
		return err
	}
	if c.ResetErr != nil {
		return c.ResetErr
	}
	if !c.ResetKeepsVerified {
		c.Loggedin = false
	}
	return nil
}

// Reset logs the card out, as a power loss or a reset of the applet does.
func (c *Card) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Loggedin = false
}

// Verify logs the card in as another process, or an earlier driver that ended without a reset, would have left it: the
// driver did not send the PIN and does not hold it. It does not touch the counter or LoginAttempts.
func (c *Card) Verify() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Loggedin = true
}

// Configure changes the knobs of the card under its lock, for a test that does it while the driver is running.
func (c *Card) Configure(f func(*Card)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

// ResetCount is Resets, read under the card's lock, for a test that reads it while the driver, in another goroutine,
// may be using the card.
func (c *Card) ResetCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Resets
}

// Attempts is LoginAttempts, read under the card's lock.
func (c *Card) Attempts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.LoginAttempts
}

// RetriesLeft is Retries, read under the card's lock.
func (c *Card) RetriesLeft() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Retries
}

// Verified reports whether the card is logged in.
func (c *Card) Verified() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Loggedin
}

// auth is what a key of the policy needs before it works.
func (c *Card) auth(k *slotKey, policy card.PINPolicy, pin card.PINSource) error {
	if err := c.dead(); err != nil {
		return err
	}
	if policy != card.PINOnce || c.Loggedin {
		if k.spec.PIN == card.PINOnce && !c.Loggedin {
			return errors.New("cardtest: security status not satisfied")
		}
		return nil
	}
	p, err := pin()
	if err != nil {
		return fmt.Errorf("pin prompt: %w", err)
	}
	defer clear(p)
	return c.login(string(p))
}

func (c *Card) key(s card.Slot, pub *ecdsa.PublicKey) (*slotKey, error) {
	k, ok := c.slots[s]
	if !ok {
		return nil, card.ErrNoKey
	}
	if !k.priv.PublicKey.Equal(pub) {
		return nil, errors.New("cardtest: the public key is not the slot's")
	}
	return k, nil
}

// Sign implements card.Card.
func (c *Card) Sign(s card.Slot, pub *ecdsa.PublicKey, policy card.PINPolicy, pin card.PINSource, digest []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, err := c.key(s, pub)
	if err != nil {
		return nil, err
	}
	if err := c.auth(k, policy, pin); err != nil {
		return nil, err
	}
	c.Signs++
	return ecdsa.SignASN1(rand.Reader, k.priv, digest)
}

// ECDH implements card.Card.
func (c *Card) ECDH(s card.Slot, pub *ecdsa.PublicKey, policy card.PINPolicy, pin card.PINSource, peer *ecdh.PublicKey) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, err := c.key(s, pub)
	if err != nil {
		return nil, err
	}
	if err := c.auth(k, policy, pin); err != nil {
		return nil, err
	}
	own, err := k.priv.ECDH()
	if err != nil {
		return nil, err
	}
	return own.ECDH(peer)
}

// Close implements card.Card.
func (c *Card) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.Loggedin = false // Close leaves the card logged out
	return nil
}

var _ card.Card = (*Card)(nil)
