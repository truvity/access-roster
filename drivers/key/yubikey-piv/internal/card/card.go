// Package card is what the YubiKey PIV key driver needs from a card, as an interface the driver can be tested
// against, and the real card behind it.
//
// The real card (piv.go, build tag sluis_card) is piv-go over pcsc-lite through cgo (ADR 0012, 0013). It is behind a
// tag so that a build without pcsc-lite headers, and the cross-compiled build of everything else, still compile
// the driver's logic; the executable of a board is built with the tag, natively, by the card build.
package card

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// Slot is the key reference of a PIV slot: 0x9a, 0x9c, 0x9d or a retired slot 0x82 to 0x95 (NIST SP 800-73-4).
type Slot byte

func (s Slot) String() string { return fmt.Sprintf("%02x", byte(s)) }

// Algorithm is the algorithm of a card key.
type Algorithm int

// The algorithms of the slot plan.
const (
	EC256 Algorithm = iota + 1 // ECDSA or ECDH over P-256
	EC384                      // ECDSA or ECDH over P-384
)

// PINPolicy says when a key needs the PIN (NIST SP 800-73-4; the Yubico key policy extension).
type PINPolicy int

// The PIN policies the slot plan uses.
const (
	PINNever PINPolicy = iota + 1 // the key works without the PIN
	PINOnce                       // the PIN once, then the card stays logged in while it is powered
)

// TouchPolicy says when a key needs a touch.
type TouchPolicy int

// TouchNever is the only touch policy of a board: it signs unattended (0006 "Touch and PIN").
const TouchNever TouchPolicy = iota + 1

// KeySpec is what a key is generated with. The policies are fixed at generation and show in the attestation.
type KeySpec struct {
	Algorithm Algorithm
	PIN       PINPolicy
	Touch     TouchPolicy
}

// Version is the firmware version of a card.
type Version struct{ Major, Minor, Patch int }

// AtLeast reports whether v is the version a.b.c or newer.
func (v Version) AtLeast(a, b, c int) bool {
	if v.Major != a {
		return v.Major > a
	}
	if v.Minor != b {
		return v.Minor > b
	}
	return v.Patch >= c
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Attestation is what a verified slot certificate says: the firmware and serial of the card that made it, the
// policies of the key and its slot.
type Attestation struct {
	Version Version
	Serial  uint32
	Slot    Slot
	PIN     PINPolicy
	Touch   TouchPolicy
}

// The errors of a card.
var (
	// ErrNoKey is a slot that holds no key.
	ErrNoKey = errors.New("card: the slot holds no key")
	// ErrManagementKey is a management key that the card refuses.
	ErrManagementKey = errors.New("card: the management key was refused")
	// ErrNoCardSupport is a build without the card (no sluis_card tag).
	ErrNoCardSupport = errors.New("card: this build has no card support; the card build is made natively with the tag sluis_card")
	// ErrNoCard is no card, or more than one when none was named.
	ErrNoCard = errors.New("card: no card found")
)

// PINError is a PIN that the card refused. Retries is what the card allows before it blocks; the PIN is not in it.
type PINError struct {
	Retries int
}

func (e *PINError) Error() string {
	if e.Retries == 0 {
		return "card: the PIN was refused and the card is blocked"
	}
	return fmt.Sprintf("card: the PIN was refused; %d attempts remain", e.Retries)
}

// PINSource gives the PIN when the card asks for it. It is called only when the card is logged out, and its error
// ends the operation without a PIN attempt.
type PINSource func() (string, error)

// DefaultManagementKey is the factory management key of a PIV applet: the 24 octets 01..08 three times (NIST SP 800-78-4;
// Yubico documents it). It is 3DES before firmware 5.7 and AES-192 from it, with the same octets; piv-go picks the
// algorithm from the firmware. It is public. The driver uses it in development only, on a card in factory state.
var DefaultManagementKey = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

// Card is one open card. The driver holds it from start to stop, exclusively. A Card is not safe for concurrent use:
// the driver serialises its calls.
type Card interface {
	// Serial and Version are what the PIV applet says.
	Serial() (uint32, error)
	Version() Version

	// AttestationCertificate is the card's own attestation certificate, signed by Yubico.
	AttestationCertificate() (*x509.Certificate, error)
	// Attest is the certificate the card makes for the key of a slot, signed by its attestation key; ErrNoKey when
	// the slot holds no key or a key that was imported.
	Attest(Slot) (*x509.Certificate, error)
	// VerifyAttestation proves that slotCert chains through attCert to the Yubico root, and reads what it says.
	VerifyAttestation(attCert, slotCert *x509.Certificate) (Attestation, error)

	// Generate makes a key in the slot, on the card, authenticated with the management key.
	Generate(managementKey []byte, slot Slot, spec KeySpec) (crypto.PublicKey, error)

	// Login sends the PIN to the card once and never again (a wrong PIN is not retried here or by the caller).
	Login(pin string) error
	// PINRetries is the attempts the card still allows.
	PINRetries() (int, error)

	// Sign signs a digest with the key of the slot and returns an ASN.1 DER signature. A key whose PIN policy is
	// PINOnce asks for the PIN through pin when the card is logged out.
	Sign(slot Slot, pub *ecdsa.PublicKey, policy PINPolicy, pin PINSource, digest []byte) ([]byte, error)
	// ECDH derives the shared secret of the key of the slot with a peer's public key.
	ECDH(slot Slot, pub *ecdsa.PublicKey, policy PINPolicy, pin PINSource, peer *ecdh.PublicKey) ([]byte, error)

	// Close releases the card.
	Close() error
}

// Opener opens a card: the one named by serial, or the only one when serial is 0. More than one card with no
// serial named is refused: "the first one found" is never chosen (docs/contributing/tools.md, Hardware tokens).
type Opener func(serial uint32) (Card, error)
