//go:build sluis_card

package card

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

// HasCardSupport is true in a build that talks to cards.
const HasCardSupport = true

// pivSlot maps a key reference to piv-go's slot. A slot outside 9a, 9c, 9d and 82 to 95 is not known.
func pivSlot(s Slot) (piv.Slot, bool) {
	switch s {
	case 0x9a:
		return piv.SlotAuthentication, true
	case 0x9c:
		return piv.SlotSignature, true
	case 0x9d:
		return piv.SlotKeyManagement, true
	}
	return piv.RetiredKeyManagementSlot(uint32(s))
}

// Open opens a card exclusively through piv-go (SCardConnect with SCARD_SHARE_EXCLUSIVE: while it is open, no other
// process can talk to the card). serial 0 means the only card; two cards with no serial named are refused.
func Open(serial uint32) (Card, error) {
	readers, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("card: list readers: %w", err)
	}
	if serial == 0 && len(readers) > 1 {
		return nil, fmt.Errorf("card: %d readers and no serial named: refusing to choose the first", len(readers))
	}
	for _, r := range readers {
		yk, err := piv.Open(r)
		if err != nil {
			if serial == 0 {
				return nil, fmt.Errorf("card: open %q: %w", r, err)
			}
			continue // another reader, or a card that someone else holds
		}
		got, err := yk.Serial()
		if err != nil {
			_ = yk.Close()
			continue
		}
		if serial != 0 && got != serial {
			_ = yk.Close()
			continue
		}
		return &pivCard{yk: yk}, nil
	}
	return nil, ErrNoCard
}

type pivCard struct {
	yk *piv.YubiKey
}

func (c *pivCard) Serial() (uint32, error) { return c.yk.Serial() }

func (c *pivCard) Version() Version {
	v := c.yk.Version()
	return Version{v.Major, v.Minor, v.Patch}
}

func (c *pivCard) AttestationCertificate() (*x509.Certificate, error) {
	return c.yk.AttestationCertificate()
}

func (c *pivCard) Attest(s Slot) (*x509.Certificate, error) {
	ps, ok := pivSlot(s)
	if !ok {
		return nil, fmt.Errorf("card: slot %s is not a key slot", s)
	}
	cert, err := c.yk.Attest(ps)
	if errors.Is(err, piv.ErrNotFound) {
		return nil, ErrNoKey
	}
	return cert, err
}

// VerifyAttestation checks the chain against Yubico's roots, which piv-go carries, and reads the extensions.
func (c *pivCard) VerifyAttestation(attCert, slotCert *x509.Certificate) (Attestation, error) {
	a, err := piv.Verify(attCert, slotCert)
	if err != nil {
		return Attestation{}, err
	}
	out := Attestation{
		Version: Version{a.Version.Major, a.Version.Minor, a.Version.Patch},
		Serial:  a.Serial,
		Slot:    Slot(a.Slot.Key), //nolint:gosec // a slot key reference is one octet
	}
	switch a.PINPolicy {
	case piv.PINPolicyNever:
		out.PIN = PINNever
	case piv.PINPolicyOnce:
		out.PIN = PINOnce
	}
	if a.TouchPolicy == piv.TouchPolicyNever {
		out.Touch = TouchNever
	}
	return out, nil
}

func (c *pivCard) Generate(managementKey []byte, s Slot, spec KeySpec) (crypto.PublicKey, error) {
	ps, ok := pivSlot(s)
	if !ok {
		return nil, fmt.Errorf("card: slot %s is not a key slot", s)
	}
	k := piv.Key{}
	switch spec.Algorithm {
	case EC256:
		k.Algorithm = piv.AlgorithmEC256
	case EC384:
		k.Algorithm = piv.AlgorithmEC384
	default:
		return nil, errors.New("card: unsupported algorithm")
	}
	switch spec.PIN {
	case PINNever:
		k.PINPolicy = piv.PINPolicyNever
	case PINOnce:
		k.PINPolicy = piv.PINPolicyOnce
	default:
		return nil, errors.New("card: unsupported PIN policy")
	}
	if spec.Touch != TouchNever {
		return nil, errors.New("card: unsupported touch policy")
	}
	k.TouchPolicy = piv.TouchPolicyNever
	pub, err := c.yk.GenerateKey(managementKey, ps, k)
	if err != nil {
		var ae piv.AuthErr
		if errors.As(err, &ae) {
			return nil, ErrManagementKey
		}
		return nil, err
	}
	return pub, nil
}

func (c *pivCard) Login(pin string) error {
	err := c.yk.VerifyPIN(pin)
	return pinError(err)
}

func (c *pivCard) PINRetries() (int, error) { return c.yk.Retries() }

func pinError(err error) error {
	var ae piv.AuthErr
	if errors.As(err, &ae) {
		return &PINError{Retries: ae.Retries}
	}
	return err
}

func (c *pivCard) key(s Slot, pub *ecdsa.PublicKey, policy PINPolicy, pin PINSource) (*piv.ECDSAPrivateKey, error) {
	ps, ok := pivSlot(s)
	if !ok {
		return nil, fmt.Errorf("card: slot %s is not a key slot", s)
	}
	auth := piv.KeyAuth{PINPolicy: piv.PINPolicyNever}
	if policy == PINOnce {
		// The policy is given, so piv-go does not ask the card for it on every call. PINPrompt runs only when the
		// card is logged out, and an error from it ends the call before any PIN is sent.
		auth = piv.KeyAuth{PINPolicy: piv.PINPolicyOnce, PINPrompt: pin}
	}
	priv, err := c.yk.PrivateKey(ps, pub, auth)
	if err != nil {
		return nil, err
	}
	ek, ok := priv.(*piv.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("card: the slot does not hold an ECDSA key")
	}
	return ek, nil
}

func (c *pivCard) Sign(s Slot, pub *ecdsa.PublicKey, policy PINPolicy, pin PINSource, digest []byte) ([]byte, error) {
	k, err := c.key(s, pub, policy, pin)
	if err != nil {
		return nil, err
	}
	sig, err := k.Sign(nil, digest, crypto.Hash(0))
	return sig, pinError(err)
}

func (c *pivCard) ECDH(s Slot, pub *ecdsa.PublicKey, policy PINPolicy, pin PINSource, peer *ecdh.PublicKey) ([]byte, error) {
	k, err := c.key(s, pub, policy, pin)
	if err != nil {
		return nil, err
	}
	secret, err := k.ECDH(peer)
	return secret, pinError(err)
}

func (c *pivCard) Close() error { return c.yk.Close() }
