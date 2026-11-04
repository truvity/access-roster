//go:build sluis_card && sluis_test

package driver_test

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card/cardtest"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
)

// These tests run the driver over a fake card whose attestations are read by the real code of the card build: piv-go's
// verifier over the anchors of yubico.go, and toAttestation. The certificates are a test PKI of the fake (TEST ONLY
// root, a PIV attestation intermediate, an attestation key and slot certificates with the Yubico extensions); no card
// takes part. They run in the native job, which builds with the tag sluis_card.

// realCard is the fake with its VerifyAttestation replaced by the real one.
type realCard struct {
	*cardtest.Card
	verify func(att, slot *x509.Certificate) (card.Attestation, error)
}

func (r *realCard) VerifyAttestation(att, slot *x509.Certificate) (card.Attestation, error) {
	return r.verify(att, slot)
}

func realOpener(t *testing.T, c *cardtest.Card) card.Opener {
	t.Helper()
	rootPEM, bundlePEM, hash, err := c.Anchors()
	if err != nil {
		t.Fatal(err)
	}
	verify, err := card.NewAttestationVerifier(rootPEM, bundlePEM, hash)
	if err != nil {
		t.Fatal(err)
	}
	open := c.Opener()
	return func(serial uint32) (card.Card, error) {
		if _, err := open(serial); err != nil {
			return nil, err
		}
		return &realCard{Card: c, verify: verify}, nil
	}
}

func TestTheRealVerificationOfAttestations(t *testing.T) {
	spec := card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchNever}
	tests := []struct {
		name  string
		setup func(c *cardtest.Card)
		want  string // a part of a problem; "" is a card that starts
	}{
		{"a key made as the plan says verifies", func(c *cardtest.Card) { _, _ = c.PutKey(0x9a, spec) }, ""},
		{"the PIN release key made as the plan says verifies", func(c *cardtest.Card) {
			_, _ = c.PutKey(0x87, card.KeySpec{Algorithm: card.EC384, PIN: card.PINNever, Touch: card.TouchNever})
		}, ""},
		{"a touch policy that differs", func(c *cardtest.Card) {
			_, _ = c.PutKey(0x9a, spec)
			c.Lie(0x9a, card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchAlways})
		}, "slots.9a.attestation: touch_policy"},
		{"a cached touch policy", func(c *cardtest.Card) {
			_, _ = c.PutKey(0x9a, spec)
			c.Lie(0x9a, card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchCached})
		}, "slots.9a.attestation: touch_policy"},
		{"a PIN policy that differs", func(c *cardtest.Card) {
			_, _ = c.PutKey(0x9a, spec)
			c.Lie(0x9a, card.KeySpec{Algorithm: card.EC384, PIN: card.PINNever, Touch: card.TouchNever})
		}, "slots.9a.attestation: pin_policy"},
		{"an attested serial that differs from the card's", func(c *cardtest.Card) {
			c.AttestedSerial = c.SerialNo + 1
			_, _ = c.PutKey(0x9a, spec)
		}, "slots.9a.attestation: serial"},
		{"an imported key (REQ-KEYS-026)", func(c *cardtest.Card) { _ = c.PutImportedKey(0x9a, spec) }, "slots.9a.attestation: origin"},
		{"a card with no attestation certificate", func(c *cardtest.Card) { c.NoAttestationCert = true }, "card.attestation"},
		{"an attestation that chains to a rogue root", func(c *cardtest.Card) {
			c.RogueRoot = true
			_, _ = c.PutKey(0x9a, spec)
		}, "slots.9a.attestation: chain"},
		{"firmware below 5.7 on the card", func(c *cardtest.Card) { c.Firmware = card.Version{Major: 5, Minor: 4, Patch: 3} }, "card.firmware"},
		{"firmware below 5.7 in the attestation", func(c *cardtest.Card) {
			c.AttestedFirmware = card.Version{Major: 5, Minor: 6, Patch: 9}
			_, _ = c.PutKey(0x9a, spec)
		}, "slots.9a.attestation: firmware"},
		{"firmware 5.7.0 in the attestation is the floor", func(c *cardtest.Card) {
			c.AttestedFirmware = card.Version{Major: 5, Minor: 7, Patch: 0}
			_, _ = c.PutKey(0x9a, spec)
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cardtest.New()
			tt.setup(c)
			s, err := driver.New(driver.Options{Environment: driver.Production, Serial: c.SerialNo, Open: realOpener(t, c)})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				_ = s.Close()
				return
			}
			var p *driver.Problems
			if !errors.As(err, &p) || !strings.Contains(strings.Join(p.List, ";"), tt.want) {
				t.Fatalf("err = %v, want a problem with %q", err, tt.want)
			}
			if !c.Closed() {
				t.Fatal("the refused card was left open")
			}
		})
	}
}
