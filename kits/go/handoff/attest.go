package handoff

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"slices"
	"strings"
	"time"
)

// CodeProofInvalid is the reason code of a certifier for evidence that does not hold (contract, "What the certifier checks", check 7).
const CodeProofInvalid = "proof-invalid"

// The extensions of a slot's attestation certificate that the certifier reads (contract, "piv"): the arc 1.3.6.1.4.1.41482.3.
var (
	oidFirmware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
	oidForm     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}
)

// The PIN policies of a PIV key, as the attestation carries them.
const (
	PINNever  = 1
	PINOnce   = 2
	PINAlways = 3
)

const attestationSubject = "YubiKey PIV Attestation "

// pivIntermediateName is in the name of every intermediate that signs the token certificate of a PIV applet ("Yubico PIV
// Attestation B2 1"; the made-up one of the vectors is "Example Test PIV Attestation Intermediate").
const pivIntermediateName = "PIV Attestation"

// PIVEvidence is what the certifier read from the attestation of a PIV key.
type PIVEvidence struct {
	// Slot is the slot the key lives in, in lower-case hexadecimal ("9c").
	Slot string
	// SPKI is the DER SubjectPublicKeyInfo of the attested key.
	SPKI []byte
	// Firmware is the version of the token, major, minor, patch.
	Firmware [3]byte
	// Serial is the serial number of the token.
	Serial *big.Int
	// PIN and Touch are the policies of the key as the token reports them (PINNever to PINAlways; touch 1 never, 2 always,
	// 3 cached). Touch is read and recorded and the reference policy does not enforce it.
	PIN, Touch byte
	// FormFactor is the token's form factor, 0 when the certificate does not carry it.
	FormFactor byte
}

// AtLeast reports whether the firmware is major.minor.patch or newer.
func (e *PIVEvidence) AtLeast(major, minor, patch byte) bool {
	have := [3]byte{e.Firmware[0], e.Firmware[1], e.Firmware[2]}
	return slices.Compare(have[:], []byte{major, minor, patch}) >= 0
}

// AttestationAnchors are the certificates the certifier pins for PIV evidence: the maker's roots, and the maker's
// intermediates of every level (the real bundle has two: "Yubico Attestation Intermediate B 1" under the root, and "Yubico PIV
// Attestation B2 1" under that), which only help to build the path. A root in the proof file is never trusted, and a certificate of the proof beyond the first two serves only
// as an untrusted helper to build the path.
type AttestationAnchors struct {
	Roots         []*x509.Certificate
	Intermediates []*x509.Certificate
}

// slots a slot certificate may name: 9a, 9c, 9d, 9e and 82 to 95 (contract, check 7).
func validPIVSlot(s string) bool {
	switch s {
	case "9a", "9c", "9d", "9e":
		return true
	}
	if len(s) != 2 || s[0] < '8' || s[0] > '9' {
		return false
	}
	var n int
	for _, c := range []byte(s) {
		switch {
		case c >= '0' && c <= '9':
			n = n*16 + int(c-'0')
		case c >= 'a' && c <= 'f':
			n = n*16 + int(c-'a') + 10
		default:
			return false
		}
	}
	return n >= 0x82 && n <= 0x95
}

// CheckPIVEvidence is check 7 of the contract for a PIV key: both certificates parse; the chain from the slot certificate
// through the token's certificate and the maker's intermediates leads to a pinned root, every certificate valid at now; the
// token's certificate is a CA with path length 0; the slot certificate's subject is "YubiKey PIV Attestation <slot>" for a
// slot the contract names; and the extensions for firmware, serial and policy are present. The refusal is proof-invalid and
// names the place, never a value. It reads the attested key and the policies and decides nothing about them: the key match
// is check 8 (the caller compares SPKI with the request's) and the policy is check 9.
func CheckPIVEvidence(attestation [][]byte, anchors AttestationAnchors, now time.Time) (*PIVEvidence, error) {
	if len(attestation) < 2 {
		return nil, refuse(CodeProofInvalid, "evidence.attestation")
	}
	certs := make([]*x509.Certificate, len(attestation))
	for i, der := range attestation {
		c, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(c.Raw, der) {
			return nil, refusef(CodeProofInvalid, "evidence.attestation[%d]", i)
		}
		certs[i] = c
	}
	slot, token := certs[0], certs[1]
	if len(anchors.Roots) == 0 {
		return nil, refuse(CodeProofInvalid, "anchors")
	}
	roots, helpers := x509.NewCertPool(), x509.NewCertPool()
	for _, r := range anchors.Roots {
		roots.AddCert(r)
	}
	for _, c := range anchors.Intermediates {
		helpers.AddCert(c)
	}
	for _, c := range certs[2:] {
		helpers.AddCert(c)
	}
	// The token's certificate leads to a pinned root (the roots of the proof are not in the pool), and is valid now.
	chains, err := token.Verify(x509.VerifyOptions{Roots: roots, Intermediates: helpers, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, refuse(CodeProofInvalid, "evidence.attestation[1].chain")
	}
	// The issuer of the token's certificate is a PIV attestation intermediate of the maker. A pinned root has more than one
	// kind of intermediate under it (the OpenPGP, FIDO and secure-domain ones among them), and a token signed by one of
	// those is not the attestation of a PIV key.
	if !slices.ContainsFunc(chains, func(c []*x509.Certificate) bool {
		return len(c) >= 3 && strings.Contains(c[1].Subject.CommonName, pivIntermediateName)
	}) {
		return nil, refuse(CodeProofInvalid, "evidence.attestation[1].issuer")
	}
	if !token.IsCA || token.MaxPathLen != 0 { // a certificate with no path length reads as -1
		return nil, refuse(CodeProofInvalid, "evidence.attestation[1].basic constraints")
	}
	// The slot certificate is signed by the token's, and is valid now.
	if slot.CheckSignatureFrom(token) != nil {
		return nil, refuse(CodeProofInvalid, "evidence.attestation[0].signature")
	}
	if now.Before(slot.NotBefore) || now.After(slot.NotAfter) {
		return nil, refuse(CodeProofInvalid, "evidence.attestation[0].validity")
	}
	name, ok := strings.CutPrefix(slot.Subject.CommonName, attestationSubject)
	if !ok || !validPIVSlot(name) {
		return nil, refuse(CodeProofInvalid, "evidence.attestation[0].subject")
	}
	ev := &PIVEvidence{Slot: name, SPKI: slot.RawSubjectPublicKeyInfo}
	// An extension appears once in a certificate that parses, so none is read twice.
	var haveFW, haveSerial, havePolicy bool
	for _, e := range slot.Extensions {
		switch {
		case e.Id.Equal(oidFirmware):
			if len(e.Value) != 3 {
				return nil, refuse(CodeProofInvalid, "evidence.attestation[0].firmware")
			}
			copy(ev.Firmware[:], e.Value)
			haveFW = true
		case e.Id.Equal(oidSerial):
			var n *big.Int
			if rest, err := asn1.Unmarshal(e.Value, &n); err != nil || len(rest) != 0 || n == nil || n.Sign() < 0 {
				return nil, refuse(CodeProofInvalid, "evidence.attestation[0].serial")
			}
			ev.Serial, haveSerial = n, true
		case e.Id.Equal(oidPolicy):
			if len(e.Value) != 2 {
				return nil, refuse(CodeProofInvalid, "evidence.attestation[0].policy")
			}
			ev.PIN, ev.Touch, havePolicy = e.Value[0], e.Value[1], true
		case e.Id.Equal(oidForm):
			if len(e.Value) != 1 {
				return nil, refuse(CodeProofInvalid, "evidence.attestation[0].form factor")
			}
			ev.FormFactor = e.Value[0]
		}
	}
	if !haveFW || !haveSerial || !havePolicy {
		return nil, refuse(CodeProofInvalid, "evidence.attestation[0].extensions")
	}
	// The policies are the values the contract names: PIN never, once or always (1 to 3), touch never, always or cached (1 to 3).
	if ev.PIN < PINNever || ev.PIN > PINAlways || ev.Touch < 1 || ev.Touch > 3 {
		return nil, refuse(CodeProofInvalid, "evidence.attestation[0].policy")
	}
	return ev, nil
}
