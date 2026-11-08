// Package handofftest makes test material for the hand-off: a made-up attestation hierarchy (a root, an intermediate, a
// token's own certificate) and the attestation of a PIV key under it, with every field that check 7 of the contract reads
// open to change. It is for tests only; nothing here is a key of anyone's. The extensions are those of a YubiKey 5
// (arc 1.3.6.1.4.1.41482.3, measured on firmware 5.8.0 and written in ritueel's hand-off contract, "piv").
package handofftest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Hierarchy is a made-up maker: a root, one or two levels of intermediates and the token's own certificate with its key.
type Hierarchy struct {
	Root *x509.Certificate
	// Upper is the intermediate directly under the root when there are two levels ("Yubico Attestation Intermediate B 1" in the
	// real bundle), nil when there is one.
	Upper *x509.Certificate
	// Intermediate is the one that signs the token's certificate ("Yubico PIV Attestation B2 1" in the real bundle).
	Intermediate, Token *x509.Certificate
	tokenKey            *ecdsa.PrivateKey
	Clock               time.Time
}

// Options shape a hierarchy.
type Options struct {
	// TokenNotCA makes the token's certificate a certificate that is not a CA.
	TokenNotCA bool
	// TokenPathLen is the path length of the token's certificate; 0 is what the contract requires.
	TokenPathLen int
	// TwoLevels puts an intermediate between the root and the one that signs the token's certificate, as the real bundle has.
	TwoLevels bool
	// IssuerName is the common name of the intermediate that signs the token's certificate; "Made-up PIV Attestation
	// Intermediate (TEST ONLY)" when empty.
	IssuerName string
	// TokenUnderRoot has the root sign the token's certificate itself, with no intermediate.
	TokenUnderRoot bool
	// RootName is the common name of the root; "Made-up Attestation Root (TEST ONLY)" when empty.
	RootName string
	// Years is how long every certificate of the chain lasts after the clock; 10 when 0.
	Years int
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func serial() *big.Int { return must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))) }

func issue(tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	tpl.SerialNumber = serial()
	tpl.SignatureAlgorithm = x509.ECDSAWithSHA384
	if parent == nil {
		parent = tpl
	}
	return must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer))))
}

// NewHierarchy makes a hierarchy valid around clock. tokenPathLen is the path length of the token's certificate (0 is what
// the contract requires); tokenCA false makes it a certificate that is not a CA.
func NewHierarchy(clock time.Time, tokenCA bool, tokenPathLen int) *Hierarchy {
	return NewHierarchyWith(clock, Options{TokenNotCA: !tokenCA, TokenPathLen: tokenPathLen})
}

// NewHierarchyWith makes a hierarchy valid around clock, as the options say.
func NewHierarchyWith(clock time.Time, o Options) *Hierarchy {
	k := func() *ecdsa.PrivateKey { return must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)) }
	years := o.Years
	if years == 0 {
		years = 10
	}
	win := func(tpl *x509.Certificate) *x509.Certificate {
		tpl.NotBefore, tpl.NotAfter = clock.AddDate(-1, 0, 0), clock.AddDate(years, 0, 0)
		return tpl
	}
	ca := func(cn string, pathLen int) *x509.Certificate {
		return win(&x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: pathLen})
	}
	rootKey, interKey, tokenKey := k(), k(), k()
	rootName := o.RootName
	if rootName == "" {
		rootName = "Made-up Attestation Root (TEST ONLY)"
	}
	root := issue(ca(rootName, 2), nil, &rootKey.PublicKey, rootKey)
	h := &Hierarchy{Root: root, tokenKey: tokenKey, Clock: clock}
	parent, parentKey := root, rootKey
	if o.TwoLevels {
		upperKey := k()
		h.Upper = issue(ca("Made-up Attestation Intermediate B 1 (TEST ONLY)", 1), root, &upperKey.PublicKey, rootKey)
		parent, parentKey = h.Upper, upperKey
	}
	name := o.IssuerName
	if name == "" {
		name = "Made-up PIV Attestation Intermediate (TEST ONLY)"
	}
	if o.TokenUnderRoot {
		tok := &x509.Certificate{Subject: pkix.Name{CommonName: "Made-up PIV Attestation F9 (TEST ONLY)"}, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 0, MaxPathLenZero: true}
		h.Token = issue(win(tok), root, &tokenKey.PublicKey, rootKey)
		return h
	}
	h.Intermediate = issue(ca(name, 1), parent, &interKey.PublicKey, parentKey)
	tok := &x509.Certificate{Subject: pkix.Name{CommonName: "Made-up PIV Attestation F9 (TEST ONLY)"}, BasicConstraintsValid: true, IsCA: !o.TokenNotCA}
	if !o.TokenNotCA {
		tok.KeyUsage, tok.MaxPathLen, tok.MaxPathLenZero = x509.KeyUsageCertSign, o.TokenPathLen, o.TokenPathLen == 0
	}
	h.Token = issue(win(tok), h.Intermediate, &tokenKey.PublicKey, interKey)
	return h
}

// Anchors are the certificates a certifier pins for this hierarchy: the root, and every intermediate as a helper.
func (h *Hierarchy) Anchors() (roots, intermediates []*x509.Certificate) {
	if h.Intermediate != nil {
		intermediates = append(intermediates, h.Intermediate)
	}
	if h.Upper != nil {
		intermediates = append(intermediates, h.Upper)
	}
	return []*x509.Certificate{h.Root}, intermediates
}

// Slot describes the attestation certificate of a key.
type Slot struct {
	Subject  string // the common name, "YubiKey PIV Attestation 9c" for a good one
	Firmware []byte // three raw bytes, nil for none
	Serial   *big.Int
	// RawSerial is the value of the serial extension as it is, for a certificate that carries something else; it replaces Serial.
	RawSerial  []byte
	Policy     []byte // PIN policy then touch policy, nil for none
	FormFactor []byte
	// Window is the validity of the slot certificate, as offsets from the clock in years (before, after); nil for -1 and +10.
	Window *[2]int
}

// GoodSlot is the attestation of a key in slot 9c of a YubiKey 5 with firmware 5.8.0, PIN policy once, touch never.
func GoodSlot(slot string, serial int64) Slot {
	return Slot{Subject: "YubiKey PIV Attestation " + slot, Firmware: []byte{5, 8, 0}, Serial: big.NewInt(serial), Policy: []byte{2, 1}, FormFactor: []byte{3}}
}

// Attest returns the attestation of pub as a card makes it: the slot certificate, then the token's own certificate.
func (h *Hierarchy) Attest(pub *ecdsa.PublicKey, s Slot) [][]byte {
	var exts []pkix.Extension
	add := func(oid asn1.ObjectIdentifier, v []byte) {
		if v != nil {
			exts = append(exts, pkix.Extension{Id: oid, Value: v})
		}
	}
	add(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}, s.Firmware)
	switch {
	case s.RawSerial != nil:
		add(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}, s.RawSerial)
	case s.Serial != nil:
		add(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}, must(asn1.Marshal(s.Serial)))
	}
	add(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}, s.Policy)
	add(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}, s.FormFactor)
	from, to := -1, 10
	if s.Window != nil {
		from, to = s.Window[0], s.Window[1]
	}
	tpl := &x509.Certificate{Subject: pkix.Name{CommonName: s.Subject}, NotBefore: h.Clock.AddDate(from, 0, 0), NotAfter: h.Clock.AddDate(to, 0, 0), ExtraExtensions: exts}
	leaf := issue(tpl, h.Token, pub, h.tokenKey)
	return [][]byte{leaf.Raw, h.Token.Raw}
}
