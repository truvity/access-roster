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

// Hierarchy is a made-up maker: root, intermediate and the token's own certificate with its key.
type Hierarchy struct {
	Root, Intermediate, Token *x509.Certificate
	tokenKey                  *ecdsa.PrivateKey
	Clock                     time.Time
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
	k := func() *ecdsa.PrivateKey { return must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)) }
	rootKey, interKey, tokenKey := k(), k(), k()
	win := func(tpl *x509.Certificate) *x509.Certificate {
		tpl.NotBefore, tpl.NotAfter = clock.AddDate(-1, 0, 0), clock.AddDate(10, 0, 0)
		return tpl
	}
	root := issue(win(&x509.Certificate{Subject: pkix.Name{CommonName: "Made-up Attestation Root (TEST ONLY)"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}), nil, &rootKey.PublicKey, rootKey)
	inter := issue(win(&x509.Certificate{Subject: pkix.Name{CommonName: "Made-up PIV Attestation Intermediate (TEST ONLY)"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 1}), root, &interKey.PublicKey, rootKey)
	tok := &x509.Certificate{Subject: pkix.Name{CommonName: "Made-up PIV Attestation F9 (TEST ONLY)"}, BasicConstraintsValid: true, IsCA: tokenCA}
	if tokenCA {
		tok.KeyUsage, tok.MaxPathLen, tok.MaxPathLenZero = x509.KeyUsageCertSign, tokenPathLen, tokenPathLen == 0
	}
	token := issue(win(tok), inter, &tokenKey.PublicKey, interKey)
	return &Hierarchy{Root: root, Intermediate: inter, Token: token, tokenKey: tokenKey, Clock: clock}
}

// Slot describes the attestation certificate of a key.
type Slot struct {
	Subject    string // the common name, "YubiKey PIV Attestation 9c" for a good one
	Firmware   []byte // three raw bytes, nil for none
	Serial     *big.Int
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
	if s.Serial != nil {
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
