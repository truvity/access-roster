package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

type chainSet struct {
	root, inter, leaf *x509.Certificate
	leafKey           *ecdsa.PrivateKey
	pin               string
}

func newChain(t *testing.T, mod func(*x509.Certificate)) chainSet {
	t.Helper()
	now := time.Now()
	rk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	lk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	mk := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Root (TEST ONLY)"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := mk(rt, rt, &rk.PublicKey, rk)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Example Intermediate (TEST ONLY)"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	inter := mk(it, root, &ik.PublicKey, rk)
	lt := &x509.Certificate{SerialNumber: new(big.Int).Rsh(big.NewInt(1).Lsh(big.NewInt(1), 127), 3), Subject: pkix.Name{CommonName: "token-signing"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if mod != nil {
		mod(lt)
	}
	leaf := mk(lt, inter, &lk.PublicKey, ik)
	sum := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	return chainSet{root, inter, leaf, lk, hex.EncodeToString(sum[:])}
}

func (c chainSet) doc(chain ...*x509.Certificate) []byte {
	var x5c []string
	for _, k := range chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(k.Raw))
	}
	pt, _ := c.leafKey.PublicKey.Bytes() // 0x04, X and Y of 48 octets each
	e := map[string]any{"kty": "EC", "crv": "P-384", "kid": "kid-1",
		"x": base64.RawURLEncoding.EncodeToString(pt[1:49]), "y": base64.RawURLEncoding.EncodeToString(pt[49:])}
	if x5c != nil {
		e["x5c"] = x5c
	}
	b, _ := json.Marshal(map[string]any{"keys": []any{e}})
	return b
}

// verifies: REQ-PKI-034
// A key set whose entry carries the token certificate, the intermediate and the root passes, with the serial number and the end;
// each way of being something else is refused, so that the check on the running installation says something.
func TestTheCheckPassesTheRealChainAndRefusesEveryOtherShape(t *testing.T) {
	c := newChain(t, nil)
	reports, err := Check(c.doc(c.leaf, c.inter, c.root), c.pin, time.Now())
	if err != nil || len(reports) != 1 || reports[0].Chain != 3 || reports[0].Serial == "" {
		t.Fatalf("%v, %+v", err, reports)
	}
	other := newChain(t, nil)
	bad := map[string][]byte{
		"no chain":              c.doc(),
		"the leaf alone":        c.doc(c.leaf),
		"no root":               c.doc(c.leaf, c.inter),
		"another root's pin":    other.doc(other.leaf, other.inter, other.root),
		"a chain that is wrong": c.doc(c.leaf, other.inter, c.root),
		"a root first":          c.doc(c.root, c.inter, c.leaf),
		"not JSON":              []byte("{"),
		"no keys":               []byte(`{"keys":[]}`),
	}
	for name, doc := range bad {
		if _, err := Check(doc, c.pin, time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A leaf that is a CA, one that allows more than a signature, and one with a name.
	for name, mod := range map[string]func(*x509.Certificate){
		"a CA":       func(l *x509.Certificate) { l.IsCA = true; l.KeyUsage |= x509.KeyUsageCertSign },
		"two usages": func(l *x509.Certificate) { l.KeyUsage |= x509.KeyUsageKeyEncipherment },
		"an EKU":     func(l *x509.Certificate) { l.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"a DNS name": func(l *x509.Certificate) { l.DNSNames = []string{"a.example.org"} },
		"has expired": func(l *x509.Certificate) {
			l.NotBefore = time.Now().AddDate(-2, 0, 0)
			l.NotAfter = time.Now().AddDate(-1, 0, 0)
		},
	} {
		b := newChain(t, mod)
		if _, err := Check(b.doc(b.leaf, b.inter, b.root), b.pin, time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A pin that is not the root's.
	if _, err := Check(c.doc(c.leaf, c.inter, c.root), other.pin, time.Now()); err == nil {
		t.Error("another pin: accepted")
	}
	// The entry's key is the leaf's key: a chain for another key is refused.
	swapped := c.doc(c.leaf, c.inter, c.root)
	var set map[string][]map[string]any
	_ = json.Unmarshal(swapped, &set)
	opt, _ := other.leafKey.PublicKey.Bytes()
	set["keys"][0]["x"] = base64.RawURLEncoding.EncodeToString(opt[1:49])
	swapped, _ = json.Marshal(set)
	if _, err := Check(swapped, c.pin, time.Now()); err == nil {
		t.Error("an entry whose key is not the certificate's: accepted")
	}
}
