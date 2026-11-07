package tokencert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/tokencert"
)

// A serial number is a random 128-bit number: 121 to 128 significant bits, written as a positive DER INTEGER with no
// superfluous octet, and no two of a thousand are alike (the draws are real random values).
func TestNewSerialIsRandom128Bits(t *testing.T) {
	seen := map[string]bool{}
	high := 0
	for range 1000 {
		s, err := tokencert.NewSerial(nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(s)] {
			t.Fatal("two equal serial numbers in a thousand")
		}
		seen[string(s)] = true
		n := new(big.Int).SetBytes(s)
		if n.BitLen() < 121 || n.BitLen() > 128 || s[0]&0x80 != 0 || (len(s) > 1 && s[0] == 0 && s[1]&0x80 == 0) {
			t.Fatalf("serial %x: %d bits, not a minimal positive INTEGER", s, n.BitLen())
		}
		if n.BitLen() == 128 {
			high++
		}
	}
	// Half of the draws have the high bit set (and a zero octet in front). A source that fixed it would show.
	if high < 400 || high > 600 {
		t.Fatalf("%d of 1000 serial numbers use all 128 bits, want about half", high)
	}
}

// The builder's certificate is read by the standard library as the profile, and refused years it cannot write.
func TestBuilderMakesTheProfile(t *testing.T) {
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now().UTC()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Intermediate (TEST ONLY)"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ik.PublicKey, ik)
	inter, _ := x509.ParseCertificate(der)
	spki, _ := x509.MarshalPKIXPublicKey(&tk.PublicKey)
	serial, _ := tokencert.NewSerial(nil)
	p := tokencert.Params{Serial: serial, Issuer: inter.RawSubject, SPKI: spki, Boundary: "dev", NotBefore: now.Add(-time.Minute), NotAfter: inter.NotAfter}
	tbs, err := tokencert.TBS(p)
	if err != nil {
		t.Fatal(err)
	}
	d := sha512.Sum384(tbs)
	sig, _ := ecdsa.SignASN1(rand.Reader, ik, d[:])
	c, err := x509.ParseCertificate(tokencert.Assemble(tbs, sig))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckSignatureFrom(inter); err != nil {
		t.Fatal(err)
	}
	if c.IsCA || c.KeyUsage != x509.KeyUsageDigitalSignature || c.SerialNumber.Cmp(new(big.Int).SetBytes(serial)) != 0 || c.Subject.CommonName != tokencert.SubjectCommonName {
		t.Fatalf("not the profile: %+v", c)
	}
	p.NotAfter = time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := tokencert.TBS(p); err == nil {
		t.Error("a validity past 2049 was written")
	}
	p.NotAfter, p.Boundary = inter.NotAfter, ""
	if _, err := tokencert.TBS(p); err == nil {
		t.Error("a certificate with no boundary was built")
	}
}
