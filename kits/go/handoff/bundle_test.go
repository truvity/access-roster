package handoff

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
)

// selfSignedV1 makes a self-signed version 1 certificate of k: a certificate with no version field, no extensions and so no
// basic constraints. Go's x509 writes only version 3, so the TBS is marshalled by hand.
func selfSignedV1(t *testing.T, k *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()
	type tbsCertificate struct {
		Serial    *big.Int
		Algorithm pkix.AlgorithmIdentifier
		Issuer    asn1.RawValue
		Validity  struct{ NotBefore, NotAfter asn1.RawValue }
		Subject   asn1.RawValue
		SPKI      asn1.RawValue
	}
	alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}} // ecdsa-with-SHA256
	name, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := asn1.Marshal(testNow.AddDate(-1, 0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	na, err := asn1.Marshal(testNow.AddDate(5, 0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	tbs := tbsCertificate{
		Serial:    big.NewInt(1),
		Algorithm: alg,
		Issuer:    asn1.RawValue{FullBytes: name},
		Subject:   asn1.RawValue{FullBytes: name},
		SPKI:      asn1.RawValue{FullBytes: spki},
	}
	tbs.Validity.NotBefore = asn1.RawValue{FullBytes: nb}
	tbs.Validity.NotAfter = asn1.RawValue{FullBytes: na}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbsDER}, alg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A CA bundle certificate must be a version 3 CA certificate with basic constraints: a version 1 certificate of a listed key,
// and a version 3 one of a listed key that has no basic constraints, are each refused as ca-bundle-mismatch, and the same
// key with the basic constraints present is accepted.
func TestCheckBundleNeedsAVersionThreeCACertificate(t *testing.T) {
	k := newKey(t)
	v1 := selfSignedV1(t, k, "Root A")
	c1, err := x509.ParseCertificate(v1)
	if err != nil {
		t.Fatalf("the version 1 test certificate does not parse: %v", err)
	}
	if c1.Version != 1 {
		t.Fatalf("test certificate version = %d, want 1", c1.Version)
	}
	list := func(der []byte) *RootList {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return &RootList{Sequence: 7, Roots: []Root{{Label: "A", X509SPKISHA256: SPKIPin(c)}}}
	}
	bundle := func(der []byte) []byte {
		return append([]byte("# trust-sequence: 7\n"), certPEM(der)...)
	}

	assertCode(t, CheckBundle(bundle(v1), list(v1)), CodeCABundleMismatch)

	// The same key, version 3, with the key usage of a CA and no basic constraints.
	noBC := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Root A"},
		NotBefore: testNow.AddDate(-1, 0, 0), NotAfter: testNow.AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, noBC, noBC, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	assertCode(t, CheckBundle(bundle(der), list(der)), CodeCABundleMismatch)

	// The positive control: the same kind of certificate with basic constraints passes.
	ca := newRoot(t, "Root A")
	if err := CheckBundle(bundle(ca.der), list(ca.der)); err != nil {
		t.Fatalf("a version 3 CA with basic constraints: %v", err)
	}
}
