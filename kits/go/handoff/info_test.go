package handoff

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"
)

// key@ signs only the shape this package builds, for its own key.
func TestCheckInfo(t *testing.T) {
	key := newKey(t)
	spki := spkiOf(t, &key.PublicKey)
	info, err := CertificationRequestInfo(spki, testSpec())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckInfo(info, spki); err != nil {
		t.Fatalf("the info this package builds: %v", err)
	}
	other := spkiOf(t, &newKey(t).PublicKey)
	if err := CheckInfo(info, other); err == nil {
		t.Error("an info for another key")
	}
	if err := CheckInfo(append(bytes.Clone(info), 0), spki); err == nil {
		t.Error("trailing data")
	}
	if err := CheckInfo(info[:len(info)-1], spki); err == nil {
		t.Error("truncated")
	}
	if err := CheckInfo(nil, spki); err == nil {
		t.Error("empty")
	}
	// A TBSCertificate is not an info.
	root := newRoot(t, "Root")
	cert := issue(t, root, makeRequest(t, key, testSpec()), testNow, testNow.AddDate(0, 13, 0), nil)
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckInfo(parsed.RawTBSCertificate, spki); err == nil {
		t.Error("a TBSCertificate was taken for an info")
	}
}

// A request that differs from the profile in any extension is not signed.
func TestCheckInfoRefusesAChangedProfile(t *testing.T) {
	key := newKey(t)
	spki := spkiOf(t, &key.PublicKey)
	good, err := requestedExtensions(testSpec().Constraints)
	if err != nil {
		t.Fatal(err)
	}
	noncritical := func(i int) []pkix.Extension {
		e := slices.Clone(good)
		e[i].Critical = false
		return e
	}
	withValue := func(i int, v []byte) []pkix.Extension {
		e := slices.Clone(good)
		e[i].Value = v
		return e
	}
	pathLen1, _ := asn1.Marshal(struct {
		CA      bool
		MaxPath int
	}{true, 1})
	noCA, _ := asn1.Marshal(struct{}{})
	sign, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
	emptyNC, _ := asn1.Marshal(struct {
		Excluded []asn1.RawValue `asn1:"tag:1,optional"`
	}{[]asn1.RawValue{{FullBytes: mustDER(t, struct{ Base asn1.RawValue }{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: []byte{0, 0, 0, 0, 0, 0, 0, 0}}})}}})
	rfc822, _ := asn1.Marshal(struct {
		Permitted []asn1.RawValue `asn1:"tag:0,optional"`
	}{[]asn1.RawValue{{FullBytes: mustDER(t, struct{ Base asn1.RawValue }{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("a@b")}})}}})
	for name, exts := range map[string][]pkix.Extension{
		"basic constraints not critical": noncritical(0),
		"key usage not critical":         noncritical(1),
		"name constraints not critical":  noncritical(2),
		"path length 1":                  withValue(0, pathLen1),
		"not a CA":                       withValue(0, noCA),
		"key usage digitalSignature":     withValue(1, sign),
		"no permitted subtree":           withValue(2, emptyNC),
		"an e-mail constraint":           withValue(2, rfc822),
		"no name constraints":            good[:2],
		"another extension":              append(slices.Clone(good), pkix.Extension{Id: testOID, Value: []byte{5, 0}}),
		"order changed":                  {good[1], good[0], good[2]},
	} {
		t.Run(name, func(t *testing.T) {
			info, err := marshalInfo(spki, testSpec().Subject, exts)
			if err != nil {
				t.Fatal(err)
			}
			if CheckInfo(info, spki) == nil {
				t.Fatal("signed")
			}
		})
	}
	good2, _ := marshalInfo(spki, testSpec().Subject, good)
	if err := CheckInfo(good2, spki); err != nil {
		t.Fatalf("the unchanged profile: %v", err)
	}
	// A version other than 0.
	bad := bytes.Clone(good2)
	for i := 0; i+2 < 12 && i < len(bad); i++ {
		if bad[i] == 0x02 && bad[i+1] == 0x01 && bad[i+2] == 0x00 {
			bad[i+2] = 0x01
		}
	}
	if CheckInfo(bad, spki) == nil {
		t.Error("version 1")
	}
}

func mustDER(t testing.TB, v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
