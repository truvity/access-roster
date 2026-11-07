package handoff

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
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

// appendTo adds the DER element extra at the end of the content of the SEQUENCE (or tagged element) der, and fixes its
// length: what encoding/asn1 would parse and ignore.
func appendTo(t *testing.T, der, extra []byte) []byte {
	t.Helper()
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		t.Fatal(err)
	}
	rv.FullBytes = nil
	rv.Bytes = append(bytes.Clone(rv.Bytes), extra...)
	out, err := asn1.Marshal(rv)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// verifies: REQ-PKI-046
// key@ signs exactly the bytes the builder makes: DER appended inside any of the nested elements, which encoding/asn1
// would ignore, is refused, and so is a name constraint that leaves the IP addresses unconstrained, a base of the wrong
// size or syntax, and a subject or a base above its bound.
func TestCheckInfoRefusesWhatTheParserIgnoresAndWhatIsUnbounded(t *testing.T) {
	key := newKey(t)
	spki := spkiOf(t, &key.PublicKey)
	good, err := CertificationRequestInfo(spki, testSpec())
	if err != nil {
		t.Fatal(err)
	}
	junk := []byte{0x04, 0x03, 'a', 'b', 'c'}
	// Trailing DER inside the outer SEQUENCE.
	if CheckInfo(appendTo(t, good, junk), spki) == nil {
		t.Error("an element after the attributes")
	}
	// Inside the attributes, the attribute, the value set and the extensions.
	var cri struct {
		Version    int
		Subject    asn1.RawValue
		PKInfo     asn1.RawValue
		Attributes asn1.RawValue
	}
	if _, err := asn1.Unmarshal(good, &cri); err != nil {
		t.Fatal(err)
	}
	var attr struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}
	if _, err := asn1.Unmarshal(cri.Attributes.Bytes, &attr); err != nil {
		t.Fatal(err)
	}
	rebuild := func(attributesBytes []byte) []byte {
		out, err := asn1.Marshal(struct {
			Version    int
			Subject    asn1.RawValue
			PKInfo     asn1.RawValue
			Attributes asn1.RawValue
		}{0, asn1.RawValue{FullBytes: cri.Subject.FullBytes}, asn1.RawValue{FullBytes: cri.PKInfo.FullBytes},
			asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attributesBytes}})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	oid, _ := asn1.Marshal(oidExtensionRequest)
	set := func(content []byte) []byte {
		b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: content})
		return b
	}
	seq := func(content []byte) []byte {
		b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
		return b
	}
	extsSeq := attr.Values.Bytes // the SEQUENCE OF Extension
	if CheckInfo(rebuild(append(bytes.Clone(cri.Attributes.Bytes), junk...)), spki) == nil {
		t.Error("a second attribute")
	}
	if CheckInfo(rebuild(seq(append(bytes.Clone(oid), append(set(extsSeq), junk...)...))), spki) == nil {
		t.Error("an element after the value set in the attribute")
	}
	if CheckInfo(rebuild(seq(append(bytes.Clone(oid), set(append(bytes.Clone(extsSeq), junk...))...))), spki) == nil {
		t.Error("an element after the extensions in the value set")
	}
	if CheckInfo(rebuild(seq(append(bytes.Clone(oid), set(appendTo(t, extsSeq, junk))...))), spki) == nil {
		t.Error("an element inside the extensions")
	}

	// Name constraints.
	ncCases := map[string]Constraints{}
	base := func(tag int, b []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: b}
	}
	zero8, zero32 := make([]byte, 8), make([]byte, 32)
	for name, tc := range map[string]struct{ permitted, excluded []asn1.RawValue }{
		"no IP permitted and none excluded": {[]asn1.RawValue{base(2, []byte("dev.example.org"))}, nil},
		"only IPv4 excluded":                {[]asn1.RawValue{base(2, []byte("dev.example.org"))}, []asn1.RawValue{base(7, zero8)}},
		"only IPv6 excluded":                {[]asn1.RawValue{base(2, []byte("dev.example.org"))}, []asn1.RawValue{base(7, zero32)}},
		"an IP base of 5 octets":            {[]asn1.RawValue{base(2, []byte("dev.example.org")), base(7, make([]byte, 5))}, nil},
		"an upper-case DNS base":            {[]asn1.RawValue{base(2, []byte("Dev.example.org"))}, []asn1.RawValue{base(7, zero8), base(7, zero32)}},
		"a DNS base above 253 octets":       {[]asn1.RawValue{base(2, bytes.Repeat([]byte("a"), 254))}, []asn1.RawValue{base(7, zero8), base(7, zero32)}},
		"an empty base":                     {[]asn1.RawValue{base(2, nil)}, []asn1.RawValue{base(7, zero8), base(7, zero32)}},
	} {
		_ = ncCases
		t.Run(name, func(t *testing.T) {
			nc, err := encodeNameConstraints(tc.permitted, tc.excluded)
			if err != nil {
				t.Fatal(err)
			}
			exts, _ := requestedExtensions(testSpec().Constraints)
			exts[2].Value = nc
			info, err := marshalInfo(spki, testSpec().Subject, exts)
			if err != nil {
				t.Fatal(err)
			}
			if CheckInfo(info, spki) == nil {
				t.Fatal("signed")
			}
		})
	}
	// Too many subtrees, and a subject above its bound.
	many := Constraints{}
	for i := range maxSubtrees + 1 {
		many.DNS = append(many.DNS, "h"+strings.Repeat("a", i%5)+".example.org"+"")
	}
	if info, err := CertificationRequestInfo(spki, RequestSpec{Subject: testSpec().Subject, Constraints: many}); err == nil && CheckInfo(info, spki) == nil {
		t.Error("more subtrees than the bound")
	}
	big := testSpec()
	big.Subject.CommonName = strings.Repeat("n", maxSubject)
	if info, err := CertificationRequestInfo(spki, big); err == nil && CheckInfo(info, spki) == nil {
		t.Error("a subject above its bound")
	}
	if err := CheckInfo(good, spki); err != nil {
		t.Errorf("the info the builder makes: %v", err)
	}
}

// The subject is the Name the builder makes: DER of another shape for the same attributes, or an element after the value
// of an attribute, which a parse ignores, is refused.
func TestCheckInfoRefusesASubjectThatIsNotTheBuildersName(t *testing.T) {
	key := newKey(t)
	spki := spkiOf(t, &key.PublicKey)
	exts, _ := requestedExtensions(testSpec().Constraints)
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	oid, _ := asn1.Marshal(cn)
	str := func(tag int, s string) []byte {
		b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte(s)})
		return b
	}
	wrap := func(tag int, content ...[]byte) []byte {
		b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, IsCompound: true, Bytes: bytes.Join(content, nil)})
		return b
	}
	name := func(value, junk []byte) []byte {
		return wrap(asn1.TagSequence, wrap(asn1.TagSet, wrap(asn1.TagSequence, oid, value, junk)))
	}
	for label, subject := range map[string][]byte{
		"the builder's own encoding":       name(str(asn1.TagPrintableString, "abc"), nil),
		"UTF8String for a printable value": name(str(asn1.TagUTF8String, "abc"), nil),
		"an element after the value":       name(str(asn1.TagPrintableString, "abc"), []byte{0x05, 0x00}),
	} {
		info, err := infoDER(spki, subject, exts)
		if err != nil {
			t.Fatal(err)
		}
		err = CheckInfo(info, spki)
		if label == "the builder's own encoding" {
			if err != nil {
				t.Errorf("%s: %v", label, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: signed", label)
		}
	}
}

// A request that key@ would refuse for its size is an error of the builder that names the bound.
func TestTheBuilderNamesTheBoundsKeyAtSignsWithin(t *testing.T) {
	spki := spkiOf(t, &newKey(t).PublicKey)
	many := Constraints{}
	for i := range maxSubtrees + 1 {
		many.DNS = append(many.DNS, fmt.Sprintf("h%d.example.org", i))
	}
	if err := many.Validate(); err == nil || !strings.Contains(err.Error(), "at most 64") {
		t.Errorf("Validate = %v", err)
	}
	if _, err := CertificationRequestInfo(spki, RequestSpec{Subject: testSpec().Subject, Constraints: many}); err == nil {
		t.Error("a request of 65 names was built")
	}
	big := testSpec()
	big.Subject.CommonName = strings.Repeat("n", maxSubject)
	_, err := CertificationRequestInfo(spki, big)
	if err == nil || !strings.Contains(err.Error(), "512 octets") {
		t.Errorf("a subject above the bound: %v", err)
	}
	if _, err := CertificationRequestInfo(spki, testSpec()); err != nil {
		t.Errorf("the request key@ signs: %v", err)
	}
}
