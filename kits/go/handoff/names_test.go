package handoff

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
)

// The form of a DNS name and of a URI constraint, as the contract's "The names in the name constraints" states it.
func TestNamesFollowTheContractsForm(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := strings.Join([]string{label63, label63, label63, strings.Repeat("a", 61)}, ".") // 63*3 + 61 + 3 periods
	if len(name253) != 253 {
		t.Fatalf("the test name has %d characters", len(name253))
	}
	for name, tc := range map[string]struct {
		dns, uri bool
	}{
		"example.org":             {true, true},
		"a":                       {true, true},
		"a-b.example.org":         {true, true},
		"0a.example.org":          {true, true},
		"example.1a":              {true, true}, // the last label is not all digits
		label63 + ".org":          {true, true},
		name253:                   {true, true},
		".example.org":            {false, true}, // a period and a domain: a URI constraint only
		"":                        {false, false},
		".":                       {false, false},
		"..example.org":           {false, false},
		"example.org.":            {false, false},
		"a..example.org":          {false, false},
		"Example.org":             {false, false},
		"*.example.org":           {false, false},
		"-a.example.org":          {false, false},
		"a-.example.org":          {false, false},
		"a_b.example.org":         {false, false},
		"example.123":             {false, false}, // a numeric last label
		"198.51.100.1":            {false, false},
		"1":                       {false, false},
		label63 + "a.example.org": {false, false}, // a label of 64
		name253 + "a":             {false, false}, // 254 characters
		"https://example.org":     {false, false},
		"example.org:8080":        {false, false},
		"example.org/ca":          {false, false},
		"a b.example.org":         {false, false},
		"bücher.example.org":      {false, false},
		"." + name253:             {false, true}, // the period at the start does not count
		"." + name253 + "a":       {false, false},
	} {
		if got := ValidDNSName(name); got != tc.dns {
			t.Errorf("ValidDNSName(%.40q) = %v, want %v", name, got, tc.dns)
		}
		if got := ValidURIHost(name); got != tc.uri {
			t.Errorf("ValidURIHost(%.40q) = %v, want %v", name, got, tc.uri)
		}
	}
	// The constraints the builder takes are held to the same form.
	for _, c := range []Constraints{
		{DNS: []string{"example.123"}}, {DNS: []string{"-a.example.org"}}, {DNS: []string{"a-.example.org"}},
		{URIHosts: []string{"example.123"}}, {URIHosts: []string{"https://example.org"}}, {DNS: []string{".example.org"}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("constraints %+v were accepted", c)
		}
	}
	for _, c := range []Constraints{{URIHosts: []string{".example.org"}}, {DNS: []string{label63 + ".org"}}, {URIHosts: []string{"sluis.example"}}} {
		if err := c.Validate(); err != nil {
			t.Errorf("constraints %+v: %v", c, err)
		}
	}
}

// The common name that `sluis key request` writes follows the contract's subject rules.
func TestCommonNameRules(t *testing.T) {
	for name, ok := range map[string]bool{
		"sluis dev intermediate": true,
		"a":                      true,
		strings.Repeat("n", 64):  true,
		"a_b @ c; d! (e) f*g&h":  true, // printable ASCII, written as a UTF8String
		"":                       false,
		strings.Repeat("n", 65):  false,
		" leading":               false,
		"trailing ":              false,
		"two  spaces":            false,
		"tab\there":              false,
		"new\nline":              false,
		"aä":                     false,
		"аpple":                  false, // a Cyrillic a
		"del\x7f":                false,
		"zero\u200bwidth":        false,
	} {
		if err := ValidCommonName(name); (err == nil) != ok {
			t.Errorf("ValidCommonName(%q) = %v, want ok %v", name, err, ok)
		}
	}
}

// The subject that is written is the contract's: one relative name holding one common name, a PrintableString when the value fits
// its alphabet and a UTF8String when it does not (`_`, `@`, `!`, `;`, `*` and `&` are outside it), and an attribute that the
// builder cannot write correctly is refused.
func TestSubjectIsWrittenAsTheContractAsks(t *testing.T) {
	spki := spkiOf(t, &newKey(t).PublicKey)
	for cn, tag := range map[string]int{"sluis dev intermediate": asn1.TagPrintableString, "sluis a_b intermediate": asn1.TagUTF8String, "x@y": asn1.TagUTF8String} {
		spec := testSpec()
		spec.Subject = pkix.Name{CommonName: cn}
		info, err := CertificationRequestInfo(spki, spec)
		if err != nil {
			t.Fatalf("%q: %v", cn, err)
		}
		if err := CheckInfo(info, spki); err != nil {
			t.Errorf("%q: key@ would not sign it: %v", cn, err)
		}
		r, err := ParseRequest(append([]byte(nil), mustAssemble(t, info)...))
		if err != nil {
			t.Fatalf("%q: %v", cn, err)
		}
		if err := CheckRequestProfile(r); err != nil {
			t.Errorf("%q: the contract's profile refuses what sluis writes: %v", cn, err)
		}
		name, err := readOne(r.Subject)
		if err != nil {
			t.Fatal(err)
		}
		rdns, err := readSubject(name)
		if err != nil || len(rdns) != 1 || len(rdns[0]) != 1 || rdns[0][0].value.tag != tag || !rdns[0][0].oid.Equal(oidCommonName) {
			t.Errorf("%q: subject %+v, want one common name of tag %d", cn, rdns, tag)
		}
	}
	// A name with another attribute is not written: the library would put several units into one relative name.
	for name, n := range map[string]pkix.Name{
		"an organisation":    {CommonName: "x", Organization: []string{"acme"}},
		"two units":          {CommonName: "x", OrganizationalUnit: []string{"a", "b"}},
		"a country":          {CommonName: "x", Country: []string{"NL"}},
		"a serial number":    {CommonName: "x", SerialNumber: "1"},
		"an extra name":      {CommonName: "x", ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidDomainComponent, Value: "org"}}},
		"no common name":     {},
		"a long common name": {CommonName: strings.Repeat("n", 65)},
	} {
		spec := testSpec()
		spec.Subject = n
		if _, err := CertificationRequestInfo(spki, spec); err == nil {
			t.Errorf("%s: a request was written", name)
		}
	}
}

func mustAssemble(t *testing.T, info []byte) []byte {
	t.Helper()
	key := newKey(t)
	_ = key
	der, err := AssembleCSR(info, []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A request whose subject or key is that of a root of the bundle is not written, and the comparison is OpenSSL's: without regard
// to case, with a run of spaces as one, whatever the string type.
func TestARequestIsNotWrittenForTheNameOrKeyOfARoot(t *testing.T) {
	root := newRoot(t, "Example Root")
	otherKey := newKey(t)
	spec := testSpec()
	spec.Roots = []*x509.Certificate{root.cert}
	spki := spkiOf(t, &otherKey.PublicKey)
	if _, err := CertificationRequestInfo(spki, spec); err != nil {
		t.Fatalf("a request for a name and a key that are no root's: %v", err)
	}
	for _, cn := range []string{"Example Root", "EXAMPLE ROOT", "example root"} {
		s := spec
		s.Subject = pkix.Name{CommonName: cn}
		if _, err := CertificationRequestInfo(spki, s); err == nil {
			t.Errorf("the name of the root %q was written", cn)
		}
	}
	if _, err := CertificationRequestInfo(spkiOf(t, &root.key.PublicKey), spec); err == nil {
		t.Error("the key of the root was written")
	}
	// The comparison itself, on names a library would not write.
	utf8Name := mustName(t, asn1.TagUTF8String, "Example   Root")
	if !SameName(utf8Name, root.cert.RawSubject) {
		t.Error("a run of spaces is one space, and the string type does not matter")
	}
	if SameName(mustName(t, asn1.TagUTF8String, "Example Roots"), root.cert.RawSubject) {
		t.Error("another name is the same")
	}
	if SameName([]byte{0x30, 0x00, 0x01}, root.cert.RawSubject) || SameName(nil, nil) {
		t.Error("a name that does not parse is equal to nothing")
	}
}

func mustName(t *testing.T, tag int, cn string) []byte {
	t.Helper()
	atv, _ := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidCommonName, asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte(cn)}})
	rdn, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: atv})
	out, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: rdn})
	if !bytes.Equal(out[:1], []byte{0x30}) {
		t.Fatal("not a name")
	}
	return out
}
