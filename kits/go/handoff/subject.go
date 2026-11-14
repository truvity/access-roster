package handoff

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// maxCommonName is the upper bound of a common name in RFC 5280, Appendix A.1, counted in characters; the contract holds a
// subject to it ("The request", the attribute table).
const maxCommonName = 64

// ValidCommonName checks a common name as the contract's subject rules do ("The request"): at least one character and at
// most 64, every character printable ASCII (U+0020 to U+007E), no space at the start or the end, and no two spaces in a row.
// The error names the rule, never the value.
func ValidCommonName(s string) error {
	if len(s) > maxCommonName {
		return fmt.Errorf("handoff: the common name has more than %d characters", maxCommonName)
	}
	return validText(s)
}

// validText is the text rule of every value of a subject: not empty, every character printable ASCII, no space at either end
// and no two in a row.
func validText(s string) error {
	switch {
	case s == "":
		return errors.New("handoff: the common name is empty")
	case s[0] == ' ' || s[len(s)-1] == ' ':
		return errors.New("handoff: the common name starts or ends with a space")
	case strings.Contains(s, "  "):
		return errors.New("handoff: the common name has two spaces in a row")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return errors.New("handoff: the common name has a character outside printable ASCII")
		}
	}
	return nil
}

// printableString reports whether every character of s is in the alphabet of a PrintableString (X.680, section 41):
// letters, digits, space and '()+,-./:=?. So _ @ ! ; * and & are not.
func printableString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ' ':
		case strings.IndexByte("'()+,-./:=?", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// commonNameName is the DER Name of a subject with one relative name that holds one common name, written as the contract asks:
// a PrintableString when the value fits its alphabet and a UTF8String when it does not (both are allowed; the choice is fixed, so
// that CheckInfo can build the same bytes again).
func commonNameName(cn string) ([]byte, error) {
	if err := ValidCommonName(cn); err != nil {
		return nil, err
	}
	tag := asn1.TagUTF8String
	if printableString(cn) {
		tag = asn1.TagPrintableString
	}
	atv, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidCommonName, asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte(cn)}})
	if err != nil {
		return nil, err
	}
	rdn, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: atv})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: rdn})
}

// subjectDER is the Name of a request. The subject of this version is one common name: a name with any other attribute is
// refused, because the library's own writer puts several organisational units into one relative name and writes a domain
// component as a PrintableString, both of which the contract refuses.
func subjectDER(n pkix.Name) ([]byte, error) {
	if len(n.Country)+len(n.Organization)+len(n.OrganizationalUnit)+len(n.Locality)+len(n.Province)+len(n.StreetAddress)+len(n.PostalCode) != 0 ||
		n.SerialNumber != "" || len(n.ExtraNames) != 0 {
		return nil, errors.New("handoff: the subject of a request is a common name and nothing else")
	}
	return commonNameName(n.CommonName)
}

// EqualsRoot reports whether the subject (a DER Name) or the key (a DER SubjectPublicKeyInfo) of a request is that of one of
// the root certificates: a name equal as OpenSSL compares names, or the same key. The contract's certifier refuses both with
// `policy` ("The request"): a key of a root in a request gives a second certificate for the root's key, and a name of a root
// in a request gives a name that a verifier takes for the root's.
func EqualsRoot(subject, spki []byte, roots []*x509.Certificate) bool {
	for _, r := range roots {
		if bytes.Equal(spki, r.RawSubjectPublicKeyInfo) || SameName(subject, r.RawSubject) {
			return true
		}
	}
	return false
}

// SameName compares two DER Names as OpenSSL 3.5 does (X509_NAME_cmp, read 2026-11-14 by the contract): without regard to case
// (ASCII), with a run of spaces as one space and none at the ends, whatever the string type, relative name by relative name.
// A name that does not parse is equal to nothing.
func SameName(a, b []byte) bool {
	ca, ok := canonName(a)
	if !ok {
		return false
	}
	cb, ok := canonName(b)
	return ok && ca == cb
}

func canonName(der []byte) (string, bool) {
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) != 0 {
		return "", false
	}
	var out []string
	for _, rdn := range seq {
		var parts []string
		for _, atv := range rdn {
			v := fmt.Sprintf("%v", atv.Value)
			if s, ok := atv.Value.(string); ok {
				v = canonText(s)
			}
			parts = append(parts, atv.Type.String()+"="+v)
		}
		sort.Strings(parts)
		out = append(out, strings.Join(parts, "+"))
	}
	return strings.Join(out, "/"), true
}

func canonText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}
