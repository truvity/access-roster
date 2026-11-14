package handoff

import (
	"bytes"
	"encoding/asn1"
	"unicode/utf8"
)

// The content of a request that the contract calls `policy` (check 9, "The code of a request that is refused for its form or
// its content"): the text and the string types of the subject, every extension and its value, and the names of the name
// constraints. The structure of a request is ParseRequest's.

// attribute types of a subject (RFC 5280, Appendix A) that carry a rule of their own.
var (
	oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidEmailAddress    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidCountry         = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidSerialNumber    = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidDNQualifier     = asn1.ObjectIdentifier{2, 5, 4, 46}
	oidOrgUnit         = asn1.ObjectIdentifier{2, 5, 4, 11}
)

// upperBound is the upper bound of RFC 5280, Appendix A.1, of the attribute types it names, in characters; 0 is none.
func upperBound(oid asn1.ObjectIdentifier) int {
	switch oid.String() {
	case "2.5.4.3", "2.5.4.10", "2.5.4.11", "2.5.4.12", "2.5.4.5": // common name, organisation, unit, title, serial number
		return 64
	case "2.5.4.7", "2.5.4.8", "2.5.4.65": // locality, state or province, pseudonym
		return 128
	case "2.5.4.41", "2.5.4.4", "2.5.4.42", "2.5.4.43", "2.5.4.44": // name, surname, given name, initials, generation qualifier
		return 32768
	case "1.2.840.113549.1.9.1": // e-mail address
		return 255
	}
	return 0
}

type atv struct {
	oid   asn1.ObjectIdentifier
	value element
}

// readSubject reads the Name element into its relative names, and fails on a fault of form: a name or a relative name that is
// empty, a relative name whose attributes are not in DER order, an attribute that is not a type and one value, a value that is
// constructed or of a class other than universal, and bytes after the value.
func readSubject(name element) ([][]atv, error) {
	if !name.universal(asn1.TagSequence, true) {
		return nil, errDER
	}
	rdns, err := readAll(name.content)
	if err != nil || len(rdns) == 0 {
		return nil, errDER
	}
	var out [][]atv
	for _, rdn := range rdns {
		if !rdn.universal(asn1.TagSet, true) {
			return nil, errDER
		}
		members, err := readAll(rdn.content)
		if err != nil || len(members) == 0 || !derOrdered(members) {
			return nil, errDER
		}
		var list []atv
		for _, m := range members {
			if !m.universal(asn1.TagSequence, true) {
				return nil, errDER
			}
			f, err := readAll(m.content)
			if err != nil || len(f) != 2 {
				return nil, errDER
			}
			oid, ok := oidOf(f[0])
			if !ok || f[1].class != asn1.ClassUniversal || f[1].constructed {
				return nil, errDER
			}
			list = append(list, atv{oid, f[1]})
		}
		out = append(out, list)
	}
	return out, nil
}

func checkSubjectForm(name element) error {
	_, err := readSubject(name)
	return err
}

// CheckSubject checks the text, the string types and the repeats of a subject (a DER Name that ParseRequest has read) against
// the contract: a fault is `policy`. Every value is a PrintableString or a UTF8String of at least one character, except a domain
// component and an e-mail address, which are IA5Strings, and a country, a serial number and a distinguished name qualifier, which
// are PrintableStrings (a country of exactly two characters). Every character is printable ASCII (U+0020 to U+007E), with no
// space at the start or the end and no two in a row; a PrintableString holds only the characters of its alphabet. The upper
// bounds of RFC 5280, Appendix A.1, hold, in characters. An attribute type stands once in a subject, except an organisational unit and
// a domain component, which may stand again in a relative name of their own, never twice in one.
func CheckSubject(der []byte) error {
	bad := func(at string) error { return refuse("policy", "subject."+at) }
	name, err := readOne(der)
	if err != nil {
		return refuse(CodeMalformed, "subject")
	}
	rdns, err := readSubject(name)
	if err != nil {
		return refuse(CodeMalformed, "subject")
	}
	seen := map[string]bool{}
	for _, rdn := range rdns {
		inRDN := map[string]bool{}
		for _, a := range rdn {
			key := a.oid.String()
			if inRDN[key] {
				return bad("repeat")
			}
			inRDN[key] = true
			if seen[key] && !a.oid.Equal(oidOrgUnit) && !a.oid.Equal(oidDomainComponent) {
				return bad("repeat")
			}
			seen[key] = true
			if err := checkValue(a); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkValue(a atv) error {
	bad := func(at string) error { return refuse("policy", "subject."+at) }
	var want []int // the string types the attribute may have
	switch {
	case a.oid.Equal(oidDomainComponent), a.oid.Equal(oidEmailAddress):
		want = []int{asn1.TagIA5String}
	case a.oid.Equal(oidCountry), a.oid.Equal(oidSerialNumber), a.oid.Equal(oidDNQualifier):
		want = []int{asn1.TagPrintableString}
	default:
		want = []int{asn1.TagPrintableString, asn1.TagUTF8String}
	}
	tag := a.value.tag
	ok := false
	for _, w := range want {
		ok = ok || w == tag
	}
	if !ok {
		return bad("type")
	}
	s := a.value.content
	if !utf8.Valid(s) {
		return bad("text")
	}
	text := string(s)
	if text == "" {
		return bad("empty")
	}
	if err := validText(text); err != nil {
		return bad("text")
	}
	if tag == asn1.TagPrintableString && !printableString(text) {
		return bad("alphabet")
	}
	n := utf8.RuneCountInString(text)
	if a.oid.Equal(oidCountry) && n != 2 {
		return bad("country")
	}
	if b := upperBound(a.oid); b != 0 && n > b {
		return bad("bound")
	}
	return nil
}

// CheckRequestProfile checks what a request asks for against the contract's profile of an intermediate (the page's "The
// request"): the subject (CheckSubject) and the extensions. The extensions are exactly these four, each once: basic constraints
// (critical; cA true, path length 0), key usage (critical; keyCertSign, and cRLSign and digitalSignature may be added), name
// constraints (critical; at least one permitted subtree, each a DNS name or a URI constraint in the contract's form, a subtree of its
// base alone; excluded subtrees none, or exactly 0.0.0.0/0 and ::/0) and extended key usage (not critical; serverAuth, clientAuth or
// both, each once). Another extension, a value that is not DER or not this one, a repeated extension and a missing one are
// `policy`. The names are not compared with a list: that is the certifier's own policy.
func CheckRequestProfile(r *Request) error {
	bad := func(at string) error { return refuse("policy", at) }
	if err := CheckSubject(r.Subject); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, e := range r.Extensions {
		id := e.ID.String()
		if seen[id] {
			return bad("extension " + id + " twice")
		}
		seen[id] = true
		var ok bool
		switch {
		case e.ID.Equal(oidBasicConstraints):
			ok = e.Critical && bytes.Equal(e.Value, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00})
		case e.ID.Equal(oidKeyUsage):
			ok = e.Critical && keyUsageOK(e.Value)
		case e.ID.Equal(oidNameConstraints):
			ok = e.Critical && NameConstraintsOK(e.Value)
		case e.ID.Equal(oidExtKeyUsage):
			ok = !e.Critical && ekuOK(e.Value)
		}
		if !ok {
			return bad("extension " + id)
		}
	}
	for _, id := range []asn1.ObjectIdentifier{oidBasicConstraints, oidKeyUsage, oidNameConstraints, oidExtKeyUsage} {
		if !seen[id.String()] {
			return bad("extension " + id.String() + " missing")
		}
	}
	return nil
}

// keyUsageOK reads a key usage BIT STRING in DER (no trailing zero bit, as a named bit string) and accepts keyCertSign (bit 5)
// with, beside it, cRLSign (bit 6) and digitalSignature (bit 0), and no other bit.
func keyUsageOK(v []byte) bool {
	e, err := readOne(v)
	if err != nil || !e.universal(asn1.TagBitString, false) || len(e.content) < 2 {
		return false
	}
	unused, data := int(e.content[0]), e.content[1:]
	last := data[len(data)-1]
	if unused > 7 || last == 0 || trailingZeros(last) != unused {
		return false
	}
	if len(data) != 1 { // the nine bits and more are bits that no use here has
		return false
	}
	bits := data[0]
	const digitalSignature, keyCertSign, cRLSign = 0x80, 0x04, 0x02
	return bits&keyCertSign != 0 && bits&^(digitalSignature|keyCertSign|cRLSign) == 0
}

func trailingZeros(b byte) int {
	n := 0
	for b&1 == 0 && n < 8 {
		b >>= 1
		n++
	}
	return n
}

// ekuOK reads an extended key usage: one or two of serverAuth and clientAuth, each once, in DER.
func ekuOK(v []byte) bool {
	e, err := readOne(v)
	if err != nil || !e.universal(asn1.TagSequence, true) {
		return false
	}
	purposes, err := readAll(e.content)
	if err != nil || len(purposes) == 0 || len(purposes) > 2 {
		return false
	}
	var seen []string
	for _, p := range purposes {
		oid, ok := oidOf(p)
		if !ok || (!oid.Equal(oidServerAuth) && !oid.Equal(oidClientAuth)) {
			return false
		}
		for _, s := range seen {
			if s == oid.String() {
				return false
			}
		}
		seen = append(seen, oid.String())
	}
	return true
}

// NameConstraintsOK reads a name constraints value in DER and applies the contract's rules: at least one permitted subtree, each
// a DNS name or a URI constraint in its strict form; each subtree its base alone (no minimum, no maximum, nothing after the base);
// excluded subtrees none, or exactly the zero IPv4 address with the zero mask and the zero IPv6 address with the zero mask.
func NameConstraintsOK(v []byte) bool {
	e, err := readOne(v)
	if err != nil || !e.universal(asn1.TagSequence, true) {
		return false
	}
	trees, err := readAll(e.content)
	if err != nil || len(trees) == 0 || len(trees) > 2 {
		return false
	}
	permitted, ok := subtreeBases(trees[0], 0)
	if !ok || len(permitted) == 0 {
		return false
	}
	for _, b := range permitted {
		switch {
		case b.is(asn1.ClassContextSpecific, 2, false):
			if !ValidDNSName(string(b.content)) {
				return false
			}
		case b.is(asn1.ClassContextSpecific, 6, false):
			if !ValidURIHost(string(b.content)) {
				return false
			}
		default: // an e-mail name, an IP range, an other name, a directory name, ...
			return false
		}
	}
	if len(trees) == 1 {
		return true
	}
	excluded, ok := subtreeBases(trees[1], 1)
	if !ok || len(excluded) != 2 {
		return false
	}
	v4, v6 := false, false
	for _, b := range excluded {
		if !b.is(asn1.ClassContextSpecific, 7, false) || len(bytes.Trim(b.content, "\x00")) != 0 {
			return false
		}
		switch len(b.content) {
		case 8:
			v4 = true
		case 32:
			v6 = true
		default:
			return false
		}
	}
	return v4 && v6
}

// subtreeBases reads a [tag] list of GeneralSubtrees, each a SEQUENCE of its base alone.
func subtreeBases(list element, tag int) ([]element, bool) {
	if !list.is(asn1.ClassContextSpecific, tag, true) {
		return nil, false
	}
	trees, err := readAll(list.content)
	if err != nil {
		return nil, false
	}
	var out []element
	for _, t := range trees {
		if !t.universal(asn1.TagSequence, true) {
			return nil, false
		}
		parts, err := readAll(t.content)
		if err != nil || len(parts) != 1 { // a minimum, a maximum or anything after the base is refused
			return nil, false
		}
		out = append(out, parts[0])
	}
	return out, true
}
