package handoff

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// maxInfo bounds a CertificationRequestInfo that a key signs.
const maxInfo = 16 << 10

// The bounds of what a request carries. A subject is a few attributes, and a name constraint base is a host name (at
// most 253 octets) or an address and its mask.
const (
	maxSubject  = 512
	maxBase     = 253
	maxSubtrees = 64
)

// CheckInfo is the check key@ makes before its key signs a CertificationRequestInfo: the info is exactly the shape
// CertificationRequestInfo builds, for the key spki and for no other. It parses the DER, checks each piece, and then
// builds the info again from the pieces it parsed and requires the same bytes (encoding/asn1 ignores elements after the
// last one it expects in a SEQUENCE, so a parse alone would let a caller append DER of its own to what the key signs).
//
// The pieces are version 0, a subject that is a Name of at most 512 octets, the key, and one attribute,
// extensionRequest, that holds three extensions in order: basic constraints (critical, cA, path length 0), key usage
// (critical, keyCertSign and cRLSign) and name constraints (critical; at least one permitted subtree; each base a
// lower-case DNS name or URI host of at most 253 octets, or an IP range of 8 or 32 octets; and either a permitted IP
// range or both address families excluded, so that REQ-PKI-046 is enforced where the signature is made). Anything else
// is refused. The key therefore signs a request for an intermediate of this profile and nothing that could be read as
// another structure: the info begins with the INTEGER 0 and carries a context tag where a TBSCertificate carries its
// validity (RFC 5280, section 4.1), and it is not a JWS signing input or a token.
//
// The error names a place, never a value.
func CheckInfo(info, spki []byte) error {
	if len(info) > maxInfo {
		return errors.New("info: too large")
	}
	var cri struct {
		Version    int
		Subject    asn1.RawValue
		PKInfo     asn1.RawValue
		Attributes asn1.RawValue
	}
	rest, err := asn1.Unmarshal(info, &cri)
	if err != nil || len(rest) != 0 {
		return errors.New("info: not a CertificationRequestInfo")
	}
	if cri.Version != 0 {
		return errors.New("info.version")
	}
	var name pkix.RDNSequence
	if len(cri.Subject.FullBytes) > maxSubject {
		return errors.New("info.subject")
	}
	if rest, err := asn1.Unmarshal(cri.Subject.FullBytes, &name); err != nil || len(rest) != 0 || len(name) == 0 {
		return errors.New("info.subject")
	}
	// The subject is the Name that the builder makes from the attributes it read: marshalled again, the same bytes. A
	// parse alone ignores what is after the last element of a SET or a SEQUENCE.
	if again, err := asn1.Marshal(name); err != nil || !bytes.Equal(again, cri.Subject.FullBytes) {
		return errors.New("info.subject")
	}
	if !bytes.Equal(cri.PKInfo.FullBytes, spki) {
		return errors.New("info.key")
	}
	if cri.Attributes.Class != asn1.ClassContextSpecific || cri.Attributes.Tag != 0 || !cri.Attributes.IsCompound {
		return errors.New("info.attributes")
	}
	var attr struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}
	rest, err = asn1.Unmarshal(cri.Attributes.Bytes, &attr)
	if err != nil || len(rest) != 0 || !attr.Type.Equal(oidExtensionRequest) {
		return errors.New("info.attributes")
	}
	if attr.Values.Class != asn1.ClassUniversal || attr.Values.Tag != asn1.TagSet || !attr.Values.IsCompound {
		return errors.New("info.attributes")
	}
	var exts []pkix.Extension
	rest, err = asn1.Unmarshal(attr.Values.Bytes, &exts)
	if err != nil || len(rest) != 0 || len(exts) != 3 {
		return errors.New("info.extensions")
	}
	want, err := requestedExtensions(Constraints{DNS: []string{"x"}})
	if err != nil {
		return err
	}
	for i, e := range exts {
		if !e.Id.Equal(want[i].Id) || !e.Critical {
			return errors.New("info.extensions")
		}
		// Basic constraints and key usage have one value; the name constraints are checked below.
		if i < 2 && !bytes.Equal(e.Value, want[i].Value) {
			return errors.New("info.extensions")
		}
	}
	nc, err := checkNameConstraints(exts[2].Value)
	if err != nil {
		return err
	}
	exts[2].Value = nc
	// The same bytes, built again from what was read: nothing was ignored and nothing is non-canonical.
	again, err := infoDER(cri.PKInfo.FullBytes, cri.Subject.FullBytes, exts)
	if err != nil || !bytes.Equal(again, info) {
		return errors.New("info: not canonical")
	}
	return nil
}

// checkNameConstraints reads NameConstraints (RFC 5280, section 4.2.1.10) and applies the rules above. It returns the
// DER built again from the bases it read, which the caller compares with what it was given.
func checkNameConstraints(der []byte) ([]byte, error) {
	bad := errors.New("info.name constraints")
	var nc struct {
		Permitted []asn1.RawValue `asn1:"tag:0,optional"`
		Excluded  []asn1.RawValue `asn1:"tag:1,optional"`
	}
	rest, err := asn1.Unmarshal(der, &nc)
	if err != nil || len(rest) != 0 || len(nc.Permitted) == 0 || len(nc.Permitted) > maxSubtrees || len(nc.Excluded) > maxSubtrees {
		return nil, bad
	}
	bases := func(list []asn1.RawValue) ([]asn1.RawValue, error) {
		var out []asn1.RawValue
		for _, st := range list {
			var sub struct{ Base asn1.RawValue }
			if rest, err := asn1.Unmarshal(st.FullBytes, &sub); err != nil || len(rest) != 0 {
				return nil, bad
			}
			b := sub.Base
			if b.Class != asn1.ClassContextSpecific || b.IsCompound || len(b.Bytes) == 0 {
				return nil, bad
			}
			switch b.Tag {
			case 2, 6: // a DNS name or a URI host
				if len(b.Bytes) > maxBase || !dnsName.Match(b.Bytes) {
					return nil, bad
				}
			case 7: // an address and its mask
				if len(b.Bytes) != 8 && len(b.Bytes) != 32 {
					return nil, bad
				}
			default:
				return nil, bad
			}
			out = append(out, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: b.Tag, Bytes: b.Bytes})
		}
		return out, nil
	}
	permitted, err := bases(nc.Permitted)
	if err != nil {
		return nil, err
	}
	excluded, err := bases(nc.Excluded)
	if err != nil {
		return nil, err
	}
	if !hasIP(permitted) && !excludesAllIP(excluded) {
		return nil, bad
	}
	return encodeNameConstraints(permitted, excluded)
}

func hasIP(bases []asn1.RawValue) bool {
	for _, b := range bases {
		if b.Tag == 7 {
			return true
		}
	}
	return false
}

// excludesAllIP reports whether both address families are excluded: the zero address with the zero mask, 8 octets for
// IPv4 and 32 for IPv6.
func excludesAllIP(bases []asn1.RawValue) bool {
	v4, v6 := false, false
	for _, b := range bases {
		if b.Tag != 7 || len(bytes.Trim(b.Bytes, "\x00")) != 0 {
			continue
		}
		switch len(b.Bytes) {
		case 8:
			v4 = true
		case 32:
			v6 = true
		}
	}
	return v4 && v6
}
