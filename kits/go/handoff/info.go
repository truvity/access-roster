package handoff

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// maxInfo bounds a CertificationRequestInfo that a key signs.
const maxInfo = 64 << 10

// CheckInfo is the check key@ makes before its key signs a CertificationRequestInfo: the info is exactly the shape
// CertificationRequestInfo builds, for the key spki and for no other. It parses the DER and checks version 0, a subject
// that is a Name, the key, and one attribute, extensionRequest, that holds three extensions in order: basic constraints
// (critical, cA, path length 0), key usage (critical, keyCertSign and cRLSign) and name constraints (critical, at
// least one permitted subtree whose bases are DNS names, URIs or IP ranges). Anything else is refused, so the key signs
// a request for an intermediate of this profile and nothing that could be read as another structure: the info begins
// with the INTEGER 0 and carries a context tag where a TBSCertificate carries its validity, so it is never a
// TBSCertificate (RFC 5280, section 4.1).
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
	if rest, err := asn1.Unmarshal(cri.Subject.FullBytes, &name); err != nil || len(rest) != 0 || len(name) == 0 {
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
	return checkNameConstraints(exts[2].Value)
}

// checkNameConstraints reads NameConstraints (RFC 5280, section 4.2.1.10) and requires at least one permitted subtree,
// each base a DNS name, a URI host or an IP range, and no other member.
func checkNameConstraints(der []byte) error {
	var nc struct {
		Permitted []asn1.RawValue `asn1:"tag:0,optional"`
		Excluded  []asn1.RawValue `asn1:"tag:1,optional"`
	}
	rest, err := asn1.Unmarshal(der, &nc)
	if err != nil || len(rest) != 0 || len(nc.Permitted) == 0 {
		return errors.New("info.name constraints")
	}
	for _, list := range [][]asn1.RawValue{nc.Permitted, nc.Excluded} {
		for _, st := range list {
			var sub struct{ Base asn1.RawValue }
			if rest, err := asn1.Unmarshal(st.FullBytes, &sub); err != nil || len(rest) != 0 {
				return errors.New("info.name constraints")
			}
			b := sub.Base
			okTag := b.Class == asn1.ClassContextSpecific && (b.Tag == 2 || b.Tag == 6 || b.Tag == 7)
			if !okTag || len(b.Bytes) == 0 {
				return errors.New("info.name constraints")
			}
		}
	}
	return nil
}
