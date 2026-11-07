package handoff

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

// The object identifiers of the request (RFC 2985, RFC 5280, RFC 5758).
var (
	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidECDSAWithSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	// The key identifiers a CA adds to a certificate, the only extensions an answer may carry that were not requested.
	oidSubjectKeyID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// Constraints are the name constraints of an intermediate (ADR 0023, "The intermediate's name constraints"):
// critical, at least one permitted subtree.
type Constraints struct {
	// URIHosts are the permitted URI hosts: the boundary's SPIFFE trust domain.
	URIHosts []string
	// DNS are the permitted DNS names: the boundary's public hosts and zones. A name permits itself and every name
	// below it (RFC 5280, section 4.2.1.10).
	DNS []string
	// IPRanges are the permitted IP ranges the boundary declares. With none, the request excludes every IP address
	// (0.0.0.0/0 and ::/0), because RFC 5280 leaves a type with no subtree unconstrained.
	IPRanges []netip.Prefix
}

var dnsName = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate refuses constraints that cannot be a request: no permitted subtree at all, a name that is not a lower-case
// host name, a range that is not in its masked form.
func (c Constraints) Validate() error {
	if len(c.URIHosts)+len(c.DNS)+len(c.IPRanges) == 0 {
		return errors.New("handoff: a request needs at least one permitted subtree")
	}
	for _, h := range c.URIHosts {
		if len(h) > 253 || !dnsName.MatchString(h) {
			return errors.New("handoff: a permitted URI host is not a lower-case host name")
		}
	}
	for _, d := range c.DNS {
		if len(d) > 253 || !dnsName.MatchString(d) {
			return errors.New("handoff: a permitted DNS name is not a lower-case host name")
		}
	}
	for _, p := range c.IPRanges {
		if !p.IsValid() || p.Masked() != p {
			return errors.New("handoff: a permitted IP range is not a prefix in its masked form")
		}
	}
	return nil
}

// RequestSpec is what a request asks for. The validity is not asked: the certifier decides it (contract, "The
// request").
type RequestSpec struct {
	Subject     pkix.Name
	Constraints Constraints
}

// CertificationRequestInfo is the DER of the CertificationRequestInfo of a PKCS#10 request (RFC 2986, section 4.1)
// for the key spki: the subject and the extensionRequest of an intermediate with basic constraints (critical, cA,
// path length 0), key usage (critical, keyCertSign and cRLSign) and name constraints (critical). The key signs these
// bytes, which is the proof of possession.
func CertificationRequestInfo(spki []byte, spec RequestSpec) ([]byte, error) {
	if err := spec.Constraints.Validate(); err != nil {
		return nil, err
	}
	if _, err := parseP384SPKI(spki); err != nil {
		return nil, err
	}
	subject, err := asn1.Marshal(spec.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("handoff: subject: %w", err)
	}
	exts, err := requestedExtensions(spec.Constraints)
	if err != nil {
		return nil, err
	}
	extsDER, err := asn1.Marshal(exts)
	if err != nil {
		return nil, fmt.Errorf("handoff: extensions: %w", err)
	}
	attr, err := asn1.Marshal(struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{oidExtensionRequest, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: extsDER}})
	if err != nil {
		return nil, fmt.Errorf("handoff: attribute: %w", err)
	}
	return asn1.Marshal(struct {
		Version    int
		Subject    asn1.RawValue
		PKInfo     asn1.RawValue
		Attributes asn1.RawValue
	}{
		Version:    0,
		Subject:    asn1.RawValue{FullBytes: subject},
		PKInfo:     asn1.RawValue{FullBytes: spki},
		Attributes: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attr},
	})
}

// requestedExtensions builds the three extensions of the request, in the order basic constraints, key usage, name
// constraints.
func requestedExtensions(c Constraints) ([]pkix.Extension, error) {
	bc, err := asn1.Marshal(struct {
		CA      bool
		MaxPath int
	}{true, 0})
	if err != nil {
		return nil, err
	}
	// keyCertSign is bit 5 and cRLSign bit 6 (RFC 5280, section 4.2.1.3): 0000 0110, seven bits used.
	ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7})
	if err != nil {
		return nil, err
	}
	nc, err := nameConstraints(c)
	if err != nil {
		return nil, err
	}
	return []pkix.Extension{
		{Id: oidBasicConstraints, Critical: true, Value: bc},
		{Id: oidKeyUsage, Critical: true, Value: ku},
		{Id: oidNameConstraints, Critical: true, Value: nc},
	}, nil
}

// nameConstraints encodes NameConstraints (RFC 5280, section 4.2.1.10): the permitted URI hosts, DNS names and IP
// ranges, and, when no IP range is permitted, both address families excluded.
func nameConstraints(c Constraints) ([]byte, error) {
	type subtree struct{ Base asn1.RawValue }
	general := func(tag int, b []byte) subtree {
		return subtree{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: b}}
	}
	var permitted, excluded []subtree
	for _, d := range c.DNS {
		permitted = append(permitted, general(2, []byte(d)))
	}
	for _, h := range c.URIHosts {
		permitted = append(permitted, general(6, []byte(h)))
	}
	for _, p := range c.IPRanges {
		permitted = append(permitted, general(7, ipSubtree(p)))
	}
	if len(c.IPRanges) == 0 {
		excluded = append(excluded, general(7, ipSubtree(netip.MustParsePrefix("0.0.0.0/0"))), general(7, ipSubtree(netip.MustParsePrefix("::/0"))))
	}
	return asn1.Marshal(struct {
		Permitted []subtree `asn1:"tag:0,optional"`
		Excluded  []subtree `asn1:"tag:1,optional"`
	}{permitted, excluded})
}

// ipSubtree is the address and the mask of an iPAddress constraint (RFC 5280, section 4.2.1.10).
func ipSubtree(p netip.Prefix) []byte {
	addr := p.Addr().AsSlice()
	mask := make([]byte, len(addr))
	for i := 0; i < p.Bits(); i++ {
		mask[i/8] |= 0x80 >> (i % 8)
	}
	return append(addr, mask...)
}

// AssembleCSR joins a CertificationRequestInfo and its ECDSA signature (ASN.1 DER, over SHA-384 of the info) into a
// PKCS#10 request, with the signature algorithm ecdsa-with-SHA384 (RFC 5758), and returns its DER.
func AssembleCSR(info, signatureDER []byte) ([]byte, error) {
	return asn1.Marshal(struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		Info:      asn1.RawValue{FullBytes: info},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA384},
		Signature: asn1.BitString{Bytes: signatureDER, BitLength: 8 * len(signatureDER)},
	})
}

// CSRPEM armours a request with the label CERTIFICATE REQUEST.
func CSRPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// CertPEM armours a certificate.
func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// parseP384SPKI reads a SubjectPublicKeyInfo and requires ECDSA on P-384, the only key of version 1.
func parseP384SPKI(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("handoff: the public key does not parse")
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, errors.New("handoff: the key is not ECDSA on P-384")
	}
	return pub, nil
}

// VerifyCSR checks a request as the certifier does in its checks 4 and 5: the key is ECDSA on P-384, the signature
// algorithm is ecdsa-with-SHA384 and the request's signature verifies with its own key. It returns the parsed request.
func VerifyCSR(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, refuse(CodeMalformed, "request.der")
	}
	if _, err := parseP384SPKI(csr.RawSubjectPublicKeyInfo); err != nil {
		return nil, refuse("algorithm-unsupported", "request.key")
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA384 || csr.CheckSignature() != nil {
		return nil, refuse("possession-invalid", "request.signature")
	}
	return csr, nil
}
