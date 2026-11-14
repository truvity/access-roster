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
	"strings"
)

// The object identifiers of the request (RFC 2985, RFC 5280, RFC 5758).
var (
	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidServerAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
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
	// (0.0.0.0/0 and ::/0), because RFC 5280 leaves a type with no subtree unconstrained. A ritueel certifier refuses a
	// permitted IP range in contract version 1 (the page's "What a name constraint permits", maintainer decision E2 B,
	// 2026-11-14), so a request that carries one is certified by no one yet; the field stays for a certifier that accepts it.
	IPRanges []netip.Prefix
}

// ValidDNSName reports whether s is a DNS name of the contract (the page's "The names in the name constraints"): the syntax of
// RFC 1034, section 3.5, and RFC 1123, section 2.1, in lower case. Labels of letters a to z, digits and hyphens are joined by
// single periods; a label has 1 to 63 characters and no hyphen at its start or its end; the name has at most 253 characters;
// the last label is not all digits, so that it is not a number; the name is not empty, has no wildcard and no period at its
// start or end.
func ValidDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return !allDigits(labels[len(labels)-1])
}

// ValidURIHost reports whether s is a URI constraint of the contract: a host in the form of ValidDNSName, or a period and a
// domain; no scheme, port or path. The period at the start does not count towards the 253 characters.
func ValidURIHost(s string) bool {
	return ValidDNSName(strings.TrimPrefix(s, "."))
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// Validate refuses constraints that cannot be a request: no permitted subtree at all, a name that is not a lower-case
// host name, a range that is not in its masked form.
func (c Constraints) Validate() error {
	if n := len(c.URIHosts) + len(c.DNS) + len(c.IPRanges); n == 0 {
		return errors.New("handoff: a request needs at least one permitted subtree")
	} else if n > maxSubtrees {
		// key@ signs at most this many (CheckInfo); say so here, with the number, and not as a refusal of the signature.
		return fmt.Errorf("handoff: %d permitted names and ranges, at most %d are signed", n, maxSubtrees)
	}
	for _, h := range c.URIHosts {
		if !ValidURIHost(h) {
			return errors.New("handoff: a permitted URI host is not a lower-case host name")
		}
	}
	for _, d := range c.DNS {
		if !ValidDNSName(d) {
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
	// Subject is the name of the intermediate. Only its common name is used: it is the whole subject of a request of this
	// version, and a name with another attribute is refused (the contract's attribute rules are the certifier's to check
	// in full, and one attribute is the form that can be written without a mistake).
	Subject     pkix.Name
	Constraints Constraints
	// Roots are the root certificates of the CA bundle the requester holds, when it holds one. A request whose subject is
	// the name of one of them (compared as OpenSSL compares names) or whose key is the key of one is refused, as the
	// certifier refuses it (contract, "The request": a second certificate for a root's key, or a name that a verifier takes for
	// the root's).
	Roots []*x509.Certificate
}

// CertificationRequestInfo is the DER of the CertificationRequestInfo of a PKCS#10 request (RFC 2986, section 4.1)
// for the key spki: the subject and the extensionRequest of an intermediate with basic constraints (critical, cA,
// path length 0), key usage (critical, keyCertSign and cRLSign), name constraints (critical) and extended key usage
// (not critical, serverAuth and clientAuth, in that order; maintainer decision E1 A, 2026-11-14). The key signs these
// bytes, which is the proof of possession.
func CertificationRequestInfo(spki []byte, spec RequestSpec) ([]byte, error) {
	if err := spec.Constraints.Validate(); err != nil {
		return nil, err
	}
	if _, err := parseP384SPKI(spki); err != nil {
		return nil, err
	}
	subject, err := subjectDER(spec.Subject)
	if err != nil {
		return nil, err
	}
	if EqualsRoot(subject, spki, spec.Roots) {
		return nil, errors.New("handoff: the subject or the key of the request is that of a root of the CA bundle")
	}
	exts, err := requestedExtensions(spec.Constraints)
	if err != nil {
		return nil, err
	}
	info, err := infoDER(spki, subject, exts)
	if err != nil {
		return nil, err
	}
	// The bounds key@ signs within, checked here with the same function, so that a request that is too large is an error
	// of the command that names the bound, and not a generic refusal of the signature.
	if err := CheckInfo(info, spki); err != nil {
		return nil, fmt.Errorf("handoff: the request is not one key@ signs (%w): a subject of at most %d octets, at most %d names and ranges, and %d octets of request", err, maxSubject, maxSubtrees, maxInfo)
	}
	return info, nil
}

// infoDER is the DER of a CertificationRequestInfo for a subject that is already DER.
func infoDER(spki, subject []byte, exts []pkix.Extension) ([]byte, error) {
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

// requestedExtensions builds the four extensions of the request, in the order basic constraints, key usage, name
// constraints, extended key usage.
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
	// The one extended key usage of every intermediate: serverAuth and clientAuth, in that order, not critical. The
	// certifier requires the extension and issues it as asked, and a certificate under the intermediate may carry only
	// these purposes (RFC 5280, section 4.2.1.12, as the verifiers read it), which is what every leaf profile of ADR 0023 needs.
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{oidServerAuth, oidClientAuth})
	if err != nil {
		return nil, err
	}
	return []pkix.Extension{
		{Id: oidBasicConstraints, Critical: true, Value: bc},
		{Id: oidKeyUsage, Critical: true, Value: ku},
		{Id: oidNameConstraints, Critical: true, Value: nc},
		{Id: oidExtKeyUsage, Critical: false, Value: eku},
	}, nil
}

// nameConstraints encodes NameConstraints (RFC 5280, section 4.2.1.10): the permitted URI hosts, DNS names and IP
// ranges, and, when no IP range is permitted, both address families excluded.
func nameConstraints(c Constraints) ([]byte, error) {
	general := func(tag int, b []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: b}
	}
	var permitted, excluded []asn1.RawValue
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
	return encodeNameConstraints(permitted, excluded)
}

// encodeNameConstraints encodes the subtrees (each a GeneralName base, with the default minimum and no maximum).
func encodeNameConstraints(permitted, excluded []asn1.RawValue) ([]byte, error) {
	type subtree struct{ Base asn1.RawValue }
	wrap := func(bases []asn1.RawValue) []subtree {
		var out []subtree
		for _, b := range bases {
			out = append(out, subtree{b})
		}
		return out
	}
	return asn1.Marshal(struct {
		Permitted []subtree `asn1:"tag:0,optional"`
		Excluded  []subtree `asn1:"tag:1,optional"`
	}{wrap(permitted), wrap(excluded)})
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

// VerifyRequest checks a request as the certifier does in its checks 2, 4 and 5, with the strict reader: the request is well
// formed (`malformed`), the key is ECDSA on P-384 (`algorithm-unsupported`), the signature algorithm is ecdsa-with-SHA384 and the
// signature verifies with the request's own key (`possession-invalid`), in that order. It returns the request as the strict reader
// read it, which holds what the standard library's parser would not read (a repeated extension, a PrintableString outside its alphabet).
func VerifyRequest(der []byte) (*Request, error) {
	r, err := ParseRequest(der)
	if err != nil {
		return nil, err
	}
	if err := r.CheckKey(); err != nil {
		return nil, err
	}
	if err := r.CheckPossession(); err != nil {
		return nil, err
	}
	return r, nil
}

// VerifyCSR is VerifyRequest, and returns the request as the standard library reads it: for the requester's own request and for a
// certifier that issues from it. A request that the strict reader accepts and the library does not read is `malformed` here.
func VerifyCSR(der []byte) (*x509.CertificateRequest, error) {
	if _, err := VerifyRequest(der); err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, refuse(CodeMalformed, "request.der")
	}
	return csr, nil
}
