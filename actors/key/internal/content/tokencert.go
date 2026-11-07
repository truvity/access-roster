package content

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"
)

// The token certificate is the one certificate the x509-intermediate purpose signs in the first working version (ADR 0023,
// "Leaf profiles": "Token signing (non-CA)"; REQ-ISO-006, REQ-PKI-036). key@ does not parse a TBSCertificate and test
// properties of what it parsed. It reads the three things the caller chooses, builds the TBSCertificate again from
// them and from what key@ itself knows, and requires the same bytes (the method of handoff.CheckInfo). The caller
// chooses the serial number and the two ends of the validity, and nothing else:
//
//   - the issuer is the subject of the intermediate that key@ has installed, and the authority key identifier is its subject
//     key identifier, when it has one;
//   - the subject is CN=token-signing, OU=signer@<boundary>, and the key is the token-signing key of this node;
//   - the extensions are basic constraints (critical, CA false), key usage (critical, digitalSignature only) and the
//     authority key identifier; there is no subject alternative name, no extended key usage and no other extension;
//   - the signature algorithm is ecdsa-with-SHA384, which is the algorithm of the intermediate's key;
//   - the validity ends when the intermediate's does (ADR 0023: "To the issuing intermediate's notAfter"), begins no
//     earlier than the intermediate's and no more than ten minutes before key@'s clock, and has at least an hour to run.
//
// This encoder is written separately from the one that builds the certificate (kits/go/tokencert), on purpose: a
// mistake in the builder must not be a mistake in the check. A second, semantic test then reads the result with the
// standard library's parser.
//
// What cannot be confused with this. A CertificationRequestInfo (RFC 2986), the other structure the same key signs
// (handoff.CheckInfo), begins with the INTEGER 0 where a TBSCertificate carries the context tag [0] that holds its
// version. TokenCertificate requires that tag first and names the INTEGER as a reason of its own, and CheckInfo
// requires the INTEGER; no byte string passes both (the tests run the two on each other's valid inputs and on mutations
// of both). Neither is a JWS signing input, which is base64url text, or a checkpoint, which is text.

// Bounds of what the caller chooses.
const (
	// A serial number is a random 128-bit number: 121 to 128 bits once its leading zero octets are taken off, which
	// leaves at least 120 bits of entropy of the 128 and refuses a short or a predictable number (REQ-PKI-002).
	minSerialBits = 121
	maxSerialBits = 128
	// A token certificate is about 400 octets; this is far above it.
	maxTokenCert = 2048
	// notBefore may be this far in the future of key@'s clock, and this far in its past: a verifier whose clock is a few
	// minutes behind accepts the certificate, and nobody needs a certificate that starts earlier than that (it must not
	// reach back to the start of the intermediate's life).
	notBeforeSkew = 5 * time.Minute
	maxBackdate   = 10 * time.Minute
	// A token certificate that has less than this to live is not made: signer's rotation (30 minutes before a key signs,
	// 65 minutes after) means a certificate must outlast an hour to be of use.
	minLifetime = time.Hour
	// UTCTime stops at 2049 (RFC 5280, section 4.1.2.5). A certificate that would end in 2050 or later needs
	// GeneralizedTime, which this encoder does not write: it is refused, and so is an intermediate that ends then. An
	// intermediate lasts about 13 months, so this is a matter for 2048.
	lastUTCYear = 2049
)

// TokenCertificateRules is what key@ knows about the certificate it signs.
type TokenCertificateRules struct {
	// Issuer is the DER of the subject Name of the installed intermediate; IssuerKeyID its subject key identifier, or
	// nil when the intermediate has none.
	Issuer      []byte
	IssuerKeyID []byte
	// SPKI is the public key of the token-signing key of this node, SubjectPublicKeyInfo in DER.
	SPKI []byte
	// Boundary is the boundary of this key@: it is in the subject.
	Boundary string
	// IssuerNotBefore and IssuerNotAfter are the validity of the installed intermediate. Now is key@'s clock.
	IssuerNotBefore, IssuerNotAfter, Now time.Time
}

// The DER pieces of the certificate that never change.
var (
	derVersion3   = []byte{0xa0, 0x03, 0x02, 0x01, 0x02}
	derEcdsaSHA38 = []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}
	oidCN         = []byte{0x06, 0x03, 0x55, 0x04, 0x03}
	oidOU         = []byte{0x06, 0x03, 0x55, 0x04, 0x0b}
	derBasicCA0   = []byte{0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00}
	derKeyUsageDS = []byte{0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80}
	oidAKI        = []byte{0x06, 0x03, 0x55, 0x1d, 0x23}
)

// subjectCN is the common name of every token certificate.
const subjectCN = "token-signing"

func tlv(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// utcLayout is the UTCTime of RFC 5280 without its Z: year, month, day, hour, minute, second (written in two parts: a run of
// twelve digits is taken by the public-content check for an account id).
const utcLayout = "060102" + "150405"

func utcTime(t time.Time) []byte {
	return tlv(0x17, []byte(t.UTC().Format(utcLayout)+"Z"))
}

// name is the Name CN=token-signing, OU=signer@<boundary>, one attribute in each RDN.
func (r TokenCertificateRules) name() []byte {
	rdn := func(oid []byte, v string) []byte {
		return tlv(0x31, tlv(0x30, oid, tlv(0x0c, []byte(v))))
	}
	return tlv(0x30, rdn(oidCN, subjectCN), rdn(oidOU, "signer@"+r.Boundary))
}

// tbs builds the TBSCertificate for the three things the caller chooses. The serial is the content octets of the INTEGER.
func (r TokenCertificateRules) tbs(serial []byte, notBefore, notAfter time.Time) []byte {
	exts := [][]byte{derBasicCA0, derKeyUsageDS}
	if len(r.IssuerKeyID) > 0 {
		exts = append(exts, tlv(0x30, oidAKI, tlv(0x04, tlv(0x30, tlv(0x80, r.IssuerKeyID)))))
	}
	return tlv(0x30,
		derVersion3,
		tlv(0x02, serial),
		derEcdsaSHA38,
		r.Issuer,
		tlv(0x30, utcTime(notBefore), utcTime(notAfter)),
		r.name(),
		r.SPKI,
		tlv(0xa3, tlv(0x30, exts...)),
	)
}

// elements splits the content of a constructed DER value into its elements, each with its header, and requires that
// nothing is left over.
func elements(der []byte) ([]asn1.RawValue, bool) {
	var out []asn1.RawValue
	for len(der) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(der, &v)
		if err != nil || len(rest) >= len(der) {
			return nil, false
		}
		out = append(out, v)
		der = rest
	}
	return out, true
}

// TokenCertificate checks that tbs is the TBSCertificate of the token certificate that key@ signs for this node, and no
// other structure. The error names a place and never a value.
func TokenCertificate(tbs []byte, r TokenCertificateRules) error {
	if len(tbs) == 0 || len(tbs) > maxTokenCert {
		return refuse("content")
	}
	if len(r.Issuer) == 0 || len(r.SPKI) == 0 || r.Boundary == "" {
		return refuse("content")
	}
	// A CertificationRequestInfo begins with the INTEGER 0: it is not this structure, and it is said so.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(tbs, &outer)
	if err != nil || len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return refuse("content")
	}
	els, ok := elements(outer.Bytes)
	if !ok || len(els) == 0 {
		return refuse("content")
	}
	if els[0].Class == asn1.ClassUniversal && els[0].Tag == asn1.TagInteger {
		return refuse("content.kind")
	}
	if len(els) != 8 {
		return refuse("content")
	}
	if !bytes.Equal(els[0].FullBytes, derVersion3) {
		return refuse("content.version")
	}
	serial, ok := serialOf(els[1])
	if !ok {
		return refuse("content.serial")
	}
	notBefore, notAfter, ok := validityOf(els[4])
	if !ok {
		return refuse("content.validity")
	}
	// The validity: it ends with the intermediate (which must end in a year UTCTime can write), starts within the
	// intermediate's and within ten minutes before now (and at most five after), and has an hour to run.
	if r.IssuerNotAfter.Year() > lastUTCYear || !notAfter.Equal(r.IssuerNotAfter) || notBefore.Before(r.IssuerNotBefore) ||
		!notAfter.After(notBefore) || notBefore.After(r.Now.Add(notBeforeSkew)) || notBefore.Before(r.Now.Add(-maxBackdate)) ||
		notAfter.Before(r.Now.Add(minLifetime)) {
		return refuse("content.validity")
	}
	if !bytes.Equal(r.tbs(serial, notBefore, notAfter), tbs) {
		return refuse("content")
	}
	return nil
}

// serialOf reads the INTEGER of a serial number: positive, written with no superfluous octet, and 121 to 128 bits.
func serialOf(v asn1.RawValue) ([]byte, bool) {
	b := v.Bytes
	if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagInteger || v.IsCompound || len(b) == 0 || b[0]&0x80 != 0 {
		return nil, false
	}
	if len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		return nil, false
	}
	v0 := b
	if v0[0] == 0 {
		v0 = v0[1:] // the sign octet; the check above leaves it only where the next octet has its high bit set
	}
	if len(v0) == 0 {
		return nil, false
	}
	bits := 8 * len(v0)
	for m := byte(0x80); m != 0 && v0[0]&m == 0; m >>= 1 {
		bits--
	}
	if bits < minSerialBits || bits > maxSerialBits {
		return nil, false
	}
	return b, true
}

// validityOf reads the Validity SEQUENCE of two UTCTimes that are written the way the builder writes them.
func validityOf(v asn1.RawValue) (time.Time, time.Time, bool) {
	var zero time.Time
	if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagSequence || !v.IsCompound {
		return zero, zero, false
	}
	els, ok := elements(v.Bytes)
	if !ok || len(els) != 2 {
		return zero, zero, false
	}
	var ts [2]time.Time
	for i, e := range els {
		if e.Class != asn1.ClassUniversal || e.Tag != asn1.TagUTCTime || e.IsCompound || len(e.Bytes) != 13 {
			return zero, zero, false
		}
		t, err := time.Parse(utcLayout+"Z", string(e.Bytes))
		if err != nil || t.Year() < 2000 || t.Year() > lastUTCYear || !bytes.Equal(utcTime(t), e.FullBytes) {
			return zero, zero, false
		}
		ts[i] = t
	}
	return ts[0], ts[1], true
}

// CheckTokenCertificate is the check of a finished certificate: the TBSCertificate passes TokenCertificate, the
// signature verifies under the intermediate's key, and the standard library reads it as a certificate that is not a CA
// and allows digital signatures only. The last is a second reading by another parser; it adds no rule.
func CheckTokenCertificate(der []byte, r TokenCertificateRules, issuer *x509.Certificate) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(c.Raw, der) {
		return nil, refuse("content")
	}
	if err := TokenCertificate(c.RawTBSCertificate, r); err != nil {
		return nil, err
	}
	if c.SignatureAlgorithm != x509.ECDSAWithSHA384 || c.CheckSignatureFrom(issuer) != nil {
		return nil, refuse("content.signature")
	}
	if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 0 ||
		len(c.UnknownExtKeyUsage) != 0 || len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses)+len(c.URIs) != 0 {
		return nil, refuse("content.profile")
	}
	return c, nil
}

// ErrNotTokenCertificate is returned where a caller needs a plain error.
var ErrNotTokenCertificate = errors.New("content: not the token certificate")
