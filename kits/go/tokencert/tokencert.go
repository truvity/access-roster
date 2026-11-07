// Package tokencert builds the certificate that the node's intermediate gives to the token-signing key (ADR 0023,
// "Leaf profiles", the row "Token signing (non-CA)"; REQ-PKI-036): a v3 certificate that is not a CA, whose key usage is
// digitalSignature only, with no subject alternative name and no extended key usage. `ca` builds the TBSCertificate here and
// has key@ sign it; key@ does not trust this builder. It checks the structure again with an encoder of its own
// (actors/key/internal/content), so a mistake here is a refusal there and never a certificate that is not this one.
package tokencert

import (
	"crypto/rand"
	"errors"
	"io"
	"time"
)

// SubjectCommonName is the common name of every token certificate; the organisational unit is signer@<boundary>.
const SubjectCommonName = "token-signing"

// Params are what a token certificate is made from.
type Params struct {
	// Serial is the content of the INTEGER of the serial number, from NewSerial.
	Serial []byte
	// Issuer is the DER of the subject Name of the intermediate; IssuerKeyID its subject key identifier, or nil.
	Issuer      []byte
	IssuerKeyID []byte
	// SPKI is the token-signing key, SubjectPublicKeyInfo in DER.
	SPKI                []byte
	Boundary            string
	NotBefore, NotAfter time.Time
}

// NewSerial draws a random serial number of 128 bits (REQ-PKI-002) from r, and returns the content of its INTEGER: it draws
// again while the number has fewer than 121 significant bits, which is one draw in 256, so that a number is never short.
// A number whose high bit is set gets a zero octet in front, as DER requires of a positive INTEGER.
func NewSerial(r io.Reader) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	for range 64 {
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		if b[0] == 0 {
			continue
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return b, nil
	}
	return nil, errors.New("tokencert: the random source gave no usable serial number")
}

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

func utcTime(t time.Time) []byte { return tlv(0x17, []byte(t.UTC().Format("060102150405")+"Z")) }

// TBS builds the TBSCertificate. Times are written to the second.
func TBS(p Params) ([]byte, error) {
	if len(p.Serial) == 0 || len(p.Issuer) == 0 || len(p.SPKI) == 0 || p.Boundary == "" {
		return nil, errors.New("tokencert: serial, issuer, key and boundary are required")
	}
	nb, na := p.NotBefore.UTC().Truncate(time.Second), p.NotAfter.UTC().Truncate(time.Second)
	if nb.Year() < 2000 || na.Year() > 2049 || !na.After(nb) {
		return nil, errors.New("tokencert: the validity is outside 2000 to 2049 or ends before it starts")
	}
	rdn := func(oid byte, v string) []byte {
		return tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, oid}, tlv(0x0c, []byte(v))))
	}
	subject := tlv(0x30, rdn(0x03, SubjectCommonName), rdn(0x0b, "signer@"+p.Boundary))
	exts := [][]byte{
		// basicConstraints: critical, cA FALSE (the empty SEQUENCE).
		tlv(0x30, []byte{0x06, 0x03, 0x55, 0x1d, 0x13}, []byte{0x01, 0x01, 0xff}, tlv(0x04, tlv(0x30))),
		// keyUsage: critical, digitalSignature only.
		tlv(0x30, []byte{0x06, 0x03, 0x55, 0x1d, 0x0f}, []byte{0x01, 0x01, 0xff}, tlv(0x04, []byte{0x03, 0x02, 0x07, 0x80})),
	}
	if len(p.IssuerKeyID) > 0 {
		exts = append(exts, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x1d, 0x23}, tlv(0x04, tlv(0x30, tlv(0x80, p.IssuerKeyID)))))
	}
	return tlv(0x30,
		[]byte{0xa0, 0x03, 0x02, 0x01, 0x02},
		tlv(0x02, p.Serial),
		// ecdsa-with-SHA384
		[]byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03},
		p.Issuer,
		tlv(0x30, utcTime(nb), utcTime(na)),
		subject,
		p.SPKI,
		tlv(0xa3, tlv(0x30, exts...)),
	), nil
}

// Assemble makes the certificate from the TBSCertificate and the ASN.1 DER ECDSA signature key@ gave over it.
func Assemble(tbs, signatureDER []byte) []byte {
	bits := append([]byte{0}, signatureDER...)
	return tlv(0x30, tbs, []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}, tlv(0x03, bits))
}
