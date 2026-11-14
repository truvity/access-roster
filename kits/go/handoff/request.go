package handoff

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
)

// Request is a PKCS#10 request read by the strict reader: the pieces that the certifier's checks and its policy use, each as
// DER where it is DER. See ParseRequest.
type Request struct {
	DER     []byte
	Info    []byte // the CertificationRequestInfo: what the key signed
	Subject []byte // the DER Name
	SPKI    []byte
	// Key is the request's key when it is ECDSA on P-384, and nil for any other key that parsed as a public key structure.
	Key        *ecdsa.PublicKey
	Extensions []RequestExtension
	sigAlg     []element
	signature  []byte
}

// RequestExtension is one extension of the extensionRequest, in the order written.
type RequestExtension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp384r1   = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// MaxRequest bounds a request file and the request in it (256 KiB, the limit of a JSON file of the contract).
const MaxRequest = 256 << 10

// ReadRequestPEM reads a request file: one PEM block labelled CERTIFICATE REQUEST, without headers, and nothing else, of at
// most 256 KiB. A fault is `malformed`. It returns the DER of the request.
func ReadRequestPEM(b []byte) ([]byte, error) {
	if len(b) > MaxRequest {
		return nil, refuse(CodeMalformed, "request.size")
	}
	// pem.Decode skips whatever comes before the BEGIN line, so the armour line must be the first line of the file.
	if !bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE REQUEST-----\n")) {
		return nil, refuse(CodeMalformed, "request.pem")
	}
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 || len(blk.Headers) != 0 || len(blk.Bytes) > MaxRequest {
		return nil, refuse(CodeMalformed, "request.pem")
	}
	return blk.Bytes, nil
}

// ParseRequest reads a PKCS#10 request (RFC 2986) in DER and refuses a fault of its form with `malformed`, the first check of the
// certifier that reads it (contract, "What the certifier checks", check 2): the DER shape, version number 0, the one
// extensionRequest attribute with its one value and no other attribute, the shape of each extension, the structure of the subject, and a
// public key that is a public key structure, in canonical form when it is P-384. A key of another algorithm is read as a key and
// refused by CheckKey, the next check, and a signature is checked by CheckPossession, the one after.
func ParseRequest(der []byte) (*Request, error) {
	bad := func(at string) (*Request, error) { return nil, refuse(CodeMalformed, "request."+at) }
	if len(der) > MaxRequest {
		return bad("size")
	}
	outer, err := readOne(der)
	if err != nil || !outer.universal(asn1.TagSequence, true) {
		return bad("der")
	}
	parts, err := readAll(outer.content)
	if err != nil || len(parts) != 3 {
		return bad("der")
	}
	info, alg, sig := parts[0], parts[1], parts[2]
	if !info.universal(asn1.TagSequence, true) || !alg.universal(asn1.TagSequence, true) {
		return bad("der")
	}
	if !sig.universal(asn1.TagBitString, false) || len(sig.content) < 1 || sig.content[0] != 0 {
		return bad("signature")
	}
	r := &Request{DER: der, Info: info.full, signature: sig.content[1:]}
	if r.sigAlg, err = readAll(alg.content); err != nil || len(r.sigAlg) == 0 || len(r.sigAlg) > 2 {
		return bad("algorithm")
	}
	if _, ok := oidOf(r.sigAlg[0]); !ok {
		return bad("algorithm")
	}
	fields, err := readAll(info.content)
	if err != nil || len(fields) != 4 {
		return bad("info")
	}
	version, subject, spki, attrs := fields[0], fields[1], fields[2], fields[3]
	// Version number 0 and no other (RFC 2986, section 4.1).
	if !version.universal(asn1.TagInteger, false) || !bytes.Equal(version.content, []byte{0}) {
		return bad("version")
	}
	if !subject.universal(asn1.TagSequence, true) || checkSubjectForm(subject) != nil {
		return bad("subject")
	}
	r.Subject = subject.full
	if err := r.readKey(spki); err != nil {
		return bad("key")
	}
	if !attrs.is(asn1.ClassContextSpecific, 0, true) {
		return bad("attributes")
	}
	if err := r.readAttributes(attrs.content); err != nil {
		return bad("attributes")
	}
	return r, nil
}

// readKey reads the SubjectPublicKeyInfo. A P-384 key must be in canonical form (an uncompressed point on the curve); a key of
// any other algorithm is kept for CheckKey to refuse.
func (r *Request) readKey(spki element) error {
	if !spki.universal(asn1.TagSequence, true) {
		return errDER
	}
	parts, err := readAll(spki.content)
	if err != nil || len(parts) != 2 || !parts[0].universal(asn1.TagSequence, true) {
		return errDER
	}
	bits := parts[1]
	if !bits.universal(asn1.TagBitString, false) || len(bits.content) < 1 || bits.content[0] != 0 {
		return errDER
	}
	alg, err := readAll(parts[0].content)
	if err != nil || len(alg) == 0 || len(alg) > 2 {
		return errDER
	}
	oid, ok := oidOf(alg[0])
	if !ok {
		return errDER
	}
	r.SPKI = spki.full
	if len(alg) == 2 && oid.Equal(oidECPublicKey) {
		if curve, ok := oidOf(alg[1]); ok && curve.Equal(oidSecp384r1) {
			k, err := x509.ParsePKIXPublicKey(spki.full)
			pub, isEC := k.(*ecdsa.PublicKey)
			if err != nil || !isEC || pub.Curve != elliptic.P384() {
				return errDER
			}
			r.Key = pub
		}
	}
	return nil
}

// readAttributes reads the content of the [0] attributes: exactly one attribute, extensionRequest, with exactly one value, a
// SEQUENCE of at least one extension.
func (r *Request) readAttributes(content []byte) error {
	attrs, err := readAll(content)
	if err != nil || len(attrs) != 1 || !attrs[0].universal(asn1.TagSequence, true) {
		return errDER
	}
	fields, err := readAll(attrs[0].content)
	if err != nil || len(fields) != 2 {
		return errDER
	}
	if oid, ok := oidOf(fields[0]); !ok || !oid.Equal(oidExtensionRequest) || !fields[1].universal(asn1.TagSet, true) {
		return errDER
	}
	values, err := readAll(fields[1].content)
	if err != nil || len(values) != 1 || !values[0].universal(asn1.TagSequence, true) {
		return errDER
	}
	exts, err := readAll(values[0].content)
	if err != nil || len(exts) == 0 {
		return errDER
	}
	for _, e := range exts {
		if !e.universal(asn1.TagSequence, true) {
			return errDER
		}
		f, err := readAll(e.content)
		if err != nil || len(f) < 2 || len(f) > 3 {
			return errDER
		}
		oid, ok := oidOf(f[0])
		if !ok {
			return errDER
		}
		x := RequestExtension{ID: oid}
		if len(f) == 3 {
			// A critical flag that is TRUE; DER leaves a FALSE out.
			if !f[1].universal(asn1.TagBoolean, false) || !bytes.Equal(f[1].content, []byte{0xff}) {
				return errDER
			}
			x.Critical = true
		}
		val := f[len(f)-1]
		if !val.universal(asn1.TagOctetString, false) {
			return errDER
		}
		x.Value = val.content
		r.Extensions = append(r.Extensions, x)
	}
	return nil
}

// CheckKey is check 4: the key is ECDSA on P-384. Another key is `algorithm-unsupported`.
func (r *Request) CheckKey() error {
	if r.Key == nil {
		return refuse("algorithm-unsupported", "request.key")
	}
	return nil
}

// CheckPossession is check 5: the signature algorithm is ecdsa-with-SHA384 and the signature verifies with the request's own
// key. Any other algorithm, and a signature that does not verify, is `possession-invalid`.
func (r *Request) CheckPossession() error {
	if err := r.CheckKey(); err != nil {
		return err
	}
	oid, _ := oidOf(r.sigAlg[0])
	if !oid.Equal(oidECDSAWithSHA384) || len(r.sigAlg) != 1 {
		return refuse("possession-invalid", "request.signature")
	}
	d := sha512.Sum384(r.Info)
	if !ecdsa.VerifyASN1(r.Key, d[:], r.signature) {
		return refuse("possession-invalid", "request.signature")
	}
	return nil
}
