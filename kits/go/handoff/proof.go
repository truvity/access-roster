package handoff

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Proof is `<stem>.proof.json` of an X.509 request: it ties the request to the evidence of where the key lives
// (contract, "The proof file").
type Proof struct {
	// RequestSHA256 is the SHA-256 of the DER of the request, in lower-case hexadecimal.
	RequestSHA256 string
	// Store is where the key lives: StorePIV, StoreAWSKMS or StoreSoftware.
	Store string
	// Attestation is the evidence of a piv key, DER, leaf first: the slot certificate, then the token's own
	// certificate.
	Attestation [][]byte
	// KeyARN and PublicKey are the evidence of an aws-kms key: the full ARN and the SubjectPublicKeyInfo, DER. The
	// certifier does not trust the public key; it reads the key itself.
	KeyARN    string
	PublicKey []byte
}

// RequestDigest is the digest the proof names for a request: the SHA-256 of its DER.
func RequestDigest(csrDER []byte) string {
	sum := sha256.Sum256(csrDER)
	return hex.EncodeToString(sum[:])
}

// Marshal writes the proof file: one UTF-8 object, members in the order of the contract, Base64 with padding for
// certificates and keys, no byte order mark and no trailing data but a newline.
func (p *Proof) Marshal() ([]byte, error) {
	if !isDigest(p.RequestSHA256) {
		return nil, fmt.Errorf("handoff: the proof names no request digest")
	}
	var b bytes.Buffer
	b.WriteString(`{"handoff":1,"type":"` + TypeX509 + `","request_sha256":"` + p.RequestSHA256 + `","store":`)
	switch p.Store {
	case StoreSoftware:
		if len(p.Attestation) != 0 || p.KeyARN != "" || p.PublicKey != nil {
			return nil, fmt.Errorf("handoff: a software key has no evidence")
		}
		b.WriteString(`"software"`)
	case StorePIV:
		if len(p.Attestation) < 2 || p.KeyARN != "" || p.PublicKey != nil {
			return nil, fmt.Errorf("handoff: a piv key has an attestation of two certificates")
		}
		b.WriteString(`"piv","evidence":{"attestation":[`)
		for i, c := range p.Attestation {
			if i > 0 {
				b.WriteByte(',')
			}
			enc, _ := json.Marshal(base64.StdEncoding.EncodeToString(c))
			b.Write(enc)
		}
		b.WriteString(`]}`)
	case StoreAWSKMS:
		if p.KeyARN == "" || len(p.PublicKey) == 0 || len(p.Attestation) != 0 {
			return nil, fmt.Errorf("handoff: an aws-kms key has its ARN and its public key")
		}
		arn, _ := json.Marshal(p.KeyARN)
		pk, _ := json.Marshal(base64.StdEncoding.EncodeToString(p.PublicKey))
		b.WriteString(`"aws-kms","evidence":{"key_arn":` + string(arn) + `,"public_key":` + string(pk) + `}`)
	default:
		return nil, fmt.Errorf("handoff: unknown store")
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}

// ParseProof reads a proof file of an X.509 request, with the contract's rules for a JSON file. A proof of another
// type is refused as malformed: a build that does not read the type does not know it.
func ParseProof(b []byte) (*Proof, error) {
	o, err := parseObject(b, "")
	if err != nil {
		return nil, err
	}
	if err := o.version(); err != nil {
		return nil, err
	}
	typ, _, err := o.str("type", true)
	if err != nil {
		return nil, err
	}
	if typ != TypeX509 {
		return nil, refuse(CodeMalformed, "type")
	}
	p := &Proof{}
	if p.RequestSHA256, _, err = o.str("request_sha256", true); err != nil {
		return nil, err
	}
	if !isDigest(p.RequestSHA256) {
		return nil, refuse(CodeMalformed, "request_sha256")
	}
	if p.Store, _, err = o.str("store", true); err != nil {
		return nil, err
	}
	ev, hasEv, err := o.object("evidence", false)
	if err != nil {
		return nil, err
	}
	switch p.Store {
	case StoreSoftware:
		if hasEv {
			return nil, refuse(CodeMalformed, "evidence")
		}
	case StorePIV:
		if !hasEv {
			return nil, refuse(CodeMalformed, "evidence")
		}
		items, _, err := ev.list("attestation", true)
		if err != nil {
			return nil, err
		}
		if len(items) < 2 {
			return nil, refuse(CodeMalformed, "evidence.attestation")
		}
		for i, raw := range items {
			der, ok := b64(raw)
			if !ok {
				return nil, refusef(CodeMalformed, "evidence.attestation[%d]", i)
			}
			p.Attestation = append(p.Attestation, der)
		}
		if err := ev.done(); err != nil {
			return nil, err
		}
	case StoreAWSKMS:
		if !hasEv {
			return nil, refuse(CodeMalformed, "evidence")
		}
		if p.KeyARN, _, err = ev.str("key_arn", true); err != nil {
			return nil, err
		}
		raw, _ := ev.take("public_key")
		var ok bool
		if p.PublicKey, ok = b64(raw); !ok {
			return nil, refuse(CodeMalformed, "evidence.public_key")
		}
		if err := ev.done(); err != nil {
			return nil, err
		}
	default:
		return nil, refuse(CodeMalformed, "store")
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return p, nil
}

// b64 reads a JSON string of standard Base64 with padding (RFC 4648, section 4), as the x5c member of RFC 7515 does.
func b64(raw json.RawMessage) ([]byte, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return nil, false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil, false
	}
	der, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(der) == 0 {
		return nil, false
	}
	return der, true
}

// CheckAttestationShape parses the certificates of a piv proof: both must be certificates. It does not verify the
// chain; that is the certifier's check, and key@'s card driver makes the one that sluis makes when it requests.
func (p *Proof) CheckAttestationShape() error {
	for i, der := range p.Attestation {
		if _, err := x509.ParseCertificate(der); err != nil {
			return refusef(CodeMalformed, "evidence.attestation[%d]", i)
		}
	}
	return nil
}

// ParseCSRPEM reads a request file: exactly one PEM block labelled CERTIFICATE REQUEST, and nothing else.
func ParseCSRPEM(b []byte) (*x509.CertificateRequest, error) {
	der, err := ReadRequestPEM(b)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, refuse(CodeMalformed, "request.der")
	}
	return csr, nil
}

// CheckRequestFiles runs the certifier's checks 1 to 5 on the files of an X.509 request: the version, the files parse with no
// unknown or repeated member, the request is well formed, `request_sha256` is the digest of the request, the key is ECDSA on P-384
// and the request's signature verifies with its own key. The first check that fails gives the code (contract, "What the certifier
// checks"). It returns the request as the strict reader read it.
func CheckRequestFiles(csrPEM, proofJSON []byte) (*Request, *Proof, error) {
	proof, err := ParseProof(proofJSON)
	if err != nil {
		return nil, nil, err
	}
	der, err := ReadRequestPEM(csrPEM)
	if err != nil {
		return nil, nil, err
	}
	// Check 2 reads the request too: a request that is not well formed is `malformed` before its digest is compared.
	r, err := ParseRequest(der)
	if err != nil {
		return nil, nil, err
	}
	if proof.RequestSHA256 != RequestDigest(der) {
		return nil, nil, refuse(CodeRequestMismatch, "proof.request_sha256")
	}
	if err := r.CheckKey(); err != nil {
		return nil, nil, err
	}
	if err := r.CheckPossession(); err != nil {
		return nil, nil, err
	}
	return r, proof, nil
}

// CheckRequest is CheckRequestFiles for sluis's own request, which it has just made, so that it never writes one the certifier
// would refuse as unreadable. It returns the request as the standard library reads it.
func CheckRequest(csrPEM, proofJSON []byte) (*x509.CertificateRequest, *Proof, error) {
	r, proof, err := CheckRequestFiles(csrPEM, proofJSON)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(r.DER)
	if err != nil {
		return nil, nil, refuse(CodeMalformed, "request.der")
	}
	return csr, proof, nil
}
