package handoff

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"time"
)

// The length an intermediate certificate is expected to have: the certifier sets 13 calendar months, and the requester
// accepts 12 to 14 (contract, "What the requester checks before it installs"; REQ-PKI-032).
const (
	MinValidityMonths = 12
	MaxValidityMonths = 14
)

// Check names, as reported in Verified.Ran and Verified.NotRun.
const (
	CheckVersion       = "version"
	CheckRequestDigest = "request_sha256"
	CheckIssuer        = "issuer"
	CheckTrustSequence = "trust_sequence"
	CheckKey           = "key"
	CheckProfile       = "profile"
	CheckValidity      = "validity"
	CheckDigests       = "result_digests"
	// CheckWhereKeyLives is the certifier's checks 6 to 8 (the store, the evidence, the key match), which a requester
	// cannot make for itself. On the floor nobody but sluis has made them.
	CheckWhereKeyLives = "certifier_store_evidence_key"
)

// X509Answer is an X.509 answer and what the requester holds to check it against.
type X509Answer struct {
	// Request is the DER of the request that was sent, and Proof the proof file that went with it.
	Request []byte
	Proof   *Proof
	// CertFile is the file of the answer, `<stem>.cert.pem`, with its name; ResultFile is `<stem>.result.json`, and
	// nil on the floor, where the answer is the certificate alone.
	CertName   string
	CertFile   []byte
	ResultFile []byte
	// Anchors are the CA certificates the operator installed (the CA bundle).
	Anchors []*x509.Certificate
	// BundleSequence is the trust sequence in the first line of the bundle, or 0 when it has none.
	BundleSequence int64
	// RootList is the signed root list sluis holds, or nil. When it is held, a certificate of the bundle is an anchor
	// only if its key is on the list.
	RootList *RootList
	Now      time.Time
}

// Verified is an answer that passed the requester's checks.
type Verified struct {
	Cert    *x509.Certificate
	CertDER []byte
	// Floor says there was no result file.
	Floor bool
	// Ran and NotRun name the checks. A check that cannot run is never reported as passed (principle 4).
	Ran    []string
	NotRun []string
}

// CertifierRefused is the error of an answer whose outcome is refused: the certifier's codes.
type CertifierRefused struct{ Reasons []string }

func (e *CertifierRefused) Error() string { return "the certifier refused the request" }

// CheckX509 runs the requester's checks of the contract on an X.509 answer, in the order of the contract's table:
// the version and the request digest, the issuer and the trust sequence, the key, the profile, the validity and the
// digests of the result file. The first that fails gives the code. It returns what it checked and what it could not.
// It changes nothing: the caller installs only an answer that passed.
func CheckX509(a X509Answer) (*Verified, error) {
	v := &Verified{Floor: a.ResultFile == nil}
	csr, err := VerifyCSR(a.Request)
	if err != nil {
		return nil, err
	}

	var res *Result
	if !v.Floor {
		if res, err = ParseResult(a.ResultFile); err != nil {
			return nil, err
		}
		v.Ran = append(v.Ran, CheckVersion)
		if !res.Issued {
			return nil, &CertifierRefused{Reasons: res.Reasons}
		}
		if res.RequestSHA256 != RequestDigest(a.Request) || (a.Proof != nil && a.Proof.RequestSHA256 != res.RequestSHA256) {
			return nil, refuse(CodeRequestMismatch, "result.request_sha256")
		}
		v.Ran = append(v.Ran, CheckRequestDigest)
	} else {
		v.NotRun = append(v.NotRun, CheckVersion, CheckRequestDigest, CheckTrustSequence, CheckDigests, CheckWhereKeyLives)
	}

	cert, der, err := parseAnswerCert(a.CertFile)
	if err != nil {
		return nil, err
	}

	// The issuer: the certificate verifies to an anchor, and the root list sluis holds is at least as recent as the
	// answer's trust sequence.
	anchors, err := usableAnchors(a)
	if err != nil {
		return nil, err
	}
	issuerPin, err := verifyChain(cert, anchors, a.Now)
	if err != nil {
		return nil, err
	}
	if res != nil {
		if res.Issuer != issuerPin {
			return nil, refuse(CodeIssuer, "result.issuer")
		}
		if a.RootList != nil {
			if res.TrustSequence > a.RootList.Sequence {
				return nil, refuse(CodeIssuer, "result.trust_sequence")
			}
			v.Ran = append(v.Ran, CheckTrustSequence)
		} else {
			v.NotRun = append(v.NotRun, CheckTrustSequence)
		}
	}
	v.Ran = append(v.Ran, CheckIssuer)

	// The key is its own.
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return nil, refuse(CodeKeyMismatch, "certificate.key")
	}
	v.Ran = append(v.Ran, CheckKey)

	if err := checkProfile(cert, csr); err != nil {
		return nil, err
	}
	v.Ran = append(v.Ran, CheckProfile)

	if err := checkValidity(cert, a.Now); err != nil {
		return nil, err
	}
	v.Ran = append(v.Ran, CheckValidity)

	if res != nil {
		if !res.ValidFrom.Equal(cert.NotBefore) || !res.ValidUntil.Equal(cert.NotAfter) {
			return nil, refuse(CodeMalformed, "result.validity")
		}
		if len(res.Artifacts) != 1 || res.Artifacts[0].Name != a.CertName || res.Artifacts[0].SHA256 != sha256Hex(a.CertFile) {
			return nil, refuse(CodeMalformed, "result.artifacts")
		}
		v.Ran = append(v.Ran, CheckDigests)
	}
	v.Cert, v.CertDER = cert, der
	return v, nil
}

// parseAnswerCert reads `<stem>.cert.pem`: one certificate and nothing else, because a root issues an intermediate
// directly and "the root is not in the file" (contract, "What is issued").
func parseAnswerCert(b []byte) (*x509.Certificate, []byte, error) {
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || len(blk.Headers) != 0 {
		return nil, nil, refuse(CodeMalformed, "certificate.pem")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, refuse(CodeMalformed, "certificate.der")
	}
	return c, blk.Bytes, nil
}

// usableAnchors applies the root list to the bundle: a certificate of the bundle is an anchor only if its key is on the
// list sluis holds, and a bundle that names a sequence names the list's.
func usableAnchors(a X509Answer) ([]*x509.Certificate, error) {
	if a.RootList == nil {
		return a.Anchors, nil
	}
	if a.BundleSequence != 0 && a.BundleSequence != a.RootList.Sequence {
		return nil, refuse(CodeIssuer, "ca-bundle.trust_sequence")
	}
	var out []*x509.Certificate
	for _, c := range a.Anchors {
		if a.RootList.HasPin(SPKIPin(c)) {
			out = append(out, c)
		}
	}
	return out, nil
}

// verifyChain verifies that the certificate is signed by one of the anchors, as a path of one link (a root issues an
// intermediate directly), and returns the pin of the anchor that issued it. The leaf's own validity is the validity
// check's, so the path is verified at a time inside it; an anchor that is not valid then is an issuer failure.
func verifyChain(cert *x509.Certificate, anchors []*x509.Certificate, now time.Time) (string, error) {
	if len(anchors) == 0 {
		return "", refuse(CodeIssuer, "anchors")
	}
	at := now
	if at.Before(cert.NotBefore) {
		at = cert.NotBefore
	}
	if at.After(cert.NotAfter) {
		at = cert.NotAfter
	}
	// A critical extension outside the profile is the profile check's refusal, with its own code; the path is verified
	// as if the certificate had none, and checkProfile refuses every critical extension the request did not ask for.
	leaf := *cert
	leaf.UnhandledCriticalExtensions = nil
	for _, root := range anchors {
		pool := x509.NewCertPool()
		pool.AddCert(root)
		_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if err != nil {
			continue
		}
		return SPKIPin(root), nil
	}
	return "", refuse(CodeIssuer, "certificate.chain")
}

// checkProfile checks that the certificate is what the request asked: the same subject, version 3, and every requested
// extension present with the same criticality and the same value. No extension outside the request is critical; the
// key identifiers a CA adds are not.
func checkProfile(cert *x509.Certificate, csr *x509.CertificateRequest) error {
	if cert.Version != 3 || !bytes.Equal(cert.RawSubject, csr.RawSubject) {
		return refuse(CodeProfile, "certificate.subject")
	}
	want := map[string]bool{}
	for _, e := range csr.Extensions {
		id := e.Id.String()
		want[id] = true
		var got *struct{ critical bool }
		count := 0
		for _, c := range cert.Extensions {
			if c.Id.Equal(e.Id) {
				count++
				if !bytes.Equal(c.Value, e.Value) {
					return refusef(CodeProfile, "extension %s", id)
				}
				got = &struct{ critical bool }{c.Critical}
			}
		}
		if count != 1 || got.critical != e.Critical {
			return refusef(CodeProfile, "extension %s", id)
		}
	}
	for _, c := range cert.Extensions {
		if c.Critical && !want[c.Id.String()] {
			return refusef(CodeProfile, "critical extension %s", c.Id.String())
		}
	}
	return nil
}

// checkValidity checks that the validity has the length the requester expects, 12 to 14 months, and has not ended.
func checkValidity(cert *x509.Certificate, now time.Time) error {
	nb, na := cert.NotBefore.UTC(), cert.NotAfter.UTC()
	if na.Before(nb.AddDate(0, MinValidityMonths, 0)) {
		return refuse(CodeValidity, "length")
	}
	if na.After(nb.AddDate(0, MaxValidityMonths, 0)) {
		return refuse(CodeValidity, "length")
	}
	if !now.Before(na) {
		return refuse(CodeValidity, "ended")
	}
	if now.Before(nb) {
		return refuse(CodeValidity, "not yet valid")
	}
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
