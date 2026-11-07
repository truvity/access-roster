package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
)

// What stands in for ritueel here, and what does not.
//
// ritueel holds the roots of the real installations and certifies a request after a ceremony. Its software-root mode is
// the certifier that CI is meant to run, and it does not exist yet: the repository truvity/ritueel holds the contract and
// its test vectors and no program (checked 2026-11-07, commit 1a3b006). Until it does, a local installation is certified
// by this file: a throwaway root made at setup, and a certifier that does what the contract's floor asks of one
// ("PKCS#10 in, X.509 out") and runs the contract's checks 1 to 5 on the request with the kit's own code.
//
// It is not ritueel and proves nothing about ritueel's policy. It has no ritueel.yaml: it accepts the software store only,
// reads no attestation, and checks the shape of the request (the three extensions of an intermediate, name constraints critical with a permitted subtree)
// and not the names against a policy of anyone's. A request from a card or a KMS key is refused store-not-allowed here,
// where ritueel would accept it.

const (
	// RootName is in the subject of every root this tool makes. Nothing that carries it is a production root.
	RootName = "sluis TEST ONLY throwaway root"
	// permittedZone is the only name space the root certifies: the registrable parent of the local installation's hosts
	// (docs/runtimes/local.md, "Host names"). A chain from this root is valid for no other name, so a leaked key
	// certifies nothing real, and no verifier that trusts a production root trusts this one.
	permittedZone = "local.test"
	rootLife      = 3 * 365 * 24 * time.Hour
	listLife      = 365 * 24 * time.Hour
	// validityMonths is what the contract's certifier sets for an intermediate (REQ-PKI-032: 13 calendar months).
	validityMonths = 13
	// skew is how far back a certificate begins, so that a reader with a clock a little behind accepts it.
	skew = time.Minute
	// trustSequence is the sequence of the one root list this tool makes, and of the bundle.
	trustSequence = 1
	// noFingerprint is the OpenPGP fingerprint a root-list entry must carry. The test root has no OpenPGP primary, so the
	// value is all zeros, which no key has.
	noFingerprint = "0000000000000000000000000000000000000000"
	timeFormat    = "2006-01-02T15:04:05Z"
)

// Files of the directory of the root. private/ holds the key and is never mounted anywhere; trust/ is public.
const (
	rootKeyFile  = "private/root.key"
	rootCertFile = "trust/root.pem"
	bundleFile   = "trust/ca-bundle.pem"
	listFile     = "trust/root-list.json"
	jwsFile      = "trust/root-list.jws"
	pinFile      = "trust/root.pin"
)

// Root is the throwaway root of a run.
type Root struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	// Pin is the x509_spki_sha256 of the root: what `sluis key install --root-pin` takes.
	Pin string
}

// Init makes the root and its public trust files in dir when they are not there, and says what it did. A root that is
// there is kept while it and its root list have more than a day left, so that a second start of the same run does not
// change the root an installed intermediate leads to.
func Init(dir string, now time.Time) (*Root, string, error) {
	if r, err := load(dir); err == nil && now.Add(24*time.Hour).Before(r.cert.NotAfter) {
		if _, err := os.Stat(filepath.Join(dir, jwsFile)); err == nil { //nolint:gosec // G703: a path of the harness's own directory
			return r, "kept the root " + r.Pin, nil
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, "", err
	}
	for _, sub := range []string{"private", "trust"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil { //nolint:gosec // G703: as above
			return nil, "", err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, "", err
	}
	var tag [4]byte
	if _, err := rand.Read(tag[:]); err != nil {
		return nil, "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		// The random tag tells two installations' roots apart in a log; the rest says what it is.
		Subject:               pkix.Name{CommonName: fmt.Sprintf("%s %x", RootName, tag), Organization: []string{"sluis TEST ONLY"}},
		NotBefore:             now.Add(-time.Hour).Truncate(time.Second),
		NotAfter:              now.Add(rootLife).Truncate(time.Second),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		// Critical name constraints (RFC 5280, 4.2.1.10): the root certifies names under local.test and nothing else. URI
		// constraints without a leading dot match the host itself, with one the hosts below it.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{permittedZone},
		PermittedURIDomains:         []string{permittedZone, "." + permittedZone},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", err
	}
	r := &Root{key: key, cert: cert, Pin: handoff.SPKIPin(cert)}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	list, jws, err := r.rootList(now)
	if err != nil {
		return nil, "", err
	}
	// The key is written first, 0600: a failure after it leaves a root with no trust files, which the next Init replaces.
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{rootKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600},
		{rootCertFile, certPEM, 0o644},
		{bundleFile, append([]byte(fmt.Sprintf("# trust-sequence: %d\n", trustSequence)), certPEM...), 0o644},
		{listFile, list, 0o644},
		{jwsFile, jws, 0o644},
		{pinFile, []byte(r.Pin + "\n"), 0o644},
	}
	for _, f := range files {
		if err := writeFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return nil, "", err
		}
	}
	return r, "made the root " + r.Pin, nil
}

// rootList is root-list.json and its detached signature, signed by the root itself (ritueel's root list reference: a
// list is signed by roots it names or already trusts; here the one root signs, and the host is given its pin).
func (r *Root) rootList(now time.Time) (list, jws []byte, err error) {
	// The members in the order the reference writes them: sorted by name, no whitespace.
	list = []byte(fmt.Sprintf(`{"expires_at":"%s","roots":[{"label":"A","openpgp_fingerprint":"%s","x509_spki_sha256":"%s"}],"sequence":%d,"signed_at":"%s","version":1}`,
		now.Add(listLife).UTC().Truncate(time.Second).Format(timeFormat), noFingerprint, r.Pin, trustSequence, now.UTC().Truncate(time.Second).Format(timeFormat)))
	hdr, err := json.Marshal(map[string]any{"alg": "ES384", "kid": r.Pin, "typ": "root-list+json", "x5c": []string{base64.StdEncoding.EncodeToString(r.cert.Raw)}})
	if err != nil {
		return nil, nil, err
	}
	prot := base64.RawURLEncoding.EncodeToString(hdr)
	sig, err := r.signES384([]byte(prot + "." + base64.RawURLEncoding.EncodeToString(list)))
	if err != nil {
		return nil, nil, err
	}
	jws = []byte(fmt.Sprintf(`{"signatures":[{"protected":"%s","signature":"%s"}]}`, prot, base64.RawURLEncoding.EncodeToString(sig)))
	return list, jws, nil
}

// signES384 signs as a JWS does (RFC 7518, 3.4): r and s, 48 bytes each, over SHA-384 of the input.
func (r *Root) signES384(input []byte) ([]byte, error) {
	d := sha512.Sum384(input)
	rr, ss, err := ecdsa.Sign(rand.Reader, r.key, d[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 96)
	rr.FillBytes(sig[:48])
	ss.FillBytes(sig[48:])
	return sig, nil
}

// load reads the root of dir.
func load(dir string) (*Root, error) {
	kb, err := os.ReadFile(filepath.Join(dir, rootKeyFile)) //nolint:gosec // a path of the harness's own directory
	if err != nil {
		return nil, err
	}
	cb, err := os.ReadFile(filepath.Join(dir, rootCertFile)) //nolint:gosec // as above
	if err != nil {
		return nil, err
	}
	kblk, _ := pem.Decode(kb)
	cblk, _ := pem.Decode(cb)
	if kblk == nil || cblk == nil {
		return nil, errors.New("certifier: the root is not PEM")
	}
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("certifier: the root certificate is not the key's")
	}
	return &Root{key: key, cert: cert, Pin: handoff.SPKIPin(cert)}, nil
}

// Load reads the root of dir, which Init made.
func Load(dir string) (*Root, error) { return load(dir) }

// Outcome is what Certify did for one request.
type Outcome struct {
	Stem string
	// Issued is true for a certificate written now; Kept for an answer that was there already and was left as it is.
	Issued, Kept bool
	// Reasons are the certifier's codes of a refusal; the result file says so, and no certificate was written.
	Reasons []string
}

// Certify answers every request in requests, writing <stem>.cert.pem and <stem>.result.json into answers. A request that
// has an answer for the same request digest is left alone: a second start does not re-issue. The checks are the
// contract's 1 to 5 on the request (the kit's CheckRequest) and then this tool's: the software store, and the request's
// shape. An issued answer is read back with the requester's checks (the kit's CheckX509) against this root and its list
// before it is kept, so the tool never leaves an answer that `sluis key install` would refuse.
func (r *Root) Certify(requests, answers string, now time.Time) ([]Outcome, error) {
	entries, err := os.ReadDir(requests)
	if err != nil {
		return nil, err
	}
	var stems []string
	for _, e := range entries {
		if stem, ok := strings.CutSuffix(e.Name(), ".csr.pem"); ok && !e.IsDir() && handoff.ValidStem(stem) {
			stems = append(stems, stem)
		}
	}
	sort.Strings(stems)
	if len(stems) == 0 {
		return nil, fmt.Errorf("certifier: no request in %s", requests)
	}
	if err := os.MkdirAll(answers, 0o755); err != nil { //nolint:gosec // public material
		return nil, err
	}
	var out []Outcome
	for _, stem := range stems {
		o, err := r.certifyOne(stem, requests, answers, now)
		if err != nil {
			return out, fmt.Errorf("certifier: %s: %w", stem, err)
		}
		out = append(out, o)
	}
	return out, nil
}

func (r *Root) certifyOne(stem, requests, answers string, now time.Time) (Outcome, error) {
	o := Outcome{Stem: stem}
	csrPEM, err := os.ReadFile(filepath.Join(requests, stem+".csr.pem")) //nolint:gosec // the run's own directory
	if err != nil {
		return o, err
	}
	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		// No digest can be named for a file that is not PEM, so there is nothing a result file could answer.
		return o, errors.New("the request is not PEM")
	}
	digest := handoff.RequestDigest(blk.Bytes)
	certName := stem + ".cert.pem"
	if kept, err := r.answered(filepath.Join(answers, stem+".result.json"), digest); err != nil {
		return o, err
	} else if kept {
		o.Kept = true
		return o, nil
	}
	proofJSON, err := os.ReadFile(filepath.Join(requests, stem+".proof.json")) //nolint:gosec // as above
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return o, r.refuse(&o, answers, stem, digest, handoff.CodeMalformed)
		}
		return o, err
	}
	csr, proof, err := handoff.CheckRequest(csrPEM, proofJSON)
	if err != nil {
		var ref *handoff.Refusal
		if !errors.As(err, &ref) {
			return o, err
		}
		return o, r.refuse(&o, answers, stem, digest, ref.Code)
	}
	// The shape of the request first, then the store: a request of the wrong shape is refused by policy whatever its store.
	if !intermediateShape(csr) {
		return o, r.refuse(&o, answers, stem, digest, "policy")
	}
	if proof.Store != handoff.StoreSoftware {
		return o, r.refuse(&o, answers, stem, digest, "store-not-allowed")
	}
	serial, err := serialNumber()
	if err != nil {
		return o, err
	}
	pub, err := x509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return o, err
	}
	nb := now.Add(-skew).UTC().Truncate(time.Second)
	tpl := &x509.Certificate{
		SerialNumber: serial, RawSubject: csr.RawSubject, NotBefore: nb, NotAfter: nb.AddDate(0, validityMonths, 0),
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		// The requested extensions, with their criticality, are the whole of the profile (the contract's floor).
		ExtraExtensions: csr.Extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, r.cert, pub, r.key)
	if err != nil {
		return o, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return o, err
	}
	result, err := json.Marshal(map[string]any{
		"handoff": 1, "type": handoff.TypeX509, "request_sha256": digest, "outcome": "issued",
		"artifacts":  []map[string]string{{"name": certName, "sha256": sha256Hex(certPEM)}},
		"valid_from": cert.NotBefore.UTC().Format(timeFormat), "valid_until": cert.NotAfter.UTC().Format(timeFormat),
		"issuer": r.Pin, "trust_sequence": trustSequence,
	})
	if err != nil {
		return o, err
	}
	if err := r.readBack(blk.Bytes, proof, certName, certPEM, result, now); err != nil {
		return o, fmt.Errorf("the answer would not install, and is not written: %w", err)
	}
	// The certificate first and the result file last: the result file is what marks the request as answered.
	if err := writeFile(filepath.Join(answers, certName), certPEM, 0o644); err != nil {
		return o, err
	}
	if err := writeFile(filepath.Join(answers, stem+".result.json"), result, 0o644); err != nil {
		return o, err
	}
	o.Issued = true
	return o, nil
}

// readBack runs the requester's checks of the contract on the answer, against this root and the list it signed.
func (r *Root) readBack(csrDER []byte, proof *handoff.Proof, certName string, certPEM, result []byte, now time.Time) error {
	list, jws, err := r.rootList(now)
	if err != nil {
		return err
	}
	// The list is read against the root's own pin, as a host installed with it would read it.
	held, _, err := handoff.ReadRootList(list, jws, nil, []string{r.Pin}, now)
	if err != nil {
		return err
	}
	_, err = handoff.CheckX509(handoff.X509Answer{
		Request: csrDER, Proof: proof, CertName: certName, CertFile: certPEM, ResultFile: result,
		Anchors: []*x509.Certificate{r.cert}, BundleSequence: trustSequence, RootList: held, Now: now,
	})
	return err
}

// answered reports whether the result file at path answers the request with this digest.
func (r *Root) answered(path, digest string) (bool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the run's own directory
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	res, err := handoff.ParseResult(b)
	if err != nil {
		// An answer that does not read is not an answer: it is made again.
		return false, nil //nolint:nilerr // see above
	}
	return res.RequestSHA256 == digest, nil
}

// refuse writes the result file of a refusal and records the reasons. No certificate is written; one left by an earlier
// answer to another request is removed, so that the answer is never a certificate beside a refusal.
func (r *Root) refuse(o *Outcome, answers, stem, digest, code string) error {
	b, err := json.Marshal(map[string]any{
		"handoff": 1, "type": handoff.TypeX509, "request_sha256": digest, "outcome": "refused", "reasons": []string{code},
	})
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(answers, stem+".cert.pem")); err != nil && !errors.Is(err, fs.ErrNotExist) { //nolint:gosec // G703: the run's own directory, and a stem that passed ValidStem
		return err
	}
	o.Reasons = []string{code}
	return writeFile(filepath.Join(answers, stem+".result.json"), b, 0o644)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// writeFile writes a file whole, through a temporary file and a rename, so that a reader never sees half of it.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".certifier-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() //nolint:gosec // G703: the name of a temporary file this function made
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path) //nolint:gosec // G703: as above
}

// intermediateShape says whether the request asks for an intermediate of the contract's profile and for nothing else:
// exactly basic constraints (critical, a CA with path length 0), key usage (critical, keyCertSign) and name constraints
// (critical, a permitted subtree). It is the part of ritueel's policy that needs no file: a request without name
// constraints is refused, whoever made it.
func intermediateShape(csr *x509.CertificateRequest) bool {
	seen := map[string]bool{}
	for _, e := range csr.Extensions {
		id := e.Id.String()
		if !e.Critical || seen[id] {
			return false
		}
		seen[id] = true
		switch id {
		case "2.5.29.19":
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional,default:-1"`
			}
			if rest, err := asn1.Unmarshal(e.Value, &bc); err != nil || len(rest) != 0 || !bc.IsCA || bc.MaxPathLen != 0 {
				return false
			}
		case "2.5.29.15":
			var bits asn1.BitString
			if rest, err := asn1.Unmarshal(e.Value, &bits); err != nil || len(rest) != 0 || bits.At(5) == 0 { // keyCertSign
				return false
			}
		case "2.5.29.30":
			var nc struct {
				Permitted asn1.RawValue `asn1:"optional,tag:0"`
				Excluded  asn1.RawValue `asn1:"optional,tag:1"`
			}
			if rest, err := asn1.Unmarshal(e.Value, &nc); err != nil || len(rest) != 0 || len(nc.Permitted.Bytes) == 0 {
				return false
			}
		default:
			return false
		}
	}
	return len(seen) == 3
}
