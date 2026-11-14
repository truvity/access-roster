package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
	"github.com/truvity/sluis/v2/kits/go/slotplan"
)

// What stands in for ritueel here, and what does not.
//
// ritueel holds the roots of the real installations and certifies a request after a ceremony. Its software-root mode is
// the certifier that CI is meant to run, and it does not exist yet: the repository truvity/ritueel holds the contract and
// its test vectors and no program (checked 2026-11-07, commit 1a3b006). Until it does, a local installation is certified
// by this file: a throwaway root made at setup, and a certifier that does what the contract's floor asks of one
// ("PKCS#10 in, X.509 out") and runs the contract's checks 1 to 5 on the request with the kit's own code.
//
// It is not ritueel and proves nothing about ritueel's policy. It has no ritueel.yaml and no ceremony. It follows the
// contract's order of checks on a request: 1 to 5 (the kit's CheckRequest); 6, the store: software always, a PIV card only
// when the caller pins the maker's attestation roots (Policy.Attestation), nothing else (a KMS key is refused
// store-not-allowed); 7, the evidence of a card (the kit's CheckPIVEvidence: the chain to a pinned root, the token's
// certificate a CA with path length 0, the slot and the extensions); 8, the attested key is the request's; 9, the policy
// below. A policy it has is small and fixed: the request asks for the three extensions of an intermediate with critical name
// constraints; every permitted name lies inside the zones this root was made for; a card has the firmware, the PIN policy
// and the slot of the purpose (9c for x509-intermediate), and, when the caller lists serials, one of them.
//
// A board's run uses it on the admin host, with a root of its own made for the board names, and never on a board.

const (
	// RootName is in the subject of every root this tool makes. Nothing that carries it is a production root.
	RootName = "sluis TEST ONLY throwaway root"
	// DefaultZone is the name space of the local installation (docs/runtimes/local.md, "Host names"). A root certifies
	// names inside its zones and nothing else, and every zone is under the reserved top-level domain test (RFC 6761), so a
	// leaked key certifies nothing real, and no verifier that trusts a production root trusts this one.
	DefaultZone = "local.test"
	rootLife    = 3 * 365 * 24 * time.Hour
	// validityMonths is what the contract's certifier sets for an intermediate (REQ-PKI-032: 13 calendar months).
	validityMonths = 13
	// skew is how far back a certificate begins, so that a reader with a clock a little behind accepts it.
	skew = time.Minute
	// trustSequence is the sequence of the one root list this tool makes, and of the bundle.
	trustSequence = 1
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
	Pin   string
	zones []string
}

// Init makes the root and its public trust files in dir when they are not there, and says what it did. A root that is
// there is kept while it and its root list have more than a day left, so that a second start of the same run does not
// change the root an installed intermediate leads to.
func Init(dir string, now time.Time, zones []string) (*Root, string, error) {
	zones, err := normaliseZones(zones, true)
	if err != nil {
		return nil, "", err
	}
	return initRoot(dir, now, zones)
}

// normaliseZones sorts the zones and refuses a zone that is not a lower-case name under test. The tests make a root for a
// zone of their own with onlyTest false.
func normaliseZones(zones []string, onlyTest bool) ([]string, error) {
	if len(zones) == 0 {
		zones = []string{DefaultZone}
	}
	out := slices.Clone(zones)
	slices.Sort(out)
	out = slices.Compact(out)
	for _, z := range out {
		if !zoneName.MatchString(z) || (onlyTest && !strings.HasSuffix(z, ".test")) {
			return nil, fmt.Errorf("certifier: the zone %q is not a lower-case name under .test", z)
		}
	}
	return out, nil
}

var zoneName = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func initRoot(dir string, now time.Time, zones []string) (*Root, string, error) {
	if r, err := load(dir); err == nil && r.usable(dir, now, zones) {
		return r, "kept the root " + r.Pin, nil
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
		PermittedDNSDomains:         zones,
		PermittedURIDomains:         withSubdomains(zones),
		// Every other kind of name is shut out, as the intermediate's own request does for IP addresses (REQ-PKI-046): RFC
		// 5280 leaves a kind with no subtree unconstrained. No IP address (both families), and mail only at local.test.
		ExcludedIPRanges:        []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}},
		PermittedEmailAddresses: withSubdomains(zones),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", err
	}
	r := &Root{key: key, cert: cert, Pin: handoff.SPKIPin(cert), zones: zones}
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

// usable says whether the root of dir can still be kept: it is for the same zones, the root and its root list both have more than a day left, and
// the list is the one the root signed, read with the root's pin as a host does. A list that expired (a list lives 13
// calendar months) would make `key install` refuse every answer, so the root is made again; the intermediate installed under the
// old one is then not under the new, and the run is a first start. A run lives 13 months at most.
func (r *Root) usable(dir string, now time.Time, zones []string) bool {
	if !slices.Equal(r.zones, zones) {
		return false // another set of names: a root made for them
	}
	if !now.Add(24 * time.Hour).Before(r.cert.NotAfter) {
		return false
	}
	list, err := os.ReadFile(filepath.Join(dir, listFile)) //nolint:gosec // a path of the harness's own directory
	if err != nil {
		return false
	}
	jws, err := os.ReadFile(filepath.Join(dir, jwsFile)) //nolint:gosec // as above
	if err != nil {
		return false
	}
	_, _, err = handoff.ReadRootList(list, jws, nil, []string{r.Pin}, now.Add(24*time.Hour))
	return err == nil
}

// rootList is root-list.json and its detached signature, signed by the root itself (ritueel's root list reference: a
// list is signed by roots it names or already trusts; here the one root signs, and the host is given its pin).
func (r *Root) rootList(now time.Time) (list, jws []byte, err error) {
	// The members in the order the reference writes them: sorted by name, no whitespace. The expiry is 13 calendar months after
	// the signing, the only value a reader accepts, and the entry has no OpenPGP fingerprint: the test root has no OpenPGP primary,
	// which a list says by leaving the member out.
	signed := now.UTC().Truncate(time.Second)
	list = []byte(fmt.Sprintf(`{"expires_at":"%s","roots":[{"label":"A","x509_spki_sha256":"%s"}],"sequence":%d,"signed_at":"%s","version":1}`,
		handoff.RootListExpiry(signed).Format(timeFormat), r.Pin, trustSequence, signed.Format(timeFormat)))
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
	if fi, err := os.Stat(filepath.Join(dir, rootKeyFile)); err == nil && fi.Mode().Perm()&0o077 != 0 { //nolint:gosec // as below
		return nil, fmt.Errorf("certifier: the root's key is readable by others (mode %04o); remove %s/private or chmod 600 its key", fi.Mode().Perm(), dir)
	}
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
	return &Root{key: key, cert: cert, Pin: handoff.SPKIPin(cert), zones: slices.Clone(cert.PermittedDNSDomains)}, nil
}

// withSubdomains lists each zone twice, as the host and as the hosts below it (a URI or mail constraint without a leading
// dot matches the host itself, with one the hosts below it).
func withSubdomains(zones []string) []string {
	var out []string
	for _, z := range zones {
		out = append(out, z, "."+z)
	}
	return out
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
	// Card is what was read from the attestation of a card request, for the record of the run; nil for software.
	Card *handoff.PIVEvidence
}

// Policy is what the caller sets for a run: whether a PIV card may be certified, and the rules of check 9 that name a card.
// The zero Policy certifies software keys only.
type Policy struct {
	// Attestation is the maker's roots and intermediates, pinned by the caller. Nil: the card store is not allowed.
	Attestation *handoff.AttestationAnchors
	// MinFirmware is the oldest firmware accepted; 5.7.0 when zero (the contract's reference policy).
	MinFirmware [3]byte
	// ContractShape checks the shape of a request as ritueel's reference policy does (handoff.CheckRequestProfile: the four
	// extensions of an intermediate, with critical name constraints of at least one permitted subtree, and a subject of the
	// contract's rules) and not as key@ signs it (handoff.CheckInfo: the one canonical shape, a common name only, with every IP
	// address excluded). It is for running ritueel's request vectors, which are of the first kind, and no flag of the command
	// sets it. Either way the request is read by the strict reader and the profile applies; key@'s shape is checked besides.
	ContractShape bool
	// Listed, when set, is ritueel's rule for names: a permitted URI constraint is inside only when it equals a listed URI host,
	// and a permitted DNS name only when it equals a listed DNS name (the contract's "Policy", the name constraints rule). Without
	// it the names are inside the zones the root was made for (a zone and every name below it), which is the rule of the boards'
	// installation: its one name is listed by the board's script as a URI host and as a DNS name, so that the exact rule would
	// accept it too.
	Listed *ListedNames
	// Roots are the root certificates of a CA bundle that the policy keeps a request from naming or keying: a request whose
	// subject is the name of one (compared as OpenSSL compares names) or whose key is the key of one is refused with `policy`. The
	// certifier's own root is always one.
	Roots []*x509.Certificate
	// Serials, when not empty, are the serial numbers of the tokens that may be certified, in decimal: the cards of a
	// run. A request from a token that is not listed is refused by policy.
	Serials []string
}

func (p Policy) minFirmware() [3]byte {
	if p.MinFirmware == [3]byte{} {
		return [3]byte{5, 7, 0}
	}
	return p.MinFirmware
}

// ListedNames are the entries that ritueel's policy lists for a requester: its URI hosts and its DNS names.
type ListedNames struct {
	URIHosts, DNSNames []string
}

// Certify answers every request in requests, writing <stem>.cert.pem and <stem>.result.json into answers. A request that
// has an answer for the same request digest is left alone: a second start does not re-issue. The checks are the
// contract's 1 to 5 on the request (the kit's CheckRequest) and then this tool's: the software store, and the request's
// shape. An issued answer is read back with the requester's checks (the kit's CheckX509) against this root and its list
// before it is kept, so the tool never leaves an answer that `sluis key install` would refuse.
func (r *Root) Certify(requests, answers string, now time.Time, pol Policy) ([]Outcome, error) {
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
		o, err := r.certifyOne(stem, requests, answers, now, pol)
		if err != nil {
			return out, fmt.Errorf("certifier: %s: %w", stem, err)
		}
		out = append(out, o)
	}
	return out, nil
}

func (r *Root) certifyOne(stem, requests, answers string, now time.Time, pol Policy) (Outcome, error) {
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
	// Checks 1 to 5, in the contract's order: the files parse and the request is well formed (malformed), the digest, the key
	// (algorithm-unsupported) and the signature (possession-invalid). The reader is strict: the library's own would read apart
	// what a certifier must refuse for another code.
	req, proof, err := handoff.CheckRequestFiles(csrPEM, proofJSON)
	if err != nil {
		var ref *handoff.Refusal
		if !errors.As(err, &ref) {
			return o, err
		}
		return o, r.refuse(&o, answers, stem, digest, ref.Code)
	}
	// Check 6, the store; 7, the evidence; 8, the key match; 9, the policy: the contract's order.
	var card *handoff.PIVEvidence
	switch {
	// A run that pins the maker's attestation is a run for cards: a software key would be certified without the serial binding
	// the run lists, so it is refused there.
	case proof.Store == handoff.StoreSoftware && pol.Attestation == nil:
	case proof.Store == handoff.StorePIV && pol.Attestation != nil:
		if card, err = handoff.CheckPIVEvidence(proof.Attestation, *pol.Attestation, now); err != nil {
			return o, r.refuseFor(&o, answers, stem, digest, err)
		}
		o.Card = card
		if !bytes.Equal(card.SPKI, req.SPKI) {
			return o, r.refuse(&o, answers, stem, digest, handoff.CodeKeyMismatch)
		}
	default:
		return o, r.refuse(&o, answers, stem, digest, "store-not-allowed")
	}
	if !r.requestAcceptable(req, pol) || (card != nil && !pol.acceptsCard(card)) {
		return o, r.refuse(&o, answers, stem, digest, "policy")
	}
	serial, err := serialNumber()
	if err != nil {
		return o, err
	}
	pub, err := x509.ParsePKIXPublicKey(req.SPKI)
	if err != nil {
		return o, err
	}
	// The requested extensions, with their criticality and in their order, are the whole of the profile (the contract's floor):
	// the extended key usage among them, which the certificate carries as asked, not critical.
	exts := make([]pkix.Extension, 0, len(req.Extensions))
	for _, e := range req.Extensions {
		exts = append(exts, pkix.Extension{Id: e.ID, Critical: e.Critical, Value: e.Value})
	}
	nb := now.Add(-skew).UTC().Truncate(time.Second)
	tpl := &x509.Certificate{
		SerialNumber: serial, RawSubject: req.Subject, NotBefore: nb, NotAfter: nb.AddDate(0, validityMonths, 0),
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		ExtraExtensions:    exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, r.cert, pub, r.key)
	if err != nil {
		// The only input that can make a certificate fail to be made is the content of the request (a name that is not a name):
		// that is a refusal of this request, and the rest of the batch goes on.
		return o, r.refuse(&o, answers, stem, digest, "policy")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return o, r.refuse(&o, answers, stem, digest, "policy")
	}
	// Check 9, the names: read from the certificate that was just made, so that the names checked are the names signed.
	if !r.namesInside(cert, pol.Listed) {
		return o, r.refuse(&o, answers, stem, digest, "policy")
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

// answered reports whether the result file at path is an issued answer to the request with this digest.
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
	// Only an issued answer is kept. A refusal is made again by the next run, so that a policy that changed (a serial added to the
	// run, a root made for more names) answers a request that was refused before; it costs nothing, a refusal being a file.
	return res.Issued && res.RequestSHA256 == digest, nil
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

// acceptsCard is the rules of check 9 that name a card: the firmware, the PIN policy (once or always), the slot of the
// purpose of the request, and the serial when the caller listed some. Touch and form factor are recorded, not enforced.
func (p Policy) acceptsCard(c *handoff.PIVEvidence) bool {
	fw := p.minFirmware()
	if !c.AtLeast(fw[0], fw[1], fw[2]) || (c.PIN != handoff.PINOnce && c.PIN != handoff.PINAlways) {
		return false
	}
	if c.Slot != slotplan.Default[handoff.TypeX509] {
		return false
	}
	if len(p.Serials) > 0 && !slices.Contains(p.Serials, c.Serial.String()) {
		return false
	}
	return true
}

// namesInside says whether every permitted name of the certificate is inside the policy: with ritueel's lists, a DNS name or a URI
// host that equals a listed entry; without, one that is a zone of this root or below one. No permitted IP range and no permitted
// e-mail name at all, either way (the root excludes every address; check 9 of the contract refuses an IP range or an e-mail name
// as a permitted subtree).
func (r *Root) namesInside(c *x509.Certificate, listed *ListedNames) bool {
	if len(c.PermittedIPRanges) != 0 || len(c.PermittedEmailAddresses) != 0 {
		return false
	}
	if listed != nil {
		return allListed(c.PermittedDNSDomains, listed.DNSNames) && allListed(c.PermittedURIDomains, listed.URIHosts)
	}
	inside := func(name string) bool {
		for _, z := range r.zones {
			if name == z || strings.HasSuffix(name, "."+z) {
				return true
			}
		}
		return false
	}
	for _, list := range [][]string{c.PermittedDNSDomains, c.PermittedURIDomains} {
		for _, n := range list {
			if !inside(n) {
				return false
			}
		}
	}
	return true
}

// allListed says whether every name equals an entry: the whole name, so that `a.example.org` is not inside a list that holds
// `example.org`, and `.example.org` is inside only a list that holds `.example.org`.
func allListed(names, entries []string) bool {
	for _, n := range names {
		if !slices.Contains(entries, n) {
			return false
		}
	}
	return true
}

// refuseFor refuses with the code of a refusal of the kit, or malformed for any other error.
func (r *Root) refuseFor(o *Outcome, answers, stem, digest string, err error) error {
	code := handoff.CodeMalformed
	var ref *handoff.Refusal
	if errors.As(err, &ref) {
		code = ref.Code
	}
	return r.refuse(o, answers, stem, digest, code)
}

// LoadAnchors reads the maker's attestation certificates the caller pins: one root, whose SHA-256 (of the DER, in lower-case
// hexadecimal) must be wantRootSHA256 when that is not empty, and a bundle of intermediates. Every certificate of the bundle
// helps to build the path and none is an anchor: the real bundle has two levels ("Yubico Attestation Intermediate B 1" under
// the root, "Yubico PIV Attestation B2 1" under that, and the OpenPGP, FIDO and secure-domain intermediates beside it), and the
// card's proof holds only the token's certificate and the slot's. That the issuer of the token's certificate is a PIV
// attestation intermediate is the check of CheckPIVEvidence.
func LoadAnchors(rootPEM, bundlePEM []byte, wantRootSHA256 string) (*handoff.AttestationAnchors, error) {
	roots, err := parseCertificates(rootPEM)
	if err != nil || len(roots) != 1 {
		return nil, errors.New("certifier: the attestation root file does not hold exactly one certificate")
	}
	if wantRootSHA256 != "" && sha256Hex(roots[0].Raw) != wantRootSHA256 {
		return nil, errors.New("certifier: the attestation root is not the pinned certificate")
	}
	bundle, err := parseCertificates(bundlePEM)
	if err != nil {
		return nil, err
	}
	a := &handoff.AttestationAnchors{Roots: roots, Intermediates: bundle}
	if !slices.ContainsFunc(bundle, func(c *x509.Certificate) bool { return strings.Contains(c.Subject.CommonName, "PIV Attestation") }) {
		return nil, errors.New("certifier: the attestation bundle holds no PIV attestation intermediate")
	}
	return a, nil
}

func parseCertificates(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out, nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certifier: a certificate does not parse: %w", err)
		}
		out = append(out, c)
	}
}

// requestAcceptable is the part of check 9 that reads the request: the contract's profile (the subject, the four extensions, the
// form of the names), the certifier's own rule for names against roots (neither the subject nor the key of a request is that of
// a root of the bundle or of this root), and, for the request that key@ signs, the one canonical shape of handoff.CheckInfo. The
// names against the policy's lists are checked on the certificate, in namesInside.
func (r *Root) requestAcceptable(req *handoff.Request, pol Policy) bool {
	if handoff.CheckRequestProfile(req) != nil {
		return false
	}
	if handoff.EqualsRoot(req.Subject, req.SPKI, append(slices.Clone(pol.Roots), r.cert)) {
		return false
	}
	return pol.ContractShape || handoff.CheckInfo(req.Info, req.SPKI) == nil
}
