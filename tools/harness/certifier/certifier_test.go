package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
	"github.com/truvity/sluis/v2/kits/go/handoff/handofftest"
)

// The vectors are ritueel's, vendored by the kit (kits/go/handoff/testdata/ritueel/README.md).
const vectorDir = "../../../kits/go/handoff/testdata/ritueel/hand-off/v1"

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // a temporary directory of a test
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // as above
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a path of the test
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// softwareRequest writes the files of `sluis key request` for a fresh software key, as key@ would sign them.
func softwareRequest(t *testing.T, dir, stem string, spec handoff.RequestSpec) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	info, err := handoff.CertificationRequestInfo(spki, spec)
	if err != nil {
		t.Fatal(err)
	}
	d := sha512.Sum384(info)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := handoff.AssembleCSR(info, sig)
	if err != nil {
		t.Fatal(err)
	}
	proof := &handoff.Proof{RequestSHA256: handoff.RequestDigest(der), Store: handoff.StoreSoftware}
	pj, err := proof.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, stem+".csr.pem"), handoff.CSRPEM(der))
	mustWrite(t, filepath.Join(dir, stem+".proof.json"), pj)
	return key
}

func localSpec() handoff.RequestSpec {
	return handoff.RequestSpec{
		Subject:     pkix.Name{CommonName: "sluis dev intermediate"},
		Constraints: handoff.Constraints{URIHosts: []string{"dev.local.test"}, DNS: []string{"dev.local.test"}},
	}
}

// installs reads the answer the way `sluis key install` does: the bundle, the root list against the pin, and the
// requester's checks of the contract.
func installs(t *testing.T, root, requests, answers, stem string, now time.Time) (*handoff.Verified, error) {
	t.Helper()
	anchors, seq, err := handoff.ParseBundle(mustRead(t, filepath.Join(root, bundleFile)))
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.TrimSpace(string(mustRead(t, filepath.Join(root, pinFile))))
	list, _, err := handoff.ReadRootList(mustRead(t, filepath.Join(root, listFile)), mustRead(t, filepath.Join(root, jwsFile)), nil, []string{pin}, now)
	if err != nil {
		t.Fatalf("the root list is refused: %v", err)
	}
	blk, _ := pem.Decode(mustRead(t, filepath.Join(requests, stem+".csr.pem")))
	proof, err := handoff.ParseProof(mustRead(t, filepath.Join(requests, stem+".proof.json")))
	if err != nil {
		t.Fatal(err)
	}
	return handoff.CheckX509(handoff.X509Answer{
		Request: blk.Bytes, Proof: proof, CertName: stem + ".cert.pem", CertFile: mustRead(t, filepath.Join(answers, stem+".cert.pem")),
		ResultFile: mustRead(t, filepath.Join(answers, stem+".result.json")), Anchors: anchors, BundleSequence: seq, RootList: list, Now: now,
	})
}

func setup(t *testing.T) (root *Root, rootDir, requests, answers string) {
	t.Helper()
	base := t.TempDir()
	rootDir, requests, answers = filepath.Join(base, "root"), filepath.Join(base, "requests"), filepath.Join(base, "answers")
	r, _, err := Init(rootDir, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, rootDir, requests, answers
}

// A request made as key@ makes it is certified, and the answer passes every check `sluis key install` runs, with the
// root list and the pin it requires, including the trust sequence.
func TestAnAnswerInstalls(t *testing.T) {
	r, rootDir, requests, answers := setup(t)
	softwareRequest(t, requests, "dev-x509-intermediate", localSpec())
	outs, err := r.Certify(requests, answers, time.Now(), Policy{})
	if err != nil || len(outs) != 1 || !outs[0].Issued {
		t.Fatalf("certify: %+v, %v", outs, err)
	}
	v, err := installs(t, rootDir, requests, answers, "dev-x509-intermediate", time.Now())
	if err != nil {
		t.Fatalf("the answer does not install: %v", err)
	}
	if v.Floor || v.TrustSequence != 1 || !v.Cert.IsCA || v.Cert.MaxPathLen != 0 || len(v.Cert.PermittedDNSDomains) != 1 {
		t.Fatalf("the certificate is not an intermediate under this root: %+v", v)
	}
	for _, c := range []string{handoff.CheckTrustSequence, handoff.CheckIssuer, handoff.CheckProfile, handoff.CheckValidity} {
		found := false
		for _, ran := range v.Ran {
			found = found || ran == c
		}
		if !found {
			t.Errorf("the check %s did not run: ran %v, not run %v", c, v.Ran, v.NotRun)
		}
	}
}

// The root cannot be mistaken for a production root and certifies nothing outside local.test: it says TEST ONLY, its name
// constraints are critical, and a chain from it to a name outside the zone does not verify.
func TestTheRootIsMarkedAndConstrained(t *testing.T) {
	r, _, _, _ := setup(t)
	c := r.cert
	if !strings.Contains(c.Subject.CommonName, "TEST ONLY") || !strings.Contains(strings.Join(c.Subject.Organization, " "), "TEST ONLY") {
		t.Errorf("the subject does not say TEST ONLY: %v", c.Subject)
	}
	if !c.PermittedDNSDomainsCritical || len(c.PermittedDNSDomains) != 1 || c.PermittedDNSDomains[0] != "local.test" {
		t.Errorf("name constraints: %v critical %v", c.PermittedDNSDomains, c.PermittedDNSDomainsCritical)
	}
	if len(c.ExcludedIPRanges) != 2 || len(c.PermittedEmailAddresses) == 0 || len(c.PermittedURIDomains) == 0 {
		t.Errorf("the root leaves a kind of name unconstrained: IP exclusions %v, mail %v, URI %v", c.ExcludedIPRanges, c.PermittedEmailAddresses, c.PermittedURIDomains)
	}
	// A leaf of each kind of name, under an intermediate this root certified, verifies inside local.test and nowhere else.
	interKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now()
	inter := &x509.Certificate{SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "i"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	iDER, err := x509.CreateCertificate(rand.Reader, inter, c, &interKey.PublicKey, r.key)
	if err != nil {
		t.Fatal(err)
	}
	iCert, _ := x509.ParseCertificate(iDER)
	uri := func(s string) *url.URL { u, _ := url.Parse(s); return u }
	for name, tc := range map[string]struct {
		tpl *x509.Certificate
		ok  bool
	}{
		"dns inside":    {&x509.Certificate{DNSNames: []string{"a.dev.local.test"}}, true},
		"dns outside":   {&x509.Certificate{DNSNames: []string{"example.org"}}, false},
		"uri inside":    {&x509.Certificate{URIs: []*url.URL{uri("spiffe://dev.local.test/ns/x")}}, true},
		"uri outside":   {&x509.Certificate{URIs: []*url.URL{uri("spiffe://example.org/ns/x")}}, false},
		"ipv4":          {&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("8.8.8.8")}}, false},
		"ipv6":          {&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("2001:4860:4860::8888")}}, false},
		"loopback":      {&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, false},
		"mail outside":  {&x509.Certificate{EmailAddresses: []string{"a@example.org"}}, false},
		"mail inside":   {&x509.Certificate{EmailAddresses: []string{"a@dev.local.test"}}, true},
		"mail the zone": {&x509.Certificate{EmailAddresses: []string{"a@local.test"}}, true},
	} {
		leafKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		leaf := tc.tpl
		leaf.SerialNumber, leaf.Subject, leaf.NotBefore, leaf.NotAfter = bigOne(), pkix.Name{CommonName: "leaf"}, now.Add(-time.Minute), now.Add(time.Minute)
		lDER, err := x509.CreateCertificate(rand.Reader, leaf, iCert, &leafKey.PublicKey, interKey)
		if err != nil {
			t.Fatal(err)
		}
		lCert, _ := x509.ParseCertificate(lDER)
		pool, inters := x509.NewCertPool(), x509.NewCertPool()
		pool.AddCert(c)
		inters.AddCert(iCert)
		_, err = lCert.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if (err == nil) != tc.ok {
			t.Errorf("%s: verified %v, want %v (%v)", name, err == nil, tc.ok, err)
		}
	}
}

// A root is kept while its root list has more than a day left, and made again after: a list that expired makes `key install`
// refuse every answer, and a root kept with it would leave the run stuck.
func TestTheKeepRule(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "root")
	t0 := time.Now()
	first, _, err := Init(dir, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	kept, did, err := Init(dir, t0.Add(time.Hour), nil)
	if err != nil || kept.Pin != first.Pin || !strings.HasPrefix(did, "kept") {
		t.Fatalf("a root with a year left: %v %q", err, did)
	}
	// The list ends in a year; a day and a bit before, it is still kept; inside the last day it is not.
	if r, _, err := Init(dir, t0.Add(listLife-48*time.Hour), nil); err != nil || r.Pin != first.Pin {
		t.Fatalf("a list with two days left is not kept: %v", err)
	}
	again, did, err := Init(dir, t0.Add(listLife-12*time.Hour), nil)
	if err != nil || again.Pin == first.Pin || !strings.HasPrefix(did, "made") {
		t.Fatalf("a list with half a day left is kept: %v %q", err, did)
	}
	// A list that does not read (a file lost) is not kept either.
	if err := os.Remove(filepath.Join(dir, jwsFile)); err != nil {
		t.Fatal(err)
	}
	if r, _, err := Init(dir, time.Now(), nil); err != nil || r.Pin == again.Pin {
		t.Fatalf("a root with no signature file is kept: %v", err)
	}
}

// Every root is new: two runs share no key, no pin and no name, and no private key is in the public files.
func TestEveryRootIsNew(t *testing.T) {
	a, dirA, _, _ := setup(t)
	b, _, _, _ := setup(t)
	if a.Pin == b.Pin || a.cert.Subject.CommonName == b.cert.Subject.CommonName {
		t.Fatal("two roots are the same")
	}
	err := filepath.WalkDir(filepath.Join(dirA, "trust"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(string(mustRead(t, p)), "PRIVATE KEY") {
			t.Errorf("%s holds a private key", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dirA, rootKeyFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the key's mode: %v %v", fi, err)
	}
}

// A second Init keeps the root, and a second Certify re-issues nothing: the certificate is byte for byte the first.
func TestASecondRunKeepsEverything(t *testing.T) {
	r, rootDir, requests, answers := setup(t)
	softwareRequest(t, requests, "dev-x509-intermediate", localSpec())
	if _, err := r.Certify(requests, answers, time.Now(), Policy{}); err != nil {
		t.Fatal(err)
	}
	first := mustRead(t, filepath.Join(answers, "dev-x509-intermediate.cert.pem"))
	r2, did, err := Init(rootDir, time.Now(), nil)
	if err != nil || r2.Pin != r.Pin || !strings.HasPrefix(did, "kept") {
		t.Fatalf("init again: %v %q", err, did)
	}
	outs, err := r2.Certify(requests, answers, time.Now().Add(time.Hour), Policy{})
	if err != nil || len(outs) != 1 || !outs[0].Kept || outs[0].Issued {
		t.Fatalf("certify again: %+v, %v", outs, err)
	}
	if string(mustRead(t, filepath.Join(answers, "dev-x509-intermediate.cert.pem"))) != string(first) {
		t.Fatal("the certificate was issued again")
	}
}

// A new request for the same stem (key@ made another key) is answered again, and the old certificate does not remain
// beside it.
func TestANewRequestIsAnsweredAgain(t *testing.T) {
	r, rootDir, requests, answers := setup(t)
	softwareRequest(t, requests, "dev-x509-intermediate", localSpec())
	if _, err := r.Certify(requests, answers, time.Now(), Policy{}); err != nil {
		t.Fatal(err)
	}
	first := mustRead(t, filepath.Join(answers, "dev-x509-intermediate.cert.pem"))
	softwareRequest(t, requests, "dev-x509-intermediate", localSpec())
	outs, err := r.Certify(requests, answers, time.Now(), Policy{})
	if err != nil || !outs[0].Issued {
		t.Fatalf("%+v %v", outs, err)
	}
	if string(mustRead(t, filepath.Join(answers, "dev-x509-intermediate.cert.pem"))) == string(first) {
		t.Fatal("the old certificate stayed")
	}
	if _, err := installs(t, rootDir, requests, answers, "dev-x509-intermediate", time.Now()); err != nil {
		t.Fatal(err)
	}
}

// ritueel's request vectors, as far as this certifier can answer them. It decides like the contract's certifier for the
// early checks (1 to 5) and the shape of the request; it differs on purpose where the decision needs ritueel's policy or
// a card's attestation, and the table says where.
func TestRitueelRequestVectors(t *testing.T) {
	var m struct {
		Requests []struct {
			ID     string   `json:"id"`
			Files  []string `json:"files"`
			Expect string   `json:"expect"`
			Reason string   `json:"reason"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(vectorDir, "manifest.json")), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Requests) != 21 {
		t.Fatalf("the manifest lists %d requests, want 21", len(m.Requests))
	}
	// Where this certifier does not follow the contract's outcome: it has no policy file, accepts the software store always
	// and never a KMS key.
	differs := map[string]string{
		"x509-kms-valid":                 "store-not-allowed",
		"x509-kms-cross-account":         "store-not-allowed",
		"x509-kms-cross-account-no-role": "store-not-allowed",
		"x509-kms-key-mismatch":          "store-not-allowed",
		"x509-kms-two-actors":            "store-not-allowed",
		"x509-software-in-production":    "issued", // ritueel's production policy refuses software; this one is for tests
		"x509-software-declined":         "issued", // ritueel's policy declines it; this one has no person to ask
	}
	anchors := vectorAnchors(t)
	ran := 0
	for _, v := range m.Requests {
		t.Run(v.ID, func(t *testing.T) {
			// A root for the vectors' names (example.org, a zone the production policy lists), and the vectors' attestation.
			base := t.TempDir()
			requests, answers := filepath.Join(base, "requests"), filepath.Join(base, "answers")
			r, _, err := initRoot(filepath.Join(base, "root"), time.Now(), []string{"example.org"})
			if err != nil {
				t.Fatal(err)
			}
			stem := "vec"
			for _, f := range v.Files {
				switch {
				case strings.HasSuffix(f, ".csr.pem"):
					mustWrite(t, filepath.Join(requests, stem+".csr.pem"), mustRead(t, filepath.Join(vectorDir, f)))
				case strings.HasSuffix(f, ".proof.json"):
					mustWrite(t, filepath.Join(requests, stem+".proof.json"), mustRead(t, filepath.Join(vectorDir, f)))
				}
			}
			// A run for cards pins the maker's attestation and takes cards only; one for software pins none.
			pol := Policy{Attestation: anchors, ContractShape: true}
			if p, err := handoff.ParseProof(mustRead(t, filepath.Join(requests, stem+".proof.json"))); err == nil && p.Store == handoff.StoreSoftware {
				pol = Policy{ContractShape: true}
			}
			outs, err := r.Certify(requests, answers, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC), pol)
			got := "issued"
			if err != nil {
				t.Fatalf("certify: %v", err)
			}
			if len(outs[0].Reasons) > 0 {
				got = outs[0].Reasons[0]
			}
			want := "issued"
			if v.Expect == "refuse" {
				want = v.Reason
			}
			if d, ok := differs[v.ID]; ok {
				want = d
			}
			if got != want {
				t.Errorf("%s: got %s, want %s", v.ID, got, want)
			}
			ran++
		})
	}
	if ran != len(m.Requests) {
		t.Fatalf("ran %d of %d vectors", ran, len(m.Requests))
	}
}

// A request whose proof does not read (here a card's proof with no evidence) is refused, a result file says so, and no
// certificate is written beside it.
func TestARefusalLeavesNoCertificate(t *testing.T) {
	r, _, requests, answers := setup(t)
	softwareRequest(t, requests, "dev-x509-intermediate", localSpec())
	pj := mustRead(t, filepath.Join(requests, "dev-x509-intermediate.proof.json"))
	mustWrite(t, filepath.Join(requests, "dev-x509-intermediate.proof.json"), []byte(strings.Replace(string(pj), `"software"`, `"piv"`, 1)))
	outs, err := r.Certify(requests, answers, time.Now(), Policy{})
	if err != nil || len(outs[0].Reasons) != 1 || outs[0].Reasons[0] != "malformed" {
		t.Fatalf("%+v %v", outs, err)
	}
	if _, err := os.Stat(filepath.Join(answers, "dev-x509-intermediate.cert.pem")); err == nil {
		t.Fatal("a certificate was written beside a refusal")
	}
	if _, err := handoff.ParseResult(mustRead(t, filepath.Join(answers, "dev-x509-intermediate.result.json"))); err != nil {
		t.Fatalf("the refusal is not a result file: %v", err)
	}
}

func bigOne() *big.Int { return big.NewInt(1) }

// vectorAnchors are the made-up attestation root and intermediate that ritueel's vectors pin.
func vectorAnchors(t *testing.T) *handoff.AttestationAnchors {
	t.Helper()
	root := mustRead(t, filepath.Join(vectorDir, "pki/test-attestation-root.pem"))
	inter := mustRead(t, filepath.Join(vectorDir, "pki/test-attestation-intermediate.pem"))
	a, err := LoadAnchors(root, inter, "")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ---- the card store ---------------------------------------------------------------------------------------------------

type cardRun struct {
	t        *testing.T
	root     *Root
	rootDir  string
	requests string
	answers  string
	h        *handofftest.Hierarchy
	pol      Policy
	now      time.Time
}

func newCardRun(t *testing.T, zones []string) *cardRun {
	t.Helper()
	base := t.TempDir()
	now := time.Now()
	r, _, err := Init(filepath.Join(base, "root"), now, zones)
	if err != nil {
		t.Fatal(err)
	}
	h := handofftest.NewHierarchy(now, true, 0)
	return &cardRun{t: t, root: r, rootDir: filepath.Join(base, "root"), requests: filepath.Join(base, "requests"), answers: filepath.Join(base, "answers"), h: h, now: now,
		pol: Policy{Attestation: &handoff.AttestationAnchors{Roots: []*x509.Certificate{h.Root}, Intermediates: []*x509.Certificate{h.Intermediate}}}}
}

// request writes the files of `sluis key request` for a card key, whose attestation is `att` over `attested` (the request's own
// key when attested is nil).
func (c *cardRun) request(spec handoff.RequestSpec, slot handofftest.Slot, attested *ecdsa.PrivateKey, mutate func([][]byte)) {
	c.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		c.t.Fatal(err)
	}
	if attested == nil {
		attested = key
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	info, err := handoff.CertificationRequestInfo(spki, spec)
	if err != nil {
		c.t.Fatal(err)
	}
	d := sha512.Sum384(info)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, d[:])
	der, err := handoff.AssembleCSR(info, sig)
	if err != nil {
		c.t.Fatal(err)
	}
	att := c.h.Attest(&attested.PublicKey, slot)
	if mutate != nil {
		mutate(att)
	}
	pj, err := (&handoff.Proof{RequestSHA256: handoff.RequestDigest(der), Store: handoff.StorePIV, Attestation: att}).Marshal()
	if err != nil {
		c.t.Fatal(err)
	}
	mustWrite(c.t, filepath.Join(c.requests, "board-x509-intermediate.csr.pem"), handoff.CSRPEM(der))
	mustWrite(c.t, filepath.Join(c.requests, "board-x509-intermediate.proof.json"), pj)
}

// outcome certifies and returns "issued" or the first reason.
func (c *cardRun) outcome() string {
	c.t.Helper()
	outs, err := c.root.Certify(c.requests, c.answers, c.now, c.pol)
	if err != nil {
		c.t.Fatal(err)
	}
	if len(outs[0].Reasons) > 0 {
		if _, err := os.Stat(filepath.Join(c.answers, "board-x509-intermediate.cert.pem")); err == nil {
			c.t.Fatal("a certificate was written beside a refusal")
		}
		return outs[0].Reasons[0]
	}
	return "issued"
}

func boardSpec() handoff.RequestSpec {
	return handoff.RequestSpec{Subject: pkix.Name{CommonName: "sluis board intermediate"}, Constraints: handoff.Constraints{URIHosts: []string{"b1.boards.test"}, DNS: []string{"b1.boards.test"}}}
}

// A good card request is certified, and the answer installs: the card's serial, firmware, slot and PIN policy are read and
// reported, and `sluis key install` would accept the answer.
func TestACardRequestIsCertified(t *testing.T) {
	c := newCardRun(t, []string{"boards.test"})
	c.request(boardSpec(), handofftest.GoodSlot("9c", 31337), nil, nil)
	c.pol.Serials = []string{"31337"}
	outs, err := c.root.Certify(c.requests, c.answers, c.now, c.pol)
	if err != nil || !outs[0].Issued || outs[0].Card == nil || outs[0].Card.Serial.Int64() != 31337 || outs[0].Card.Slot != "9c" {
		t.Fatalf("%+v %v", outs, err)
	}
	if _, err := installs(t, c.rootDir, c.requests, c.answers, "board-x509-intermediate", c.now); err != nil {
		t.Fatalf("the answer does not install: %v", err)
	}
}

// Each rule of the card's checks refuses with the contract's code and writes no certificate.
func TestACardRequestIsRefused(t *testing.T) {
	good := handofftest.GoodSlot
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, tc := range map[string]struct {
		slot    handofftest.Slot
		attest  *ecdsa.PrivateKey
		mutate  func([][]byte)
		pol     func(*Policy)
		spec    *handoff.RequestSpec
		storeIs string // a proof of another store
		want    string
	}{
		"attestation of another slot":   {slot: good("9a", 1), want: "policy"},
		"attestation of a retired slot": {slot: good("82", 1), want: "policy"},
		"attestation of another key":    {slot: good("9c", 1), attest: other, want: handoff.CodeKeyMismatch},
		"a damaged token certificate":   {slot: good("9c", 1), mutate: func(a [][]byte) { a[1] = flip(a[1]) }, want: handoff.CodeProofInvalid},
		"a damaged slot signature":      {slot: good("9c", 1), mutate: func(a [][]byte) { a[0] = flipTail(a[0]) }, want: handoff.CodeProofInvalid},
		"a chain to another maker": {slot: good("9c", 1), pol: func(p *Policy) {
			o := handofftest.NewHierarchy(time.Now(), true, 0)
			p.Attestation = &handoff.AttestationAnchors{Roots: []*x509.Certificate{o.Root}, Intermediates: []*x509.Certificate{o.Intermediate}}
		}, want: handoff.CodeProofInvalid},
		"the intermediate not pinned":         {slot: good("9c", 1), pol: func(p *Policy) { p.Attestation.Intermediates = nil }, want: handoff.CodeProofInvalid},
		"a serial the run did not list":       {slot: good("9c", 77), pol: func(p *Policy) { p.Serials = []string{"1", "2"} }, want: "policy"},
		"firmware 5.4.3":                      {slot: func() handofftest.Slot { s := good("9c", 1); s.Firmware = []byte{5, 4, 3}; return s }(), want: "policy"},
		"firmware below the run's minimum":    {slot: good("9c", 1), pol: func(p *Policy) { p.MinFirmware = [3]byte{5, 9, 0} }, want: "policy"},
		"PIN policy never":                    {slot: func() handofftest.Slot { s := good("9c", 1); s.Policy = []byte{1, 1}; return s }(), want: "policy"},
		"names outside the root's zones":      {slot: good("9c", 1), spec: &handoff.RequestSpec{Subject: pkix.Name{CommonName: "x"}, Constraints: handoff.Constraints{URIHosts: []string{"example.org"}, DNS: []string{"example.org"}}}, want: "policy"},
		"a zone of the name only as a suffix": {slot: good("9c", 1), spec: &handoff.RequestSpec{Subject: pkix.Name{CommonName: "x"}, Constraints: handoff.Constraints{DNS: []string{"notboards.test"}}}, want: "policy"},
		"no name constraints that permit":     {slot: good("9c", 1), spec: &handoff.RequestSpec{Subject: pkix.Name{CommonName: "x"}, Constraints: handoff.Constraints{IPRanges: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}, want: "policy"},
		"the card store with no anchors":      {slot: good("9c", 1), pol: func(p *Policy) { p.Attestation = nil }, want: "store-not-allowed"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCardRun(t, []string{"boards.test"})
			spec := boardSpec()
			if tc.spec != nil {
				spec = *tc.spec
			}
			c.request(spec, tc.slot, tc.attest, tc.mutate)
			if tc.pol != nil {
				tc.pol(&c.pol)
			}
			if got := c.outcome(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func flip(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)/2] ^= 1
	return c
}

func flipTail(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)-3] ^= 1
	return c
}

// A software request is held to the same names, and a KMS request is refused.
func TestSoftwareNamesAndKMS(t *testing.T) {
	r, _, requests, answers := setup(t)
	softwareRequest(t, requests, "dev-x509-intermediate", handoff.RequestSpec{Subject: pkix.Name{CommonName: "x"}, Constraints: handoff.Constraints{DNS: []string{"example.org"}}})
	outs, err := r.Certify(requests, answers, time.Now(), Policy{})
	if err != nil || len(outs[0].Reasons) != 1 || outs[0].Reasons[0] != "policy" {
		t.Fatalf("software names outside local.test: %+v %v", outs, err)
	}
	// KMS: a proof of the store aws-kms.
	csr := mustRead(t, filepath.Join(requests, "dev-x509-intermediate.csr.pem"))
	blk, _ := pem.Decode(csr)
	pj, err := (&handoff.Proof{RequestSHA256: handoff.RequestDigest(blk.Bytes), Store: handoff.StoreAWSKMS, KeyARN: "arn:aws:kms:eu-west-1:111122223333:key/x", PublicKey: []byte{1}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(requests, "dev-x509-intermediate.proof.json"), pj)
	_ = os.Remove(filepath.Join(answers, "dev-x509-intermediate.result.json"))
	outs, err = r.Certify(requests, answers, time.Now(), Policy{Attestation: &handoff.AttestationAnchors{}})
	if err != nil || len(outs[0].Reasons) != 1 || outs[0].Reasons[0] != "store-not-allowed" {
		t.Fatalf("kms: %+v %v", outs, err)
	}
}

// The zones: a root is made for the names it is given, a zone must be under .test, and a changed set of zones is a new root.
func TestZones(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "root")
	for _, bad := range []string{"example.org", "test", "Boards.test", "a b.test", "-x.test", ""} {
		if _, _, err := Init(filepath.Join(t.TempDir(), "r"), time.Now(), []string{bad}); err == nil && bad != "" {
			t.Errorf("the zone %q is accepted", bad)
		}
	}
	a, _, err := Init(dir, time.Now(), []string{"boards.test", "local.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.cert.PermittedDNSDomains) != 2 || len(a.cert.ExcludedIPRanges) != 2 {
		t.Errorf("constraints: %v, IP exclusions %v", a.cert.PermittedDNSDomains, a.cert.ExcludedIPRanges)
	}
	same, _, _ := Init(dir, time.Now(), []string{"local.test", "boards.test"})
	if same.Pin != a.Pin {
		t.Error("the same zones in another order made a new root")
	}
	other, did, _ := Init(dir, time.Now(), []string{"boards.test"})
	if other.Pin == a.Pin || !strings.HasPrefix(did, "made") {
		t.Errorf("another set of zones kept the root: %q", did)
	}
}

// The maker's files: the root must be the pinned one, and a bundle with no PIV intermediate is no bundle.
func TestLoadAnchors(t *testing.T) {
	root := mustRead(t, filepath.Join(vectorDir, "pki/test-attestation-root.pem"))
	inter := mustRead(t, filepath.Join(vectorDir, "pki/test-attestation-intermediate.pem"))
	blk, _ := pem.Decode(root)
	rc, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := LoadAnchors(root, inter, sha256Hex(rc.Raw)); err != nil {
		t.Fatalf("the pinned root: %v", err)
	}
	if _, err := LoadAnchors(root, inter, strings.Repeat("0", 64)); err == nil {
		t.Error("a root that is not the pinned one")
	}
	if _, err := LoadAnchors(append(root, inter...), inter, ""); err == nil {
		t.Error("two certificates as the root")
	}
	if _, err := LoadAnchors(root, root, ""); err == nil {
		t.Error("a bundle with no PIV attestation intermediate")
	}
}

// The flags of certify become the policy: the maker's files come as a pair and are pinned, the firmware and the serials are read
// as numbers, and the other spellings are refused.
func TestPolicyFromFlags(t *testing.T) {
	root, inter := filepath.Join(vectorDir, "pki/test-attestation-root.pem"), filepath.Join(vectorDir, "pki/test-attestation-intermediate.pem")
	pol, err := policyFrom(root, inter, "", "5.9.1", []string{"42"})
	if err != nil || pol.Attestation == nil || pol.MinFirmware != [3]byte{5, 9, 1} || len(pol.Serials) != 1 {
		t.Fatalf("%+v %v", pol, err)
	}
	if pol, err := policyFrom("", "", "", "", nil); err != nil || pol.Attestation != nil {
		t.Errorf("no files must mean no card store: %+v %v", pol, err)
	}
	for name, args := range map[string][5]string{
		"a root without a bundle":  {root, "", "", "", ""},
		"a bundle without a root":  {"", inter, "", "", ""},
		"a wrong pin":              {root, inter, strings.Repeat("0", 64), "", ""},
		"a firmware of two parts":  {root, inter, "", "5.9", ""},
		"a firmware with a letter": {root, inter, "", "5.x.1", ""},
		"a serial with a letter":   {root, inter, "", "", "12x"},
		"a negative serial":        {root, inter, "", "", "-3"},
		"a missing file":           {root + ".missing", inter, "", "", ""},
	} {
		var serials []string
		if args[4] != "" {
			serials = []string{args[4]}
		}
		if _, err := policyFrom(args[0], args[1], args[2], args[3], serials); err == nil {
			t.Errorf("%s is accepted", name)
		}
	}
}

// The real bundle has two levels, and a card's proof holds only the token's certificate and the slot's. The anchors loaded from
// the repository's own files must build the path from "Yubico PIV Attestation B2 1" to the pinned root through "Yubico
// Attestation Intermediate B 1"; the anchors of the first version of this tool, which kept only the intermediates named PIV,
// could not.
const (
	realCerts      = "../../../drivers/key/yubikey-piv/internal/card/certs"
	realRootSHA256 = "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8" // the card driver's pin
)

func TestTheRealBundleBuildsThePath(t *testing.T) {
	root := mustRead(t, filepath.Join(realCerts, "yubico-attestation-root-1.pem"))
	bundle := mustRead(t, filepath.Join(realCerts, "yubico-intermediate.pem"))
	a, err := LoadAnchors(root, bundle, realRootSHA256)
	if err != nil {
		t.Fatalf("the repository's files with the driver's pin: %v", err)
	}
	var piv []*x509.Certificate
	for _, c := range a.Intermediates {
		if strings.HasPrefix(c.Subject.CommonName, "Yubico PIV Attestation ") {
			piv = append(piv, c)
		}
	}
	if len(piv) < 3 || len(a.Intermediates) < 10 {
		t.Fatalf("the bundle has %d certificates and %d PIV intermediates", len(a.Intermediates), len(piv))
	}
	pool := func(cs []*x509.Certificate) *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range cs {
			p.AddCert(c)
		}
		return p
	}
	var onlyPIV []*x509.Certificate // what the filter of the first version kept
	for _, c := range a.Intermediates {
		if strings.Contains(c.Subject.CommonName, "PIV Attestation") {
			onlyPIV = append(onlyPIV, c)
		}
	}
	for _, c := range piv {
		opts := x509.VerifyOptions{Roots: pool(a.Roots), Intermediates: pool(a.Intermediates), CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
		chains, err := c.Verify(opts)
		if err != nil || len(chains) == 0 || len(chains[0]) != 3 {
			t.Errorf("%s: no path to the root through the loaded anchors: %v", c.Subject.CommonName, err)
		}
		opts.Intermediates = pool(onlyPIV)
		if _, err := c.Verify(opts); err == nil {
			t.Errorf("%s: the filtered set builds the path, so this test does not show the missing link", c.Subject.CommonName)
		}
	}
	// A bundle is not a root: the pin refuses another root file.
	if _, err := LoadAnchors(bundle, bundle, realRootSHA256); err == nil {
		t.Error("the bundle as the root")
	}
}

// A card whose chain has the real shape, two levels under the root, is certified when the whole bundle is pinned, and refused
// without the upper level.
func TestACardWithTwoLevelsIsCertified(t *testing.T) {
	c := newCardRun(t, []string{"boards.test"})
	c.h = handofftest.NewHierarchyWith(c.now, handofftest.Options{TwoLevels: true, IssuerName: "Made-up PIV Attestation B2 1 (TEST ONLY)"})
	roots, inters := c.h.Anchors()
	c.pol.Attestation = &handoff.AttestationAnchors{Roots: roots, Intermediates: inters}
	c.request(boardSpec(), handofftest.GoodSlot("9c", 7), nil, nil)
	if got := c.outcome(); got != "issued" {
		t.Fatalf("two levels with the whole bundle: %s", got)
	}
	c2 := newCardRun(t, []string{"boards.test"})
	c2.h = c.h
	c2.pol.Attestation = &handoff.AttestationAnchors{Roots: roots, Intermediates: inters[:1]}
	c2.request(boardSpec(), handofftest.GoodSlot("9c", 7), nil, nil)
	if got := c2.outcome(); got != handoff.CodeProofInvalid {
		t.Fatalf("two levels without the upper one: %s", got)
	}
	// A token under an OpenPGP intermediate is not a PIV attestation, though the root is pinned.
	c3 := newCardRun(t, []string{"boards.test"})
	c3.h = handofftest.NewHierarchyWith(c3.now, handofftest.Options{TwoLevels: true, IssuerName: "Made-up OPGP Attestation B2 1 (TEST ONLY)"})
	r3, i3 := c3.h.Anchors()
	c3.pol.Attestation = &handoff.AttestationAnchors{Roots: r3, Intermediates: i3}
	c3.request(boardSpec(), handofftest.GoodSlot("9c", 7), nil, nil)
	if got := c3.outcome(); got != handoff.CodeProofInvalid {
		t.Fatalf("a token under an OpenPGP intermediate: %s", got)
	}
}

// A run that pins the card attestation takes cards only: a software key is not certified there, serials or none.
func TestACardRunRefusesSoftware(t *testing.T) {
	c := newCardRun(t, []string{"boards.test"})
	softwareRequest(t, c.requests, "board-x509-intermediate", boardSpec())
	for _, serials := range [][]string{nil, {"1"}} {
		c.pol.Serials = serials
		if got := c.outcome(); got != "store-not-allowed" {
			t.Errorf("software under a card run (serials %v): %s", serials, got)
		}
	}
	c.pol.Attestation = nil
	if got := c.outcome(); got != "issued" {
		t.Errorf("software under a run with no attestation: %s", got)
	}
}

// A refusal is answered again by the next run: the policy changed, and the request that was refused for it is certified.
func TestARefusalIsAnsweredAgainWhenThePolicyChanged(t *testing.T) {
	c := newCardRun(t, []string{"boards.test"})
	c.request(boardSpec(), handofftest.GoodSlot("9c", 5), nil, nil)
	c.pol.Serials = []string{"6"}
	if got := c.outcome(); got != "policy" {
		t.Fatalf("the serial is not the run's: %s", got)
	}
	c.pol.Serials = []string{"5", "6"}
	if got := c.outcome(); got != "issued" {
		t.Fatalf("the serial was added to the run: %s", got)
	}
	// And an issued answer is kept, whatever the policy says afterwards.
	first := mustRead(t, filepath.Join(c.answers, "board-x509-intermediate.cert.pem"))
	c.pol.Serials = []string{"9"}
	outs, err := c.root.Certify(c.requests, c.answers, c.now, c.pol)
	if err != nil || !outs[0].Kept || string(mustRead(t, filepath.Join(c.answers, "board-x509-intermediate.cert.pem"))) != string(first) {
		t.Fatalf("%+v %v", outs, err)
	}
}

// The root's key is read by its owner alone: a key with a wider mode is not used, and a run that finds one stops.
func TestAWideRootKeyIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "root")
	if _, _, err := Init(dir, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, rootKeyFile)
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		if err := os.Chmod(key, mode); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Init(dir, time.Now(), nil); err == nil {
			t.Errorf("Init uses a key of mode %04o", mode)
		}
		if _, err := Load(dir); err == nil {
			t.Errorf("Load uses a key of mode %04o", mode)
		}
	}
	if err := os.Chmod(key, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err != nil {
		t.Errorf("a key of mode 0400: %v", err)
	}
}

// What the policy accepts is accepted at its boundary: the oldest firmware, either PIN policy that asks for a PIN, any touch policy,
// and a serial among several.
func TestACardPolicyAcceptsItsBoundary(t *testing.T) {
	for name, tc := range map[string]struct {
		slot func(*handofftest.Slot)
		pol  func(*Policy)
		want string
	}{
		"firmware 5.7.0":                       {func(s *handofftest.Slot) { s.Firmware = []byte{5, 7, 0} }, nil, "issued"},
		"firmware 5.6.255":                     {func(s *handofftest.Slot) { s.Firmware = []byte{5, 6, 255} }, nil, "policy"},
		"firmware 6.0.0":                       {func(s *handofftest.Slot) { s.Firmware = []byte{6, 0, 0} }, nil, "issued"},
		"firmware 5.8.0 at a minimum of 5.8.0": {nil, func(p *Policy) { p.MinFirmware = [3]byte{5, 8, 0} }, "issued"},
		"PIN once":                             {func(s *handofftest.Slot) { s.Policy = []byte{handoff.PINOnce, 1} }, nil, "issued"},
		"PIN always":                           {func(s *handofftest.Slot) { s.Policy = []byte{handoff.PINAlways, 1} }, nil, "issued"},
		"touch always":                         {func(s *handofftest.Slot) { s.Policy = []byte{handoff.PINOnce, 2} }, nil, "issued"},
		"touch cached":                         {func(s *handofftest.Slot) { s.Policy = []byte{handoff.PINOnce, 3} }, nil, "issued"},
		"a serial among several":               {nil, func(p *Policy) { p.Serials = []string{"1", "31337", "2"} }, "issued"},
		"a serial that only starts like one":   {nil, func(p *Policy) { p.Serials = []string{"3133", "313370"} }, "policy"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCardRun(t, []string{"boards.test"})
			s := handofftest.GoodSlot("9c", 31337)
			if tc.slot != nil {
				tc.slot(&s)
			}
			c.request(boardSpec(), s, nil, nil)
			if tc.pol != nil {
				tc.pol(&c.pol)
			}
			if got := c.outcome(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}
