package main

import (
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
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
	r, _, err := Init(rootDir, time.Now())
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
	outs, err := r.Certify(requests, answers, time.Now())
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
	first, _, err := Init(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	kept, did, err := Init(dir, t0.Add(time.Hour))
	if err != nil || kept.Pin != first.Pin || !strings.HasPrefix(did, "kept") {
		t.Fatalf("a root with a year left: %v %q", err, did)
	}
	// The list ends in a year; a day and a bit before, it is still kept; inside the last day it is not.
	if r, _, err := Init(dir, t0.Add(listLife-48*time.Hour)); err != nil || r.Pin != first.Pin {
		t.Fatalf("a list with two days left is not kept: %v", err)
	}
	again, did, err := Init(dir, t0.Add(listLife-12*time.Hour))
	if err != nil || again.Pin == first.Pin || !strings.HasPrefix(did, "made") {
		t.Fatalf("a list with half a day left is kept: %v %q", err, did)
	}
	// A list that does not read (a file lost) is not kept either.
	if err := os.Remove(filepath.Join(dir, jwsFile)); err != nil {
		t.Fatal(err)
	}
	if r, _, err := Init(dir, time.Now()); err != nil || r.Pin == again.Pin {
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
	if _, err := r.Certify(requests, answers, time.Now()); err != nil {
		t.Fatal(err)
	}
	first := mustRead(t, filepath.Join(answers, "dev-x509-intermediate.cert.pem"))
	r2, did, err := Init(rootDir, time.Now())
	if err != nil || r2.Pin != r.Pin || !strings.HasPrefix(did, "kept") {
		t.Fatalf("init again: %v %q", err, did)
	}
	outs, err := r2.Certify(requests, answers, time.Now().Add(time.Hour))
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
	if _, err := r.Certify(requests, answers, time.Now()); err != nil {
		t.Fatal(err)
	}
	first := mustRead(t, filepath.Join(answers, "dev-x509-intermediate.cert.pem"))
	softwareRequest(t, requests, "dev-x509-intermediate", localSpec())
	outs, err := r.Certify(requests, answers, time.Now())
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
	// Where this certifier does not follow the contract's outcome: it has no policy file, no attestation check and
	// accepts the software store always.
	differs := map[string]string{
		"x509-piv-valid":                 "store-not-allowed",
		"x509-kms-valid":                 "store-not-allowed",
		"x509-kms-cross-account":         "store-not-allowed",
		"x509-kms-cross-account-no-role": "store-not-allowed",
		"x509-piv-key-mismatch":          "store-not-allowed",
		"x509-piv-untrusted-chain":       "store-not-allowed",
		"x509-piv-pin-never":             "store-not-allowed",
		"x509-piv-old-firmware":          "store-not-allowed",
		"x509-kms-key-mismatch":          "store-not-allowed",
		"x509-kms-two-actors":            "store-not-allowed",
		"x509-software-in-production":    "issued",            // ritueel's production policy refuses software; this one is for tests
		"x509-software-declined":         "issued",            // ritueel's policy declines it; this one has no policy
		"x509-name-constraint-outside":   "store-not-allowed", // a card request; its names are ritueel.yaml's to check, not this tool's
	}
	ran := 0
	for _, v := range m.Requests {
		t.Run(v.ID, func(t *testing.T) {
			r, _, requests, answers := setup(t)
			stem := "vec"
			for _, f := range v.Files {
				switch {
				case strings.HasSuffix(f, ".csr.pem"):
					mustWrite(t, filepath.Join(requests, stem+".csr.pem"), mustRead(t, filepath.Join(vectorDir, f)))
				case strings.HasSuffix(f, ".proof.json"):
					mustWrite(t, filepath.Join(requests, stem+".proof.json"), mustRead(t, filepath.Join(vectorDir, f)))
				}
			}
			outs, err := r.Certify(requests, answers, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
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
	outs, err := r.Certify(requests, answers, time.Now())
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
