package handoff

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// The tests build their own fixtures: a throwaway root made here, a request made by this package, and a certificate
// that a floor CA would issue for it. Nothing here comes from ritueel; vectors_test.go runs ritueel's own vectors.

// testNow is the clock of the generated fixtures.
var testNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

type testRoot struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newRoot(t testing.TB, cn string) *testRoot {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: testNow.AddDate(-1, 0, 0), NotAfter: testNow.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testRoot{k, c, der}
}

func spkiOf(t testing.TB, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testSpec() RequestSpec {
	return RequestSpec{
		Subject: pkix.Name{CommonName: "Example Intermediate (TEST ONLY)"},
		Constraints: Constraints{
			URIHosts: []string{"dev.example.org"},
			DNS:      []string{"dev.example.org", "dev.example.internal"},
		},
	}
}

// makeRequest builds and signs a request with key, as key@ will for the key it holds, and returns its DER.
func makeRequest(t testing.TB, key *ecdsa.PrivateKey, spec RequestSpec) []byte {
	t.Helper()
	info, err := CertificationRequestInfo(spiKOfKey(t, key), spec)
	if err != nil {
		t.Fatal(err)
	}
	der, err := AssembleCSR(info, signDigest(t, key, info))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// signDigest signs SHA-384 of info with key, ASN.1 DER: what key@'s card driver returns for a digest.
func signDigest(t testing.TB, key *ecdsa.PrivateKey, info []byte) []byte {
	t.Helper()
	d := sha512.Sum384(info)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func spiKOfKey(t testing.TB, key *ecdsa.PrivateKey) []byte { return spkiOf(t, &key.PublicKey) }

// issue is what a floor CA does: copy the subject, the key and the requested extensions with their criticality, and
// make the certificate valid for the given span. mutate may change the template before it is signed.
func issue(t testing.TB, root *testRoot, csrDER []byte, notBefore, notAfter time.Time, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(randBytes(t, 16)), RawSubject: csr.RawSubject,
		NotBefore: notBefore, NotAfter: notAfter,
		ExtraExtensions: csr.Extensions,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, pub, root.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func randBytes(t testing.TB, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// resultFile is a result file for a certificate, as a certifier writes it.
func resultFile(t testing.TB, csrDER, certPEM []byte, certName string, root *testRoot, seq int64) []byte {
	t.Helper()
	cert, _, err := parseAnswerCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{
		"handoff": 1, "type": TypeX509, "request_sha256": RequestDigest(csrDER), "outcome": "issued",
		"artifacts":  []map[string]string{{"name": certName, "sha256": sha256Hex(certPEM)}},
		"valid_from": cert.NotBefore.UTC().Format(timeFormat), "valid_until": cert.NotAfter.UTC().Format(timeFormat),
		"issuer": SPKIPin(root.cert), "trust_sequence": seq,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// answer is a good full answer for a fresh request.
type answer struct {
	root                *testRoot
	key                 *ecdsa.PrivateKey
	csr                 []byte
	certPEM, resultFile []byte
	in                  X509Answer
}

func goodAnswer(t testing.TB) *answer {
	t.Helper()
	a := &answer{root: newRoot(t, "Example Root A (TEST ONLY)"), key: newKey(t)}
	a.csr = makeRequest(t, a.key, testSpec())
	a.certPEM = certPEM(issue(t, a.root, a.csr, testNow, testNow.AddDate(0, 13, 0), nil))
	a.resultFile = resultFile(t, a.csr, a.certPEM, "dev-x509-intermediate.cert.pem", a.root, 7)
	proof := &Proof{RequestSHA256: RequestDigest(a.csr), Store: StoreSoftware}
	a.in = X509Answer{
		Request: a.csr, Proof: proof, CertName: "dev-x509-intermediate.cert.pem", CertFile: a.certPEM, ResultFile: a.resultFile,
		Anchors: []*x509.Certificate{a.root.cert}, Now: testNow.Add(time.Hour),
	}
	return a
}
