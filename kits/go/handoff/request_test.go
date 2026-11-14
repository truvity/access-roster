package handoff

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// verifies: REQ-PKI-028
// The request this package writes is a PKCS#10 request that an independent parser reads (Go's crypto/x509), whose
// signature verifies, and whose extensions are the ones of the contract: critical, but for the extended key usage, which is not.
func TestRequestIsAValidPKCS10(t *testing.T) {
	key := newKey(t)
	der := makeRequest(t, key, testSpec())
	csr, err := VerifyCSR(der)
	if err != nil {
		t.Fatalf("VerifyCSR: %v", err)
	}
	if csr.Subject.CommonName != "Example Intermediate (TEST ONLY)" {
		t.Errorf("subject = %v", csr.Subject)
	}
	if len(csr.Extensions) != 4 {
		t.Fatalf("extensions = %d, want 4", len(csr.Extensions))
	}
	for _, e := range csr.Extensions {
		if e.Critical == e.Id.Equal(oidExtKeyUsage) {
			t.Errorf("extension %v has the wrong criticality: %v", e.Id, e.Critical)
		}
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("signature: %v", err)
	}
}

// verifies: REQ-PKI-045
// The name constraints are read back by a real X.509 parser from a certificate that carries the request's
// extensions: critical, the permitted URI host and DNS names, and nothing permitted for an IP address.
func TestRequestNameConstraintsPermitOnlyTheBoundarysNames(t *testing.T) {
	root := newRoot(t, "Example Root")
	der := makeRequest(t, newKey(t), testSpec())
	cert, err := x509.ParseCertificate(issue(t, root, der, testNow, testNow.AddDate(0, 13, 0), nil))
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PermittedDNSDomainsCritical {
		t.Error("the name constraints are not critical")
	}
	if got := strings.Join(cert.PermittedDNSDomains, ","); got != "dev.example.org,dev.example.internal" {
		t.Errorf("permitted DNS = %q", got)
	}
	if len(cert.PermittedURIDomains) != 1 || cert.PermittedURIDomains[0] != "dev.example.org" {
		t.Errorf("permitted URI = %v", cert.PermittedURIDomains)
	}
	if !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("basic constraints: CA %v, path length %d (zero %v)", cert.IsCA, cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage = %v", cert.KeyUsage)
	}
}

// verifies: REQ-PKI-046
// With no IP range declared the request excludes both address families, so that no leaf of the intermediate can carry an
// address; with a range declared it is permitted and nothing is excluded.
func TestRequestExcludesEveryIPRangeWhenNoneIsDeclared(t *testing.T) {
	root := newRoot(t, "Example Root")
	for _, tc := range []struct {
		name      string
		ranges    []netip.Prefix
		permitted int
		excluded  []string
	}{
		{"none declared", nil, 0, []string{"0.0.0.0/0", "::/0"}},
		{"one declared", []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec()
			spec.Constraints.IPRanges = tc.ranges
			der := makeRequest(t, newKey(t), spec)
			cert, err := x509.ParseCertificate(issue(t, root, der, testNow, testNow.AddDate(0, 13, 0), nil))
			if err != nil {
				t.Fatal(err)
			}
			if len(cert.PermittedIPRanges) != tc.permitted {
				t.Errorf("permitted IP ranges = %v, want %d", cert.PermittedIPRanges, tc.permitted)
			}
			var got []string
			for _, n := range cert.ExcludedIPRanges {
				got = append(got, n.String())
			}
			if strings.Join(got, ",") != strings.Join(tc.excluded, ",") {
				t.Errorf("excluded IP ranges = %v, want %v", got, tc.excluded)
			}
		})
	}
}

func TestConstraintsRefuseWhatCannotBeARequest(t *testing.T) {
	for name, c := range map[string]Constraints{
		"no subtree":      {},
		"upper case":      {DNS: []string{"Dev.Example.org"}},
		"underscore":      {DNS: []string{"a_b.example.org"}},
		"empty host":      {URIHosts: []string{""}},
		"unmasked range":  {IPRanges: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/8")}},
		"a URL as a host": {URIHosts: []string{"spiffe://dev.example.org"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CertificationRequestInfo(spkiOf(t, &newKey(t).PublicKey), RequestSpec{Constraints: c}); err == nil {
				t.Fatal("a request was built")
			}
		})
	}
}

func TestOnlyP384KeysAreRequested(t *testing.T) {
	if _, err := CertificationRequestInfo([]byte("not a key"), testSpec()); err == nil {
		t.Fatal("a request for garbage")
	}
}

// A request whose signature is made by another key, or whose signature algorithm is not ecdsa-with-SHA384, is refused
// by the certifier's checks 4 and 5, and sluis refuses to write it.
func TestVerifyCSRRefusesAWrongSignature(t *testing.T) {
	key, other := newKey(t), newKey(t)
	info, err := CertificationRequestInfo(spiKOfKey(t, key), testSpec())
	if err != nil {
		t.Fatal(err)
	}
	sig := signDigest(t, other, info)
	der, _ := AssembleCSR(info, sig)
	_, err = VerifyCSR(der)
	assertCode(t, err, "possession-invalid")
}

func assertCode(t testing.TB, err error, code string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("error = %v, want the code %s", err, code)
	}
	if r.Code != code {
		t.Fatalf("code = %s (%s), want %s", r.Code, r.At, code)
	}
}

// verifies: REQ-PKI-030
func TestProofRoundTripsAndRefusesWhatTheContractRefuses(t *testing.T) {
	der := makeRequest(t, newKey(t), testSpec())
	good := &Proof{RequestSHA256: RequestDigest(der), Store: StoreSoftware}
	b, err := good.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"handoff":1,"type":"x509-intermediate","request_sha256":"`+good.RequestSHA256+`","store":"software"}`+"\n" {
		t.Errorf("proof = %s", b)
	}
	p, err := ParseProof(b)
	if err != nil || p.Store != StoreSoftware || p.RequestSHA256 != good.RequestSHA256 {
		t.Fatalf("ParseProof = %+v, %v", p, err)
	}
	d := good.RequestSHA256
	for name, tc := range map[string]struct {
		in, code string
	}{
		"version 2":         {`{"handoff":2,"type":"x509-intermediate","request_sha256":"` + d + `","store":"software"}`, "version-unsupported"},
		"version 0":         {`{"handoff":0,"type":"x509-intermediate","request_sha256":"` + d + `","store":"software"}`, "version-unsupported"},
		"version 99":        {`{"handoff":99,"type":"x509-intermediate","request_sha256":"` + d + `","store":"software"}`, "version-unsupported"},
		"version first":     {`{"handoff":2,"zzz":1}`, "version-unsupported"},
		"no version":        {`{"type":"x509-intermediate","request_sha256":"` + d + `","store":"software"}`, "malformed"},
		"unknown member":    {`{"handoff":1,"type":"x509-intermediate","request_sha256":"` + d + `","store":"software","extra":1}`, "malformed"},
		"repeated member":   {`{"handoff":1,"type":"x509-intermediate","type":"x509-intermediate","request_sha256":"` + d + `","store":"software"}`, "malformed"},
		"unknown type":      {`{"handoff":1,"type":"tls-leaf","request_sha256":"` + d + `","store":"software"}`, "malformed"},
		"other known type":  {`{"handoff":1,"type":"ssh-ca-key","request_sha256":"` + d + `","store":"software"}`, "malformed"},
		"software evidence": {`{"handoff":1,"type":"x509-intermediate","request_sha256":"` + d + `","store":"software","evidence":{}}`, "malformed"},
		"piv no evidence":   {`{"handoff":1,"type":"x509-intermediate","request_sha256":"` + d + `","store":"piv"}`, "malformed"},
		"unknown store":     {`{"handoff":1,"type":"x509-intermediate","request_sha256":"` + d + `","store":"hsm"}`, "malformed"},
		"short digest":      {`{"handoff":1,"type":"x509-intermediate","request_sha256":"abc","store":"software"}`, "malformed"},
		"upper digest":      {`{"handoff":1,"type":"x509-intermediate","request_sha256":"` + strings.ToUpper(d) + `","store":"software"}`, "malformed"},
		"float version":     {`{"handoff":1.0,"type":"x509-intermediate","request_sha256":"` + d + `","store":"software"}`, "malformed"},
		"byte order mark":   {"\xef\xbb\xbf" + `{"handoff":1,"type":"x509-intermediate","request_sha256":"` + d + `","store":"software"}`, "malformed"},
		"trailing data":     {`{"handoff":1,"type":"x509-intermediate","request_sha256":"` + d + `","store":"software"} {}`, "malformed"},
		"not an object":     {`[1]`, "malformed"},
		"too large":         {`{"handoff":1,"pad":"` + strings.Repeat("a", MaxJSON) + `"}`, "malformed"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProof([]byte(tc.in))
			assertCode(t, err, tc.code)
		})
	}
}

func TestProofCarriesItsEvidence(t *testing.T) {
	d := RequestDigest([]byte("x"))
	piv := &Proof{RequestSHA256: d, Store: StorePIV, Attestation: [][]byte{{1, 2, 3}, {4, 5, 6}}}
	b, err := piv.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseProof(b)
	if err != nil || len(p.Attestation) != 2 || !bytes.Equal(p.Attestation[1], []byte{4, 5, 6}) {
		t.Fatalf("piv: %+v, %v", p, err)
	}
	kms := &Proof{RequestSHA256: d, Store: StoreAWSKMS, KeyARN: "arn:aws:kms:eu-west-1:111122223333:key/abc", PublicKey: []byte{9, 9}}
	b, err = kms.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if p, err = ParseProof(b); err != nil || p.KeyARN != kms.KeyARN || !bytes.Equal(p.PublicKey, []byte{9, 9}) {
		t.Fatalf("kms: %+v, %v", p, err)
	}
	for name, bad := range map[string]*Proof{
		"piv with one certificate": {RequestSHA256: d, Store: StorePIV, Attestation: [][]byte{{1}}},
		"software with evidence":   {RequestSHA256: d, Store: StoreSoftware, Attestation: [][]byte{{1}, {2}}},
		"kms without a key":        {RequestSHA256: d, Store: StoreAWSKMS},
		"no digest":                {Store: StoreSoftware},
	} {
		if _, err := bad.Marshal(); err == nil {
			t.Errorf("%s: written", name)
		}
	}
}

func TestCheckRequestIsTheCertifiersFirstFiveChecks(t *testing.T) {
	key := newKey(t)
	der := makeRequest(t, key, testSpec())
	csrPEM := CSRPEM(der)
	proof, _ := (&Proof{RequestSHA256: RequestDigest(der), Store: StoreSoftware}).Marshal()
	if _, _, err := CheckRequest(csrPEM, proof); err != nil {
		t.Fatalf("a good request: %v", err)
	}
	other, _ := (&Proof{RequestSHA256: RequestDigest([]byte("another request")), Store: StoreSoftware}).Marshal()
	_, _, err := CheckRequest(csrPEM, other)
	assertCode(t, err, "request-mismatch")
	_, _, err = CheckRequest(append(csrPEM, csrPEM...), proof)
	assertCode(t, err, "malformed")
	_, _, err = CheckRequest([]byte("-----BEGIN NOPE-----\n-----END NOPE-----\n"), proof)
	assertCode(t, err, "malformed")
}

// A request whose signature is a valid ECDSA signature over the SHA-384 digest of its info, but whose signature
// algorithm names ecdsa-with-SHA256, is not possession-proven: check 5 of the contract takes only ecdsa-with-SHA384.
// The signature here verifies, so only the algorithm check refuses it.
func TestRequestSignedWithAnotherAlgorithmIsPossessionInvalid(t *testing.T) {
	key := newKey(t)
	info, err := CertificationRequestInfo(spiKOfKey(t, key), testSpec())
	if err != nil {
		t.Fatal(err)
	}
	oidSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	sig := signDigest(t, key, info)
	der, err := asn1.Marshal(struct {
		Info      asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		Info:      asn1.RawValue{FullBytes: info},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		Signature: asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyRequest(der)
	assertCode(t, err, "possession-invalid")
}
