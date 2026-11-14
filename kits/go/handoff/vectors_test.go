package handoff

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests run the vectors of ritueel's hand-off contract (testdata/ritueel/README.md says where they come from: the whole
// set, as ritueel wrote it). A requester passes when its decision and code match the manifest for every answer; the checks
// of the certifier that sluis makes itself on a request (1 to 5) are run on every request. The first working version builds
// the type x509-intermediate only: a vector of another type is refused by sluis's readers as `malformed`, which is what the
// contract says of a type the receiver does not know, and the test says so for each. Every vector must run: a manifest that
// lists none, or a vector whose file is missing, fails the test.

const vectorDir = "testdata/ritueel/hand-off/v1"

type manifest struct {
	Clock  string `json:"clock"`
	Pinned struct {
		RootList struct {
			X509 []string `json:"x509"`
		} `json:"root_list"`
		FloorAnchors  []string `json:"floor_anchors"`
		TrustSequence int64    `json:"trust_sequence"`
	} `json:"pinned"`
	Requests []struct {
		ID     string   `json:"id"`
		Type   string   `json:"type"`
		Config string   `json:"config"`
		Files  []string `json:"files"`
		Expect string   `json:"expect"`
		Reason string   `json:"reason"`
	} `json:"requests"`
	Responses []struct {
		ID      string   `json:"id"`
		Type    string   `json:"type"`
		Request string   `json:"request"`
		Floor   bool     `json:"floor"`
		Files   []string `json:"files"`
		Expect  string   `json:"expect"`
		Reason  string   `json:"reason"`
	} `json:"responses"`
}

func loadManifest(t *testing.T) *manifest {
	t.Helper()
	b := mustRead(t, filepath.Join(vectorDir, "manifest.json"))
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func mustRead(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: a vector path of this package
	if err != nil {
		t.Fatalf("a vector is missing: %v", err)
	}
	return b
}

func readCerts(t *testing.T, files []string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for _, f := range files {
		blk, _ := pem.Decode(mustRead(t, filepath.Join(vectorDir, f)))
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func vectorFile(files []string, suffix string) string {
	for _, f := range files {
		if bytes.HasSuffix([]byte(f), []byte(suffix)) {
			return f
		}
	}
	return ""
}

// The vectors that the manifest lists, in all and for the type sluis builds. A count that moves is a decision for the reader of
// the diff: the vendored set changed.
const (
	wantRequests      = 166
	wantResponses     = 38
	wantX509Requests  = 127
	wantX509Responses = 20
)

// verifies: REQ-PKI-030
// Every request vector is read by the checks sluis makes on a request: a version it does not know, an unknown member, a
// request that is not well formed, one that is not the one the proof names, a key that is not P-384 and a bad signature are
// refused with the contract's code, in the contract's order; every other vector of the type passes the first five checks,
// because the later checks are the certifier's. A request of another type is refused as malformed.
func TestRequestVectors(t *testing.T) {
	m := loadManifest(t)
	if len(m.Requests) != wantRequests {
		t.Fatalf("the manifest lists %d requests, want %d", len(m.Requests), wantRequests)
	}
	early := map[string]bool{
		"version-unsupported": true, "malformed": true, "request-mismatch": true,
		"algorithm-unsupported": true, "possession-invalid": true,
	}
	x509s := 0
	for _, r := range m.Requests {
		t.Run(r.ID, func(t *testing.T) {
			if r.Type != TypeX509 {
				// sluis builds no other type in the first working version: the proof names a type it does not know.
				proof := mustRead(t, filepath.Join(vectorDir, vectorFile(r.Files, ".proof.json")))
				_, err := ParseProof(proof)
				if r.Reason == CodeVersionUnsupported {
					assertCode(t, err, CodeVersionUnsupported) // the version is read first, and nothing else in the file
				} else {
					assertCode(t, err, CodeMalformed)
				}
				return
			}
			x509s++
			csr := mustRead(t, filepath.Join(vectorDir, vectorFile(r.Files, ".csr.pem")))
			proof := mustRead(t, filepath.Join(vectorDir, vectorFile(r.Files, ".proof.json")))
			req, _, err := CheckRequestFiles(csr, proof)
			if r.Expect == "refuse" && early[r.Reason] {
				assertCode(t, err, r.Reason)
				return
			}
			if err != nil {
				t.Fatalf("the first five checks refuse a vector that they pass: %v", err)
			}
			// The content that the contract calls policy: an accepted request holds none of it, and a request refused with policy
			// for its content is refused by the profile (a refusal for a list, a store or a card is the certifier's).
			perr := CheckRequestProfile(req)
			if r.Expect == "accept" && perr != nil {
				t.Errorf("the profile refuses a request the contract accepts: %v", perr)
			}
			if r.Expect == "refuse" && perr != nil {
				assertCode(t, perr, "policy")
			}
		})
	}
	if x509s != wantX509Requests {
		t.Fatalf("ran %d X.509 requests, want %d", x509s, wantX509Requests)
	}
}

// The extensions of a request that sluis writes have the values of the vectors for the basic constraints and the key
// usage, byte for byte, and the same criticality.
func TestOurRequestMatchesTheVectorsExtensions(t *testing.T) {
	theirs, err := ParseCSRPEM(mustRead(t, filepath.Join(vectorDir, "requests/x509-software-valid.csr.pem")))
	if err != nil {
		t.Fatal(err)
	}
	ours, err := VerifyCSR(makeRequest(t, newKey(t), testSpec()))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{oidBasicConstraints.String(), oidKeyUsage.String(), oidNameConstraints.String()} {
		a, b := findExt(theirs, id), findExt(ours, id)
		if a == nil || b == nil || a.Critical != b.Critical {
			t.Fatalf("extension %s is not in both, or its criticality differs", id)
		}
		if id != oidNameConstraints.String() && !bytes.Equal(a.Value, b.Value) {
			t.Errorf("extension %s differs from the vector", id)
		}
	}
}

// The extended key usage that sluis writes is the one of the vector that states serverAuth and clientAuth: the same bytes and
// the same flag (not critical), and so is every extension of that request that sluis writes.
func TestOurExtendedKeyUsageIsTheVectors(t *testing.T) {
	theirs, err := ParseCSRPEM(mustRead(t, filepath.Join(vectorDir, "requests/x509-eku-server-and-client.csr.pem")))
	if err != nil {
		t.Fatal(err)
	}
	ours, err := VerifyCSR(makeRequest(t, newKey(t), testSpec()))
	if err != nil {
		t.Fatal(err)
	}
	a, b := findExt(theirs, oidExtKeyUsage.String()), findExt(ours, oidExtKeyUsage.String())
	if a == nil || b == nil || a.Critical || b.Critical || !bytes.Equal(a.Value, b.Value) {
		t.Fatalf("the extended key usage differs from the vector: %+v %+v", a, b)
	}
	if got := makeRequest(t, newKey(t), testSpec()); CheckRequestProfileOf(t, got) != nil {
		t.Errorf("the request sluis writes is refused by the contract's profile: %v", CheckRequestProfileOf(t, got))
	}
}

// CheckRequestProfileOf reads a request and applies the contract's profile to it.
func CheckRequestProfileOf(t *testing.T, der []byte) error {
	t.Helper()
	r, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return CheckRequestProfile(r)
}

func findExt(c *x509.CertificateRequest, id string) *struct {
	Critical bool
	Value    []byte
} {
	for _, e := range c.Extensions {
		if e.Id.String() == id {
			return &struct {
				Critical bool
				Value    []byte
			}{e.Critical, e.Value}
		}
	}
	return nil
}

// verifies: REQ-PKI-029
// verifies: REQ-PKI-032
// verifies: REQ-PKI-050
// Every answer vector is installed or refused with the code the manifest gives: a certificate for another key, a chain to
// a root that is not installed or not on the list, a profile that is not the request's, and a validity of two years or
// one that ended. The floor vectors run with the foreign anchor and no result file.
func TestAnswerVectors(t *testing.T) {
	m := loadManifest(t)
	if len(m.Responses) != wantResponses {
		t.Fatalf("the manifest lists %d answers, want %d", len(m.Responses), wantResponses)
	}
	now, err := time.Parse(time.RFC3339, m.Clock)
	if err != nil {
		t.Fatal(err)
	}
	requests := map[string][]string{}
	for _, r := range m.Requests {
		requests[r.ID] = r.Files
	}
	list := readVectorRootList(t, "seq7-a")
	x509s := 0
	for _, r := range m.Responses {
		t.Run(r.ID, func(t *testing.T) {
			if r.Type != TypeX509 {
				// An answer of a type sluis does not build: its result file names a type it does not know.
				_, err := ParseResult(mustRead(t, filepath.Join(vectorDir, vectorFile(r.Files, ".result.json"))))
				assertCode(t, err, CodeMalformed)
				return
			}
			x509s++
			rf, ok := requests[r.Request]
			if !ok {
				t.Fatalf("the vector names the request %q, which is not listed", r.Request)
			}
			csr, _ := pem.Decode(mustRead(t, filepath.Join(vectorDir, vectorFile(rf, ".csr.pem"))))
			certPath := vectorFile(r.Files, ".cert.pem")
			a := X509Answer{
				Request: csr.Bytes, CertName: filepath.Base(certPath), CertFile: mustRead(t, filepath.Join(vectorDir, certPath)), Now: now,
			}
			if proof, err := ParseProof(mustRead(t, filepath.Join(vectorDir, vectorFile(rf, ".proof.json")))); err == nil {
				a.Proof = proof
			}
			if r.Floor {
				a.Anchors = readCerts(t, m.Pinned.FloorAnchors)
			} else {
				a.Anchors = readCerts(t, m.Pinned.RootList.X509)
				a.ResultFile = mustRead(t, filepath.Join(vectorDir, vectorFile(r.Files, ".result.json")))
				a.RootList = list
			}
			v, err := CheckX509(a)
			switch r.Expect {
			case "install":
				if err != nil {
					t.Fatalf("an answer that must install is refused: %v", err)
				}
				if v.Floor != r.Floor {
					t.Errorf("Floor = %v", v.Floor)
				}
				if r.Floor && !contains(v.NotRun, CheckTrustSequence) {
					t.Errorf("the floor reports the trust sequence as checked: ran %v, not run %v", v.Ran, v.NotRun)
				}
				if !r.Floor && !contains(v.Ran, CheckTrustSequence) {
					t.Errorf("a full answer with a held list did not check the trust sequence: ran %v", v.Ran)
				}
			case "refuse":
				assertCode(t, err, r.Reason)
			default:
				t.Fatalf("expect %q", r.Expect)
			}
		})
	}
	if x509s != wantX509Responses {
		t.Fatalf("ran %d X.509 answers, want %d", x509s, wantX509Responses)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// The run fails on a broken vector (issue #1070: "a deliberately broken vector fails the run"): one byte of a good
// certificate changed, and the answer that installs is refused.
func TestABrokenVectorFailsTheRun(t *testing.T) {
	m := loadManifest(t)
	now, _ := time.Parse(time.RFC3339, m.Clock)
	csr, _ := pem.Decode(mustRead(t, filepath.Join(vectorDir, "requests/x509-piv-valid.csr.pem")))
	cert := mustRead(t, filepath.Join(vectorDir, "responses/x509-piv-valid.cert.pem"))
	a := X509Answer{
		Request: csr.Bytes, CertName: "x509-piv-valid.cert.pem", CertFile: cert, Now: now,
		ResultFile: mustRead(t, filepath.Join(vectorDir, "responses/x509-piv-valid.result.json")),
		Anchors:    readCerts(t, m.Pinned.RootList.X509),
	}
	if _, err := CheckX509(a); err != nil {
		t.Fatalf("the good vector is refused: %v", err)
	}
	broken := bytes.Clone(cert)
	broken[len(broken)/2] ^= 0x01
	a.CertFile = broken
	if _, err := CheckX509(a); err == nil {
		t.Fatal("a vector with one byte changed installs")
	}
}
