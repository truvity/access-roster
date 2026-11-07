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

// These tests run the vectors of ritueel's hand-off contract (testdata/ritueel/README.md says where they come from and
// what was left out). A requester passes when its decision and code match the manifest for every answer; the checks
// of the certifier that sluis makes itself on a request (1 to 5) are run on every request. Every vector must run: a
// manifest that lists none, or a vector whose file is missing, fails the test.

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

// The vectors that the manifest lists for the type sluis builds. A count that moves is a decision for the reader of the
// diff: the vendored set changed.
const (
	wantX509Requests  = 21
	wantX509Responses = 12
)

// Every request vector is read by the checks sluis makes on a request: a version it does not know, an unknown member, a
// request that is not the one the proof names, a key that is not P-384 and a bad signature are refused with the
// contract's code; every other vector passes the first five checks, because the later checks are the certifier's.
func TestRequestVectors(t *testing.T) {
	m := loadManifest(t)
	if len(m.Requests) != wantX509Requests {
		t.Fatalf("the manifest lists %d X.509 requests, want %d", len(m.Requests), wantX509Requests)
	}
	early := map[string]bool{
		"version-unsupported": true, "malformed": true, "request-mismatch": true,
		"algorithm-unsupported": true, "possession-invalid": true,
	}
	for _, r := range m.Requests {
		t.Run(r.ID, func(t *testing.T) {
			csr := mustRead(t, filepath.Join(vectorDir, vectorFile(r.Files, ".csr.pem")))
			proof := mustRead(t, filepath.Join(vectorDir, vectorFile(r.Files, ".proof.json")))
			_, _, err := CheckRequest(csr, proof)
			if r.Expect == "refuse" && early[r.Reason] {
				assertCode(t, err, r.Reason)
				return
			}
			if err != nil {
				t.Fatalf("the first five checks refuse a vector that they pass: %v", err)
			}
		})
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

// Every answer vector is installed or refused with the code the manifest gives: a certificate for another key, a chain to
// a root that is not installed or not on the list, a profile that is not the request's, and a validity of two years or
// one that ended. The floor vectors run with the foreign anchor and no result file.
func TestAnswerVectors(t *testing.T) {
	m := loadManifest(t)
	if len(m.Responses) != wantX509Responses {
		t.Fatalf("the manifest lists %d X.509 answers, want %d", len(m.Responses), wantX509Responses)
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
	for _, r := range m.Responses {
		t.Run(r.ID, func(t *testing.T) {
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
