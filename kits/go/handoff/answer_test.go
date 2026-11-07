package handoff

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAGoodFullAnswerPassesEveryCheck(t *testing.T) {
	a := goodAnswer(t)
	v, err := CheckX509(a.in)
	if err != nil {
		t.Fatal(err)
	}
	if v.Floor || len(v.NotRun) != 1 || v.NotRun[0] != CheckTrustSequence {
		// No root list is held here, so the trust sequence cannot be checked and must say so.
		t.Fatalf("floor %v, not run %v", v.Floor, v.NotRun)
	}
	if v.Cert == nil || len(v.CertDER) == 0 {
		t.Fatal("no certificate returned")
	}
}

// A check that cannot run is never reported as passed (principle 4): on the floor there is no result file, so the
// version, the request digest, the digests, the trust sequence and the certifier's checks of where the key lives are all
// reported as not run.
func TestTheFloorSaysWhatItDidNotRun(t *testing.T) {
	a := goodAnswer(t)
	a.in.ResultFile = nil
	v, err := CheckX509(a.in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{CheckVersion, CheckRequestDigest, CheckTrustSequence, CheckDigests, CheckWhereKeyLives}
	if strings.Join(v.NotRun, ",") != strings.Join(want, ",") {
		t.Fatalf("not run = %v, want %v", v.NotRun, want)
	}
	for _, n := range want {
		if contains(v.Ran, n) {
			t.Errorf("%s is reported as run", n)
		}
	}
	for _, n := range []string{CheckIssuer, CheckKey, CheckProfile, CheckValidity} {
		if !contains(v.Ran, n) {
			t.Errorf("%s did not run on the floor", n)
		}
	}
}

// verifies: REQ-PKI-029
// A certificate whose chain leads to no anchor, and one for another key, are refused with their codes, and the result
// carries nothing to install.
func TestAnswerWithTheWrongChainOrKeyIsRefused(t *testing.T) {
	t.Run("a root that is not installed", func(t *testing.T) {
		a := goodAnswer(t)
		other := newRoot(t, "Example Root Z (TEST ONLY)")
		a.in.Anchors = []*x509.Certificate{other.cert}
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeIssuer)
	})
	t.Run("no anchor at all", func(t *testing.T) {
		a := goodAnswer(t)
		a.in.Anchors = nil
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeIssuer)
	})
	t.Run("a certificate of another key", func(t *testing.T) {
		a := goodAnswer(t)
		other := makeRequest(t, newKey(t), testSpec())
		a.in.CertFile = certPEM(issue(t, a.root, other, testNow, testNow.AddDate(0, 13, 0), nil))
		a.in.ResultFile = resultFile(t, a.csr, a.in.CertFile, a.in.CertName, a.root, 7)
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeKeyMismatch)
	})
	t.Run("a certificate that names another issuer than the root that signed it", func(t *testing.T) {
		a := goodAnswer(t)
		var r map[string]any
		_ = json.Unmarshal(a.in.ResultFile, &r)
		r["issuer"] = strings.Repeat("0", 64)
		a.in.ResultFile, _ = json.Marshal(r)
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeIssuer)
	})
	t.Run("the root is in the answer", func(t *testing.T) {
		a := goodAnswer(t)
		a.in.CertFile = append(append([]byte{}, a.certPEM...), certPEM(a.root.der)...)
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeMalformed)
	})
}

// verifies: REQ-PKI-030
// An answer of a contract version the requester does not know is refused as version-unsupported, whatever else it holds,
// and an answer of another version than the request's is not read.
func TestAnswerOfAnUnknownVersionIsRefused(t *testing.T) {
	a := goodAnswer(t)
	var r map[string]any
	_ = json.Unmarshal(a.in.ResultFile, &r)
	r["handoff"] = 2
	r["unknown_member_of_version_2"] = true
	a.in.ResultFile, _ = json.Marshal(r)
	_, err := CheckX509(a.in)
	assertCode(t, err, CodeVersionUnsupported)
	// The same file in version 1 with the unknown member is malformed: the version is read first, then the members.
	r["handoff"] = 1
	a.in.ResultFile, _ = json.Marshal(r)
	_, err = CheckX509(a.in)
	assertCode(t, err, CodeMalformed)
}

// verifies: REQ-PKI-032
// A certificate valid for more than 14 months is refused, and so is one valid for less than 12, or one that has ended or
// has not begun; 13 months, the certifier's length, installs, and so do the two ends of the window.
func TestAnswerValidity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		months    int
		days      int
		nowOffset time.Duration
		code      string
	}{
		{"13 months", 13, 0, time.Hour, ""},
		{"12 months", 12, 0, time.Hour, ""},
		{"14 months", 14, 0, time.Hour, ""},
		{"14 months and a day", 14, 1, time.Hour, CodeValidity},
		{"two years", 24, 0, time.Hour, CodeValidity},
		{"11 months and 29 days", 11, 29, time.Hour, CodeValidity},
		{"ended", 13, 0, 14 * 30 * 24 * time.Hour, CodeValidity},
		{"not begun", 13, 0, -time.Hour, CodeValidity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := goodAnswer(t)
			na := testNow.AddDate(0, tc.months, tc.days)
			a.in.CertFile = certPEM(issue(t, a.root, a.csr, testNow, na, nil))
			a.in.ResultFile = resultFile(t, a.csr, a.in.CertFile, a.in.CertName, a.root, 7)
			a.in.Now = testNow.Add(tc.nowOffset)
			_, err := CheckX509(a.in)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			assertCode(t, err, tc.code)
		})
	}
}

// verifies: REQ-PKI-050
// An answer whose trust sequence is above the sequence of the root list the requester holds is refused, and nothing is
// returned to install; one at or below it passes, and the check is reported as run.
func TestAnswerWithATrustSequenceAboveTheHeldListIsRefused(t *testing.T) {
	a := goodAnswer(t)
	a.in.RootList = &RootList{Sequence: 7, Roots: []Root{{Label: "A", X509SPKISHA256: SPKIPin(a.root.cert), OpenPGPFingerprint: strings.Repeat("a", 40)}}}
	for _, tc := range []struct {
		seq  int64
		fail bool
	}{{6, false}, {7, false}, {8, true}, {1000, true}} {
		a.in.ResultFile = resultFile(t, a.csr, a.in.CertFile, a.in.CertName, a.root, tc.seq)
		v, err := CheckX509(a.in)
		if tc.fail {
			assertCode(t, err, CodeIssuer)
			if v != nil {
				t.Errorf("sequence %d: an answer is returned with a refusal", tc.seq)
			}
			continue
		}
		if err != nil {
			t.Fatalf("sequence %d: %v", tc.seq, err)
		}
		if !contains(v.Ran, CheckTrustSequence) || contains(v.NotRun, CheckTrustSequence) {
			t.Errorf("sequence %d: ran %v, not run %v", tc.seq, v.Ran, v.NotRun)
		}
	}
}

// A root list that nothing anchored still bounds the sequence, but the check is reported as not run, never as passed.
func TestAnUnanchoredListDoesNotCountTheTrustSequenceAsChecked(t *testing.T) {
	a := goodAnswer(t)
	a.in.RootList = &RootList{Sequence: 7, Roots: []Root{{Label: "A", X509SPKISHA256: SPKIPin(a.root.cert), OpenPGPFingerprint: strings.Repeat("a", 40)}}}
	a.in.ListUnanchored = true
	v, err := CheckX509(a.in)
	if err != nil {
		t.Fatal(err)
	}
	if contains(v.Ran, CheckTrustSequence) || !contains(v.NotRun, CheckTrustSequence) {
		t.Fatalf("ran %v, not run %v", v.Ran, v.NotRun)
	}
	a.in.ResultFile = resultFile(t, a.csr, a.in.CertFile, a.in.CertName, a.root, 8)
	_, err = CheckX509(a.in)
	assertCode(t, err, CodeIssuer)
}

// With a root list held, a certificate of the bundle is an anchor only if its key is on the list; a bundle that names
// another sequence than the list's is refused.
func TestRootListGatesTheAnchors(t *testing.T) {
	a := goodAnswer(t)
	listed := &RootList{Sequence: 7, Roots: []Root{{Label: "A", X509SPKISHA256: SPKIPin(a.root.cert), OpenPGPFingerprint: strings.Repeat("a", 40)}}}
	a.in.RootList = listed
	if _, err := CheckX509(a.in); err != nil {
		t.Fatalf("an anchor on the list: %v", err)
	}
	a.in.RootList = &RootList{Sequence: 7, Roots: []Root{{Label: "B", X509SPKISHA256: strings.Repeat("0", 64), OpenPGPFingerprint: strings.Repeat("b", 40)}}}
	_, err := CheckX509(a.in)
	assertCode(t, err, CodeIssuer)
	a.in.RootList, a.in.BundleSequence = listed, 8
	_, err = CheckX509(a.in)
	assertCode(t, err, CodeIssuer)
}

func TestAnswerProfile(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*x509.Certificate)
		code   string
	}{
		"extensions dropped": {func(c *x509.Certificate) { c.ExtraExtensions = nil; c.IsCA, c.BasicConstraintsValid = true, true }, CodeProfile},
		"another critical extension": {func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, extension(testOID, true))
		}, CodeProfile},
		"an unrequested non-critical extension": {func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, extension(testOID, false))
		}, CodeProfile},
		"an unrequested extended key usage": {func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, CodeProfile},
		"the key identifiers a CA adds":     {func(c *x509.Certificate) { c.SubjectKeyId = []byte{1, 2, 3, 4, 5} }, ""},
		"a requested extension made non-critical": {func(c *x509.Certificate) {
			for i := range c.ExtraExtensions {
				c.ExtraExtensions[i].Critical = false
			}
		}, CodeProfile},
		"another subject": {func(c *x509.Certificate) { c.RawSubject = nil; c.Subject.CommonName = "other" }, CodeProfile},
	} {
		t.Run(name, func(t *testing.T) {
			a := goodAnswer(t)
			a.in.CertFile = certPEM(issue(t, a.root, a.csr, testNow, testNow.AddDate(0, 13, 0), tc.mutate))
			a.in.ResultFile = resultFile(t, a.csr, a.in.CertFile, a.in.CertName, a.root, 7)
			_, err := CheckX509(a.in)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			assertCode(t, err, tc.code)
		})
	}
}

// A path length of 1, a changed name constraint and a changed key usage are all a certificate that is not what the
// request asked.
func TestAnswerThatChangesWhatWasAsked(t *testing.T) {
	a := goodAnswer(t)
	other := testSpec()
	other.Constraints.DNS = append(other.Constraints.DNS, "prod.example.org")
	otherCSR := makeRequest(t, a.key, other)
	// The certificate carries the extensions of another request for the same key.
	a.in.CertFile = certPEM(issue(t, a.root, otherCSR, testNow, testNow.AddDate(0, 13, 0), nil))
	a.in.ResultFile = resultFile(t, a.csr, a.in.CertFile, a.in.CertName, a.root, 7)
	_, err := CheckX509(a.in)
	assertCode(t, err, CodeProfile)
}

func TestAnswerDigestsAndRequestBinding(t *testing.T) {
	t.Run("the result names another request", func(t *testing.T) {
		a := goodAnswer(t)
		var r map[string]any
		_ = json.Unmarshal(a.in.ResultFile, &r)
		r["request_sha256"] = RequestDigest([]byte("another"))
		a.in.ResultFile, _ = json.Marshal(r)
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeRequestMismatch)
	})
	t.Run("the proof names another request than the result", func(t *testing.T) {
		a := goodAnswer(t)
		a.in.Proof = &Proof{RequestSHA256: RequestDigest([]byte("another")), Store: StoreSoftware}
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeRequestMismatch)
	})
	t.Run("the digest of the certificate file is not the result's", func(t *testing.T) {
		a := goodAnswer(t)
		var r map[string]any
		_ = json.Unmarshal(a.in.ResultFile, &r)
		r["artifacts"] = []map[string]string{{"name": a.in.CertName, "sha256": strings.Repeat("0", 64)}}
		a.in.ResultFile, _ = json.Marshal(r)
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeMalformed)
	})
	t.Run("the result lists a file that is not there", func(t *testing.T) {
		a := goodAnswer(t)
		var r map[string]any
		_ = json.Unmarshal(a.in.ResultFile, &r)
		r["artifacts"] = []map[string]string{{"name": a.in.CertName, "sha256": sha256Hex(a.certPEM)}, {"name": "x.bin", "sha256": strings.Repeat("1", 64)}}
		a.in.ResultFile, _ = json.Marshal(r)
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeMalformed)
	})
	t.Run("the validity in the result is not the certificate's", func(t *testing.T) {
		a := goodAnswer(t)
		var r map[string]any
		_ = json.Unmarshal(a.in.ResultFile, &r)
		r["valid_until"] = testNow.AddDate(0, 12, 0).Format(timeFormat)
		a.in.ResultFile, _ = json.Marshal(r)
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeMalformed)
	})
	t.Run("the certifier refused", func(t *testing.T) {
		a := goodAnswer(t)
		a.in.ResultFile = []byte(`{"handoff":1,"type":"x509-intermediate","request_sha256":"` + RequestDigest(a.csr) + `","outcome":"refused","reasons":["policy","declined"]}`)
		_, err := CheckX509(a.in)
		var cr *CertifierRefused
		if !errors.As(err, &cr) || strings.Join(cr.Reasons, ",") != "policy,declined" {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("a refused answer with an artifact", func(t *testing.T) {
		a := goodAnswer(t)
		a.in.ResultFile = []byte(`{"handoff":1,"type":"x509-intermediate","request_sha256":"` + RequestDigest(a.csr) + `","outcome":"refused","reasons":["policy"],"artifacts":[{"name":"a","sha256":"` + strings.Repeat("0", 64) + `"}]}`)
		_, err := CheckX509(a.in)
		assertCode(t, err, CodeMalformed)
	})
}

func TestResultFileIsStrict(t *testing.T) {
	a := goodAnswer(t)
	good := string(a.in.ResultFile)
	for name, mutate := range map[string]func(string) string{
		"unknown member":  func(s string) string { return strings.Replace(s, `{"`, `{"extra":1,"`, 1) },
		"repeated member": func(s string) string { return strings.Replace(s, `{"`, `{"outcome":"issued","`, 1) },
		"float sequence":  func(s string) string { return strings.Replace(s, `"trust_sequence":7`, `"trust_sequence":7.0`, 1) },
		"zero sequence":   func(s string) string { return strings.Replace(s, `"trust_sequence":7`, `"trust_sequence":0`, 1) },
		"local time":      func(s string) string { return strings.Replace(s, "Z\"", "+01:00\"", 1) },
		"unknown outcome": func(s string) string { return strings.Replace(s, `"issued"`, `"maybe"`, 1) },
		"other type":      func(s string) string { return strings.Replace(s, `"x509-intermediate"`, `"ssh-ca-key"`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseResult([]byte(mutate(good))); err == nil {
				t.Fatal("accepted")
			} else {
				assertCode(t, err, CodeMalformed)
			}
		})
	}
	if _, err := ParseResult([]byte(good)); err != nil {
		t.Fatalf("the good result: %v", err)
	}
}

var testOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

func extension(oid asn1.ObjectIdentifier, critical bool) pkix.Extension {
	return pkix.Extension{Id: oid, Critical: critical, Value: []byte{0x05, 0x00}}
}
