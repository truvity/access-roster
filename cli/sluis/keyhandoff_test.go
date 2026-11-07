//go:build sluis_test

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/handoff"
	krefusal "github.com/truvity/sluis/v2/kits/go/refusal"
)

// fakeHandoff is key@'s hand-off side: it holds one software key, signs a CertificationRequestInfo only after the same
// check key@ makes (handoff.CheckInfo), and records what it is asked to install. key@'s own tests are in
// actors/key/internal/keyd; this stands for it so that the command is tested end to end over the Connect protocol.
type fakeHandoff struct {
	keyv2alpha1connect.UnimplementedKeyHandoffServiceHandler
	key       *ecdsa.PrivateKey
	store     string
	refuseIns error
	badSig    bool
	mu        sync.Mutex
	installed []*keyv2alpha1.InstallRequest
}

func (f *fakeHandoff) spki() []byte {
	b, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	return b
}

func (f *fakeHandoff) Prepare(context.Context, *connect.Request[keyv2alpha1.PrepareRequest]) (*connect.Response[keyv2alpha1.PrepareResponse], error) {
	return connect.NewResponse(&keyv2alpha1.PrepareResponse{SpkiDer: f.spki(), Store: f.store}), nil
}

func (f *fakeHandoff) SignRequest(_ context.Context, req *connect.Request[keyv2alpha1.SignRequestRequest]) (*connect.Response[keyv2alpha1.SignRequestResponse], error) {
	if err := handoff.CheckInfo(req.Msg.GetInfo(), f.spki()); err != nil {
		return nil, krefusal.New(connect.CodeInvalidArgument, "content", "info")
	}
	d := sha512.Sum384(req.Msg.GetInfo())
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, d[:])
	if err != nil {
		return nil, err
	}
	if f.badSig {
		sig[len(sig)-1] ^= 1
	}
	return connect.NewResponse(&keyv2alpha1.SignRequestResponse{SignatureDer: sig}), nil
}

func (f *fakeHandoff) Install(_ context.Context, req *connect.Request[keyv2alpha1.InstallRequest]) (*connect.Response[keyv2alpha1.InstallResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuseIns != nil {
		return nil, f.refuseIns
	}
	f.installed = append(f.installed, req.Msg)
	return connect.NewResponse(&keyv2alpha1.InstallResponse{Id: "x509-intermediate/test", Audited: true}), nil
}

func (f *fakeHandoff) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.installed)
}

func serveHandoff(t *testing.T, f *fakeHandoff) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "h")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(keyv2alpha1connect.NewKeyHandoffServiceHandler(f))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: mux, Protocols: &p, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func newFakeHandoff(t *testing.T) *fakeHandoff {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHandoff{key: k, store: "software"}
}

var reqNames = []string{"--trust-domain", "dev.example.org", "--dns-zone", "dev.example.org", "--dns-zone", "dev.example.internal"}

func doRequest(ta *testApp, sock, out string, extra ...string) int {
	args := append([]string{"key", "request", "--boundary", "dev", "--socket", sock, "--out", out}, reqNames...)
	return ta.do(append(args, extra...)...)
}

// verifies: REQ-PKI-028
// verifies: REQ-PKI-045
// verifies: REQ-PKI-046
// `sluis key request` writes a PKCS#10 request and the proof of where the key lives, which pass the certifier's checks 1
// to 5; the request carries critical name constraints that permit the boundary's names and exclude every IP range; it
// prints the key's fingerprint and the files, in text and in the JSON object of cli.md.
func TestKeyRequestWritesTheRequestAndTheProof(t *testing.T) {
	f := newFakeHandoff(t)
	sock := serveHandoff(t, f)
	ta := newTestApp(t)
	out := filepath.Join(t.TempDir(), "req")
	if code := doRequest(ta, sock, out, "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	o := ta.object(t)
	fp := fingerprint(f.spki())
	keys := o["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["fingerprint"] != fp || keys[0].(map[string]any)["store"] != "software" || keys[0].(map[string]any)["purpose"] != "x509-intermediate" {
		t.Fatalf("keys = %v", keys)
	}
	reqs := o["requests"].([]any)
	if len(reqs) != 1 || reqs[0].(map[string]any)["stem"] != "dev-x509-intermediate" || len(reqs[0].(map[string]any)["files"].([]any)) != 2 {
		t.Fatalf("requests = %v", reqs)
	}
	csrPEM := mustReadFile(t, filepath.Join(out, "dev-x509-intermediate.csr.pem"))
	proof := mustReadFile(t, filepath.Join(out, "dev-x509-intermediate.proof.json"))
	csr, _, err := handoff.CheckRequest(csrPEM, proof)
	if err != nil {
		t.Fatalf("the files fail the certifier's checks: %v", err)
	}
	// The name constraints, read by a real parser from a certificate that carries the request's extensions.
	root := mustCA(t)
	cert, err := x509.ParseCertificate(issueFor(t, root, csrPEM, time.Now(), time.Now().AddDate(0, 13, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PermittedDNSDomainsCritical || strings.Join(cert.PermittedDNSDomains, ",") != "dev.example.org,dev.example.internal" ||
		len(cert.PermittedURIDomains) != 1 || cert.PermittedURIDomains[0] != "dev.example.org" {
		t.Errorf("name constraints: critical %v, DNS %v, URI %v", cert.PermittedDNSDomainsCritical, cert.PermittedDNSDomains, cert.PermittedURIDomains)
	}
	if len(cert.PermittedIPRanges) != 0 || len(cert.ExcludedIPRanges) != 2 {
		t.Errorf("IP ranges: permitted %v, excluded %v", cert.PermittedIPRanges, cert.ExcludedIPRanges)
	}
	if csr.Subject.CommonName != "sluis dev intermediate" {
		t.Errorf("subject = %v", csr.Subject)
	}
	// Text output names the fingerprint, and a second run does not replace the request.
	if code := doRequest(ta, sock, filepath.Join(t.TempDir(), "req2")); code != 0 || !strings.Contains(ta.out.String(), fp) {
		t.Fatalf("exit %d, out %q", code, ta.out.String())
	}
	if code := doRequest(ta, sock, out); code != 1 {
		t.Fatalf("a second request into the same directory: exit %d", code)
	}
	if after := mustReadFile(t, filepath.Join(out, "dev-x509-intermediate.csr.pem")); string(after) != string(csrPEM) {
		t.Fatal("the request was replaced without --replace")
	}
	if code := doRequest(ta, sock, out, "--replace"); code != 0 {
		t.Fatalf("--replace: exit %d; %s", code, ta.err.String())
	}
}

// With ranges declared, they are permitted and nothing is excluded.
func TestKeyRequestWithDeclaredRanges(t *testing.T) {
	f := newFakeHandoff(t)
	sock := serveHandoff(t, f)
	ta := newTestApp(t)
	out := t.TempDir()
	if code := doRequest(ta, sock, out, "--ip-range", "10.20.0.0/16"); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	cert, err := x509.ParseCertificate(issueFor(t, mustCA(t), mustReadFile(t, filepath.Join(out, "dev-x509-intermediate.csr.pem")), time.Now(), time.Now().AddDate(0, 13, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.PermittedIPRanges) != 1 || len(cert.ExcludedIPRanges) != 0 {
		t.Errorf("permitted %v, excluded %v", cert.PermittedIPRanges, cert.ExcludedIPRanges)
	}
}

func TestKeyRequestUsage(t *testing.T) {
	f := newFakeHandoff(t)
	sock := serveHandoff(t, f)
	ta := newTestApp(t)
	for name, args := range map[string][]string{
		"no boundary":      {"key", "request", "--socket", sock, "--out", t.TempDir(), "--trust-domain", "dev.example.org"},
		"no names":         {"key", "request", "--boundary", "dev", "--socket", sock, "--out", t.TempDir()},
		"another purpose":  {"key", "request", "--boundary", "dev", "--socket", sock, "--out", t.TempDir(), "--trust-domain", "d.example.org", "--purpose", "ssh-user"},
		"a bad range":      {"key", "request", "--boundary", "dev", "--socket", sock, "--out", t.TempDir(), "--ip-range", "10.1.2.3/8"},
		"an argument":      {"key", "request", "extra", "--boundary", "dev", "--socket", sock, "--trust-domain", "d.example.org"},
		"an upper-case dn": {"key", "request", "--boundary", "dev", "--socket", sock, "--out", t.TempDir(), "--dns-zone", "Dev.Example.org"},
	} {
		if code := ta.do(args...); code != 2 {
			t.Errorf("%s: exit %d, want 2; %s", name, code, ta.err.String())
		}
	}
}

// key@'s refusal is exit 4 with its reason, and a request that key@ does not answer is a failure.
func TestKeyRequestWhenKeyRefusesOrIsAway(t *testing.T) {
	ta := newTestApp(t)
	if code := doRequest(ta, filepath.Join(t.TempDir(), "none.sock"), t.TempDir()); code != 1 {
		t.Errorf("no key@: exit %d", code)
	}
	f := newFakeHandoff(t)
	f.store = "unknown"
	sock := serveHandoff(t, f)
	out := t.TempDir()
	if code := doRequest(ta, sock, out); code == 0 {
		t.Error("a store the contract has no word for was requested")
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("a failed request left %d files", len(entries))
	}
}

// A request that fails the certifier's checks is never written, and a request whose proof cannot be written leaves no
// request behind.
func TestKeyRequestWritesNothingItCannotStandBehind(t *testing.T) {
	f := newFakeHandoff(t)
	f.badSig = true
	sock := serveHandoff(t, f)
	ta := newTestApp(t)
	out := t.TempDir()
	if code := doRequest(ta, sock, out); code != 1 {
		t.Fatalf("a bad signature: exit %d", code)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("%d files were written", len(entries))
	}
	f.badSig = false
	if err := os.Mkdir(filepath.Join(out, "dev-x509-intermediate.proof.json"), 0o755); err != nil { //nolint:gosec // the test's own directory
		t.Fatal(err)
	}
	if code := doRequest(ta, sock, out); code != 1 {
		t.Fatalf("a proof that cannot be written: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(out, "dev-x509-intermediate.csr.pem")); err == nil {
		t.Error("the request was left without its proof")
	}
}

// answer is what a test ca returns for the request `key request` wrote.
type answerSet struct {
	dir, req string
	root     *caRoot
	bundle   string
}

type caRoot struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func mustCA(t *testing.T) *caRoot {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Root (TEST ONLY)"},
		NotBefore: time.Now().AddDate(-5, 0, 0), NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &caRoot{k, c, der}
}

func mustReadFile(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// issueFor is what a floor CA does for the request: the subject, the key and the requested extensions with their
// criticality, for the given span.
func issueFor(t *testing.T, root *caRoot, csrPEM []byte, nb, na time.Time) []byte {
	t.Helper()
	blk, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), RawSubject: csr.RawSubject, NotBefore: nb, NotAfter: na, ExtraExtensions: csr.Extensions}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, pub, root.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// newAnswers runs `key request` and lays an answer out as ritueel would: the certificate (and the result file unless
// floor), the CA bundle, and the request directory.
func newAnswers(t *testing.T, ta *testApp, _ *fakeHandoff, sock string, floor bool) *answerSet {
	t.Helper()
	s := &answerSet{dir: t.TempDir(), req: t.TempDir(), root: mustCA(t)}
	if code := doRequest(ta, sock, s.req); code != 0 {
		t.Fatalf("key request: exit %d; %s", code, ta.err.String())
	}
	s.bundle = filepath.Join(t.TempDir(), "ca-bundle.pem")
	if err := os.WriteFile(s.bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.root.der}), 0o600); err != nil {
		t.Fatal(err)
	}
	s.write(t, ta, floor, time.Now().Add(-time.Minute), time.Now().AddDate(0, 13, 0), nil)
	return s
}

// write lays the answer out; mutate may change the result file's members.
func (s *answerSet) write(t *testing.T, _ *testApp, floor bool, nb, na time.Time, mutate func(map[string]any)) {
	t.Helper()
	csrPEM := mustReadFile(t, filepath.Join(s.req, "dev-x509-intermediate.csr.pem"))
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issueFor(t, s.root, csrPEM, nb, na)})
	writeFile(t, filepath.Join(s.dir, "dev-x509-intermediate.cert.pem"), certPEM)
	resPath := filepath.Join(s.dir, "dev-x509-intermediate.result.json")
	if floor {
		_ = os.Remove(resPath)
		return
	}
	blk, _ := pem.Decode(csrPEM)
	m := map[string]any{
		"handoff": 1, "type": "x509-intermediate", "request_sha256": handoff.RequestDigest(blk.Bytes), "outcome": "issued",
		"artifacts":  []map[string]string{{"name": "dev-x509-intermediate.cert.pem", "sha256": fileDigest(certPEM)}},
		"valid_from": nb.UTC().Format("2006-01-02T15:04:05Z"), "valid_until": na.UTC().Format("2006-01-02T15:04:05Z"),
		"issuer": rootPin(s.root), "trust_sequence": 7,
	}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.Marshal(m)
	writeFile(t, resPath, b)
}

func rootPin(r *caRoot) string { return handoff.SPKIPin(r.cert) }

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s *answerSet) install(ta *testApp, sock string, extra ...string) int {
	args := append([]string{"key", "install", s.dir, "--boundary", "dev", "--socket", sock, "--requests", s.req, "--ca-bundle", s.bundle}, extra...)
	return ta.do(args...)
}

// verifies: REQ-PKI-029
// An answer that passes the requester's checks is handed to key@ as a chain of the one certificate, with its trust
// sequence; the output names each stem and the checks that did not run.
func TestKeyInstallHandsAGoodAnswerToKeyAt(t *testing.T) {
	f := newFakeHandoff(t)
	sock := serveHandoff(t, f)
	ta := newTestApp(t)
	s := newAnswers(t, ta, f, sock, false)
	if code := s.install(ta, sock, "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	if f.count() != 1 {
		t.Fatalf("key@ was asked %d times", f.count())
	}
	got := f.installed[0]
	cert, err := x509.ParseCertificate(got.GetChain()[0])
	if err != nil || len(got.GetChain()) != 1 || got.GetTrustSequence() != 7 || got.GetPurpose() != "x509-intermediate" || cert.Subject.CommonName != "sluis dev intermediate" {
		t.Fatalf("install = %v, %v", got, err)
	}
	inst := ta.object(t)["installed"].([]any)[0].(map[string]any)
	if inst["stem"] != "dev-x509-intermediate" || inst["outcome"] != "installed" {
		t.Fatalf("installed = %v", inst)
	}
	// No root list is held: the trust sequence cannot be checked and the output says so.
	if nr, _ := inst["not_run"].([]any); len(nr) != 1 || nr[0] != "trust_sequence" {
		t.Errorf("not_run = %v", inst["not_run"])
	}
}

// On the floor, with no result file, the answer installs and the output lists everything the floor cannot check.
func TestKeyInstallOnTheFloorSaysWhatItDidNotRun(t *testing.T) {
	f := newFakeHandoff(t)
	sock := serveHandoff(t, f)
	ta := newTestApp(t)
	s := newAnswers(t, ta, f, sock, true)
	if code := s.install(ta, sock); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	if f.count() != 1 || f.installed[0].GetTrustSequence() != 0 {
		t.Fatalf("installs = %d", f.count())
	}
	for _, w := range []string{"version", "request_sha256", "trust_sequence", "result_digests", "certifier_store_evidence_key"} {
		if !strings.Contains(ta.out.String(), w) {
			t.Errorf("the output does not say that %s did not run:\n%s", w, ta.out.String())
		}
	}
}

// verifies: REQ-PKI-029
// verifies: REQ-PKI-030
// verifies: REQ-PKI-032
// An answer that fails a check installs nothing, exits 3 and names the contract's code: a certificate for another key, a
// chain to a root that is not installed, an unknown version, a validity above the maximum, one that ended, and an answer
// the certifier refused.
func TestKeyInstallRefusesAndChangesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		code   string
		mutate func(s *answerSet, ta *testApp, t *testing.T)
	}{
		"another key": {"key-mismatch", func(s *answerSet, _ *testApp, t *testing.T) {
			other := newFakeHandoff(t)
			osock := serveHandoff(t, other)
			ta2 := newTestApp(t)
			dir := t.TempDir()
			if code := doRequest(ta2, osock, dir); code != 0 {
				t.Fatal("request")
			}
			// A certificate for the other key, with a result file that names the right request.
			csr := mustReadFile(t, filepath.Join(dir, "dev-x509-intermediate.csr.pem"))
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issueFor(t, s.root, csr, time.Now().Add(-time.Minute), time.Now().AddDate(0, 13, 0))})
			writeFile(t, filepath.Join(s.dir, "dev-x509-intermediate.cert.pem"), certPEM)
			writeFile(t, filepath.Join(s.dir, "dev-x509-intermediate.result.json"), mustReadFile(t, filepath.Join(s.dir, "dev-x509-intermediate.result.json")))
		}},
		"a root that is not installed": {"issuer", func(s *answerSet, _ *testApp, t *testing.T) {
			other := mustCA(t)
			writeFile(t, s.bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.der}))
		}},
		"an unknown version": {"version-unsupported", func(s *answerSet, ta *testApp, t *testing.T) {
			s.write(t, ta, false, time.Now().Add(-time.Minute), time.Now().AddDate(0, 13, 0), func(m map[string]any) { m["handoff"] = 2 })
		}},
		"two years": {"validity", func(s *answerSet, ta *testApp, t *testing.T) {
			s.write(t, ta, false, time.Now().Add(-time.Minute), time.Now().AddDate(2, 0, 0), nil)
		}},
		"ended": {"validity", func(s *answerSet, ta *testApp, t *testing.T) {
			s.write(t, ta, false, time.Now().AddDate(-2, 0, 0), time.Now().AddDate(-2, 13, 0), nil)
		}},
		"the certifier refused": {"policy", func(s *answerSet, _ *testApp, t *testing.T) {
			_ = os.Remove(filepath.Join(s.dir, "dev-x509-intermediate.cert.pem"))
			csr, _ := pem.Decode(mustReadFile(t, filepath.Join(s.req, "dev-x509-intermediate.csr.pem")))
			writeFile(t, filepath.Join(s.dir, "dev-x509-intermediate.result.json"),
				[]byte(fmt.Sprintf(`{"handoff":1,"type":"x509-intermediate","request_sha256":%q,"outcome":"refused","reasons":["policy"]}`, handoff.RequestDigest(csr.Bytes))))
		}},
		"the request of another key": {"request-mismatch", func(s *answerSet, ta *testApp, t *testing.T) {
			s.write(t, ta, false, time.Now().Add(-time.Minute), time.Now().AddDate(0, 13, 0), func(m map[string]any) {
				m["request_sha256"] = handoff.RequestDigest([]byte("another"))
			})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeHandoff(t)
			sock := serveHandoff(t, f)
			ta := newTestApp(t)
			s := newAnswers(t, ta, f, sock, false)
			tc.mutate(s, ta, t)
			if code := s.install(ta, sock, "--output", "json"); code != 3 {
				t.Fatalf("exit %d, want 3; out %s; err %s", code, ta.out.String(), ta.err.String())
			}
			if f.count() != 0 {
				t.Fatal("key@ was asked to install a refused answer")
			}
			o := ta.object(t)
			if o["outcome"] != "refused" {
				t.Errorf("outcome = %v", o["outcome"])
			}
			reasons, _ := o["reasons"].([]any)
			if len(reasons) != 1 || reasons[0] != tc.code {
				t.Errorf("reasons = %v, want [%s]", reasons, tc.code)
			}
		})
	}
}

// key@'s refusal of the install is exit 4 with its reason; no answer and no request are failures.
func TestKeyInstallWhenKeyRefusesOrThereIsNothingToInstall(t *testing.T) {
	f := newFakeHandoff(t)
	f.refuseIns = krefusal.New(connect.CodeInvalidArgument, "key-mismatch", "chain[0]")
	sock := serveHandoff(t, f)
	ta := newTestApp(t)
	s := newAnswers(t, ta, f, sock, false)
	if code := s.install(ta, sock, "--output", "json"); code != 4 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	o := ta.object(t)
	if o["outcome"] != "refused" || o["exit_code"] != float64(4) {
		t.Errorf("object = %v", o)
	}
	// No answer in the directory.
	empty := &answerSet{dir: t.TempDir(), req: s.req, bundle: s.bundle}
	if code := empty.install(ta, sock); code != 1 {
		t.Errorf("no answer: exit %d", code)
	}
	// No request.
	none := &answerSet{dir: s.dir, req: t.TempDir(), bundle: s.bundle}
	if code := none.install(ta, sock); code != 1 {
		t.Errorf("no request: exit %d", code)
	}
	// Usage.
	for name, args := range map[string][]string{
		"no bundle":   {"key", "install", s.dir, "--boundary", "dev", "--socket", sock},
		"no boundary": {"key", "install", s.dir, "--socket", sock, "--ca-bundle", s.bundle},
		"no dir":      {"key", "install", "--boundary", "dev", "--socket", sock, "--ca-bundle", s.bundle},
		"pin only":    {"key", "install", s.dir, "--boundary", "dev", "--socket", sock, "--ca-bundle", s.bundle, "--root-pin", strings.Repeat("a", 64)},
	} {
		if code := ta.do(args...); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}

// writeRootList signs a root list of the one test root, at the sequence, as that root would (ES384, detached JWS in the
// general serialisation), and returns the path of root-list.json; root-list.jws is beside it.
func writeRootList(t *testing.T, root *caRoot, seq int) string {
	t.Helper()
	list := fmt.Sprintf(`{"expires_at":"%s","roots":[{"label":"A","openpgp_fingerprint":"%s","x509_spki_sha256":"%s"}],"sequence":%d,"signed_at":"%s","version":1}`,
		time.Now().AddDate(1, 0, 0).UTC().Format("2006-01-02T15:04:05Z"), strings.Repeat("a", 40), rootPin(root), seq, time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05Z"))
	hdr, _ := json.Marshal(map[string]any{"alg": "ES384", "kid": rootPin(root), "typ": "root-list+json", "x5c": []string{base64.StdEncoding.EncodeToString(root.der)}})
	prot := base64.RawURLEncoding.EncodeToString(hdr)
	d := sha512.Sum384([]byte(prot + "." + base64.RawURLEncoding.EncodeToString([]byte(list))))
	r, s, err := ecdsa.Sign(rand.Reader, root.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	jws := fmt.Sprintf(`{"signatures":[{"protected":%q,"signature":%q}]}`, prot, base64.RawURLEncoding.EncodeToString(sig))
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "root-list.json"), []byte(list))
	writeFile(t, filepath.Join(dir, "root-list.jws"), []byte(jws))
	return filepath.Join(dir, "root-list.json")
}

// verifies: REQ-PKI-050
// verifies: REQ-PKI-029
// With a signed root list held, an answer whose trust sequence is above the list's is refused and nothing is installed; at
// or below it installs, and the trust sequence is reported as checked. A bundle certificate that the list does not pin is
// no anchor.
func TestKeyInstallChecksTheTrustSequenceAgainstTheRootList(t *testing.T) {
	for _, tc := range []struct {
		name      string
		listSeq   int
		code      int
		reason    string
		installed int
	}{
		{"above the list", 6, 3, "issuer", 0},
		{"at the list", 7, 0, "", 1},
		{"below the list", 9, 0, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeHandoff(t)
			sock := serveHandoff(t, f)
			ta := newTestApp(t)
			s := newAnswers(t, ta, f, sock, false)
			list := writeRootList(t, s.root, tc.listSeq)
			code := s.install(ta, sock, "--root-list", list, "--root-pin", rootPin(s.root), "--output", "json")
			if code != tc.code || f.count() != tc.installed {
				t.Fatalf("exit %d, installs %d; %s", code, f.count(), ta.out.String())
			}
			o := ta.object(t)
			if tc.reason != "" {
				if r, _ := o["reasons"].([]any); len(r) != 1 || r[0] != tc.reason {
					t.Errorf("reasons = %v", o["reasons"])
				}
				return
			}
			if nr := o["installed"].([]any)[0].(map[string]any)["not_run"]; nr != nil {
				t.Errorf("not_run = %v: the list was read against a pin and the sequence was checked", nr)
			}
		})
	}
	// A list that pins another root: the bundle's certificate is no anchor.
	f := newFakeHandoff(t)
	sock := serveHandoff(t, f)
	ta := newTestApp(t)
	s := newAnswers(t, ta, f, sock, false)
	other := mustCA(t)
	list := writeRootList(t, other, 7)
	if code := s.install(ta, sock, "--root-list", list, "--root-pin", rootPin(other)); code != 3 || f.count() != 0 {
		t.Fatalf("a list that does not pin the anchor: exit %d, installs %d", code, f.count())
	}
	// A root list read with no pin says that it did not weigh its signers.
	list = writeRootList(t, s.root, 7)
	if code := s.install(ta, sock, "--root-list", list); code != 0 || !strings.Contains(ta.out.String(), "root_list_signers") {
		t.Fatalf("exit %d; %s", code, ta.out.String())
	}
}
