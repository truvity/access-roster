//go:build sluis_test

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	krefusal "github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

const (
	kidA = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	kidB = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
)

// fakeKeyAdmin is key@'s admin side: it verifies the declaration under one publisher key, as key@ does, and answers
// with each key, or with the refusal it is told to give.
type fakeKeyAdmin struct {
	keyv2alpha1connect.UnimplementedKeyAdminServiceHandler
	pub     *ecdsa.PublicKey
	refuse  error
	audited bool
	mu      sync.Mutex
	got     []byte
}

func (f *fakeKeyAdmin) Revoke(_ context.Context, req *connect.Request[keyv2alpha1.RevokeRequest]) (*connect.Response[keyv2alpha1.RevokeResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil {
		return nil, f.refuse
	}
	v, err := signedconfig.VerifyDeclaration(req.Msg.GetDeclaration(), signedconfig.KeyRevocationDeclaration,
		[]signedconfig.Publisher{{KID: "publisher-1", Key: f.pub}})
	if err != nil {
		return nil, krefusal.New(connect.CodePermissionDenied, "declaration", "declaration")
	}
	f.got = v.Payload
	return connect.NewResponse(&keyv2alpha1.RevokeResponse{Seq: v.Seq, Audited: f.audited, Keys: []*keyv2alpha1.RevokedKey{
		{Kid: kidA}, {Kid: kidB, Already: true},
	}}), nil
}

func serveKeyAdmin(t *testing.T, f *fakeKeyAdmin) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k")
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
	mux.Handle(keyv2alpha1connect.NewKeyAdminServiceHandler(f))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: mux, Protocols: &p, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// verifies: REQ-KEYS-092
// The two steps of `sluis key revoke`: it writes the declaration for the keys and the reason, the publisher signs it,
// and the command delivers the signed declaration to key@'s admin socket and prints what key@ did with each key.
func TestKeyRevokeWritesThenDeliversADeclaration(t *testing.T) {
	pub, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeKeyAdmin{pub: &pub.PublicKey, audited: true}
	sock := serveKeyAdmin(t, f)
	ta := newTestApp(t)
	dir := t.TempDir()
	decl := filepath.Join(dir, "revoke.yaml")
	if code := ta.do("key", "revoke", "--boundary", "dev", "--kid", kidA, "--kid", kidB, "--reason", "compromise", "--out", decl); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	payload, err := os.ReadFile(decl) //nolint:gosec // the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"boundary: dev\n", "  - " + kidA + "\n", "  - " + kidB + "\n", "reason: compromise\n"} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("the declaration lacks %q:\n%s", want, payload)
		}
	}
	if strings.Contains(string(payload), "purpose") {
		t.Fatal("a declaration names keys, never a purpose")
	}
	doc, err := signedconfig.Sign(pub, "publisher-1", 42, signedconfig.KeyRevocationDeclaration, payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(dir, "revoke.jws")
	if err := os.WriteFile(signed, doc, 0o600); err != nil { //nolint:gosec // the test's own temporary file
		t.Fatal(err)
	}
	if code := ta.do("key", "revoke", "--boundary", "dev", "--declaration", signed, "--socket", sock, "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	if string(f.got) != string(payload) {
		t.Fatal("key@ did not get the declaration that was written")
	}
	o := ta.object(t)
	r, _ := o["revoke"].(map[string]any)
	keys, _ := r["keys"].([]any)
	if o["outcome"] != "done" || r["seq"] != float64(42) || len(keys) != 2 || r["audited"] != true {
		t.Fatalf("object = %v", o)
	}
	if !strings.Contains(ta.err.String(), "not confirmed") {
		t.Fatalf("the command must say the revocation is not confirmed: %q", ta.err.String())
	}

	// A fact that key@ could not make durable fails the command, though the keys are revoked.
	f.audited = false
	if code := ta.do("key", "revoke", "--boundary", "dev", "--declaration", signed, "--socket", sock); code != 1 {
		t.Fatalf("exit %d, want 1 when the audit fact is not durable", code)
	}
}

// A refusal of key@ exits 3 with its reason and field path; a declaration that key@ cannot be reached for fails.
func TestKeyRevokeReportsTheRefusalOfKeyAt(t *testing.T) {
	f := &fakeKeyAdmin{refuse: krefusal.New(connect.CodeFailedPrecondition, "unknown-kid", "kids[1]")}
	sock := serveKeyAdmin(t, f)
	ta := newTestApp(t)
	signed := filepath.Join(t.TempDir(), "revoke.jws")
	if err := os.WriteFile(signed, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := ta.do("key", "revoke", "--boundary", "dev", "--declaration", signed, "--socket", sock, "--output", "json"); code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
	o := ta.object(t)
	reasons, _ := o["reasons"].([]any)
	if len(reasons) != 2 || reasons[0] != "unknown-kid" || reasons[1] != "kids[1]" {
		t.Fatalf("object = %v", o)
	}
	if code := ta.do("key", "revoke", "--boundary", "dev", "--declaration", signed, "--socket", filepath.Join(t.TempDir(), "none.sock")); code != 1 {
		t.Fatalf("exit %d with no key@, want 1", code)
	}
}

// The declaration is checked before it is written: keys that are not thumbprints, a key twice, a reason outside the
// list, no boundary, and a mix of the two steps are usage errors, and nothing is written.
func TestKeyRevokeRefusesABadDeclaration(t *testing.T) {
	ta := newTestApp(t)
	out := filepath.Join(t.TempDir(), "revoke.yaml")
	for name, args := range map[string][]string{
		"no key":        {"--boundary", "dev", "--reason", "drill"},
		"not a kid":     {"--boundary", "dev", "--kid", "token-signing", "--reason", "drill"},
		"twice":         {"--boundary", "dev", "--kid", kidA, "--kid", kidA, "--reason", "drill"},
		"a reason":      {"--boundary", "dev", "--kid", kidA, "--reason", "because"},
		"no boundary":   {"--kid", kidA, "--reason", "drill"},
		"both steps":    {"--boundary", "dev", "--kid", kidA, "--reason", "drill", "--declaration", out},
		"socket alone":  {"--boundary", "dev", "--kid", kidA, "--reason", "drill", "--socket", out},
		"an argument":   {"--boundary", "dev", "--kid", kidA, "--reason", "drill", "extra"},
		"bad boundary":  {"--boundary", "../dev", "--kid", kidA, "--reason", "drill"},
		"empty --kid":   {"--boundary", "dev", "--kid", "", "--reason", "drill"},
		"upper reason":  {"--boundary", "dev", "--kid", kidA, "--reason", "Drill"},
		"purpose given": {"--boundary", "dev", "--kid", kidA, "--reason", "drill", "--purpose", "token-signing"},
	} {
		if code := ta.do(append([]string{"key", "revoke", "--out", out}, args...)...); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a refused declaration was written")
	}
}
