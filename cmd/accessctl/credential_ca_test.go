package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// openbaoRoots is shared by every command that reaches OpenBAO (`bao`,
// `pg`, `psql`; `credential`'s own callers used it too, before ADR 0013
// removed them), so it is tested directly here rather than once per
// command: the bundle is ADDED to the system's roots, never put in their
// place, so an installation whose certificate a public CA signs keeps
// verifying with a bundle named for another.
func TestTheBundleIsAddedToTheSystemRoots(t *testing.T) {
	root := newPrivateRoot(t)

	got, err := openbaoRoots(root.bundle)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system roots on this platform: %v", err)
	}
	if !want.AppendCertsFromPEM(root.pem) {
		t.Fatal("the test's own bundle holds no certificate")
	}
	if !got.Equal(want) {
		t.Error("the roots are not the system's with the bundle added")
	}
}

// A bundle that cannot be read, or holds no certificate, is refused
// rather than silently trusting nothing extra -- named clearly enough
// that `bao`'s and `pg`'s own usage errors (each calling this directly
// from their flag resolution) say the same thing.
func TestABundleThatTrustsNothingIsRefused(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	keyOnly := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyOnly, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct{ path, says string }{
		"a file that is not there": {path: filepath.Join(dir, "absent.pem"), says: "read the OpenBAO CA bundle"},
		"a directory":              {path: dir, says: "read the OpenBAO CA bundle"},
		"an empty file":            {path: empty, says: "holds no PEM certificate"},
		"a key, not a certificate": {path: keyOnly, says: "holds no PEM certificate"},
	} {
		_, err := openbaoRoots(tc.path)
		if codeFor(err) != exitUsage || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v, want a usage error saying %q", name, err, tc.says)
		}
	}
}

// privateRoot is a CA no system trusts, with its certificate written as
// a bundle a caller can name. Shared by bao_test.go (`--ca-cert` reaching
// the child as BAO_CACERT) and pg_test.go (the same bundle trusting the
// PKI's own login and sign calls).
type privateRoot struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
	bundle      string
}

func newPrivateRoot(t *testing.T) *privateRoot {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the root key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example private root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the root: %v", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("read back the root: %v", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	bundle := filepath.Join(t.TempDir(), "root.pem")
	if err = os.WriteFile(bundle, encoded, 0o600); err != nil {
		t.Fatalf("write the bundle: %v", err)
	}
	return &privateRoot{certificate: certificate, key: key, pem: encoded, bundle: bundle}
}

// serve answers handler over TLS with a leaf for the loopback address
// that this root signed, and returns the server's URL.
func (r *privateRoot) serve(t *testing.T, handler http.Handler) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "openbao.example"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, r.certificate, &key.PublicKey, r.key)
	if err != nil {
		t.Fatalf("sign the leaf: %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	// The server's own log line for every refused handshake is noise
	// here: refusing them is what half of these tests are for.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// newFakeOpenBAOUnderPrivateRoot is the fake installation over TLS, its
// certificate signed by a root no system trusts, and that root's bundle.
func newFakeOpenBAOUnderPrivateRoot(t *testing.T) (*fakeOpenBAO, string) {
	t.Helper()

	root := newPrivateRoot(t)
	fake := unstartedFakeOpenBAO(t)
	fake.URL = root.serve(t, http.HandlerFunc(fake.serve))
	return fake, root.bundle
}
