package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// An installation whose API is served under a private root is reached
// only when that root is named: with no bundle the connection is refused
// as untrusted — and the refusal says how to fix it — and with one, from
// the flag or from either variable, the whole credential is minted.
func TestAPrivateRootIsTrustedOnlyWhenNamed(t *testing.T) {
	bao, bundle := newFakeOpenBAOUnderPrivateRoot(t)
	issuer := newFakeIssuer(t)
	signedInHome(t)

	err := credential([]string{"ssh", "--env", "staging", "--identity", "id_example",
		"--issuer", issuer, "--address", bao.URL})
	if err == nil {
		t.Fatal("a server under a private root was trusted with no bundle named")
	}
	if !errors.Is(err, errUnreachable) || !strings.Contains(err.Error(), "--ca-cert") ||
		!strings.Contains(err.Error(), envOpenBAOCACert) {
		t.Errorf("an untrusted server = %v, want it unreachable and the way to trust it named", err)
	}
	if len(bao.calls) != 0 {
		t.Errorf("OpenBAO answered an untrusted connection: %v", bao.calls)
	}

	for name, tc := range map[string]struct {
		bao, vault string
		args       []string
	}{
		"the flag":       {args: []string{"--ca-cert", bundle}},
		envOpenBAOCACert: {bao: bundle},
		envVaultCACert:   {vault: bundle},
	} {
		t.Setenv(envOpenBAOCACert, tc.bao)
		t.Setenv(envVaultCACert, tc.vault)
		bao.calls = nil

		args := append([]string{"ssh", "--env", "staging", "--identity", "id_example",
			"--issuer", issuer, "--address", bao.URL}, tc.args...)
		_ = captureStdout(t, func() error { return credential(args) })

		if !slices.Equal(bao.calls, []string{"auth/jwt-roster/login", "ssh/sign/user", "auth/token/revoke-self"}) {
			t.Errorf("%s: called %v, want a login, one signing and a revoke", name, bao.calls)
		}
	}
}

// The bundle is for OpenBAO and nothing else: an issuer under the same
// private root is still verified against the system's roots, so the
// exchange is refused and OpenBAO is never reached.
func TestTheBundleDoesNotVouchForTheIssuer(t *testing.T) {
	root := newPrivateRoot(t)
	bao := unstartedFakeOpenBAO(t)
	bao.URL = root.serve(t, http.HandlerFunc(bao.serve))
	issuer := root.serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	signedInHome(t)

	err := credential([]string{"ssh", "--env", "staging", "--identity", "id_example",
		"--issuer", issuer, "--address", bao.URL, "--ca-cert", root.bundle})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("an issuer under the private root = %v, want its certificate refused", err)
	}
	if len(bao.calls) != 0 {
		t.Errorf("OpenBAO was called after an exchange that should have failed: %v", bao.calls)
	}
}

// The bundle is the first of: the flag, BAO_CACERT, VAULT_CACERT. A
// variable the flag outranks is not read at all, so one pointing at
// something unreadable does not stop a command that named its own.
func TestCACertPrecedence(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")
	t.Setenv(envVaultAddress, "")
	t.Setenv(envOpenBAONamespace, "")
	t.Setenv(envVaultNamespace, "")

	fromFlag, fromBAO, fromVault := newPrivateRoot(t).bundle, newPrivateRoot(t).bundle, newPrivateRoot(t).bundle
	missing := filepath.Join(t.TempDir(), "absent.pem")

	for name, tc := range map[string]struct {
		bao, vault string
		args       []string
		want       string
	}{
		"nothing":                 {want: ""},
		"VAULT_CACERT alone":      {vault: fromVault, want: fromVault},
		"BAO_CACERT over VAULT":   {bao: fromBAO, vault: fromVault, want: fromBAO},
		"the flag over both":      {bao: fromBAO, vault: fromVault, args: []string{"--ca-cert", fromFlag}, want: fromFlag},
		"the flag over a missing": {bao: missing, vault: missing, args: []string{"--ca-cert", fromFlag}, want: fromFlag},
	} {
		t.Setenv(envOpenBAOCACert, tc.bao)
		t.Setenv(envVaultCACert, tc.vault)
		got, err := parseCredentialFlags(append([]string{"ssh", "--env", "staging"}, tc.args...))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.caCert != tc.want {
			t.Errorf("%s: bundle %q, want %q", name, got.caCert, tc.want)
		}
		if (got.roots == nil) != (tc.want == "") {
			t.Errorf("%s: roots %v, want them read exactly when a bundle is named", name, got.roots)
		}
	}
}

// The bundle is added to the system's roots, never put in their place:
// an installation whose certificate a public CA signs keeps verifying
// with a bundle named for another.
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

// A bundle that cannot be read, or holds no certificate, is a mistake in
// what was typed — refused before anything is exchanged, and named, so
// the flag never silently trusts nothing extra.
func TestABundleThatTrustsNothingIsAUsageError(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")
	t.Setenv(envOpenBAOCACert, "")
	t.Setenv(envVaultCACert, "")

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	keyOnly := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyOnly, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		path, says string
	}{
		"a file that is not there": {path: filepath.Join(dir, "absent.pem"), says: "read the OpenBAO CA bundle"},
		"a directory":              {path: dir, says: "read the OpenBAO CA bundle"},
		"an empty file":            {path: empty, says: "holds no PEM certificate"},
		"a key, not a certificate": {path: keyOnly, says: "holds no PEM certificate"},
	} {
		_, err := parseCredentialFlags([]string{"ssh", "--env", "staging", "--ca-cert", tc.path})
		if codeFor(err) != exitUsage || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v, want a usage error saying %q", name, err, tc.says)
		}
	}

	// And from the variable the same way, since that is where a stale
	// path most often lives.
	t.Setenv(envOpenBAOCACert, empty)
	if _, err := parseCredentialFlags([]string{"ssh", "--env", "staging"}); codeFor(err) != exitUsage {
		t.Errorf("an empty bundle from %s: %v, want a usage error", envOpenBAOCACert, err)
	}
}

// privateRoot is a CA no system trusts, with its certificate written as
// a bundle a caller can name.
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
