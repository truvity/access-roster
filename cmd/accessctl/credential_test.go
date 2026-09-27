package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The subject the whole chain is about: the issuer exchanged for it, the
// role writes it into the certificate, and the server logs it.
const theSubject = "ada@north.example"

// signedLocally is the PKI kinds' one promise: the key was made here and
// never sent. The request to `path` is a CSR for exactly the key written
// at `<base>.key` (0600, ECDSA P-384), the certificate at `<base>.crt` is
// for that key, no request carried a private key in any field, and the
// manager was never asked to generate one.
func signedLocally(t *testing.T, bao *fakeOpenBAO, path, base string) {
	t.Helper()

	for _, called := range bao.calls {
		if strings.HasPrefix(called, "pki/issue/") {
			t.Errorf("called %s: the manager was asked to make the key", called)
		}
	}
	for called, body := range bao.bodies {
		for field, value := range body {
			if field == "private_key" || strings.Contains(fmt.Sprint(value), "PRIVATE KEY") {
				t.Errorf("%s carried a private key in %q", called, field)
			}
		}
	}

	block, _ := pem.Decode([]byte(fmt.Sprint(bao.bodies[path]["csr"])))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("%s was sent no CSR: %v", path, bao.bodies[path])
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse the CSR: %v", err)
	}
	if request.Subject.CommonName != theSubject {
		t.Errorf("the CSR asks for %q, want the roster subject", request.Subject.CommonName)
	}

	info, err := os.Stat(base + ".key")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s.key is %v, want 0600", base, info.Mode().Perm())
	}
	raw, err := os.ReadFile(base + ".key")
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(raw)
	if keyBlock == nil {
		t.Fatalf("%s.key is not PEM", base)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("read the written key: %v", err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P384() {
		t.Fatalf("the written key is %T, want ECDSA on P-384", parsedKey)
	}
	if !key.PublicKey.Equal(request.PublicKey) {
		t.Error("the CSR is for a key other than the one written")
	}

	certificate, err := os.ReadFile(base + ".crt")
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := parseLeaf(string(certificate))
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(leafCert.PublicKey) {
		t.Error("the certificate is for a key other than the one written")
	}
}

// signedInHome is a laptop with a cached sign-in and nothing else, and
// the home directory it keeps everything under.
// signedInHome is a temporary HOME with a session already cached FOR
// THIS ISSUER. The issuer is an argument rather than a constant because
// a session now belongs to the installation it was minted at: one saved
// under a different issuer reads as "not signed in", which is the whole
// point of the split and would otherwise make every test here pass by
// accident on a shared file.
func signedInHome(t *testing.T, issuer string) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("PGSERVICEFILE", "")
	t.Setenv(envGitHubTokenURL, "")
	t.Setenv(envGitHubTokenGrant, "")
	t.Setenv(envOpenBAONamespace, "")
	t.Setenv(envVaultNamespace, "")
	t.Setenv(envOpenBAOCACert, "")
	t.Setenv(envVaultCACert, "")
	t.Setenv("SSH_AUTH_SOCK", "")

	if err := saveSession(issuer, Session{RefreshToken: "a-refresh", Email: theSubject}); err != nil {
		t.Fatalf("save the session: %v", err)
	}
	return home
}

// newFakeIssuer answers the refresh and the exchange, and nothing else.
func newFakeIssuer(t *testing.T) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") == "refresh_token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "the-sign-in", "refresh_token": "a-refresh"})
			return
		}
		if r.Form.Get("audience") != openbaoAudience {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_target"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "for-openbao", "expires_in": 900})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// fakeOpenBAO is an installation with the two engines and the JWT mount,
// which signs for real so that what this tool parses is what
// OpenBAO would have returned.
type fakeOpenBAO struct {
	URL string

	calls      []string
	bodies     map[string]map[string]any
	namespaces map[string]string
	tokens     map[string]string
	methods    map[string]string
	queries    map[string]string

	// kv is a KV version 2 engine: the full path under the mount, to the
	// fields at it. deleted is a path whose latest version was soft
	// deleted, which still lists and no longer reads.
	kv      map[string]map[string]any
	deleted map[string]bool

	refuse       map[string]int
	revokeStatus int
	// swapKey signs a key of the fake's own instead of the CSR's.
	swapKey bool
	// leaseSeconds, when set, is returned as the login's lease_duration
	// -- omitted by default, exactly as before this field existed, so
	// every test that does not set it keeps seeing a login with no
	// lease at all.
	leaseSeconds int
	// pkiLifetime, when set, is the issued certificate's NotAfter minus
	// NotBefore -- one hour by default, overridden by a test that needs
	// to force a re-mint by leaving too little of it for pg.go's own
	// certReuseMargin.
	pkiLifetime time.Duration

	ca     ssh.Signer
	pkiKey ed25519.PrivateKey
	pki    *x509.Certificate
}

func newFakeOpenBAO(t *testing.T) *fakeOpenBAO {
	t.Helper()

	fake := unstartedFakeOpenBAO(t)
	server := httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(server.Close)
	fake.URL = server.URL
	return fake
}

// unstartedFakeOpenBAO is the installation's state, for a test to serve
// however it needs to.
func unstartedFakeOpenBAO(t *testing.T) *fakeOpenBAO {
	t.Helper()

	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate the SSH CA: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		t.Fatalf("read back the SSH CA: %v", err)
	}

	pkiPublic, pkiKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate the PKI key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example issuing"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, pkiPublic, pkiKey)
	if err != nil {
		t.Fatalf("create the issuing CA: %v", err)
	}
	authority, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("read back the issuing CA: %v", err)
	}

	return &fakeOpenBAO{
		bodies:     map[string]map[string]any{},
		namespaces: map[string]string{},
		tokens:     map[string]string{},
		methods:    map[string]string{},
		queries:    map[string]string{},
		kv:         map[string]map[string]any{},
		deleted:    map[string]bool{},
		ca:         signer,
		pkiKey:     pkiKey,
		pki:        authority,
	}
}

func (f *fakeOpenBAO) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	body := map[string]any{}
	_ = json.NewDecoder(r.Body).Decode(&body)

	f.calls = append(f.calls, path)
	f.bodies[path] = body
	f.namespaces[path] = r.Header.Get(namespaceHeader)
	f.tokens[path] = r.Header.Get("X-Vault-Token")
	f.methods[path] = r.Method
	f.queries[path] = r.URL.RawQuery

	if status, refused := f.refuse[path]; refused {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(path, "/login"):
		auth := map[string]any{"client_token": "the-bao-token"}
		if f.leaseSeconds > 0 {
			auth["lease_duration"] = f.leaseSeconds
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": auth})
	case path == "auth/token/revoke-self":
		if f.revokeStatus != 0 {
			w.WriteHeader(f.revokeStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"batch tokens cannot be revoked"}})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(path, "ssh/sign/"):
		f.sign(w, body)
	case strings.HasPrefix(path, "pki/sign/"):
		f.signRequest(w, body)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// sign is the SSH secrets engine with a role whose `key_id_format` names
// the roster subject, which is the whole point of the arrangement.
func (f *fakeOpenBAO) sign(w http.ResponseWriter, body map[string]any) {
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body["public_key"].(string)))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	certificate := &ssh.Certificate{
		Key:         public,
		Serial:      7,
		CertType:    ssh.UserCert,
		KeyId:       theSubject,
		ValidAfter:  uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore: uint64(time.Now().Add(30 * time.Minute).Unix()),
	}
	if principals, ok := body["valid_principals"].(string); ok && principals != "" {
		certificate.ValidPrincipals = strings.Split(principals, ",")
	}
	if err = certificate.SignCert(rand.Reader, f.ca); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
		"signed_key":    string(ssh.MarshalAuthorizedKey(certificate)),
		"serial_number": "7",
	}})
}

// signRequest is the PKI engine's `sign`, with a role shaped the way a
// credential role is: key_type ec and key_bits 384, the common name read
// from the CSR (use_csr_common_name) and the SANs from the request
// (use_csr_sans off). A CSR that does not verify, or is for another kind
// of key, is refused as the role would refuse it.
func (f *fakeOpenBAO) signRequest(w http.ResponseWriter, body map[string]any) {
	refuse := func(why string) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{why}})
	}
	csr, _ := body["csr"].(string)
	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		refuse("no csr")
		return
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		refuse("the csr does not verify")
		return
	}
	public, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P384() {
		refuse("role requires key type ec with 384 bits")
		return
	}
	var signed any = public
	if f.swapKey {
		other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		signed = &other.PublicKey
	}

	lifetime := f.pkiLifetime
	if lifetime == 0 {
		lifetime = time.Hour
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: request.Subject.CommonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if uris, _ := body["uri_sans"].(string); uris != "" {
		for _, raw := range strings.Split(uris, ",") {
			parsed, err := url.Parse(raw)
			if err != nil {
				refuse("bad uri_sans")
				return
			}
			template.URIs = append(template.URIs, parsed)
		}
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, f.pki, signed, f.pkiKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
		"certificate":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})),
		"issuing_ca":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.pki.Raw})),
		"serial_number": template.SerialNumber.String(),
	}})
}

// noSecretsOnDisk is the rule this command exists to keep: whatever it
// wrote, none of it is a token that could mint another credential.
func noSecretsOnDisk(t *testing.T, home string, secrets ...string) {
	t.Helper()

	err := filepath.WalkDir(home, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := os.ReadFile(path) //nolint:gosec // a directory this test made
		if err != nil {
			return err
		}
		for _, secret := range secrets {
			if strings.Contains(string(body), secret) {
				t.Errorf("%s holds %q, which must never be written anywhere", path, secret)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", home, err)
	}
}
