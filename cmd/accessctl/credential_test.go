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
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The subject the whole chain is about: the issuer exchanged for it, the
// role writes it into the certificate, and the server logs it.
const theSubject = "ada@north.example"

// The flags become exactly the request, and the defaults are the layout
// the roles are rendered into: one namespace per environment, named for
// it, for every kind — and a project's own namespace for a database only
// when --project asks for it.
func TestCredentialFlagsAreReadAsTheRequest(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")
	t.Setenv(envVaultAddress, "")
	t.Setenv(envOpenBAONamespace, "")
	t.Setenv(envVaultNamespace, "")

	for name, tc := range map[string]struct {
		args      []string
		namespace string
		path      string
		check     func(credentialRequest) error
	}{
		"ssh, as short as it gets": {
			args:      []string{"ssh", "--env", "staging"},
			namespace: "staging",
			path:      "ssh/sign/user",
			check: func(got credentialRequest) error {
				if got.mount != rosterMount || got.loginRole != rosterLoginRole || got.audience != openbaoAudience {
					return errors.New("the login defaults were not the roster's")
				}
				return nil
			},
		},
		"ssh, the privileged role asked for by name": {
			args:      []string{"ssh", "--env", "staging", "--role", "admin", "--principal", "deploy", "--principal", "ops"},
			namespace: "staging",
			path:      "ssh/sign/admin",
			check: func(got credentialRequest) error {
				if !slices.Equal(got.principals, []string{"deploy", "ops"}) {
					return errors.New("the principals were not kept in order")
				}
				return nil
			},
		},
		"a database, in the environment's namespace": {
			args:      []string{"db", "--env", "staging", "--host", "db.example", "--dbname", "orders"},
			namespace: "staging",
			path:      "pki/sign/db-client",
			check: func(got credentialRequest) error {
				if got.service != "staging" || got.port != "5432" {
					return errors.New("the service entry did not default to the environment on 5432")
				}
				return nil
			},
		},
		"a database, in a project's own namespace": {
			args: []string{"db", "--env", "staging", "--project", "example",
				"--host", "db.example", "--dbname", "orders"},
			namespace: "example/staging",
			path:      "pki/sign/db-client",
			check:     func(credentialRequest) error { return nil },
		},
		"a machine certificate": {
			args:      []string{"client", "--env", "staging", "--out", "/tmp/example.crt"},
			namespace: "staging",
			path:      "pki/sign/client",
			check:     func(credentialRequest) error { return nil },
		},
		"a second installation naming everything itself": {
			args: []string{"ssh", "--env", "staging", "--namespace", "elsewhere",
				"--mount", "jwt-people", "--login-role", "people", "--audience", "bao"},
			namespace: "elsewhere",
			path:      "ssh/sign/user",
			check: func(got credentialRequest) error {
				if got.mount != "jwt-people" || got.loginRole != "people" || got.audience != "bao" {
					return errors.New("the overrides were not taken")
				}
				return nil
			},
		},
	} {
		got, err := parseCredentialFlags(tc.args)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.namespace != tc.namespace || got.path() != tc.path {
			t.Errorf("%s: namespace %q, path %q", name, got.namespace, got.path())
		}
		if err = tc.check(got); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A mistake in the command line is a usage error, before anything is
// exchanged. The flags are declared per kind, so a flag that belongs to
// another kind is refused rather than quietly ignored — which is how
// somebody comes to believe they narrowed a credential they did not.
func TestACredentialNobodyCouldMintIsAUsageError(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")
	t.Setenv(envVaultAddress, "")
	t.Setenv(envOpenBAONamespace, "")
	t.Setenv(envVaultNamespace, "")

	for name, args := range map[string][]string{
		"no kind at all":                   {},
		"a flag where the kind goes":       {"--env", "staging"},
		"a kind that is not one":           {"vpn", "--env", "staging"},
		"no environment":                   {"ssh"},
		"a database going nowhere":         {"db", "--env", "staging", "--project", "example", "--dbname", "orders"},
		"a database with no database":      {"db", "--env", "staging", "--project", "example", "--host", "db.example"},
		"a client certificate with no out": {"client", "--env", "staging"},
		"a principal on a database":        {"db", "--env", "staging", "--project", "example", "--principal", "deploy"},
		"an out on an ssh certificate":     {"ssh", "--env", "staging", "--out", "/tmp/x"},
		"an argument that is not a flag":   {"ssh", "--env", "staging", "staging"},
		"an audience of nothing":           {"ssh", "--env", "staging", "--audience", " "},
	} {
		if _, err := parseCredentialFlags(args); codeFor(err) != exitUsage {
			t.Errorf("%s: %v, want a usage error", name, err)
		}
	}

	// And with no address there is nothing to call, which is the same
	// kind of mistake — and the message is the fix: the flag and the
	// variable, each with the shape of a value.
	t.Setenv(envOpenBAOAddress, "")
	_, err := parseCredentialFlags([]string{"ssh", "--env", "staging"})
	if codeFor(err) != exitUsage {
		t.Errorf("no address: %v, want a usage error", err)
	}
	for _, says := range []string{"--address https://", "export " + envOpenBAOAddress + "=https://", envVaultAddress} {
		if err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("no address: %v, want it to say %q", err, says)
		}
	}
}

// The namespace is the first of: the flag, BAO_NAMESPACE, VAULT_NAMESPACE,
// and the environment itself. A shell already pointed at an installation
// keeps working, and a flag still wins over the shell.
func TestCredentialNamespacePrecedence(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")
	t.Setenv(envVaultAddress, "")

	for name, tc := range []struct {
		bao, vault string
		args       []string
		want       string
	}{
		{args: []string{"ssh", "--env", "staging"}, want: "staging"},
		{vault: "from-vault", args: []string{"ssh", "--env", "staging"}, want: "from-vault"},
		{bao: "from-bao", vault: "from-vault", args: []string{"ssh", "--env", "staging"}, want: "from-bao"},
		{bao: "from-bao", args: []string{"ssh", "--env", "staging", "--namespace", "from-flag"}, want: "from-flag"},
		{bao: "from-bao", args: []string{"db", "--env", "staging", "--project", "example",
			"--host", "db.example", "--dbname", "orders"}, want: "from-bao"},
	} {
		t.Setenv(envOpenBAONamespace, tc.bao)
		t.Setenv(envVaultNamespace, tc.vault)
		got, err := parseCredentialFlags(tc.args)
		if err != nil {
			t.Errorf("case %d: %v", name, err)
			continue
		}
		if got.namespace != tc.want {
			t.Errorf("case %d: namespace %q, want %q", name, got.namespace, tc.want)
		}
	}
}

// `--help` on ssh is where somebody deciding whether they need the
// privileged role looks, so it says what each of the two is for, and
// which one is the default.
func TestSSHHelpSaysWhatEachRoleIsFor(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")

	// The flag package prints help to os.Stderr, read when it prints.
	out, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = out
	_, err = parseCredentialFlags([]string{"ssh", "--help"})
	os.Stderr = saved
	if codeFor(err) != exitUsage || !strings.Contains(err.Error(), flag.ErrHelp.Error()) {
		t.Errorf("--help: %v, want the help printed and a usage exit", err)
	}

	help, _ := os.ReadFile(out.Name())
	for _, says := range []string{
		"'user' for everyday logins", "'admin' for administering the host", `(default "user")`,
		envOpenBAOAddress, "--env value itself",
	} {
		if !strings.Contains(string(help), says) {
			t.Errorf("--help is\n%s\nwant it to say %q", help, says)
		}
	}
}

// The whole sentence, once: the sign-in is exchanged for `openbao`, the
// exchanged token logs in on the JWT mount in the environment's
// namespace, ONE sign call is made, and the certificate lands in the
// agent. The signing request carries the public key and the principals
// and NO ttl — the role decides how long this lives.
func TestSSHCertificateIsSignedAndAddedToTheAgent(t *testing.T) {
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	home := signedInHome(t)
	socket := runAgent(t)

	written := captureStdout(t, func() error {
		return credential([]string{"ssh", "--env", "staging", "--principal", "deploy",
			"--issuer", issuer, "--address", bao.URL})
	})

	if got := bao.calls; !slices.Equal(got, []string{"auth/jwt-roster/login", "ssh/sign/user", "auth/token/revoke-self"}) {
		t.Fatalf("called %v, want a login, one signing and a revoke", got)
	}
	if bao.namespaces["ssh/sign/user"] != "staging" {
		t.Errorf("signed in namespace %q", bao.namespaces["ssh/sign/user"])
	}
	if bao.bodies["auth/jwt-roster/login"]["jwt"] != "for-openbao" ||
		bao.bodies["auth/jwt-roster/login"]["role"] != rosterLoginRole {
		t.Errorf("logged in with %v, want the exchanged token as the roster role", bao.bodies["auth/jwt-roster/login"])
	}
	if bao.tokens["ssh/sign/user"] != "the-bao-token" || bao.tokens["auth/token/revoke-self"] != "the-bao-token" {
		t.Errorf("the login's token was not what signed: %v", bao.tokens)
	}

	signing := bao.bodies["ssh/sign/user"]
	if !strings.HasPrefix(signing["public_key"].(string), "ssh-ed25519 ") {
		t.Errorf("asked to sign %v, want a public key", signing["public_key"])
	}
	if signing["valid_principals"] != "deploy" {
		t.Errorf("asked for principals %v, want the one requested", signing["valid_principals"])
	}
	for _, chosen := range []string{"ttl", "valid_before", "key_id", "extensions", "cert_type"} {
		if _, sent := signing[chosen]; sent {
			t.Errorf("the request carries %q, which is the role's to decide: %v", chosen, signing)
		}
	}

	// What is printed is what somebody searching for this credential in
	// an audit trail has to type, and nothing else: no key, no token.
	if !strings.Contains(written, theSubject) {
		t.Errorf("stdout = %q, want the key_id so it can be found in audit", written)
	}
	if strings.Contains(written, "PRIVATE KEY") || strings.Contains(written, "the-bao-token") {
		t.Errorf("stdout carried a secret: %q", written)
	}

	keys, err := agent.NewClient(dial(t, socket)).List()
	if err != nil {
		t.Fatalf("list the agent: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("the agent holds %d keys, want the one certificate", len(keys))
	}
	held, err := parseCertificate(keys[0].String())
	if err != nil {
		t.Fatalf("the agent holds something that is not a certificate: %v", err)
	}
	if held.KeyId != theSubject || !slices.Equal(held.ValidPrincipals, []string{"deploy"}) {
		t.Errorf("the agent holds %q for %v", held.KeyId, held.ValidPrincipals)
	}

	// Nothing that could mint a second credential is left behind: not the
	// exchanged token, not OpenBAO's.
	noSecretsOnDisk(t, home, "for-openbao", "the-bao-token")
}

// The other delivery: the key in `~/.ssh` with the certificate beside it,
// named the way OpenSSH looks for it, so `ssh -i` picks up both.
//
// The revoke is refused here on purpose. A batch token — what a mount
// that writes nothing per login hands out — cannot be revoked and says
// so, and that must not fail a credential that was delivered.
func TestSSHCertificateCanBeWrittenBesideTheKey(t *testing.T) {
	bao := newFakeOpenBAO(t)
	bao.revokeStatus = http.StatusBadRequest
	issuer := newFakeIssuer(t)
	home := signedInHome(t)

	written := captureStdout(t, func() error {
		return credential([]string{"ssh", "--env", "staging", "--identity", "id_example",
			"--issuer", issuer, "--address", bao.URL})
	})

	key := filepath.Join(home, ".ssh", "id_example")
	for path, mode := range map[string]fs.FileMode{
		key:               0o600,
		key + ".pub":      0o644,
		key + "-cert.pub": 0o644,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s is %v, want %v", path, info.Mode().Perm(), mode)
		}
	}
	if !strings.Contains(written, key) {
		t.Errorf("stdout = %q, want it to say where the files are", written)
	}

	private, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("read the key: %v", err)
	}
	if _, err = ssh.ParsePrivateKey(private); err != nil {
		t.Errorf("the key is not one OpenSSH can read: %v", err)
	}
	certificate, err := os.ReadFile(key + "-cert.pub")
	if err != nil {
		t.Fatalf("read the certificate: %v", err)
	}
	held, err := parseCertificate(string(certificate))
	if err != nil {
		t.Fatalf("beside the key is not a certificate: %v", err)
	}
	if held.KeyId != theSubject {
		t.Errorf("key_id = %q", held.KeyId)
	}

	// Minting again replaces what this tool wrote before.
	if _, err = os.Stat(key); err != nil {
		t.Fatal(err)
	}
	_ = captureStdout(t, func() error {
		return credential([]string{"ssh", "--env", "staging", "--identity", "id_example",
			"--issuer", issuer, "--address", bao.URL})
	})

	// Somebody else's key is never replaced: `--identity id_ed25519` is
	// one keystroke away from the key a person has used for years.
	theirs := filepath.Join(home, ".ssh", "id_ed25519")
	if err = os.WriteFile(theirs, []byte("their own key"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = credential([]string{"ssh", "--env", "staging", "--identity", "id_ed25519",
		"--issuer", issuer, "--address", bao.URL})
	if err == nil {
		t.Fatal("a key this tool did not write was overwritten")
	}
	if body, _ := os.ReadFile(theirs); string(body) != "their own key" {
		t.Errorf("their key now holds %q", body)
	}
}

// A database credential is one `sign` call and a psql service entry that
// names the files it wrote. The database role is the certificate's common
// name — the server maps it through `pg_ident` — so the entry must not
// invent a user of its own.
func TestDatabaseCredentialBecomesAPsqlService(t *testing.T) {
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	home := signedInHome(t)

	_ = captureStdout(t, func() error {
		return credential([]string{"db", "--env", "staging",
			"--host", "db.example", "--dbname", "orders", "--service", "orders",
			"--issuer", issuer, "--address", bao.URL})
	})

	if !slices.Contains(bao.calls, "pki/sign/db-client") {
		t.Fatalf("called %v, want the database role", bao.calls)
	}
	if bao.namespaces["pki/sign/db-client"] != "staging" {
		t.Errorf("signed in namespace %q, want the environment's", bao.namespaces["pki/sign/db-client"])
	}
	if bao.bodies["pki/sign/db-client"]["common_name"] != theSubject {
		t.Errorf("asked for common name %v, want the roster subject", bao.bodies["pki/sign/db-client"]["common_name"])
	}
	if _, sent := bao.bodies["pki/sign/db-client"]["ttl"]; sent {
		t.Error("the request carries a ttl, which is the role's to decide")
	}
	signedLocally(t, bao, "pki/sign/db-client",
		filepath.Join(home, ".config", "accessctl", "credentials", "staging", "orders"))

	service, err := os.ReadFile(filepath.Join(home, ".pg_service.conf"))
	if err != nil {
		t.Fatalf("read the service file: %v", err)
	}
	for _, line := range []string{
		"[orders]", "host=db.example", "port=5432", "dbname=orders",
		"user=" + theSubject, "sslmode=verify-full", "sslcert=", "sslkey=", "sslrootcert=",
	} {
		if !strings.Contains(string(service), line) {
			t.Errorf("the entry has no %q:\n%s", line, service)
		}
	}

	base := filepath.Join(home, ".config", "accessctl", "credentials", "staging", "orders")
	for _, path := range []string{base + ".crt", base + ".key", base + "-ca.crt"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v, want 0600", path, info.Mode().Perm())
		}
	}

	// A credential for a second database leaves the first entry alone:
	// one block per service, not one block for this tool.
	_ = captureStdout(t, func() error {
		return credential([]string{"db", "--env", "staging", "--project", "example",
			"--host", "db.example", "--dbname", "invoices", "--service", "invoices",
			"--issuer", issuer, "--address", bao.URL})
	})
	service, err = os.ReadFile(filepath.Join(home, ".pg_service.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(service), "[orders]") || !strings.Contains(string(service), "[invoices]") {
		t.Errorf("one service replaced the other:\n%s", service)
	}

	noSecretsOnDisk(t, home, "for-openbao", "the-bao-token")
}

// A machine certificate goes where the caller said, and the URI SAN it
// asked for is passed through for the role to allow or refuse.
func TestClientCertificateIsWrittenWhereTheCallerAsked(t *testing.T) {
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	home := signedInHome(t)
	out := filepath.Join(home, "certs", "gateway.crt")

	written := captureStdout(t, func() error {
		return credential([]string{"client", "--env", "staging", "--out", out,
			"--uri-san", "spiffe://example/workload", "--issuer", issuer, "--address", bao.URL})
	})

	if bao.bodies["pki/sign/client"]["uri_sans"] != "spiffe://example/workload" {
		t.Errorf("asked for %v, want the URI SAN requested", bao.bodies["pki/sign/client"]["uri_sans"])
	}
	base := strings.TrimSuffix(out, ".crt")
	for _, path := range []string{base + ".crt", base + ".key", base + "-ca.crt"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if !strings.Contains(written, theSubject) {
		t.Errorf("stdout = %q, want the common name so it can be found in audit", written)
	}

	certificate, err := os.ReadFile(base + ".crt")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseLeaf(string(certificate))
	if err != nil {
		t.Fatalf("what was written is not a certificate: %v", err)
	}
	if parsed.Subject.CommonName != theSubject {
		t.Errorf("common name = %q", parsed.Subject.CommonName)
	}
	if len(parsed.URIs) != 1 || parsed.URIs[0].String() != "spiffe://example/workload" {
		t.Errorf("URI SANs = %v, want the one requested", parsed.URIs)
	}
	signedLocally(t, bao, "pki/sign/client", base)
}

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

// A certificate for a key other than the one asked about is refused
// rather than written beside it: the pair would fail only when a server
// is asked to accept it.
func TestACertificateForAnotherKeyIsNotWritten(t *testing.T) {
	bao := newFakeOpenBAO(t)
	bao.swapKey = true
	issuer := newFakeIssuer(t)
	home := signedInHome(t)
	out := filepath.Join(home, "certs", "gateway.crt")

	err := credential([]string{"client", "--env", "staging", "--out", out,
		"--issuer", issuer, "--address", bao.URL})
	if err == nil || !strings.Contains(err.Error(), "other than the one it was asked to sign") {
		t.Fatalf("a mismatched certificate = %v, want it refused", err)
	}
	if _, statErr := os.Stat(strings.TrimSuffix(out, ".crt") + ".key"); !os.IsNotExist(statErr) {
		t.Errorf("a key was written for a certificate that does not match it: %v", statErr)
	}
}

// A refusal by OpenBAO is final and exits as a refusal: the groups behind
// the token do not open that role, and running it again will not change
// that. A role that does not exist yet says so in words, because "404"
// on a path of this shape reads as nothing at all.
func TestARefusalIsFinalAndAMissingRoleSaysSo(t *testing.T) {
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t)

	bao.refuse = map[string]int{"ssh/sign/admin": http.StatusForbidden}
	err := credential([]string{"ssh", "--env", "staging", "--role", "admin",
		"--issuer", issuer, "--address", bao.URL})
	if !errors.Is(err, errNotGranted) || codeFor(err) != exitNotGranted {
		t.Errorf("a refusal = %v (exit %d), want not granted", err, codeFor(err))
	}

	bao.refuse = map[string]int{"ssh/sign/user": http.StatusNotFound}
	err = credential([]string{"ssh", "--env", "staging", "--issuer", issuer, "--address", bao.URL})
	if err == nil || !strings.Contains(err.Error(), "ssh/sign/user") || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("a missing role = %v, want it named", err)
	}
}

// A laptop with no sign-in is told to sign in, and nothing is asked of
// OpenBAO: the exchange is the first refusal, not the last.
func TestACredentialNeedsASignInFirst(t *testing.T) {
	bao := newFakeOpenBAO(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv(envGitHubTokenURL, "")
	t.Setenv(envGitHubTokenGrant, "")

	err := credential([]string{"ssh", "--env", "staging", "--issuer", "https://issuer.invalid", "--address", bao.URL})
	if !errors.Is(err, errNotSignedIn) {
		t.Errorf("err = %v, want the sign-in to be what is missing", err)
	}
	if len(bao.calls) != 0 {
		t.Errorf("OpenBAO was called anyway: %v", bao.calls)
	}
}

// signedInHome is a laptop with a cached sign-in and nothing else, and
// the home directory it keeps everything under.
func signedInHome(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("PGSERVICEFILE", "")
	t.Setenv(envGitHubTokenURL, "")
	t.Setenv(envGitHubTokenGrant, "")
	t.Setenv(envOpenBAONamespace, "")
	t.Setenv(envVaultNamespace, "")
	t.Setenv("SSH_AUTH_SOCK", "")

	if err := saveSession(Session{RefreshToken: "a-refresh", Email: theSubject}); err != nil {
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

	refuse       map[string]int
	revokeStatus int
	// swapKey signs a key of the fake's own instead of the CSR's.
	swapKey bool

	ca     ssh.Signer
	pkiKey ed25519.PrivateKey
	pki    *x509.Certificate
}

func newFakeOpenBAO(t *testing.T) *fakeOpenBAO {
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

	fake := &fakeOpenBAO{
		bodies:     map[string]map[string]any{},
		namespaces: map[string]string{},
		tokens:     map[string]string{},
		ca:         signer,
		pkiKey:     pkiKey,
		pki:        authority,
	}
	server := httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(server.Close)
	fake.URL = server.URL
	return fake
}

func (f *fakeOpenBAO) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	body := map[string]any{}
	_ = json.NewDecoder(r.Body).Decode(&body)

	f.calls = append(f.calls, path)
	f.bodies[path] = body
	f.namespaces[path] = r.Header.Get(namespaceHeader)
	f.tokens[path] = r.Header.Get("X-Vault-Token")

	if status, refused := f.refuse[path]; refused {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(path, "/login"):
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "the-bao-token"}})
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

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: request.Subject.CommonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
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

// runAgent starts an ssh-agent on a socket of its own and points
// SSH_AUTH_SOCK at it.
func runAgent(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatalf("make a socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket := filepath.Join(dir, "sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on %s: %v", socket, err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	keyring := agent.NewKeyring()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, connection) }()
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", socket)
	return socket
}

func dial(t *testing.T, socket string) net.Conn {
	t.Helper()

	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("reach the agent: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
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
