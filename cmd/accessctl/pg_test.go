package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeClientScript is what stands in for `psql`, or any command
// `accessctl pg` is asked to run: it proves what it received by printing
// its own arguments and the libpq variables this file sets, and exits
// with FAKE_EXIT (0 by default).
const fakeClientScript = `#!/bin/sh
echo "ARGS $*"
echo "PGSSLCERT=$PGSSLCERT"
echo "PGSSLKEY=$PGSSLKEY"
echo "PGSSLROOTCERT=$PGSSLROOTCERT"
echo "PGSSLMODE=$PGSSLMODE"
echo "PGUSER=$PGUSER"
exit "${FAKE_EXIT:-0}"
`

// newFakeClient writes fakeClientScript on PATH under the given name --
// "psql" for the psql tests, anything else for pg's own "any command"
// promise.
func newFakeClient(t *testing.T, name string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(fakeClientScript), 0o700); err != nil { //nolint:gosec // a test fixture
		t.Fatalf("write the fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// The whole sentence: sign-in exchanged for openbao, logged in to the
// PKI's own namespace, ONE sign call made for a CSR generated locally,
// and psql run with libpq's own variables pointed at the result --
// PGUSER the certificate's OWN common name, read back from what was
// issued rather than from what was asked for.
func TestPsqlMintsACertificateAndRunsPsql(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	home := signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging",
			"--", "-h", "db.example", "-d", "orders"})
	})

	if !slices.Contains(bao.calls, "auth/jwt-roster/login") || !slices.Contains(bao.calls, "pki/sign/db-client") {
		t.Fatalf("called %v, want a login and one signing", bao.calls)
	}
	if bao.namespaces["auth/jwt-roster/login"] != "staging" || bao.namespaces["pki/sign/db-client"] != "staging" {
		t.Errorf("namespaces = %v, want both in the PKI's own namespace", bao.namespaces)
	}
	if _, sent := bao.bodies["pki/sign/db-client"]["ttl"]; sent {
		t.Error("the request carries a ttl, which is the role's to decide")
	}

	base := credentialBase(t, bao.URL, "staging", "db-client")
	signedLocally(t, bao, "pki/sign/db-client", base)

	if !strings.Contains(written, "ARGS -h db.example -d orders") {
		t.Errorf("stdout = %q, want psql's own arguments passed through unchanged", written)
	}
	if !strings.Contains(written, "PGSSLCERT="+base+".crt") || !strings.Contains(written, "PGSSLKEY="+base+".key") ||
		!strings.Contains(written, "PGSSLROOTCERT="+base+"-ca.crt") {
		t.Errorf("stdout = %q, want the certificate's own files named", written)
	}
	if !strings.Contains(written, "PGSSLMODE=verify-full") {
		t.Errorf("stdout = %q, want sslmode=verify-full", written)
	}
	if !strings.Contains(written, "PGUSER="+theSubject) {
		t.Errorf("stdout = %q, want PGUSER set to the certificate's own common name", written)
	}

	// Nothing that could mint a second credential is left behind: not the
	// exchanged token, not OpenBAO's own.
	noSecretsOnDisk(t, home, "for-openbao", "the-bao-token")
}

// --login-ns lets `pg`/`psql` log in at a PARENT namespace while the
// certificate is still SIGNED in the target namespace (-ns) -- the token
// minted at the parent is valid there and in its children, and the sign
// call is what actually reaches the PKI mount.
func TestPsqlSignsInTargetNamespaceWithAParentLoginToken(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	if _, err := captureStdoutErr(t, func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "devel/team",
			"--login-ns", "devel", "--", "-c", "select 1"})
	}); err != nil {
		t.Fatal(err)
	}

	if bao.namespaces["auth/jwt-roster/login"] != "devel" {
		t.Errorf("logged in to %q, want the parent devel", bao.namespaces["auth/jwt-roster/login"])
	}
	if bao.namespaces["pki/sign/db-client"] != "devel/team" {
		t.Errorf("signed in %q, want the TARGET namespace devel/team, unaffected by --login-ns", bao.namespaces["pki/sign/db-client"])
	}
	if bao.tokens["pki/sign/db-client"] != "the-bao-token" {
		t.Errorf("the sign call presented token %q, want the one minted at the parent login", bao.tokens["pki/sign/db-client"])
	}
}

// The login is cached by the LOGIN namespace and shared with a sibling
// target under the same parent; the certificate itself is still cached
// by -ns (the TARGET), so two children mint two certificates from one
// shared login.
func TestPgLoginNsSharesTheLoginCacheButSignsPerTarget(t *testing.T) {
	newFakeClient(t, "backup-tool")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	bao.leaseSeconds = 900
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	for _, target := range []string{"devel/a", "devel/b"} {
		target := target
		if _, err := captureStdoutErr(t, func() error {
			return run([]string{"pg", "--issuer", issuer, "--address", bao.URL, "-ns", target,
				"--login-ns", "devel", "--", "backup-tool"})
		}); err != nil {
			t.Fatal(err)
		}
	}

	if got := count(bao.calls, "auth/jwt-roster/login"); got != 1 {
		t.Errorf("logged in %d times for two children of the same parent login, want exactly one", got)
	}
	if got := count(bao.calls, "pki/sign/db-client"); got != 2 {
		t.Errorf("signed %d times, want one PER TARGET namespace: the certificate cache is keyed by -ns, not by the login", got)
	}
}

// A target namespace that --login-ns does not cover is refused before
// any exchange -- the same refusal `accessctl bao` gives, shared through
// checkNamespaceLogin.
func TestPgLoginNsRefusesANonDescendantTarget(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")

	err := pg([]string{"-ns", "devel", "--login-ns", "dev", "--", "psql"})
	if codeFor(err) != exitUsage {
		t.Fatalf("err = %v, want a usage error before any exchange (dev is not a path-parent of devel)", err)
	}
	if !strings.Contains(err.Error(), "dev") || !strings.Contains(err.Error(), "devel") {
		t.Errorf("err = %v, want it to name both namespaces", err)
	}
}

// `pg -- <command>` runs anything, not only psql, with the same
// environment.
func TestPgRunsAnArbitraryCommand(t *testing.T) {
	newFakeClient(t, "backup-tool")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"pg", "--issuer", issuer, "--address", bao.URL, "-ns", "staging",
			"--", "backup-tool", "--full"})
	})
	if !strings.Contains(written, "ARGS --full") {
		t.Errorf("stdout = %q, want the command's own arguments", written)
	}
}

// A certificate with enough life left is reused rather than re-minted --
// one login, one sign call for two runs -- both through the SAME cache
// `accessctl bao` uses for its own login (openBAOLogin, bao.go).
func TestPsqlCertificateIsReused(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	bao.leaseSeconds = 900
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	run2 := func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging", "--", "-c", "select 1"})
	}
	if _, err := captureStdoutErr(t, run2); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdoutErr(t, run2); err != nil {
		t.Fatal(err)
	}

	logins, signs := count(bao.calls, "auth/jwt-roster/login"), count(bao.calls, "pki/sign/db-client")
	if logins != 1 || signs != 1 {
		t.Errorf("logins=%d signs=%d over two runs, want exactly one of each: the certificate should be reused", logins, signs)
	}
}

// A certificate already on disk with too little life left for
// certReuseMargin is replaced rather than handed to the command: seeded
// directly, rather than by waiting out an hour-long fake certificate, so
// this needs no fake clock.
func TestPsqlReMintsANearExpiryCertificate(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	base := credentialBase(t, bao.URL, "staging", "db-client")
	seedNearExpiryLeaf(t, base, theSubject)

	if _, err := captureStdoutErr(t, func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging"})
	}); err != nil {
		t.Fatal(err)
	}
	if got := count(bao.calls, "pki/sign/db-client"); got != 1 {
		t.Errorf("signs = %d, want exactly one re-mint of the near-expiry certificate", got)
	}
}

// seedNearExpiryLeaf writes a self-signed, otherwise-valid certificate
// and key pair at base whose remaining life is under certReuseMargin --
// what a certificate this command minted a while ago looks like on disk
// once it is close to needing a re-mint.
func seedNearExpiryLeaf(t *testing.T, base, commonName string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(base), err)
	}
	private, err := ecdsa.GenerateKey(leafCurve, rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certReuseMargin / 2),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatalf("create the stale certificate: %v", err)
	}
	key, err := encodeKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	if err = writeLeaf(base, leaf{Certificate: certPEM, Key: key, Authority: certPEM}); err != nil {
		t.Fatalf("seed the stale certificate: %v", err)
	}
}

// A caller's own PGUSER is never second-guessed: it (or a service file's
// `user=`, which already outranks it) names who they mean to connect as.
func TestPsqlDoesNotOverrideAnExistingPGUser(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)
	t.Setenv("PGUSER", "already-chosen")

	written := captureStdout(t, func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging"})
	})
	if !strings.Contains(written, "PGUSER=already-chosen") {
		t.Errorf("stdout = %q, want the caller's own PGUSER kept", written)
	}
}

// PGSSLROOTCERT and PGSSLMODE are set only when the caller has not
// already chosen one: the PKI's own CA is not necessarily the CA that
// signed the database SERVER's certificate, so this must not shadow a
// root or a mode the caller already named.
func TestPsqlDoesNotOverrideAnExistingRootCertOrMode(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)
	t.Setenv("PGSSLROOTCERT", "/etc/ssl/server-ca.pem")
	t.Setenv("PGSSLMODE", "require")

	written := captureStdout(t, func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging"})
	})
	if !strings.Contains(written, "PGSSLROOTCERT=/etc/ssl/server-ca.pem") {
		t.Errorf("stdout = %q, want the caller's own PGSSLROOTCERT kept", written)
	}
	if !strings.Contains(written, "PGSSLMODE=require") {
		t.Errorf("stdout = %q, want the caller's own PGSSLMODE kept", written)
	}
	// PGSSLCERT and PGSSLKEY are always accessctl's own: there is no
	// caller value for them that would make sense to keep instead.
	if !strings.Contains(written, "PGSSLCERT="+credentialBase(t, bao.URL, "staging", "db-client")+".crt") {
		t.Errorf("stdout = %q, want PGSSLCERT set regardless", written)
	}
}

// A role that returns no chain and no issuing certificate leaves no
// `-ca.crt` file behind, and PGSSLROOTCERT must then be left unset
// entirely rather than pointed at a file that does not exist.
func TestPsqlSkipsRootCertWhenNoCAWasReturned(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	bao.noIssuingCA = true
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging"})
	})
	if !strings.Contains(written, "PGSSLROOTCERT=\n") {
		t.Errorf("stdout = %q, want PGSSLROOTCERT left unset (no CA was returned)", written)
	}

	base := credentialBase(t, bao.URL, "staging", "db-client")
	if _, err := os.Stat(base + "-ca.crt"); !os.IsNotExist(err) {
		t.Errorf("a CA file was written even though the role returned none: %v", err)
	}
}

// A cached certificate is reused only for the SAME common name it was
// minted for. Without this, `--common-name other` -- or simply signing
// in as someone else against the same -ns/-role -- would silently reuse
// the previous identity's certificate, since the cache is keyed by path
// (namespace and role) and not by who it was minted for.
func TestPsqlDoesNotReuseAnotherIdentitysCertificate(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	run1 := func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging"})
	}
	if _, err := captureStdoutErr(t, run1); err != nil {
		t.Fatal(err)
	}
	if got := count(bao.calls, "pki/sign/db-client"); got != 1 {
		t.Fatalf("signs = %d after the first mint, want 1", got)
	}

	run2 := func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging",
			"--common-name", "someone-else"})
	}
	if _, err := captureStdoutErr(t, run2); err != nil {
		t.Fatal(err)
	}
	if got := count(bao.calls, "pki/sign/db-client"); got != 2 {
		t.Errorf("signs = %d after a different --common-name, want a fresh mint (2): "+
			"the previous identity's certificate must not be reused", got)
	}
	if bao.bodies["pki/sign/db-client"]["common_name"] != "someone-else" {
		t.Errorf("common_name = %v, want the new identity", bao.bodies["pki/sign/db-client"]["common_name"])
	}
}

// Two OpenBAO installations never share a cached certificate, even at
// the same namespace and role: the address is part of the cache path.
func TestPsqlDoesNotShareTheCacheAcrossAddresses(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	baoA := newFakeOpenBAO(t)
	baoB := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	for _, address := range []string{baoA.URL, baoB.URL} {
		address := address
		if _, err := captureStdoutErr(t, func() error {
			return run([]string{"psql", "--issuer", issuer, "--address", address, "-ns", "staging"})
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := count(baoA.calls, "pki/sign/db-client"); got != 1 {
		t.Errorf("installation A signed %d times, want 1", got)
	}
	if got := count(baoB.calls, "pki/sign/db-client"); got != 1 {
		t.Errorf("installation B signed %d times, want 1", got)
	}
}

// `--common-name` overrides the signed-in identity, and the role can
// still refuse a name it does not sign for -- read the same way
// `accessctl credential` used to.
func TestPsqlCommonNameOverride(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	_ = captureStdout(t, func() error {
		return run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging", "--common-name", "svc-orders"})
	})
	if bao.bodies["pki/sign/db-client"]["common_name"] != "svc-orders" {
		t.Errorf("common_name = %v, want the override", bao.bodies["pki/sign/db-client"]["common_name"])
	}
}

// A certificate for a key other than the one asked about is refused
// rather than handed to the command: the pair would fail only once a
// server was asked to accept it.
func TestPsqlRefusesAMismatchedCertificate(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	bao.swapKey = true
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	err := run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging"})
	if err == nil || !strings.Contains(err.Error(), "other than the one it was asked to sign") {
		t.Fatalf("a mismatched certificate = %v, want it refused", err)
	}
	base := credentialBase(t, bao.URL, "staging", "db-client")
	if _, statErr := os.Stat(base + ".key"); !os.IsNotExist(statErr) {
		t.Errorf("a key was written for a certificate that does not match it: %v", statErr)
	}
}

// A refusal by OpenBAO is final, and a missing role says so in words.
func TestPsqlRefusalIsFinalAndAMissingRoleSaysSo(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	bao.refuse = map[string]int{"pki/sign/db-client": 403}
	err := run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging"})
	if !errors.Is(err, errNotGranted) || codeFor(err) != exitNotGranted {
		t.Errorf("a refusal = %v (exit %d), want not granted", err, codeFor(err))
	}

	bao.refuse = map[string]int{"pki/sign/db-client": 404}
	err = run([]string{"psql", "--issuer", issuer, "--address", bao.URL, "-ns", "staging"})
	if err == nil || !strings.Contains(err.Error(), "pki/sign/db-client") || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("a missing role = %v, want it named", err)
	}
}

// A laptop with no sign-in is told to sign in, and nothing is asked of
// OpenBAO: the exchange is the first refusal, not the last.
func TestPsqlNeedsASignInFirst(t *testing.T) {
	newFakeClient(t, "psql")
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv(envGitHubTokenURL, "")
	t.Setenv(envGitHubTokenGrant, "")

	err := run([]string{"psql", "--issuer", "https://issuer.invalid", "--address", bao.URL, "-ns", "staging"})
	if !errors.Is(err, errNotSignedIn) {
		t.Errorf("err = %v, want the sign-in to be what is missing", err)
	}
	if len(bao.calls) != 0 {
		t.Errorf("OpenBAO was called anyway: %v", bao.calls)
	}
}

// `pg` with nothing to run is a usage error before anything is
// exchanged.
func TestPgWithNoCommandIsAUsageError(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")
	if err := pg([]string{}); codeFor(err) != exitUsage {
		t.Errorf("err = %v, want a usage error", err)
	}
}

// `accessctl credential`, `ssh`, `db` and `client` are removed, each
// pointing at its own replacement; anything else, or no kind at all,
// names all three.
func TestCredentialIsRemoved(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		says []string
	}{
		"ssh":      {[]string{"credential", "ssh"}, []string{"v1.34.0", "accessctl bao ssh -mode=ca"}},
		"db":       {[]string{"credential", "db"}, []string{"v1.34.0", "accessctl psql", "accessctl pg --"}},
		"client":   {[]string{"credential", "client"}, []string{"v1.34.0", "accessctl bao write"}},
		"no kind":  {[]string{"credential"}, []string{"v1.34.0", "accessctl bao ssh", "accessctl psql", "accessctl bao write"}},
		"bad kind": {[]string{"credential", "vpn"}, []string{"v1.34.0", "accessctl bao ssh", "accessctl psql"}},
	} {
		err := run(tc.args)
		if err == nil {
			t.Errorf("%s: no error, want the removal refused", name)
			continue
		}
		if codeFor(err) == exitOK {
			t.Errorf("%s: exit 0, want a non-zero exit", name)
		}
		for _, says := range tc.says {
			if !strings.Contains(err.Error(), says) {
				t.Errorf("%s: %v, want it to say %q", name, err, says)
			}
		}
	}
}

// count is how many of calls equal target -- bao.calls is a slice, not a
// set, since a test cares how MANY times something was called, not only
// whether it was.
func count(calls []string, target string) int {
	n := 0
	for _, call := range calls {
		if call == target {
			n++
		}
	}
	return n
}

// captureStdoutErr is captureStdout for a caller that wants the error
// rather than a t.Fatalf on one -- this file's reuse tests run the
// command more than once and need to tell which run failed.
func captureStdoutErr(t *testing.T, run func() error) (string, error) {
	t.Helper()

	out, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatalf("create stdout: %v", err)
	}
	saved := stdout
	stdout = out
	defer func() { stdout = saved }()

	runErr := run()
	written, _ := os.ReadFile(out.Name())
	return string(written), runErr
}

// credentialBase is the base path pg.go's own credentialDir(address, ns,
// role) gives a certificate at "client" -- what a test needs to find a
// certificate on disk without re-deriving the address hash by hand.
func credentialBase(t *testing.T, address, ns, role string) string {
	t.Helper()

	dir, err := credentialDir(address, ns, role)
	if err != nil {
		t.Fatalf("credentialDir: %v", err)
	}
	return filepath.Join(dir, "client")
}
