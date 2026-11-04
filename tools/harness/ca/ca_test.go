package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readChain(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a path in the test's temporary directory
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return out
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

func TestTheLeafVerifiesForTheBoundaryHostUnderTheTestCA(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if _, err := Ensure(dir, []string{"sluis.dev.local.test"}, now); err != nil {
		t.Fatal(err)
	}
	ca := readChain(t, filepath.Join(dir, "ca.pem"))
	chain := readChain(t, filepath.Join(dir, "leaf.pem"))
	if len(ca) != 1 || len(chain) != 2 {
		t.Fatalf("%d CA certificates, a chain of %d", len(ca), len(chain))
	}
	if !strings.Contains(ca[0].Subject.CommonName, "TEST ONLY") {
		t.Fatalf("the CA is called %q", ca[0].Subject.CommonName)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca[0])
	opts := x509.VerifyOptions{Roots: pool, DNSName: "sluis.dev.local.test", CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := chain[0].Verify(opts); err != nil {
		t.Fatalf("the leaf does not verify: %v", err)
	}
	if chain[0].Subject.CommonName != "sluis.dev.local.test" {
		t.Fatal("the leaf is not for the host")
	}
	// P-384 all through (decision D-8).
	for _, c := range append(ca, chain...) {
		if pk, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P384() {
			t.Fatal("a key that is not an ECDSA P-384 key")
		}
	}
	// The leaf is for the host named, and not for another one under the same CA.
	opts.DNSName = "other.local.test"
	if _, err := chain[0].Verify(opts); err == nil {
		t.Fatal("the leaf verified for a host it was not made for")
	}
	// The leaf is a leaf: seven days, not a CA.
	if chain[0].IsCA || chain[0].NotAfter.Sub(chain[0].NotBefore) > 7*24*time.Hour+time.Hour {
		t.Fatal("the leaf is a CA or lives longer than seven days")
	}
}

func TestTheCAIsConstrainedToTheTestDomain(t *testing.T) {
	dir := t.TempDir()
	if _, err := Ensure(dir, []string{"sluis.dev.local.test"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	ca := readChain(t, filepath.Join(dir, "ca.pem"))[0]
	if len(ca.PermittedDNSDomains) != 1 || ca.PermittedDNSDomains[0] != "local.test" || !ca.PermittedDNSDomainsCritical {
		t.Fatalf("name constraints: %v", ca.PermittedDNSDomains)
	}
	// A host outside the constraint is refused before anything is signed.
	if _, err := Ensure(t.TempDir(), []string{"example.com"}, time.Now()); err == nil {
		t.Fatal("a leaf for a name outside local.test was made")
	}
}

func TestKeysAreP384AndThePrivateOnesAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	if _, err := Ensure(dir, []string{"sluis.dev.local.test"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, c := range readChain(t, filepath.Join(dir, "leaf.pem")) {
		if c.SignatureAlgorithm != x509.ECDSAWithSHA384 {
			t.Fatalf("signature algorithm %v", c.SignatureAlgorithm)
		}
	}
	for _, k := range []string{"ca.key", "leaf.key"} {
		fi, err := os.Stat(filepath.Join(dir, k))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", k, err, fi)
		}
	}
}

func TestASecondRunKeepsTheCAAndTheLeaf(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if _, err := Ensure(dir, []string{"sluis.dev.local.test"}, now); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "leaf.pem")) //nolint:gosec // a path in the test's temporary directory
	out, err := Ensure(dir, []string{"sluis.dev.local.test"}, now.Add(time.Hour))
	if err != nil || out != "nothing to do" {
		t.Fatalf("%q %v", out, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "leaf.pem")) //nolint:gosec // a path in the test's temporary directory
	if string(before) != string(after) {
		t.Fatal("the leaf was made again")
	}
	// Less than a day left: the leaf is made again under the same CA.
	ca1, _ := os.ReadFile(filepath.Join(dir, "ca.pem")) //nolint:gosec // a path in the test's temporary directory
	out, err = Ensure(dir, []string{"sluis.dev.local.test"}, now.Add(6*24*time.Hour+2*time.Hour))
	if err != nil || !strings.Contains(out, "leaf") || strings.Contains(out, "CA") {
		t.Fatalf("%q %v", out, err)
	}
	ca2, _ := os.ReadFile(filepath.Join(dir, "ca.pem")) //nolint:gosec // a path in the test's temporary directory
	if string(ca1) != string(ca2) {
		t.Fatal("the CA moved with the leaf")
	}
}
