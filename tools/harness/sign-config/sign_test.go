package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoConfig is the real config source of the local installation, two levels above tools/harness/sign-config.
const repoConfig = "../../../tests/installations/local/config"
const repoBootstrap = "../../../tests/installations/local/bootstrap.yaml"

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignedDocumentVerifiesAndCarriesTheBytes(t *testing.T) {
	k := testKey(t)
	payload := []byte("default:\n  name: dev\n")
	doc, err := Sign(k, "publisher-1", 7, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, seq, err := Verify(doc, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) || seq != 7 {
		t.Fatalf("payload %q seq %d", got, seq)
	}
	// A key other than the publisher's refuses it.
	if _, _, err := Verify(doc, &testKey(t).PublicKey); err == nil {
		t.Fatal("a document verified under another key")
	}
}

func TestOneChangedCharacterOfThePayloadIsRefused(t *testing.T) {
	k := testKey(t)
	doc, err := Sign(k, "publisher-1", 1, []byte("a: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	// The payload is the first base64url string of the document; change its first character.
	i := strings.Index(string(doc), `"payload": "`) + len(`"payload": "`)
	bad := []byte(string(doc))
	if bad[i] == 'Y' {
		bad[i] = 'Z'
	} else {
		bad[i] = 'Y'
	}
	if _, _, err := Verify(bad, &k.PublicKey); err == nil {
		t.Fatal("a tampered payload verified")
	}
}

func TestSignRefusesAKeyThatIsNotP384(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(k, "publisher-1", 1, []byte("x")); err == nil {
		t.Fatal("signed with a P-256 key")
	}
}

func TestRunSignsEverySourceOfTheLocalInstallationAndPinsTheKey(t *testing.T) {
	dir := t.TempDir()
	o := Options{
		ConfigDir: repoConfig, BootstrapTemplate: repoBootstrap, KeyDir: filepath.Join(dir, "key"),
		Out: filepath.Join(dir, "config"), BootstrapOut: filepath.Join(dir, "bootstrap.yaml"), KID: "publisher-1", Seq: 5,
	}
	names, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	// One document for every source file: the sweep is not empty and not a prefix of the sources.
	var want int
	srcs, _ := os.ReadDir(repoConfig)
	for _, e := range srcs {
		for _, ext := range sources {
			if strings.HasSuffix(e.Name(), ext) {
				want++
			}
		}
	}
	if want < 8 || len(names) != want {
		t.Fatalf("signed %d documents for %d sources", len(names), want)
	}
	// The bootstrap file pins the key that signed them.
	boot, err := os.ReadFile(o.BootstrapOut)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(o.KeyDir, "publisher.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	k, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	sum := sha512.Sum384(spki)
	if !strings.Contains(string(boot), hex.EncodeToString(sum[:])) {
		t.Fatal("the bootstrap file does not carry the pin of the publisher key")
	}
	if strings.Contains(string(boot), "db0b54d40d09fffd") {
		t.Fatal("the bootstrap file still pins the key of the vectors")
	}
	if !strings.Contains(string(boot), "config_source: { driver: file") {
		t.Fatal("the rest of the template was lost")
	}
	// Each document verifies and holds its source, byte for byte.
	for _, n := range names {
		doc, err := os.ReadFile(filepath.Join(o.Out, n)) //nolint:gosec // a path in the test's temporary directory
		if err != nil {
			t.Fatal(err)
		}
		payload, seq, err := Verify(doc, &k.PublicKey)
		if err != nil || seq != 5 {
			t.Fatalf("%s: %v seq %d", n, err, seq)
		}
		var src []byte
		for _, ext := range sources {
			if b, err := os.ReadFile(filepath.Join(repoConfig, strings.TrimSuffix(n, ".jws")+ext)); err == nil { //nolint:gosec // a path of the repository's config sources
				src = b
			}
		}
		if string(src) != string(payload) {
			t.Fatalf("%s: the payload is not the source", n)
		}
	}
	// A second run keeps the key, so that the pin does not move, and signs under the new seq.
	o.Seq = 6
	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
	boot2, _ := os.ReadFile(o.BootstrapOut)
	if string(boot) != string(boot2) {
		t.Fatal("a second run moved the pin")
	}
}

func TestRunRefusesAnEmptyConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := Run(Options{
		ConfigDir: dir, BootstrapTemplate: repoBootstrap, KeyDir: filepath.Join(dir, "key"),
		Out: filepath.Join(dir, "out"), BootstrapOut: filepath.Join(dir, "b.yaml"), KID: "publisher-1", Seq: 1,
	})
	if err == nil {
		t.Fatal("an empty sweep signed nothing and said nothing")
	}
}

func TestBootstrapWithoutAPublishersBlockIsRefused(t *testing.T) {
	if _, err := Bootstrap("boundary: dev\n", "publisher-1", []byte{1}); err == nil {
		t.Fatal("a template without publishers was accepted")
	}
}
