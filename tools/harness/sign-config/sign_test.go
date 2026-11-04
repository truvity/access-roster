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

	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
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
	doc, err := Sign(k, "publisher-1", 7, "Boundary", payload)
	if err != nil {
		t.Fatal(err)
	}
	got, seq, err := Verify(doc, &k.PublicKey, "Boundary")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) || seq != 7 {
		t.Fatalf("payload %q seq %d", got, seq)
	}
	// A key other than the publisher's refuses it.
	if _, _, err := Verify(doc, &testKey(t).PublicKey, "Boundary"); err == nil {
		t.Fatal("a document verified under another key")
	}
}

// REQ-DATA-099: a document names its kind in the signed header, so a document of one kind cannot be served as another.
func TestADocumentNamesItsKind(t *testing.T) {
	k := testKey(t)
	doc, err := Sign(k, "publisher-1", 1, "KeyPlan", []byte("a: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(doc, &k.PublicKey, "KeyPlan"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(doc, &k.PublicKey, "Boundary"); err == nil {
		t.Fatal("a KeyPlan document verified as a Boundary")
	}
}

func TestOneChangedCharacterOfThePayloadIsRefused(t *testing.T) {
	k := testKey(t)
	doc, err := Sign(k, "publisher-1", 1, "Boundary", []byte("a: 1\n"))
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
	if _, _, err := Verify(bad, &k.PublicKey, "Boundary"); err == nil {
		t.Fatal("a tampered payload verified")
	}
}

func TestSignRefusesAKeyThatIsNotP384(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(k, "publisher-1", 1, "Boundary", []byte("x")); err == nil {
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
	if strings.Contains(string(boot), "d4c36e17a4d13238") {
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
		kind, ok := registry.KindBySegment(strings.TrimSuffix(n, ".jws"))
		if !ok {
			t.Fatalf("%s is not the segment of a kind", n)
		}
		payload, seq, err := Verify(doc, &k.PublicKey, kind.Name)
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

// The thumbprints of the RFC 7638 example (section 3.1) and of the P-384 vector of actors/key.
const (
	idA = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	idB = "S6so4ozvKppaEWY0wKql5mscesqW7SqnwqkfyQ_fabw"
)

func TestRecipientsReplaceTheEmptyListOfTheKeyPlan(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoConfig, "key-plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := WithRecipients(src, []string{idA, idB})
	if err != nil {
		t.Fatal(err)
	}
	want := "  recipients:\n    - " + idA + "\n    - " + idB + "\n"
	if !strings.Contains(string(got), want) || strings.Contains(string(got), "recipients: []") {
		t.Fatalf("the list was not replaced:\n%s", got)
	}
	// Nothing else changed: the source and the result differ by that one line.
	if strings.Replace(string(src), "  recipients: []\n", want, 1) != string(got) {
		t.Fatal("more than the list changed")
	}
	for name, ids := range map[string][]string{
		"a label":      {"node-1-abcdefghijklmnop"},
		"a repeat":     {idA, idA},
		"a short one":  {idA[:42]},
		"a padded one": {idA + "="},
	} {
		if _, err := WithRecipients(src, ids); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := WithRecipients([]byte("default:\n  cache_ttl: 15m\n"), []string{idA}); err == nil {
		t.Error("a source with no empty list was accepted")
	}
}

func TestRunSignsTheRecipientsIntoTheKeyPlan(t *testing.T) {
	dir := t.TempDir()
	o := Options{
		ConfigDir: repoConfig, BootstrapTemplate: repoBootstrap, KeyDir: filepath.Join(dir, "key"),
		Out: filepath.Join(dir, "config"), BootstrapOut: filepath.Join(dir, "bootstrap.yaml"), KID: "publisher-1", Seq: 5,
		Recipients: []string{idB},
	}
	if _, err := Run(o); err != nil {
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
	doc, err := os.ReadFile(filepath.Join(o.Out, "key-plan.jws"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := Verify(doc, &k.PublicKey, "KeyPlan")
	if err != nil || !strings.Contains(string(payload), "    - "+idB+"\n") {
		t.Fatalf("the signed KeyPlan does not list the recipient: %v\n%s", err, payload)
	}
}

func TestReadRecipients(t *testing.T) {
	f := filepath.Join(t.TempDir(), "r")
	if err := os.WriteFile(f, []byte("# the nodes\n"+idA+" # node-1\n\n  "+idB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readRecipients(f)
	if err != nil || len(got) != 2 || got[0] != idA || got[1] != idB {
		t.Fatalf("readRecipients = %v, %v", got, err)
	}
}

// A declaration is signed with the publisher key that already exists, as a KeyRevocationDeclaration that the kit
// verifies under that key; with no key it is refused, and no key is made.
func TestSignDeclarationFileUsesTheExistingPublisherKey(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "revoke.yaml")
	payload := []byte("boundary: dev\nkids:\n  - AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\nreason: drill\n")
	if err := os.WriteFile(in, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(dir, "publisher")
	out := filepath.Join(dir, "revoke.jws")
	if err := SignDeclarationFile(keyDir, "publisher-1", 7, in, out); err == nil {
		t.Fatal("a declaration was signed with no publisher key")
	}
	if _, err := os.Stat(keyDir); !os.IsNotExist(err) {
		t.Fatal("a publisher key was made for a declaration")
	}
	key, err := loadOrMakeKey(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignDeclarationFile(keyDir, "publisher-1", 7, in, out); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(out) //nolint:gosec // the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	v, err := signedconfig.VerifyDeclaration(doc, signedconfig.KeyRevocationDeclaration, []signedconfig.Publisher{{KID: "publisher-1", Key: &key.PublicKey}})
	if err != nil || v.Seq != 7 || string(v.Payload) != string(payload) {
		t.Fatalf("VerifyDeclaration = %v, %v", v, err)
	}
}
