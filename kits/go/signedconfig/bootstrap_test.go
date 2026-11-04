package signedconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

// The bootstrap file of the local installation pins the test key of the vectors on the signed config page.
const localBootstrap = "../../../tests/installations/local/bootstrap.yaml"

func pemOf(t *testing.T, pub *ecdsa.PublicKey) (text, pin string) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum384(der)
	return strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "\n"), hex.EncodeToString(sum[:])
}

func file(t *testing.T, kid string, pub *ecdsa.PublicKey, pin string, extra string) string {
	t.Helper()
	text, sum := pemOf(t, pub)
	if pin == "" {
		pin = sum
	}
	var b strings.Builder
	b.WriteString("boundary: dev\npublishers:\n  - kid: " + kid + "\n    public_key: |\n")
	for l := range strings.SplitSeq(text, "\n") {
		b.WriteString("      " + l + "\n")
	}
	b.WriteString("    spki_sha384: \"" + pin + "\"\n" + extra)
	return b.String()
}

func newKey(t *testing.T, c elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

// verifies: REQ-KEYS-110
// the publishers block of the local bootstrap file verifies the vector it pins.
func TestParsePublishersLocalExampleVerifiesVector1(t *testing.T) {
	raw, err := os.ReadFile(localBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	pubs, err := ParsePublishers(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(pubs) != 1 || pubs[0].KID != "publisher-1" {
		t.Fatalf("publishers = %+v", pubs)
	}
	v := loadVectors(t)
	var doc string
	for _, c := range v.Cases {
		if c.Name == "vector 1 where the kind has no co_signs" {
			doc = c.Document
		}
	}
	got, err := Verify([]byte(doc), "Boundary", pubs)
	if err != nil || got.Seq != 1 {
		t.Fatalf("vector 1 under the local bootstrap: %v, %+v", err, got)
	}
}

func TestParsePublishersRefusals(t *testing.T) {
	p384 := newKey(t, elliptic.P384())
	p256 := newKey(t, elliptic.P256())
	_, goodPin := pemOf(t, p384)
	wrongPin := strings.Repeat("0", len(goodPin))
	good := file(t, "publisher-1", p384, "", "")
	if _, err := ParsePublishers([]byte(good)); err != nil {
		t.Fatalf("a good file: %v", err)
	}
	two := good + strings.SplitN(good, "publishers:\n", 2)[1]
	cases := []struct{ name, text, want string }{
		{"a pin that does not match", file(t, "publisher-1", p384, wrongPin, ""), "spki_sha384: does not match the key"},
		{"a key that is not on P-384", file(t, "publisher-1", p256, "", ""), "public_key: not an EC P-384"},
		{"a kid used twice", two, "kid: not unique"},
		{"no publishers", "boundary: dev\npublishers: []\n", "must hold at least one publisher"},
		{"no publishers block", "boundary: dev\n", "must hold at least one publisher"},
		{"an unknown key of a publisher", file(t, "publisher-1", p384, "", "    role: admin\n"), "unknown key"},
		{"co_signs naming a kind that is not a config kind", file(t, "publisher-1", p384, "", "    co_signs: [DataKeyWrap]\n"), "not a config kind"},
		{"an anchor", strings.Replace(good, "kid: publisher-1", "kid: &k publisher-1", 1), "anchors, aliases and tags"},
		{"an explicit tag", strings.Replace(good, "kid: publisher-1", "kid: !!str publisher-1", 1), "anchors, aliases and tags"},
		{"a duplicate key", good + "boundary: other\n", "duplicate key"},
		{"a kid that is Null, a string in the profile and no kid", strings.Replace(good, "kid: publisher-1", "kid: Null", 1), "kid: must be lower-case kebab-case"},
		{"a kid with upper case", strings.Replace(good, "kid: publisher-1", "kid: Publisher", 1), "kid: must be lower-case kebab-case"},
		{"a merge key at the top", good + "<<: {a: 1}\n", "merge key"},
		{"the non-specific tag", strings.Replace(good, "kid: publisher-1", "kid: ! publisher-1", 1), "anchors, aliases and tags"},
		{"a byte order mark after the start", strings.Replace(good, "boundary: dev", "boundary: dev\n\ufeff", 1), "byte order mark"},
		{"a second document", good + "---\nboundary: other\n", "more than one document"},
		{"not YAML", "publishers: [", "not YAML"},
		{"text before the PEM block", strings.Replace(good, "public_key: |\n", "public_key: |\n      note\n", 1), "must be one PEM PUBLIC KEY block"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePublishers([]byte(c.text))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal containing %q", err, c.want)
			}
			if strings.Contains(err.Error(), "BEGIN PUBLIC KEY") {
				t.Fatalf("the error shows the value: %v", err)
			}
		})
	}
	pubs, err := ParsePublishers([]byte(file(t, "publisher-1", p384, "", "    co_signs: [KeyPlan]\n")))
	if err != nil || len(pubs[0].CoSigns) != 1 || pubs[0].CoSigns[0] != "KeyPlan" {
		t.Fatalf("co_signs: %v %+v", err, pubs)
	}
}
