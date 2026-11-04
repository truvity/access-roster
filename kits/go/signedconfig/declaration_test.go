//go:build sluis_test

package signedconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// verifies: REQ-KEYS-108
// A declaration is verified as a config document is (the format, the header, the pinned keys), under a kind of its own
// that no config kind shares: a declaration is not config, and a config document is not a declaration.
func TestADeclarationIsNotConfigAndConfigIsNotADeclaration(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubs := []Publisher{{KID: "publisher-1", Key: &key.PublicKey}}
	payload := []byte("boundary: dev\nkids: [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]\nreason: drill\n")

	if _, ok := registry.KindByName(KeyRevocationDeclaration); ok {
		t.Fatal("the declaration's kind is a kind of the registry: store@ could load it as config")
	}
	decl, err := Sign(key, "publisher-1", 7, KeyRevocationDeclaration, payload)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyDeclaration(decl, KeyRevocationDeclaration, pubs)
	if err != nil {
		t.Fatalf("a declaration signed by a pinned publisher: %v", err)
	}
	if v.Seq != 7 || string(v.Payload) != string(payload) || !slices.Equal(v.KIDs, []string{"publisher-1"}) {
		t.Fatalf("read %d %q %v", v.Seq, v.Payload, v.KIDs)
	}

	// The config verifier does not take the declaration's kind, and the declaration verifier no config kind: each is a
	// caller's error, never a refusal of the document.
	var r *Refused
	if _, err := Verify(decl, KeyRevocationDeclaration, pubs); err == nil || errors.As(err, &r) {
		t.Fatalf("Verify of a declaration kind: %v", err)
	}
	if _, err := VerifyDeclaration(decl, "KeyPlan", pubs); err == nil || errors.As(err, &r) {
		t.Fatalf("VerifyDeclaration of a config kind: %v", err)
	}

	// A KeyPlan document is refused as a declaration at step 2, its header naming another kind.
	plan, err := Sign(key, "publisher-1", 8, "KeyPlan", payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDeclaration(plan, KeyRevocationDeclaration, pubs); !errors.As(err, &r) || r.Step != 2 {
		t.Fatalf("a KeyPlan as a declaration: %v, want a refusal at step 2", err)
	}

	// A key that is not pinned signs no declaration (step 3), and a changed payload does not verify (step 4).
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := Sign(other, "publisher-2", 9, KeyRevocationDeclaration, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDeclaration(forged, KeyRevocationDeclaration, pubs); !errors.As(err, &r) || r.Step != 3 {
		t.Fatalf("an unpinned key: %v, want a refusal at step 3", err)
	}
	impostor, err := Sign(other, "publisher-1", 9, KeyRevocationDeclaration, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDeclaration(impostor, KeyRevocationDeclaration, pubs); !errors.As(err, &r) || r.Step != 4 {
		t.Fatalf("another key under the pinned kid: %v, want a refusal at step 4", err)
	}
}
