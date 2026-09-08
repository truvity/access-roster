package issuer_test

import (
	"bytes"
	"testing"

	"github.com/truvity/access-roster/internal/issuer"
)

// The key has to outlive the process, and outlive it identically in every
// replica: one minted per start invalidates every token it signed, and two
// replicas with two keys hand out tokens half the fleet cannot verify.
func TestASigningKeySurvivesBeingWrittenDown(t *testing.T) {
	t.Parallel()

	key, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	stored := key.PEM()
	if !bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatalf("the stored key is not PEM: %q", stored)
	}

	same, err := issuer.ParseSigningKey(stored)
	if err != nil {
		t.Fatalf("ParseSigningKey: %v", err)
	}
	// The id travels with the key. Published under a new one, every token
	// signed before this moment stops verifying — which is the failure
	// storing the key at all exists to prevent.
	if same.ID() != key.ID() {
		t.Errorf("id = %q, want %q: the key and its id must not separate", same.ID(), key.ID())
	}
	if same.SignatureAlgorithm() != key.SignatureAlgorithm() {
		t.Errorf("algorithm changed on the way back")
	}

	// Two keys are two keys.
	other, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	if other.ID() == key.ID() {
		t.Error("two generated keys share an id")
	}
}

// What cannot be read must not be guessed at: a key with no id, or none
// at all, is a service that should refuse to start rather than sign with
// something nobody can verify against.
func TestAnUnreadableSigningKeyIsRefused(t *testing.T) {
	t.Parallel()

	for name, encoded := range map[string][]byte{
		"not PEM at all":  []byte("hello"),
		"empty":           nil,
		"PEM with no key": []byte("-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"),
		"no key id": []byte("-----BEGIN PRIVATE KEY-----\n" +
			"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n" +
			"-----END PRIVATE KEY-----\n"),
	} {
		if _, err := issuer.ParseSigningKey(encoded); err == nil {
			t.Errorf("%s was accepted as a signing key", name)
		}
	}
}
