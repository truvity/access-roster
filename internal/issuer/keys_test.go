package issuer_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/truvity/access-roster/internal/issuer"
)

// The key arrives from somewhere else — cert-manager issuing one,
// external-secrets delivering one — so it has to be readable in whichever
// encoding that somewhere else wrote, and its id has to come from the key
// itself rather than from anything travelling beside it.
func TestASigningKeyIsReadWhicheverWayItWasWritten(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	encodings := map[string][]byte{
		"PKCS#1, as cert-manager and openssl often write it": pem.EncodeToMemory(
			&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		"PKCS#8, as cert-manager also writes it": pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	}

	ids := map[string]string{}
	for name, encoded := range encodings {
		parsed, parseErr := issuer.ParseSigningKey(encoded)
		if parseErr != nil {
			t.Fatalf("%s: %v", name, parseErr)
		}
		ids[name] = parsed.ID()
		if parsed.ID() == "" {
			t.Errorf("%s: no key id", name)
		}
	}
	// One key is one id however it was written down. Anything else and a
	// re-encoded Secret would republish the same key under a new id, and
	// every token signed before that stops verifying.
	var seen string
	for name, id := range ids {
		if seen == "" {
			seen = id
			continue
		}
		if id != seen {
			t.Errorf("%s gave a different id for the same key", name)
		}
	}

	// And two keys are two ids, which is what makes rotation possible:
	// the previous public key can stay in the JWKS without either being
	// mistaken for the other.
	other, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	if other.ID() == seen {
		t.Error("two keys share an id")
	}
}

// What cannot be read must not be guessed at: signing with a key nobody
// else has produces tokens that look fine and verify nowhere, which is
// worse than refusing to start.
func TestAnUnreadableSigningKeyIsRefused(t *testing.T) {
	t.Parallel()

	// A curve this issuer has no JOSE algorithm for. P-224 is a real
	// curve with no `ES*` pairing in RFC 7518, so it exercises the
	// refusal without needing a malformed key.
	weak, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	weakBytes, err := x509.MarshalPKCS8PrivateKey(weak)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for name, encoded := range map[string][]byte{
		"not PEM at all":  []byte("hello"),
		"empty":           nil,
		"PEM with no key": []byte("-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"),
		"an EC key on a curve with no JOSE algorithm": pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: weakBytes}),
	} {
		if _, err := issuer.ParseSigningKey(encoded); err == nil {
			t.Errorf("%s was accepted as a signing key", name)
		}
	}
}

// TestEachKeyKindSignsItsOwnAlgorithm is the pairing RFC 7518 fixes: the
// curve decides the hash, and an RSA key still signs RS256 so an
// installation that keeps its key keeps its tokens.
func TestEachKeyKindSignsItsOwnAlgorithm(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}

	for name, tc := range map[string]struct {
		key  crypto.Signer
		want jose.SignatureAlgorithm
	}{
		"RSA":   {key: rsaKey, want: jose.RS256},
		"P-256": {key: mustEC(t, elliptic.P256()), want: jose.ES256},
		"P-384": {key: mustEC(t, elliptic.P384()), want: jose.ES384},
		"P-521": {key: mustEC(t, elliptic.P521()), want: jose.ES512},
	} {
		encoded, err := x509.MarshalPKCS8PrivateKey(tc.key)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		parsed, err := issuer.ParseSigningKey(pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := parsed.SignatureAlgorithm(); got != tc.want {
			t.Errorf("%s signs %s, want %s", name, got, tc.want)
		}
	}
}

func mustEC(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate %s: %v", curve.Params().Name, err)
	}
	return key
}
