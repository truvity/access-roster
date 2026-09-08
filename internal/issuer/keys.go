package issuer

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// SigningKey is one RSA key with an id, satisfying both of the library's
// key interfaces: the private half signs, the public half is published in
// the JWKS.
//
// **The issuer does not create it.** It reads a key some other part of
// the platform put in a Secret — cert-manager issuing one, or
// external-secrets delivering one — mounted as a file. A service that
// mints its own credential is an exception to how everything else here
// gets one, and exceptions are what make an estate hard to reason about.
// It also has to be the same key in every replica and across every
// restart: one minted per process invalidates every token it signed on
// every rollout, and two replicas with two keys hand out tokens that half
// the fleet cannot verify.
//
// The id is the key's own RFC 7638 thumbprint rather than a name given to
// it. That is what lets a key arrive from anywhere: nothing has to carry
// an id beside it, two services reading the same Secret compute the same
// one, and a key and its id cannot be separated because the id is a
// function of the key. Rotation follows from the same property — a new
// key is a new id, so the previous public key can stay in the JWKS for one
// token lifetime without either being mistaken for the other.
type SigningKey struct {
	id  string
	key *rsa.PrivateKey
}

// NewSigningKey generates one, for a local run. A deployment reads the
// key it was given; see [ParseSigningKey].
func NewSigningKey() (*SigningKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate a signing key: %w", err)
	}
	return newSigningKey(key)
}

// ParseSigningKey reads a PEM private key as some other part of the
// platform wrote it.
//
// Both encodings are accepted because both are what turns up: cert-manager
// writes PKCS#1 or PKCS#8 depending on its issuer, and a key put in a
// store by hand is usually whichever openssl produced that day. Refusing
// one of them would be a service that will not start for a reason nobody
// would guess from the message.
func ParseSigningKey(encoded []byte) (*SigningKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, errors.New("issuer: the signing key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return newSigningKey(key)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuer: read the signing key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		// An EC key is a perfectly good signing key and this issuer does
		// not sign with one yet, so say which it got rather than failing
		// on a type assertion.
		return nil, fmt.Errorf("issuer: the signing key is %T; this issuer signs RS256 and needs an RSA key", parsed)
	}
	return newSigningKey(key)
}

func newSigningKey(key *rsa.PrivateKey) (*SigningKey, error) {
	id, err := thumbprint(key)
	if err != nil {
		return nil, err
	}
	return &SigningKey{id: id, key: key}, nil
}

// thumbprint is the RFC 7638 JWK thumbprint of the public half, which is
// what every JWKS consumer already knows how to compute.
func thumbprint(key *rsa.PrivateKey) (string, error) {
	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(jose.RS256), Use: "sig"}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("issuer: derive the key id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// SignatureAlgorithm is what this key signs with. RS256 because every
// relying party understands it, including the ones this replaces.
func (k *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }

// Key is the private half, which the library signs with and nothing else
// ever sees.
func (k *SigningKey) Key() any { return k.key }

// ID is the key id, published in the JWKS and put in every token's header
// so that a verifier knows which key to check it with.
func (k *SigningKey) ID() string { return k.id }

// Derive returns a key for a purpose that is not signing tokens — the
// short-lived state a half-finished login carries, and anything else that
// must be the same in every replica.
//
// Derived rather than configured, because the alternative is a second
// Secret that must be provisioned, rotated and kept in step with this
// one, to protect something that lives for ten minutes. Rotating the
// signing key changes it, which invalidates logins that are part-way
// through and nothing else.
//
// The label separates purposes: two derivations of the same key are
// unrelated, so a value one of them signs cannot be replayed at another.
func (k *SigningKey) Derive(label string) []byte {
	mac := hmac.New(sha256.New, x509.MarshalPKCS1PrivateKey(k.key))
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// publicKey is the published half.
type publicKey struct{ *SigningKey }

func (k publicKey) ID() string                         { return k.id }
func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return &k.key.PublicKey }
