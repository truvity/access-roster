package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// SigningKey is one RSA key with an id, satisfying both of the library's
// key interfaces: the private half signs, the public half is published in
// the JWKS.
//
// It has to outlive the process, and outlive it identically in every
// replica. A key minted per start invalidates every token it signed on
// every rollout, and two replicas with two keys hand out tokens that half
// the fleet cannot verify — which looks like an intermittent outage and
// is really a coin toss. So a deployment reads it from a Secret through
// [ParseSigningKey], and only a local run generates one.
//
// Rotation is not here yet. When it comes, the previous public key stays
// in the JWKS for one token lifetime so that tokens already issued keep
// verifying, which is why the id travels with the key rather than being
// derived from it.
type SigningKey struct {
	id  string
	key *rsa.PrivateKey
}

// NewSigningKey generates one.
func NewSigningKey() (*SigningKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate a signing key: %w", err)
	}
	return &SigningKey{id: uuid.NewString(), key: key}, nil
}

// PEM encodes the key for storage. The id is carried in a header rather
// than beside the file, so that a key and its id cannot be separated: a
// key published under the wrong id verifies nothing.
func (k *SigningKey) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: map[string]string{keyIDHeader: k.id},
		Bytes:   x509.MarshalPKCS1PrivateKey(k.key),
	})
}

// ParseSigningKey reads one back.
func ParseSigningKey(encoded []byte) (*SigningKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, errors.New("issuer: the stored signing key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuer: read the stored signing key: %w", err)
	}
	id := block.Headers[keyIDHeader]
	if id == "" {
		// A key with no id would be published under a new one on every
		// start, so every token signed before this moment stops
		// verifying — the failure the storage exists to prevent.
		return nil, errors.New("issuer: the stored signing key carries no key id")
	}
	return &SigningKey{id: id, key: key}, nil
}

// keyIDHeader is where the id rides in the PEM.
const keyIDHeader = "kid"

// SignatureAlgorithm is what this key signs with. RS256 because every
// relying party understands it, including the ones this replaces.
func (k *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }

// Key is the private half, which the library signs with and nothing else
// ever sees.
func (k *SigningKey) Key() any { return k.key }

// ID is the key id, published in the JWKS and put in every token's header
// so that a verifier knows which key to check it with.
func (k *SigningKey) ID() string { return k.id }

// publicKey is the published half.
type publicKey struct{ *SigningKey }

func (k publicKey) ID() string                         { return k.id }
func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return &k.key.PublicKey }
