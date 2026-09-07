package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// signingKey is one RSA key with an id, satisfying both of the library's
// key interfaces: the private half signs, the public half is published in
// the JWKS.
//
// In a deployment the key comes from a Secret and rotates, with the
// previous public key left in the JWKS for one token lifetime so that
// tokens already issued keep verifying. Here it is generated per process,
// which is right for a spike and wrong for anything else: every restart
// invalidates every token it signed.
type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

func newSigningKey() (*signingKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate a signing key: %w", err)
	}
	return &signingKey{id: uuid.NewString(), key: key}, nil
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *signingKey) Key() any                                    { return k.key }
func (k *signingKey) ID() string                                  { return k.id }

// publicKey is the published half.
type publicKey struct{ *signingKey }

func (k publicKey) ID() string                         { return k.id }
func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return &k.key.PublicKey }
