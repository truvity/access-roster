package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// SigningKey is one key with an id, satisfying both of the library's key
// interfaces: the private half signs, the public half is published in the
// JWKS.
//
// RSA and ECDSA are both accepted, and the algorithm follows from the key
// rather than being configured beside it: an RSA key signs RS256, a P-256
// key ES256, P-384 ES384, P-521 ES512. Nothing has to declare which,
// because a key that disagreed with its declaration would produce tokens
// no relying party could verify.
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
// key is a new id, so the previous public key can stay in the JWKS
// without either being mistaken for the other.
//
// A single SigningKey does not decide HOW LONG the previous one stays
// published, or WHEN this one starts signing rather than merely being
// published — that is [KeyRing], which watches for a new one to appear
// and keeps the schedule every replica agrees on.
type SigningKey struct {
	id   string
	key  crypto.Signer
	alg  jose.SignatureAlgorithm
	seed []byte
}

// NewSigningKey generates one, for a local run. A deployment reads the
// key it was given; see [ParseSigningKey].
//
// P-384 rather than RSA: a local run should exercise the same shape a
// deployment gets, and the chart's default is a P-384 key.
func NewSigningKey() (*SigningKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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
	key, ok := parsed.(crypto.Signer)
	if !ok {
		// Say which key arrived rather than failing on a type assertion.
		return nil, fmt.Errorf("issuer: the signing key is %T, which cannot sign", parsed)
	}
	return newSigningKey(key)
}

func newSigningKey(key crypto.Signer) (*SigningKey, error) {
	alg, err := signatureAlgorithm(key)
	if err != nil {
		return nil, err
	}
	id, err := thumbprint(key)
	if err != nil {
		return nil, err
	}
	sd, err := seed(key)
	if err != nil {
		return nil, err
	}
	return &SigningKey{id: id, key: key, alg: alg, seed: sd}, nil
}

// signatureAlgorithm is what a key of this kind signs with. The curve
// decides the hash for ECDSA -- that pairing is fixed by RFC 7518, not a
// preference -- so there is nothing here to configure.
func signatureAlgorithm(key crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
		return "", fmt.Errorf("issuer: the signing key is an EC key on %s; this issuer signs with P-256, P-384 or P-521", key.Curve.Params().Name)
	}
	return "", fmt.Errorf("issuer: the signing key is %T; this issuer signs with an RSA or ECDSA key", key)
}

// seed is a stable secret encoding of the private half, for [SigningKey.Derive].
//
// PKCS#1 for RSA, which is what it was before EC keys were accepted, so an
// installation that keeps its RSA key derives exactly what it derived
// before and no half-finished login is invalidated by the upgrade. PKCS#1
// encodes only RSA, hence the second form.
func seed(key crypto.Signer) ([]byte, error) {
	if key, ok := key.(*rsa.PrivateKey); ok {
		return x509.MarshalPKCS1PrivateKey(key), nil
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("issuer: encode the signing key: %w", err)
	}
	return encoded, nil
}

// thumbprint is the RFC 7638 JWK thumbprint of the public half, which is
// what every JWKS consumer already knows how to compute.
//
// RFC 7638 hashes only the key's required members -- kty, n and e for RSA,
// kty, crv, x and y for EC -- so neither `alg` nor `use` enters it, and an
// RSA key keeps the id it had before this function stopped naming RS256.
func thumbprint(key crypto.Signer) (string, error) {
	jwk := jose.JSONWebKey{Key: key.Public(), Use: "sig"}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("issuer: derive the key id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// SignatureAlgorithm is what this key signs with, derived from the key
// itself; see [signatureAlgorithm].
func (k *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.alg }

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
	mac := hmac.New(sha256.New, k.seed)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// publishedKey is one entry in the JWKS: enough to verify a signature,
// never enough to make one.
//
// It is its own type rather than a view over [SigningKey] because a
// [KeyRing] publishes keys it never held the private half of — one
// another replica reported having seen, kept here only so this replica
// forgets neither the key nor its schedule across a restart. Building a
// SigningKey for those would need a private key that does not exist here.
type publishedKey struct {
	id  string
	alg jose.SignatureAlgorithm
	pub any
}

func (k publishedKey) ID() string                         { return k.id }
func (k publishedKey) Algorithm() jose.SignatureAlgorithm { return k.alg }
func (k publishedKey) Use() string                        { return "sig" }
func (k publishedKey) Key() any                           { return k.pub }

// signingAlgorithms are every algorithm a [SigningKey] can ever produce:
// RS256 for RSA, ES256/ES384/ES512 for the three curves this issuer
// accepts (see [signatureAlgorithm]).
//
// The library's own verifiers -- checking an `id_token_hint` at
// `/end_session`, checking a bearer access token at the session service
// and the grants endpoint -- are told to accept all four, always, rather
// than whichever this installation happens to sign with today. Their real
// defence is the key SET: [localKeys.VerifySignature] only ever accepts a
// signature one of THIS issuer's own published keys produces, so widening
// the algorithm allow-list costs nothing an attacker could use. What it
// buys is a verifier that does not go stale the moment an operator
// changes `signingKey.certificate.algorithm` -- rotating from RSA to
// ECDSA is then just a rotation, not a second thing to keep in step.
//
// Discovery is different and stays dynamic: `id_token_signing_alg_values_supported`
// is a promise to EVERY OTHER relying party about what they will be
// handed, so it has to say only what is actually published right now —
// see [Storage.SignatureAlgorithms].
var signingAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES384, jose.ES512}

// signingAlgorithmStrings is [signingAlgorithms] as the library's options
// want them.
func signingAlgorithmStrings() []string {
	out := make([]string, len(signingAlgorithms))
	for i, alg := range signingAlgorithms {
		out[i] = string(alg)
	}
	return out
}
