// Package wrap wraps a data key for a recipient and unwraps it (ADR 0006, "DataKeyWrap"): ECDH-ES on P-384
// with an ephemeral sender key, HKDF-SHA384 for the key-encryption key, and AES key wrap (RFC 3394).
//
// Making a wrap needs only the recipient's public key. Opening one needs the recipient's private key, which
// stays in the key store: the caller does the ECDH there and passes the shared secret to Unwrap.
package wrap

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
)

const (
	infoPrefix = "sluis-wrap-v1"
	kekLen     = 32
	// DataKeyLen is the length of a data key.
	DataKeyLen = 32
)

// Context is what a wrap is bound to. It is the info of the key derivation, so a wrap cannot be opened as
// another key, in another boundary or tenant, or by another recipient.
type Context struct {
	Boundary   string
	Tenant     string // "-" for a boundary purpose
	Purpose    string
	Generation uint32
	Recipient  string
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s))) //nolint:gosec // a part of an address is at most 300 bytes
	return append(b, s...)
}

// info is "sluis-wrap-v1" | u16 len | boundary | u16 len | tenant | u16 len | purpose | u32 generation |
// u16 len | recipient.
func (c Context) info() []byte {
	b := []byte(infoPrefix)
	b = appendString(b, c.Boundary)
	b = appendString(b, c.Tenant)
	b = appendString(b, c.Purpose)
	b = binary.BigEndian.AppendUint32(b, c.Generation)
	return appendString(b, c.Recipient)
}

// kek derives the key-encryption key: HKDF-SHA384 (RFC 5869) with an empty salt.
func (c Context) kek(secret []byte) ([]byte, error) {
	return hkdf.Key(sha512.New384, secret, nil, string(c.info()), kekLen)
}

// ParsePublic reads a SEC1 uncompressed P-384 point.
func ParsePublic(sec1 []byte) (*ecdh.PublicKey, error) {
	return ecdh.P384().NewPublicKey(sec1)
}

// Wrap wraps dataKey for the recipient's public key. It returns the ephemeral public key (SEC1 uncompressed)
// and the wrapped key.
func Wrap(c Context, recipient *ecdh.PublicKey, dataKey []byte) (ephemeralPublic, wrapped []byte, err error) {
	if len(dataKey) != DataKeyLen {
		return nil, nil, errors.New("wrap: data key is not 32 bytes")
	}
	eph, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	secret, err := eph.ECDH(recipient)
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	kek, err := c.kek(secret)
	if err != nil {
		return nil, nil, err
	}
	defer clear(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err = josecipher.KeyWrap(block, dataKey)
	if err != nil {
		return nil, nil, err
	}
	return eph.PublicKey().Bytes(), wrapped, nil
}

// Unwrap opens a wrapped key from the shared secret that the recipient's key made with the ephemeral public
// key. A wrong secret, context or wrapped key is an error that says nothing more.
func Unwrap(c Context, secret, wrapped []byte) ([]byte, error) {
	kek, err := c.kek(secret)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	key, err := josecipher.KeyUnwrap(block, wrapped)
	if err != nil {
		return nil, errors.New("wrap: cannot unwrap")
	}
	if len(key) != DataKeyLen {
		clear(key)
		return nil, fmt.Errorf("wrap: unwrapped key has the wrong length")
	}
	return key, nil
}
