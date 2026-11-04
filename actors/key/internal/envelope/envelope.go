// Package envelope is the byte layout of a sealed value (docs/reference/store-api.md, "The sealed envelope"):
//
//	envelope = version (1 byte, 0x01) | purpose (1 byte) | generation (4 bytes, big-endian)
//	         | nonce (12 bytes) | ciphertext | tag (16 bytes)
//	aad      = "sluis-seal-v1" | version | purpose | generation
//	         | u16 length | boundary | u16 length | tenant ("-" when the address has none)
//	         | u16 length | kind | u16 length | id
//
// The cipher is AES-256-GCM. The nonce comes from the cryptographic library (cipher.NewGCMWithRandomNonce),
// never from the caller (ADR 0006, "Algorithms").
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	// Version is the only version of the layout.
	Version byte = 0x01
	// HeaderLen is the length of version, purpose and generation.
	HeaderLen = 6
	// MinLen is the shortest envelope: the header, the 12-byte nonce, an empty ciphertext and the 16-byte tag.
	MinLen = HeaderLen + 12 + 16
	// KeyLen is the length of a data key.
	KeyLen = 32
	// NoTenant is the tenant part of an address that has none.
	NoTenant = "-"

	aadPrefix = "sluis-seal-v1"
)

// The purpose codes of store-api.md.
const (
	CodeData     byte = 0x01
	CodeEvidence byte = 0x02
	CodeCookie   byte = 0x03
	CodeGrant    byte = 0x04
)

// Code returns the envelope code of a purpose name. It is false for a purpose that is not sealed.
func Code(purpose string) (byte, bool) {
	switch purpose {
	case "data":
		return CodeData, true
	case "evidence":
		return CodeEvidence, true
	case "cookie":
		return CodeCookie, true
	case "grant":
		return CodeGrant, true
	}
	return 0, false
}

// ErrOpen is the one error of Open: it does not say which part failed.
var ErrOpen = errors.New("envelope: cannot open")

// Address is the full address an envelope is bound to.
type Address struct {
	Boundary, Tenant, Kind, ID string // Tenant is "-" when the address has none
}

// Header is the clear header of an envelope.
type Header struct {
	Purpose    byte
	Generation uint32
}

// ParseHeader reads the header of an envelope. It does not authenticate it: Open does, through the AAD.
func ParseHeader(env []byte) (Header, error) {
	if len(env) < MinLen || env[0] != Version {
		return Header{}, ErrOpen
	}
	return Header{Purpose: env[1], Generation: binary.BigEndian.Uint32(env[2:6])}, nil
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s))) //nolint:gosec // an address part is at most 300 bytes
	return append(b, s...)
}

// AAD returns the additional authenticated data of an envelope.
func AAD(purpose byte, generation uint32, a Address) []byte {
	b := make([]byte, 0, 64+len(a.Boundary)+len(a.Tenant)+len(a.Kind)+len(a.ID))
	b = append(b, aadPrefix...)
	b = append(b, Version, purpose)
	b = binary.BigEndian.AppendUint32(b, generation)
	b = appendString(b, a.Boundary)
	b = appendString(b, a.Tenant)
	b = appendString(b, a.Kind)
	return appendString(b, a.ID)
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, errors.New("envelope: data key is not 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// The library draws the nonce from crypto/rand and puts it before the ciphertext.
	return cipher.NewGCMWithRandomNonce(block)
}

// Seal seals plaintext under key at the address. The header is part of the authenticated data.
func Seal(key []byte, purpose byte, generation uint32, a Address, plaintext []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, MinLen+len(plaintext))
	out = append(out, Version, purpose)
	out = binary.BigEndian.AppendUint32(out, generation)
	// The nil nonce is by design: an AEAD from NewGCMWithRandomNonce draws the nonce itself.
	return aead.Seal(out, nil, plaintext, AAD(purpose, generation, a)), nil //nolint:gosec // G407: see above
}

// Open opens an envelope under key at the address. Any failure, a changed header byte included, is ErrOpen.
func Open(key []byte, env []byte, a Address) ([]byte, error) {
	h, err := ParseHeader(env)
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nil, env[HeaderLen:], AAD(h.Purpose, h.Generation, a))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
