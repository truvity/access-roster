package sessiond

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
)

// idEncoding is lower-case base32 without padding, the form of every random id of sluis (store-api.md, "Address
// encoding": a random value of 128 bits in lower-case base32).
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// randomBytes reads n bytes from the operating system's generator, the only source of randomness of sluis
// (BRIEF-COMMON, "Algorithms").
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// randomID is 128 random bits as 26 lower-case base32 characters: a subject (0019 "Assigning a subject"), a session
// id, a cookie id, a token id.
func randomID() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return lowerBase32(b), nil
}

func lowerBase32(b []byte) string {
	out := idEncoding.EncodeToString(b)
	buf := []byte(out)
	for i, c := range buf {
		if c >= 'A' && c <= 'Z' {
			buf[i] = c + ('a' - 'A')
		}
	}
	return string(buf)
}

// randomToken is 256 random bits as 43 characters of base64url without padding: a code, a state, a nonce, a
// refresh secret. A PKCE verifier has the same form (RFC 7636 section 4.1: 43 characters is the shortest).
func randomToken() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// s256 is the PKCE transform of RFC 7636 section 4.2: BASE64URL(SHA256(verifier)).
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// secretID is the id of an item that is found by a secret the client holds: the hex of SHA-384 of it, 96 characters.
// The item can be compared and never read back into the secret (0004 "Treatment": hashed).
func secretID(secret string) string {
	sum := sha512.Sum384([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// secretHash is SHA-384 of a secret: the stored form of a refresh token.
func secretHash(secret string) []byte {
	sum := sha512.Sum384([]byte(secret))
	return sum[:]
}

// equal compares two strings in constant time for their length.
func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// lengthPrefixed appends each part with a 4-byte big-endian length in front, so that ("ab","c") and ("a","bc")
// differ (the same rule as the audit pseudonym input of 0029).
func lengthPrefixed(parts ...string) []byte {
	var out []byte
	for _, p := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p))) //nolint:gosec // bounded by the callers' checks
		out = append(out, p...)
	}
	return out
}
