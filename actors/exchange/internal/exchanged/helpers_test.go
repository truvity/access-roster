//go:build sluis_test

package exchanged_test

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex is the id of a VerifierKeyCache item: the lower-case hex SHA-256 of the issuer URL.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
