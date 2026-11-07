// Package handoff is sluis's side of the hand-off to root custody: the files a requester writes (a PKCS#10 request
// and a proof file), the files it reads back (a certificate and a result file), the checks it runs before it installs
// an answer, and the reader of the signed root list. The specification is ritueel's hand-off contract, version 1
// (https://ritueel.id/reference/hand-off-contract/); it owns the files, the profiles, the reason codes and the test
// vectors, and this package copies none of them but the code names. The two products share no code (ADR 0024, "The
// hand-off"): this package is written from the page and tested against the page's vectors.
//
// The first working version builds the X.509 intermediate (type x509-intermediate), in the stores piv and software.
// The OpenPGP subkey and the SSH CA key come with the signing API and ssh-ca, and a message of those types, or any
// other type, is refused as malformed, which is what the contract says of a type the receiver does not know.
//
// Nothing in an error carries a value of a file. A refusal names a code of the contract and a place (a member or a
// check), never what the file held ("errors name a path, never a value", cli.md).
package handoff

import (
	"fmt"
	"regexp"
)

// Version is the contract version this package speaks.
const Version = 1

// MaxJSON bounds a JSON file of the contract (256 KiB).
const MaxJSON = 256 << 10

// TypeX509 is the request type of an intermediate certificate.
const TypeX509 = "x509-intermediate"

// The stores of a proof file.
const (
	StorePIV      = "piv"
	StoreSoftware = "software"
	StoreAWSKMS   = "aws-kms"
)

// The reason codes of the requester's checks (contract, "What the requester checks before it installs"), and
// malformed, which the receiver of any file uses.
const (
	CodeVersionUnsupported = "version-unsupported"
	CodeMalformed          = "malformed"
	CodeRequestMismatch    = "request-mismatch"
	CodeIssuer             = "issuer"
	CodeKeyMismatch        = "key-mismatch"
	CodeProfile            = "profile"
	CodeValidity           = "validity"
)

// Refusal is a refusal by a check: the contract's code and the place the check looked at.
type Refusal struct {
	Code string
	// At names the member or the check, such as "evidence.attestation[1]" or "validity.length"; never a value.
	At string
}

func (r *Refusal) Error() string {
	if r.At == "" {
		return r.Code
	}
	return r.Code + " at " + r.At
}

func refuse(code, at string) *Refusal { return &Refusal{Code: code, At: at} }

func refusef(code, format string, args ...any) *Refusal {
	return &Refusal{Code: code, At: fmt.Sprintf(format, args...)}
}

var stemPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidStem reports whether s is a stem of the contract: lower-case letters, digits and hyphens, 1 to 63
// characters, starting with a letter or a digit.
func ValidStem(s string) bool { return stemPattern.MatchString(s) }
