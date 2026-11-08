package driver

import (
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
)

// The algorithms of the key-store port (keystore.proto).
const (
	ES384    = "ES384"     // ECDSA over P-384 with SHA-384 (RFC 7518, section 3.4)
	ES256    = "ES256"     // ECDSA over P-256 with SHA-256 (RFC 7518, section 3.4); the audit-log purpose only
	ECDHP384 = "ECDH-P384" // ECDH over P-384 (NIST SP 800-56A)
	RS256    = "RS256"     // RSASSA-PKCS1-v1_5 over SHA-256 with an RSA-2048 key (RFC 7518, section 3.3); the RS256 purpose only
)

// FirmwareFloor is the oldest firmware a board's card may run: 5.7 fixes the EUCLEAK flaw (ADR 0006, "Touch and
// PIN"). The driver refuses a card below it, by what the card says and by what its attestations say.
var FirmwareFloor = card.Version{Major: 5, Minor: 7, Patch: 0}

// entry is one row of the slot plan: what a purpose is on a card.
type entry struct {
	purpose   string
	slot      card.Slot
	algorithm string // the port's name
	spec      card.KeySpec
	curveBits int // 256 or 384; 0 for the RSA key
}

// optional says that a card whose slot holds a key that is not the plan's still starts, the purpose left absent: the RS256 key,
// which only some installations use. Every other key refuses the start.
func (e entry) optional() bool { return e.algorithm == RS256 }

// digestLen is the length of the digest the key signs: the curve's size for an EC key, SHA-256 for the RSA key.
func (e entry) digestLen() int {
	if e.algorithm == RS256 {
		return 32
	}
	return e.curveBits / 8
}

// The default slot map, version 1 (ADR 0006, "The slot plan"; docs/architecture/keys.yaml slot_plan). Every slot
// is generated with PIN once and touch never, except 87, the PIN release key, which signs while the board is
// locked: PIN never, touch never. The audit-log key is P-256 (ADR 0006, "Named exceptions"); every other key is
// P-384. A purpose with no slot here (a spare slot is named by the installation's KeyPlan) is not served.
//
// 9e is not used: the card-authentication slot signs without a PIN by default.
var slotPlan = []entry{
	{"x509-intermediate", 0x9c, ES384, spec384(card.PINOnce), 384},
	{"token-signing", 0x9a, ES384, spec384(card.PINOnce), 384},
	{"wrapping", 0x9d, ECDHP384, spec384(card.PINOnce), 384},
	{"ssh-user", 0x82, ES384, spec384(card.PINOnce), 384},
	{"ssh-host", 0x83, ES384, spec384(card.PINOnce), 384},
	{"audit-log", 0x84, ES256, card.KeySpec{Algorithm: card.EC256, PIN: card.PINOnce, Touch: card.TouchNever}, 256},
	{"release-signing", 0x85, ES384, spec384(card.PINOnce), 384},
	{"workload-issuer", 0x86, ES384, spec384(card.PINOnce), 384},
	{"pin-release", 0x87, ES384, spec384(card.PINNever), 384},
	// The RS256 purpose (the per-audience exception) has the first of the spare slots, 88, by a fixed row, and not by a name in
	// the KeyPlan: the card driver verifies no override of a slot. It is RSA-2048, PIN once, touch never, born on the card and
	// attested like the others. One private-key operation of the card takes about 0.17 s (measured, firmware 5.8; the driver admits four at
	// once, signs them one at a time, and holds the card meanwhile; see signRS256).
	{"token-signing-rs256", 0x88, RS256, card.KeySpec{Algorithm: card.RSA2048, PIN: card.PINOnce, Touch: card.TouchNever}, 0},
}

func spec384(pin card.PINPolicy) card.KeySpec {
	return card.KeySpec{Algorithm: card.EC384, PIN: pin, Touch: card.TouchNever}
}

// planFor returns the row of a purpose.
func planFor(purpose string) (entry, bool) {
	for _, e := range slotPlan {
		if e.purpose == purpose {
			return e, true
		}
	}
	return entry{}, false
}
