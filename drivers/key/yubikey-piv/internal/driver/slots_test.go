//go:build sluis_test

package driver_test

import (
	"errors"
	"testing"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
)

// verifies: REQ-KEYS-048
// A slot of the board plan holds a key only when its purpose was asked for. On a fresh development card the driver
// is asked for token-signing: slot 9a then holds a key and the slot of release-signing (85), like every other slot of the plan,
// is empty. A second request, for release-signing, fills slot 85 and no other: enabling a purpose adds exactly one key
// and one slot. This is the card half of the row; key@ asks only for the purposes of the KeyPlan (key@'s test in
// actors/key/internal/keyd).
func TestADevelopmentCardHoldsAKeyOnlyInTheSlotsEnsured(t *testing.T) {
	r := start(t, driver.Development)
	slots := map[string]card.Slot{
		"x509-intermediate": 0x9c, "token-signing": 0x9a, "wrapping": 0x9d, "ssh-user": 0x82, "ssh-host": 0x83,
		"audit-log": 0x84, "release-signing": 0x85, "workload-issuer": 0x86, "pin-release": 0x87,
	}
	held := func() map[string]bool {
		out := map[string]bool{}
		for p, s := range slots {
			_, err := r.card.Attest(s)
			switch {
			case err == nil:
				out[p] = true
			case errors.Is(err, card.ErrNoKey):
			default:
				t.Fatalf("slot %s: %v", s, err)
			}
		}
		return out
	}
	if got := held(); len(got) != 0 {
		t.Fatalf("a fresh card holds keys in %v", got)
	}
	ensure(t, r.key, "token-signing", "ES384")
	if got := held(); len(got) != 1 || !got["token-signing"] {
		t.Fatalf("after one request the card holds keys for %v, want token-signing alone", got)
	}
	ensure(t, r.key, "release-signing", "ES384")
	if got := held(); len(got) != 2 || !got["token-signing"] || !got["release-signing"] {
		t.Fatalf("after enabling release-signing the card holds keys for %v, want it and token-signing", got)
	}
}
