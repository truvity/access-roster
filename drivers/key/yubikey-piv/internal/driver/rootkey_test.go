//go:build sluis_test

package driver_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
)

// The card driver makes no key for a root (REQ-PKI-027): a request for a root purpose, under any algorithm, is refused
// as a purpose the card does not serve, in a development install where the driver makes keys, and no slot of the card
// holds a key afterwards. The slot plan has no row that names a root. The driver offers no operation that exports a
// private key: Ensure never exports, and Sign and Ecdh answer with a signature and a shared secret.
//
// verifies: REQ-PKI-027
func TestTheCardDriverMakesNoRootKey(t *testing.T) {
	r := start(t, driver.Development)
	ctx := context.Background()
	for _, purpose := range []string{"root", "root-ca", "ca-root", "x509-root", "root-key", "trust-anchor", "Root"} {
		for _, alg := range []string{"ES384", "ES256", "ECDH-P384"} {
			_, err := r.key.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
			wantRefused(t, err, connect.CodeInvalidArgument, "purpose")
		}
		if _, err := sign(r.key, purpose, "ES384", make([]byte, 48)); err == nil {
			t.Errorf("Sign under %q succeeded", purpose)
		}
	}
	// No slot of the card, those of the plan and the spare range alike, holds a key.
	held := 0
	for s := card.Slot(0x82); s <= 0x95; s++ {
		if _, err := r.card.Attest(s); err == nil {
			held++
		} else if !errors.Is(err, card.ErrNoKey) {
			t.Fatalf("slot %s: %v", s, err)
		}
	}
	for _, s := range []card.Slot{0x9a, 0x9c, 0x9d, 0x9e} {
		if _, err := r.card.Attest(s); err == nil {
			held++
		} else if !errors.Is(err, card.ErrNoKey) {
			t.Fatalf("slot %s: %v", s, err)
		}
	}
	if held != 0 {
		t.Errorf("the card holds %d keys after the requests for a root", held)
	}
	// A purpose of the plan still gets its key: the refusals were about the root.
	if !ensure(t, r.key, "x509-intermediate", "ES384").GetCreated() {
		t.Error("the intermediate's key was not made")
	}
}
