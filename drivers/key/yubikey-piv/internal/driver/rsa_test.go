//go:build sluis_test

package driver_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card/cardtest"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
)

// The RSA key of the RS256 purpose on a card (ADR 0006, "Named exceptions"): slot 88 by a fixed row, RSA-2048, PIN once, touch
// never, born on the card, attested, and a signature that takes seconds of the card's time (REQ-KEYS-274 to 277).

const rsPurpose = "token-signing-rs256"

var rsaSpec = card.KeySpec{Algorithm: card.RSA2048, PIN: card.PINOnce, Touch: card.TouchNever}

func digest256() []byte { d := sha256.Sum256([]byte("x")); return d[:] }

func rsaPublic(t *testing.T, spki []byte) *rsa.PublicKey {
	t.Helper()
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 || pub.E != 65537 {
		t.Fatalf("the key is %T, want RSA-2048 with the exponent 65537", k)
	}
	return pub
}

// verifies: REQ-KEYS-274
// In development the driver makes the key of the RS256 purpose on the card, in slot 88, RSA-2048, PIN once and touch never,
// verifies the attestation of the new key like every other, and returns the same key the second time. The algorithm of another
// purpose is refused for it, and its algorithm for the others.
func TestTheRS256KeyIsMadeInSlot88WithItsPolicies(t *testing.T) {
	r := start(t, driver.Development)
	res := ensure(t, r.key, rsPurpose, "RS256")
	if !res.GetCreated() {
		t.Fatal("not created on a factory card")
	}
	pub := rsaPublic(t, res.GetSpkiDer())
	att, err := r.card.Attest(0x88)
	if err != nil {
		t.Fatalf("slot 88 holds no key: %v", err)
	}
	root, _ := r.card.AttestationCertificate()
	a, err := r.card.VerifyAttestation(root, att)
	if err != nil {
		t.Fatal(err)
	}
	if a.Slot != 0x88 || a.PIN != card.PINOnce || a.Touch != card.TouchNever {
		t.Fatalf("attested %+v, want slot 88, PIN once, touch never", a)
	}
	if got, ok := att.PublicKey.(*rsa.PublicKey); !ok || !got.Equal(pub) {
		t.Fatal("the attested key is not the key returned")
	}
	if again := ensure(t, r.key, rsPurpose, "RS256"); again.GetCreated() || !bytes.Equal(again.GetSpkiDer(), res.GetSpkiDer()) {
		t.Fatal("a second Ensure made a key or returned another one")
	}
	for _, c := range []struct{ purpose, alg string }{
		{"token-signing", "RS256"}, {"audit-log", "RS256"}, {"wrapping", "RS256"}, {"x509-intermediate", "RS256"}, {"pin-release", "RS256"},
		{rsPurpose, "ES384"}, {rsPurpose, "ES256"}, {rsPurpose, "ECDH-P384"},
	} {
		_, err := r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: c.purpose, Algorithm: c.alg}))
		wantRefused(t, err, connect.CodeFailedPrecondition, "algorithm")
	}
	_, err = r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: rsPurpose, Algorithm: "PS256"}))
	wantRefused(t, err, connect.CodeInvalidArgument, "algorithm")
}

// verifies: REQ-KEYS-274
// The key is signed with on the card as RSASSA-PKCS1-v1_5 over a SHA-256 digest and the signature verifies with the standard
// library (and is not PSS); a locked driver, a wrong algorithm, a digest of the wrong length and a purpose that holds an EC key
// are refused before the card is asked, and the key does not agree on a secret.
func TestTheRS256KeySignsPKCS1v15OnTheCardOnceUnlocked(t *testing.T) {
	r := start(t, driver.Development)
	pub := rsaPublic(t, ensure(t, r.key, rsPurpose, "RS256").GetSpkiDer())
	ensure(t, r.key, "token-signing", "ES384")
	d := digest256()
	_, err := sign(r.key, rsPurpose, "RS256", d)
	wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	if started, _ := r.card.RSACounts(); started != 0 || r.card.LoginAttempts != 0 {
		t.Fatalf("the locked driver talked to the card: %d RSA signatures, %d logins", started, r.card.LoginAttempts)
	}
	r.unlock(t, "123456")
	res, err := sign(r.key, rsPurpose, "RS256", d)
	if err != nil {
		t.Fatal(err)
	}
	sig := res.GetSignatureDer()
	if len(sig) != 256 {
		t.Fatalf("%d octets", len(sig))
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d, sig); err != nil {
		t.Fatalf("not PKCS#1 v1.5 over SHA-256: %v", err)
	}
	if rsa.VerifyPSS(pub, crypto.SHA256, d, sig, nil) == nil {
		t.Fatal("the signature is also a PSS signature")
	}
	for name, c := range map[string]struct {
		purpose, alg string
		digest       []byte
		code         connect.Code
		reason       string
	}{
		"ES384 for the RSA key":   {rsPurpose, "ES384", d, connect.CodeInvalidArgument, "algorithm"},
		"no algorithm":            {rsPurpose, "", d, connect.CodeInvalidArgument, "algorithm"},
		"RS256 for the token key": {"token-signing", "RS256", d, connect.CodeInvalidArgument, "algorithm"},
		"a SHA-384 digest":        {rsPurpose, "RS256", digest384(), connect.CodeInvalidArgument, "digest"},
		"a short digest":          {rsPurpose, "RS256", d[:31], connect.CodeInvalidArgument, "digest"},
		"no digest":               {rsPurpose, "RS256", nil, connect.CodeInvalidArgument, "digest"},
	} {
		started, _ := r.card.RSACounts()
		_, err := sign(r.key, c.purpose, c.alg, c.digest)
		if err == nil || connect.CodeOf(err) != c.code {
			t.Errorf("%s: %v, want %s/%s", name, err, c.code, c.reason)
			continue
		}
		if now, _ := r.card.RSACounts(); now != started {
			t.Errorf("%s: the card was asked", name)
		}
	}
	_, err = r.key.Ecdh(context.Background(), connect.NewRequest(&keystorev2alpha1.EcdhRequest{Purpose: rsPurpose, PeerPublic: p384Point(t)}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "algorithm")
	// The EC key of another purpose does not take the RSA path.
	if _, err := sign(r.key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatalf("the ES384 key after an RSA signature: %v", err)
	}
}

// verifies: REQ-KEYS-275
// A card that signs wrongly is caught before the signature leaves the driver, and the PIN refusal of an RSA operation locks the
// driver like any other.
func TestAWrongRSASignatureFromTheCardDoesNotLeaveTheDriver(t *testing.T) {
	c := cardtest.New()
	r := startWith(t, c, driver.Development, "key", self())
	ensure(t, r.key, rsPurpose, "RS256")
	r.unlock(t, "123456")
	c.Configure(func(c *cardtest.Card) { c.RSACorrupt = true })
	_, err := sign(r.key, rsPurpose, "RS256", digest256())
	wantRefused(t, err, connect.CodeInternal, "store")
	c.Configure(func(c *cardtest.Card) { c.RSACorrupt = false })
	if _, err := sign(r.key, rsPurpose, "RS256", digest256()); err != nil {
		t.Fatalf("after the fault: %v", err)
	}
}

// verifies: REQ-KEYS-274
// A card that holds a key in slot 88 that is not the RSA-2048 key of the plan does not stop the driver, in production as well: an
// EC key, an RSA key of another size, a key whose attestation states another policy, a key made by another card and an imported
// key. The RS256 purpose is optional, so the driver starts, serves the other keys and leaves that purpose absent (it never
// uses the key, and never replaces it). An RSA key in the slot of an EC purpose is refused at start, as before: the refusal
// names the slot and a word.
func TestAWrongKeyInSlot88OrAnRSAKeyInAnotherSlotIsRefusedAtStart(t *testing.T) {
	ec := card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchNever}
	for _, tt := range []struct {
		name  string
		setup func(c *cardtest.Card)
		want  string
	}{
		{"the RSA key of the plan", func(c *cardtest.Card) { _, _ = c.PutRSAKey(0x88, rsaSpec) }, ""},
		{"an EC key in slot 88", func(c *cardtest.Card) { _, _ = c.PutKey(0x88, ec) }, "absent"},
		{"an RSA-3072 key in slot 88", func(c *cardtest.Card) { c.RSAKeyBits = 3072; _, _ = c.PutRSAKey(0x88, rsaSpec) }, "absent"},
		{"an RSA-1024 key in slot 88", func(c *cardtest.Card) { c.RSAKeyBits = 1024; _, _ = c.PutRSAKey(0x88, rsaSpec) }, "absent"},
		{"an RSA key whose attestation states PIN never", func(c *cardtest.Card) {
			_, _ = c.PutRSAKey(0x88, rsaSpec)
			c.Lie(0x88, card.KeySpec{Algorithm: card.RSA2048, PIN: card.PINNever, Touch: card.TouchNever})
		}, "absent"},
		{"an RSA key whose attestation states touch always", func(c *cardtest.Card) {
			_, _ = c.PutRSAKey(0x88, rsaSpec)
			c.Lie(0x88, card.KeySpec{Algorithm: card.RSA2048, PIN: card.PINOnce, Touch: card.TouchAlways})
		}, "absent"},
		{"an RSA key made with the PIN never policy", func(c *cardtest.Card) {
			_, _ = c.PutRSAKey(0x88, card.KeySpec{Algorithm: card.RSA2048, PIN: card.PINNever, Touch: card.TouchNever})
		}, "absent"},
		{"an attestation that chains to another root", func(c *cardtest.Card) { c.RogueRoot = true; _, _ = c.PutRSAKey(0x88, rsaSpec) }, "absent"},
		{"an attestation of another card's serial", func(c *cardtest.Card) {
			c.AttestedSerial = c.SerialNo + 1
			_, _ = c.PutRSAKey(0x88, rsaSpec)
		}, "absent"},
		{"an imported key", func(c *cardtest.Card) { _ = c.PutImportedKey(0x88, rsaSpec) }, "absent"},
		{"an RSA key in the slot of the token key", func(c *cardtest.Card) { _, _ = c.PutRSAKey(0x9a, rsaSpec) }, "slots.9a.attestation: algorithm"},
		{"an RSA key in the audit-log slot", func(c *cardtest.Card) { _, _ = c.PutRSAKey(0x84, rsaSpec) }, "slots.84.attestation: algorithm"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := cardtest.New()
			tt.setup(c)
			svc, err := driver.New(driver.Options{Environment: driver.Production, Serial: c.SerialNo, Open: c.Opener()})
			if tt.want == "" || tt.want == "absent" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				defer func() { _ = svc.Close() }()
				// The driver is up; the key of slot 88 is the plan's (want "") or it is not served (want "absent").
				served := slices.Contains(svc.Present(), rsPurpose)
				if served != (tt.want == "") {
					t.Fatalf("the purposes present are %v: RS256 served = %v, want %v", svc.Present(), served, tt.want == "")
				}
				return
			}
			var p *driver.Problems
			if !errors.As(err, &p) || !strings.Contains(strings.Join(p.List, ";"), tt.want) {
				t.Fatalf("err = %v, want a problem with %q", err, tt.want)
			}
			if !c.Closed() {
				t.Fatal("the refused card was left open")
			}
		})
	}
	// Staging and production never make the key: a card that has none answers absent.
	r := start(t, driver.Staging)
	_, err := r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: rsPurpose, Algorithm: "RS256"}))
	wantRefused(t, err, connect.CodeNotFound, "absent")
	if ec, _ := r.card.Attest(0x88); ec != nil {
		t.Fatal("a staging driver made a key")
	}
}

// verifies: REQ-KEYS-276
// One private-key operation of an RSA-2048 key takes seconds of the card's time, and the driver holds one conversation with the
// card. It admits the RSA signatures it is told to (the one on the card and those that wait for it) and refuses the rest at
// once as busy, without touching the card, so that a flood of RS256 requests builds no queue for the other keys to wait in.
// The test holds the card in its signature at a gate, not by the clock: more signers than places call at once, and the ones
// that are refused come back at once, whichever they are; the admitted ones come back when the gate opens.
func TestOnlyAFewRSASignaturesAreAdmittedAndTheRestAreRefusedAtOnce(t *testing.T) {
	// 0 is the default of the driver, which is one place.
	for _, given := range []int{0, 2, 3} {
		queue := max(given, 1)
		t.Run(fmt.Sprintf("places-%d", queue), func(t *testing.T) {
			c := cardtest.New()
			r := startOpts(t, c, driver.Development, "key", self(), driver.Options{Node: "node-a", RSAQueue: given})
			ensure(t, r.key, rsPurpose, "RS256")
			ensure(t, r.key, "token-signing", "ES384")
			r.unlock(t, "123456")
			gate := make(chan struct{})
			started := make(chan struct{}, 8)
			c.Configure(func(c *cardtest.Card) { c.RSAGate, c.RSAStarted = gate, started })
			const callers = 12
			results := make(chan error, callers)
			for range callers {
				go func() {
					_, err := sign(r.key, rsPurpose, "RS256", digest256())
					results <- err
				}()
			}
			// The callers beyond the places are refused at once, and nothing else comes back while the card holds the first.
			for range callers - queue {
				wantRefused(t, <-results, connect.CodeResourceExhausted, "busy")
			}
			<-started
			if s, _ := c.RSACounts(); s != 1 {
				t.Fatalf("%d RSA signatures on the card while one is held, want 1", s)
			}
			select {
			case err := <-results:
				t.Fatalf("an admitted signature came back while the card held the first: %v", err)
			default:
			}
			close(gate) // the card finishes; the waiting ones follow
			for range queue {
				if err := <-results; err != nil {
					t.Fatalf("an admitted signature: %v", err)
				}
			}
			if s, d := c.RSACounts(); s != queue || d != queue {
				t.Fatalf("%d started and %d done, want %d: the refused callers reached the card", s, d, queue)
			}
			// The places are free again, and the other keys sign.
			if _, err := sign(r.key, rsPurpose, "RS256", digest256()); err != nil {
				t.Fatalf("after the burst: %v", err)
			}
			if _, err := sign(r.key, "token-signing", "ES384", digest384()); err != nil {
				t.Fatalf("ES384 after the burst: %v", err)
			}
		})
	}
}

// The ES384 signature that meets an RSA signature on the card waits for it, the card being one conversation, and is signed
// when it ends: the driver does not drop it, and an RSA flood behind the first cannot lengthen the wait. This is the driver as it
// is by default, not tuned: one place, so the ES384 signature waits for one RSA signature and every other RSA request is refused.
//
// verifies: REQ-KEYS-276
func TestAnES384SignatureWaitsForTheRSAOneOnTheCardAndNotForTheFlood(t *testing.T) {
	c := cardtest.New()
	r := startOpts(t, c, driver.Development, "key", self(), driver.Options{Node: "node-a"})
	ensure(t, r.key, rsPurpose, "RS256")
	ensure(t, r.key, "token-signing", "ES384")
	r.unlock(t, "123456")
	gate := make(chan struct{})
	started := make(chan struct{}, 4)
	c.Configure(func(c *cardtest.Card) { c.RSAGate, c.RSAStarted = gate, started })
	rsDone := make(chan error, 1)
	go func() { _, err := sign(r.key, rsPurpose, "RS256", digest256()); rsDone <- err }()
	<-started
	esDone := make(chan error, 1)
	go func() { _, err := sign(r.key, "token-signing", "ES384", digest384()); esDone <- err }()
	// The flood: refused at once, the ES384 signature still waiting for the card.
	for range 20 {
		_, err := sign(r.key, rsPurpose, "RS256", digest256())
		wantRefused(t, err, connect.CodeResourceExhausted, "busy")
	}
	select {
	case err := <-esDone:
		t.Fatalf("the ES384 signature was made while the card held the RSA one: %v", err)
	default:
	}
	close(gate)
	if err := <-rsDone; err != nil {
		t.Fatal(err)
	}
	if err := <-esDone; err != nil {
		t.Fatalf("ES384 after the RSA signature: %v", err)
	}
	if s, d := c.RSACounts(); s != 1 || d != 1 {
		t.Fatalf("%d RSA signatures started, %d done; the flood reached the card", s, d)
	}
}

// verifies: REQ-KEYS-274
// The attestation of an RSA key is read from the certificate's public key, so a card must not be able to give the driver a
// key other than the one it attests: the key Generate returns must be the attested one.
func TestGenerateAndAttestAgreeForTheRSAKey(t *testing.T) {
	c := cardtest.New()
	r := startWith(t, c, driver.Development, "key", self())
	res := ensure(t, r.key, rsPurpose, "RS256")
	att, err := c.Attest(0x88)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.MarshalPKIXPublicKey(att.PublicKey)
	if err != nil || !bytes.Equal(want, res.GetSpkiDer()) {
		t.Fatalf("the driver's key is not the attested one: %v", err)
	}
	if _, ok := att.PublicKey.(*ecdsa.PublicKey); ok {
		t.Fatal("an EC key attested for the RSA slot")
	}
}

// verifies: REQ-KEYS-274
// The driver in development makes the RS256 key only into an empty slot. A foreign key in slot 88 (an imported key, one of another
// type) leaves the purpose absent, and Ensure does not replace it: the card still holds the key it held.
func TestADevelopmentDriverNeverReplacesAForeignKeyInSlot88(t *testing.T) {
	ec := card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchNever}
	for name, setup := range map[string]func(c *cardtest.Card){
		"an imported RSA key": func(c *cardtest.Card) { _ = c.PutImportedKey(0x88, rsaSpec) },
		"an EC key":           func(c *cardtest.Card) { _, _ = c.PutKey(0x88, ec) },
	} {
		t.Run(name, func(t *testing.T) {
			c := cardtest.New()
			setup(c)
			before, errBefore := c.Attest(0x88)
			r := startWith(t, c, driver.Development, "key", self())
			_, err := r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: rsPurpose, Algorithm: "RS256"}))
			wantRefused(t, err, connect.CodeFailedPrecondition, "card")
			_, err = r.key.PublicKey(context.Background(), connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: rsPurpose}))
			wantRefused(t, err, connect.CodeNotFound, "absent")
			// The other keys are made and served as before.
			ensure(t, r.key, "token-signing", "ES384")
			after, errAfter := c.Attest(0x88)
			// (The fake signs a new attestation certificate at each call; the key in it is what must stay.)
			if (errBefore == nil) != (errAfter == nil) {
				t.Fatalf("slot 88 changed: before %v, after %v", errBefore, errAfter)
			}
			if errBefore == nil {
				was, _ := x509.MarshalPKIXPublicKey(before.PublicKey)
				now, _ := x509.MarshalPKIXPublicKey(after.PublicKey)
				if !bytes.Equal(was, now) {
					t.Fatal("the key of slot 88 was replaced")
				}
			}
		})
	}
}
