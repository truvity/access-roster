//go:build sluis_test

package driver_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card/cardtest"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
)

// bytesFieldsOf walks a message and lists its bytes fields as "Message.field".
func bytesFieldsOf(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool, out *[]string) {
	if seen[md.FullName()] {
		return
	}
	seen[md.FullName()] = true
	fields := md.Fields()
	for i := range fields.Len() {
		f := fields.Get(i)
		switch f.Kind() {
		case protoreflect.BytesKind:
			*out = append(*out, string(md.Name())+"."+string(f.Name()))
		case protoreflect.MessageKind, protoreflect.GroupKind:
			bytesFieldsOf(f.Message(), seen, out)
		}
	}
}

// verifies: REQ-KEYS-002
// A private key made by the card driver is non-extractable: the port has no call that answers with one, and nothing the
// driver answers holds one. Two checks. The tripwire: the response messages of the key-store port are walked, and each
// bytes field in them must be on the list below with the reason it is not a private key; a new bytes field fails the
// test until someone has read it. The scan: every purpose of the slot plan gets a key on a fake card, every call of the
// port that answers is made (Ensure, PublicKey, Sign, Ecdh, Attest), and the private scalar of each key, which the fake
// card lets the test read, is in none of the answers. What it cannot show is that the card's own firmware refuses to
// export a key: the PIV applet has no command to read a private key out, which is a property of the device that the
// attestation of origin (REQ-KEYS-026) rests on.
func TestNoAnswerOfTheCardDriverHoldsAPrivateKey(t *testing.T) {
	allowed := map[string]string{
		"EnsureResponse.spki_der":                       "a public key",
		"KeyStoreSignResponse.signature_der":            "a signature",
		"KeyStorePublicKeyResponse.spki_der":            "a public key",
		"EcdhResponse.shared_secret":                    "the agreed secret with a peer's public key, not the key",
		"AttestResponse.attestation":                    "a certificate",
		"AttestResponse.attestation_signer":             "a certificate",
		"VerifyAttestationResponse.spki_der":            "a public key",
		"BeginPinReleaseResponse.ephemeral_public":      "a public key",
		"BeginPinReleaseResponse.request_text":          "the text of a request",
		"BeginPinReleaseResponse.request_signature_der": "a signature",
		"SealPinResponse.answer_text":                   "the text of an answer, the PIN sealed to a one-time public key",
		"SealPinResponse.answer_signature_der":          "a signature",
	}
	var got []string
	svc := keystorev2alpha1.File_sluis_port_keystore_v2alpha1_keystore_proto.Services().ByName("KeyStoreService")
	if svc == nil {
		t.Fatal("KeyStoreService not found")
	}
	methods := svc.Methods()
	for i := range methods.Len() {
		bytesFieldsOf(methods.Get(i).Output(), map[protoreflect.FullName]bool{}, &got)
	}
	for _, f := range got {
		if _, ok := allowed[f]; !ok {
			t.Errorf("response field %s is bytes and is not on the list: is it a private key?", f)
		}
	}
	if len(got) < 8 {
		t.Fatalf("the walk found %d bytes fields (%v): it walked the wrong thing", len(got), got)
	}
	if len(got) > 0 && !slices.Contains(got, "EcdhResponse.shared_secret") {
		t.Fatalf("the walk did not reach the Ecdh answer: %v", got)
	}

	// The scan of what the driver answers.
	r := start(t, driver.Development)
	r.unlock(t, "123456")
	var answers [][]byte
	for _, p := range []struct{ purpose, alg string }{
		{"x509-intermediate", "ES384"}, {"token-signing", "ES384"}, {"wrapping", "ECDH-P384"}, {"audit-log", "ES256"}, {"pin-release", "ES384"},
	} {
		answers = append(answers, ensure(t, r.key, p.purpose, p.alg).GetSpkiDer())
		pk, err := r.key.PublicKey(context.Background(), connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: p.purpose}))
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, pk.Msg.GetSpkiDer())
	}
	if res, err := sign(r.key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatal(err)
	} else {
		answers = append(answers, res.GetSignatureDer())
	}
	peer, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e, err := r.key.Ecdh(context.Background(), connect.NewRequest(&keystorev2alpha1.EcdhRequest{Purpose: "wrapping", PeerPublic: peer.PublicKey().Bytes()}))
	if err != nil {
		t.Fatal(err)
	}
	answers = append(answers, e.Msg.GetSharedSecret())
	scalars := r.card.PrivateScalars()
	if len(scalars) != 5 {
		t.Fatalf("the fake card holds %d keys, want 5", len(scalars))
	}
	for _, s := range scalars {
		for i, a := range answers {
			if bytes.Contains(a, s) {
				t.Errorf("answer %d holds a private scalar", i)
			}
		}
		// The scalar is not the shared secret either, nor a prefix of one.
		if len(s) < 30 {
			t.Fatalf("a scalar of %d bytes: the scan would prove nothing", len(s))
		}
	}
}

// verifies: REQ-KEYS-004, REQ-KEYS-022
// The card driver declares the signature algorithms it supports (ES384, ES256 for the audit-log purpose, and ECDH-P384
// for key agreement) and refuses every other: Ensure and Sign answer an undeclared algorithm, EdDSA among them, with the
// reason "algorithm", on a card at the firmware floor and on a newer one, so a card whose firmware has no EdDSA is never
// asked for it and a card whose firmware has it is not given it by this driver. A card below the floor is refused at start
// (the cases of TestDriverRefusesToStart and of the real attestation chains), so there is no firmware below the floor on
// which any algorithm is signed. The declaration is checked against the refusals: nothing declared is refused here.
func TestTheDriverRefusesAnAlgorithmItDoesNotDeclare(t *testing.T) {
	for _, fw := range []card.Version{{Major: 5, Minor: 7, Patch: 0}, {Major: 5, Minor: 8, Patch: 0}, {Major: 6, Minor: 0, Patch: 0}} {
		t.Run(fw.String(), func(t *testing.T) {
			c := cardtest.New()
			c.Firmware = fw
			r := startWith(t, c, driver.Development, "key", self())
			r.unlock(t, "123456")
			caps, err := r.key.Capabilities(context.Background(), connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			declared := caps.Msg.GetAlgorithms()
			if !slices.Equal(declared, []string{"ES384", "ES256", "ECDH-P384"}) {
				t.Fatalf("declared %v", declared)
			}
			for _, alg := range []string{"EdDSA", "Ed25519", "RS256", "PS256", "ES512", "ES384 ", "es384", ""} {
				if slices.Contains(declared, alg) {
					t.Fatalf("%q is declared", alg)
				}
				_, err := r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: alg}))
				wantRefused(t, err, connect.CodeInvalidArgument, "algorithm")
				ensure(t, r.key, "token-signing", "ES384") // the slot has its key, so that Sign reaches the algorithm check
				_, err = sign(r.key, "token-signing", alg, digest384())
				wantRefused(t, err, connect.CodeInvalidArgument, "algorithm")
			}
			if n := c.Attempts(); n != 1 { // the one PIN attempt of the unlock: nothing undeclared reached the card
				t.Fatalf("%d PIN attempts", n)
			}
			// Each declared algorithm is served by the purpose that has it.
			for _, p := range []struct{ purpose, alg string }{{"token-signing", "ES384"}, {"audit-log", "ES256"}, {"wrapping", "ECDH-P384"}} {
				ensure(t, r.key, p.purpose, p.alg)
			}
		})
	}
}

// verifies: REQ-KEYS-086
// A PIN offered on the admin socket by a uid other than the administrator is refused before it is read: the answer is
// the refusal of the caller and not the refusal of a message that is too long, which is what a handler that had read the
// body would give (the handler reads at most 4096 bytes). Nothing reaches the card. The administrator's own call, with
// the same sizes, is not refused as a caller, so the check is the uid and nothing else.
func TestAPINFromAnotherUIDIsRefusedBeforeItIsRead(t *testing.T) {
	r := startWith(t, cardtest.New(), driver.Development, "key", func(uint32) bool { return false })
	for _, size := range []int{6, 4096, 1 << 20} {
		_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: bytes.Repeat([]byte("1"), size)}))
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("a PIN of %d bytes from another uid: %v, want permission_denied", size, err)
		}
	}
	if r.card.Attempts() != 0 {
		t.Fatal("a PIN of a non-administrator reached the card")
	}
	adm := start(t, driver.Development)
	_, err := adm.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: bytes.Repeat([]byte("1"), 1<<20)}))
	if connect.CodeOf(err) == connect.CodePermissionDenied {
		t.Fatalf("the administrator was refused as a caller: %v", err)
	}
}
