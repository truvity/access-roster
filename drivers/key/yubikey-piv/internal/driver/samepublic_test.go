package driver

import (
	"bytes"
	"context"
	"log/slog"
	"strings"

	"connectrpc.com/connect"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card/cardtest"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"testing"
)

// verifies: REQ-KEYS-274
// A key that Generate returns is accepted only when it is the key the slot's attestation certifies, of the same type and the
// same value: an EC key for an RSA slot, an RSA key for an EC slot, and another key of the right type are refused. A
// samePublic that said yes to any of them would let a card hand the driver a key it did not attest.
func TestSamePublicAcceptsOnlyTheAttestedKey(t *testing.T) {
	ec1, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsa1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecSlot := &slotKey{pub: &ec1.PublicKey}
	rsaSlot := &slotKey{rsaPub: &rsa1.PublicKey}
	for name, c := range map[string]struct {
		got  any
		slot *slotKey
		want bool
	}{
		"the attested EC key":          {&ec1.PublicKey, ecSlot, true},
		"the attested RSA key":         {&rsa1.PublicKey, rsaSlot, true},
		"another EC key":               {&ec2.PublicKey, ecSlot, false},
		"another RSA key":              {&rsa2.PublicKey, rsaSlot, false},
		"an EC key for the RSA slot":   {&ec1.PublicKey, rsaSlot, false},
		"an RSA key for the EC slot":   {&rsa1.PublicKey, ecSlot, false},
		"something that is not a key":  {"key", ecSlot, false},
		"nothing":                      {nil, rsaSlot, false},
		"the EC key of an empty slot":  {&ec1.PublicKey, &slotKey{}, false},
		"the RSA key of an empty slot": {&rsa1.PublicKey, &slotKey{}, false},
	} {
		if got := samePublic(c.got, c.slot); got != c.want {
			t.Errorf("%s: samePublic = %v, want %v", name, got, c.want)
		}
	}
}

// verifies: REQ-KEYS-276
// An RSA signature whose caller has gone by the time it has the card's lock is refused as canceled, before it asks the card
// anything (a locked driver would answer locked to the same request, so the answer shows which check came first).
func TestAnRSASignatureOfACallerThatHasGoneIsRefusedBeforeTheCard(t *testing.T) {
	c := cardtest.New()
	s, err := New(Options{Environment: Development, Open: c.Opener()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing-rs256", Algorithm: RS256})); err != nil {
		t.Fatal(err)
	}
	req := func() *connect.Request[keystorev2alpha1.KeyStoreSignRequest] {
		return connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: "token-signing-rs256", Algorithm: RS256, Digest: make([]byte, 32)})
	}
	// The driver is locked: the request of a caller that is there is refused for that.
	_, err = s.Sign(context.Background(), req())
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a live caller: %v, want a locked refusal", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Sign(ctx, req())
	if connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("a caller that had gone: %v, want canceled", err)
	}
	if s, d := c.RSACounts(); s != 0 || d != 0 {
		t.Fatalf("the card was asked for %d RSA signatures", s)
	}
}

// verifies: REQ-KEYS-276
// A flood of busy refusals writes one journal line, then one a minute with the count between: it does not write a line each.
func TestTheBusyRefusalsOfAFloodWriteOneJournalLine(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	s := &Service{}
	for range 50 {
		if e := s.busy(context.Background()); connect.CodeOf(e) != connect.CodeResourceExhausted {
			t.Fatalf("code %v", connect.CodeOf(e))
		}
	}
	if n := strings.Count(buf.String(), "refused as busy"); n != 1 {
		t.Fatalf("%d journal lines for 50 refusals, want 1:\n%s", n, buf.String())
	}
}
