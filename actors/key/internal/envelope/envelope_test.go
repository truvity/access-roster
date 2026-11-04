package envelope_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
)

// The vector of store-api.md, "The sealed envelope" (checked there 2026-11-03).
const (
	vecKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vecEnv = "010100000001a0a1a2a3a4a5a6a7a8a9aaab83601d4035a767333479d34abf5280916c787fad2fae39"
	vecAAD = "736c7569732d7365616c2d7631010100000001000470726f64000461636d650006706572736f6e001a713778326d356e74346b7a336336766470396261386877726665"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var vecAddr = envelope.Address{Boundary: "prod", Tenant: "acme", Kind: "person", ID: "q7x2m5nt4kz3c6vdp9ba8hwrfe"}

func TestVectorAAD(t *testing.T) {
	got := envelope.AAD(envelope.CodeData, 1, vecAddr)
	if !bytes.Equal(got, mustHex(t, vecAAD)) {
		t.Fatalf("aad = %x, want %s", got, vecAAD)
	}
}

func TestVectorOpens(t *testing.T) {
	key, env := mustHex(t, vecKey), mustHex(t, vecEnv)
	pt, err := envelope.Open(key, env, vecAddr)
	if err != nil || string(pt) != "example" {
		t.Fatalf("Open = %q, %v; want example", pt, err)
	}
	h, err := envelope.ParseHeader(env)
	if err != nil || h.Purpose != envelope.CodeData || h.Generation != 1 {
		t.Fatalf("header = %+v, %v", h, err)
	}
}

func TestVectorFailsElsewhere(t *testing.T) {
	key, env := mustHex(t, vecKey), mustHex(t, vecEnv)
	for name, a := range map[string]envelope.Address{
		"tenant":    {Boundary: "prod", Tenant: "globex", Kind: "person", ID: vecAddr.ID},
		"boundary":  {Boundary: "dev", Tenant: "acme", Kind: "person", ID: vecAddr.ID},
		"kind":      {Boundary: "prod", Tenant: "acme", Kind: "session", ID: vecAddr.ID},
		"id":        {Boundary: "prod", Tenant: "acme", Kind: "person", ID: "other"},
		"no tenant": {Boundary: "prod", Tenant: envelope.NoTenant, Kind: "person", ID: vecAddr.ID},
	} {
		if _, err := envelope.Open(key, env, a); err == nil {
			t.Errorf("opened under another %s", name)
		}
	}
}

func TestHeaderBytesAreAuthenticated(t *testing.T) {
	key := mustHex(t, vecKey)
	for i := 0; i < envelope.HeaderLen; i++ {
		env := mustHex(t, vecEnv)
		env[i] ^= 0x01
		if _, err := envelope.Open(key, env, vecAddr); err == nil {
			t.Errorf("header byte %d changed in place and the envelope still opens", i)
		}
	}
	env := mustHex(t, vecEnv)
	env[len(env)-1] ^= 0x01
	if _, err := envelope.Open(key, env, vecAddr); err == nil {
		t.Error("a changed tag still opens")
	}
	if _, err := envelope.Open(key, env[:envelope.MinLen-1], vecAddr); err == nil {
		t.Error("a short envelope opens")
	}
}

func TestSealRoundTripAndFreshNonce(t *testing.T) {
	key := mustHex(t, vecKey)
	a, err := envelope.Seal(key, envelope.CodeCookie, 7, vecAddr, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := envelope.Seal(key, envelope.CodeCookie, 7, vecAddr, []byte("hello"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of one plaintext are identical: the nonce is not fresh")
	}
	if len(a) != envelope.HeaderLen+12+5+16 {
		t.Fatalf("envelope length = %d", len(a))
	}
	pt, err := envelope.Open(key, a, vecAddr)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	if _, err := envelope.Seal(key[:16], 1, 1, vecAddr, nil); err == nil {
		t.Fatal("a 16-byte key was accepted")
	}
}
