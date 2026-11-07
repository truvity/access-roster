//go:build sluis_test

package wrap_test

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/truvity/sluis/v2/actors/key/internal/wrap"
)

// The throw-away keys of the vector: a recipient scalar 01 02 ... 30 (48 bytes) and a data key A0 A1 ... BF. They are
// public and protect nothing.
func vectorKeys(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	scalar := make([]byte, 48)
	for i := range scalar {
		scalar[i] = byte(i + 1)
	}
	priv, err := ecdh.P384().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	dk := make([]byte, 32)
	for i := range dk {
		dk[i] = byte(0xA0 + i)
	}
	return priv, dk
}

var vectorContext = wrap.Context{Boundary: "prod", Tenant: "acme", Purpose: "data", Generation: 1, Recipient: "recipient-label-one"}

const (
	vectorRecipientPublic = "04c76f2283dda95cd49b0ed9e733d2904474e37216f124e13d2c9ab4cf01021c49ad9cabb3d0b97499aef2f0ab313fa02826bc1f83451b5c8962a75caff73588d4400a6296436154fb343c393e91048a6c7bcbadc83cd8a5f26feae883156f92a1"
	vectorEphemeral       = "04b8b5a62d32c66927eb8575e086da8c827c49bda22ffb09b7a4f71ece473f6412b5e919245752b917c8dc244ef9e4d3b5d532b83d22c2a1e5218f4ce59c578160bd6ce2310f80073e0b85a8227cbb89ee712e8cc6e68c4ff6ea189d7a82187748"
	vectorWrapped         = "4d206bbe480346a592dd5077316b0a6aab6cb55b2454311719fa1411f5cbfdffe717c6f4c3021b93"
)

// hkdf is RFC 5869 written out with HMAC alone, so that the test does not use the library the code uses.
func hkdf(h func() hash.Hash, secret, salt, info []byte, n int) []byte {
	if salt == nil {
		salt = make([]byte, h().Size())
	}
	ext := hmac.New(h, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(h, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// aesUnwrap is RFC 3394 section 2.2.2 written out, over the AES block alone.
func aesUnwrap(t *testing.T, kek, wrapped []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	n := len(wrapped)/8 - 1
	a := bytes.Clone(wrapped[:8])
	r := make([][]byte, n)
	for i := range r {
		r[i] = bytes.Clone(wrapped[8*(i+1) : 8*(i+2)])
	}
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			tv := uint64(n*j + i) //nolint:gosec // small and positive
			x := bytes.Clone(a)
			binary.BigEndian.PutUint64(x, binary.BigEndian.Uint64(a)^tv)
			b := make([]byte, 16)
			block.Decrypt(b, append(x, r[i-1]...))
			a = b[:8]
			r[i-1] = b[8:]
		}
	}
	if !bytes.Equal(a, []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}) {
		t.Fatal("RFC 3394 integrity check failed")
	}
	return bytes.Join(r, nil)
}

// info is the text of the key derivation, written here from the documented layout and not from the code's.
func info(c wrap.Context) []byte {
	var b []byte
	b = append(b, "sluis-wrap-v1"...)
	for _, s := range []string{c.Boundary, c.Tenant, c.Purpose} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(s))) //nolint:gosec // a short test string
		b = append(b, s...)
	}
	b = binary.BigEndian.AppendUint32(b, c.Generation)
	b = binary.BigEndian.AppendUint16(b, uint16(len(c.Recipient))) //nolint:gosec // a short test string
	return append(b, c.Recipient...)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The two primitives written out here are themselves checked against the published vectors, so that the checks
// below stand on something other than the code under test.
func TestTheReferencePrimitivesAreTheStandardsVectors(t *testing.T) {
	// RFC 5869, appendix A.1 (SHA-256).
	okm := hkdf(sha256.New, mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), mustHex(t, "000102030405060708090a0b0c"), mustHex(t, "f0f1f2f3f4f5f6f7f8f9"), 42)
	if hex.EncodeToString(okm) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Fatalf("HKDF-SHA256 case 1 = %x", okm)
	}
	// RFC 3394, section 4.6: 256 bits of key data wrapped with a 256-bit KEK.
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	got := aesUnwrap(t, kek, mustHex(t, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"))
	if hex.EncodeToString(got) != "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f" {
		t.Fatalf("AES key unwrap = %x", got)
	}
}

// verifies: REQ-KEYS-053
// A board wrap is ECDH on P-384, HKDF-SHA384 and AES key wrap, bound to the wrap's own address. A fixed vector
// pins the construction: a stored wrap (made once, for the throw-away recipient key of this file) opens to the data
// key by the shared secret of P-384 ECDH, a key-encryption key of HKDF-SHA384 with an empty salt over an info text built from the
// address here, and RFC 3394, each written out in this file from the standards; and the same wrap does not open when any
// part of the address (boundary, tenant, purpose, generation, recipient) or the version prefix differs. Then fresh wraps
// of the code are opened the same way, so the vector is not the only thing the code is held to.
func TestABoardWrapIsEcdhP384HkdfSha384AndAesKeyWrapBoundToItsAddress(t *testing.T) {
	priv, dk := vectorKeys(t)
	if hex.EncodeToString(priv.PublicKey().Bytes()) != vectorRecipientPublic {
		t.Fatal("the recipient key of the vector is not the one the vector was made for")
	}
	eph, err := ecdh.P384().NewPublicKey(mustHex(t, vectorEphemeral))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := priv.ECDH(eph) // ECDH on P-384
	if err != nil {
		t.Fatal(err)
	}
	wrapped := mustHex(t, vectorWrapped)

	// The standards, by hand.
	kek := hkdf(sha512.New384, secret, nil, info(vectorContext), 32)
	if got := aesUnwrap(t, kek, wrapped); !bytes.Equal(got, dk) {
		t.Fatalf("the vector, opened by hand, = %x, want the data key %x", got, dk)
	}
	// The code opens the vector to the same key.
	got, err := wrap.Unwrap(vectorContext, secret, wrapped)
	if err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("Unwrap of the vector = %x, %v", got, err)
	}
	// Bound to the address: each part changes the key-encryption key, so the wrap does not open.
	for name, c := range map[string]wrap.Context{
		"boundary":   {Boundary: "stage", Tenant: "acme", Purpose: "data", Generation: 1, Recipient: "recipient-label-one"},
		"tenant":     {Boundary: "prod", Tenant: "globex", Purpose: "data", Generation: 1, Recipient: "recipient-label-one"},
		"no tenant":  {Boundary: "prod", Tenant: "-", Purpose: "data", Generation: 1, Recipient: "recipient-label-one"},
		"purpose":    {Boundary: "prod", Tenant: "acme", Purpose: "chain", Generation: 1, Recipient: "recipient-label-one"},
		"generation": {Boundary: "prod", Tenant: "acme", Purpose: "data", Generation: 2, Recipient: "recipient-label-one"},
		"recipient":  {Boundary: "prod", Tenant: "acme", Purpose: "data", Generation: 1, Recipient: "recipient-label-two"},
		// Parts run together must not read as other parts: the lengths are in the text.
		"tenant moved into boundary": {Boundary: "prodacme", Tenant: "", Purpose: "data", Generation: 1, Recipient: "recipient-label-one"},
	} {
		if _, err := wrap.Unwrap(c, secret, wrapped); err == nil {
			t.Errorf("the wrap opened under another %s", name)
		}
	}
	// A bit flipped in the wrapped key is caught by the integrity value of RFC 3394.
	bad := bytes.Clone(wrapped)
	bad[7] ^= 1
	if _, err := wrap.Unwrap(vectorContext, secret, bad); err == nil {
		t.Error("a wrap with a flipped bit opened")
	}

	// Fresh wraps of the code follow the same construction, for other keys and addresses.
	for _, c := range []wrap.Context{
		vectorContext,
		{Boundary: "dev", Tenant: "-", Purpose: "cookie", Generation: 7, Recipient: "x"},
		{Boundary: "dev", Tenant: "acme", Purpose: "pseudonym", Generation: 202611, Recipient: "node-1-abcdefghijklmnop"},
	} {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		eph, w, err := wrap.Wrap(c, priv.PublicKey(), key)
		if err != nil {
			t.Fatal(err)
		}
		peer, err := ecdh.P384().NewPublicKey(eph)
		if err != nil {
			t.Fatalf("the ephemeral key is not a SEC1 point on P-384: %v", err)
		}
		s, err := priv.ECDH(peer)
		if err != nil {
			t.Fatal(err)
		}
		if got := aesUnwrap(t, hkdf(sha512.New384, s, nil, info(c), 32), w); !bytes.Equal(got, key) {
			t.Errorf("a wrap of the code for %+v does not open by the standards: %x", c, got)
		}
	}
}
