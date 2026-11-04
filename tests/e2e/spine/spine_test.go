package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestBundlePath(t *testing.T) {
	for _, c := range []struct {
		n     int64
		width int
		want  string
	}{
		{0, 256, "tile/entries/000"},
		{0, 3, "tile/entries/000.p/3"},
		{1234, 256, "tile/entries/x001/234"},
	} {
		if got := bundlePath(c.n, c.width); got != c.want {
			t.Errorf("bundlePath(%d, %d) = %q, want %q", c.n, c.width, got, c.want)
		}
	}
}

func bundleOf(entries ...string) []byte {
	var b []byte
	for _, e := range entries {
		b = binary.BigEndian.AppendUint16(b, uint16(len(e))) //nolint:gosec // short test entries
		b = append(b, e...)
	}
	return b
}

func TestSplitBundle(t *testing.T) {
	got, err := splitBundle(bundleOf("a", "bc", "def"), 2)
	if err != nil || len(got) != 2 || string(got[0]) != "a" || string(got[1]) != "bc" {
		t.Fatalf("splitBundle = %q, %v", got, err)
	}
	if _, err := splitBundle(bundleOf("a"), 2); err == nil {
		t.Error("a bundle shorter than asked was accepted")
	}
	if _, err := splitBundle(append(bundleOf("abc")[:3], 0), 1); err == nil {
		t.Error("an entry cut short was accepted")
	}
}

func TestVerifyToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(kid string) string {
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		o, err := s.Sign([]byte(`{"sub":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := o.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES384", Use: "sig"}}}

	tok := sign("k1")
	if err := verifyToken(tok, set); err != nil {
		t.Fatalf("a good token: %v", err)
	}
	if err := verifyToken(sign("other"), set); err == nil {
		t.Error("a token with an unknown kid was accepted")
	}
	parts := strings.Split(tok, ".")
	parts[1] = "eyJzdWIiOiJ5In0" // {"sub":"y"}
	if err := verifyToken(strings.Join(parts, "."), set); err == nil {
		t.Error("a token with changed claims was accepted")
	}

	h, c, err := decode(tok)
	if err != nil || !strings.Contains(h, `"ES384"`) || c != `{"sub":"x"}` {
		t.Errorf("decode = %q, %q, %v", h, c, err)
	}
	if strings.Contains(h+c, parts[2]) {
		t.Error("decode shows the signature")
	}
}
