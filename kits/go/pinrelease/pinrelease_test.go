package pinrelease

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// A UUIDv7 of 2026-11-04T12:00:00Z (0x01a1a66e2a00 ms), version 7, variant 10.
const testID = "01a1a66e-2a00-7abc-8def-0123456789ab"

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func request(t *testing.T, k *ecdh.PrivateKey) []byte {
	t.Helper()
	text, err := RequestText(Request{Boundary: "prod", Node: "board-a", ID: testID, Ephemeral: k.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// The layout of a request text, octet by octet: the vector a second implementation checks itself against.
func TestRequestTextLayout(t *testing.T) {
	eph := bytes.Repeat([]byte{0xaa}, 97)
	eph[0] = 0x04
	// The point must be on the curve, so the layout is checked on encode() and the parse on a real key below.
	got := encode([]byte(RequestDomain), []byte("prod"), []byte("board-a"), []byte(testID), eph)
	want := "00000014" + hex.EncodeToString([]byte(RequestDomain)) +
		"00000004" + hex.EncodeToString([]byte("prod")) +
		"00000007" + hex.EncodeToString([]byte("board-a")) +
		"00000024" + hex.EncodeToString([]byte(testID)) +
		"00000061" + hex.EncodeToString(eph)
	if hex.EncodeToString(got) != want {
		t.Fatalf("layout\n got %x\nwant %s", got, want)
	}
}

func TestUUIDv7Time(t *testing.T) {
	at, err := UUIDv7Time(testID)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC); !at.Equal(want) {
		t.Fatalf("time %v, want %v", at, want)
	}
	for _, bad := range []string{
		"", "01a1a66e-2a00-4abc-8def-0123456789ab", // version 4
		"01a1a66e-2a00-7abc-cdef-0123456789ab", // variant 110
		"019A4EC5-C400-7ABC-8DEF-0123456789AB", // upper case is not the canonical form
		"019a4ec5c4007abc8def0123456789ab",     // no hyphens
		"01a1a66e-2a00-7abc-8def-0123456789ag",
	} {
		if _, err := UUIDv7Time(bad); err == nil {
			t.Errorf("%q read as a UUIDv7", bad)
		}
	}
}

// verifies: REQ-KEYS-059
// A sealed PIN opens with the one-time key of its own request, and with nothing else: another request's key, another
// request text, a changed octet, or the answer of one request given to another.
func TestSealOpensOnlyWithItsOwnRequest(t *testing.T) {
	pin := []byte("123456")
	own := newKey(t)
	text := request(t, own)
	pub, sealed, err := Seal(pin, text)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(own, text, pub, sealed)
	if err != nil || !bytes.Equal(got, pin) {
		t.Fatalf("open: %v", err)
	}

	other := newKey(t)
	otherText := request(t, other)
	if _, err := Open(other, otherText, pub, sealed); err == nil {
		t.Fatal("another request's key opened the PIN")
	}
	if _, err := Open(other, text, pub, sealed); err == nil {
		t.Fatal("a key that is not the request's was used")
	}
	// The same key under another text (another node): the info and the additional data differ.
	moved, err := RequestText(Request{Boundary: "prod", Node: "board-b", ID: testID, Ephemeral: own.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(own, moved, pub, sealed); err == nil {
		t.Fatal("the PIN opened under another request text")
	}
	for i := range sealed {
		c := bytes.Clone(sealed)
		c[i] ^= 0x01
		if _, err := Open(own, text, pub, c); err == nil {
			t.Fatalf("a changed octet %d opened", i)
		}
	}
	if _, err := Open(own, text, other.PublicKey().Bytes(), sealed); err == nil {
		t.Fatal("another releaser key opened")
	}
}

func TestSealRefusesABadPIN(t *testing.T) {
	text := request(t, newKey(t))
	for _, pin := range []string{"12345", "123456789"} {
		if _, _, err := Seal([]byte(pin), text); err == nil {
			t.Errorf("a PIN of %d octets was sealed", len(pin))
		}
	}
}

func TestParseRequestIsStrict(t *testing.T) {
	k := newKey(t)
	text := request(t, k)
	r, err := ParseRequest(text)
	if err != nil {
		t.Fatal(err)
	}
	if r.Boundary != "prod" || r.Node != "board-a" || r.ID != testID || !bytes.Equal(r.Ephemeral, k.PublicKey().Bytes()) {
		t.Fatalf("read %+v", r)
	}
	cases := map[string][]byte{
		"a trailing octet": append(bytes.Clone(text), 0),
		"cut short":        text[:len(text)-1],
		"another domain":   encode([]byte(AnswerDomain), []byte("prod"), []byte("board-a"), []byte(testID), k.PublicKey().Bytes()),
		"a short key":      encode([]byte(RequestDomain), []byte("prod"), []byte("board-a"), []byte(testID), k.PublicKey().Bytes()[:96]),
		"no node":          encode([]byte(RequestDomain), []byte("prod"), nil, []byte(testID), k.PublicKey().Bytes()),
		"a huge length":    append([]byte{0xff, 0xff, 0xff, 0xff}, text...),
		"not a UUIDv7":     encode([]byte(RequestDomain), []byte("prod"), []byte("board-a"), []byte("1"), k.PublicKey().Bytes()),
	}
	for name, b := range cases {
		if _, err := ParseRequest(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAnswerRoundTripAndStrictness(t *testing.T) {
	k := newKey(t)
	text := request(t, k)
	pub, sealed, err := Seal([]byte("12345678"), text)
	if err != nil {
		t.Fatal(err)
	}
	a := Answer{Boundary: "prod", Releaser: "board-b", Requester: "board-a", ID: testID, RequestSHA384: Digest(text), Ephemeral: pub, Sealed: sealed}
	at, err := AnswerText(a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAnswer(at)
	if err != nil {
		t.Fatal(err)
	}
	if got.Releaser != "board-b" || got.Requester != "board-a" || !bytes.Equal(got.Sealed, sealed) || !bytes.Equal(got.RequestSHA384, Digest(text)) {
		t.Fatalf("read %+v", got)
	}
	if _, err := ParseRequest(at); err == nil {
		t.Fatal("an answer read as a request")
	}
	if _, err := ParseAnswer(text); err == nil {
		t.Fatal("a request read as an answer")
	}
	bad := a
	bad.RequestSHA384 = bad.RequestSHA384[:47]
	if _, err := AnswerText(bad); err == nil || !strings.Contains(err.Error(), "SHA-384") {
		t.Fatalf("a short digest: %v", err)
	}
}

func TestNewIDIsAUUIDv7OfItsTime(t *testing.T) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 123_000_000, time.UTC)
	for range 100 {
		id, err := NewID(at)
		if err != nil {
			t.Fatal(err)
		}
		got, err := UUIDv7Time(id)
		if err != nil || !got.Equal(at) {
			t.Fatalf("%s: %v, %v", id, got, err)
		}
	}
	a, _ := NewID(at)
	b, _ := NewID(at)
	if a == b {
		t.Fatal("two ids of one time are equal")
	}
}
