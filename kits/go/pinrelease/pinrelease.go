// Package pinrelease is the wire format of the PIN release between boards (ADR 0006, "Touch and PIN"; settled
// 2026-11-04): the signed text of a request and of its answer, and the sealing of the PIN to the request.
//
// A locked board's key@ writes a PinReleaseRequest whose text is
//
//	"sluis-pin-release-v1" || boundary || node || request id || ephemeral public key
//
// and an unlocked peer answers with a PinRelease whose text is
//
//	"sluis-pin-release-answer-v1" || boundary || releasing node || requesting node || request id ||
//	SHA-384(request text) || releaser's ephemeral public key || sealed PIN
//
// Every field is a 4-octet big-endian length followed by its octets, so no field can run into the next. Each text is
// signed with ES384 by the pin-release key (card slot 87) of the node that wrote it. The PIN is sealed with ECDH P-384
// between a fresh key of the releaser and the request's ephemeral key, HKDF-SHA384 (RFC 5869) with no salt and the
// request text as info, and AES-256-GCM with a random nonce and the request text as additional data.
//
// The package holds no key and no PIN: the card drivers seal and open (the PIN never leaves them), key@ builds and
// checks the texts.
package pinrelease

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The domains of the two texts. A request text can never be read as an answer, nor the other way round.
const (
	RequestDomain = "sluis-pin-release-v1"
	AnswerDomain  = "sluis-pin-release-answer-v1"
)

// The sizes of the fields.
const (
	publicLen = 97 // SEC1 uncompressed P-384: 0x04 || X || Y
	digestLen = sha512.Size384
	keyLen    = 32 // AES-256
	// maxField bounds every field, so that a hostile length cannot ask for memory.
	maxField = 4096
	// MaxPIN is the longest PIV PIN (NIST SP 800-73-4, part 2, 3.2.1: 6 to 8 octets).
	MaxPIN = 8
	// MinPIN is the shortest.
	MinPIN = 6
)

// ErrFormat is a text that is not of the format.
var ErrFormat = errors.New("pinrelease: not a text of the format")

// Request is the content of a request text.
type Request struct {
	Boundary  string
	Node      string
	ID        string // a UUIDv7 in the canonical lower-case form (RFC 9562, section 4)
	Ephemeral []byte // SEC1 uncompressed P-384
}

// Answer is the content of an answer text.
type Answer struct {
	Boundary      string
	Releaser      string
	Requester     string
	ID            string
	RequestSHA384 []byte
	Ephemeral     []byte // the releaser's, SEC1 uncompressed P-384
	Sealed        []byte // the nonce, then the ciphertext and tag
}

func appendField(b, f []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(f))) //nolint:gosec // the fields are bounded by maxField
	return append(b, f...)
}

func encode(fields ...[]byte) []byte {
	var b []byte
	for _, f := range fields {
		b = appendField(b, f)
	}
	return b
}

// decode splits a text into exactly n fields. A trailing octet, a short field or an oversized one is refused.
func decode(b []byte, n int) ([][]byte, error) {
	out := make([][]byte, 0, n)
	for range n {
		if len(b) < 4 {
			return nil, ErrFormat
		}
		l := binary.BigEndian.Uint32(b)
		b = b[4:]
		if l > maxField || uint64(l) > uint64(len(b)) {
			return nil, ErrFormat
		}
		out = append(out, b[:l])
		b = b[l:]
	}
	if len(b) != 0 {
		return nil, ErrFormat
	}
	return out, nil
}

// RequestText is the signed text of a request. It checks what it is given, so that a text it makes always parses.
func RequestText(r Request) ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return encode([]byte(RequestDomain), []byte(r.Boundary), []byte(r.Node), []byte(r.ID), r.Ephemeral), nil
}

// ParseRequest reads a request text strictly.
func ParseRequest(text []byte) (Request, error) {
	f, err := decode(text, 5)
	if err != nil {
		return Request{}, err
	}
	if string(f[0]) != RequestDomain {
		return Request{}, ErrFormat
	}
	r := Request{Boundary: string(f[1]), Node: string(f[2]), ID: string(f[3]), Ephemeral: bytes.Clone(f[4])}
	if err := r.check(); err != nil {
		return Request{}, err
	}
	return r, nil
}

func (r Request) check() error {
	if r.Boundary == "" || r.Node == "" {
		return fmt.Errorf("%w: boundary and node are required", ErrFormat)
	}
	if _, err := UUIDv7Time(r.ID); err != nil {
		return err
	}
	if _, err := ecdh.P384().NewPublicKey(r.Ephemeral); err != nil || len(r.Ephemeral) != publicLen {
		return fmt.Errorf("%w: the ephemeral key is not a P-384 point", ErrFormat)
	}
	return nil
}

// AnswerText is the signed text of an answer.
func AnswerText(a Answer) ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	return encode([]byte(AnswerDomain), []byte(a.Boundary), []byte(a.Releaser), []byte(a.Requester), []byte(a.ID),
		a.RequestSHA384, a.Ephemeral, a.Sealed), nil
}

// ParseAnswer reads an answer text strictly.
func ParseAnswer(text []byte) (Answer, error) {
	f, err := decode(text, 8)
	if err != nil {
		return Answer{}, err
	}
	if string(f[0]) != AnswerDomain {
		return Answer{}, ErrFormat
	}
	a := Answer{Boundary: string(f[1]), Releaser: string(f[2]), Requester: string(f[3]), ID: string(f[4]),
		RequestSHA384: bytes.Clone(f[5]), Ephemeral: bytes.Clone(f[6]), Sealed: bytes.Clone(f[7])}
	if err := a.check(); err != nil {
		return Answer{}, err
	}
	return a, nil
}

func (a Answer) check() error {
	if a.Boundary == "" || a.Releaser == "" || a.Requester == "" {
		return fmt.Errorf("%w: boundary and nodes are required", ErrFormat)
	}
	if _, err := UUIDv7Time(a.ID); err != nil {
		return err
	}
	if len(a.RequestSHA384) != digestLen {
		return fmt.Errorf("%w: the request digest is not SHA-384", ErrFormat)
	}
	if _, err := ecdh.P384().NewPublicKey(a.Ephemeral); err != nil || len(a.Ephemeral) != publicLen {
		return fmt.Errorf("%w: the ephemeral key is not a P-384 point", ErrFormat)
	}
	// The nonce (12), at least a 6-octet PIN, the tag (16).
	if len(a.Sealed) < 12+MinPIN+16 || len(a.Sealed) > 12+MaxPIN+16 {
		return fmt.Errorf("%w: the sealed PIN has the wrong length", ErrFormat)
	}
	return nil
}

// Digest is SHA-384 of a text: what the pin-release key signs (ES384, RFC 7518, section 3.4).
func Digest(text []byte) []byte {
	d := sha512.Sum384(text)
	return d[:]
}

// aead is AES-256-GCM under the key that HKDF-SHA384 derives from the shared secret, with the request text as info.
// The nonce is the library's random one (cipher.NewGCMWithRandomNonce), prepended to the ciphertext.
func aead(shared, requestText []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha512.New384, shared, nil, string(requestText), keyLen)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// Seal seals a PIN to the ephemeral key of a request: a fresh P-384 key of the releaser, ECDH with the request's key,
// HKDF-SHA384 and AES-256-GCM, with the request text as info and as additional data. It returns the releaser's
// public key and the sealed PIN. The caller is a card driver that holds the PIN.
func Seal(pin, requestText []byte) (releaserPublic, sealed []byte, err error) {
	if len(pin) < MinPIN || len(pin) > MaxPIN {
		return nil, nil, errors.New("pinrelease: the PIN has the wrong length")
	}
	r, err := ParseRequest(requestText)
	if err != nil {
		return nil, nil, err
	}
	peer, err := ecdh.P384().NewPublicKey(r.Ephemeral)
	if err != nil {
		return nil, nil, err
	}
	own, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err := own.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	defer clear(shared)
	g, err := aead(shared, requestText)
	if err != nil {
		return nil, nil, err
	}
	return own.PublicKey().Bytes(), g.Seal(nil, nil, pin, requestText), nil //nolint:gosec // G407: the nonce is the library's random one (NewGCMWithRandomNonce), not a constant
}

// Open opens a sealed PIN with the one-time key of the request. It fails for another request's key, another request
// text, or a changed octet. The caller wipes the PIN.
func Open(own *ecdh.PrivateKey, requestText, releaserPublic, sealed []byte) ([]byte, error) {
	r, err := ParseRequest(requestText)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.Ephemeral, own.PublicKey().Bytes()) {
		return nil, errors.New("pinrelease: the request is not of this one-time key")
	}
	peer, err := ecdh.P384().NewPublicKey(releaserPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: the releaser's key is not a P-384 point", ErrFormat)
	}
	shared, err := own.ECDH(peer)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	g, err := aead(shared, requestText)
	if err != nil {
		return nil, err
	}
	pin, err := g.Open(nil, nil, sealed, requestText)
	if err != nil {
		return nil, errors.New("pinrelease: the sealed PIN does not open")
	}
	if len(pin) < MinPIN || len(pin) > MaxPIN {
		clear(pin)
		return nil, errors.New("pinrelease: the PIN has the wrong length")
	}
	return pin, nil
}

// NewID returns a request id: a UUIDv7 (RFC 9562, section 5.7) of the time given, with 74 random bits and no counter.
// The time is what freshness is checked against, so it is the caller's clock exactly and not moved forward by an
// earlier id, as a monotonic generator would.
func NewID(at time.Time) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[6:]); err != nil {
		return "", err
	}
	ms := uint64(at.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	b[6] = 0x70 | b[6]&0x0f // version 7
	b[8] = 0x80 | b[8]&0x3f // variant 10
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, c := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexd[c>>4], hexd[c&0x0f])
	}
	return string(out), nil
}

// UUIDv7Time reads the time of a UUIDv7 in the canonical lower-case text form (RFC 9562, sections 4 and 5.7): 48
// bits of Unix milliseconds, version 7, variant 10. Any other form is refused.
func UUIDv7Time(id string) (time.Time, error) {
	bad := fmt.Errorf("%w: the request id is not a UUIDv7", ErrFormat)
	if len(id) != 36 {
		return time.Time{}, bad
	}
	var raw [16]byte
	j := 0
	for i := 0; i < len(id); i++ {
		c := id[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return time.Time{}, bad
			}
			continue
		}
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return time.Time{}, bad
		}
		raw[j/2] |= v << (4 * (1 - j%2))
		j++
	}
	if raw[6]>>4 != 7 || raw[8]>>6 != 2 {
		return time.Time{}, bad
	}
	var ms uint64
	for _, b := range raw[:6] {
		ms = ms<<8 | uint64(b)
	}
	return time.UnixMilli(int64(ms)).UTC(), nil
}
