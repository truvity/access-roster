// Package content checks what key@ is asked to sign (ADR 0006, "Keys sign in place"): a token purpose signs only
// a JWS signing input, and the audit log purpose only a checkpoint body. A mistake in a parser here refuses a
// signature; it never signs the wrong thing.
package content

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxLen bounds the content of one signature.
const MaxLen = 64 << 10

// ErrContent is the one error of this package: it names a field by path, never a value.
type ErrContent struct{ Path string }

func (e *ErrContent) Error() string { return "content: refused at " + e.Path }

func refuse(path string) error { return &ErrContent{Path: path} }

// objectMembers reads a JSON text that is exactly one object, and returns its members as raw values. A
// duplicate member name is refused: two parsers would disagree about which one counts (RFC 7515, section 4:
// the Header Parameter names "MUST be unique"; RFC 8259, section 4: names "SHOULD be unique").
func objectMembers(b []byte) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		name, ok := tok.(string)
		if !ok {
			return nil, false
		}
		if _, dup := out[name]; dup {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		out[name] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return out, true
}

func stringMember(m map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := m[name]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// intMember reads a JSON number that is an integer in the range of int64, with no fraction or exponent.
func intMember(m map[string]json.RawMessage, name string) (int64, bool) {
	raw, ok := m[name]
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseInt(string(raw), 10, 64)
	return v, err == nil
}

// JWSSigningInput checks that content is the signing input of a compact JWS (RFC 7515, section 5.1):
// b64url(header) "." b64url(payload), with no padding. The header holds exactly the members alg, kid and typ
// (alg "ES384", kid the key's id, typ "JWT" or "at+jwt", RFC 9068 section 2.1), and the payload is a JSON
// object with a string iss, a string aud and integer iat and exp (RFC 7519, section 4.1) where exp > iat.
func JWSSigningInput(content []byte, keyID string) error {
	if len(content) > MaxLen {
		return refuse("content")
	}
	head, payload, ok := strings.Cut(string(content), ".")
	if !ok || strings.Contains(payload, ".") {
		return refuse("content")
	}
	enc := base64.RawURLEncoding.Strict()
	hb, err := enc.DecodeString(head)
	if err != nil {
		return refuse("content.header")
	}
	pb, err := enc.DecodeString(payload)
	if err != nil {
		return refuse("content.payload")
	}
	h, ok := objectMembers(hb)
	if !ok || len(h) != 3 {
		return refuse("content.header")
	}
	if alg, _ := stringMember(h, "alg"); alg != "ES384" {
		return refuse("content.header.alg")
	}
	if kid, _ := stringMember(h, "kid"); kid == "" || kid != keyID {
		return refuse("content.header.kid")
	}
	if typ, _ := stringMember(h, "typ"); typ != "JWT" && typ != "at+jwt" {
		return refuse("content.header.typ")
	}
	p, ok := objectMembers(pb)
	if !ok {
		return refuse("content.payload")
	}
	if s, ok := stringMember(p, "iss"); !ok || s == "" {
		return refuse("content.payload.iss")
	}
	if s, ok := stringMember(p, "aud"); !ok || s == "" {
		return refuse("content.payload.aud")
	}
	iat, ok := intMember(p, "iat")
	if !ok {
		return refuse("content.payload.iat")
	}
	exp, ok := intMember(p, "exp")
	if !ok || exp <= iat {
		return refuse("content.payload.exp")
	}
	return nil
}

// Checkpoint checks that content is the body of a checkpoint of the C2SP tlog-checkpoint specification: an
// origin line, the tree size in decimal, the root hash in standard base64 (32 bytes), optional extension lines,
// and a newline after the last line. The signed note adds its signature lines after this body, so the body is
// what is signed (C2SP signed-note).
func Checkpoint(content []byte) error {
	if len(content) > MaxLen || !utf8.Valid(content) {
		return refuse("content")
	}
	s := string(content)
	if !strings.HasSuffix(s, "\n") {
		return refuse("content")
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) < 3 {
		return refuse("content")
	}
	for _, l := range lines {
		if l == "" || strings.ContainsAny(l, "\x00\r") {
			return refuse("content")
		}
	}
	// lines[0] is the origin: a non-empty line.
	size := lines[1]
	if size != "0" && (size[0] < '1' || size[0] > '9') {
		return refuse("content.size")
	}
	if n, err := strconv.ParseUint(size, 10, 64); err != nil || strconv.FormatUint(n, 10) != size {
		return refuse("content.size")
	}
	root, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(root) != 32 {
		return refuse("content.root")
	}
	return nil
}
