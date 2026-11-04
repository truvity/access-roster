package signedconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// seqLimit: seq is below 2^53, so that a JSON number holds it exactly in every reader.
const seqLimit = 1 << 53

// signatureLen is an ECDSA P-384 signature, r then s, 48 bytes each (RFC 7518, section 3.4).
const signatureLen = 96

// b64 is base64url without padding (RFC 7515, section 2). Strict refuses a final character whose unused bits are
// not zero, as the Rust reader does.
var b64 = base64.RawURLEncoding.Strict()

// decode64 decodes base64url strictly. encoding/base64 skips a carriage return and a line feed anywhere in its input,
// which the Rust reader refuses, so a byte outside the alphabet is refused here before the decoder sees it.
func decode64(s string) ([]byte, error) {
	for i := range len(s) {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return nil, errors.New("not base64url")
		}
	}
	return b64.DecodeString(s)
}

// Publisher is a publisher key of the bootstrap file: the trust anchor of config.
type Publisher struct {
	KID     string
	Key     *ecdsa.PublicKey // an EC P-384 key
	CoSigns []string         // kind names whose documents need this key's signature as well
}

// Refused is a document that was refused: the step of signed-config.md at which it failed and the rule. It never
// holds a value of the document.
type Refused struct {
	Step int
	Rule string
}

func (r *Refused) Error() string { return fmt.Sprintf("signed config: step %d: %s", r.Step, r.Rule) }

func refuse(step int, rule string) error { return &Refused{Step: step, Rule: rule} }

// Verified is a document whose signatures verified under the pinned keys.
type Verified struct {
	Seq     uint64
	Payload []byte   // the reviewed file, byte for byte
	Digest  [48]byte // the SHA-384 of the payload: what an audit fact names
}

type signature struct {
	protected, signature string
	kid                  string
	seq                  uint64
}

// MaxDocument is the largest signed document the kit reads: 3 MiB, the 2 MiB of the largest config service limit known
// (signed-config.md, "The payload") a third larger in base64url, with room for the signatures. store@ refuses to hold a
// larger one and the typed call (kits/go/store) reads no more, so a store@ that is the adversary cannot make a reader
// buffer without bound.
const MaxDocument = 3 << 20

// Verify takes steps 1 to 4 of signed-config.md for the document doc of the config kind `kind` (its registry name, such
// as "KeyPlan") under the pinned publishers. Nothing before the signatures reads the payload. The sequence number
// (step 5) is Sequencer's, and the payload (step 6) is the caller's.
//
// The error is a *Refused for a document that fails a step. A `kind` that is not the name of a config kind of the
// registry is an error of the caller and not a refusal: it must never skip the check of the co-signers.
func Verify(doc []byte, kind string, publishers []Publisher) (*Verified, error) {
	if k, ok := registry.KindByName(kind); !ok || k.Class != "config" {
		return nil, fmt.Errorf("signedconfig: %q is not the name of a config kind", kind)
	}
	if len(doc) > MaxDocument {
		return nil, refuse(1, "the document is larger than the bound")
	}
	// Step 1: structure. The general JSON serialisation; the compact and the flattened ones, an unprotected
	// `header` and any other member are all refused here.
	top, ok := parseObject(doc)
	if !ok {
		return nil, refuse(1, "not a JSON object in the general serialisation")
	}
	payload, okP := top.str("payload")
	sigs, okS := top.arr("signatures")
	if !top.exactly("payload", "signatures") || !okP || !okS {
		return nil, refuse(1, "needs a payload and signatures, and no other member")
	}
	if len(sigs) == 0 {
		return nil, refuse(1, "needs at least one signature")
	}
	type pair struct{ protected, signature string }
	parsed := make([]pair, 0, len(sigs))
	for _, s := range sigs {
		o, isObj := s.(*object)
		if !isObj || !o.exactly("protected", "signature") {
			return nil, refuse(1, "a signature has protected and signature, and no other member")
		}
		p, ok1 := o.str("protected")
		g, ok2 := o.str("signature")
		if !ok1 || !ok2 {
			return nil, refuse(1, "a signature has protected and signature, and no other member")
		}
		parsed = append(parsed, pair{p, g})
	}

	// Step 2: headers.
	signatures := make([]signature, 0, len(parsed))
	for _, p := range parsed {
		raw, err := decode64(p.protected)
		if err != nil {
			return nil, refuse(2, "the protected header is not base64url JSON")
		}
		h, ok := parseObject(raw)
		if !ok {
			return nil, refuse(2, "the protected header is not base64url JSON")
		}
		alg, okA := h.str("alg")
		kid, okK := h.str("kid")
		seqNum, okN := h.num("seq")
		named, okD := h.str("kind")
		if !h.exactly("alg", "kid", "seq", "kind") || !okA || !okK || !okN || !okD {
			return nil, refuse(2, "the protected header needs alg, kid, seq and kind, and no other member")
		}
		if alg != "ES384" {
			return nil, refuse(2, "alg must be ES384")
		}
		// The signed header names the kind, so a document of one kind cannot be served as another's.
		if named != kind {
			return nil, refuse(2, "kind is not the kind of the document asked for")
		}
		seq, err := strconv.ParseUint(seqNum, 10, 64)
		if err != nil || seq < 1 || seq >= seqLimit {
			return nil, refuse(2, "seq must be a positive integer below 2^53")
		}
		signatures = append(signatures, signature{protected: p.protected, signature: p.signature, kid: kid, seq: seq})
	}
	seq := signatures[0].seq
	for _, s := range signatures {
		if s.seq != seq {
			return nil, refuse(2, "the signatures carry different seq")
		}
	}

	// Step 3: keys.
	used := map[string]bool{}
	keys := make([]Publisher, 0, len(signatures))
	for _, s := range signatures {
		i := slices.IndexFunc(publishers, func(p Publisher) bool { return p.KID == s.kid })
		if i < 0 {
			return nil, refuse(3, "a kid is not in the bootstrap file")
		}
		if used[s.kid] {
			return nil, refuse(3, "a kid is used twice")
		}
		used[s.kid] = true
		keys = append(keys, publishers[i])
	}

	// Step 4: signatures, over the bytes as they were received (RFC 7515, section 5.2: the signing input is
	// ASCII(protected) "." payload, which is the compact form go-jose reads).
	for i, s := range signatures {
		if raw, err := decode64(s.signature); err != nil || len(raw) != signatureLen {
			return nil, refuse(4, "a signature is not 96 bytes of r then s")
		}
		if keys[i].Key == nil {
			return nil, refuse(4, "a signature does not verify")
		}
		jws, err := jose.ParseSignedCompact(s.protected+"."+payload+"."+s.signature, []jose.SignatureAlgorithm{jose.ES384})
		if err != nil {
			// The payload is not base64url, or the header is not one go-jose reads.
			return nil, refuse(4, "a signature does not verify")
		}
		if _, err := jws.Verify(keys[i].Key); err != nil {
			return nil, refuse(4, "a signature does not verify")
		}
	}
	// One publisher key without `co_signs`, and every key whose `co_signs` names this kind.
	if !slices.ContainsFunc(keys, func(p Publisher) bool { return len(p.CoSigns) == 0 }) {
		return nil, refuse(4, "no publisher key signed it")
	}
	if slices.ContainsFunc(publishers, func(p Publisher) bool { return slices.Contains(p.CoSigns, kind) && !used[p.KID] }) {
		return nil, refuse(4, "a co-signer's signature is missing")
	}
	body, err := decode64(payload)
	if err != nil {
		return nil, refuse(4, "the payload is not base64url")
	}
	return &Verified{Seq: seq, Payload: body, Digest: sha512.Sum384(body)}, nil
}

// object is a JSON object read with the one rule encoding/json does not have: a duplicate key is an error, at any
// depth. Its members are kept in order.
type object struct {
	keys []string
	vals []any // *object, []any, json.Number, string, bool or nil
}

func (o *object) get(k string) (any, bool) {
	i := slices.Index(o.keys, k)
	if i < 0 {
		return nil, false
	}
	return o.vals[i], true
}

// exactly reports whether the keys of the object are exactly names, in any order.
func (o *object) exactly(names ...string) bool {
	if len(o.keys) != len(names) {
		return false
	}
	for _, n := range names {
		if !slices.Contains(o.keys, n) {
			return false
		}
	}
	return true
}

func (o *object) str(k string) (string, bool) {
	v, _ := o.get(k)
	s, ok := v.(string)
	return s, ok
}

func (o *object) arr(k string) ([]any, bool) {
	v, _ := o.get(k)
	a, ok := v.([]any)
	return a, ok
}

// num returns the text of a number member. A number that is not a plain non-negative integer fails to parse as one
// where it is used, which is how a float, an exponent or a negative number is refused.
func (o *object) num(k string) (string, bool) {
	v, _ := o.get(k)
	n, ok := v.(json.Number)
	return string(n), ok
}

// parseObject reads bytes as one JSON object, and nothing after it. Bytes that are not UTF-8 are refused, as the
// Rust reader does; encoding/json would replace them.
func parseObject(b []byte) (*object, bool) {
	if !utf8.Valid(b) || loneSurrogate(b) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := readValue(d)
	if err != nil {
		return nil, false
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	o, ok := v.(*object)
	return o, ok
}

// loneSurrogate reports whether the JSON text has a \u escape of a surrogate that is not half of a pair. The Rust reader
// refuses it; encoding/json would read it as U+FFFD, and the two would then disagree about a document.
func loneSurrogate(b []byte) bool {
	hex4 := func(i int) (rune, bool) {
		if i+6 > len(b) || b[i] != '\\' || b[i+1] != 'u' {
			return 0, false
		}
		var r rune
		for _, c := range b[i+2 : i+6] {
			switch {
			case c >= '0' && c <= '9':
				r = r<<4 | rune(c-'0')
			case c >= 'a' && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case c >= 'A' && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if i+1 < len(b) && b[i+1] == 'u' {
			r, ok := hex4(i)
			switch {
			case ok && r >= 0xD800 && r <= 0xDBFF:
				low, ok2 := hex4(i + 6)
				if !ok2 || low < 0xDC00 || low > 0xDFFF {
					return true
				}
				i += 11
			case ok && r >= 0xDC00 && r <= 0xDFFF:
				return true
			default:
				i += 5
			}
			continue
		}
		i++ // the escaped character: \\ and \" are skipped as a pair
	}
	return false
}

// maxDepth bounds the nesting that the reader follows. A signed document is flat; the bound only keeps the stack.
const maxDepth = 64

func readValue(d *json.Decoder) (any, error) { return readAt(d, 0) }

func readAt(d *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("too deep")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := t.(json.Delim)
	if !isDelim {
		return t, nil // string, json.Number, bool or nil
	}
	switch delim {
	case '{':
		o := &object{}
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok {
				return nil, errors.New("key")
			}
			if slices.Contains(o.keys, k) {
				return nil, errors.New("duplicate key")
			}
			v, err := readAt(d, depth+1)
			if err != nil {
				return nil, err
			}
			o.keys = append(o.keys, k)
			o.vals = append(o.vals, v)
		}
		if _, err := d.Token(); err != nil { // the closing brace
			return nil, err
		}
		return o, nil
	case '[':
		a := []any{}
		for d.More() {
			v, err := readAt(d, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		if _, err := d.Token(); err != nil { // the closing bracket
			return nil, err
		}
		return a, nil
	}
	return nil, errors.New("unexpected delimiter")
}
