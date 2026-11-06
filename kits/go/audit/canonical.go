package audit

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/gowebpki/jcs"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// maxSafeInt is 2^53-1, the largest integer a record may carry (0030 "Canonical rules"; RFC 8785 section 3.2.2.3
// takes numbers through IEEE 754 doubles, which hold integers exactly up to this bound).
const maxSafeInt = 1<<53 - 1

// maxDepth bounds the nesting of a value, so a hostile or buggy caller cannot make the walk recurse far.
const maxDepth = 16

// Canonical returns v as RFC 8785 (JCS) canonical JSON.
//
// The canonical form itself (member order by UTF-16 code units, string escapes, number text, no insignificant
// whitespace, and the refusal of a duplicate member name) comes from github.com/gowebpki/jcs, which takes JSON
// text. What this function adds is the sluis profile, checked while the value is written as plain JSON text for
// the library (REQ-SEC-018: no home-made code for an external standard).
//
// The allowed types are nil, bool, string, int, int64, []string, []any and map[string]any. A float or any other
// type is refused, and so is an integer outside +-(2^53-1), a string or member name that is not valid UTF-8, and
// a value nested deeper than maxDepth: sluis records carry no floating point (0030 "Canonical rules"), so the
// library never sees a number other than an integer. A nil slice or map is the empty array or object.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := profileJSON(&b, v, "", 0); err != nil {
		return nil, err
	}
	out, err := jcs.Transform(b.Bytes())
	if err != nil {
		// The profile check leaves the library nothing it can refuse; if it does, the value has no canonical form.
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "")
	}
	return out, nil
}

// profileJSON checks v against the sluis profile and writes it as JSON text, in no particular member order and
// with no particular escapes: the library canonicalises both. Members are visited in byte order of their names so
// that the first refusal does not depend on the map's iteration order.
func profileJSON(b *bytes.Buffer, v any, path string, depth int) error {
	if depth > maxDepth {
		return refusal.New(connect.CodeInvalidArgument, "bound", path)
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		return writeText(b, x, path)
	case int:
		return writeInt(b, int64(x), path)
	case int64:
		return writeInt(b, x, path)
	case []string:
		b.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeText(b, s, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := profileJSON(b, e, path+"["+strconv.Itoa(i)+"]", depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		b.WriteByte('{')
		for i, k := range slices.Sorted(maps.Keys(x)) {
			if i > 0 {
				b.WriteByte(',')
			}
			p := path + "." + k
			if path == "" {
				p = k
			}
			if !utf8.ValidString(k) {
				return refusal.New(connect.CodeInvalidArgument, "schema", path)
			}
			if err := writeText(b, k, p); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := profileJSON(b, x[k], p, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		// A float, a map of another type, a struct: none has a canonical form in a sluis record.
		return refusal.New(connect.CodeInvalidArgument, "schema", path)
	}
	return nil
}

func writeInt(b *bytes.Buffer, n int64, path string) error {
	if n > maxSafeInt || n < -maxSafeInt {
		return refusal.New(connect.CodeInvalidArgument, "bound", path)
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

// writeText writes s as a JSON string. A string that is not valid UTF-8 is refused: encoding/json would replace
// the bad bytes with U+FFFD, and two different records would then share one canonical form.
func writeText(b *bytes.Buffer, s, path string) error {
	if !utf8.ValidString(s) {
		return refusal.New(connect.CodeInvalidArgument, "schema", path)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return refusal.New(connect.CodeInvalidArgument, "schema", path)
	}
	b.Write(raw)
	return nil
}
