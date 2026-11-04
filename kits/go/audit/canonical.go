package audit

import (
	"bytes"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// maxSafeInt is 2^53-1, the largest integer a record may carry (0030 "Canonical rules"; RFC 8785 section 3.2.2.3
// takes numbers through IEEE 754 doubles, which hold integers exactly up to this bound).
const maxSafeInt = 1<<53 - 1

// maxDepth bounds the nesting of a value, so a hostile or buggy caller cannot make the walk recurse far.
const maxDepth = 16

// Canonical returns v as RFC 8785 (JCS) canonical JSON.
//
// The allowed types are nil, bool, string, int, int64, []string, []any and map[string]any. A float or any other
// type is refused, and so is an integer outside +-(2^53-1) and a string that is not valid UTF-8: sluis records
// carry no floating point (0030 "Canonical rules"), so the number formatting of RFC 8785 section 3.2.2.3 reduces
// to the decimal digits of an integer.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := canon(&b, v, "", 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func canon(b *bytes.Buffer, v any, path string, depth int) error {
	if depth > maxDepth {
		return refusal.New(connect.CodeInvalidArgument, "bound", path)
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		return writeString(b, x, path)
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
			if err := writeString(b, s, path+"["+strconv.Itoa(i)+"]"); err != nil {
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
			if err := canon(b, e, path+"["+strconv.Itoa(i)+"]", depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		return writeObject(b, x, path, depth)
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

// writeObject writes the members sorted by the UTF-16 code units of their names (RFC 8785 section 3.2.3).
func writeObject(b *bytes.Buffer, m map[string]any, path string, depth int) error {
	type member struct {
		name string
		u16  []uint16
	}
	ms := make([]member, 0, len(m))
	for k := range m {
		if !utf8.ValidString(k) {
			return refusal.New(connect.CodeInvalidArgument, "schema", path)
		}
		ms = append(ms, member{k, utf16.Encode([]rune(k))})
	}
	sort.Slice(ms, func(i, j int) bool { return lessUTF16(ms[i].u16, ms[j].u16) })
	b.WriteByte('{')
	for i, mb := range ms {
		if i > 0 {
			b.WriteByte(',')
		}
		p := path + "." + mb.name
		if path == "" {
			p = mb.name
		}
		if err := writeString(b, mb.name, p); err != nil {
			return err
		}
		b.WriteByte(':')
		if err := canon(b, m[mb.name], p, depth+1); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

func lessUTF16(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

const hexDigits = "0123456789abcdef"

// writeString writes s as a JSON string by RFC 8785 section 3.2.2.2 (which is ECMAScript JSON.stringify): the
// short escapes for backspace, tab, line feed, form feed and carriage return, \" and \\, \u00xx in lower case for
// the other control characters, and every other character as itself in UTF-8.
func writeString(b *bytes.Buffer, s, path string) error {
	if !utf8.ValidString(s) {
		return refusal.New(connect.CodeInvalidArgument, "schema", path)
	}
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
