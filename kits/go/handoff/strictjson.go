package handoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
	"unicode/utf8"
)

// object is a JSON object whose members are read one by one. The contract's rules for a JSON file: one UTF-8 object,
// no byte order mark, at most MaxJSON bytes, a member name once, and a member the page does not define is an error.
type object struct {
	m map[string]json.RawMessage
	// at is the place of the object in the file, for a refusal: "" for the file, "evidence" for a member.
	at string
}

// parseObject reads b as exactly one JSON object.
func parseObject(b []byte, at string) (*object, error) {
	if len(b) > MaxJSON {
		return nil, refuse(CodeMalformed, joinAt(at, "size"))
	}
	if bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) || !utf8.Valid(b) {
		return nil, refuse(CodeMalformed, joinAt(at, "encoding"))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, refuse(CodeMalformed, joinAt(at, "object"))
	}
	o := &object{m: map[string]json.RawMessage{}, at: at}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, refuse(CodeMalformed, joinAt(at, "object"))
		}
		name, ok := tok.(string)
		if !ok {
			return nil, refuse(CodeMalformed, joinAt(at, "object"))
		}
		if _, dup := o.m[name]; dup {
			return nil, refuse(CodeMalformed, joinAt(at, "repeated member"))
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, refuse(CodeMalformed, joinAt(at, name))
		}
		o.m[name] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, refuse(CodeMalformed, joinAt(at, "object"))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, refuse(CodeMalformed, joinAt(at, "trailing data"))
	}
	return o, nil
}

func joinAt(at, name string) string {
	if at == "" {
		return name
	}
	return at + "." + name
}

// take removes a member and returns its raw value.
func (o *object) take(name string) (json.RawMessage, bool) {
	raw, ok := o.m[name]
	delete(o.m, name)
	return raw, ok
}

// done refuses a member that was not taken: the contract defines no other.
func (o *object) done() error {
	if len(o.m) > 0 {
		return refuse(CodeMalformed, joinAt(o.at, "unknown member"))
	}
	return nil
}

// str takes a string member. required says whether its absence is a refusal.
func (o *object) str(name string, required bool) (string, bool, error) {
	raw, ok := o.take(name)
	if !ok {
		if required {
			return "", false, refuse(CodeMalformed, joinAt(o.at, name))
		}
		return "", false, nil
	}
	if len(raw) == 0 || raw[0] != '"' {
		return "", false, refuse(CodeMalformed, joinAt(o.at, name))
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, refuse(CodeMalformed, joinAt(o.at, name))
	}
	return s, true, nil
}

// maxSafeInteger is 2^53-1, the bound of an integer member: the range that the canonical form of RFC 8785 holds exactly (the contract,
// "JSON files").
const maxSafeInteger = 9007199254740991

// integer takes an integer member: digits only, no fraction and no exponent (contract, "JSON files").
func (o *object) integer(name string, required bool) (int64, bool, error) {
	raw, ok := o.take(name)
	if !ok {
		if required {
			return 0, false, refuse(CodeMalformed, joinAt(o.at, name))
		}
		return 0, false, nil
	}
	v, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || v > maxSafeInteger || v < -maxSafeInteger {
		return 0, false, refuse(CodeMalformed, joinAt(o.at, name))
	}
	return v, true, nil
}

// list takes a member that is a list and returns the raw items.
func (o *object) list(name string, required bool) ([]json.RawMessage, bool, error) {
	raw, ok := o.take(name)
	if !ok {
		if required {
			return nil, false, refuse(CodeMalformed, joinAt(o.at, name))
		}
		return nil, false, nil
	}
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false, refuse(CodeMalformed, joinAt(o.at, name))
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false, refuse(CodeMalformed, joinAt(o.at, name))
	}
	return items, true, nil
}

// object takes a member that is an object.
func (o *object) object(name string, required bool) (*object, bool, error) {
	raw, ok := o.take(name)
	if !ok {
		if required {
			return nil, false, refuse(CodeMalformed, joinAt(o.at, name))
		}
		return nil, false, nil
	}
	sub, err := parseObject(raw, joinAt(o.at, name))
	if err != nil {
		return nil, false, err
	}
	return sub, true, nil
}

// version reads the contract version, which comes before anything else: a receiver that does not know the version
// reads nothing else in the message (contract, "Versioning").
func (o *object) version() error {
	raw, ok := o.take("handoff")
	if !ok {
		return refuse(CodeMalformed, "handoff")
	}
	v, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return refuse(CodeMalformed, "handoff")
	}
	if v != Version {
		return refuse(CodeVersionUnsupported, "handoff")
	}
	return nil
}

// timeFormat is a time of the contract: YYYY-MM-DDThh:mm:ssZ in UTC, whole seconds.
const timeFormat = "2006-01-02T15:04:05Z"

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(timeFormat, s)
	if err != nil || t.Format(timeFormat) != s {
		return time.Time{}, false
	}
	return t, true
}

// isDigest reports whether s is a SHA-256 in lower-case hexadecimal.
func isDigest(s string) bool { return isLowerHex(s, 64) }

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
