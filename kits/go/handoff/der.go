package handoff

import (
	"bytes"
	"encoding/asn1"
	"errors"
)

// A strict reader of DER, for the requests that a certifier reads from someone else (the contract's "The request"). The
// standard library's parser is lenient on purpose (it reads BER lengths of some kinds, ignores what follows the last element
// it expects, and merges what a verifier would read apart), and the contract fixes a code for each fault, in the order of the
// checks: so the request is read here, element by element, and every fault of form is one error.

var errDER = errors.New("handoff: not DER")

// element is one DER element: its class and tag, whether it is constructed, its content and its whole encoding.
type element struct {
	class       int
	tag         int
	constructed bool
	content     []byte
	full        []byte
}

func (e element) is(class, tag int, constructed bool) bool {
	return e.class == class && e.tag == tag && e.constructed == constructed
}

// universal reports whether the element is the universal type with that tag, primitive or constructed as the type is.
func (e element) universal(tag int, constructed bool) bool {
	return e.is(asn1.ClassUniversal, tag, constructed)
}

// readElement reads the first element of b: a one-octet identifier, a definite length in its shortest form, and the content. It
// returns the rest.
func readElement(b []byte) (element, []byte, error) {
	if len(b) < 2 {
		return element{}, nil, errDER
	}
	id := b[0]
	if id&0x1f == 0x1f { // a tag number of more than one octet
		return element{}, nil, errDER
	}
	n, hdr := int(b[1]), 2
	if n >= 0x80 {
		k := n & 0x7f
		if k == 0 || k > 3 || len(b) < 2+k { // indefinite, or a length that no request of 256 KiB has
			return element{}, nil, errDER
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		// The shortest form: no leading zero octet, and long form only from 128.
		if b[2] == 0 || n < 0x80 {
			return element{}, nil, errDER
		}
		hdr = 2 + k
	}
	if n > len(b)-hdr {
		return element{}, nil, errDER
	}
	return element{
		class: int(id >> 6), tag: int(id & 0x1f), constructed: id&0x20 != 0,
		content: b[hdr : hdr+n], full: b[:hdr+n],
	}, b[hdr+n:], nil
}

// readAll reads every element of b, in order.
func readAll(b []byte) ([]element, error) {
	var out []element
	for len(b) > 0 {
		e, rest, err := readElement(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = rest
	}
	return out, nil
}

// readOne reads b as exactly one element and nothing after it.
func readOne(b []byte) (element, error) {
	e, rest, err := readElement(b)
	if err != nil || len(rest) != 0 {
		return element{}, errDER
	}
	return e, nil
}

// oidOf reads an OBJECT IDENTIFIER element.
func oidOf(e element) (asn1.ObjectIdentifier, bool) {
	if !e.universal(asn1.TagOID, false) || len(e.content) == 0 {
		return nil, false
	}
	var oid asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(e.full, &oid); err != nil || len(rest) != 0 {
		return nil, false
	}
	return oid, true
}

// derOrdered reports whether the encodings of the members of a SET OF stand in ascending order (X.690, section 11.6): compared as
// octet strings, the shorter one padded with zero octets.
func derOrdered(members []element) bool {
	for i := 1; i < len(members); i++ {
		if compareDER(members[i-1].full, members[i].full) > 0 {
			return false
		}
	}
	return true
}

func compareDER(a, b []byte) int {
	n := max(len(a), len(b))
	pa, pb := make([]byte, n), make([]byte, n)
	copy(pa, a)
	copy(pb, b)
	return bytes.Compare(pa, pb)
}
