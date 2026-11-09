package pkgs

import (
	"bytes"
	"errors"
	"fmt"
)

// RPMMeta is the main header of an .rpm, for the code that writes repository metadata (tools/release/repo): the tags as rpm
// numbers them, and where the header lies in the file. It is not a check; ReadPackage is, and it also holds the payload to the
// header.
type RPMMeta struct {
	h rpmHeader
	// HeaderStart and HeaderEnd are the byte range of the main header in the file (the `header-range` of a repository's primary
	// metadata, which lets a client fetch the header alone).
	HeaderStart, HeaderEnd int64
	// PayloadSize is the size of the compressed payload, the `archive` size of the metadata.
	PayloadSize int64
}

// ReadRPMMeta reads the lead, the signature header and the main header of an .rpm.
func ReadRPMMeta(raw []byte) (*RPMMeta, error) {
	if len(raw) < 96 || !bytes.Equal(raw[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return nil, errors.New("not an rpm")
	}
	_, rest, err := readRPMHeader(raw[96:], true)
	if err != nil {
		return nil, fmt.Errorf("signature header: %w", err)
	}
	h, payload, err := readRPMHeader(rest, false)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	return &RPMMeta{h: h, HeaderStart: int64(len(raw) - len(rest)), HeaderEnd: int64(len(raw) - len(payload)), PayloadSize: int64(len(payload))}, nil
}

// Str is a string tag, "" when the tag is absent or not a string.
func (m *RPMMeta) Str(tag uint32) string { return m.h.str(tag) }

// Strs is a string-array tag.
func (m *RPMMeta) Strs(tag uint32) []string { return m.h.strs(tag) }

// U32s is an integer tag of 16 or 32 bits.
func (m *RPMMeta) U32s(tag uint32) []uint32 { return m.h.u32s(tag) }

// U64s is an integer tag of 64 bits.
func (m *RPMMeta) U64s(tag uint32) []uint64 { return m.h.u64s(tag) }
