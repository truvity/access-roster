package handoff

import (
	"encoding/pem"
	"fmt"
	"testing"
)

// The request file holds one armoured block and nothing before it: pem.Decode would skip a line of text ahead of the BEGIN line.
func TestTextBeforeTheRequestBlockIsMalformed(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{0x30, 0x00}})
	if _, err := ReadRequestPEM(block); err != nil {
		t.Fatalf("the block alone is refused: %v", err)
	}
	_, err := ReadRequestPEM(append([]byte("a line of text\n"), block...))
	assertCode(t, err, CodeMalformed)
}

// The answer's certificate file holds the armour first too.
func TestTextBeforeTheAnswerCertificateIsMalformed(t *testing.T) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}})
	_, _, err := parseAnswerCert(append([]byte("text\n"), cert...))
	assertCode(t, err, CodeMalformed)
}

const digestZero = "0000000000000000000000000000000000000000000000000000000000000000"

// A refused result is a whole file: a member it does not define is an error, as for an issued one.
func TestAnUnknownMemberOfARefusedResultIsMalformed(t *testing.T) {
	raw := fmt.Sprintf(`{"handoff":1,"type":"x509-intermediate","request_sha256":"%s","outcome":"refused","reasons":["policy"],"extra":1}`, digestZero)
	_, err := ParseResult([]byte(raw))
	assertCode(t, err, CodeMalformed)
}

// An integer member is within the range RFC 8785 holds exactly: 2^53-1 in either sign and no further.
func TestIntegerMembersAreBoundedToTheSafeRange(t *testing.T) {
	issued := func(seq string) []byte {
		return []byte(fmt.Sprintf(`{"handoff":1,"type":"x509-intermediate","request_sha256":"%s","outcome":"issued",`+
			`"artifacts":[{"name":"a.cert.pem","sha256":"%s"}],"valid_from":"2027-01-31T10:00:00Z","valid_until":"2028-02-29T10:00:00Z",`+
			`"issuer":"%s","trust_sequence":%s}`, digestZero, digestZero, digestZero, seq))
	}
	for _, seq := range []string{"9007199254740992", "9007199254740992000"} {
		_, err := ParseResult(issued(seq))
		assertCode(t, err, CodeMalformed)
	}
	if _, err := ParseResult(issued("9007199254740991")); err != nil {
		t.Errorf("the largest safe integer is refused: %v", err)
	}
}
