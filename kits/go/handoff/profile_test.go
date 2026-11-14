package handoff

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"
)

func tlv(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	if len(body) < 0x80 {
		return append([]byte{tag, byte(len(body) & 0x7f)}, body...)
	}
	if len(body) < 0x100 {
		return append([]byte{tag, 0x81, byte(len(body) & 0xff)}, body...)
	}
	return append([]byte{tag, 0x82, byte(len(body) >> 8 & 0xff), byte(len(body) & 0xff)}, body...)
}

func general(tag byte, b []byte) []byte { return tlv(0x30, tlv(tag, b)) } // a subtree: the base alone

// An excluded subtree is the base alone: a minimum or a maximum after it, or a base that is not a primitive iPAddress, is not
// the every-address form, whatever else a lenient decoder would let through.
func TestNameConstraintsAreTheContractsAndNothingElse(t *testing.T) {
	dns := general(0x82, []byte("dev.example.org"))
	uri := general(0x86, []byte(".example.org"))
	zero8, zero32 := bytes.Repeat([]byte{0}, 8), bytes.Repeat([]byte{0}, 32)
	v4, v6 := general(0x87, zero8), general(0x87, zero32)
	nc := func(permitted []byte, excluded ...[]byte) []byte {
		parts := [][]byte{}
		if permitted != nil {
			parts = append(parts, tlv(0xa0, permitted))
		}
		if len(excluded) > 0 {
			parts = append(parts, tlv(0xa1, excluded...))
		}
		return tlv(0x30, parts...)
	}
	withMin := tlv(0x30, tlv(0x87, zero8), tlv(0x80, []byte{0}))
	withMax := tlv(0x30, tlv(0x87, zero8), tlv(0x81, []byte{5}))
	for name, tc := range map[string]struct {
		der []byte
		ok  bool
	}{
		"a DNS name and nothing excluded":     {nc(dns), true},
		"a DNS name and a URI constraint":     {nc(append(bytes.Clone(dns), uri...)), true},
		"every address excluded":              {nc(dns, v4, v6), true},
		"every address excluded, other order": {nc(dns, v6, v4), true},
		"only IPv4 excluded":                  {nc(dns, v4), false},
		"every address excluded twice":        {nc(dns, v4, v4, v6), false},
		"a minimum of 0 stated":               {nc(dns, withMin, v6), false},
		"a maximum":                           {nc(dns, withMax, v6), false},
		"a minimum on a permitted DNS name":   {nc(tlv(0x30, tlv(0x82, []byte("dev.example.org")), tlv(0x80, []byte{0}))), false},
		"a constructed base":                  {nc(dns, general(0xa7, zero8), v6), false},
		"a trailing byte":                     {append(nc(dns), 0), false},
		"no permitted subtree":                {nc(nil, v4, v6), false},
		"an empty permitted list":             {nc([]byte{}), false},
		"a permitted IP range":                {nc(append(bytes.Clone(dns), general(0x87, []byte{10, 0, 0, 0, 255, 0, 0, 0})...)), false},
		"an e-mail name":                      {nc(general(0x81, []byte("example.org"))), false},
		"a directory name":                    {nc(tlv(0x30, tlv(0xa4, tlv(0x30)))), false},
		"a DNS name in upper case":            {nc(general(0x82, []byte("Dev.example.org"))), false},
		"a DNS name with a leading period":    {nc(general(0x82, []byte(".example.org"))), false},
		"a non-zero excluded address":         {nc(dns, general(0x87, append([]byte{10}, make([]byte, 7)...)), v6), false},
		"a 4-octet excluded address":          {nc(dns, general(0x87, make([]byte, 4)), v6), false},
	} {
		if got := NameConstraintsOK(tc.der); got != tc.ok {
			t.Errorf("%s: NameConstraintsOK = %v, want %v", name, got, tc.ok)
		}
	}
}

// The key usage is a named bit string in DER with keyCertSign, and cRLSign and digitalSignature besides; the extended key usage is
// serverAuth, clientAuth or both, each once.
func TestKeyUsageAndExtendedKeyUsageValues(t *testing.T) {
	bits := func(b byte, unused byte) []byte { return tlv(0x03, []byte{unused}, []byte{b}) }
	for name, tc := range map[string]struct {
		v  []byte
		ok bool
	}{
		"keyCertSign and cRLSign":         {bits(0x06, 1), true},
		"keyCertSign alone":               {bits(0x04, 2), true},
		"with digitalSignature":           {bits(0x86, 1), true},
		"cRLSign alone":                   {bits(0x02, 1), false},
		"keyCertSign and keyEncipherment": {bits(0x24, 2), false},
		"keyCertSign and keyAgreement":    {bits(0x0c, 2), false},
		"a trailing zero bit":             {bits(0x04, 1), false}, // not DER: the bit string is not trimmed
		"unused bits that are set":        {bits(0x05, 2), false},
		"empty":                           {tlv(0x03, []byte{0}), false},
		"not a bit string":                {tlv(0x04, []byte{0x06}), false},
	} {
		if got := keyUsageOK(tc.v); got != tc.ok {
			t.Errorf("key usage, %s: %v, want %v", name, got, tc.ok)
		}
	}
	oid := func(o asn1.ObjectIdentifier) []byte { b, _ := asn1.Marshal(o); return b }
	for name, tc := range map[string]struct {
		v  []byte
		ok bool
	}{
		"serverAuth and clientAuth":  {tlv(0x30, oid(oidServerAuth), oid(oidClientAuth)), true},
		"clientAuth and serverAuth":  {tlv(0x30, oid(oidClientAuth), oid(oidServerAuth)), true},
		"serverAuth":                 {tlv(0x30, oid(oidServerAuth)), true},
		"serverAuth twice":           {tlv(0x30, oid(oidServerAuth), oid(oidServerAuth)), false},
		"empty":                      {tlv(0x30), false},
		"any extended key usage":     {tlv(0x30, oid(asn1.ObjectIdentifier{2, 5, 29, 37, 0})), false},
		"code signing beside server": {tlv(0x30, oid(oidServerAuth), oid(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3})), false},
		"a trailing byte":            {append(tlv(0x30, oid(oidServerAuth)), 0), false},
		"an octet string":            {tlv(0x04, oid(oidServerAuth)), false},
	} {
		if got := ekuOK(tc.v); got != tc.ok {
			t.Errorf("extended key usage, %s: %v, want %v", name, got, tc.ok)
		}
	}
}

// The strict reader refuses what a lenient one reads: a length that is not in its shortest form, an indefinite length, a tag of
// more than one octet, a length past the end, and bytes after the element.
func TestTheStrictReaderIsStrict(t *testing.T) {
	for name, b := range map[string][]byte{
		"a long length for a short content": {0x30, 0x81, 0x01, 0x00},
		"a long length with a leading zero": {0x30, 0x82, 0x00, 0x80},
		"an indefinite length":              {0x30, 0x80, 0x00, 0x00},
		"a high tag number":                 {0x1f, 0x81, 0x01, 0x00},
		"a length past the end":             {0x30, 0x05, 0x00},
		"a single octet":                    {0x30},
		"empty":                             nil,
	} {
		if _, _, err := readElement(b); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, err := readOne([]byte{0x05, 0x00, 0x00}); err == nil {
		t.Error("a byte after the element")
	}
	if e, err := readOne(append([]byte{0x30, 0x81, 0x80}, make([]byte, 0x80)...)); err != nil || len(e.content) != 0x80 {
		t.Errorf("a length of 128 in the long form: %v", err)
	}
}

// A request whose bytes are right in every way but one is refused with the code of that fault, in the order of the checks: the
// fault of form before the key, the key before the signature.
func TestRequestChecksComeInTheContractsOrder(t *testing.T) {
	key := newKey(t)
	der := makeRequest(t, key, testSpec())
	if _, err := VerifyRequest(der); err != nil {
		t.Fatal(err)
	}
	// One byte of the signature changed: possession.
	bad := bytes.Clone(der)
	bad[len(bad)-3] ^= 0xff
	_, err := VerifyRequest(bad)
	assertCode(t, err, "possession-invalid")
	// Version 1: malformed, though the signature no longer verifies either.
	v1 := bytes.Clone(der)
	i := bytes.Index(v1, []byte{0x02, 0x01, 0x00})
	v1[i+2] = 0x01
	_, err = VerifyRequest(v1)
	assertCode(t, err, CodeMalformed)
	// Trailing bytes after the request, and a request cut short.
	_, err = VerifyRequest(append(bytes.Clone(der), 0))
	assertCode(t, err, CodeMalformed)
	_, err = VerifyRequest(der[:len(der)-1])
	assertCode(t, err, CodeMalformed)
}

// csrWithExtensions is a request signed by key whose extensionRequest holds the given extension elements, written as they are.
func csrWithExtensions(t *testing.T, key *ecdsa.PrivateKey, exts ...[]byte) []byte {
	t.Helper()
	spki := spkiOf(t, &key.PublicKey)
	subject, err := commonNameName("x")
	if err != nil {
		t.Fatal(err)
	}
	attr := tlv(0x30, mustDER(t, oidExtensionRequest), tlv(0x31, tlv(0x30, exts...)))
	info := tlv(0x30, []byte{0x02, 0x01, 0x00}, subject, spki, tlv(0xa0, attr))
	d := sha512.Sum384(info)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := AssembleCSR(info, sig)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func extElement(oid asn1.ObjectIdentifier, critical *bool, value []byte, t *testing.T) []byte {
	parts := [][]byte{mustDER(t, oid)}
	if critical != nil {
		b := byte(0)
		if *critical {
			b = 0xff
		}
		parts = append(parts, tlv(0x01, []byte{b}))
	}
	return tlv(0x30, append(parts, tlv(0x04, value))...)
}

// The shape of an extension is its identifier, its flag (TRUE, or left out: DER leaves out FALSE) and its octet string; an
// extension that stands twice is a refusal of content (`policy`), and a flag written as FALSE a refusal of form (`malformed`).
func TestExtensionsOfARequest(t *testing.T) {
	key := newKey(t)
	good, err := requestedExtensions(testSpec().Constraints)
	if err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	var elems [][]byte
	for _, e := range good {
		c := e.Critical
		elems = append(elems, extElement(e.Id, map[bool]*bool{true: &yes, false: nil}[c], e.Value, t))
	}
	if r, err := ParseRequest(csrWithExtensions(t, key, elems...)); err != nil || CheckRequestProfile(r) != nil {
		t.Fatalf("the extensions sluis writes: %v", err)
	}
	// The flag of the extended key usage written as FALSE.
	falseFlag := append(slices.Clone(elems[:3]), extElement(oidExtKeyUsage, &no, good[3].Value, t))
	_, err = ParseRequest(csrWithExtensions(t, key, falseFlag...))
	assertCode(t, err, CodeMalformed)
	// An extension twice.
	twice := append(slices.Clone(elems), elems[0])
	r, err := ParseRequest(csrWithExtensions(t, key, twice...))
	if err != nil {
		t.Fatal(err)
	}
	assertCode(t, CheckRequestProfile(r), "policy")
	// The extended key usage critical, and missing.
	crit := append(slices.Clone(elems[:3]), extElement(oidExtKeyUsage, &yes, good[3].Value, t))
	r, _ = ParseRequest(csrWithExtensions(t, key, crit...))
	assertCode(t, CheckRequestProfile(r), "policy")
	r, _ = ParseRequest(csrWithExtensions(t, key, elems[:3]...))
	assertCode(t, CheckRequestProfile(r), "policy")
	// Each of basic constraints, key usage and name constraints must be critical: left out (not critical) it is a policy refusal, the
	// same as the extended key usage above. Each case clears the flag of one of the three and keeps the others.
	for i := 0; i < 3; i++ {
		clear := slices.Clone(elems)
		clear[i] = extElement(good[i].Id, nil, good[i].Value, t)
		r, err := ParseRequest(csrWithExtensions(t, key, clear...))
		if err != nil {
			t.Fatalf("extension %s not critical: parse: %v", good[i].Id, err)
		}
		assertCode(t, CheckRequestProfile(r), "policy")
	}
}

// The files of a request are checked in the contract's order: a request that is not well formed is `malformed` before its digest is
// compared, and a digest that is not the request's is `request-mismatch` before the key is read.
func TestRequestFilesComeInTheContractsOrder(t *testing.T) {
	key := newKey(t)
	der := makeRequest(t, key, testSpec())
	proofFor := func(digestOf []byte) []byte {
		p, err := (&Proof{RequestSHA256: RequestDigest(digestOf), Store: StoreSoftware}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	other := proofFor([]byte("another request"))
	// A request of version 1, with the proof of another request: malformed comes first.
	v1 := bytes.Clone(der)
	v1[bytes.Index(v1, []byte{0x02, 0x01, 0x00})+2] = 0x01
	_, _, err := CheckRequestFiles(CSRPEM(v1), other)
	assertCode(t, err, CodeMalformed)
	// A P-256 request with the proof of another request: the digest comes before the key.
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256spki, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	info, err := infoDER(p256spki, mustSubject(t), mustExtensions(t))
	if err != nil {
		t.Fatal(err)
	}
	dg := sha512.Sum384(info)
	sig, _ := ecdsa.SignASN1(rand.Reader, p256, dg[:])
	p256req, _ := AssembleCSR(info, sig)
	_, _, err = CheckRequestFiles(CSRPEM(p256req), other)
	assertCode(t, err, CodeRequestMismatch)
	_, _, err = CheckRequestFiles(CSRPEM(p256req), proofFor(p256req))
	assertCode(t, err, "algorithm-unsupported")
	// The key before the signature.
	_, _, err = CheckRequestFiles(CSRPEM(der), other)
	assertCode(t, err, CodeRequestMismatch)
}

func mustSubject(t *testing.T) []byte {
	t.Helper()
	s, err := commonNameName("x")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustExtensions(t *testing.T) []pkix.Extension {
	t.Helper()
	e, err := requestedExtensions(testSpec().Constraints)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A signature algorithm other than ecdsa-with-SHA384 is `possession-invalid` even when the signature is a good SHA-384 one: the
// algorithm is part of what the contract fixes, and the label of the request says what it was signed with.
func TestASignatureLabelledWithAnotherAlgorithmIsRefused(t *testing.T) {
	der := makeRequest(t, newKey(t), testSpec())
	oid := []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03} // ecdsa-with-SHA384
	i := bytes.LastIndex(der, oid)
	if i < 0 {
		t.Fatal("the algorithm is not in the request")
	}
	if _, err := VerifyRequest(der); err != nil {
		t.Fatal(err)
	}
	for _, last := range []byte{0x02, 0x04} { // ecdsa-with-SHA256 and ecdsa-with-SHA512
		other := bytes.Clone(der)
		other[i+len(oid)-1] = last
		_, err := VerifyRequest(other)
		assertCode(t, err, "possession-invalid")
	}
}
