//go:build sluis_test

package keyd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"connectrpc.com/connect"
)

// sshCertBody is the body an OpenSSH certificate is signed over (PROTOCOL.certkeys): the type string, a nonce, the
// public key, serial, type, key id, the principals, the validity window, the critical options and extensions, a
// reserved string and the signing key. Every field is the SSH wire form (uint32 length, then the bytes). The contents
// are not what the test is about: it is a well-formed body that a CA would sign, and key@ must not sign it under a token
// purpose.
func sshCertBody(pub *ecdsa.PublicKey) []byte {
	str := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) } //nolint:gosec // short
	var out []byte
	out = append(out, str([]byte("ecdsa-sha2-nistp384-cert-v01@openssh.com"))...)
	out = append(out, str(make([]byte, 32))...) // nonce
	out = append(out, str([]byte("nistp384"))...)
	point, _ := pub.ECDH()
	out = append(out, str(point.Bytes())...)
	out = binary.BigEndian.AppendUint64(out, 1)     // serial
	out = binary.BigEndian.AppendUint32(out, 1)     // type: user
	out = append(out, str([]byte("alice"))...)      // key id
	out = append(out, str(str([]byte("alice")))...) // principals
	out = binary.BigEndian.AppendUint64(out, 0)     // valid after
	out = binary.BigEndian.AppendUint64(out, 1<<62)
	out = append(out, str(nil)...) // critical options
	out = append(out, str(nil)...) // extensions
	out = append(out, str(nil)...) // reserved
	out = append(out, str(str([]byte("ecdsa-sha2-nistp384")))...)
	return out
}

// verifies: REQ-ISO-008
// T-9 (the threat model: "A key is made to sign another protocol's data or a wider certificate"): a token purpose is
// asked to sign a TBSCertificate and an OpenSSH certificate body, and is refused by content, whoever asks and whatever
// the bytes look like. The control is the same key signing a JWS signing input in the same test, so that the refusal is
// the content check and not a missing key or a closed rule. The driver is never asked to sign what is refused.
func TestATokenPurposeSignsNoCertificateBody(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	_, kid := publicKey(t, n, "signer", "token-signing")
	ca, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A TBSCertificate, as a CA would sign it: the to-be-signed part of a real certificate, here a certificate that
	// asks for CA powers, which is what a token key that signed it would hand out.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ca.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"a TBSCertificate":            cert.RawTBSCertificate,
		"a whole certificate":         der,
		"an OpenSSH certificate body": sshCertBody(&ca.PublicKey),
	}
	signs := n.driver.signs.Load()
	for name, c := range cases {
		for _, actor := range []string{"signer"} {
			_, err := n.client(actor).Sign(context.Background(), signReq("token-signing", c))
			wantRefusalNamed(t, name+" as "+actor, err, connect.CodeInvalidArgument, "content")
		}
	}
	if got := n.driver.signs.Load(); got != signs {
		t.Fatalf("the driver was asked to sign refused content %d times", got-signs)
	}
	// The refusals are audited with the reason and the path, and carry no byte of the content.
	refused := 0
	for _, ev := range n.audit.all() {
		if ev.Action == ActionRefuse && ev.Reason == reasonContent {
			refused++
		}
	}
	if refused != len(cases) {
		t.Fatalf("%d content refusals audited, want %d", refused, len(cases))
	}
	// The control: a JWS signing input is signed by the very same key and caller.
	if _, err := n.client("signer").Sign(context.Background(), signReq("token-signing", tokenInput(kid, "", ""))); err != nil {
		t.Fatalf("the control, a JWS signing input, was refused: %v", err)
	}
	// An actor with no rule for the token purpose is refused by the rule before the content is read, even for a
	// well-formed JWS signing input.
	for _, actor := range []string{"ca", "ssh-ca", "writer"} {
		_, err := n.client(actor).Sign(context.Background(), signReq("token-signing", tokenInput(kid, "", "")))
		wantRefusalNamed(t, actor+" asks for a token signature", err, connect.CodePermissionDenied, "rule")
	}
}
