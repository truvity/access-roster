//go:build sluis_test

package keyd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/handoff"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/tokencert"
)

// certifiedNode is a node whose intermediate has been certified by a throwaway root and installed.
func certifiedNode(t *testing.T) (*node, *intRoot, *x509.Certificate) {
	t.Helper()
	n := handoffNode(t, nil)
	root := newIntRoot(t, n)
	der := certFor(t, n, root, true)
	if _, err := install(n, "x509-intermediate", false, 1, der); err != nil {
		t.Fatalf("Install: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return n, root, c
}

// tokenTBS is the TBSCertificate ca would send for the token key of the node, valid from a minute before the clock to the
// end of the intermediate.
func tokenTBS(t *testing.T, n *node, inter *x509.Certificate) []byte {
	t.Helper()
	serial, err := tokencert.NewSerial(nil)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := tokencert.TBS(tokencert.Params{
		Serial: serial, Issuer: inter.RawSubject, IssuerKeyID: inter.SubjectKeyId, SPKI: n.srv.keys["token-signing"].spki, Boundary: testBoundary,
		NotBefore: n.e.clock.now().Add(-time.Minute), NotAfter: inter.NotAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tbs
}

func signTBS(n *node, who string, tbs []byte) (*keyv2alpha1.SignResponse, error) {
	res, err := n.client(who).Sign(context.Background(), signReq("x509-intermediate", tbs))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func putCertificate(n *node, who, purpose string, der []byte) (*keyv2alpha1.PutCertificateResponse, error) {
	return putCertificateReplacing(n, who, purpose, der, false)
}

func putCertificateReplacing(n *node, who, purpose string, der []byte, replace bool) (*keyv2alpha1.PutCertificateResponse, error) {
	res, err := n.client(who).PutCertificate(context.Background(), connect.NewRequest(&keyv2alpha1.PutCertificateRequest{Purpose: purpose, Certificate: der, Replace: replace}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// certifyToken does what ca does: sign, assemble, put.
func certifyToken(t *testing.T, n *node, inter *x509.Certificate) []byte {
	t.Helper()
	der := signedToken(t, n, inter)
	if _, err := putCertificate(n, "ca", "token-signing", der); err != nil {
		t.Fatalf("PutCertificate: %v", err)
	}
	return der
}

// signedToken is the certificate ca assembles from key@'s signature, not yet handed back.
func signedToken(t *testing.T, n *node, inter *x509.Certificate) []byte {
	t.Helper()
	tbs := tokenTBS(t, n, inter)
	sig, err := signTBS(n, "ca", tbs)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tokencert.Assemble(tbs, sig.GetSignatureDer())
}

// verifies: REQ-ISO-006, REQ-PKI-036, REQ-PKI-034
// ca asks the intermediate's purpose to sign the TBSCertificate of the token certificate; key@ signs it, ca assembles the
// certificate and hands it back; the certificate is not a CA, allows digital signatures only, verifies under the root, and
// is what PublicKey gives signer as the chain of the token key. The signature is an audit fact that names what it covers,
// durable before it left; the write is an audit fact too; and nothing asked store@ for an item that was not there.
func TestTheIntermediateSignsTheTokenCertificateAndPublicKeyGivesTheChain(t *testing.T) {
	n, root, inter := certifiedNode(t)
	tok := n.srv.keys["token-signing"]
	absent := n.e.store.absentCount()
	if x5c := publicKeyX5C(t, n, "signer"); len(x5c) != 0 {
		t.Fatalf("the chain before a certificate is made: %d certificates", len(x5c))
	}
	tbs := tokenTBS(t, n, inter)
	sig, err := signTBS(n, "ca", tbs)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	der := tokencert.Assemble(tbs, sig.GetSignatureDer())
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 0 || len(c.DNSNames)+len(c.URIs)+len(c.IPAddresses)+len(c.EmailAddresses) != 0 {
		t.Fatalf("the certificate is not the profile: %+v", c)
	}
	d := sha512.Sum384(tbs)
	if !ecdsa.VerifyASN1(n.srv.keys["x509-intermediate"].pub, d[:], sig.GetSignatureDer()) {
		t.Fatal("the signature does not verify under the intermediate's key")
	}
	res, err := putCertificate(n, "ca", "token-signing", der)
	if err != nil || res.GetAlready() || res.GetReplaced() || res.GetId() != "token-signing/"+recipientLabel(tok.keyID) {
		t.Fatalf("PutCertificate = %+v, %v", res, err)
	}
	x5c := publicKeyX5C(t, n, "signer")
	if len(x5c) != 2 || string(x5c[0]) != string(der) || string(x5c[1]) != string(inter.Raw) {
		t.Fatalf("the chain is %d certificates, not the token certificate and the intermediate", len(x5c))
	}
	// The chain verifies to the root as a verifier would walk it.
	leaf, _ := x509.ParseCertificate(x5c[0])
	mid, _ := x509.ParseCertificate(x5c[1])
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.cert)
	inters.AddCert(mid)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: n.e.clock.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("the chain does not verify to the root: %v", err)
	}
	// Another purpose has no chain.
	if got := publicKeyX5CFor(t, n, "writer", "audit-log"); len(got) != 0 {
		t.Fatal("a purpose other than token-signing carries a chain")
	}
	var signed, stored bool
	for _, ev := range n.audit.all() {
		switch {
		case ev.Action == ActionSign && ev.Fields["purpose"] == "x509-intermediate" && ev.Fields["caller"] == "ca" && ev.Blocking && ev.Fields["tbs_sha384"] == hex.EncodeToString(d[:]):
			signed = true
		case ev.Action == ActionCertificateInstall && ev.Fields["purpose"] == "token-signing" && ev.Blocking && ev.Fields["key_id"] == tok.keyID && ev.Fields["chain_length"] == int64(2):
			stored = true
		}
	}
	if !signed || !stored {
		t.Errorf("audit facts: signature %v, store %v", signed, stored)
	}
	if got := n.e.store.absentCount(); got != absent {
		t.Errorf("%d Gets of an item that was not there", got-absent)
	}
}

func publicKeyX5C(t *testing.T, n *node, who string) [][]byte {
	return publicKeyX5CFor(t, n, who, "token-signing")
}

func publicKeyX5CFor(t *testing.T, n *node, who, purpose string) [][]byte {
	t.Helper()
	res, err := n.client(who).PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: purpose}))
	if err != nil {
		t.Fatalf("PublicKey(%s): %v", purpose, err)
	}
	return res.Msg.GetX5C()
}

// verifies: REQ-ISO-006
// The intermediate signs the token certificate and no other content. A JWS signing input, a CertificationRequestInfo
// (which the same key signs through SignRequest), a certificate of a CA, one for another key, one with a name, with the
// wrong dates or a short serial number, truncated or padded bytes, and random bytes are refused with the content reason;
// the driver is never asked, no signature is an audit fact, and the refusal is.
func TestTheIntermediateSignsNothingButTheTokenCertificate(t *testing.T) {
	n, _, inter := certifiedNode(t)
	good := tokenTBS(t, n, inter)
	ik := n.srv.keys["x509-intermediate"]
	cri, err := handoff.CertificationRequestInfo(ik.spki, handoffSpec())
	if err != nil {
		t.Fatal(err)
	}
	k, _ := n.driver.key("x509-intermediate")
	other := func(mod func(*x509.Certificate)) []byte {
		now := n.e.clock.now()
		tmpl := &x509.Certificate{SerialNumber: inter.SerialNumber, Subject: pkix.Name{CommonName: "token-signing", OrganizationalUnit: []string{"signer@" + testBoundary}},
			NotBefore: now.Add(-time.Minute), NotAfter: inter.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
		mod(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c.RawTBSCertificate
	}
	random := make([]byte, 400)
	_, _ = rand.Read(random)
	cases := map[string][]byte{
		"a CertificationRequestInfo": cri,
		"a JWS signing input":        tokenInput(ik.keyID, "", ""),
		"a CA":                       other(func(c *x509.Certificate) { c.IsCA = true }),
		"the intermediate's own key": other(func(*x509.Certificate) {}),
		"trailing byte":              append(append([]byte{}, good...), 0),
		"truncated":                  good[:len(good)-1],
		"random bytes":               random,
		"empty":                      nil,
	}
	before := n.driver.signs.Load()
	signed := n.audit.count(ActionSign)
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := signTBS(n, "ca", in)
			wantRefusal(t, err, connect.CodeInvalidArgument, "content")
		})
	}
	if n.driver.signs.Load() != before || n.audit.count(ActionSign) != signed {
		t.Error("a refused content reached the driver or was audited as a signature")
	}
	// Another actor has no rule for the intermediate.
	_, err = signTBS(n, "signer", good)
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	// And SignRequest refuses the certificate: neither passes the other's path.
	_, err = n.handoff().SignRequest(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: "x509-intermediate", Info: good}))
	n.refusal(t, err, connect.CodeInvalidArgument, reasonContent, "info")
}

// There is nothing to certify under before an intermediate is installed: the refusal is its own, and nothing is signed.
func TestTheIntermediateSignsNothingBeforeItIsInstalled(t *testing.T) {
	n := handoffNode(t, nil)
	_, err := signTBS(n, "ca", []byte{0x30, 0x00})
	wantRefusal(t, err, connect.CodeFailedPrecondition, "intermediate")
	_, err = putCertificate(n, "ca", "token-signing", []byte{0x30, 0x00})
	wantRefusal(t, err, connect.CodeFailedPrecondition, "intermediate")
	if n.driver.signs.Load() != 0 {
		t.Error("the driver was asked to sign")
	}
}

// verifies: REQ-ISO-006
// A certificate is neither signed nor stored for a revoked token key, and a revoked intermediate signs nothing: the
// refusal is `revoked`, it comes before the driver is asked, and the signature is not an audit fact.
func TestTheTokenCertificateOfARevokedKeyIsNeitherSignedNorStored(t *testing.T) {
	for _, purpose := range []string{"token-signing", "x509-intermediate"} {
		t.Run(purpose, func(t *testing.T) {
			n, _, inter := certifiedNode(t)
			der := signedToken(t, n, inter) // signed while neither key was revoked
			signs, facts := n.driver.signs.Load(), n.audit.count(ActionSign)
			pk := n.srv.keys[purpose]
			if _, err := n.revoke(n.e.declare(n.e.nextSeq(), "compromise", pk.keyID)); err != nil {
				t.Fatal(err)
			}
			_, err := signTBS(n, "ca", tokenTBS(t, n, inter))
			wantRefusal(t, err, connect.CodePermissionDenied, "revoked")
			if n.driver.signs.Load() != signs || n.audit.count(ActionSign) != facts {
				t.Error("a revoked key's certificate reached the driver or was audited as a signature")
			}
			_, err = putCertificate(n, "ca", "token-signing", der)
			wantRefusal(t, err, connect.CodePermissionDenied, "revoked")
			for id := range certItems(n) {
				if strings.HasPrefix(id, "token-signing/") {
					t.Fatalf("%s was stored for a revoked key", id)
				}
			}
		})
	}
}

// verifies: REQ-ISO-006
// A revoked key's chain is not given: after the token key or the intermediate is revoked, PublicKey and TokenKey say none,
// though the certificate is stored and valid. When the revocation cannot be read, none either.
func TestNoChainIsGivenWhileEitherKeyIsRevoked(t *testing.T) {
	for _, purpose := range []string{"token-signing", "x509-intermediate"} {
		t.Run(purpose, func(t *testing.T) {
			n, _, inter := certifiedNode(t)
			certifyToken(t, n, inter)
			if len(publicKeyX5C(t, n, "signer")) != 2 {
				t.Fatal("no chain before the revocation")
			}
			if _, err := n.revoke(n.e.declare(n.e.nextSeq(), "compromise", n.srv.keys[purpose].keyID)); err != nil {
				t.Fatal(err)
			}
			if got := publicKeyX5C(t, n, "signer"); len(got) != 0 {
				t.Fatalf("a chain of %d certificates after the revocation", len(got))
			}
		})
	}
	n, _, inter := certifiedNode(t)
	certifyToken(t, n, inter)
	n.e.store.failKind = "key-revocation"
	if got := publicKeyX5C(t, n, "signer"); len(got) != 0 {
		t.Fatal("a chain is given while KeyRevocation cannot be read")
	}
}

// verifies: REQ-ISO-006
// PutCertificate does not take ca's word. It refuses a certificate that key@ would not have signed, though its signature
// is good: a CA, a certificate for another key, one with a name; a certificate that the intermediate did not sign; a
// caller that may not sign for the intermediate; a purpose other than token-signing; and bytes. Nothing is stored.
func TestPutCertificateChecksWhatItKeeps(t *testing.T) {
	n, _, inter := certifiedNode(t)
	k, _ := n.driver.key("x509-intermediate")
	now := n.e.clock.now()
	std := func(signer *ecdsa.PrivateKey, mod func(*x509.Certificate)) []byte {
		tmpl := &x509.Certificate{SerialNumber: inter.SerialNumber, Subject: pkix.Name{CommonName: "token-signing", OrganizationalUnit: []string{"signer@" + testBoundary}},
			NotBefore: now.Add(-time.Minute), NotAfter: inter.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, AuthorityKeyId: inter.SubjectKeyId}
		mod(tmpl)
		tk, _ := n.driver.key("token-signing")
		der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &tk.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	// A well-formed TBS signed by a key that is not the intermediate's.
	good := tokenTBS(t, n, inter)
	stranger, _ := ecdsa.GenerateKey(k.Curve, rand.Reader)
	gd := sha512.Sum384(good)
	sig, _ := ecdsa.SignASN1(rand.Reader, stranger, gd[:])
	cases := map[string]struct {
		who, purpose string
		der          []byte
		code         connect.Code
		reason       string
	}{
		"a CA":                           {"ca", "token-signing", std(k, func(c *x509.Certificate) { c.IsCA = true }), connect.CodeInvalidArgument, "content"},
		"a name":                         {"ca", "token-signing", std(k, func(c *x509.Certificate) { c.DNSNames = []string{"a.example.org"} }), connect.CodeInvalidArgument, "content"},
		"standard encoding of a good":    {"ca", "token-signing", std(k, func(*x509.Certificate) {}), connect.CodeInvalidArgument, "content"},
		"not signed by the intermediate": {"ca", "token-signing", tokencert.Assemble(good, sig), connect.CodeInvalidArgument, "content"},
		"garbage":                        {"ca", "token-signing", []byte("not a certificate"), connect.CodeInvalidArgument, "content"},
		"empty":                          {"ca", "token-signing", nil, connect.CodeInvalidArgument, "schema"},
		"another purpose":                {"ca", "x509-intermediate", good, connect.CodeInvalidArgument, "purpose"},
		"signer may not":                 {"signer", "token-signing", good, connect.CodePermissionDenied, "rule"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := putCertificate(n, tc.who, tc.purpose, tc.der)
			wantRefusal(t, err, tc.code, tc.reason)
		})
	}
	for id := range certItems(n) {
		if len(id) > 13 && id[:13] == "token-signing" {
			t.Fatalf("%s was stored by a refused call", id)
		}
	}
	if n.audit.count(ActionCertificateInstall) != 1 { // the intermediate's own install
		t.Errorf("%d install facts", n.audit.count(ActionCertificateInstall))
	}
}

// Storing the same certificate again writes nothing and says so. A second certificate that ends no later than the stored one,
// which is valid and signed by the installed intermediate, does not replace it (a shorter certificate would shorten the
// chain that is published) unless the caller says replace, and then the fact shows it, with the hashes that tie it to the
// signature.
func TestPutCertificateIsIdempotentAndDoesNotShortenTheChain(t *testing.T) {
	n, _, inter := certifiedNode(t)
	der := certifyToken(t, n, inter)
	facts := n.audit.count(ActionCertificateInstall)
	res, err := putCertificate(n, "ca", "token-signing", der)
	if err != nil || !res.GetAlready() || n.audit.count(ActionCertificateInstall) != facts {
		t.Fatalf("the same certificate again: %+v, %v, %d facts", res, err, n.audit.count(ActionCertificateInstall)-facts)
	}
	again := signedToken(t, n, inter) // a new serial number, the same end: a different certificate
	if string(again) == string(der) {
		t.Fatal("two certificates with one serial number")
	}
	_, err = putCertificate(n, "ca", "token-signing", again)
	wantRefusal(t, err, connect.CodeFailedPrecondition, "stale")
	if x5c := publicKeyX5C(t, n, "signer"); len(x5c) != 2 || string(x5c[0]) != string(der) {
		t.Fatal("a refused replacement changed the chain")
	}
	if n.audit.count(ActionCertificateInstall) != facts {
		t.Fatal("a refused replacement is an install fact")
	}
	res, err = putCertificateReplacing(n, "ca", "token-signing", again, true)
	if err != nil || !res.GetReplaced() {
		t.Fatalf("replace: %+v, %v", res, err)
	}
	var fact map[string]any
	for _, ev := range n.audit.all() {
		if ev.Action == ActionCertificateInstall && ev.Fields["purpose"] == "token-signing" && ev.Fields["replace"] == true {
			fact = ev.Fields
		}
	}
	c, _ := x509.ParseCertificate(again)
	tbs, leaf := sha512.Sum384(c.RawTBSCertificate), sha512.Sum384(again)
	if fact == nil || fact["previous_not_after"] == nil || fact["tbs_sha384"] != hex.EncodeToString(tbs[:]) || fact["leaf_sha384"] != hex.EncodeToString(leaf[:]) {
		t.Fatalf("the install fact of the replacement: %v", fact)
	}
	// The fact ties to the signature: the key.sign fact of the same TBS names the same hash.
	var signed bool
	for _, ev := range n.audit.all() {
		if ev.Action == ActionSign && ev.Fields["tbs_sha384"] == fact["tbs_sha384"] {
			signed = true
		}
	}
	if !signed {
		t.Error("no signature fact names the TBS that the store names")
	}
}

// A certificate that ends later replaces the stored one without saying so (a renewal); an older one does not come back.
func TestPutCertificateReplacesWhatNoLongerServes(t *testing.T) {
	n, root, inter := certifiedNode(t)
	old := certifyToken(t, n, inter)
	k, _ := n.driver.key("x509-intermediate")
	now := n.e.clock.now()
	renewed := root.issue(t, csrOf(t, k), now.Add(-time.Hour), now.AddDate(0, 14, 0), nil)
	if _, err := install(n, "x509-intermediate", false, 2, renewed); err != nil {
		t.Fatal(err)
	}
	rc, _ := x509.ParseCertificate(renewed)
	next := signedToken(t, n, rc)
	if res, err := putCertificate(n, "ca", "token-signing", next); err != nil || !res.GetReplaced() {
		t.Fatalf("a later end: %+v, %v", res, err)
	}
	// The old one was signed under the old intermediate: its chain is not the installed one, and it ends earlier than the
	// stored one. It serves (it verifies under the renewed intermediate) and does not end later: refused.
	if _, err := putCertificate(n, "ca", "token-signing", old); err == nil {
		t.Fatal("an older certificate replaced a newer one")
	}
}

// The chain PublicKey gives is true: after a renewal of the intermediate the old token certificate is still given as long
// as it verifies under the renewed one (same key, same subject), with the renewed intermediate's chain, so that the key set
// has no gap while ca makes the certificate again; a certificate that has ended is not given.
func TestPublicKeyGivesTheOldLeafAfterARenewalAndNothingThatNoLongerFits(t *testing.T) {
	n, root, inter := certifiedNode(t)
	old := certifyToken(t, n, inter)
	if len(publicKeyX5C(t, n, "signer")) != 2 {
		t.Fatal("no chain")
	}
	// A renewal: the same key and subject, a later end.
	k, _ := n.driver.key("x509-intermediate")
	now := n.e.clock.now()
	renewed := root.issue(t, csrOf(t, k), now.Add(-time.Hour), now.AddDate(0, 14, 0), nil)
	if _, err := install(n, "x509-intermediate", false, 2, renewed); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	got := publicKeyX5C(t, n, "signer")
	if len(got) != 2 || string(got[0]) != string(old) || string(got[1]) != string(renewed) {
		t.Fatalf("after a renewal: %d certificates, the old leaf and the renewed intermediate expected", len(got))
	}
	// The chain verifies to the root as a verifier would walk it.
	leaf, _ := x509.ParseCertificate(got[0])
	mid, _ := x509.ParseCertificate(got[1])
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.cert)
	inters.AddCert(mid)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: n.e.clock.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("the chain after the renewal does not verify: %v", err)
	}
	rc, _ := x509.ParseCertificate(renewed)
	made := certifyToken(t, n, rc)
	if got := publicKeyX5C(t, n, "signer"); len(got) != 2 || string(got[0]) != string(made) || string(got[1]) != string(renewed) {
		t.Fatal("the certificate made again is not given")
	}
	n.e.clock.advance(15 * 31 * 24 * time.Hour)
	if got := publicKeyX5C(t, n, "signer"); len(got) != 0 {
		t.Fatal("a certificate that has ended is given")
	}
}

// An intermediate of another key is not the issuer of the stored certificate: no chain is given for it.
func TestPublicKeyGivesNoChainUnderAnotherIntermediateKey(t *testing.T) {
	n, root, inter := certifiedNode(t)
	certifyToken(t, n, inter)
	// The stored intermediate is replaced, in the store, by a certificate of a key that did not sign the token certificate.
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := n.e.clock.now()
	der := root.issue(t, csrOf(t, other), now.Add(-time.Hour), now.AddDate(0, 13, 0), func(c *x509.Certificate) { c.RawSubject = inter.RawSubject })
	id := "x509-intermediate/" + recipientLabel(n.srv.keys["x509-intermediate"].keyID)
	cur := certItems(n)[id]
	cur.Chain = [][]byte{der}
	n.e.store.put("key-certificate", "", id, cur)
	if got := publicKeyX5C(t, n, "signer"); len(got) != 0 {
		t.Fatalf("a chain of %d certificates under an intermediate that did not sign the certificate", len(got))
	}
}

// A stored certificate that the intermediate's key did not sign is not given, though its issuer name, its key and its dates
// are right (a store@ that is compromised can put anything in the kind).
func TestPublicKeyGivesNoChainForACertificateTheIntermediateDidNotSign(t *testing.T) {
	n, _, inter := certifiedNode(t)
	der := certifyToken(t, n, inter)
	c, _ := x509.ParseCertificate(der)
	stranger, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	d := sha512.Sum384(c.RawTBSCertificate)
	sig, _ := ecdsa.SignASN1(rand.Reader, stranger, d[:])
	forged := tokencert.Assemble(c.RawTBSCertificate, sig)
	id := "token-signing/" + recipientLabel(n.srv.keys["token-signing"].keyID)
	cur := certItems(n)[id]
	cur.Chain = append([][]byte{forged}, cur.Chain[1:]...)
	n.e.store.put("key-certificate", "", id, cur)
	if got := publicKeyX5C(t, n, "signer"); len(got) != 0 {
		t.Fatalf("a chain of %d certificates led by a certificate the intermediate did not sign", len(got))
	}
}

// ca learns which key it certifies from TokenKey, which only ca may ask (the registry gives the token key's public key to
// signer alone). The answer is what PublicKey gives signer: the key, and the chain once there is one that fits.
func TestTokenKeyTellsCaTheKeyAndTheChain(t *testing.T) {
	n, _, inter := certifiedNode(t)
	tok := n.srv.keys["token-signing"]
	ask := func(who string) (*keyv2alpha1.TokenKeyResponse, error) {
		res, err := n.client(who).TokenKey(context.Background(), connect.NewRequest(&keyv2alpha1.TokenKeyRequest{}))
		if err != nil {
			return nil, err
		}
		return res.Msg, nil
	}
	absent := n.e.store.absentCount()
	got, err := ask("ca")
	if err != nil || string(got.GetSpkiDer()) != string(tok.spki) || got.GetKeyId() != tok.keyID || len(got.GetChain()) != 0 ||
		string(got.GetIntermediateSpkiDer()) != string(n.srv.keys["x509-intermediate"].spki) {
		t.Fatalf("before a certificate: %+v, %v", got, err)
	}
	der := certifyToken(t, n, inter)
	got, err = ask("ca")
	if err != nil || len(got.GetChain()) != 2 || string(got.GetChain()[0]) != string(der) {
		t.Fatalf("after: %+v, %v", got, err)
	}
	for _, who := range []string{"signer", "session", "exchange", "policy"} {
		_, err := ask(who)
		wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	}
	if n.e.store.absentCount() != absent {
		t.Error("TokenKey asked store@ for an item that was not there")
	}
	// And ca still has no rule for the token key's public key.
	_, err = n.client("ca").PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "token-signing"}))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
}

// A KeyPlan with no intermediate (the state before the hand-off, and of an installation that never has one): TokenKey answers
// with no intermediate and refuses nothing, so a ca that waits makes no refusal record each time it looks.
func TestTokenKeyOfAPlanWithoutAnIntermediateRefusesNothing(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	before, absent := n.audit.count(ActionRefuse), e.store.absentCount()
	for range 5 {
		res, err := n.client("ca").TokenKey(context.Background(), connect.NewRequest(&keyv2alpha1.TokenKeyRequest{}))
		if err != nil || len(res.Msg.GetIntermediateSpkiDer()) != 0 || len(res.Msg.GetChain()) != 0 || len(res.Msg.GetSpkiDer()) == 0 {
			t.Fatalf("%+v, %v", res.Msg, err)
		}
	}
	if n.audit.count(ActionRefuse) != before || e.store.absentCount() != absent {
		t.Fatalf("%d refusals, %d Gets of an absent item", n.audit.count(ActionRefuse)-before, e.store.absentCount()-absent)
	}
}

func publicKeyOf(t *testing.T, n *node) *keyv2alpha1.PublicKeyResponse {
	t.Helper()
	res, err := n.client("signer").PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "token-signing"}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg
}

// verifies: REQ-PKI-034
// PublicKey tells an empty chain that means "none yet" from one that means "take it down": x5c_withdrawn is false while no
// certificate is stored, and with a chain; it is true once a stored certificate is not given because it has ended, the
// intermediate did not sign it, or either key is revoked. When the revocations cannot be read, key@ cannot tell and says
// false.
func TestPublicKeySaysWhenItWithdrawsAChain(t *testing.T) {
	n, _, inter := certifiedNode(t)
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 0 || r.GetX5CWithdrawn() {
		t.Fatalf("before a certificate: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
	certifyToken(t, n, inter)
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 2 || r.GetX5CWithdrawn() {
		t.Fatalf("with a chain: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
	// Revocations that cannot be read: no chain, and no claim that it was withdrawn.
	n.e.store.failKind = "key-revocation"
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 0 || r.GetX5CWithdrawn() {
		t.Fatalf("unreadable revocations: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
	n.e.store.failKind = ""
	// The intermediate is revoked: withdrawn.
	if _, err := n.revoke(n.e.declare(n.e.nextSeq(), "compromise", n.srv.keys["x509-intermediate"].keyID)); err != nil {
		t.Fatal(err)
	}
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 0 || !r.GetX5CWithdrawn() {
		t.Fatalf("revoked intermediate: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
}

func TestPublicKeySaysWithdrawnForAnEndedCertificateAndAForgedOne(t *testing.T) {
	n, _, inter := certifiedNode(t)
	der := certifyToken(t, n, inter)
	// Forged: the intermediate's key did not sign it.
	c, _ := x509.ParseCertificate(der)
	stranger, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	d := sha512.Sum384(c.RawTBSCertificate)
	sig, _ := ecdsa.SignASN1(rand.Reader, stranger, d[:])
	id := "token-signing/" + recipientLabel(n.srv.keys["token-signing"].keyID)
	cur := certItems(n)[id]
	good := append([][]byte(nil), cur.Chain...)
	cur.Chain = append([][]byte{tokencert.Assemble(c.RawTBSCertificate, sig)}, cur.Chain[1:]...)
	n.e.store.put("key-certificate", "", id, cur)
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 0 || !r.GetX5CWithdrawn() {
		t.Fatalf("forged: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
	cur.Chain = good
	n.e.store.put("key-certificate", "", id, cur)
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 2 || r.GetX5CWithdrawn() {
		t.Fatal("the good chain is not given again")
	}
	// Ended: the intermediate has ended too, so a renewal would be needed; the stored certificate is withdrawn.
	n.e.clock.advance(15 * 31 * 24 * time.Hour)
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 0 || !r.GetX5CWithdrawn() {
		t.Fatalf("ended: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
}

// A plan with no token-signing key has nothing to certify: TokenKey answers empty and refuses nothing, so a ca that looks every
// few seconds writes no record (REQ-AUDIT-180). The healthcheck of ca calls nothing at all.
func TestTokenKeyOfAPlanWithoutATokenKeyRefusesNothing(t *testing.T) {
	e := newTestEnv(t, "development")
	plan := proto.Clone(e.plan).(*configv2alpha1.KeyPlan)
	var kept []*configv2alpha1.KeyPurposePlan
	for _, p := range plan.Purposes {
		if p.Purpose != "token-signing" {
			kept = append(kept, p)
		}
	}
	plan.Purposes = kept
	e.putPlan(plan)
	n := e.startedNode(nodeOpts{})
	before := n.audit.count(ActionRefuse)
	for range 5 {
		res, err := n.client("ca").TokenKey(context.Background(), connect.NewRequest(&keyv2alpha1.TokenKeyRequest{}))
		if err != nil || len(res.Msg.GetSpkiDer()) != 0 || len(res.Msg.GetChain()) != 0 {
			t.Fatalf("%+v, %v", res.Msg, err)
		}
	}
	if n.audit.count(ActionRefuse) != before {
		t.Fatalf("%d refusals", n.audit.count(ActionRefuse)-before)
	}
}

// A stored certificate that the installed intermediate did not issue does not "serve", and a good one replaces it without
// saying replace, though it ends no later: the issuer name of the stored one is not the intermediate's subject (the first
// case), or its signature is not the intermediate's key's (the second).
func TestPutCertificateReplacesAStoredCertificateThatDoesNotServe(t *testing.T) {
	for _, name := range []string{"another issuer name", "not signed by the intermediate"} {
		t.Run(name, func(t *testing.T) {
			n, _, inter := certifiedNode(t)
			good := signedToken(t, n, inter)
			gc, _ := x509.ParseCertificate(good)
			ik, _ := n.driver.key("x509-intermediate")
			serial, _ := tokencert.NewSerial(nil)
			p := tokencert.Params{Serial: serial, Issuer: inter.RawSubject, IssuerKeyID: inter.SubjectKeyId, SPKI: n.srv.keys["token-signing"].spki, Boundary: testBoundary,
				NotBefore: gc.NotBefore, NotAfter: gc.NotAfter}
			signer := ik
			if name == "another issuer name" {
				p.Issuer = []byte{0x30, 0x00}
			} else {
				signer, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			}
			tbs, err := tokencert.TBS(p)
			if err != nil {
				t.Fatal(err)
			}
			d := sha512.Sum384(tbs)
			sig, _ := ecdsa.SignASN1(rand.Reader, signer, d[:])
			bad := tokencert.Assemble(tbs, sig)
			if _, err := x509.ParseCertificate(bad); err != nil {
				t.Fatal(err)
			}
			id := "token-signing/" + recipientLabel(n.srv.keys["token-signing"].keyID)
			n.e.store.put("key-certificate", "", id, &keyv2alpha1.KeyCertificate{
				Purpose: "token-signing", Recipient: recipientLabel(n.srv.keys["token-signing"].keyID), SpkiDer: n.srv.keys["token-signing"].spki,
				Chain: append([][]byte{bad}, certItems(n)["x509-intermediate/"+recipientLabel(n.srv.keys["x509-intermediate"].keyID)].Chain...),
			})
			res, err := putCertificate(n, "ca", "token-signing", good)
			if err != nil || !res.GetReplaced() {
				t.Fatalf("a good certificate over one that does not serve: %+v, %v", res, err)
			}
			if x5c := publicKeyX5C(t, n, "signer"); len(x5c) != 2 || string(x5c[0]) != string(good) {
				t.Fatal("the good certificate is not the chain")
			}
		})
	}
}

// verifies: REQ-PKI-034
// When the kinds cannot be read, key@ cannot tell a chain that is gone from one that is not there yet, and says false: a
// signer keeps the chain it has. (The revocations cannot be read: the same, tested above.)
func TestPublicKeyDoesNotWithdrawWhenTheKindsCannotBeRead(t *testing.T) {
	n, _, inter := certifiedNode(t)
	certifyToken(t, n, inter)
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 2 || r.GetX5CWithdrawn() {
		t.Fatal("no chain to begin with")
	}
	n.e.store.failKind = "key-certificate"
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 0 || r.GetX5CWithdrawn() {
		t.Fatalf("unreadable KeyCertificate: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
	n.e.store.failKind = ""
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 2 || r.GetX5CWithdrawn() {
		t.Fatal("the chain does not come back when the kind can be read again")
	}
}

// TokenKey and PutCertificate ask for the operation certify, and not for sign: a holder of sign alone (the intermediate's
// signing) is refused both, and a holder of certify alone passes the rule. The registry gives certify to ca only, and the
// rule is replaced here to show which operation each handler asks for.
func TestTokenKeyAndPutCertificateAskForCertifyNotSign(t *testing.T) {
	n, _, inter := certifiedNode(t)
	der := signedToken(t, n, inter)
	var asked []string
	grant := func(ops ...string) {
		n.srv.allows = func(actor, scope, purpose, op string) bool {
			if purpose == "x509-intermediate" && actor == "ca" {
				asked = append(asked, op)
				for _, o := range ops {
					if o == op {
						return true
					}
				}
				return false
			}
			return registry.KeyAllows(actor, scope, purpose, op)
		}
	}
	grant("sign", "public-key")
	_, err := n.client("ca").TokenKey(context.Background(), connect.NewRequest(&keyv2alpha1.TokenKeyRequest{}))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	_, err = putCertificate(n, "ca", "token-signing", der)
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	grant("certify")
	if _, err := n.client("ca").TokenKey(context.Background(), connect.NewRequest(&keyv2alpha1.TokenKeyRequest{})); err != nil {
		t.Fatalf("certify alone does not pass TokenKey: %v", err)
	}
	if _, err := putCertificate(n, "ca", "token-signing", der); err != nil {
		t.Fatalf("certify alone does not pass PutCertificate: %v", err)
	}
	for _, op := range asked {
		if op != "sign" && op != "certify" {
			t.Fatalf("asked for %q", op)
		}
	}
}

// forgedToken is a certificate for the token key (or another) that the intermediate's key signs, as a store@ that is
// compromised could put in the kind: with the issuer name, key and dates the caller names. It never passed key@.
func forgedToken(t *testing.T, n *node, inter *x509.Certificate, spki, issuer []byte, nb, na time.Time) []byte {
	t.Helper()
	serial, _ := tokencert.NewSerial(nil)
	tbs, err := tokencert.TBS(tokencert.Params{Serial: serial, Issuer: issuer, IssuerKeyID: inter.SubjectKeyId, SPKI: spki, Boundary: testBoundary, NotBefore: nb, NotAfter: na})
	if err != nil {
		t.Fatal(err)
	}
	ik, _ := n.driver.key("x509-intermediate")
	d := sha512.Sum384(tbs)
	sig, _ := ecdsa.SignASN1(rand.Reader, ik, d[:])
	return tokencert.Assemble(tbs, sig)
}

// storeToken puts a certificate in the kind as the token key's, with the intermediate's installed chain behind it.
func storeToken(n *node, leaf []byte) {
	tok := n.srv.keys["token-signing"]
	chain := certItems(n)["x509-intermediate/"+recipientLabel(n.srv.keys["x509-intermediate"].keyID)].Chain
	n.e.store.put("key-certificate", "", tokenCertificateID(tok), &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", Recipient: recipientLabel(tok.keyID), SpkiDer: tok.spki, Chain: append([][]byte{leaf}, chain...),
	})
}

// verifies: REQ-PKI-034
// A stored certificate is withdrawn, and not given, when its issuer name is not the installed intermediate's subject although
// the signature is the intermediate's, when it has not begun although everything else is right, and when it is for another
// key than the token key.
func TestPublicKeyWithdrawsAStoredCertificateByIssuerNameAndByStart(t *testing.T) {
	n, _, inter := certifiedNode(t)
	tok := n.srv.keys["token-signing"]
	now := n.e.clock.now()
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	for name, der := range map[string][]byte{
		// Signed by the intermediate and valid, and for a key that is not this node's token key.
		"another key":         forgedToken(t, n, inter, otherSPKI, inter.RawSubject, now.Add(-time.Minute), inter.NotAfter),
		"another issuer name": forgedToken(t, n, inter, tok.spki, []byte{0x30, 0x00}, now.Add(-time.Minute), inter.NotAfter),
		"not begun":           forgedToken(t, n, inter, tok.spki, inter.RawSubject, now.Add(time.Hour), inter.NotAfter),
	} {
		t.Run(name, func(t *testing.T) {
			storeToken(n, der)
			if r := publicKeyOf(t, n); len(r.GetX5C()) != 0 || !r.GetX5CWithdrawn() {
				t.Fatalf("%d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
			}
		})
	}
	// And the control: with the right issuer name and a start that has begun, the same construction is given.
	storeToken(n, forgedToken(t, n, inter, tok.spki, inter.RawSubject, now.Add(-time.Minute), inter.NotAfter))
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 2 || r.GetX5CWithdrawn() {
		t.Fatalf("the control: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
}

// A stored certificate for another key, though signed by the intermediate and ending as late as the new one, does not serve
// this key: a good certificate replaces it without saying replace.
func TestPutCertificateReplacesAStoredCertificateOfAnotherKey(t *testing.T) {
	n, _, inter := certifiedNode(t)
	good := signedToken(t, n, inter)
	gc, _ := x509.ParseCertificate(good)
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	storeToken(n, forgedToken(t, n, inter, otherSPKI, inter.RawSubject, gc.NotBefore, gc.NotAfter))
	res, err := putCertificate(n, "ca", "token-signing", good)
	if err != nil || !res.GetReplaced() {
		t.Fatalf("a good certificate over one for another key: %+v, %v", res, err)
	}
}

// The chain of a stored certificate is withdrawn, and not simply left out, when the intermediate it was issued under is no
// longer this node's: the plan dropped it (a revoked intermediate may be dropped from the KeyPlan), or replaced it by another
// key with nothing installed for it. Otherwise a signer would go on publishing a chain under an intermediate key@ no longer has.
func TestPublicKeyWithdrawsTheChainWhenTheIntermediateIsDroppedOrReplaced(t *testing.T) {
	n, _, inter := certifiedNode(t)
	certifyToken(t, n, inter)
	if r := publicKeyOf(t, n); len(r.GetX5C()) != 2 || r.GetX5CWithdrawn() {
		t.Fatal("no chain to begin with")
	}
	tok := n.srv.keys["token-signing"]
	askSigner := func(who *node) *keyv2alpha1.PublicKeyResponse {
		res, err := who.client("signer").PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "token-signing"}))
		if err != nil {
			t.Fatal(err)
		}
		return res.Msg
	}
	// Dropped: the KeyPlan of the restarted key@ has no intermediate. The token key and its certificate are as they were.
	e := n.e
	plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
	e.putPlan(plan)
	dropped := e.startedNode(nodeOpts{name: "node-2", driver: n.driver})
	if string(dropped.srv.keys["token-signing"].spki) != string(tok.spki) {
		t.Fatal("the restarted key@ has another token key")
	}
	if _, ok := dropped.srv.keys["x509-intermediate"]; ok {
		t.Fatal("the plan still has an intermediate")
	}
	if r := askSigner(dropped); len(r.GetX5C()) != 0 || !r.GetX5CWithdrawn() {
		t.Fatalf("dropped: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
	// Replaced: the plan has an intermediate, but another key's, and nothing is installed for it.
	p2 := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
	p2.Purposes = append(p2.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "x509-intermediate", Algorithm: "ES384", Slot: "9c"})
	e.putPlan(p2)
	d2 := newFakeDriver("software")
	d2.keys["token-signing"], _ = n.driver.key("token-signing")
	d2.keys["wrapping"], _ = n.driver.key("wrapping")
	replaced := e.startedNode(nodeOpts{name: "node-3", driver: d2})
	if string(replaced.srv.keys["x509-intermediate"].spki) == string(n.srv.keys["x509-intermediate"].spki) {
		t.Fatal("the intermediate was not replaced")
	}
	if r := askSigner(replaced); len(r.GetX5C()) != 0 || !r.GetX5CWithdrawn() {
		t.Fatalf("replaced: %d certificates, withdrawn %v", len(r.GetX5C()), r.GetX5CWithdrawn())
	}
}

// verifies: REQ-ISO-006
// Sign for the intermediate has a bucket of its own: a few signatures and then `rate`, and the hand-off's SignRequest, which
// shares the key, is not stopped by it. The bucket fills again with time, so a ca that retries after a backoff gets through.
func TestSignForTheIntermediateIsLimitedApartFromSignRequest(t *testing.T) {
	n, _, inter := certifiedNode(t)
	for i := range int(certBurst) {
		if _, err := signTBS(n, "ca", tokenTBS(t, n, inter)); err != nil {
			t.Fatalf("signature %d of the burst: %v", i+1, err)
		}
	}
	before := n.audit.count(ActionSign)
	_, err := signTBS(n, "ca", tokenTBS(t, n, inter))
	wantRefusal(t, err, connect.CodeResourceExhausted, "rate")
	if n.audit.count(ActionSign) != before {
		t.Fatal("a refused signature is an audit fact of a signature")
	}
	// The hand-off is not stopped.
	info, _ := handoff.CertificationRequestInfo(n.srv.keys["x509-intermediate"].spki, handoffSpec())
	if _, err := n.handoff().SignRequest(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: "x509-intermediate", Info: info})); err != nil {
		t.Fatalf("SignRequest after the burst of Sign: %v", err)
	}
	// A quarter of an hour later one more is allowed, and then none.
	n.e.clock.advance(16 * time.Minute)
	if _, err := signTBS(n, "ca", tokenTBS(t, n, inter)); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
	_, err = signTBS(n, "ca", tokenTBS(t, n, inter))
	wantRefusal(t, err, connect.CodeResourceExhausted, "rate")
}

// verifies: REQ-ISO-006
// A certificate Sign takes nothing from the bucket of SignRequest: after the burst of certificates the hand-off still has its
// full burst of 100, and one more is refused.
func TestSignForTheIntermediateTakesNothingFromSignRequestsBucket(t *testing.T) {
	n, _, inter := certifiedNode(t)
	for i := range int(certBurst) {
		if _, err := signTBS(n, "ca", tokenTBS(t, n, inter)); err != nil {
			t.Fatalf("signature %d of the burst: %v", i+1, err)
		}
	}
	info, _ := handoff.CertificationRequestInfo(n.srv.keys["x509-intermediate"].spki, handoffSpec())
	call := func() error {
		_, err := n.handoff().SignRequest(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: "x509-intermediate", Info: info}))
		return err
	}
	for i := range int(signBurst) {
		if err := call(); err != nil {
			t.Fatalf("request signature %d of %d after %d certificates: %v", i+1, int(signBurst), int(certBurst), err)
		}
	}
	n.refusal(t, call(), connect.CodeResourceExhausted, reasonRate, "")
}

// recordOf builds the record the emitter would write for an event of key@ and validates it against the action table, as the
// emitter does before it leaves the process.
func recordOf(t *testing.T, ev Event) error {
	t.Helper()
	act, ok := audit.Sluis().Action(ev.Action)
	if !ok {
		t.Fatalf("no action %q in the table", ev.Action)
	}
	rec, err := audit.BuildRecord("key", testBoundary, "0.0.0-test", "01950000-0000-7000-8000-000000000001", 1793750400000, "req-7f3a_01", "",
		audit.Event{Action: act, Status: audit.StatusSuccess, Sluis: ev.Fields})
	if err != nil {
		return err
	}
	return audit.Sluis().Validate(rec)
}

// verifies: REQ-AUDIT-022
// The serial number and the end of the validity of a token certificate are in the audit fact of its store, and the fact is a
// record the action table accepts. The store a real PutCertificate makes is validated, and so are facts made with random
// serial numbers (the values of tokencert.NewSerial) and random key ids of the shape of a thumbprint, which begin with '-' or
// '_' one time in thirty-two and are what a strict pattern refuses by accident.
func TestTheStoreOfATokenCertificateIsAFactWithItsSerialAndEnd(t *testing.T) {
	n, _, inter := certifiedNode(t)
	der := certifyToken(t, n, inter)
	c, _ := x509.ParseCertificate(der)
	var fact *Event
	for _, ev := range n.audit.all() {
		if ev.Action == ActionCertificateInstall && ev.Fields["purpose"] == "token-signing" {
			ev := ev
			fact = &ev
		}
	}
	if fact == nil {
		t.Fatal("no fact of the store")
	}
	if fact.Fields["serial"] != hex.EncodeToString(c.SerialNumber.Bytes()) || fact.Fields["not_after"] != c.NotAfter.Unix() {
		t.Fatalf("the fact names serial %v and end %v, the certificate has %x and %d", fact.Fields["serial"], fact.Fields["not_after"], c.SerialNumber.Bytes(), c.NotAfter.Unix())
	}
	if err := recordOf(t, *fact); err != nil {
		t.Fatalf("the table refuses the real fact: %v", err)
	}
	// The install of the intermediate has neither member, and is still accepted.
	for _, ev := range n.audit.all() {
		if ev.Action == ActionCertificateInstall && ev.Fields["purpose"] == "x509-intermediate" {
			if _, has := ev.Fields["serial"]; has {
				t.Error("the install of the intermediate names a serial number")
			}
			if err := recordOf(t, ev); err != nil {
				t.Errorf("the table refuses the install of the intermediate: %v", err)
			}
		}
	}
	// Random values.
	starting := 0
	for range 400 {
		serial, err := tokencert.NewSerial(nil)
		if err != nil {
			t.Fatal(err)
		}
		kid := make([]byte, 32)
		_, _ = rand.Read(kid)
		id := base64.RawURLEncoding.EncodeToString(kid)
		if id[0] == '-' || id[0] == '_' {
			starting++
		}
		ev := Event{Action: ActionCertificateInstall, Fields: map[string]any{
			"purpose": "token-signing", "key_id": id, "caller": "ca", "chain_length": int64(3), "trust_sequence": int64(7), "replace": false,
			"tbs_sha384": hex.EncodeToString(kid) + hex.EncodeToString(kid[:16]), "leaf_sha384": hex.EncodeToString(kid) + hex.EncodeToString(kid[:16]),
			"serial": hex.EncodeToString(new(big.Int).SetBytes(serial).Bytes()), "not_after": time.Now().AddDate(1, 0, 0).Unix(),
		}}
		if err := recordOf(t, ev); err != nil {
			t.Fatalf("the table refuses key id %q, serial %x: %v", id, serial, err)
		}
	}
	if starting == 0 {
		t.Log("no random key id began with '-' or '_' in this run (about one in thirty-two): the shapes are covered by domain-vectors.json")
	}
	// And the bounds hold: a serial of 21 octets, an uppercase one and an empty one are refused.
	for name, bad := range map[string]string{"21 octets": strings.Repeat("ab", 21), "uppercase": "ABCDEF01", "empty": "", "not hex": "xyz1"} {
		ev := Event{Action: ActionCertificateInstall, Fields: map[string]any{
			"purpose": "token-signing", "key_id": "k", "caller": "ca", "chain_length": int64(3), "trust_sequence": int64(7), "replace": false, "serial": bad,
		}}
		if err := recordOf(t, ev); err == nil {
			t.Errorf("a serial number of %s was accepted", name)
		}
	}
}

// A ca that retries cannot get stuck on the bucket. ca waits 15 s after a pass that failed, then twice as long each time, up to 15
// minutes, and every attempt that reaches key@ takes a token (a Put that is refused after a good signature costs one too).
// With the clock of the test, and no wait, the schedule is run for two days: the burst is used up in the first minutes, a few
// attempts are refused for rate, and then every attempt, 15 minutes apart, finds a token (the bucket gives one every 12).
func TestARetriedCaIsNeverStuckOnTheCertificateBucket(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	l := newLimiters(func() time.Time { return now })
	wait, refusedAfterBurst, taken, tries := 15*time.Second, 0, 0, 0
	var firstSteady time.Duration
	start := now
	for now.Sub(start) < 48*time.Hour {
		tries++
		if l.allowCertificate() {
			taken++
			if taken == int(certBurst)+1 && firstSteady == 0 {
				firstSteady = now.Sub(start)
			}
		} else if now.Sub(start) > 30*time.Minute {
			refusedAfterBurst++
		}
		wait = min(max(2*wait, 15*time.Second), 15*time.Minute)
		now = now.Add(wait)
	}
	if refusedAfterBurst != 0 {
		t.Fatalf("%d attempts after the first half hour were refused for rate: the bucket holds a retrying ca", refusedAfterBurst)
	}
	if want := 48 * 4; taken < want { // 15-minute attempts for two days
		t.Fatalf("%d signatures in two days of retries, want at least %d", taken, want)
	}
	// And a ca that stops for a while finds the burst again: an hour without a call refills at least four.
	now = now.Add(time.Hour)
	for i := range int(certBurst) {
		if !l.allowCertificate() {
			t.Fatalf("after an hour of quiet the %d-th of the burst is refused", i+1)
		}
	}
	if l.allowCertificate() {
		t.Fatal("the bucket gave more than its burst")
	}
	t.Logf("%d attempts, %d signatures, the burst used up by %v", tries, taken, firstSteady)
}
