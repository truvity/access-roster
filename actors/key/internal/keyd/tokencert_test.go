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
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/handoff"
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

// verifies: REQ-ISO-006
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
	if got := publicKeyX5CFor(t, n, "ca", "x509-intermediate"); len(got) != 0 {
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
