//go:build sluis_card

package card

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestTheEmbeddedBundleTrustsTheIntermediateOfTheNewestCards(t *testing.T) {
	v, err := newVerifier(yubicoRootPEM, yubicoIntermediatePEM, yubicoRootSHA256)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range v.Roots.Subjects() { //nolint:staticcheck // a pool built here, not the system's
		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(s, &rdn); err != nil {
			t.Fatal(err)
		}
		var name pkix.Name
		name.FillFromRDNSequence(&rdn)
		names = append(names, name.CommonName)
	}
	joined := strings.Join(names, "|")
	for _, want := range []string{"Yubico Attestation Root 1", "Yubico PIV Attestation B 1", "Yubico PIV Attestation B2 1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the anchors lack %q: %s", want, joined)
		}
	}
	for _, n := range names {
		if strings.Contains(n, "FIDO") || strings.Contains(n, "OPGP") || strings.Contains(n, "SD ") {
			t.Errorf("the anchors hold %q, which does not sign a PIV attestation", n)
		}
	}
}

// A card in miniature: a root, the intermediate, the PIV attestation intermediate, the card's attestation key and a slot
// certificate with the Yubico extensions.
type pki struct {
	root, inter, pivInter, att *x509.Certificate
	rootPEM, bundlePEM         []byte
	attKey, pivKey, interKey   *ecdsa.PrivateKey
	rootHash                   string
}

func mkCert(t *testing.T, cn string, ca bool, pub *ecdsa.PublicKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ext []pkix.Extension) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if pub == nil {
		pub = &k.PublicKey
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: ca, BasicConstraintsValid: true, ExtraExtensions: ext,
	}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	signer, signerKey := tmpl, k
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, pub, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

func pemOf(cs ...*x509.Certificate) []byte {
	var b []byte
	for _, c := range cs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}

func newPKI(t *testing.T, pivName string) *pki {
	t.Helper()
	p := &pki{}
	var rootKey *ecdsa.PrivateKey
	p.root, rootKey = mkCert(t, "TEST ONLY Yubico Attestation Root 1", true, nil, nil, nil, nil)
	p.inter, p.interKey = mkCert(t, "TEST ONLY Yubico Attestation Intermediate B 1", true, nil, p.root, rootKey, nil)
	p.pivInter, p.pivKey = mkCert(t, pivName, true, nil, p.inter, p.interKey, nil)
	p.att, p.attKey = mkCert(t, "TEST ONLY Yubico PIV Attestation", true, nil, p.pivInter, p.pivKey, nil)
	sum := sha256.Sum256(p.root.Raw)
	p.rootHash = hex.EncodeToString(sum[:])
	p.rootPEM = pemOf(p.root)
	p.bundlePEM = pemOf(p.inter, p.pivInter)
	return p
}

func (p *pki) slotCert(t *testing.T) *x509.Certificate {
	t.Helper()
	serial, _ := asn1.Marshal(int64(1234567))
	slotKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	c, _ := mkCert(t, "YubiKey PIV Attestation 9a", false, &slotKey.PublicKey, p.att, p.attKey, []pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}, Value: []byte{5, 8, 0}},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}, Value: serial},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}, Value: []byte{0x02, 0x01}},
	})
	return c
}

func TestAChainThroughAPIVAttestationIntermediateVerifiesAndIsRead(t *testing.T) {
	p := newPKI(t, "Yubico PIV Attestation B2 1")
	v, err := newVerifier(p.rootPEM, p.bundlePEM, p.rootHash)
	if err != nil {
		t.Fatal(err)
	}
	a, err := v.Verify(p.att, p.slotCert(t))
	if err != nil {
		t.Fatal(err)
	}
	got := toAttestation(a)
	if got.Version != (Version{5, 8, 0}) || got.Serial != 1234567 || got.Slot != 0x9a || got.PIN != PINOnce || got.Touch != TouchNever {
		t.Fatalf("read %+v, want 5.8.0, serial 1234567, slot 9a, PIN once, touch never", got)
	}
}

func TestAChainThroughAnotherIntermediateIsRefused(t *testing.T) {
	// A FIDO attestation CA is Yubico's too, and does not sign the attestation key of a PIV applet.
	p := newPKI(t, "Yubico FIDO Attestation B2 1")
	if _, err := newVerifier(p.rootPEM, p.bundlePEM, p.rootHash); err == nil {
		t.Fatal("a bundle with no PIV attestation intermediate was accepted")
	}
}

func TestAChainToAnotherRootIsRefused(t *testing.T) {
	good := newPKI(t, "Yubico PIV Attestation B2 1")
	rogue := newPKI(t, "Yubico PIV Attestation B2 1")
	v, err := newVerifier(good.rootPEM, good.bundlePEM, good.rootHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(rogue.att, rogue.slotCert(t)); err == nil {
		t.Fatal("an attestation from another PKI verified")
	}
}

func TestAnIntermediateThatDoesNotChainToThePinnedRootIsNotAnAnchor(t *testing.T) {
	good := newPKI(t, "Yubico PIV Attestation B2 1")
	rogue := newPKI(t, "Yubico PIV Attestation B2 1")
	// The bundle holds the rogue PKI's PIV intermediate beside the good one: only the good one may become an anchor.
	v, err := newVerifier(good.rootPEM, append(good.bundlePEM, rogue.bundlePEM...), good.rootHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(rogue.att, rogue.slotCert(t)); err == nil {
		t.Fatal("an intermediate of another root became an anchor")
	}
	if _, err := v.Verify(good.att, good.slotCert(t)); err != nil {
		t.Fatalf("the good chain: %v", err)
	}
}

func TestARootThatIsNotThePinnedOneIsRefused(t *testing.T) {
	p := newPKI(t, "Yubico PIV Attestation B2 1")
	if _, err := newVerifier(p.rootPEM, p.bundlePEM, strings.Repeat("00", 32)); err == nil {
		t.Fatal("a root with another hash was accepted")
	}
}
