package content_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/actors/key/internal/content"
	"github.com/truvity/sluis/v2/kits/go/handoff"
)

const (
	tokenVectorFile  = "../../../../tests/testdata/key/token-certificate-vector.json"
	keysetVectorFile = "../../../../tests/testdata/key/keyset-vectors.json"
)

// tokenVector is a chain of a test installation as the code makes it: a root, an intermediate under it as the hand-off makes
// one, and the token certificate that the node's intermediate gave to a token key. Everything is hex of DER. The keys of
// the root and the intermediate are thrown away; the token key is the public key of the entry "retiring key with a
// certificate chain" in keyset-vectors.json, which carries the same chain as its x5c.
type tokenVector struct {
	Note         string `json:"note"`
	Boundary     string `json:"boundary"`
	At           string `json:"at"` // RFC 3339: the time the chain is read at, inside the validity of all three
	TokenSPKI    string `json:"token_spki"`
	Token        string `json:"token_certificate"`
	Intermediate string `json:"intermediate"`
	Root         string `json:"root"`
	RootPin      string `json:"root_x509_spki_sha256"`
}

func readVector(t *testing.T) tokenVector {
	t.Helper()
	b, err := os.ReadFile(tokenVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v tokenVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verifies: REQ-PKI-036
// The token certificate of a test installation (tests/testdata/key/token-certificate-vector.json, made by the code under test
// with keys that were thrown away): basic constraints say not a CA, key usage allows digital signature only, there is no
// name and no extended key usage, the subject is the token-signing profile's, the serial number is 121 to 128 bits, the
// chain verifies to the root at the time of the vector, and key@'s check accepts the TBSCertificate as it stood then. The
// root's pin is the one a root list names.
func TestTheTokenCertificateOfATestInstallationIsTheProfile(t *testing.T) {
	v := readVector(t)
	tok, err := x509.ParseCertificate(unhex(t, v.Token))
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(unhex(t, v.Intermediate))
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(unhex(t, v.Root))
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, v.At)
	if err != nil {
		t.Fatal(err)
	}
	if tok.IsCA || !tok.BasicConstraintsValid || tok.KeyUsage != x509.KeyUsageDigitalSignature || len(tok.ExtKeyUsage) != 0 || len(tok.UnknownExtKeyUsage) != 0 ||
		len(tok.DNSNames)+len(tok.EmailAddresses)+len(tok.IPAddresses)+len(tok.URIs) != 0 || tok.Version != 3 {
		t.Fatalf("not the profile: %+v", tok)
	}
	if tok.Subject.CommonName != "token-signing" || len(tok.Subject.OrganizationalUnit) != 1 || tok.Subject.OrganizationalUnit[0] != "signer@"+v.Boundary {
		t.Fatalf("subject %v", tok.Subject)
	}
	if n := tok.SerialNumber.BitLen(); n < 121 || n > 128 {
		t.Fatalf("serial of %d bits", n)
	}
	if !bytes.Equal(tok.RawSubjectPublicKeyInfo, unhex(t, v.TokenSPKI)) || !tok.NotAfter.Equal(inter.NotAfter) {
		t.Fatal("key, or the end is not the intermediate's")
	}
	if !inter.IsCA || inter.MaxPathLen != 0 || !inter.MaxPathLenZero || inter.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("the intermediate is not an intermediate of the hand-off")
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(inter)
	if _, err := tok.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("the chain does not verify to the root: %v", err)
	}
	if handoff.SPKIPin(root) != v.RootPin {
		t.Fatal("the pin of the root is not the one recorded")
	}
	rules := content.TokenCertificateRules{
		Issuer: inter.RawSubject, IssuerKeyID: inter.SubjectKeyId, SPKI: unhex(t, v.TokenSPKI), Boundary: v.Boundary,
		IssuerNotBefore: inter.NotBefore, IssuerNotAfter: inter.NotAfter, Now: tok.NotBefore.Add(5 * time.Minute),
	}
	if _, err := content.CheckTokenCertificate(tok.Raw, rules, inter); err != nil {
		t.Fatalf("key@'s check refuses the vector: %v", err)
	}
}

// verifies: REQ-PKI-034
// The chain in the key set's known answers is the vector's: a real chain, so that nothing in the golden files is a stand-in.
func TestTheKeySetVectorCarriesTheRealChain(t *testing.T) {
	v := readVector(t)
	b, err := os.ReadFile(keysetVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var ks struct {
		Published []struct {
			Name string   `json:"name"`
			X5C  []string `json:"x5c"`
			JWK  struct {
				X5C []string `json:"x5c"`
			} `json:"jwk"`
			SPKI string `json:"spki"`
		} `json:"published"`
	}
	if err := json.Unmarshal(b, &ks); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, k := range ks.Published {
		if len(k.X5C) == 0 {
			continue
		}
		found = true
		want := []string{v.Token, v.Intermediate, v.Root}
		if len(k.X5C) != 3 || len(k.JWK.X5C) != 3 || k.SPKI != v.TokenSPKI {
			t.Fatalf("%s: chain of %d/%d certificates, key %s", k.Name, len(k.X5C), len(k.JWK.X5C), k.SPKI[:16])
		}
		for i, w := range want {
			if k.X5C[i] != w || k.JWK.X5C[i] != base64.StdEncoding.EncodeToString(unhex(t, w)) {
				t.Fatalf("%s: certificate %d is not the vector's", k.Name, i)
			}
		}
	}
	if !found {
		t.Fatal("no entry of the key set vectors carries a chain")
	}
}
