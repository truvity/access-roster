//go:build sluis_vectors

package content_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
	"github.com/truvity/sluis/v2/kits/go/tokencert"
)

// TestWriteVectors makes new vector files: go test -tags sluis_vectors ./actors/key/internal/content -run WriteVectors. It is
// built only with that tag, so CI neither runs nor skips it. The keys of the root and the intermediate are random and thrown away; the
// token certificate is built and checked by the code under test.
func TestWriteVectors(t *testing.T) {
	old := readKeysetSPKI(t)
	rk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Root (TEST ONLY)"}, NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(20, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rder, _ := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	root, _ := x509.ParseCertificate(rder)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sluis dev intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 13, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains: []string{"dev.example.org"}, PermittedDNSDomainsCritical: true}
	ider, err := x509.CreateCertificate(rand.Reader, it, root, &ik.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(ider)
	serial, _ := tokencert.NewSerial(nil)
	tbs, err := tokencert.TBS(tokencert.Params{Serial: serial, Issuer: inter.RawSubject, IssuerKeyID: inter.SubjectKeyId, SPKI: old, Boundary: "dev",
		NotBefore: now.Add(-time.Minute), NotAfter: inter.NotAfter})
	if err != nil {
		t.Fatal(err)
	}
	d := sha512.Sum384(tbs)
	sig, _ := ecdsa.SignASN1(rand.Reader, ik, d[:])
	tokDER := tokencert.Assemble(tbs, sig)
	v := tokenVector{
		Note:     "A chain of a test installation as the code makes it: a root, an intermediate under it, and the token certificate that the intermediate gave to the token key of the entry 'retiring key with a certificate chain' of keyset-vectors.json. The keys of the root and of the intermediate were random and are thrown away. The vector is read by actors/key/internal/content (REQ-PKI-036); regenerate with go test -tags sluis_vectors.",
		Boundary: "dev", At: now.Format(time.RFC3339), TokenSPKI: hex.EncodeToString(old), Token: hex.EncodeToString(tokDER),
		Intermediate: hex.EncodeToString(ider), Root: hex.EncodeToString(rder), RootPin: handoff.SPKIPin(root),
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(chainVectorFile, append(out, '\n'), 0o644); err != nil { //nolint:gosec // a test vector
		t.Fatal(err)
	}
	// The same chain in the key set's known answers.
	b, _ := os.ReadFile(keysetVectorFile)
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, e := range doc["published"].([]any) {
		k := e.(map[string]any)
		if _, ok := k["x5c"]; !ok {
			continue
		}
		k["x5c"] = []any{v.Token, v.Intermediate, v.Root}
		k["jwk"].(map[string]any)["x5c"] = []any{stdb64(tokDER), stdb64(ider), stdb64(rder)}
	}
	doc["note"] = "Known answers for the published key set (REQ-KEYS-006): a ring key in, the JWK (RFC 7517 section 4, RFC 7518 section 6.2) out. The keys are two P-384 keys made with `openssl ecparam -name secp384r1 -genkey`; spki is the DER of `openssl ec -pubout`, and x and y are the base64url (no padding) of the two halves of the `pub:` point in `openssl ec -text`, not computed by the code under test. x5c is standard base64 of the certificate bytes (RFC 7517 section 4.7); the chain of the entry with one is the real chain of token-certificate-vector.json: the token certificate, the intermediate, the root. `published` lists the ring keys, in order, that the set must list, with the entry each must produce; `left_out` lists ring keys the set must not list."
	out, _ = json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(keysetVectorFile, append(out, '\n'), 0o644); err != nil { //nolint:gosec // a test vector
		t.Fatal(err)
	}
}

func stdb64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func readKeysetSPKI(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(keysetVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var ks struct {
		Published []struct {
			X5C  []string `json:"x5c"`
			SPKI string   `json:"spki"`
		} `json:"published"`
	}
	if err := json.Unmarshal(b, &ks); err != nil {
		t.Fatal(err)
	}
	for _, k := range ks.Published {
		if len(k.X5C) > 0 {
			return unhex(t, k.SPKI)
		}
	}
	t.Fatal("no entry with a chain")
	return nil
}
