// Command mkcard writes the files of a made-up card for the tests of the scripts that certify one: a made-up maker's attestation
// root and bundle (two levels, as the real one has), and the request and proof that `sluis key request` writes for a key in a card
// of that maker. Nothing here is a key of anyone's, and the maker is not Yubico.
//
//	mkcard -dir DIR -stem dev-x509-intermediate -serial 31337 [-slot 9c] [-names dev.boards.test]
//
// It writes DIR/attest-root.pem, DIR/attest-bundle.pem, DIR/attest-root.sha256 and DIR/<stem>.csr.pem and <stem>.proof.json.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
	"github.com/truvity/sluis/v2/kits/go/handoff/handofftest"
)

func main() {
	dir := flag.String("dir", "", "the directory to write to")
	stem := flag.String("stem", "dev-x509-intermediate", "the stem of the request")
	serial := flag.Int64("serial", 1, "the serial number of the token")
	slot := flag.String("slot", "9c", "the slot of the key")
	names := flag.String("names", "dev.boards.test", "the trust domain and DNS zone the request asks for")
	flag.Parse()
	if *dir == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: mkcard -dir DIR [-stem S] [-serial N] [-slot 9c] [-names N]")
		os.Exit(2)
	}
	if err := run(*dir, *stem, *serial, *slot, *names); err != nil {
		fmt.Fprintln(os.Stderr, "mkcard:", err)
		os.Exit(1)
	}
}

func run(dir, stem string, serial int64, slot, names string) error {
	now := time.Now()
	h := handofftest.NewHierarchyWith(now, handofftest.Options{TwoLevels: true, IssuerName: "Made-up PIV Attestation B2 1 (TEST ONLY)"})
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	info, err := handoff.CertificationRequestInfo(spki, handoff.RequestSpec{
		Subject:     pkix.Name{CommonName: "sluis board intermediate"},
		Constraints: handoff.Constraints{URIHosts: []string{names}, DNS: []string{names}},
	})
	if err != nil {
		return err
	}
	d := sha512.Sum384(info)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		return err
	}
	der, err := handoff.AssembleCSR(info, sig)
	if err != nil {
		return err
	}
	g := handofftest.GoodSlot(slot, serial)
	proof, err := (&handoff.Proof{RequestSHA256: handoff.RequestDigest(der), Store: handoff.StorePIV, Attestation: h.Attest(&key.PublicKey, g)}).Marshal()
	if err != nil {
		return err
	}
	pemOf := func(cs ...*x509.Certificate) []byte {
		var b []byte
		for _, c := range cs {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
		return b
	}
	sum := sha256.Sum256(h.Root.Raw)
	files := map[string][]byte{
		"attest-root.pem":    pemOf(h.Root),
		"attest-bundle.pem":  pemOf(h.Upper, h.Intermediate),
		"attest-root.sha256": []byte(hex.EncodeToString(sum[:]) + "\n"),
		stem + ".csr.pem":    handoff.CSRPEM(der),
		stem + ".proof.json": proof,
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // test material
		return err
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil { //nolint:gosec // test material, public
			return err
		}
	}
	return nil
}
