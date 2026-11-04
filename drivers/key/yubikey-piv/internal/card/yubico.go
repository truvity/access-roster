//go:build sluis_card

package card

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"

	_ "embed" // the Yubico certificates below

	"github.com/go-piv/piv-go/v2/piv"
)

// What the driver trusts to say that a key was born on a YubiKey: Yubico's attestation root and the PIV attestation
// intermediates that chain to it, both public and published at developers.yubico.com/PKI (fetched 2026-11-04).
//
//   - certs/yubico-attestation-root-1.pem is "Yubico Attestation Root 1" from yubico-ca-certs.txt, the same certificate as
//     piv-go's certs/yubico-ca-1.pem. Its SHA-256 (DER) is pinned below.
//   - certs/yubico-intermediate.pem is yubico-intermediate.pem (15 certificates). piv-go v2.6.0 embeds 10 of them and
//     lacks "Yubico PIV Attestation B2 1", the intermediate that signs the attestation key of a card made since
//     August 2025. The Nanos of the boards (firmware 5.8.0) are of that batch, and piv.Verify with piv-go's own set
//     refuses them ("does not chain to the Yubico root"). Measured on a board, 2026-11-04.
//
// The check itself is still piv-go's (piv.Verifier): the chain of the slot certificate through the card's attestation
// certificate, and the reading of the firmware, serial and policy extensions. Only the anchors are ours: the root,
// and each "Yubico PIV Attestation" intermediate that this package has first verified against the root through the
// bundle. A change to either file is a change to what the driver trusts: review it as one.
//
//go:embed certs/yubico-attestation-root-1.pem
var yubicoRootPEM []byte

//go:embed certs/yubico-intermediate.pem
var yubicoIntermediatePEM []byte

// yubicoRootSHA256 is the SHA-256 of the DER form of "Yubico Attestation Root 1".
const yubicoRootSHA256 = "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8"

// pivIntermediatePrefix is the common name of the intermediates that sign the attestation key of a PIV applet.
const pivIntermediatePrefix = "Yubico PIV Attestation "

var (
	verifierOnce sync.Once
	verifier     *piv.Verifier
	verifierErr  error
)

// yubicoVerifier is the verifier over the embedded Yubico certificates, built once.
func yubicoVerifier() (*piv.Verifier, error) {
	verifierOnce.Do(func() {
		verifier, verifierErr = newVerifier(yubicoRootPEM, yubicoIntermediatePEM, yubicoRootSHA256)
	})
	return verifier, verifierErr
}

// newVerifier builds the piv-go verifier whose trust anchors are the root (checked against wantRootSHA256) and every
// PIV attestation intermediate of the bundle that chains to it. A bundle with none is refused: a verifier that would
// accept nothing is not a verifier.
func newVerifier(rootPEM, bundlePEM []byte, wantRootSHA256 string) (*piv.Verifier, error) {
	roots, err := parseCerts(rootPEM)
	if err != nil || len(roots) != 1 {
		return nil, errors.New("card: the Yubico root file does not hold exactly one certificate")
	}
	sum := sha256.Sum256(roots[0].Raw)
	if hex.EncodeToString(sum[:]) != wantRootSHA256 {
		return nil, errors.New("card: the Yubico root is not the pinned certificate")
	}
	bundle, err := parseCerts(bundlePEM)
	if err != nil {
		return nil, err
	}
	rootPool, interPool := x509.NewCertPool(), x509.NewCertPool()
	rootPool.AddCert(roots[0])
	for _, c := range bundle {
		interPool.AddCert(c)
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(roots[0])
	n := 0
	for _, c := range bundle {
		if !strings.HasPrefix(c.Subject.CommonName, pivIntermediatePrefix) {
			continue
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: interPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			continue // not signed through the pinned root: not trusted
		}
		anchors.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, errors.New("card: the Yubico bundle holds no PIV attestation intermediate that chains to the root")
	}
	return &piv.Verifier{Roots: anchors}, nil
}

func parseCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("card: a Yubico certificate does not parse: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}
