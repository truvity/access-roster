package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	// CAName is the common name of the CA: it says what it is wherever a certificate is shown.
	CAName = "sluis TEST ONLY harness CA"
	// constrainedTo is the DNS subtree the CA may certify: the registrable parent of every host of the local
	// installation (docs/runtimes/local.md, "Host names"). A leaf for any other name does not verify.
	constrainedTo = "local.test"
	caLife        = 30 * 24 * time.Hour
	leafLife      = 7 * 24 * time.Hour // local.md, "TLS": valid for seven days
	renewBelow    = 24 * time.Hour     // made again at the next run when less than a day is left
)

func nowFunc() time.Time { return time.Now() }

// Ensure makes what is missing in dir and says what it did.
func Ensure(dir string, hosts []string, now time.Time) (string, error) {
	hosts = slices.DeleteFunc(slices.Clone(hosts), func(h string) bool { return strings.TrimSpace(h) == "" })
	if len(hosts) == 0 {
		return "", errors.New("no host name")
	}
	for _, h := range hosts {
		if h != constrainedTo && !strings.HasSuffix(h, "."+constrainedTo) {
			return "", fmt.Errorf("host %q is outside %s, which the CA is constrained to", h, constrainedTo)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var did []string
	ca, caKey, err := loadPair(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	switch {
	case err == nil && now.Before(ca.NotAfter.Add(-leafLife)):
	case err == nil || errors.Is(err, os.ErrNotExist):
		ca, caKey, err = makeCA(dir, now)
		if err != nil {
			return "", err
		}
		did = append(did, "made the CA")
		// A new CA invalidates the leaf.
		_ = os.Remove(filepath.Join(dir, "leaf.pem"))
	default:
		return "", err
	}
	leaf, _, err := loadPair(filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "leaf.key"))
	if err != nil || now.Add(renewBelow).After(leaf.NotAfter) || !slices.Equal(leaf.DNSNames, hosts) {
		if err := makeLeaf(dir, ca, caKey, hosts, now); err != nil {
			return "", err
		}
		did = append(did, "made the leaf for "+strings.Join(hosts, ", "))
	}
	if len(did) == 0 {
		return "nothing to do", nil
	}
	return strings.Join(did, "; "), nil
}

func makeCA(dir string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: CAName, Organization: []string{"sluis TEST ONLY"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caLife),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		// The CA can certify names under local.test and nothing else (RFC 5280, section 4.2.1.10).
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{constrainedTo},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	// The CA's key is read by this tool alone: mode 0600. The certificate is public.
	if err := writePair(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), [][]byte{der}, key); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func makeLeaf(dir string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, hosts []string, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := serialNumber()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: hosts[0], Organization: []string{"sluis TEST ONLY"}},
		DNSNames:           hosts,
		NotBefore:          now.Add(-time.Minute),
		NotAfter:           minTime(now.Add(leafLife), ca.NotAfter),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	// leaf.pem is the chain a server sends: the leaf, then the CA.
	return writePair(filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "leaf.key"), [][]byte{der, ca.Raw}, key)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// loadPair reads the first certificate of certPath and the key of keyPath.
func loadPair(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(certPath) //nolint:gosec // a path of the harness's own directory
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(keyPath) //nolint:gosec // a path of the harness's own directory
	if err != nil {
		return nil, nil, err
	}
	cblock, _ := pem.Decode(cb)
	kblock, _ := pem.Decode(kb)
	if cblock == nil || kblock == nil {
		return nil, nil, fmt.Errorf("%s or %s is not PEM", certPath, keyPath)
	}
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kblock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func writePair(certPath, keyPath string, chain [][]byte, key *ecdsa.PrivateKey) error {
	var c []byte
	for _, der := range chain {
		c = append(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, c, 0o644); err != nil { //nolint:gosec // a certificate is public
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
}
