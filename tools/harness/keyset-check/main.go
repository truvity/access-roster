// Command keyset-check reads the key set that the local installation publishes (`/jwks` of the boundary's host, through the
// forwarder) and checks that every key of it carries an x5c chain that a verifier could use (REQ-PKI-034, REQ-PKI-036): the
// first certificate is the token certificate (not a CA, key usage digitalSignature only, no name, the key of the entry), the
// chain verifies, and its last certificate is the root whose pin the hand-off recorded. `just local-up` runs it after the
// hand-off, since `ca` makes the token certificate once the intermediate is installed.
//
//	go run ./tools/harness/keyset-check -pin HEX [-ca FILE] [-addr HOST:PORT] [-host NAME] [-wait 3m]
//
// It is a test harness tool, never part of a product binary: it trusts the harness CA only, and dials the loopback port of the
// forwarder so that no hosts-file line is needed.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// jwk is the part of a JSON Web Key this check reads (RFC 7517, section 4).
type jwk struct {
	Kty string   `json:"kty"`
	Crv string   `json:"crv"`
	Kid string   `json:"kid"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	X5C []string `json:"x5c"`
}

// Report is what a good key set shows for one key.
type Report struct {
	Kid, Serial string
	NotAfter    time.Time
	Chain       int
}

// Check verifies the key set document against the pin of the root (the x509_spki_sha256, lower-case hex) at the time now. It
// returns one report for each key, or the first thing that is wrong.
func Check(doc []byte, pin string, now time.Time) ([]Report, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, fmt.Errorf("the key set is not JSON: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("the key set lists no key")
	}
	var out []Report
	for _, k := range set.Keys {
		r, err := checkKey(k, pin, now)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k.Kid, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func checkKey(k jwk, pin string, now time.Time) (Report, error) {
	if len(k.X5C) < 3 {
		return Report{}, fmt.Errorf("x5c has %d certificates, want the token certificate, the intermediate and the root", len(k.X5C))
	}
	certs := make([]*x509.Certificate, len(k.X5C))
	for i, s := range k.X5C {
		der, err := base64.StdEncoding.DecodeString(s) // x5c is standard base64, not base64url (RFC 7517, section 4.7)
		if err != nil {
			return Report{}, fmt.Errorf("x5c[%d] is not standard base64: %w", i, err)
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return Report{}, fmt.Errorf("x5c[%d] is not a certificate: %w", i, err)
		}
	}
	leaf, root := certs[0], certs[len(certs)-1]
	if k.Kty != "EC" || k.Crv != "P-384" {
		return Report{}, errors.New("the entry is not a P-384 key")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return Report{}, errors.New("the token certificate does not hold a P-384 key")
	}
	if !sameKey(k, pub) {
		return Report{}, errors.New("the token certificate holds another key than the entry")
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 0 || len(leaf.UnknownExtKeyUsage) != 0 ||
		len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses)+len(leaf.URIs) != 0 {
		return Report{}, errors.New("the first certificate is not a token certificate (a CA, or more than digital signature, or a name)")
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, c := range certs[1 : len(certs)-1] {
		inters.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return Report{}, fmt.Errorf("the chain does not verify to its last certificate: %w", err)
	}
	sum := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	if got := hex.EncodeToString(sum[:]); got != pin {
		return Report{}, fmt.Errorf("the last certificate is a root with pin %s, not the hand-off's %s", got, pin)
	}
	return Report{Kid: k.Kid, Serial: hex.EncodeToString(leaf.SerialNumber.Bytes()), NotAfter: leaf.NotAfter, Chain: len(certs)}, nil
}

// sameKey says that the JWK holds the public key: the uncompressed point, 0x04 and the two 48-octet coordinates (RFC 7518,
// section 6.2.1.2 asks for the full length, so a coordinate cut short is another key as far as this check goes).
func sameKey(k jwk, pub *ecdsa.PublicKey) bool {
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err1 != nil || err2 != nil || len(x) != 48 || len(y) != 48 {
		return false
	}
	got, err := pub.Bytes()
	return err == nil && bytes.Equal(got, append(append([]byte{4}, x...), y...))
}

func main() {
	ca := flag.String("ca", ".cache/local/ca/ca.pem", "the harness CA")
	addr := flag.String("addr", "127.0.0.1:"+port(), "where the forwarder listens")
	host := flag.String("host", "sluis.dev.local.test", "the name of the boundary's host")
	pin := flag.String("pin", "", "the x509_spki_sha256 of the root the hand-off was certified by (required)")
	wait := flag.Duration("wait", 0, "keep trying this long: ca makes the certificate a few seconds after the intermediate is installed, and exporter@ publishes it after")
	flag.Parse()
	if *pin == "" {
		fmt.Fprintln(os.Stderr, "keyset-check: -pin is required")
		os.Exit(2)
	}
	c, err := client(*ca, *addr, *host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keyset-check: %v\n", err)
		os.Exit(1)
	}
	end := time.Now().Add(*wait)
	for {
		reports, err := fetchAndCheck(c, *host, *pin)
		if err == nil {
			for _, r := range reports {
				fmt.Printf("keyset-check: key %s has an x5c chain of %d (token certificate, intermediate, root), serial %s, ends %s, and it verifies to the root %s\n",
					r.Kid, r.Chain, r.Serial, r.NotAfter.UTC().Format(time.RFC3339), (*pin)[:16])
			}
			return
		}
		if !time.Now().Before(end) {
			fmt.Fprintf(os.Stderr, "keyset-check: FAILED: %v\n", err)
			os.Exit(1)
		}
		time.Sleep(3 * time.Second)
	}
}

func fetchAndCheck(c *http.Client, host, pin string) ([]Report, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/jwks", http.NoBody)
	if err != nil {
		return nil, err
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jwks: status %d", res.StatusCode)
	}
	return Check(body, pin, time.Now())
}

// client trusts the harness CA only and dials the forwarder's loopback address whatever the name.
func client(caFile, addr, host string) (*http.Client, error) {
	pem, err := os.ReadFile(caFile) //nolint:gosec // the harness CA, named by the recipe
	if err != nil {
		return nil, fmt.Errorf("the harness CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the harness CA holds no certificate")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}, nil
}

func port() string {
	if p := os.Getenv("SLUIS_LOCAL_PORT"); p != "" {
		return p
	}
	return "8443"
}
