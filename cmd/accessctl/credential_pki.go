package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// The defaults that make the common command short. Each is overridable,
// because a second installation is allowed to name things differently.
const (
	// openbaoAudience is the exchange client OpenBAO accepts tokens of.
	openbaoAudience = "openbao"
	// rosterMount is the JWT auth mount people and jobs log in through.
	rosterMount = "jwt-roster"
	// rosterLoginRole is the one role on that mount; groups decide the rest.
	rosterLoginRole = "roster"
	// pkiMount is the engine `accessctl pg`/`psql`'s certificate role lives on.
	pkiMount = "pki"
)

// leaf is one issued certificate, as the caller of this file needs it.
type leaf struct {
	// Certificate, Key and Authority are PEM, exactly as they will be
	// written.
	Certificate string
	Key         string
	Authority   string
	// Parsed is the certificate itself, which is where the common name,
	// the serial and the expiry are read from — never from what was
	// asked for.
	Parsed *x509.Certificate
}

// leafCurve is the key a PKI credential is made with: ECDSA on P-384,
// which is what a role with `key_type=ec` and `key_bits=384` signs, and
// what a role with `key_type=any` accepts. A role that insists on another
// key type refuses the request, and says so.
var leafCurve = elliptic.P384()

// issue makes the one call that mints a certificate: `sign`, over a
// certificate request for a key made here.
//
// The private key never leaves this process except into the file it is
// written to. OpenBAO is sent a CSR — the public key, and the names asked
// for — and returns a certificate for that key; there is no call in this
// command that would have the manager generate a key and send it back
// over the wire, and a role can therefore offer `sign` alone.
//
// name is the common name already resolved by the caller (accessctl asks
// for the roster subject unless `--common-name` overrides it); path is
// `<pki mount>/sign/<role>`. Both are carried in the CSR, for a role that
// reads names from it (`use_csr_common_name`, `use_csr_sans`), and in the
// request, for one that does not. No TTL is sent, so `max_ttl` on the
// role is the only thing that decides how long this lives.
func issue(ctx context.Context, bao *openbao, path, name string, uris []string) (leaf, error) {
	if name == "" {
		return leaf{}, badUsage("no common name to ask for: sign in again, or pass --common-name")
	}

	private, err := ecdsa.GenerateKey(leafCurve, rand.Reader)
	if err != nil {
		return leaf{}, fmt.Errorf("generate a key: %w", err)
	}
	csr, err := certificateRequest(private, name, uris)
	if err != nil {
		return leaf{}, err
	}

	body := map[string]any{"csr": csr, "common_name": name}
	if len(uris) > 0 {
		body["uri_sans"] = strings.Join(uris, ",")
	}
	data, err := bao.write(ctx, path, body)
	if err != nil {
		return leaf{}, err
	}

	issued := leaf{
		Certificate: text(data["certificate"]),
		Authority:   authorityOf(data),
	}
	if issued.Certificate == "" {
		return leaf{}, fmt.Errorf("%s returned no certificate", path)
	}
	if issued.Parsed, err = parseLeaf(issued.Certificate); err != nil {
		return leaf{}, err
	}
	// A certificate for some other key is no use with this one, and
	// writing the two side by side would leave a pair that fails only
	// when a server is asked to accept it.
	if !private.PublicKey.Equal(issued.Parsed.PublicKey) {
		return leaf{}, fmt.Errorf("%s returned a certificate for a key other than the one it was asked to sign", path)
	}
	if issued.Key, err = encodeKey(private); err != nil {
		return leaf{}, err
	}
	return issued, nil
}

// certificateRequest is the CSR for the key: the common name and the URI
// SANs asked for, signed by the key itself so the manager can check the
// caller holds it.
func certificateRequest(private *ecdsa.PrivateKey, name string, uris []string) (string, error) {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}
	for _, raw := range uris {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", badUsage("--uri-san %q is not a URI: %v", raw, err)
		}
		template.URIs = append(template.URIs, parsed)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, private)
	if err != nil {
		return "", fmt.Errorf("build the certificate request: %w", err)
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))), nil
}

// encodeKey is the key as PKCS #8 PEM, the form libpq, OpenSSL and Go
// all read.
func encodeKey(private *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", fmt.Errorf("encode the key: %w", err)
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))), nil
}

// authorityOf is the chain to verify a server against, the whole chain
// when the role returns one and the issuer alone when it does not.
func authorityOf(data map[string]any) string {
	chain, ok := data["ca_chain"].([]any)
	if !ok || len(chain) == 0 {
		return text(data["issuing_ca"])
	}
	var built strings.Builder
	for _, one := range chain {
		if pemText := text(one); pemText != "" {
			built.WriteString(strings.TrimSuffix(pemText, "\n") + "\n")
		}
	}
	return built.String()
}

func text(value any) string {
	asString, _ := value.(string)
	return strings.TrimSpace(asString)
}

func parseLeaf(certificate string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return nil, fmt.Errorf("the issued certificate is not PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("read the issued certificate: %w", err)
	}
	return parsed, nil
}

// colonHex is the serial the way every tool that shows one writes it, so
// what is printed here can be pasted into a search of the audit trail.
func colonHex(raw []byte) string {
	parts := make([]string, 0, len(raw))
	for _, b := range raw {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, ":")
}

// writeLeaf writes the three files every consumer of a client
// certificate ends up needing, under one name.
func writeLeaf(base string, issued leaf) error {
	if err := writeSecret(base+".crt", []byte(issued.Certificate+"\n")); err != nil {
		return err
	}
	if err := writeSecret(base+".key", []byte(issued.Key+"\n")); err != nil {
		return err
	}
	if issued.Authority != "" {
		if err := writeSecret(base+"-ca.crt", []byte(issued.Authority)); err != nil {
			return err
		}
	}
	return nil
}

// credentialDir is where a certificate this tool minted is kept: beside
// the configuration, in a directory only this account may enter, one
// level per namespace and one below that per role -- so a certificate
// for `db-client` in `staging` never collides with one for `db-client`
// in `example/staging`, or with a second role in the same namespace.
//
// The OpenBAO token is NOT here, and is nowhere: what is on disk is a
// certificate and a key that expire on their own, and a path that says
// which namespace and role they are for.
func credentialDir(namespace, role string) (string, error) {
	base, err := configDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "credentials", namespace, role)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

// writeSecret replaces a file that only this account may read.
//
// Removed first rather than truncated: writing over a file keeps the mode
// it already had, and a key written into a world-readable file that
// existed before is a key somebody else can read.
func writeSecret(path string, body []byte) error { return replaceFile(path, body, 0o600) }

func replaceFile(path string, body []byte, mode os.FileMode) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // a path the caller named
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err = file.Write(body); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
