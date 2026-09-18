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
	"time"
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
// The common name is REQUESTED and not decided here: accessctl asks for
// the roster subject it is already holding, and the role says whether
// that is a name it will sign. It is carried in the CSR, for a role that
// reads names from it (`use_csr_common_name`), and in the request, for one
// that does not; the URI SANs likewise. No TTL is sent, so `max_ttl` on
// the role is the only thing that decides how long this lives.
func issue(ctx context.Context, bao *openbao, request credentialRequest, subject string) (leaf, error) {
	name := strings.TrimSpace(request.commonName)
	if name == "" {
		name = subject
	}
	if name == "" {
		return leaf{}, badUsage("no common name to ask for: sign in again, or pass --common-name")
	}

	private, err := ecdsa.GenerateKey(leafCurve, rand.Reader)
	if err != nil {
		return leaf{}, fmt.Errorf("generate a key: %w", err)
	}
	csr, err := certificateRequest(private, name, request.uris)
	if err != nil {
		return leaf{}, err
	}

	body := map[string]any{"csr": csr, "common_name": name}
	if len(request.uris) > 0 {
		body["uri_sans"] = strings.Join(request.uris, ",")
	}
	data, err := bao.write(ctx, request.path(), body)
	if err != nil {
		return leaf{}, err
	}

	issued := leaf{
		Certificate: text(data["certificate"]),
		Authority:   authorityOf(data),
	}
	if issued.Certificate == "" {
		return leaf{}, fmt.Errorf("%s returned no certificate", request.path())
	}
	if issued.Parsed, err = parseLeaf(issued.Certificate); err != nil {
		return leaf{}, err
	}
	// A certificate for some other key is no use with this one, and
	// writing the two side by side would leave a pair that fails only
	// when a server is asked to accept it.
	if !private.PublicKey.Equal(issued.Parsed.PublicKey) {
		return leaf{}, fmt.Errorf("%s returned a certificate for a key other than the one it was asked to sign", request.path())
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

// describe prints what the audit trail will show, and nothing else. The
// key is never printed: a credential on a terminal is a credential in a
// scrollback buffer.
func describe(issued leaf) {
	_, _ = fmt.Fprintf(stdout, "common_name %s\n", issued.Parsed.Subject.CommonName)
	_, _ = fmt.Fprintf(stdout, "serial      %s\n", colonHex(issued.Parsed.SerialNumber.Bytes()))
	_, _ = fmt.Fprintf(stdout, "expires     %s\n", issued.Parsed.NotAfter.UTC().Format(time.RFC3339))
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

// dbCredential has a client certificate signed for a database and leaves
// behind a psql service entry that uses it.
//
// A service entry rather than a printed connection string: `psql
// "service=<name>"` is one word for a person to remember and the same
// word for everything that reads libpq, and the entry names the files
// rather than carrying a secret. When the certificate expires the entry
// stays and stops working, which is the honest state — the next run of
// this command replaces the files under the same entry.
func dbCredential(ctx context.Context, bao *openbao, request credentialRequest, subject string) error {
	issued, err := issue(ctx, bao, request, subject)
	if err != nil {
		return err
	}

	dir, err := credentialDir(request.env)
	if err != nil {
		return err
	}
	base := filepath.Join(dir, request.service)
	if err = writeLeaf(base, issued); err != nil {
		return err
	}

	path, err := pgServicePath()
	if err != nil {
		return err
	}
	// The database role is the certificate's common name: the server maps
	// it through `pg_ident`, so the entry must not invent a user of its
	// own.
	entry := fmt.Sprintf("[%s]\nhost=%s\nport=%s\ndbname=%s\nuser=%s\nsslmode=verify-full\nsslcert=%s\nsslkey=%s\nsslrootcert=%s\n",
		request.service, request.host, request.port, request.dbname, issued.Parsed.Subject.CommonName,
		base+".crt", base+".key", base+"-ca.crt")
	if err = writeServiceEntry(path, request.service, entry); err != nil {
		return err
	}

	describe(issued)
	_, _ = fmt.Fprintf(stdout, "\nService %q written to %s, with the certificate in %s.\n", request.service, path, dir)
	_, _ = fmt.Fprintf(stdout, "  psql \"service=%s\"\n", request.service)
	return nil
}

// clientCredential has a client certificate signed and writes it where the
// caller said, for a workload or a person calling something that wants
// mutual TLS.
func clientCredential(ctx context.Context, bao *openbao, request credentialRequest, subject string) error {
	issued, err := issue(ctx, bao, request, subject)
	if err != nil {
		return err
	}

	base := strings.TrimSuffix(strings.TrimSuffix(filepath.Clean(request.out), ".crt"), ".pem")
	if parent := filepath.Dir(base); parent != "" {
		if err = os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", parent, err)
		}
	}
	if err = writeLeaf(base, issued); err != nil {
		return err
	}

	describe(issued)
	_, _ = fmt.Fprintf(stdout, "\nWritten to %s.crt, %s.key and %s-ca.crt.\n", base, base, base)
	return nil
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

// credentialDir is where certificates this tool minted are kept: beside
// the configuration, in a directory only this account may enter.
//
// The OpenBAO token is NOT here, and is nowhere: what is on disk is a
// certificate and a key that expire on their own, and a name that says
// which environment they are for.
func credentialDir(env string) (string, error) {
	base, err := configDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "credentials", env)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

// pgServicePath is libpq's own file, in libpq's own order: the variable
// it reads first, then the file it looks for in the home directory.
func pgServicePath() (string, error) {
	if named := strings.TrimSpace(os.Getenv("PGSERVICEFILE")); named != "" {
		return named, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find the home directory: %w", err)
	}
	return filepath.Join(home, ".pg_service.conf"), nil
}

// writeServiceEntry replaces this service's entry and leaves every other
// line alone.
//
// One block per service, not one block for this tool: somebody with a
// credential for two databases has two live entries, and rewriting a
// single block would delete the one they are not minting right now.
func writeServiceEntry(path, service, entry string) error {
	start, end := serviceMarkers(service)

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	existing, err := os.ReadFile(path) //nolint:gosec // the caller's own libpq configuration
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	body := stripBlock(string(existing), start, end) + start + "\n" + entry + end + "\n"
	if err = os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// serviceMarkers name the block one service owns. `#` is a comment to
// libpq as it is to the AWS configuration, so the markers are invisible
// to everything but this.
func serviceMarkers(service string) (string, string) {
	return fmt.Sprintf("# >>> accessctl %s >>>", service), fmt.Sprintf("# <<< accessctl %s <<<", service)
}
