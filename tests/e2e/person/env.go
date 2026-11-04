package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The local installation (docs/runtimes/local.md). These are the public names of the harness, not of any real host.
const (
	boundary = "dev"
	tenant   = "acme" // the default tenant of the boundary (tests/installations/local/config/boundary.yaml)
	host     = "sluis.dev.local.test"
	issuer   = "https://" + host
	cliID    = "sluis-cli"   // the client the CLI signs in as
	audience = "example-app" // the audience of `sluis token`
)

// config is what the run takes from its surroundings. None of it is in the repository.
type config struct {
	root     string // the repository
	project  string // the Compose project (COMPOSE_PROJECT_NAME, default sluis-local)
	tag      string // the tag of the images (SLUIS_LOCAL_TAG, default dev)
	port     string // the loopback port of the forwarder (SLUIS_LOCAL_PORT, default 8443)
	caFile   string // the harness CA (SSL_CERT_FILE)
	cli      string // the sluis executable of the build
	secrets  string // the file with the identity provider's users' secrets
	pool     *x509.CertPool
	dialHost string // the forwarder's loopback address
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() (*config, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	c := &config{
		root: root, project: envOr("COMPOSE_PROJECT_NAME", "sluis-local"), tag: envOr("SLUIS_LOCAL_TAG", "dev"),
		port: envOr("SLUIS_LOCAL_PORT", "8443"), caFile: os.Getenv("SSL_CERT_FILE"),
		cli: filepath.Join(root, "dist", "local", "bin", "cli", "sluis"),
	}
	c.secrets = os.Getenv("SLUIS_KEYCLOAK_SECRETS")
	if c.secrets == "" && os.Getenv("SLUIS_BUILD_DIR") != "" {
		c.secrets = filepath.Join(os.Getenv("SLUIS_BUILD_DIR"), "keycloak-secrets.env")
	}
	if c.caFile == "" {
		return nil, errors.New("SSL_CERT_FILE does not name the harness CA (.cache/local/ca/ca.pem); run it as a `just` recipe")
	}
	pem, err := os.ReadFile(c.caFile) //nolint:gosec // the recipe names the harness CA
	if err != nil {
		return nil, fmt.Errorf("SSL_CERT_FILE: %w", err)
	}
	c.pool = x509.NewCertPool()
	if !c.pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("SSL_CERT_FILE holds no certificate")
	}
	if c.secrets == "" {
		return nil, errors.New("SLUIS_KEYCLOAK_SECRETS (or SLUIS_BUILD_DIR) does not name the identity provider's secrets file")
	}
	if _, err := os.Stat(c.cli); err != nil {
		return nil, fmt.Errorf("%s is missing; run `just local-up` first", c.cli)
	}
	c.dialHost = net.JoinHostPort("127.0.0.1", c.port)
	return c, nil
}

// repoRoot is the directory with the Justfile, found from the working directory.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "Justfile")); err == nil {
			return d, nil
		}
		if d == filepath.Dir(d) {
			return "", errors.New("no Justfile above the working directory; run it from the repository")
		}
	}
}

// httpClient is the harness's client: the installation's host name goes to the forwarder's loopback port as `curl
// --resolve` would send it, and the certificate is checked against the name and the harness CA alone (never the system
// pool). Every other host is dialled as it is, which is how it reaches the identity provider on the loopback.
func (c *config) httpClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: c.pool, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				if h, _, err := net.SplitHostPort(addr); err == nil && h == host {
					addr = c.dialHost
				}
				return d.DialContext(ctx, network, addr)
			},
		},
	}
}

// proxy is a CONNECT proxy that serves one name: the installation's host, whatever the port, is the forwarder. The CLI
// is the product's executable with no flag for it, and Go's HTTP client sends https requests through HTTPS_PROXY, so
// this is how the CLI reaches a `.test` name that no hosts file maps and a forwarder that listens on a high port.
type proxy struct {
	ln       net.Listener
	dialHost string
}

func (c *config) startProxy() (*proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &proxy{ln: ln, dialHost: c.dialHost}
	go func() { _ = http.Serve(ln, p) }() //nolint:gosec // a loopback proxy of a test, closed with the run
	return p, nil
}

func (p *proxy) URL() string { return "http://" + p.ln.Addr().String() }
func (p *proxy) Close()      { _ = p.ln.Close() }

// ServeHTTP answers CONNECT for the installation's host and refuses everything else.
func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h, _, err := net.SplitHostPort(r.Host)
	if r.Method != http.MethodConnect || err != nil || h != host {
		http.Error(w, "this proxy serves the installation's host only", http.StatusForbidden)
		return
	}
	up, err := net.DialTimeout("tcp", p.dialHost, 10*time.Second)
	if err != nil {
		http.Error(w, "the forwarder is not reachable", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = brw.Flush()
	go func() { _, _ = io.Copy(up, brw); _ = up.Close() }()
	go func() { _, _ = io.Copy(conn, up); _ = conn.Close() }()
}

// secretsOf reads the named variables from the secrets file inside this process. The values are returned to the
// caller and nowhere else: the file is never printed, and a missing name is reported by name only.
func secretsOf(path string, names ...string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // the recipe names the harness's secrets file
	if err != nil {
		return nil, fmt.Errorf("the secrets file: %w", err)
	}
	defer func() { _ = f.Close() }()
	all := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			all[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	out := map[string]string{}
	for _, n := range names {
		v, ok := all[n]
		if !ok || v == "" {
			return nil, fmt.Errorf("the secrets file has no %s", n)
		}
		out[n] = v
	}
	return out, nil
}
