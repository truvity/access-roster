package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The local installation (docs/runtimes/local.md). These are the public names of the harness, not of any real host.
const (
	project  = "sluis-local" // the Compose project
	boundary = "dev"
	tenant   = "acme" // the default tenant of the boundary (tests/installations/local/config/boundary.yaml)
	host     = "sluis.dev.local.test"
	audience = "sluis-cli" // an InstallationClient of the local config
	image    = "sluis-local/signer:dev"
	// batchWait is the writer's batch interval (5 s) with margin.
	batchWait = 20 * time.Second
)

// services the smoke needs healthy before it starts.
var services = []string{"policy", "signer", "key", "store", "writer", "entry", "forwarder", "rqlite", "drv-key-software", "drv-writer-spool", "drv-writer-fs"}

func smoke() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cli := filepath.Join(root, "dist", "local", "bin", "cli", "sluis")
	caFile := os.Getenv("SSL_CERT_FILE")
	if caFile == "" {
		return errors.New("SSL_CERT_FILE does not name the harness CA (.cache/local/ca/ca.pem); run it as `just local-smoke`")
	}
	if _, err := os.Stat(cli); err != nil {
		return fmt.Errorf("%s is missing; run `just local-up` first", cli)
	}
	if err := requireHealthy(); err != nil {
		return err
	}
	d := &docker{self: self, cli: cli}

	// --- 1. The decision, and 2. the token: the harness client under the uid of exchange.
	corr := "smoke-" + strconv.FormatInt(time.Now().UnixMilli(), 36)
	var dec decideOut
	err = d.step(&dec, spec{user: "exchange", groups: []string{"policy", "signer"}, mounts: []string{"run-policy:/run/sluis/policy", "run-signer:/run/sluis/signer"}},
		"decide-sign", "--boundary", boundary, "--tenant", tenant, "--issuer", "https://"+host, "--audience", audience, "--correlation", corr)
	if err != nil {
		return fmt.Errorf("the client under the uid of exchange: %w", err)
	}
	fmt.Println("== 1. The decision (policy, asked by the uid of exchange)")
	fmt.Printf("action:        token.exchange for p-alice, client %s, tenant %s\n", audience, tenant)
	fmt.Printf("decision:      %s\n", strings.ToLower(dec.Decision))
	fmt.Printf("grant names:   %s\n", strings.Join(dec.GrantNames, ", "))
	fmt.Printf("decided by:    %s\n", strings.Join(dec.PolicyIDs, ", "))
	fmt.Printf("decision id:   %s\n", dec.DecisionID)
	fmt.Printf("sealed grant:  %s\n", sealedText(dec.SealedGrant))
	if dec.Decision != "ALLOW" {
		return errors.New("policy did not allow the token.exchange the local config allows")
	}
	if !contains(dec.GrantNames, "dev:example-app:user") {
		return errors.New("the decision does not name the grant dev:example-app:user")
	}
	if dec.SealedGrant == 0 {
		return errors.New("the decision is an allow without a sealed grant")
	}
	if dec.Token == "" {
		return errors.New("signer returned no token")
	}

	fmt.Println("\n== 2. The token (signer, signed by key@ in place)")
	hdr, claims, err := decode(dec.Token)
	if err != nil {
		return err
	}
	fmt.Printf("header:        %s\n", hdr)
	fmt.Printf("claims:        %s\n", claims)
	keys, err := fetchJWKS(caFile)
	if err != nil {
		return err
	}
	if err := verifyToken(dec.Token, keys); err != nil {
		return err
	}
	fmt.Printf("signature:     ES384, verified with kid %s from https://%s/jwks (the forwarder, trusting only the harness CA)\n", dec.KeyID, host)

	// --- 3. The audit trail.
	fmt.Println("\n== 3. The audit trail (emitters, spool, writer, fs blob)")
	logCopy, err := os.MkdirTemp("", "spine-log-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(logCopy) }()
	if err := os.Chmod(logCopy, 0o755); err != nil { //nolint:gosec // the indexer's uid must enter the copy
		return err
	}
	// The indexer opens evidence (a built-in permit of policy); the log is a copy of the blob below the writer's driver,
	// whose directory only its own uid may enter.
	indexer := spec{user: "indexer", groups: []string{"policy"},
		mounts: []string{"run-policy:/run/sluis/policy", "key-indexer:/run/sluis/key/" + boundary}}
	var found auditOut
	var lastErr error
	deadline := time.Now().Add(batchWait)
	for {
		if err := d.copyLog(root, logCopy); err != nil {
			return err
		}
		found = auditOut{}
		err = d.step(&found, withDir(indexer, logCopy+":/log"), "audit-find", "--boundary", boundary, "--blob", "/log",
			"--decision-id", dec.DecisionID, "--correlation", corr)
		if err != nil && !strings.Contains(err.Error(), "no checkpoint yet") {
			return fmt.Errorf("the records of this run: %w", err)
		}
		lastErr = err
		if err == nil && found.complete() || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if lastErr != nil {
		return fmt.Errorf("the log could not be read within %s: %w", batchWait, lastErr)
	}
	for _, w := range wanted {
		ok := false
		for _, f := range found.Found {
			if f.Event == w {
				fmt.Printf("record:        %-14s by %s\n", f.Event, f.Actor)
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("the log (%d entries, %d records) holds no %s record of this run within %s", found.Size, found.Records, w, batchWait)
		}
	}
	vk, err := verifierKey()
	if err != nil {
		return err
	}
	out, err := d.verify(vk, logCopy)
	if err != nil {
		return fmt.Errorf("sluis audit verify: %w", err)
	}
	fmt.Println("verify:       ", out)

	// --- 4. The shared store, through store@ and as readers the registry allows.
	fmt.Println("\n== 4. The shared store (read through store@)")
	var ring readOut
	err = d.step(&ring, spec{user: "signer", groups: []string{"store"}, mounts: []string{"run-store:/run/sluis/store"}},
		"store-read", "--kind", "signing-ring", "--tenant", "")
	if err != nil {
		return fmt.Errorf("SigningRing as signer: %w", err)
	}
	if len(ring.Items) != 1 || len(ring.Items[0].Detail) == 0 {
		return errors.New("SigningRing holds no key")
	}
	fmt.Printf("SigningRing:   default at version %d, keys: %s (read as signer)\n", ring.Items[0].Version, strings.Join(ring.Items[0].Detail, "; "))
	if !strings.Contains(strings.Join(ring.Items[0].Detail, " "), dec.KeyID+" ES384 active") {
		return errors.New("the SigningRing does not hold the key that signed the token as an active ES384 key")
	}
	var wraps readOut
	err = d.step(&wraps, spec{user: "key", groups: []string{"store"}, mounts: []string{"run-store:/run/sluis/store"}},
		"store-read", "--kind", "data-key-wrap", "--tenant", tenant)
	if err != nil {
		return fmt.Errorf("DataKeyWrap as key: %w", err)
	}
	if len(wraps.Items) == 0 {
		return errors.New("DataKeyWrap holds no item")
	}
	ids := make([]string, 0, len(wraps.Items))
	for _, it := range wraps.Items {
		ids = append(ids, it.ID)
	}
	fmt.Printf("DataKeyWrap:   %d items in tenant %s (read as key@): %s\n", len(wraps.Items), tenant, strings.Join(ids, ", "))

	fmt.Println("\nsmoke: M1 passed")
	return nil
}

func sealedText(n int) string {
	if n == 0 {
		return "none"
	}
	return fmt.Sprintf("yes (%d bytes, not shown)", n)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
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

// requireHealthy fails with the name of every service of the project that is missing or not healthy.
func requireHealthy() error {
	out, err := exec.Command("docker", "ps", "--all", "--filter", "label=com.docker.compose.project="+project,
		"--format", `{{.Label "com.docker.compose.service"}} {{.State}} {{.Status}}`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker is not usable: %s", strings.TrimSpace(string(out)))
	}
	have := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(l, " ", 3)
		if len(f) == 3 {
			have[f[0]] = f[1] + " " + f[2]
		}
	}
	var bad []string
	for _, s := range services {
		st, ok := have[s]
		switch {
		case !ok:
			bad = append(bad, s+" (missing)")
		case !strings.HasPrefix(st, "running") || strings.Contains(st, "unhealthy") || strings.Contains(st, "starting"):
			bad = append(bad, s+" ("+st+")")
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("the local installation is not up: %s; run `just local-up`", strings.Join(bad, ", "))
	}
	return nil
}

// docker runs the steps in containers.
type docker struct{ self, cli string }

// spec is the identity and the mounts of a container: the actor whose uid it has, the actors whose socket groups it
// joins, and the volumes of the project to mount read-only.
type spec struct {
	user   string
	groups []string
	mounts []string
}

func uidOf(name string) (string, error) {
	u, ok := registry.UID(name, 0)
	if !ok {
		return "", fmt.Errorf("%s has no uid in the registry", name)
	}
	return strconv.FormatUint(uint64(u), 10), nil
}

func (d *docker) args(s spec, entrypoint, binary string) ([]string, error) {
	u, err := uidOf(s.user)
	if err != nil {
		return nil, err
	}
	a := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--user", u + ":" + u}
	for _, g := range s.groups {
		gid, err := uidOf(g)
		if err != nil {
			return nil, err
		}
		a = append(a, "--group-add", gid)
	}
	for _, m := range s.mounts {
		if dir, ok := strings.CutPrefix(m, "dir:"); ok {
			a = append(a, "-v", dir+":ro") // a directory of the host
			continue
		}
		a = append(a, "-v", project+"_"+m+":ro")
	}
	a = append(a, "-v", binary+":"+entrypoint+":ro", "--entrypoint", entrypoint, image)
	return a, nil
}

// step runs `spine step <name>` in a container and decodes its JSON answer.
func (d *docker) step(into any, s spec, name string, args ...string) error {
	a, err := d.args(s, "/spine", d.self)
	if err != nil {
		return err
	}
	a = append(a, append([]string{"step", name}, args...)...)
	var stdout, stderr bytes.Buffer
	c := exec.Command("docker", a...) //nolint:gosec // the arguments are built here from the registry and constants
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s: %s", name, strings.TrimSpace(stderr.String()))
	}
	if err := json.Unmarshal(stdout.Bytes(), into); err != nil {
		return fmt.Errorf("%s: the answer is not JSON", name)
	}
	return nil
}

// verify runs the CLI's `audit verify` on a copy of the log. It needs no container: it reads files and checks them
// against the log's public key.
func (d *docker) verify(verifierKey, dir string) (string, error) {
	var stdout, stderr bytes.Buffer
	c := exec.Command(d.cli, "audit", "verify", "--key", verifierKey, dir) //nolint:gosec // the CLI of this build
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(stderr.String()+stdout.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// copyLog copies the log of the writer's blob into dst, as the uid that owns the blob (nobody else may enter it), by
// way of a tar stream. Only directories and regular files are taken.
func (d *docker) copyLog(root, dst string) error {
	compose, err := os.ReadFile(filepath.Join(root, "deploy", "local", "compose.yaml")) //nolint:gosec // a file of this repository
	if err != nil {
		return err
	}
	alpine := regexp.MustCompile(`alpine@sha256:[0-9a-f]{64}`).FindString(string(compose))
	if alpine == "" {
		return errors.New("deploy/local/compose.yaml names no alpine image")
	}
	u, err := uidOf("driver-writer-fs")
	if err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	c := exec.Command("docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--user", u+":"+u, //nolint:gosec // the image is pinned in the Compose file of this repository
		"-v", project+"_state-blob:/blob:ro", alpine, "tar", "-C", "/blob/audit/main", "-cf", "-", ".")
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("copy the log: %s", strings.TrimSpace(stderr.String()))
	}
	tr := tar.NewReader(&stdout)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("copy the log: %w", err)
		}
		name := filepath.Clean(h.Name)
		if !filepath.IsLocal(name) {
			return errors.New("copy the log: a path leaves the log")
		}
		p := filepath.Join(dst, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil { //nolint:gosec // a temporary copy the indexer's uid must enter
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // as above
				return err
			}
			if err := writeLimited(p, tr); err != nil {
				return err
			}
		}
	}
}

func writeLimited(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec // readable by the indexer's uid
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(r, 1<<25)); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func withDir(s spec, dir string) spec {
	s.mounts = append(append([]string{}, s.mounts...), "dir:"+dir)
	return s
}

var verifierRE = regexp.MustCompile(`"verifier_key":"([^"]+)"`)

// verifierKey is the public key of the log, which the writer logs when it starts.
func verifierKey() (string, error) {
	out, err := exec.Command("docker", "ps", "-q", "--filter", "label=com.docker.compose.project="+project,
		"--filter", "label=com.docker.compose.service=writer").Output()
	id := strings.TrimSpace(string(out))
	if err != nil || id == "" {
		return "", errors.New("the writer container is not running")
	}
	logs, err := exec.Command("docker", "logs", id).CombinedOutput() //nolint:gosec // id is a container id that docker printed
	if err != nil {
		return "", errors.New("the writer's log cannot be read")
	}
	all := verifierRE.FindAllSubmatch(logs, -1)
	if len(all) == 0 {
		return "", errors.New("the writer's log does not carry the log's verifier key")
	}
	return string(all[len(all)-1][1]), nil
}

// decode returns the header and the claims of a compact JWS as JSON text. The signature is never decoded or shown.
func decode(token string) (header, claims string, err error) {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return "", "", errors.New("the token is not a compact JWS")
	}
	h, err1 := base64.RawURLEncoding.DecodeString(p[0])
	c, err2 := base64.RawURLEncoding.DecodeString(p[1])
	if err1 != nil || err2 != nil {
		return "", "", errors.New("the token is not base64url")
	}
	return string(h), string(c), nil
}

// fetchJWKS reads /jwks from entry through the forwarder on the loopback port, trusting only the CA file the
// environment names (SSL_CERT_FILE), and never the system pool.
func fetchJWKS(caFile string) (*jose.JSONWebKeySet, error) {
	pem, err := os.ReadFile(caFile) //nolint:gosec // the recipe names the harness CA
	if err != nil {
		return nil, fmt.Errorf("SSL_CERT_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("SSL_CERT_FILE holds no certificate")
	}
	port := os.Getenv("SLUIS_LOCAL_PORT")
	if port == "" {
		port = "8443"
	}
	hc := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, ServerName: host},
			// The name is a .test name that only the harness knows: it is mapped to the loopback here, as `curl
			// --resolve` does, and the certificate is still checked against the name.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			},
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+":"+port+"/jwks", http.NoBody) //nolint:gosec // the host is the harness name; only the loopback port comes from the environment
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req) //nolint:gosec // as above
	if err != nil {
		return nil, fmt.Errorf("GET /jwks through the forwarder: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil || res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jwks through the forwarder: status %d", res.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, errors.New("/jwks is not a JWK Set")
	}
	return &set, nil
}

// verifyToken checks the signature of an ES384 JWS against the key set (RFC 7515 section 5.2; RFC 7517).
func verifyToken(token string, set *jose.JSONWebKeySet) error {
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return fmt.Errorf("the token is not an ES384 JWS: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return errors.New("the token has more than one signature")
	}
	kid := jws.Signatures[0].Header.KeyID
	keys := set.Key(kid)
	if len(keys) == 0 {
		return fmt.Errorf("the key set at /jwks has no key %q", kid)
	}
	if _, err := jws.Verify(keys[0]); err != nil {
		return errors.New("the signature does not verify with the key set at /jwks")
	}
	return nil
}
