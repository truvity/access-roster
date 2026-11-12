package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
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
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The three forms of `sluis key revoke` against the local installation (docs/reference/cli.md, "sluis key revoke"):
//
//  1. `--kid` and `--reason` write the declaration. It runs on the host and reads nothing.
//  2. The publisher signs it: tools/harness/sign-config, with the publisher key of this run.
//  3. `--declaration` delivers it to key@'s admin socket and then checks that the key left both key sets a verifier can be
//     given: the public one that the issuer's discovery document names, and the live one of entry's socket.
//  4. `--check` looks again, delivering nothing.
//
// The key it revokes is a drill: 32 random bytes as a thumbprint that no component holds, delivered with `allow_unknown`.
// key@ writes a KeyRevocation for it, audits it and refuses nothing, and no component's key is touched, so every other step
// of the job runs as before. The negative control is `--check` on a key the installation does publish: it must say
// `still listed` and exit 5, or the confirmation proves nothing.

// revokeObject is the `revoke` member of the JSON object of `sluis key revoke`.
type revokeObject struct {
	Written string `json:"written"`
	Seq     uint64 `json:"seq"`
	Keys    []struct {
		Kid     string `json:"kid"`
		Already bool   `json:"already"`
		Unknown bool   `json:"unknown"`
		Pending bool   `json:"pending"`
	} `json:"keys"`
	Audited      *bool `json:"audited"`
	Confirmation *struct {
		Confirmed bool     `json:"confirmed"`
		Rounds    int      `json:"rounds"`
		Kids      []string `json:"kids"`
		Warnings  []string `json:"warnings"`
		Addresses []struct {
			Name         string   `json:"name"`
			Address      string   `json:"address"`
			State        string   `json:"state"`
			Issuer       string   `json:"issuer"`
			IssuerSource string   `json:"issuer_source"`
			Keys         *int     `json:"keys"`
			Listed       []string `json:"listed"`
			Reason       string   `json:"reason"`
		} `json:"addresses"`
	} `json:"confirmation"`
}

var thumbprint = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// checkRevokeWritten judges the first form: the declaration file for one key, and the object that names it.
func checkRevokeWritten(r ran, path, kid string) error {
	o, err := decode(r, "key revoke")
	if err != nil {
		return err
	}
	if r.code != 0 || o.Outcome != "done" {
		return fmt.Errorf("exit %d, outcome %s, want 0 and done: %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
	}
	if o.Revoke == nil || o.Revoke.Written != path {
		return fmt.Errorf("the object does not say that %s was written", path)
	}
	b, err := os.ReadFile(path) //nolint:gosec // the file this run asked the command to write
	if err != nil {
		return err
	}
	for _, line := range []string{"boundary: " + boundary, "  - " + kid, "reason: drill", "allow_unknown: true"} {
		if !slicesContainsLine(string(b), line) {
			return fmt.Errorf("the declaration has no line %q", line)
		}
	}
	return nil
}

func slicesContainsLine(text, line string) bool {
	for _, l := range strings.Split(text, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

// checkConfirmedAbsent judges a confirmation that found the key in neither key set: the public one and entry's, in that
// order, each read (it counts keys, the positive control) and each naming the issuer it belongs to.
func checkConfirmedAbsent(o *object) error {
	if o.Revoke == nil {
		return errors.New("the object has no revoke member")
	}
	c := o.Revoke.Confirmation
	if c == nil || !c.Confirmed {
		return fmt.Errorf("the keys are not confirmed gone: %+v", c)
	}
	if len(c.Addresses) != 2 || c.Addresses[0].Name != "public" || c.Addresses[1].Name != "entry" {
		return fmt.Errorf("the confirmation reads %d addresses, want the public key set and entry's", len(c.Addresses))
	}
	for _, a := range c.Addresses {
		if a.State != "absent" {
			return fmt.Errorf("the %s key set is %s (%s), want absent", a.Name, a.State, a.Reason)
		}
		if a.Keys == nil || *a.Keys == 0 {
			return fmt.Errorf("the %s key set was read but lists no key: an absent key proves nothing", a.Name)
		}
		if a.Issuer == "" {
			return fmt.Errorf("the %s address names no issuer", a.Name)
		}
	}
	return nil
}

// checkDelivered judges the delivery of the signed declaration (the second form), or its repeat: one key, unknown to key@,
// revoked now or already revoked, the audit fact durable, and the confirmation clean.
func checkDelivered(r ran, kid string, already bool) error {
	o, err := decode(r, "key revoke")
	if err != nil {
		return err
	}
	if r.code != 0 || o.Outcome != "done" {
		return fmt.Errorf("exit %d, outcome %s, want 0 and done: %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
	}
	v := o.Revoke
	if v == nil || len(v.Keys) != 1 || v.Keys[0].Kid != kid {
		return fmt.Errorf("the object does not list the one key %s: %+v", kid, v)
	}
	if k := v.Keys[0]; k.Already != already || !k.Unknown || k.Pending {
		return fmt.Errorf("the key is already=%t unknown=%t pending=%t, want already=%t unknown=true pending=false", k.Already, k.Unknown, k.Pending, already)
	}
	if v.Seq == 0 || v.Audited == nil || !*v.Audited {
		return fmt.Errorf("seq %d, audited %v: key@ must take the declaration and make its fact durable", v.Seq, v.Audited)
	}
	return checkConfirmedAbsent(o)
}

// checkCheckedAbsent judges `--check` on the key of the drill: nothing delivered, both key sets without it.
func checkCheckedAbsent(r ran) error {
	o, err := decode(r, "key revoke")
	if err != nil {
		return err
	}
	if r.code != 0 || o.Outcome != "done" || o.Revoke == nil {
		return fmt.Errorf("exit %d, outcome %s, want 0 and done: %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
	}
	if o.Revoke.Seq != 0 || len(o.Revoke.Keys) != 0 {
		return errors.New("--check delivered something: it must only look")
	}
	return checkConfirmedAbsent(o)
}

// checkStillListed judges `--check` on a key that both key sets list: exit 5, failed, not confirmed, and each address says
// `listed` and names the key.
func checkStillListed(r ran, kid string) error {
	o, err := decode(r, "key revoke")
	if err != nil {
		return err
	}
	if r.code != 5 || o.Outcome != "failed" {
		return fmt.Errorf("exit %d, outcome %s, want 5 and failed: %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
	}
	if o.Revoke == nil || o.Revoke.Confirmation == nil {
		return errors.New("the object has no confirmation")
	}
	c := o.Revoke.Confirmation
	if c.Confirmed || len(c.Addresses) != 2 {
		return fmt.Errorf("the confirmation is %+v, want two addresses and not confirmed", c)
	}
	for _, a := range c.Addresses {
		if a.State != "listed" || len(a.Listed) != 1 || a.Listed[0] != kid {
			return fmt.Errorf("the %s key set is %s %v (%s), want listed with %s", a.Name, a.State, a.Listed, a.Reason, kid)
		}
	}
	return nil
}

// randomKid is a thumbprint-shaped id that no key has: 32 random bytes, base64url without padding.
func randomKid() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func keyRevokeSmoke(e *env) error {
	fmt.Println("== sluis key revoke")
	kid, err := randomKid()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "cli-smoke-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	declaration, signed := filepath.Join(tmp, "revoke.yaml"), filepath.Join(tmp, "revoke.jws")

	// 1. The declaration, and the refusals of its arguments.
	r, err := onHost(e.cli, "key", "revoke", "--boundary", boundary, "--kid", kid, "--reason", "drill", "--allow-unknown", "--out", declaration, "--output", "json")
	if err != nil {
		return err
	}
	if err := checkRevokeWritten(r, declaration, kid); err != nil {
		return fmt.Errorf("--kid: %w", err)
	}
	fmt.Printf("%-44s exit 0  declaration for one key\n", "key revoke --kid ... --out")
	other, err := randomKid()
	if err != nil {
		return err
	}
	for name, args := range map[string][]string{
		"a key id that is not a thumbprint": {"--kid", "short", "--reason", "drill"},
		"a key named twice":                 {"--kid", kid, "--kid", kid, "--reason", "drill"},
		"a reason that is not one":          {"--kid", kid, "--reason", "because"},
		"a confirmation flag with --kid":    {"--kid", kid, "--reason", "drill", "--wait", "5s"},
		"--check with a reason":             {"--check", "--kid", kid, "--reason", "drill"},
		"--declaration with a key":          {"--declaration", signed, "--kid", other},
	} {
		if r, err = onHost(e.cli, append([]string{"key", "revoke", "--boundary", boundary}, args...)...); err != nil {
			return err
		}
		if err := checkUsage(r); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if r, err = onHost(e.cli, "key", "revoke", "--kid", kid, "--reason", "drill"); err != nil {
		return err
	}
	if err := checkUsage(r); err != nil {
		return fmt.Errorf("no boundary: %w", err)
	}
	fmt.Printf("%-44s exit 2\n", "bad key id, twice, bad reason, mixed flags")

	// 2. The publisher signs it.
	sign := exec.Command("go", "run", "./tools/harness/sign-config", "-key-dir", filepath.Join(e.root, ".cache", "local", "publisher"), //nolint:gosec // the harness of this repository, with paths made here
		"-declaration", declaration, "-declaration-out", signed)
	sign.Dir = e.root
	if out, err := sign.CombinedOutput(); err != nil {
		return fmt.Errorf("sign-config: %w: %s", err, cut(string(out)))
	}

	// 3. The delivery, in a container that has key@'s admin socket, entry's socket and the network of the installation.
	rig, err := startRig(e, signed)
	if err != nil {
		return err
	}
	defer rig.stop()
	deliver := []string{"key", "revoke", "--boundary", boundary, "--declaration", "/revoke.jws", "--wait", "90s", "--output", "json"}
	if r, err = rig.run(deliver...); err != nil {
		return err
	}
	if err := checkDelivered(r, kid, false); err != nil {
		return fmt.Errorf("--declaration: %w\nstandard error: %s\nthe relay says: %s", err, cut(r.stderr), rig.logs())
	}
	fmt.Printf("%-44s exit 0  revoked, confirmed absent from both key sets\n", "key revoke --declaration")
	// The same declaration again is a retry of the declaration taken last: the key is already revoked.
	if r, err = rig.run(deliver...); err != nil {
		return err
	}
	if err := checkDelivered(r, kid, true); err != nil {
		return fmt.Errorf("--declaration again: %w", err)
	}
	fmt.Printf("%-44s exit 0  already revoked\n", "key revoke --declaration, again")

	// 4. The second look, and its negative control.
	if r, err = rig.run("key", "revoke", "--boundary", boundary, "--check", "--kid", kid, "--wait", "0", "--output", "json"); err != nil {
		return err
	}
	if err := checkCheckedAbsent(r); err != nil {
		return fmt.Errorf("--check on the revoked key: %w", err)
	}
	fmt.Printf("%-44s exit 0  confirmed\n", "key revoke --check --kid (the drill key)")
	live, err := publishedThumbprint(e)
	if err != nil {
		return err
	}
	if r, err = rig.run("key", "revoke", "--boundary", boundary, "--check", "--kid", live, "--wait", "0", "--output", "json"); err != nil {
		return err
	}
	if err := checkStillListed(r, live); err != nil {
		return fmt.Errorf("--check on a key the installation publishes: %w", err)
	}
	fmt.Printf("%-44s exit 5  still listed in both key sets\n", "key revoke --check --kid (a published key)")
	return nil
}

// rig is what the delivery needs: the signed declaration, and the issuer's name reaching the forwarder. The issuer of the
// local installation is https://sluis.dev.local.test on the standard port, which the forwarder serves on 8443 for a browser
// that goes through a proxy (deploy/local/Caddyfile). The CLI reads the public key set with no proxy, so a relay of the
// installation's network answers to that name on port 443 and passes the bytes on to the forwarder. TLS ends at the
// forwarder, with the leaf of the harness CA, which the CLI is given by SSL_CERT_FILE.
type rig struct {
	e      *env
	signed string
	relay  string
	net    string
}

func startRig(e *env, signed string) (*rig, error) {
	compose, err := os.ReadFile(filepath.Join(e.root, "deploy", "local", "compose.yaml"))
	if err != nil {
		return nil, err
	}
	socat := regexp.MustCompile(`alpine/socat@sha256:[0-9a-f]{64}`).FindString(string(compose))
	if socat == "" {
		return nil, errors.New("deploy/local/compose.yaml names no socat image")
	}
	g := &rig{e: e, signed: signed, relay: project + "-revoke-relay", net: project + "_default"}
	_ = exec.Command("docker", "rm", "-f", g.relay).Run()                                                                                     //nolint:gosec // a name made here
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", g.relay, "--network", g.net, "--network-alias", "sluis.dev.local.test", //nolint:gosec // the image is pinned in the Compose file
		"--user", "0:0", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true",
		socat, "TCP-LISTEN:443,fork,reuseaddr", "TCP:forwarder:8443").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("the relay did not start: %s", cut(string(out)))
	}
	time.Sleep(2 * time.Second)
	if out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", g.relay).Output(); err != nil || strings.TrimSpace(string(out)) != "true" { //nolint:gosec // a name made here
		return nil, errors.New("the relay stopped; see `docker logs " + g.relay + "`")
	}
	return g, nil
}

// logs is the end of the relay's log, for a failure.
func (g *rig) logs() string {
	out, _ := exec.Command("docker", "logs", "--tail", "20", g.relay).CombinedOutput() //nolint:gosec // a name made here
	return cut(string(out))
}

func (g *rig) stop() { _ = exec.Command("docker", "rm", "-f", g.relay).Run() } //nolint:gosec // a name made here

// run runs the CLI as root in a container with key@'s run directory, entry's, the harness CA and the network.
func (g *rig) run(args ...string) (ran, error) {
	a := []string{"run", "--rm", "--network", g.net, "--read-only", "--security-opt", "no-new-privileges:true", "--user", "0:0",
		"-v", project + "_run-key:/run/sluis/key:ro", "-v", project + "_run-entry:/run/sluis/entry:ro",
		"-v", filepath.Join(g.e.root, ".cache", "local", "ca", "ca.pem") + ":/ca.pem:ro", "-e", "SSL_CERT_FILE=/ca.pem",
		"-v", g.signed + ":/revoke.jws:ro", "-v", g.e.cli + ":/sluis:ro", "--entrypoint", "/sluis", image}
	return run(exec.Command("docker", append(a, args...)...)) //nolint:gosec // the arguments are built here from constants
}

// publishedThumbprint is the RFC 7638 thumbprint of the first key of the public key set, read through the forwarder's
// published port the way a relying party would, trusting only the harness CA.
func publishedThumbprint(e *env) (string, error) {
	pem, err := os.ReadFile(filepath.Join(e.root, ".cache", "local", "ca", "ca.pem"))
	if err != nil {
		return "", err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return "", errors.New("the CA of this run is not a certificate")
	}
	port := os.Getenv("SLUIS_LOCAL_PORT")
	if port == "" {
		port = "8443"
	}
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "sluis.dev.local.test", MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			},
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://sluis.dev.local.test/jwks", nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("the public key set: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("the public key set: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the public key set: status %d", resp.StatusCode)
	}
	return firstThumbprint(body)
}

// firstThumbprint is the thumbprint of the first key of a JSON Web Key Set.
func firstThumbprint(set []byte) (string, error) {
	var s jose.JSONWebKeySet
	if err := json.NewDecoder(bytes.NewReader(set)).Decode(&s); err != nil {
		return "", fmt.Errorf("the public key set is not a key set: %w", err)
	}
	if len(s.Keys) == 0 {
		return "", errors.New("the public key set holds no key")
	}
	tp, err := s.Keys[0].Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(tp)
	if !thumbprint.MatchString(id) {
		return "", errors.New("the thumbprint of the first key is not 43 characters of base64url")
	}
	return id, nil
}
