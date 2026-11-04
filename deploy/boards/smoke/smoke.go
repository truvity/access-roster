package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// The boards' installation (PLAN.md §6, D-12, D-16). These are the public names of the harness, not of any host.
const (
	boundary = "dev"
	tenant   = "acme" // the default tenant of the boundary (tests/installations/local/config/boundary.yaml)
	host     = "sluis.dev.boards.test"
	audience = "sluis-cli" // an InstallationClient of the config
	// batchWait is the writer's batch interval (5 s) with margin.
	batchWait = 40 * time.Second
	blobLog   = "/var/lib/sluis-state/dev/drv-writer-fs/audit/main"
)

// units the smoke needs active on a board before it starts.
var units = []string{
	"sluis-drv-key-software", "sluis-drv-store-credential", "sluis-drv-store-file", "sluis-drv-store-rqlite-durable",
	"sluis-drv-store-rqlite-temp", "sluis-drv-writer-fs", "sluis-drv-writer-spool",
	"sluis-store", "sluis-key", "sluis-writer", "sluis-entry", "sluis-policy", "sluis-signer",
}

// board is one board reached over SSH.
type board struct {
	addr, user, agent string
	dir               string // a directory only root can write, with the smoke's executables
	node              string // the board's host name, which is the node name in the ring
	keyID             string // the key that signed this run's token, which the later boards must find in the ring
}

func smoke() error {
	list := strings.Fields(os.Getenv("SLUIS_BOARDS"))
	user := os.Getenv("SLUIS_BOARD_SSH_USER")
	if len(list) == 0 || user == "" {
		return errors.New("SLUIS_BOARDS and SLUIS_BOARD_SSH_USER are not set; source the run.env of the build")
	}
	agent := os.Getenv("SLUIS_BOARD_SSH_AUTH_SOCK")
	if agent == "" {
		agent = os.Getenv("SSH_AUTH_SOCK")
	}
	root, err := repoRoot()
	if err != nil {
		return err
	}
	step := filepath.Join(root, "dist", "arm64", "smoke", "spine")
	cli := filepath.Join(root, "dist", "arm64", "cli", "sluis")
	for _, f := range []string{step, cli} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("%s is missing; run `just boards-smoke`, which builds it, after `just build-arm64`", f)
		}
	}
	var done []*board // the boards that passed, whose items the next must find
	for _, addr := range list {
		if !regexp.MustCompile(`^[A-Za-z0-9.-]+$`).MatchString(addr) {
			return fmt.Errorf("refusing the board name %q", addr)
		}
		b := &board{addr: addr, user: user, agent: agent}
		fmt.Printf("######## board %s\n", addr)
		err := b.run(step, cli, done)
		b.cleanup()
		if err != nil {
			return fmt.Errorf("board %s: %w", addr, err)
		}
		done = append(done, b)
	}
	fmt.Printf("\nsmoke: M1 passed on %d boards\n", len(done))
	return nil
}

func (b *board) run(step, cli string, earlier []*board) error {
	out, err := b.sh(nil, "hostname")
	if err != nil {
		return err
	}
	b.node = strings.TrimSpace(out)
	fmt.Printf("== 0. The units (node %s)\n", b.node)
	if err := b.requireActive(); err != nil {
		return err
	}
	fmt.Printf("active:        %d units of the skeleton\n", len(units))
	if b.dir, err = b.upload([2]string{step, "spine"}, [2]string{cli, "sluis"}); err != nil {
		return err
	}

	// --- 1. The decision, and 2. the token: the harness client under the uid of exchange.
	corr := "smoke-" + strconv.FormatInt(time.Now().UnixMilli(), 36)
	var dec decideOut
	if err := b.step(&dec, "exchange", []string{"policy", "signer"}, "decide-sign", "--boundary", boundary, "--tenant", tenant,
		"--issuer", "https://"+host, "--audience", audience, "--correlation", corr); err != nil {
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
		return errors.New("policy did not allow the token.exchange the config allows")
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

	fmt.Println("== 2. The token (signer, signed by key@ in place)")
	hdr, claims, err := decode(dec.Token)
	if err != nil {
		return err
	}
	fmt.Printf("header:        %s\n", hdr)
	fmt.Printf("claims:        %s\n", claims)
	set, err := b.jwks()
	if err != nil {
		return err
	}
	if err := verifyToken(dec.Token, set); err != nil {
		return err
	}
	b.keyID = dec.KeyID
	fmt.Printf("signature:     ES384, verified with kid %s from /jwks of entry on this board (through its socket, as the forwarder's uid)\n", dec.KeyID)

	// --- 3. The audit trail.
	fmt.Println("== 3. The audit trail (emitters, spool, writer, fs blob)")
	if err := b.audit(dec, corr); err != nil {
		return err
	}

	// --- 4. The shared store, through store@ and as readers the registry allows.
	fmt.Println("== 4. The shared store (read through store@)")
	var ring readOut
	if err := b.step(&ring, "signer", []string{"store"}, "store-read", "--kind", "signing-ring", "--tenant", ""); err != nil {
		return fmt.Errorf("SigningRing as signer: %w", err)
	}
	if len(ring.Items) != 1 || len(ring.Items[0].Detail) == 0 {
		return errors.New("SigningRing holds no key")
	}
	detail := strings.Join(ring.Items[0].Detail, "; ")
	fmt.Printf("SigningRing:   default at version %d, %d keys: %s (read as signer)\n", ring.Items[0].Version, len(ring.Items[0].Detail), detail)
	if !strings.Contains(detail, dec.KeyID+" ES384 active") {
		return errors.New("the SigningRing does not hold the key that signed the token as an active ES384 key")
	}
	var wraps readOut
	if err := b.step(&wraps, "key", []string{"store"}, "store-read", "--kind", "data-key-wrap", "--tenant", tenant); err != nil {
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

	// The shared rqlite cluster: what the earlier boards wrote is here.
	for _, e := range earlier {
		if !strings.Contains(detail, e.keyID+" ES384 ") {
			return fmt.Errorf("the SigningRing holds no key %s of node %s, which ran before: the boards do not share the store", e.keyID, e.node)
		}
		if !strings.Contains(strings.Join(ids, " "), e.node) {
			return fmt.Errorf("DataKeyWrap holds no item for node %s, which ran before: the boards do not share the store", e.node)
		}
		fmt.Printf("shared:        found the SigningRing key %s and the DataKeyWrap item of %s, which ran before\n", e.keyID, e.node)
	}

	fmt.Println("== 5. Memory")
	mem, err := b.sh(nil, `free -m | sed -n '1,2p'; for u in $(systemctl list-units 'sluis-*' --no-legend --plain | awk '{print $1}'); do p=$(systemctl show -p MainPID --value "$u"); printf '%-46s rss %s kB\n' "$u" "$(ps -o rss= -p "$p" | tr -d ' ')"; done`)
	if err != nil {
		return err
	}
	fmt.Print(mem)
	return nil
}

// sh runs a shell command on the board as the SSH user. The agent socket is set for ssh alone.
func (b *board) sh(stdin io.Reader, script string) (string, error) {
	c := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", b.user+"@"+b.addr, script) //nolint:gosec // the board comes from the environment of the run; the script is built here
	c.Env = append(os.Environ(), "SSH_AUTH_SOCK="+b.agent)
	c.Stdin = stdin
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s: %s", firstWord(script), strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return "ssh"
	}
	return f[0]
}

func (b *board) requireActive() error {
	var bad []string
	for _, u := range units {
		name := u + "@dev.service"
		if u == "sluis-rqlite" {
			name = u + ".service"
		}
		out, _ := b.sh(nil, "systemctl is-active "+name) // a non-zero exit is an inactive unit
		if st := strings.TrimSpace(out); st != "active" {
			bad = append(bad, name+" ("+st+")")
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("units not active: %s; run `just boards-deploy`", strings.Join(bad, ", "))
	}
	return nil
}

// upload puts the files in a new directory that only root can write and everyone can enter, so that the uid of an
// actor may run them. It returns the directory.
func (b *board) upload(files ...[2]string) (string, error) {
	out, err := b.sh(nil, "sudo -n mktemp -d /tmp/sluis-smoke.XXXXXX")
	if err != nil {
		return "", err
	}
	dir := strings.TrimSpace(out)
	if !regexp.MustCompile(`^/tmp/sluis-smoke\.[A-Za-z0-9]{6}$`).MatchString(dir) {
		return "", errors.New("the board made an unexpected directory")
	}
	b.dir = dir
	if _, err := b.sh(nil, "sudo -n chmod 0755 "+dir); err != nil {
		return "", err
	}
	for _, p := range files {
		f, err := os.Open(p[0])
		if err != nil {
			return "", err
		}
		_, err = b.sh(f, fmt.Sprintf("sudo -n tee %s/%s >/dev/null && sudo -n chmod 0755 %s/%s", dir, p[1], dir, p[1]))
		_ = f.Close()
		if err != nil {
			return "", err
		}
	}
	return dir, nil
}

func (b *board) cleanup() {
	if b.dir != "" && strings.HasPrefix(b.dir, "/tmp/sluis-smoke.") {
		_, _ = b.sh(nil, "sudo -n rm -rf "+b.dir)
	}
}

func uidOf(name string) (uint32, error) {
	u, ok := registry.UID(name, 0)
	if !ok {
		return 0, fmt.Errorf("%s has no uid in the registry", name)
	}
	return u, nil
}

// asActor is the command prefix that runs a program under the uid of an actor with the groups of the actors it may
// call. The groups are those of the units: the group of an actor has the number of its uid.
func (b *board) asActor(user string, groups []string) (string, error) {
	u, err := uidOf(user)
	if err != nil {
		return "", err
	}
	gs := make([]string, 0, len(groups))
	for _, g := range groups {
		gid, err := uidOf(g)
		if err != nil {
			return "", err
		}
		gs = append(gs, strconv.FormatUint(uint64(gid), 10))
	}
	groupFlag := "--clear-groups"
	if len(gs) > 0 {
		groupFlag = "--groups " + strings.Join(gs, ",")
	}
	return fmt.Sprintf("sudo -n setpriv --reuid %d --regid %d %s --inh-caps=-all ", u, u, groupFlag), nil
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// step runs `spine step <name>` under an actor's uid and decodes its JSON answer.
func (b *board) step(into any, user string, groups []string, name string, args ...string) error {
	return b.stepIn(into, user, groups, "", name, args...)
}

// stepIn is step with a bind mount "from:to" made first, in a mount namespace of the step alone.
func (b *board) stepIn(into any, user string, groups []string, bind, name string, args ...string) error {
	prefix, err := b.asActor(user, groups)
	if err != nil {
		return err
	}
	cmd := prefix + b.dir + "/spine step " + name
	for _, a := range args {
		cmd += " " + quote(a)
	}
	if bind != "" {
		from, to, _ := strings.Cut(bind, ":")
		cmd = "sudo -n unshare --mount sh -c " + quote("mount --bind "+from+" "+to+" && exec "+strings.TrimPrefix(cmd, "sudo -n "))
	}
	out, err := b.sh(nil, cmd)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(out), into); err != nil {
		return fmt.Errorf("%s: the answer is not JSON", name)
	}
	return nil
}

// jwks reads /jwks from entry through its socket, as the forwarder's uid, the one caller entry serves. The TLS of the
// forwarder is not in this smoke: it is the harness's and arrives with the edge.
func (b *board) jwks() (*jose.JSONWebKeySet, error) {
	prefix, err := b.asActor("harness-forwarder", nil)
	if err != nil {
		return nil, err
	}
	out, err := b.sh(nil, prefix+"curl -s -f --max-time 10 --unix-socket /run/sluis/entry/dev.sock -H 'Host: "+host+"' http://localhost/jwks")
	if err != nil {
		return nil, fmt.Errorf("GET /jwks from entry: %w", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(out), &set); err != nil {
		return nil, errors.New("/jwks is not a JWK Set")
	}
	return &set, nil
}

// audit waits for the writer's batch, opens the records the run caused, and has the CLI verify the log.
func (b *board) audit(dec decideOut, corr string) error {
	indexer := func(into any) error {
		// The step dials key@ at /run/sluis/key/<boundary>/key.sock, as in the local installation, where each caller
		// mounts its own directory of key@ there. On a board the directory of the indexer is bind-mounted over it, in a
		// mount namespace of the step alone.
		return b.stepIn(into, "indexer", []string{"policy"}, "/run/sluis/key/"+boundary+"/indexer:/run/sluis/key/"+boundary,
			"audit-find", "--boundary", boundary, "--blob", b.dir+"/log", "--decision-id", dec.DecisionID, "--correlation", corr)
	}
	var found auditOut
	var lastErr error
	deadline := time.Now().Add(batchWait)
	for {
		// A copy of the log, below the writer's driver, whose directory only its own uid may enter.
		if _, err := b.sh(nil, fmt.Sprintf("sudo -n rm -rf %[1]s/log && sudo -n mkdir -m 0755 %[1]s/log && sudo -n tar -C %[2]s -cf - . | sudo -n tar -C %[1]s/log --no-same-owner -xf - && sudo -n chmod -R a+rX %[1]s/log", b.dir, blobLog)); err != nil {
			lastErr = err
		} else {
			found = auditOut{}
			err = indexer(&found)
			if err != nil && !strings.Contains(err.Error(), "no checkpoint yet") {
				return fmt.Errorf("the records of this run: %w", err)
			}
			lastErr = err
			if err == nil && found.complete() {
				break
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
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
	// The writer logs the public key of the log when it starts.
	logs, err := b.sh(nil, "sudo -n journalctl -u sluis-writer@dev -o cat --no-pager | grep -o '\"verifier_key\":\"[^\"]*\"' | tail -1")
	m := regexp.MustCompile(`"verifier_key":"([^"]+)"`).FindStringSubmatch(logs)
	if err != nil || m == nil {
		return errors.New("the writer's log does not carry the log's verifier key")
	}
	out, err := b.sh(nil, b.dir+"/sluis audit verify --key "+quote(m[1])+" "+b.dir+"/log")
	if err != nil {
		return fmt.Errorf("sluis audit verify: %w", err)
	}
	fmt.Println("verify:       ", strings.TrimSpace(out))
	return nil
}

// What the steps of tests/e2e/spine print: the same JSON, read here for the lines a person reads.
type decideOut struct {
	Decision    string   `json:"decision"`
	GrantNames  []string `json:"grant_names"`
	PolicyIDs   []string `json:"policy_ids"`
	DecisionID  string   `json:"decision_id"`
	SealedGrant int      `json:"sealed_grant_bytes"`
	Token       string   `json:"token"`
	KeyID       string   `json:"key_id"`
}

type itemOut struct {
	ID      string   `json:"id"`
	Version uint64   `json:"version"`
	Detail  []string `json:"detail,omitempty"`
}

type readOut struct {
	Items []itemOut `json:"items"`
}

type foundEntry struct {
	Event string `json:"event"`
	Actor string `json:"actor"`
}

type auditOut struct {
	Size    int64        `json:"size"`
	Records int          `json:"records"`
	Found   []foundEntry `json:"found"`
}

// wanted are the records the M1 spine must have written (the same list as the local smoke).
var wanted = []string{"policy.decide", "signer.sign", "key.sign"}

func (a auditOut) complete() bool {
	for _, w := range wanted {
		ok := false
		for _, f := range a.Found {
			ok = ok || f.Event == w
		}
		if !ok {
			return false
		}
	}
	return true
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
