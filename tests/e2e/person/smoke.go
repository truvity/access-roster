package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// services the smoke needs healthy before it starts.
var services = []string{"policy", "signer", "key", "store", "writer", "entry", "forwarder", "rqlite", "session", "exchange",
	"adapter-upstream-oidc", "idp-loopback", "drv-key-software", "drv-writer-spool", "drv-writer-fs"}

// wanted are the records of the run that must be in the log: one for every step of the person's path (PLAN.md §2, "M2":
// every step is audited). An event is its action name in the audit catalogue.
var wanted = []string{
	"entry.authorize", "session.authorize", "upstream.begin", "entry.callback", "upstream.complete", "session.signin",
	"entry.token", "session.token", "policy.decide", "signer.sign", "key.sign", "exchange.token",
}

// smoke runs the M2 proof. With PERSON_TRACE set, a failure also prints the failed steps of the audit log (their closed
// reasons), which is where a refusal of an actor is recorded.
func smoke() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	var from int64
	err = smokeRun(cfg, &from)
	if err != nil && os.Getenv("PERSON_TRACE") != "" {
		cfg.diagnose(from)
	}
	return err
}

// diagnose prints the failed steps among the records since entry `from`.
func (c *config) diagnose(from int64) {
	time.Sleep(batchWait / 2)
	dir, err := os.MkdirTemp("", "person-diag-")
	if err != nil {
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	_ = os.Chmod(dir, 0o755) //nolint:gosec // the indexer's uid must enter the copy
	if c.copyLog(dir) != nil {
		return
	}
	ev, err := c.events(dir, from)
	if err != nil {
		fmt.Fprintln(os.Stderr, "diagnose:", err)
		return
	}
	for _, r := range ev.Records {
		if r.Status != "" && r.Status != "Success" || r.Reason != "" {
			fmt.Fprintf(os.Stderr, "diagnose: %s by %s: %s %s\n", r.Event, r.Actor, r.Status, r.Reason)
		}
	}
}

func smokeRun(cfg *config, fromOut *int64) error {
	var err error
	if err := cfg.requireHealthy(); err != nil {
		return err
	}
	s, err := newSession(cfg, "alice")
	if err != nil {
		return err
	}
	defer s.close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	logCopy, err := os.MkdirTemp("", "person-log-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(logCopy) }()
	if err := os.Chmod(logCopy, 0o755); err != nil { //nolint:gosec // the indexer's uid must enter the copy
		return err
	}
	// The records of this run are the entries after the log's size now.
	from := fromOut
	if err := cfg.copyLog(logCopy); err == nil {
		if *from, err = logSize(logCopy); err != nil {
			return err
		}
	}

	var jwks jose.JSONWebKeySet
	if err := getJSON(ctx, s.hc, issuer+"/jwks", &jwks); err != nil {
		return err
	}

	// --- 1. The sign-in: sluis login, through the forwarder, entry, session, the adapter and the identity provider.
	fmt.Println("== 1. sluis login --issuer " + issuer + " (alice: password and TOTP, filled in by the harness)")
	out, err := s.login(ctx)
	if err != nil {
		return fmt.Errorf("sluis login: %w", err)
	}
	fmt.Println("cli:           " + out)
	idt, err := s.idToken(ctx)
	if err != nil {
		return fmt.Errorf("the ID token: %w", err)
	}
	idHdr, idClaims, err := parseToken(idt)
	if err != nil {
		return err
	}
	if err := checkIDToken(idClaims); err != nil {
		return err
	}
	kid, err := verifyToken(idt, &jwks)
	if err != nil {
		return fmt.Errorf("the ID token: %w", err)
	}
	fmt.Println("\nID token (the claims; the signature is not shown)")
	printToken(idHdr, idClaims)
	fmt.Printf("signature:     ES384, verified with kid %s from %s/jwks (the forwarder, trusting only the harness CA)\n", kid, issuer)

	loginAT, err := s.cachedAccessToken()
	if err != nil {
		return err
	}
	_, atClaims, err := parseToken(loginAT)
	if err != nil {
		return err
	}
	fmt.Printf("\naccess token of the sign-in (client %s): groups %v\n", cliID, atClaims["groups"])

	// --- 2. The exchange: sluis token --audience example-app.
	fmt.Println("\n== 2. sluis token --audience " + audience + " (exchange, RFC 8693)")
	tok, err := s.token(ctx, audience)
	if err != nil {
		return fmt.Errorf("sluis token: %w", err)
	}
	xHdr, xClaims, err := parseToken(tok)
	if err != nil {
		return err
	}
	if err := checkExchanged(xHdr, xClaims, atClaims); err != nil {
		return err
	}
	kid, err = verifyToken(tok, &jwks)
	if err != nil {
		return fmt.Errorf("the exchanged token: %w", err)
	}
	fmt.Println("exchanged token (the claims; the signature is not shown)")
	printToken(xHdr, xClaims)
	fmt.Printf("signature:     ES384, verified with kid %s from %s/jwks\n", kid, issuer)
	// ADR 0034: both subjects are Mac(the tenant's pairwise key, sector and person id), so one person in one tenant
	// should have one. Reported, not enforced: the two actors build the Mac input differently (see the pull request).
	if idClaims["sub"] == xClaims["sub"] {
		fmt.Println("subjects:      the sign-in's sub and the exchanged token's sub are the same pairwise subject")
	} else {
		fmt.Println("subjects:      NOTE the sign-in's sub and the exchanged token's sub differ (session and exchange build the Mac input differently)")
	}

	// --- 3. The audit trail.
	fmt.Println("\n== 3. The audit trail (emitters, spool, writer, fs blob)")
	var ev *eventsOut
	deadline := time.Now().Add(batchWait)
	for {
		if err := os.RemoveAll(logCopy); err != nil {
			return err
		}
		if err := os.MkdirAll(logCopy, 0o755); err != nil { //nolint:gosec // as above
			return err
		}
		if err := cfg.copyLog(logCopy); err != nil {
			return err
		}
		ev, err = cfg.events(logCopy, *from)
		if err != nil && !strings.Contains(err.Error(), "no checkpoint yet") {
			return fmt.Errorf("the records of this run: %w", err)
		}
		if err == nil && len(missing(ev)) == 0 {
			break
		}
		if !time.Now().Before(deadline) {
			if err != nil {
				return fmt.Errorf("the log could not be read within %s: %w", batchWait, err)
			}
			return fmt.Errorf("the log (%d entries, %d records of this run) holds no %s record of this run within %s",
				ev.Size, len(ev.Records), strings.Join(missing(ev), ", "), batchWait)
		}
		time.Sleep(time.Second)
	}
	counts := map[string]int{}
	for _, r := range ev.Records {
		counts[r.Event]++
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		mark := ""
		if slices.Contains(wanted, n) {
			mark = "  (required)"
		}
		fmt.Printf("record:        %-20s x%d%s\n", n, counts[n], mark)
	}
	vk, err := cfg.verifierKey()
	if err != nil {
		return err
	}
	res, err := cfg.verify(vk, logCopy)
	if err != nil {
		return fmt.Errorf("sluis audit verify: %w", err)
	}
	fmt.Println("audit verify: ", res)
	fmt.Println("\nsmoke: M2 passed")
	return nil
}

func missing(ev *eventsOut) []string {
	have := map[string]bool{}
	for _, r := range ev.Records {
		have[r.Event] = true
	}
	var m []string
	for _, w := range wanted {
		if !have[w] {
			m = append(m, w)
		}
	}
	return m
}

// cachedAccessToken is the access token the CLI cached at the sign-in.
func (s *session) cachedAccessToken() (string, error) {
	files, _ := filepath.Glob(filepath.Join(s.home, "sluis", "tokens", "*.json"))
	if len(files) != 1 {
		return "", fmt.Errorf("the CLI's token cache holds %d files, want 1", len(files))
	}
	b, err := os.ReadFile(files[0])
	if err != nil {
		return "", err
	}
	var set struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(b, &set) != nil || set.AccessToken == "" {
		return "", errors.New("the CLI's token cache holds no access token")
	}
	return set.AccessToken, nil
}

var pairwiseRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// checkIDToken asserts what the sign-in must show (ADR 0017, 0020, 0034): the issuer, the client as audience, a subject
// that is the pairwise form and not the user name, and an amr that is only RFC 8176 tokens. An acr, if present, is the
// upstream's own; nothing raises it.
func checkIDToken(c map[string]any) error {
	if c["iss"] != issuer || c["aud"] != cliID {
		return fmt.Errorf("the ID token is for iss %v aud %v, want %s and %s", c["iss"], c["aud"], issuer, cliID)
	}
	sub, _ := c["sub"].(string)
	if !pairwiseRE.MatchString(sub) {
		return errors.New("the ID token's sub is not a pairwise subject (256 bits, base64url)")
	}
	amr, ok := c["amr"].([]any)
	if !ok || len(amr) == 0 || len(amr) > 16 {
		return errors.New("the ID token has no amr, or more than 16 entries")
	}
	for _, m := range amr {
		if s, _ := m.(string); !regexp.MustCompile(`^[a-z0-9_-]{1,64}$`).MatchString(s) {
			return errors.New("the ID token has an amr entry that is not an RFC 8176 token")
		}
	}
	return nil
}

// checkExchanged asserts what the exchange must show: an at+jwt for the audience, whose groups are the held names in the
// audience's scope alone, a narrowing of the sign-in's.
func checkExchanged(h, c, signIn map[string]any) error {
	if h["typ"] != "at+jwt" || h["alg"] != "ES384" {
		return fmt.Errorf("the exchanged token's header is %v %v, want at+jwt ES384", h["typ"], h["alg"])
	}
	if c["iss"] != issuer || c["aud"] != audience {
		return fmt.Errorf("the exchanged token is for iss %v aud %v", c["iss"], c["aud"])
	}
	if !pairwiseRE.MatchString(fmt.Sprint(c["sub"])) {
		return errors.New("the exchanged token's sub is not a pairwise subject")
	}
	groups := strs(c["groups"])
	wide := strs(signIn["groups"])
	if len(groups) == 0 {
		return errors.New("the exchanged token has no groups")
	}
	for _, g := range groups {
		if !strings.HasPrefix(g, "dev:example-app:") {
			return fmt.Errorf("the exchanged token holds a group %q outside the audience's scope", g)
		}
		if !slices.Contains(wide, g) {
			return fmt.Errorf("the exchanged token holds a group %q the sign-in did not", g)
		}
	}
	if len(groups) >= len(wide) {
		return fmt.Errorf("the groups were not narrowed: %v from %v", groups, wide)
	}
	return nil
}

func strs(v any) []string {
	l, _ := v.([]any)
	var out []string
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func printToken(h, c map[string]any) {
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(c)
	fmt.Printf("header:        %s\nclaims:        %s\n", hb, cb)
}

// requireHealthy fails with the name of every service of the project that is missing or not healthy.
func (c *config) requireHealthy() error {
	out, err := exec.Command("docker", "ps", "--all", "--filter", "label=com.docker.compose.project="+c.project, //nolint:gosec // G204: the project name is the recipe's own
		"--format", `{{.Label "com.docker.compose.service"}} {{.State}} {{.Status}}`).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker is not usable: %s", strings.TrimSpace(string(out)))
	}
	have := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f := strings.SplitN(l, " ", 3); len(f) == 3 {
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
