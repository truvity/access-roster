// Command upstream-subjects writes the subjects of the test users that the local installation's config names, for
// tools/harness/sign-config `-subjects`. The policy binds a test user by the value of the upstream's subject claim,
// `sub`, never by the user name (REQ-SUBJ-044), and Keycloak makes a user's `sub`, the user's id, when it imports its
// realm. So the value cannot be in the repository: this tool reads it from the realm at run time. It is a test harness
// tool, never part of a product binary.
//
//	go run ./tools/harness/upstream-subjects -config tests/installations/local/config -secrets "$SLUIS_KEYCLOAK_SECRETS" -out .cache/local/subjects
//	go run ./tools/harness/upstream-subjects -config tests/installations/local/config -unbound -out .cache/deny/subjects
//
// The users are the ones the sources name as {{sub:<user>}}. With -secrets, the tool signs in to the realm's admin API
// as the bootstrap administrator of the secrets file (KC_BOOTSTRAP_ADMIN_USERNAME and KC_BOOTSTRAP_ADMIN_PASSWORD) and
// asks for each user by its exact user name; the realm and its address are those of the issuer in upstream.yaml. With
// -unbound, for a run where nobody signs in (the deny matrix, whose realm is empty), each user gets a random UUID that
// no account of the realm has, so the bindings bind nobody. No secret and no token is printed.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// placeholder is a test user's account in a source; tools/harness/sign-config fills it.
var placeholder = regexp.MustCompile(`\{\{sub:([a-z][a-z0-9_-]{0,63})\}\}`)

// issuerLine is the issuer of the upstream in upstream.yaml: a Keycloak realm, <base>/realms/<realm>.
var issuerLine = regexp.MustCompile(`(?m)^[ \t]+issuer:[ \t]*(\S+)[ \t]*$`)

func main() {
	configDir := flag.String("config", "tests/installations/local/config", "the directory of the unsigned config sources")
	secrets := flag.String("secrets", "", "the harness's secrets file, with the realm's bootstrap administrator")
	unbound := flag.Bool("unbound", false, "give each user a random UUID instead: nobody of this run signs in")
	out := flag.String("out", "", "the file to write, a user and its sub on each line")
	flag.Parse()
	if flag.NArg() != 0 || *out == "" || (*secrets == "") == !*unbound {
		fmt.Fprintln(os.Stderr, "upstream-subjects: -out and exactly one of -secrets and -unbound are required, and there are no arguments")
		os.Exit(2)
	}
	if err := run(*configDir, *secrets, *unbound, *out); err != nil {
		fmt.Fprintf(os.Stderr, "upstream-subjects: %v\n", err)
		os.Exit(1)
	}
}

func run(configDir, secrets string, unbound bool, out string) error {
	users, err := Users(configDir)
	if err != nil {
		return err
	}
	subjects := map[string]string{}
	if unbound {
		for _, u := range users {
			if subjects[u], err = randomUUID(); err != nil {
				return err
			}
		}
	} else {
		base, realm, err := Realm(configDir)
		if err != nil {
			return err
		}
		admin, err := readAdmin(secrets)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c := &Client{HTTP: newHTTPClient(), Base: base}
		if err := c.Login(ctx, admin[0], admin[1]); err != nil {
			return err
		}
		for _, u := range users {
			if subjects[u], err = c.UserID(ctx, realm, u); err != nil {
				return err
			}
		}
	}
	var b strings.Builder
	b.WriteString("# the subjects of the test users of this run (tools/harness/upstream-subjects)\n")
	for _, u := range users {
		fmt.Fprintf(&b, "%s %s\n", u, subjects[u])
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
		return err
	}
	how := "from the realm"
	if unbound {
		how = "unbound (random)"
	}
	fmt.Printf("upstream-subjects: %d users, %s: %s\n", len(users), how, strings.Join(users, " "))
	return nil
}

// Users returns the users the sources of dir name as {{sub:<user>}}, sorted, each once.
func Users(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("config directory: %w", err)
	}
	var users []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // a source of the config directory the recipe names
		if err != nil {
			return nil, err
		}
		for _, m := range placeholder.FindAllSubmatch(b, -1) {
			users = append(users, string(m[1]))
		}
	}
	slices.Sort(users)
	return slices.Compact(users), nil
}

// Realm returns the base URL of the identity provider and the name of the realm, from the issuer of upstream.yaml.
func Realm(dir string) (base, realm string, err error) {
	b, err := os.ReadFile(filepath.Join(dir, "upstream.yaml")) //nolint:gosec // a source of the config directory the recipe names
	if err != nil {
		return "", "", err
	}
	m := issuerLine.FindAllSubmatch(b, -1)
	if len(m) != 1 {
		return "", "", errors.New("upstream.yaml must name exactly one issuer")
	}
	u, err := url.Parse(string(m[0][1]))
	if err != nil {
		return "", "", errors.New("upstream.yaml: the issuer is not a URL")
	}
	before, name, ok := strings.Cut(u.Path, "/realms/")
	if !ok || name == "" || strings.Contains(name, "/") {
		return "", "", errors.New("upstream.yaml: the issuer is not a Keycloak realm, <base>/realms/<realm>")
	}
	return u.Scheme + "://" + u.Host + before, name, nil
}

// readAdmin reads the realm's bootstrap administrator from the secrets file. The values are returned, never printed.
func readAdmin(path string) ([2]string, error) {
	f, err := os.Open(path) //nolint:gosec // the harness's secrets file, which the recipe names
	if err != nil {
		return [2]string{}, fmt.Errorf("the secrets file: %w", err)
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
	if err := sc.Err(); err != nil {
		return [2]string{}, fmt.Errorf("the secrets file: %w", err)
	}
	user, pass := all["KC_BOOTSTRAP_ADMIN_USERNAME"], all["KC_BOOTSTRAP_ADMIN_PASSWORD"]
	if user == "" || pass == "" {
		return [2]string{}, errors.New("the secrets file has no KC_BOOTSTRAP_ADMIN_USERNAME and KC_BOOTSTRAP_ADMIN_PASSWORD")
	}
	return [2]string{user, pass}, nil
}

// newHTTPClient follows no redirect: a 307 or 308 would send the administrator's password again, to another address.
// The redirect comes back as the answer, and do refuses it as a status that is not 200.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Client asks Keycloak's admin REST API.
type Client struct {
	HTTP  *http.Client
	Base  string // the identity provider, without /realms/...
	token string
}

// Login takes an admin token from the master realm with the bootstrap administrator's password, through the client
// admin-cli, as Keycloak's own admin CLI does.
func (c *Client) Login(ctx context.Context, user, pass string) error {
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {user}, "password": {pass}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.do(req, &tok); err != nil {
		return fmt.Errorf("admin sign-in: %w", err)
	}
	if tok.AccessToken == "" {
		return errors.New("admin sign-in: no access token")
	}
	c.token = tok.AccessToken
	return nil
}

// UserID returns the id of the realm's user with exactly this user name, which Keycloak sends as the ID token's `sub`.
func (c *Client) UserID(ctx context.Context, realm, user string) (string, error) {
	q := url.Values{"username": {user}, "exact": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/admin/realms/"+url.PathEscape(realm)+"/users?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	var found []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := c.do(req, &found); err != nil {
		return "", fmt.Errorf("user %s: %w", user, err)
	}
	var ids []string
	for _, f := range found {
		if f.Username == user && f.ID != "" {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) != 1 {
		return "", fmt.Errorf("the realm %s has %d users named %s, not one", realm, len(ids), user)
	}
	return ids[0], nil
}

// do sends req and decodes a 200 answer. An error names the status only: an answer can hold a token.
func (c *Client) do(req *http.Request, into any) error {
	res, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: status %d", req.Method, req.URL.Path, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(into); err != nil {
		return fmt.Errorf("%s %s: the answer is not JSON", req.Method, req.URL.Path)
	}
	return nil
}

// randomUUID is a version 4 UUID from the operating system's randomness (RFC 9562, section 5.4).
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
