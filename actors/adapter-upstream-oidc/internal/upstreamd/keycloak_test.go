//go:build sluis_test

package upstreamd_test

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is HMAC-SHA1 by default, and the development realm's authenticator uses it
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
)

// The tests of this file run against the development Keycloak of the build (run.env: SLUIS_UPSTREAM_ISSUER, the client
// SLUIS_UPSTREAM_CLIENT_LOCAL, and SLUIS_KEYCLOAK_SECRETS, the file with the passwords, the TOTP secrets and the client
// secret). Where they are not set, as in CI, the tests say SKIP and are not run. No secret is printed.

type keycloak struct {
	issuer, clientID string
	secrets          map[string]string
}

func realKeycloak(t *testing.T) *keycloak {
	t.Helper()
	k := &keycloak{issuer: os.Getenv("SLUIS_UPSTREAM_ISSUER"), clientID: os.Getenv("SLUIS_UPSTREAM_CLIENT_LOCAL")}
	file := os.Getenv("SLUIS_KEYCLOAK_SECRETS")
	if k.issuer == "" || k.clientID == "" || file == "" {
		t.Skip("SKIP: SLUIS_UPSTREAM_ISSUER, SLUIS_UPSTREAM_CLIENT_LOCAL and SLUIS_KEYCLOAK_SECRETS are not set; this test needs the development Keycloak")
	}
	f, err := os.Open(file) //nolint:gosec // the path is the harness's own
	if err != nil {
		t.Skip("SKIP: the Keycloak secrets file cannot be read; this test needs the development Keycloak")
	}
	defer func() { _ = f.Close() }()
	k.secrets = map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '='); i > 0 && !strings.HasPrefix(line, "#") {
			k.secrets[line[:i]] = line[i+1:]
		}
	}
	for _, need := range []string{"SLUIS_LOCAL_CLIENT_SECRET", "ALICE_PASSWORD", "ALICE_TOTP_RAW", "BOB_PASSWORD", "BOB_TOTP_RAW"} {
		if k.secrets[need] == "" {
			t.Skip("SKIP: the Keycloak secrets file lacks a value this test needs")
		}
	}
	probe := &http.Client{Timeout: 3 * time.Second}
	resp, err := probe.Get(strings.TrimSuffix(k.issuer, "/") + "/.well-known/openid-configuration") //nolint:noctx,gosec // a probe of the development issuer
	if err != nil {
		t.Skip("SKIP: the development Keycloak is not reachable")
	}
	_ = resp.Body.Close()
	return k
}

// totp is the code of RFC 6238 (RFC 4226 section 5.3) for the 30 s step of t: the realm keeps the secret as the raw
// string, which is the HMAC key as it stands.
func totp(raw string, t time.Time) string {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(t.Unix()/30)) //nolint:gosec // time is positive
	m := hmac.New(sha1.New, []byte(raw))
	m.Write(c[:])
	sum := m.Sum(nil)
	o := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[o:o+4])&0x7fffffff)%1_000_000)
}

// jar keeps every cookie it is given and sends them all back. Keycloak marks its cookies Secure, which the standard
// jar will not send over plain HTTP; the development issuer is on loopback (D-11).
type jar struct {
	mu sync.Mutex
	c  map[string]*http.Cookie
}

func (j *jar) SetCookies(_ *url.URL, cs []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.c == nil {
		j.c = map[string]*http.Cookie{}
	}
	for _, c := range cs {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j.c, c.Name)
		} else {
			j.c[c.Name] = c
		}
	}
}

func (j *jar) Cookies(*url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, 0, len(j.c))
	for _, c := range j.c {
		out = append(out, c)
	}
	return out
}

var formAction = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)

// signIn drives the browser's part headless, the way the CLI agent did: the authorization URL, the password form, the
// one-time code form. It returns the code and the iss parameter of the callback. A TOTP code is good for one use, so
// when the realm refuses one that an earlier run has just used, it waits for the next step once.
func (k *keycloak) signIn(t *testing.T, authURL, user string) (code, state, iss string) {
	t.Helper()
	u := strings.ToUpper(user)
	var lastStep int64
	for attempt := 0; attempt < 2; attempt++ {
		hc := &http.Client{Timeout: 20 * time.Second, Jar: &jar{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		get := func(target string, form url.Values) (*http.Response, string) {
			var resp *http.Response
			var err error
			if form == nil {
				resp, err = hc.Get(target) //nolint:noctx // a test against the development issuer
			} else {
				resp, err = hc.PostForm(target, form) //nolint:noctx // a test against the development issuer
			}
			if err != nil {
				t.Fatalf("sign-in request failed: %v", errors.Unwrap(err))
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			return resp, string(b)
		}
		action := func(page string) string {
			m := formAction.FindStringSubmatch(page)
			if m == nil {
				t.Fatalf("sign-in: no form on the page")
			}
			return html.UnescapeString(m[1])
		}
		resp, page := get(authURL, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("sign-in: the authorization endpoint answered %d", resp.StatusCode)
		}
		_, page = get(action(page), url.Values{"username": {user}, "password": {k.secrets[u+"_PASSWORD"]}, "credentialId": {""}})
		now := time.Now()
		if now.Unix()/30 == lastStep {
			time.Sleep(time.Until(time.Unix((lastStep+1)*30, 0)) + time.Second)
			now = time.Now()
		}
		lastStep = now.Unix() / 30
		resp, _ = get(action(page), url.Values{"otp": {totp(k.secrets[u+"_TOTP_RAW"], now)}, "login": {"Sign In"}})
		if resp.StatusCode != http.StatusFound {
			continue // the code was used in this step already: try the next step once
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal("sign-in: the callback is not a URL")
		}
		q := loc.Query()
		return q.Get("code"), q.Get("state"), q.Get("iss")
	}
	t.Fatalf("sign-in: %s was refused the one-time code twice", user)
	return "", "", ""
}

func (k *keycloak) env(t *testing.T) *env {
	t.Helper()
	return newEnv(t, envOptions{
		environment: "development", secret: k.secrets["SLUIS_LOCAL_CLIENT_SECRET"],
		upstream: &configv2alpha1.Upstream{
			Name: "workforce", Kind: "oidc", Issuer: k.issuer, ClientId: k.clientID,
			SubjectClaim: "preferred_username", Scopes: []string{"profile", "email"},
		},
	})
}

// begin makes the authorization URL with the adapter and returns what session would keep.
func (k *keycloak) begin(t *testing.T, e *env, nonce string) (authURL, verifier, state string) {
	t.Helper()
	verifier, challenge := pkcePair(t)
	state = "state-" + nonce
	res, err := e.begin(context.Background(), &integrationv2alpha1.BeginRequest{
		Upstream: "workforce", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge,
	})
	if err != nil {
		t.Fatalf("Begin against the real Keycloak: %v", err)
	}
	return res.GetAuthorizationUrl(), verifier, state
}

func TestKeycloakBeginAndComplete(t *testing.T) {
	k := realKeycloak(t)
	e := k.env(t)
	ctx := context.Background()

	authURL, verifier, state := k.begin(t, e, "nonce-alice-1")
	u, _ := url.Parse(authURL)
	if q := u.Query(); q.Get("code_challenge_method") != "S256" || q.Get("client_id") != k.clientID || q.Get("nonce") != "nonce-alice-1" {
		t.Fatalf("authorization URL query is not what Begin was asked for: %v", q)
	}
	code, gotState, iss := k.signIn(t, authURL, "alice")
	if code == "" || gotState != state {
		t.Fatalf("the callback has no code, or the state is not session's own")
	}

	a, err := e.complete(ctx, &integrationv2alpha1.CompleteRequest{
		Upstream: "workforce", Code: code, RedirectUri: callback, CodeVerifier: verifier, Nonce: "nonce-alice-1", Iss: iss,
	})
	if err != nil {
		t.Fatalf("Complete against the real Keycloak: %v", err)
	}
	if a.GetIssuer() != k.issuer || a.GetSubjectClaim() != "preferred_username" || a.GetSubject() != "alice" {
		t.Errorf("assertion identity = %q %q %q", a.GetIssuer(), a.GetSubjectClaim(), a.GetSubject())
	}
	if !a.GetAmrPresent() || strings.Join(a.GetAmr(), ",") != "pwd,otp,mfa" {
		t.Errorf("amr = %v (present %v), want [pwd otp mfa]", a.GetAmr(), a.GetAmrPresent())
	}
	t.Logf("Complete returned subject=%s amr=%v acr-present=%v", a.GetSubject(), a.GetAmr(), a.Acr != nil)

	// A code is good for one exchange (RFC 6749 section 4.1.2): the replay is refused, and says nothing of why.
	_, err = e.complete(ctx, &integrationv2alpha1.CompleteRequest{
		Upstream: "workforce", Code: code, RedirectUri: callback, CodeVerifier: verifier, Nonce: "nonce-alice-1", Iss: iss,
	})
	refused(t, err, "UPSTREAM_REJECTED", connect.CodeFailedPrecondition, "code")
}

func TestKeycloakRefusesANonceThatIsNotTheBeginStep(t *testing.T) {
	k := realKeycloak(t)
	e := k.env(t)
	authURL, verifier, _ := k.begin(t, e, "nonce-bob-1")
	code, _, iss := k.signIn(t, authURL, "bob")
	_, err := e.complete(context.Background(), &integrationv2alpha1.CompleteRequest{
		Upstream: "workforce", Code: code, RedirectUri: callback, CodeVerifier: verifier, Nonce: "a-different-nonce", Iss: iss,
	})
	refused(t, err, "UPSTREAM_REJECTED", connect.CodeFailedPrecondition, "id_token.nonce")
}

func TestKeycloakRefusesAnIssThatIsNotTheUpstreams(t *testing.T) {
	k := realKeycloak(t)
	e := k.env(t)
	// No sign-in is needed: the iss parameter is checked before the code is used (RFC 9207 section 2.4).
	v, _ := pkcePair(t)
	for name, iss := range map[string]string{"another issuer": "https://evil.example.com/realms/sluis-test", "none": ""} {
		_, err := e.complete(context.Background(), &integrationv2alpha1.CompleteRequest{
			Upstream: "workforce", Code: "unused", RedirectUri: callback, CodeVerifier: v, Nonce: "n", Iss: iss,
		})
		if r, _ := refusalPath(err); r != "iss" {
			t.Errorf("%s: got %v, want a refusal at iss (Keycloak advertises the iss parameter)", name, err)
		}
	}
}
