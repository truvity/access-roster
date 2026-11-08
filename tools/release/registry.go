package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// registry is the little of the registry API the release needs. It reads over plain HTTP from the throwaway registry of the
// rehearsal, which has no authentication, and from ghcr.io, which answers 401 with a Bearer challenge: the client then asks the
// token endpoint it names, with the user and token below when it has them (SLUIS_REGISTRY_USER, SLUIS_REGISTRY_TOKEN) and
// anonymously when it has not, and retries. When it holds a token it sends it only to an HTTPS endpoint on the host of the
// registry or on ghcr.io: a registry that names another realm cannot take the token somewhere else. It is no client for any
// other use.
type registry struct {
	base  string // http://127.0.0.1:5000, or https://ghcr.io
	http  *http.Client
	user  string
	token string
	bears map[string]string // the bearer tokens by challenge
	seen  map[string]bool   // the blobs whose hash was checked
}

// newAnonymousRegistry is a client that never sends a credential, whatever the environment holds: it reads what any stranger can
// read, which is what "public" means.
func newAnonymousRegistry(base string, client *http.Client) *registry {
	r := newRegistry(base, client)
	r.user, r.token = "", ""
	return r
}

func newRegistry(base string, client *http.Client) *registry {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &registry{base: strings.TrimSuffix(base, "/"), http: client,
		user: os.Getenv("SLUIS_REGISTRY_USER"), token: os.Getenv("SLUIS_REGISTRY_TOKEN"), bears: map[string]string{}, seen: map[string]bool{}}
}

// statusError is a registry answer that is not 200.
type statusError struct {
	Path string
	Code int
	Text string
}

func (e *statusError) Error() string { return fmt.Sprintf("GET %s: %s", e.Path, e.Text) }

// notFound says whether err is the registry's 404.
func notFound(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

const accept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// realmAllowed is the rule for where a token may go.
func (r *registry) realmAllowed(u *url.URL) error {
	if r.token == "" {
		return nil
	}
	b, err := url.Parse(r.base)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("the token endpoint %s is not HTTPS, and a token is set", u.Redacted())
	}
	if u.Hostname() != b.Hostname() && u.Hostname() != "ghcr.io" {
		return fmt.Errorf("the token endpoint is on %s, which is neither the registry's host %s nor ghcr.io: the token is not sent", u.Hostname(), b.Hostname())
	}
	return nil
}

// bearer asks the token endpoint of a Bearer challenge for a token.
func (r *registry) bearer(challenge string) (string, error) {
	if t, ok := r.bears[challenge]; ok {
		return t, nil
	}
	params := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(challenge, -1) {
		params[m[1]] = m[2]
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("the registry's challenge %q names no token endpoint", challenge)
	}
	u, err := url.Parse(realm)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("the registry's token endpoint %q is not a URL", realm)
	}
	if err := r.realmAllowed(u); err != nil {
		return "", err
	}
	q := u.Query()
	for _, k := range []string{"service", "scope"} {
		if params[k] != "" {
			q.Set(k, params[k])
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	if r.token != "" {
		user := r.user
		if user == "" {
			user = "token"
		}
		req.SetBasicAuth(user, r.token)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: %s", resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return "", err
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if t == "" {
		return "", fmt.Errorf("the token endpoint gave no token")
	}
	r.bears[challenge] = t
	return t, nil
}

// get reads one path of the registry.
func (r *registry) get(p, accepts string) ([]byte, http.Header, error) {
	return r.do(http.MethodGet, p, accepts)
}

// head asks for one path of the registry without reading it: nil when the registry answers 200 (a blob behind a redirect to a
// CDN is followed; the client does not send its bearer token to another host).
func (r *registry) head(p string) error {
	_, _, err := r.do(http.MethodHead, p, "")
	return err
}

func (r *registry) do(method, p, accepts string) ([]byte, http.Header, error) {
	bearer := ""
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(method, r.base+p, nil) //nolint:gosec // the registry of the release: named on the command line or in the list of images this tool made
		if err != nil {
			return nil, nil, err
		}
		if accepts != "" {
			req.Header.Set("Accept", accepts)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := r.http.Do(req) //nolint:gosec // the same registry
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			challenge := resp.Header.Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, "Bearer ") {
				return nil, nil, &statusError{p, resp.StatusCode, fmt.Sprintf("%s, and the challenge %q is not a bearer one", resp.Status, challenge)}
			}
			if bearer, err = r.bearer(challenge); err != nil {
				return nil, nil, fmt.Errorf("GET %s: %w", p, err)
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, nil, &statusError{p, resp.StatusCode, resp.Status}
		}
		return body, resp.Header, nil
	}
	return nil, nil, &statusError{p, http.StatusUnauthorized, "unauthorized"}
}

func sha256Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// getVerified reads a manifest or a blob by its digest and fails unless the bytes hash to it: the registry is not trusted to
// send what the digest names.
func (r *registry) getVerified(p, digest, accepts string) ([]byte, error) {
	if !strings.HasPrefix(digest, "sha256:") {
		return nil, fmt.Errorf("GET %s: the digest %q is not sha256", p, digest)
	}
	body, _, err := r.get(p, accepts)
	if err != nil {
		return nil, err
	}
	if got := sha256Digest(body); got != digest {
		return nil, fmt.Errorf("GET %s: the bytes hash to %s, not to the digest %s", p, got, digest)
	}
	return body, nil
}

// retryDelay is the pause before the second try of a read that can be tried again; it is a variable so that the tests need no wait.
var retryDelay = 2 * time.Second

// retryable says whether a read failed in a way that another try can mend: the registry or the network was unwell (a transport error,
// 429, 5xx). A refusal, a missing object, or bytes that are not the digest are answers, and are not tried again.
func retryable(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.Code == http.StatusTooManyRequests || se.Code >= 500
	}
	var ue *url.Error
	return errors.As(err, &ue)
}

// getVerifiedRetry is getVerified with up to three tries for a read that failed in a way another try can mend. It is for the one
// read of a release that depends on a registry of someone else (the pinned base on gcr.io).
func (r *registry) getVerifiedRetry(p, digest, accepts string) ([]byte, error) {
	var err error
	for try := 1; try <= 3; try++ {
		var b []byte
		if b, err = r.getVerified(p, digest, accepts); err == nil || !retryable(err) {
			return b, err
		}
		if try < 3 {
			time.Sleep(time.Duration(try) * retryDelay)
		}
	}
	return nil, err
}
