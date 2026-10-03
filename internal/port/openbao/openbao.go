// Package openbao is the [port.Export] adapter over an OpenBao (or Vault) KV
// version 2 mount: a copy of a secret is one key under the mount, written
// with the HTTP API and nothing else.
//
// It logs in as the service and holds no long-lived credential. Two methods
// share one request, `POST auth/<mount>/login {role, jwt}`: `kubernetes` (the
// Kubernetes auth method, whose JWT is the pod's ServiceAccount token) and
// `jwt` (the JWT/OIDC method, whose JWT is any token the deployment can read:
// a projected ServiceAccount token on Kubernetes, or the web identity token
// AWS issues a Lambda by outbound federation). The token a login returns is
// kept until most of its lease has passed, per OpenBao namespace, because a
// login inside a namespace opens a token for that namespace alone.
//
// The writes are shaped for the way copies are consumed (docs/decisions/0034):
//
//   - ExportReplace is `POST data/<path>`: the key holds exactly the
//     properties. A whole-secret copy.
//   - ExportPatch is `PATCH data/<path>` with a JSON merge patch: the given
//     properties are set and the others are left, atomically on the server. A
//     key that does not exist yet is created by a POST.
//
// Both read the key first and write nothing when it already holds what would
// be written, so the hourly reconcile makes no new KV version and still puts
// back what somebody changed. The policy the service needs is therefore
// `read`, `create`, `update` and `patch` on `<mount>/data/<prefix>/*`; Delete
// removes every version through `<mount>/metadata/<path>` and needs `delete`
// there, which the exporter never asks for.
//
// Nothing here logs or returns a value: an error names the method, the path
// and the status, and the server's own error text, which carries no data.
package openbao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/port"
)

// The login methods.
const (
	// MethodKubernetes is the Kubernetes auth method, mounted at `kubernetes`
	// unless the configuration says otherwise.
	MethodKubernetes = "kubernetes"
	// MethodJWT is the JWT/OIDC auth method, mounted at `jwt` unless the
	// configuration says otherwise.
	MethodJWT = "jwt"
)

// DefaultServiceAccountToken is where a pod's ServiceAccount token is.
const DefaultServiceAccountToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// DefaultMount is the KV version 2 mount.
const DefaultMount = "kv"

// TokenSource returns the JWT to log in with, afresh on every call. A Lambda
// plugs in the web identity token of its outbound federation here.
type TokenSource func(ctx context.Context) (string, error)

// FileTokenSource reads the JWT from a file on every call, so a projected
// token the kubelet rotates is always the current one.
func FileTokenSource(path string) TokenSource {
	return func(context.Context) (string, error) {
		raw, err := os.ReadFile(path) //nolint:gosec // the path is the deployment's configuration
		if err != nil {
			return "", fmt.Errorf("read the login token: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", fmt.Errorf("the login token file %s is empty", path)
		}
		return token, nil
	}
}

// Auth is how the service logs in.
type Auth struct {
	// Method is [MethodKubernetes] or [MethodJWT].
	Method string
	// Mount is the auth method's mount path inside each namespace. Empty is
	// the method's own name.
	Mount string
	// Role is the role the login asks for.
	Role string
	// TokenFile is where the JWT is read from. Empty is the ServiceAccount
	// token for [MethodKubernetes]; [MethodJWT] needs this or Token.
	TokenFile string
	// Token, when set, is the JWT source and TokenFile is ignored.
	Token TokenSource
}

// Config is what New needs.
type Config struct {
	// Address is the server: https://openbao.example, with no path.
	Address string
	// CAFile and CAPEM are the certificate authorities the server's
	// certificate is verified against, instead of the system's. Both empty
	// uses the system's.
	CAFile string
	CAPEM  []byte
	// Mount is the KV version 2 mount. Empty is [DefaultMount].
	Mount string
	// Namespace is the OpenBao namespace a target without one writes to.
	Namespace string
	Auth      Auth
	// Client replaces the HTTP client, for a test.
	Client *http.Client
	// Now replaces the clock, for a test.
	Now func() time.Time
}

// Store is the adapter.
type Store struct {
	base      *url.URL
	mount     string
	namespace string
	auth      Auth
	token     TokenSource
	client    *http.Client
	now       func() time.Time

	mu       sync.Mutex
	sessions map[string]session
}

var _ port.Export = (*Store)(nil)

type session struct {
	token   string
	renewAt time.Time
}

// New validates the configuration and returns the adapter. It does not
// connect: an OpenBao that is down at start must not stop the service, since
// an export is never a dependency.
func New(cfg Config) (*Store, error) {
	base, err := url.Parse(cfg.Address)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") ||
		base.User != nil || (base.Path != "" && base.Path != "/") || base.RawQuery != "" {
		return nil, fmt.Errorf("openbao: address %q is not an http(s) URL with a host and no path or credentials", cfg.Address)
	}
	base.Path = ""
	mount := cfg.Mount
	if mount == "" {
		mount = DefaultMount
	}
	if err = port.CheckExportPath(mount); err != nil {
		return nil, fmt.Errorf("openbao: mount %q is not a mount path", mount)
	}
	auth := cfg.Auth
	switch auth.Method {
	case MethodKubernetes, MethodJWT:
	default:
		return nil, fmt.Errorf("openbao: auth method %q is %q or %q", auth.Method, MethodKubernetes, MethodJWT)
	}
	if auth.Role == "" {
		return nil, errors.New("openbao: auth.role is required")
	}
	if auth.Mount == "" {
		auth.Mount = auth.Method
	}
	if err = port.CheckExportPath(auth.Mount); err != nil {
		return nil, fmt.Errorf("openbao: auth.mount %q is not a mount path", auth.Mount)
	}
	token := auth.Token
	if token == nil {
		file := auth.TokenFile
		if file == "" && auth.Method == MethodKubernetes {
			file = DefaultServiceAccountToken
		}
		if file == "" {
			return nil, errors.New("openbao: auth method jwt needs a tokenFile or a token source")
		}
		token = FileTokenSource(file)
	}
	client := cfg.Client
	if client == nil {
		if client, err = httpClient(cfg); err != nil {
			return nil, err
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Store{
		base: base, mount: mount, namespace: cfg.Namespace, auth: auth, token: token,
		client: client, now: now, sessions: map[string]session{},
	}, nil
}

func httpClient(cfg Config) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	pem := cfg.CAPEM
	if cfg.CAFile != "" {
		raw, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("openbao: read the CA bundle: %w", err)
		}
		pem = append(pem, raw...)
	}
	if len(pem) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("openbao: the CA bundle holds no certificate")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

// Put implements [port.Export].
func (s *Store) Put(ctx context.Context, target port.ExportTarget, properties map[string]string, mode port.ExportMode) error {
	if err := port.CheckExport(target, properties, mode); err != nil {
		return err
	}
	ns := s.ns(target)
	have, found, err := s.read(ctx, ns, target.Path)
	if err != nil {
		return err
	}
	switch {
	case found && same(have, properties, mode):
		return nil
	case found && mode == port.ExportPatch:
		status, body, err := s.call(ctx, ns, "PATCH", s.dataPath(target.Path), "application/merge-patch+json", payload(properties))
		if err != nil {
			return err
		}
		if status != http.StatusNotFound { // gone since the read: create it below
			return answer("patch", target, status, body)
		}
	}
	status, body, err := s.call(ctx, ns, "POST", s.dataPath(target.Path), "application/json", payload(properties))
	if err != nil {
		return err
	}
	return answer("write", target, status, body)
}

// Delete implements [port.Export]: every version of the key, and its
// metadata.
func (s *Store) Delete(ctx context.Context, target port.ExportTarget) error {
	if err := port.CheckExportPath(target.Path); err != nil {
		return err
	}
	status, body, err := s.call(ctx, s.ns(target), "DELETE", s.mount+"/metadata/"+target.Path, "", nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	return answer("delete", target, status, body)
}

func (s *Store) ns(target port.ExportTarget) string {
	if target.Namespace != "" {
		return target.Namespace
	}
	return s.namespace
}

func (s *Store) dataPath(path string) string { return s.mount + "/data/" + path }

func payload(properties map[string]string) []byte {
	raw, _ := json.Marshal(map[string]any{"data": properties}) // strings only
	return raw
}

// same reports whether writing properties in the mode would change nothing.
func same(have, properties map[string]string, mode port.ExportMode) bool {
	if mode == port.ExportReplace {
		return maps.Equal(have, properties)
	}
	for k, v := range properties {
		if cur, ok := have[k]; !ok || cur != v {
			return false
		}
	}
	return true
}

// read returns the current version of a key. A key that is absent, or whose
// current version is deleted, is not found.
func (s *Store) read(ctx context.Context, ns, path string) (map[string]string, bool, error) {
	status, body, err := s.call(ctx, ns, "GET", s.dataPath(path), "", nil)
	if err != nil {
		return nil, false, err
	}
	switch status {
	case http.StatusOK:
		var out struct {
			Data struct {
				Data map[string]any `json:"data"`
			} `json:"data"`
		}
		if err = json.Unmarshal(body, &out); err != nil {
			return nil, false, fmt.Errorf("%w: the answer to a read of %s is not JSON", port.ErrUnavailable, path)
		}
		have := make(map[string]string, len(out.Data.Data))
		for k, v := range out.Data.Data {
			text, ok := v.(string)
			if !ok {
				// A property that is not text is never what this service wrote:
				// the key is different, whatever else it holds.
				text = fmt.Sprint(v)
			}
			have[k] = text
		}
		return have, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, answer("read", port.ExportTarget{Path: path}, status, body)
	}
}

// call makes one request inside a namespace, logging in first when there is
// no live token, and once more when the server refuses the token it had.
func (s *Store) call(ctx context.Context, ns, method, path, contentType string, body []byte) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		token, err := s.login(ctx, ns, attempt > 0)
		if err != nil {
			return 0, nil, err
		}
		status, raw, err := s.do(ctx, ns, method, path, contentType, token, body)
		if err != nil {
			return 0, nil, err
		}
		if status == http.StatusForbidden && attempt == 0 {
			// A token revoked or expired early reads as forbidden; one fresh
			// login tells that from a policy that does not allow the write.
			continue
		}
		return status, raw, nil
	}
}

func (s *Store) do(ctx context.Context, ns, method, path, contentType, token string, body []byte) (int, []byte, error) {
	endpoint := s.base.String() + "/v1/" + path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %s %s: %s", port.ErrUnavailable, method, path, trimErr(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %s %s: %s", port.ErrUnavailable, method, path, trimErr(err))
	}
	return resp.StatusCode, raw, nil
}

// login returns the token for a namespace, logging in when it has none or
// most of its lease has gone, or when force is set.
func (s *Store) login(ctx context.Context, ns string, force bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.sessions[ns]; ok && !force && s.now().Before(cur.renewAt) {
		return cur.token, nil
	}
	jwt, err := s.token(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", port.ErrUnavailable, err)
	}
	body, _ := json.Marshal(map[string]string{"role": s.auth.Role, "jwt": jwt})
	path := "auth/" + s.auth.Mount + "/login"
	status, raw, err := s.do(ctx, ns, "POST", path, "application/json", "", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", answer("log in", port.ExportTarget{Namespace: ns, Path: path}, status, raw)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err = json.Unmarshal(raw, &out); err != nil || out.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: the login answered no token", port.ErrUnavailable)
	}
	lease := time.Duration(out.Auth.LeaseDuration) * time.Second
	if lease <= 0 {
		lease = time.Minute
	}
	s.sessions[ns] = session{token: out.Auth.ClientToken, renewAt: s.now().Add(lease * 8 / 10)}
	return out.Auth.ClientToken, nil
}

// answer turns a status into an error. A 5xx, a 429 and a sealed or standby
// server are the store being down; any other refusal is the configuration's
// (a role, a policy, a path) and is said as it is.
func answer(what string, target port.ExportTarget, status int, body []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	detail := serverError(body)
	switch {
	case status >= 500, status == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s %s: status %d%s", port.ErrUnavailable, what, target, status, detail)
	default:
		return fmt.Errorf("openbao: %s %s: status %d%s", what, target, status, detail)
	}
}

// serverError is the `errors` of an OpenBao error answer, which names the
// refusal and carries no data. Anything else is dropped.
func serverError(body []byte) string {
	var out struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &out) != nil || len(out.Errors) == 0 {
		return ""
	}
	text := strings.Join(out.Errors, "; ")
	if len(text) > 200 {
		text = text[:200]
	}
	return ": " + text
}

// trimErr is a transport error without the URL the client already named.
func trimErr(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err.Error()
	}
	return err.Error()
}
