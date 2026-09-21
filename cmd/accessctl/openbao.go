package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// The OpenBAO API this speaks, which is a handful of calls: log in,
// write once, read, list, revoke. No client library, deliberately — each
// of them is plain JSON over HTTP, and the alternative is a dependency
// tree larger than the rest of this binary inside a tool people install
// to avoid installing things.
//
// The token a login returns lives in this struct and nowhere else. It is
// never written to a file, never printed, and never passed as an
// argument: the whole point of minting a credential this way is that the
// thing which could mint another is gone by the time the command exits.
type openbao struct {
	// Address is the API's base URL, without a trailing slash.
	Address string
	// Namespace is the OpenBAO namespace every call is made in, sent as a
	// header rather than as a path prefix so that one address serves
	// every environment.
	Namespace string
	// Client is the HTTP client; the retrying one in practice.
	Client *http.Client

	// token is the login's answer, held for the life of one command.
	token string
}

// The address and namespace are read from the same variables the `bao`
// CLI reads, so a shell already pointed at an installation needs no
// flags — and the Vault-named pair beside them, because an environment
// that predates the fork has those set.
const (
	envOpenBAOAddress   = "BAO_ADDR"
	envVaultAddress     = "VAULT_ADDR"
	envOpenBAONamespace = "BAO_NAMESPACE"
	envVaultNamespace   = "VAULT_NAMESPACE"
	envOpenBAOCACert    = "BAO_CACERT"
	envVaultCACert      = "VAULT_CACERT"
)

// openbaoRoots is what the OpenBAO connection verifies against when an
// installation serves its API under a private root: the system's roots
// with the bundle at path ADDED, never in their place.
//
// Added, because replacing them would make the option a trap: an
// installation whose certificate a public CA signs, or which moves to
// one, would stop verifying the day somebody's shell exported the
// bundle for another. And only this connection: the exchange at the
// issuer keeps the system's trust, so a bundle handed to accessctl for
// OpenBAO cannot vouch for anything else it talks to. The alternative
// people reached for, SSL_CERT_FILE, does the opposite on both counts.
//
// A bundle that cannot be read, or holds no certificate, is refused
// rather than ignored: a flag that silently trusts nothing extra reads,
// later, as an outage.
func openbaoRoots(path string) (*x509.CertPool, error) {
	bundle, err := os.ReadFile(path) //nolint:gosec // the path the caller named
	if err != nil {
		return nil, badUsage("read the OpenBAO CA bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		// A platform with no system roots to add to: the bundle alone is
		// still strictly more than the nothing this connection had.
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(bundle) {
		return nil, badUsage("the OpenBAO CA bundle %s holds no PEM certificate", path)
	}
	return roots, nil
}

// untrusted says whether a request failed because the server's
// certificate did not verify, which on this connection is almost always
// a private root the system does not know.
func untrusted(err error) bool {
	var (
		unknownCA x509.UnknownAuthorityError
		verify    *tls.CertificateVerificationError
	)
	return errors.As(err, &unknownCA) || errors.As(err, &verify)
}

// namespaceHeader carries the namespace on every call. The name is the
// Vault-compatible one, which OpenBAO kept.
const namespaceHeader = "X-Vault-Namespace"

// firstEnv is the first of these variables that is set to something.
func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

// login trades the exchanged token for an OpenBAO one on the JWT mount.
//
// This is the second half of the same sentence the exchange began: the
// issuer decided the identity may ask OpenBAO for something, and the
// mount's role decides what its groups open once it is inside. Neither
// half can be skipped, which is why a session revoked in the console
// stops issuance within the exchange's token cap.
func (b *openbao) login(ctx context.Context, mount, role, jwt string) error {
	data, err := b.call(ctx, http.MethodPost, "auth/"+mount+"/login", nil, map[string]any{"role": role, "jwt": jwt})
	if err != nil {
		return fmt.Errorf("log in on %s: %w", mount, err)
	}
	if data.Auth == nil || strings.TrimSpace(data.Auth.ClientToken) == "" {
		return fmt.Errorf("%w: the login on %s returned no token", errUnreachable, mount)
	}
	b.token = data.Auth.ClientToken
	return nil
}

// write is the one call that mints: `ssh/sign/<role>` or
// `pki/sign/<role>`, and nothing else in the whole command.
func (b *openbao) write(ctx context.Context, path string, body map[string]any) (map[string]any, error) {
	answer, err := b.call(ctx, http.MethodPost, path, nil, body)
	if err != nil {
		return nil, err
	}
	if answer.Data == nil {
		return nil, fmt.Errorf("%w: %s answered with no data", errUnreachable, path)
	}
	return answer.Data, nil
}

// read is one value out of a KV version 2 engine: the fields of the
// latest version at `<mount>/data/<path>`, and no metadata.
//
// `data/` is the API path, not the path `bao kv get` prints. `bao kv get
// -mount=kv orders/checkout/API_TOKEN` reads `kv/data/orders/checkout/API_TOKEN`,
// and a policy written on the path off the command line grants nothing at
// all — which shows up as a 403 for somebody who is plainly in the group,
// and sends people looking at the issuer.
//
// The answer's envelope nests the value one level down (`data.data`),
// beside the version metadata this never reads: what is wanted is the
// fields, and the version a value came from is not something to write
// into a file that is regenerated on every run.
func (b *openbao) read(ctx context.Context, mount, path string) (map[string]any, error) {
	// A deleted latest version is a 404 carrying the version's metadata,
	// and `call`'s 404 sentence is about a mount or a role — which is
	// true of the paths `credential` calls and nonsense on this one. The
	// difference matters because a deleted version still LISTS: the name
	// is there, the value is not, and the message has to say which.
	gone := func() error {
		return notFound{fmt.Errorf("%s/data/%s holds no current value: either it was removed "+
			"between the listing and this read, or its latest version was deleted", mount, path)}
	}
	answer, err := b.call(ctx, http.MethodGet, mount+"/data/"+path, nil, nil)
	if nothingThere(err) {
		return nil, gone()
	}
	if err != nil {
		return nil, err
	}
	fields, ok := answer.Data["data"].(map[string]any)
	if !ok || fields == nil {
		return nil, gone()
	}
	return fields, nil
}

// list is the names directly under a KV version 2 prefix, a name ending
// in `/` being a prefix of its own rather than a value.
//
// GET with `?list=true` rather than the `LIST` method, although OpenBAO
// routes both to the same handler: LIST is not a method anything between
// a laptop and the API is obliged to forward, and the one that refuses it
// answers 405 — which arrives here as a failure about the path rather
// than about the proxy. Vault's own client sends GET for the same reason,
// so this is the spelling installations are known to serve.
func (b *openbao) list(ctx context.Context, mount, prefix string) ([]string, error) {
	answer, err := b.call(ctx, http.MethodGet, mount+"/metadata/"+prefix, url.Values{"list": {"true"}}, nil)
	if err != nil {
		return nil, err
	}
	raw, _ := answer.Data["keys"].([]any)
	names := make([]string, 0, len(raw))
	for _, one := range raw {
		if name, ok := one.(string); ok && strings.TrimSpace(name) != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// revokeSelf ends the login, and is deliberately best-effort.
//
// A batch token — which is what a mount that issues no storage writes per
// login hands out — cannot be revoked at all, and says so. That is not a
// failure of the command: the token was never written anywhere, it is
// gone from this process the moment it exits, and its own short cap ends
// it regardless. So the refusal is swallowed rather than turned into a
// non-zero exit for a credential that was delivered successfully.
func (b *openbao) revokeSelf(ctx context.Context) {
	if b.token == "" {
		return
	}
	_, _ = b.call(ctx, http.MethodPost, "auth/token/revoke-self", nil, nil)
	b.token = ""
}

// notFound is a path OpenBAO has nothing at, typed because the two
// callers read it differently: a missing role is the end of the command,
// while a KV prefix with nothing under it is an empty listing — OpenBAO
// answers 404 rather than an empty one — and the caller decides what an
// empty answer means.
type notFound struct{ error }

func nothingThere(err error) bool {
	var missing notFound
	return errors.As(err, &missing)
}

// answer is as much of OpenBAO's envelope as anything here reads.
type answer struct {
	Data map[string]any `json:"data"`
	Auth *struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

// call is one request, with the status turned into this tool's exit
// codes. Everything this tool asks OpenBAO goes through here — the POSTs
// that log in, sign and revoke, and the GETs that read and list — so a
// status means one thing in one place.
//
// The mapping is the contract the rest of the tool already keeps: a
// refusal is final and a script should stop, an outage is worth another
// try. A 404 gets a sentence of its own because on a path of this shape
// it almost always means the role has not been created yet, which reads
// as nothing at all when it arrives as "404 Not Found"; it is also typed,
// because on a KV path it means something else entirely and only the
// caller can tell which.
func (b *openbao) call(ctx context.Context, method, path string, query url.Values, body map[string]any) (answer, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return answer{}, fmt.Errorf("render the request to %s: %w", path, err)
		}
		payload = bytes.NewReader(encoded)
	}

	address := b.Address + "/v1/" + path
	if len(query) > 0 {
		address += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, address, payload)
	if err != nil {
		return answer{}, fmt.Errorf("%w: build the request to %s: %w", errUnreachable, path, err)
	}
	request.Header.Set("Content-Type", "application/json")
	if b.Namespace != "" {
		request.Header.Set(namespaceHeader, b.Namespace)
	}
	if b.token != "" {
		request.Header.Set("X-Vault-Token", b.token)
	}

	client := b.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		if untrusted(err) {
			return answer{}, fmt.Errorf("%w: %s: %w (a private root? pass --ca-cert <bundle>, or export %s)",
				errUnreachable, path, err, envOpenBAOCACert)
		}
		return answer{}, fmt.Errorf("%w: %s: %w", errUnreachable, path, err)
	}
	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return answer{}, fmt.Errorf("%w: read the answer from %s: %w", errUnreachable, path, err)
	}

	var decoded answer
	// A body that is not JSON is a proxy or a login page answering in
	// OpenBAO's place, and the status is then the only thing worth
	// repeating.
	_ = json.Unmarshal(raw, &decoded)
	said := strings.Join(decoded.Errors, "; ")

	switch {
	case response.StatusCode == http.StatusOK || response.StatusCode == http.StatusNoContent:
		return decoded, nil
	case response.StatusCode == http.StatusForbidden:
		return answer{}, fmt.Errorf("%w: %s: %s", errNotGranted, path, or(said, "refused"))
	case response.StatusCode == http.StatusNotFound:
		return answer{}, notFound{fmt.Errorf("%s does not exist: %s",
			path, or(said, "the mount or the role has not been created in this namespace"))}
	case response.StatusCode >= http.StatusInternalServerError:
		return answer{}, fmt.Errorf("%w: %s answered %s: %s", errUnreachable, path, response.Status, said)
	default:
		return answer{}, fmt.Errorf("%s answered %s: %s", path, response.Status, or(said, "no reason given"))
	}
}

// or is the first of the two that says something.
func or(said, fallback string) string {
	if strings.TrimSpace(said) == "" {
		return fallback
	}
	return said
}
