package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// The OpenBAO API this speaks, which is three calls: log in, write once,
// revoke. No client library, deliberately — a login, one `sign` or
// `issue` and a revoke are plain JSON over HTTP, and the alternative is a
// dependency tree larger than the rest of this binary inside a tool
// people install to avoid installing things.
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
)

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
	data, err := b.call(ctx, "auth/"+mount+"/login", map[string]any{"role": role, "jwt": jwt})
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
// `pki/issue/<role>`, and nothing else in the whole command.
func (b *openbao) write(ctx context.Context, path string, body map[string]any) (map[string]any, error) {
	answer, err := b.call(ctx, path, body)
	if err != nil {
		return nil, err
	}
	if answer.Data == nil {
		return nil, fmt.Errorf("%w: %s answered with no data", errUnreachable, path)
	}
	return answer.Data, nil
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
	_, _ = b.call(ctx, "auth/token/revoke-self", nil)
	b.token = ""
}

// answer is as much of OpenBAO's envelope as anything here reads.
type answer struct {
	Data map[string]any `json:"data"`
	Auth *struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

// call is one POST, with the status turned into this tool's exit codes.
//
// The mapping is the contract the rest of the tool already keeps: a
// refusal is final and a script should stop, an outage is worth another
// try. A 404 gets a sentence of its own because on a path of this shape
// it almost always means the role has not been created yet, which reads
// as nothing at all when it arrives as "404 Not Found".
func (b *openbao) call(ctx context.Context, path string, body map[string]any) (answer, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return answer{}, fmt.Errorf("render the request to %s: %w", path, err)
		}
		payload = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.Address+"/v1/"+path, payload)
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
		return answer{}, fmt.Errorf("%s does not exist: %s",
			path, or(said, "the mount or the role has not been created in this namespace"))
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
