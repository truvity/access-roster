package sessiond

import (
	"encoding/json"
	"net/http"

	"connectrpc.com/connect"

	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// oauthError is an error of RFC 6749 section 5.2 (and 4.1.2.1): the code is from the closed list of the RFC, the
// description is a fixed text that holds no value of the request.
type oauthError struct {
	status int
	code   string
	desc   string
	extra  map[string]string // step-up members (RFC 9470), when policy asked for them
}

func (e *oauthError) Error() string { return e.code }

func (e *oauthError) body() []byte {
	m := map[string]string{"error": e.code, "error_description": e.desc}
	for k, v := range e.extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte(`{"error":"server_error"}`)
	}
	return b
}

// tokenError is the answer of the token endpoint to an error: JSON, never cached. An invalid_client is a 401 with
// WWW-Authenticate (RFC 6749 section 5.2), so entry does not have to guess it.
func tokenError(e *oauthError) *connect.Response[typev2alpha1.HttpReply] {
	h := append([]*typev2alpha1.Header{header("Content-Type", "application/json")}, noStore()...)
	if e.status == http.StatusUnauthorized {
		h = append(h, header("WWW-Authenticate", `Basic realm="sluis", charset="UTF-8"`))
	}
	return reply(e.status, e.body(), h...)
}

// The errors of the token endpoint (RFC 6749 section 5.2). A description is fixed per code, so an unknown client, a
// refused person and a spent code answer in the same words: the caller learns the class of the refusal and nothing
// about which rule it was.
func errInvalidRequest() *oauthError {
	return &oauthError{status: http.StatusBadRequest, code: "invalid_request", desc: "the request is malformed"}
}

func errInvalidClient() *oauthError {
	return &oauthError{status: http.StatusUnauthorized, code: "invalid_client", desc: "client authentication failed"}
}

func errInvalidGrant() *oauthError {
	return &oauthError{status: http.StatusBadRequest, code: "invalid_grant", desc: "the grant is invalid, expired or revoked"}
}

func errInvalidScope() *oauthError {
	return &oauthError{status: http.StatusBadRequest, code: "invalid_scope", desc: "the scope is not allowed"}
}

func errUnsupportedGrant() *oauthError {
	return &oauthError{status: http.StatusBadRequest, code: "unsupported_grant_type", desc: "the grant type is not served"}
}

// errStepUp is RFC 9470 section 3: the authentication is not enough for this client, and what to ask for is in the
// answer. The values are the ones the policy that denied named; session adds no word of its own to them.
func errStepUp(extra map[string]string) *oauthError {
	return &oauthError{status: http.StatusBadRequest, code: "insufficient_user_authentication", desc: "a fresher or stronger authentication is needed", extra: extra}
}

// tokenResponse is a successful answer of the token endpoint (RFC 6749 section 5.1, OpenID Connect Core section 3.1.3.3).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func tokenOK(t tokenResponse) (*connect.Response[typev2alpha1.HttpReply], error) {
	b, err := json.Marshal(t) //nolint:gosec // the token endpoint's answer is a token (RFC 6749 section 5.1); it is the response, not a leak
	if err != nil {
		return nil, internal("token", err)
	}
	h := append([]*typev2alpha1.Header{header("Content-Type", "application/json")}, noStore()...)
	return reply(http.StatusOK, b, h...), nil
}
